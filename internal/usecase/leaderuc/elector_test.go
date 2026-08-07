package leaderuc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeLeaderStore is an in-file ports.LeaderStore for these usecase tests, mirroring the fenced
// lease semantics. Keeping it here avoids a usecase -> infrastructure import edge in the test.
type fakeLeaderStore struct {
	mu      sync.Mutex
	holder  string
	fence   int64
	expires time.Time
	present bool
}

func newFakeLeaderStore() *fakeLeaderStore { return &fakeLeaderStore{} }

var _ ports.LeaderStore = (*fakeLeaderStore)(nil)

func (s *fakeLeaderStore) Acquire(_ context.Context, _, holder string, term time.Duration, now time.Time) (bool, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !s.present:
		s.holder, s.fence, s.expires, s.present = holder, 1, now.Add(term), true
		return true, s.fence, nil
	case s.holder == holder:
		s.expires = now.Add(term)
		return true, s.fence, nil
	case !s.expires.After(now):
		s.holder, s.expires = holder, now.Add(term)
		s.fence++
		return true, s.fence, nil
	default:
		return false, s.fence, nil
	}
}

func (s *fakeLeaderStore) Resign(_ context.Context, _, holder string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.present && s.holder == holder {
		// Expire, keep the fence (matches the production stores): monotonic across handover.
		s.holder = ""
		s.expires = now
	}
	return nil
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.t = c.t.Add(d)
}

type fakeAudit struct{ actions []string }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.actions = append(a.actions, e.Action)
	return nil
}

func TestNewElectorValidation(t *testing.T) {
	store := newFakeLeaderStore()
	clk := &fakeClock{t: time.Unix(1000, 0)}
	cases := []struct{ term, renew time.Duration }{
		{0, time.Second},
		{10 * time.Second, 0},
		{10 * time.Second, 5 * time.Second}, // renew == term/2, must be strictly less
		{10 * time.Second, 6 * time.Second},
	}
	for _, c := range cases {
		if _, err := NewElector(store, &fakeAudit{}, clk, "sched", "inst", c.term, c.renew); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("term=%s renew=%s should be invalid", c.term, c.renew)
		}
	}
	if _, err := NewElector(store, &fakeAudit{}, clk, "", "inst", 10*time.Second, time.Second); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty resource should be invalid")
	}
	if _, err := NewElector(nil, &fakeAudit{}, clk, "sched", "inst", 10*time.Second, time.Second); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil store should be invalid")
	}
}

func TestElectorSingleLeaderAndHandover(t *testing.T) {
	ctx := context.Background()
	store := newFakeLeaderStore()
	clk := &fakeClock{t: time.Unix(1000, 0)}
	const term, renew = 15 * time.Second, 5 * time.Second

	a, err := NewElector(store, &fakeAudit{}, clk, "sched", "inst-a", term, renew)
	if err != nil {
		t.Fatalf("new a: %v", err)
	}
	b, err := NewElector(store, &fakeAudit{}, clk, "sched", "inst-b", term, renew)
	if err != nil {
		t.Fatalf("new b: %v", err)
	}

	// a campaigns first and wins; b then sees a live lease and stays a follower.
	if err := a.tick(ctx); err != nil {
		t.Fatalf("a tick: %v", err)
	}
	if err := b.tick(ctx); err != nil {
		t.Fatalf("b tick: %v", err)
	}
	if !a.IsLeader() || b.IsLeader() {
		t.Fatalf("expected exactly a to be leader: a=%v b=%v", a.IsLeader(), b.IsLeader())
	}
	firstFence := a.Fence()

	// a renews within the term; b still cannot take over.
	clk.advance(renew)
	_ = a.tick(ctx)
	_ = b.tick(ctx)
	if !a.IsLeader() || b.IsLeader() {
		t.Fatalf("after renewal a must still lead: a=%v b=%v", a.IsLeader(), b.IsLeader())
	}

	// a stops renewing; once the term expires, b takes over and the fence is bumped.
	clk.advance(2 * term)
	if err := b.tick(ctx); err != nil {
		t.Fatalf("b takeover tick: %v", err)
	}
	if !b.IsLeader() {
		t.Fatalf("b should take over an expired lease")
	}
	if b.Fence() <= firstFence {
		t.Fatalf("takeover must bump the fence: first=%d now=%d", firstFence, b.Fence())
	}

	// a ticks again and discovers it has lost leadership (fail-safe).
	_ = a.tick(ctx)
	if a.IsLeader() {
		t.Fatalf("a must observe it lost leadership after b took over")
	}
}

func TestElectorResignFreesLease(t *testing.T) {
	ctx := context.Background()
	store := newFakeLeaderStore()
	clk := &fakeClock{t: time.Unix(1000, 0)}
	const term, renew = 15 * time.Second, 5 * time.Second
	audit := &fakeAudit{}
	a, _ := NewElector(store, audit, clk, "sched", "inst-a", term, renew)
	b, _ := NewElector(store, &fakeAudit{}, clk, "sched", "inst-b", term, renew)

	_ = a.tick(ctx)
	if !a.IsLeader() {
		t.Fatalf("a should lead")
	}
	a.resign() // releases immediately, without waiting for the term
	if a.IsLeader() {
		t.Fatalf("a should not be leader after resign")
	}
	// b can take over right away even though the term has not expired.
	if err := b.tick(ctx); err != nil {
		t.Fatalf("b tick: %v", err)
	}
	if !b.IsLeader() {
		t.Fatalf("b should acquire immediately after a resigned")
	}
	// The transitions were audited.
	var acquired, resigned bool
	for _, act := range audit.actions {
		if act == "leader.acquired" {
			acquired = true
		}
		if act == "leader.resigned" {
			resigned = true
		}
	}
	if !acquired || !resigned {
		t.Fatalf("expected acquired+resigned audit entries, got %v", audit.actions)
	}
}

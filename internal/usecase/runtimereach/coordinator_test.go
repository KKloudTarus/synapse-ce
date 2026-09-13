package runtimereach

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	dr "github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type proposeCall struct {
	proposer  string
	subjectID shared.ID
	claim     judgment.ReachabilityClaim
}

type fakeRecorder struct {
	prior    []judgment.Judgment
	proposes []proposeCall
	verifies []int
	nextID   int
}

func (r *fakeRecorder) Propose(_ context.Context, proposer string, _ shared.ID, _ judgment.Capability, _ judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	rc, _ := claim.(judgment.ReachabilityClaim)
	r.proposes = append(r.proposes, proposeCall{proposer: proposer, subjectID: subjectID, claim: rc})
	r.nextID++
	return judgment.Judgment{ID: shared.ID(string(rune('a' + r.nextID))), Version: 1, ProposedBy: proposer, SubjectID: subjectID, Claim: rc}, nil
}

func (r *fakeRecorder) Verify(_ context.Context, _ string, _, _ shared.ID, score int, _ string, _ int) (judgment.Judgment, error) {
	r.verifies = append(r.verifies, score)
	return judgment.Judgment{}, nil
}

func (r *fakeRecorder) List(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return r.prior, nil
}

type fakeAudit struct{ actions []string }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.actions = append(a.actions, e.Action)
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func newCoordinator(t *testing.T, prior ...judgment.Judgment) (*Coordinator, *fakeRecorder, *fakeAudit) {
	t.Helper()
	rec := &fakeRecorder{prior: prior}
	aud := &fakeAudit{}
	c, err := NewCoordinator(rec, aud, fixedClock{})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	return c, rec, aud
}

func TestRecordMintsRaiseOnlyRuntimeReachable(t *testing.T) {
	c, rec, _ := newCoordinator(t)
	n, err := c.Record(context.Background(), "eng", []dr.Hit{
		{FindingID: "f1", Package: dr.PackageRef{Name: "libssl3", Version: "3.0"}, Match: dr.MatchFileIdentity},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(rec.proposes) != 1 {
		t.Fatalf("minted %d judgments, proposes=%d, want 1", n, len(rec.proposes))
	}
	got := rec.proposes[0]
	if got.proposer != judgment.ProofActorRuntimeLibLoadedScan {
		t.Errorf("proposer = %q, want the reserved runtime-libloaded scan actor", got.proposer)
	}
	if got.claim.Reachable != judgment.Reachable || got.claim.Tier != judgment.TierRuntime {
		t.Errorf("claim = %+v, want reachable at tier-runtime", got.claim)
	}
	if len(rec.verifies) != 1 || rec.verifies[0] != verdict.DeterministicProofScore {
		t.Errorf("verify scores = %v, want one at %d", rec.verifies, verdict.DeterministicProofScore)
	}
}

func TestRecordNeverMintsNotReachable(t *testing.T) {
	// The coordinator has no path that produces a not_reachable claim: every minted claim must be reachable,
	// so a runtime observation can never suppress a finding.
	c, rec, _ := newCoordinator(t)
	if _, err := c.Record(context.Background(), "eng", []dr.Hit{
		{FindingID: "f1", Package: dr.PackageRef{Name: "a", Version: "1"}, Match: dr.MatchUniquePath},
		{FindingID: "f2", Package: dr.PackageRef{Name: "b", Version: "2"}, Match: dr.MatchFileIdentity},
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range rec.proposes {
		if p.claim.Reachable != judgment.Reachable {
			t.Fatalf("minted a non-reachable claim %+v; runtime is raise-only", p.claim)
		}
		if p.claim.SuppressesFinding() {
			t.Fatalf("minted claim suppresses finding %+v", p.claim)
		}
	}
}

func TestRecordSupersedesWeakerStaticPrior(t *testing.T) {
	// A prior Tier-2 static not_reachable exists; an observed load must supersede it (raise), never be
	// blocked by it. This is the "refutes a stale static negative" case.
	prior := judgment.Judgment{
		ID: "old", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1",
		State: judgment.StateConfirmed,
		Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2, Confidence: 90, EntrypointsPresent: true},
	}
	c, rec, aud := newCoordinator(t, prior)
	n, err := c.Record(context.Background(), "eng", []dr.Hit{{FindingID: "f1", Package: dr.PackageRef{Name: "a", Version: "1"}, Match: dr.MatchFileIdentity}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("minted %d, want 1 (runtime supersedes a static not_reachable)", n)
	}
	found := false
	for _, a := range aud.actions {
		if a == "judgment.superseded" {
			found = true
		}
	}
	if !found {
		t.Errorf("audit actions = %v, want a judgment.superseded entry", aud.actions)
	}
	_ = rec
}

func TestRecordNoChurnOnExistingRuntimeReachable(t *testing.T) {
	// A finding already reachable at TierRuntime must not re-mint on the next observation (no churn).
	prior := judgment.Judgment{
		ID: "old", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1",
		State: judgment.StateConfirmed,
		Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.TierRuntime, Confidence: 100},
	}
	c, rec, _ := newCoordinator(t, prior)
	n, err := c.Record(context.Background(), "eng", []dr.Hit{{FindingID: "f1", Package: dr.PackageRef{Name: "a", Version: "1"}, Match: dr.MatchFileIdentity}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(rec.proposes) != 0 {
		t.Fatalf("minted %d (proposes %d), want 0 (no churn)", n, len(rec.proposes))
	}
}

// TestRecordReMintsWhenPriorIsUnconfirmed proves a dangling PROPOSED judgment (a mint whose Verify never
// cleared, e.g. after a transient store error) does not permanently block the real raise: since a same-tier
// claim does not supersede an equal one, treating the inert proposed judgment as a standing prior would skip
// the mint forever. The next report must re-mint and recover.
func TestRecordReMintsWhenPriorIsUnconfirmed(t *testing.T) {
	prior := judgment.Judgment{
		ID: "dangling", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1",
		State: judgment.StateProposed, // inert: Propose landed, Verify did not
		Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.TierRuntime, Confidence: 100},
	}
	c, rec, _ := newCoordinator(t, prior)
	n, err := c.Record(context.Background(), "eng", []dr.Hit{{FindingID: "f1", Package: dr.PackageRef{Name: "a", Version: "1"}, Match: dr.MatchFileIdentity}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(rec.proposes) != 1 {
		t.Fatalf("minted %d (proposes %d), want 1 (an inert proposed prior must not block the raise)", n, len(rec.proposes))
	}
}

// TestRecordReMintsWhenPriorIsRefuted proves a refuted prior likewise does not stand: a runtime observation
// must be able to raise even after an earlier attempt was refuted.
func TestRecordReMintsWhenPriorIsRefuted(t *testing.T) {
	prior := judgment.Judgment{
		ID: "refuted", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1",
		State: judgment.StateRefuted,
		Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.TierRuntime, Confidence: 100},
	}
	c, rec, _ := newCoordinator(t, prior)
	n, err := c.Record(context.Background(), "eng", []dr.Hit{{FindingID: "f1", Package: dr.PackageRef{Name: "a", Version: "1"}, Match: dr.MatchFileIdentity}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(rec.proposes) != 1 {
		t.Fatalf("minted %d (proposes %d), want 1 (a refuted prior must not block the raise)", n, len(rec.proposes))
	}
}

func TestRecordDeduplicatesAndSortsHits(t *testing.T) {
	c, rec, _ := newCoordinator(t)
	n, err := c.Record(context.Background(), "eng", []dr.Hit{
		{FindingID: "f2", Package: dr.PackageRef{Name: "b", Version: "2"}, Match: dr.MatchUniquePath},
		{FindingID: "f1", Package: dr.PackageRef{Name: "a", Version: "1"}, Match: dr.MatchFileIdentity},
		{FindingID: "f1", Package: dr.PackageRef{Name: "a", Version: "1"}, Match: dr.MatchUniquePath}, // dup
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("minted %d, want 2 (deduplicated)", n)
	}
	if rec.proposes[0].subjectID != "f1" || rec.proposes[1].subjectID != "f2" {
		t.Fatalf("proposes not sorted by finding id: %q, %q", rec.proposes[0].subjectID, rec.proposes[1].subjectID)
	}
}

func TestRecordEmptyAndValidation(t *testing.T) {
	c, _, _ := newCoordinator(t)
	if n, err := c.Record(context.Background(), "eng", nil); err != nil || n != 0 {
		t.Fatalf("empty hits: n=%d err=%v, want 0,nil", n, err)
	}
	if _, err := c.Record(context.Background(), "", []dr.Hit{{FindingID: "f1"}}); err == nil {
		t.Fatal("zero engagement id must error")
	}
}

func TestNewCoordinatorValidatesDeps(t *testing.T) {
	if _, err := NewCoordinator(nil, &fakeAudit{}, fixedClock{}); err == nil {
		t.Fatal("nil recorder must error")
	}
}

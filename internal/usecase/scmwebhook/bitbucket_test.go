package scmwebhook

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type bitbucketScans struct {
	targets         []ports.BitbucketScanTarget
	tenant, project shared.ID
	err             error
	resolveErr      error
	onResolve       func()
}

func (s *bitbucketScans) ResolveBitbucketWebhookTarget(_ context.Context, _, _ shared.ID, target ports.BitbucketScanTarget) (ports.BitbucketScanTarget, error) {
	if s.onResolve != nil {
		s.onResolve()
	}
	target.SHA += strings.Repeat("b", 28)
	target.ResolvedRepository = "https://bitbucket.org/trusted/app.git"
	return target, s.resolveErr
}

func (s *bitbucketScans) StartBitbucketWebhookAnalysis(_ context.Context, _ string, tenant, project shared.ID, target ports.BitbucketScanTarget) (ports.ScanJob, error) {
	s.targets = append(s.targets, target)
	s.tenant, s.project = tenant, project
	return ports.ScanJob{}, s.err
}

type bitbucketDedupe struct {
	mu       sync.Mutex
	receipts map[string]bool
}

func (d *bitbucketDedupe) AcceptBitbucketWebhook(ctx context.Context, id ports.InboundWebhookIdentity, uuid, digest string, receive func(context.Context) error) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := id.TenantID.String() + id.PublicID
	if d.receipts[key+uuid] || d.receipts[key+digest] {
		return false, nil
	}
	if err := receive(ctx); err != nil {
		return false, err
	}
	d.receipts[key+uuid], d.receipts[key+digest] = true, true
	return true, nil
}
func bitbucketFixture(t *testing.T) (*BitbucketReceiver, *bitbucketScans, ports.InboundWebhookIdentity) {
	t.Helper()
	scans := &bitbucketScans{}
	reader := &fakeIntegrations{item: integration.Integration{ID: "bb", TenantID: "tenant", Provider: "bitbucket", Enabled: true}, bindings: []integration.Binding{{ProjectID: "stored-project"}}}
	r, err := NewBitbucketReceiver(reader, scans, &bitbucketDedupe{receipts: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	return r, scans, ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant", OwnerKind: "integration", OwnerID: "bb"}
}
func bbPush(sha string) []byte {
	return []byte(`{"repository":{"links":{"clone":[{"href":"https://attacker.invalid/evil.git"}]}},"push":{"changes":[{"new":{"type":"branch","name":"feature/fix","target":{"hash":"` + sha + `"}}}]}}`)
}
func TestBitbucketReplayAndFailedQueueRetry(t *testing.T) {
	r, scans, id := bitbucketFixture(t)
	e := ports.InboundWebhookEvent{Provider: "bitbucket", EventType: "repo:push", EventID: "uuid-1", Body: bbPush(strings.Repeat("a", 40))}
	scans.err = errors.New("queue unavailable")
	if err := r.ReceiveInboundWebhook(context.Background(), id, e); err == nil {
		t.Fatal("queue failure accepted")
	}
	scans.err = nil
	for _, uuid := range []string{"uuid-1", "uuid-1", "uuid-2"} {
		e.EventID = uuid
		if err := r.ReceiveInboundWebhook(context.Background(), id, e); err != nil {
			t.Fatal(err)
		}
	}
	if len(scans.targets) != 2 || scans.project != "stored-project" || scans.tenant != "tenant" {
		t.Fatalf("calls=%d project=%s tenant=%s", len(scans.targets), scans.project, scans.tenant)
	}
	if got := scans.targets[1]; got.Ref != "feature/fix" || got.SHA != strings.Repeat("a", 40) || got.Fork {
		t.Fatalf("target=%+v", got)
	}
}
func bbPR(source, dest, state string) []byte {
	return []byte(`{"pullrequest":{"state":"` + state + `","source":{"branch":{"name":"contrib/fix"},"commit":{"hash":"` + strings.Repeat("b", 40) + `"},"repository":{"uuid":"` + source + `","links":{"clone":[{"href":"https://attacker.invalid/fork.git"}]}}},"destination":{"branch":{"name":"release/1.0"},"repository":{"uuid":"` + dest + `"}}}}`)
}
func TestBitbucketForkTrustAndPRLifecycle(t *testing.T) {
	a := "{11111111-1111-1111-1111-111111111111}"
	b := "{22222222-2222-2222-2222-222222222222}"
	for _, tc := range []struct {
		name, source, dest, state, event string
		fork                             bool
		count                            int
	}{
		{"trusted", a, a, "OPEN", "pullrequest:created", false, 1},
		{"fork", a, b, "OPEN", "pullrequest:updated", true, 1},
		{"missing identity", "", b, "OPEN", "pullrequest:created", true, 1},
		{"merged", a, a, "MERGED", "pullrequest:updated", false, 0},
		{"declined", a, a, "DECLINED", "pullrequest:updated", false, 0},
		{"comment", a, a, "OPEN", "pullrequest:comment_created", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, scans, id := bitbucketFixture(t)
			err := r.ReceiveInboundWebhook(context.Background(), id, ports.InboundWebhookEvent{Provider: "bitbucket", EventType: tc.event, EventID: "id", Body: bbPR(tc.source, tc.dest, tc.state)})
			if err != nil || len(scans.targets) != tc.count {
				t.Fatalf("err=%v targets=%+v", err, scans.targets)
			}
			if tc.count > 0 {
				got := scans.targets[0]
				if got.Fork != tc.fork || !got.PullRequest || got.BaseRef != "release/1.0" {
					t.Fatalf("PR target=%+v", got)
				}
			}
		})
	}
}
func TestBitbucketValidatesWholePushBeforeEnqueue(t *testing.T) {
	r, scans, id := bitbucketFixture(t)
	body := []byte(`{"push":{"changes":[{"new":{"type":"branch","name":"good","target":{"hash":"` + strings.Repeat("a", 40) + `"}}},{"new":{"type":"branch","name":"bad","target":{"hash":"` + strings.Repeat("a", 41) + `"}}}]}}`)
	err := r.ReceiveInboundWebhook(context.Background(), id, ports.InboundWebhookEvent{Provider: "bitbucket", EventType: "repo:push", EventID: "id", Body: body})
	if !errors.Is(err, shared.ErrValidation) || len(scans.targets) != 0 {
		t.Fatalf("partial push queued: err=%v targets=%+v", err, scans.targets)
	}
	for _, ref := range []string{"a//b", "a/.hidden", "a/b.lock", "a..b", "refs/heads/"} {
		if validBitbucketRef(ref) {
			t.Errorf("accepted invalid ref %q", ref)
		}
	}
}
func TestBitbucketRejectsHeaderBodyMismatchAndIgnoresDeletedTags(t *testing.T) {
	if _, err := bitbucketScanTargets("pullrequest:created", bbPush(strings.Repeat("a", 40))); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatch err=%v", err)
	}
	body := []byte(`{"push":{"changes":[{"closed":true,"new":null},{"new":{"type":"tag","name":"v1","target":{"hash":"invalid"}}}]}}`)
	if targets, err := bitbucketScanTargets("repo:push", body); err != nil || len(targets) != 0 {
		t.Fatalf("deleted/tag targets=%+v err=%v", targets, err)
	}
}

func TestBitbucketRejectsUnsignedEventHeaderReclassification(t *testing.T) {
	a := "{11111111-1111-1111-1111-111111111111}"
	for _, field := range []string{"comment", "approval", "changes_request"} {
		t.Run(field, func(t *testing.T) {
			r, scans, id := bitbucketFixture(t)
			body := bbPR(a, a, "OPEN")
			body = append(body[:len(body)-1], []byte(`,"`+field+`":{"id":1}}`)...)
			err := r.ReceiveInboundWebhook(context.Background(), id, ports.InboundWebhookEvent{Provider: "bitbucket", EventType: "pullrequest:created", EventID: "id", Body: body})
			if !errors.Is(err, shared.ErrValidation) || len(scans.targets) != 0 {
				t.Fatalf("reclassified %s event queued: %v", field, err)
			}
		})
	}
}

func TestBitbucketPullRequestAcceptsProviderCommitPrefix(t *testing.T) {
	a := "{11111111-1111-1111-1111-111111111111}"
	for _, event := range []string{"pullrequest:created", "pullrequest:updated"} {
		body := []byte(strings.ReplaceAll(string(bbPR(a, a, "OPEN")), strings.Repeat("b", 40), strings.Repeat("b", 12)))
		targets, err := bitbucketScanTargets(event, body)
		if err != nil || len(targets) != 1 || targets[0].SHA != strings.Repeat("b", 12) {
			t.Fatalf("provider PR commit rejected: targets=%+v err=%v", targets, err)
		}
	}
	if _, err := bitbucketScanTargets("repo:push", bbPush(strings.Repeat("b", 12))); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("abbreviated push accepted: %v", err)
	}
}

func TestBitbucketCommitResolutionFailureRetriesWithoutConsumingReceipt(t *testing.T) {
	r, scans, id := bitbucketFixture(t)
	a := "{11111111-1111-1111-1111-111111111111}"
	body := []byte(strings.ReplaceAll(string(bbPR(a, a, "OPEN")), strings.Repeat("b", 40), strings.Repeat("b", 12)))
	event := ports.InboundWebhookEvent{Provider: "bitbucket", EventType: "pullrequest:created", EventID: "delivery", Body: body}
	scans.resolveErr = errors.New("upstream unavailable")
	if err := r.ReceiveInboundWebhook(context.Background(), id, event); err == nil || len(scans.targets) != 0 {
		t.Fatalf("failed resolution queued: %v %+v", err, scans.targets)
	}
	scans.resolveErr = nil
	for _, uuid := range []string{"delivery", "delivery", "changed-uuid"} {
		event.EventID = uuid
		if err := r.ReceiveInboundWebhook(context.Background(), id, event); err != nil {
			t.Fatal(err)
		}
	}
	if len(scans.targets) != 1 || scans.targets[0].SHA != strings.Repeat("b", 40) {
		t.Fatalf("retry/replay lost pinned commit: %+v", scans.targets)
	}
}

func TestBitbucketRechecksBindingAfterCommitResolution(t *testing.T) {
	for _, mutation := range []string{"binding", "disabled"} {
		t.Run(mutation, func(t *testing.T) {
			r, scans, id := bitbucketFixture(t)
			reader := r.integrations.(*fakeIntegrations)
			scans.onResolve = func() {
				if mutation == "binding" {
					reader.bindings[0].ProjectID = "another-project"
				} else {
					reader.item.Enabled = false
				}
			}
			a := "{11111111-1111-1111-1111-111111111111}"
			body := []byte(strings.ReplaceAll(string(bbPR(a, a, "OPEN")), strings.Repeat("b", 40), strings.Repeat("b", 12)))
			if err := r.ReceiveInboundWebhook(context.Background(), id, ports.InboundWebhookEvent{Provider: "bitbucket", EventType: "pullrequest:created", EventID: "delivery", Body: body}); err == nil || len(scans.targets) != 0 {
				t.Fatalf("stale resolution queued: err=%v targets=%+v", err, scans.targets)
			}
		})
	}
}

package scmwebhook

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeWebhookDeduper struct {
	mu       sync.Mutex
	claimed  map[string]bool
	releases int
	err      error
}

func newFakeWebhookDeduper() *fakeWebhookDeduper {
	return &fakeWebhookDeduper{claimed: map[string]bool{}}
}

func (f *fakeWebhookDeduper) ProcessInboundWebhookEvent(ctx context.Context, id ports.InboundWebhookIdentity, event ports.InboundWebhookEvent, receive func(context.Context) error) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	prefix := id.TenantID.String() + ":" + id.PublicID + ":" + event.Provider + ":"
	key := prefix + event.EventID
	bodyKey := prefix + event.PayloadSHA256
	if f.claimed[key] || f.claimed[bodyKey] {
		return false, nil
	}
	err := receive(ctx)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		f.releases++
		return false, err
	}
	f.claimed[key] = true
	f.claimed[bodyKey] = true
	return true, nil
}

type webhookClock struct{ at time.Time }

func (c webhookClock) Now() time.Time { return c.at }

func newReceiverForTest(t *testing.T, bindings BindingReader, scans ProjectScanner, deduper *fakeWebhookDeduper) *Receiver {
	t.Helper()
	if deduper == nil {
		deduper = newFakeWebhookDeduper()
	}
	receiver, err := NewReceiver(bindings, scans, deduper, webhookClock{at: time.Unix(100, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return receiver
}

type fakeBindingReader struct {
	bindings []integration.Binding
	err      error
}

func (f *fakeBindingReader) ListIntegrationBindings(context.Context, shared.ID) ([]integration.Binding, error) {
	return append([]integration.Binding(nil), f.bindings...), f.err
}

type webhookScanCall struct {
	target                    ports.WebhookScanTarget
	actor, ref, fetchRef, sha string
	tenant, project           shared.ID
	fork                      bool
}

type fakeProjectScanner struct {
	calls []webhookScanCall
	err   error
}

func (f *fakeProjectScanner) StartGitLabWebhookAnalysis(_ context.Context, actor string, tenant, project shared.ID, target ports.WebhookScanTarget) (ports.ScanJob, error) {
	f.calls = append(f.calls, webhookScanCall{target: target, actor: actor, tenant: tenant, project: project, ref: target.Ref, fetchRef: target.FetchRef, sha: target.SHA, fork: target.Fork})
	return ports.ScanJob{}, f.err
}

func gitLabIdentity() ports.InboundWebhookIdentity {
	return ports.InboundWebhookIdentity{PublicID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TenantID: "tenant", OwnerKind: "integration", OwnerID: "gitlab-hook"}
}

func TestGitLabReceiverDedupesReplayAndReleasesFailedAttempt(t *testing.T) {
	bindings := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	scans := &fakeProjectScanner{}
	deduper := newFakeWebhookDeduper()
	receiver := newReceiverForTest(t, bindings, scans, deduper)
	event := ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", EventID: "13792a34-cac6-4fda-95a8-c58e00a3954e",
		Body: []byte(`{"ref":"refs/heads/main","checkout_sha":"dddddddddddddddddddddddddddddddddddddddd"}`),
	}
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); err != nil {
		t.Fatal(err)
	}
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 {
		t.Fatalf("replayed event started %d scans, want 1", len(scans.calls))
	}

	failingScans := &fakeProjectScanner{err: errors.New("queue unavailable")}
	deduper2 := newFakeWebhookDeduper()
	receiver = newReceiverForTest(t, bindings, failingScans, deduper2)
	event.EventID = "23792a34-cac6-4fda-95a8-c58e00a3954e"
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); err == nil {
		t.Fatal("failed scan start unexpectedly succeeded")
	}
	if deduper2.releases != 1 {
		t.Fatalf("failed processing released %d claims, want 1", deduper2.releases)
	}
	failingScans.err = nil
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); err != nil {
		t.Fatal(err)
	}
	if len(failingScans.calls) != 2 {
		t.Fatalf("retry calls = %d, want 2 attempts", len(failingScans.calls))
	}
}

func TestGitLabPushRoutesOnlyBoundProjectAndIgnoresPayloadURL(t *testing.T) {
	bindings := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	scans := &fakeProjectScanner{}
	receiver := newReceiverForTest(t, bindings, scans, nil)
	body := []byte(`{
		"ref":"refs/heads/main",
		"checkout_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"project":{"git_http_url":"https://attacker.example/evil.git"},
		"repository":{"url":"https://attacker.example/evil.git"}
	}`)
	err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", EventID: "event", Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 {
		t.Fatalf("scan calls = %d, want 1", len(scans.calls))
	}
	got := scans.calls[0]
	if got.tenant != "tenant" || got.project != "project-1" || got.ref != "main" ||
		got.sha != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || got.fork {
		t.Fatalf("unexpected scan call: %#v", got)
	}
}

func TestGitLabForkMergeRequestDisablesBuildExecutionAtProjectBoundary(t *testing.T) {
	bindings := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	scans := &fakeProjectScanner{}
	receiver := newReceiverForTest(t, bindings, scans, nil)
	body := []byte(`{
		"object_attributes":{
			"iid":17,
			"source_branch":"fork/feature",
 "target_branch":"release/1.0",
			"source_project_id":22,
			"target_project_id":11,
			"last_commit":{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			"source":{"git_http_url":"https://fork.example/never-used.git"},
			"target":{"git_http_url":"https://target.example/also-not-used.git"}
		}
	}`)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Merge Request Hook", EventID: "event", Body: body,
	}); err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 || !scans.calls[0].fork {
		t.Fatalf("fork MR scan = %#v", scans.calls)
	}
	if scans.calls[0].target.BaseRef != "release/1.0" || scans.calls[0].target.MergeRequestNumber != 17 {
		t.Fatalf("MR metadata lost: %+v", scans.calls[0].target)
	}
	if scans.calls[0].ref != "fork/feature" ||
		scans.calls[0].fetchRef != "refs/merge-requests/17/head" ||
		scans.calls[0].sha != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("fork target = %#v", scans.calls[0])
	}
}

func TestGitLabMergeRequestRequiresIIDForTargetSideRef(t *testing.T) {
	bindings := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	scans := &fakeProjectScanner{}
	receiver := newReceiverForTest(t, bindings, scans, nil)
	body := []byte(`{"object_attributes":{"source_branch":"feature","source_project_id":11,"target_project_id":11,"last_commit":{"id":"cccccccccccccccccccccccccccccccccccccccc"}}}`)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Merge Request Hook", EventID: "event-no-iid", Body: body,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing iid error = %v, want validation", err)
	}
	if len(scans.calls) != 0 {
		t.Fatalf("MR without target-side ref started scans: %#v", scans.calls)
	}
}

func TestGitLabMergeRequestMissingProjectIdentityFailsSafeAsFork(t *testing.T) {
	bindings := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	scans := &fakeProjectScanner{}
	receiver := newReceiverForTest(t, bindings, scans, nil)
	body := []byte(`{
		"object_attributes":{
			"iid":18,
			"source_branch":"feature",
			"last_commit":{"id":"cccccccccccccccccccccccccccccccccccccccc"}
		}
	}`)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Merge Request Hook", EventID: "event", Body: body,
	}); err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 || !scans.calls[0].fork {
		t.Fatalf("missing fork identity must tighten policy: %#v", scans.calls)
	}
}

func TestGitLabReceiverFailsClosedOnAmbiguousBindingOrInvalidSHA(t *testing.T) {
	scans := &fakeProjectScanner{}
	multi := &fakeBindingReader{bindings: []integration.Binding{
		{IntegrationID: "gitlab-hook", ProjectID: "project-1"},
		{IntegrationID: "gitlab-hook", ProjectID: "project-2"},
	}}
	receiver := newReceiverForTest(t, multi, scans, nil)
	body := []byte(`{"ref":"refs/heads/main","checkout_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", EventID: "33792a34-cac6-4fda-95a8-c58e00a3954e", Body: body,
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("ambiguous binding error = %v, want conflict", err)
	}

	single := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	receiver = newReceiverForTest(t, single, scans, nil)
	bad := []byte(`{"ref":"refs/heads/main","checkout_sha":"NOT-A-SHA"}`)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", EventID: "43792a34-cac6-4fda-95a8-c58e00a3954e", Body: bad,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid sha error = %v, want validation", err)
	}
	if len(scans.calls) != 0 {
		t.Fatalf("invalid/ambiguous event started scans: %#v", scans.calls)
	}
}

func TestGitLabUnsupportedAndDeleteEventsAreNoOps(t *testing.T) {
	bindings := &fakeBindingReader{bindings: []integration.Binding{{IntegrationID: "gitlab-hook", ProjectID: "project-1"}}}
	scans := &fakeProjectScanner{}
	receiver := newReceiverForTest(t, bindings, scans, nil)
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Pipeline Hook", EventID: "53792a34-cac6-4fda-95a8-c58e00a3954e", Body: []byte(`{"url":"https://attacker.example"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", EventID: "63792a34-cac6-4fda-95a8-c58e00a3954e",
		Body: []byte(`{"ref":"refs/heads/deleted","checkout_sha":null,"after":"0000000000000000000000000000000000000000"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 0 {
		t.Fatalf("no-op events started scans: %#v", scans.calls)
	}
}

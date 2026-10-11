package scmwebhook

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAllSCMProvidersScanThroughSharedReceiver(t *testing.T) {
	github, githubScans, githubIdentity := webhookFixture()
	gitlabScans := &fakeProjectScanner{}
	gitlab := newReceiverForTest(t, &fakeBindingReader{bindings: []integration.Binding{
		{IntegrationID: "gitlab-hook", ProjectID: "gitlab-project"},
	}}, gitlabScans, nil)
	bitbucket, bitbucketScans, bitbucketIdentity := bitbucketFixture(t)
	receiver, err := NewProviderReceiver(github, gitlab, bitbucket)
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 40)
	if err := receiver.ReceiveInboundWebhook(context.Background(), githubIdentity, ports.InboundWebhookEvent{
		Provider: "github", EventType: "pull_request", EventID: "github-delivery", Ref: "fork/fix", SHA: sha, Fork: true,
	}); err != nil {
		t.Fatal(err)
	}
	if len(githubScans.calls) != 1 || len(gitlabScans.calls) != 0 {
		t.Fatalf("GitHub delivery: github=%d gitlab=%d", len(githubScans.calls), len(gitlabScans.calls))
	}
	if in := githubScans.calls[0].input; !in.DisableGitCredentials || !in.NoBuildExecution || in.Commit != sha {
		t.Fatalf("GitHub fork restrictions lost during dispatch: %+v", in)
	}
	event := ports.InboundWebhookEvent{
		Provider: "gitlab", EventType: "Push Hook", EventID: "gitlab-delivery",
		Body: []byte(`{"object_kind":"push","ref":"refs/heads/main","after":"` + sha + `"}`),
	}
	for range 2 {
		if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); err != nil {
			t.Fatal(err)
		}
	}
	if len(githubScans.calls) != 1 || len(gitlabScans.calls) != 1 {
		t.Fatalf("GitLab replay: github=%d gitlab=%d", len(githubScans.calls), len(gitlabScans.calls))
	}
	if got := gitlabScans.calls[0]; got.project != "gitlab-project" || got.tenant != "tenant" || got.sha != sha {
		t.Fatalf("GitLab dispatch lost its bound identity or pin: %+v", got)
	}
	// Retry failed enqueue, then deduplicate UUID and authenticated-body replays.
	bitbucketEvent := ports.InboundWebhookEvent{
		Provider: "bitbucket", EventType: "repo:push", EventID: "bitbucket-delivery", Body: bbPush(sha),
	}
	queueErr := errors.New("queue unavailable")
	bitbucketScans.err = queueErr
	if err := receiver.ReceiveInboundWebhook(context.Background(), bitbucketIdentity, bitbucketEvent); !errors.Is(err, queueErr) {
		t.Fatalf("Bitbucket enqueue failure=%v", err)
	}
	bitbucketScans.err = nil
	for _, uuid := range []string{"bitbucket-delivery", "bitbucket-delivery", "changed-uuid"} {
		bitbucketEvent.EventID = uuid
		if err := receiver.ReceiveInboundWebhook(context.Background(), bitbucketIdentity, bitbucketEvent); err != nil {
			t.Fatal(err)
		}
	}
	if len(bitbucketScans.targets) != 2 || bitbucketScans.tenant != bitbucketIdentity.TenantID || bitbucketScans.project != "stored-project" {
		t.Fatalf("Bitbucket retry/replay: %+v", bitbucketScans)
	}
	if got := bitbucketScans.targets[1]; got.SHA != sha || got.Ref != "feature/fix" || got.Fork {
		t.Fatalf("Bitbucket push target: %+v", got)
	}
	bitbucketEvent.EventType, bitbucketEvent.EventID = "pullrequest:created", "bitbucket-fork-delivery"
	bitbucketEvent.Body = bbPR("{11111111-1111-1111-1111-111111111111}", "{22222222-2222-2222-2222-222222222222}", "OPEN")
	for range 2 {
		if err := receiver.ReceiveInboundWebhook(context.Background(), bitbucketIdentity, bitbucketEvent); err != nil {
			t.Fatal(err)
		}
	}
	if len(bitbucketScans.targets) != 3 {
		t.Fatalf("Bitbucket fork replay: %d scan attempts", len(bitbucketScans.targets))
	}
	if got := bitbucketScans.targets[2]; !got.Fork || !got.PullRequest || got.BaseRef != "release/1.0" || got.SHA != strings.Repeat("b", 40) {
		t.Fatalf("Bitbucket fork restrictions lost during dispatch: %+v", got)
	}
	if len(githubScans.calls) != 1 || len(gitlabScans.calls) != 1 {
		t.Fatal("Bitbucket delivery invoked another provider")
	}
	event.Provider = "unknown"
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown provider error=%v", err)
	}
	if len(githubScans.calls) != 1 || len(gitlabScans.calls) != 1 || len(bitbucketScans.targets) != 3 {
		t.Fatal("unsupported provider invoked an SCM receiver")
	}
}

func TestProviderReceiverRequiresEveryProvider(t *testing.T) {
	github, _, _ := webhookFixture()
	gitlab := newReceiverForTest(t, &fakeBindingReader{}, &fakeProjectScanner{}, nil)
	bitbucket, _, _ := bitbucketFixture(t)
	for _, receivers := range [][3]ports.InboundWebhookReceiver{
		{nil, gitlab, bitbucket}, {github, nil, bitbucket}, {github, gitlab, nil},
	} {
		if _, err := NewProviderReceiver(receivers[0], receivers[1], receivers[2]); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("missing provider receiver error=%v", err)
		}
	}
}

package docpublish

import (
	"context"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type prewriteThrottleProvider struct {
	*releaseProvider
	throttled bool
}

func (p *prewriteThrottleProvider) GetDocument(ctx context.Context, page string) (ports.DocumentRemoteState, error) {
	if p.throttled {
		return ports.DocumentRemoteState{}, &ports.DocumentProviderError{Code: "rate_limited", Status: 429, RetryAfter: 2 * time.Minute}
	}
	return p.releaseProvider.GetDocument(ctx, page)
}

type prewriteThrottleRegistry struct {
	releaseProviders
	provider ports.DocumentProvider
}

func (r prewriteThrottleRegistry) DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error) {
	return r.provider, nil
}

func assertPrewriteDeferred(t *testing.T, f *releaseFixture, id shared.ID, attempts, uploads, writes, purges int) time.Time {
	t.Helper()
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", id)
	if err != nil {
		t.Fatal(err)
	}
	if command.Intent.State != writeintent.Pending || command.Intent.Attempts != attempts || command.NextAttemptAt.IsZero() || !command.NextAttemptAt.Equal(f.clock.Now().Add(2*time.Minute)) || f.provider.uploads != uploads || f.provider.writes != writes || f.provider.purges != purges {
		t.Fatalf("pre-write throttle command=%+v effects upload/write/purge=%d/%d/%d", command, f.provider.uploads, f.provider.writes, f.provider.purges)
	}
	if early, err := f.service.Execute(context.Background(), "tenant", id); err != nil || early.State != writeintent.Pending {
		t.Fatalf("early direct retry=%+v err=%v", early, err)
	}
	command, err = f.store.GetDocumentCommand(context.Background(), "tenant", id)
	if err != nil || !command.NextAttemptAt.Equal(f.clock.Now().Add(2*time.Minute)) || command.Intent.Attempts != attempts || f.provider.uploads != uploads || f.provider.writes != writes || f.provider.purges != purges {
		t.Fatalf("early direct retry changed durable throttle command=%+v effects upload/write/purge=%d/%d/%d err=%v", command, f.provider.uploads, f.provider.writes, f.provider.purges, err)
	}
	return command.NextAttemptAt
}

func TestExecuteDefersPrewriteThrottleAcrossDocumentSteps(t *testing.T) {
	t.Run("restrictions", func(t *testing.T) {
		f := newReleaseFixture(t)
		intent := f.publish(t)
		if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil {
			t.Fatal(err)
		}
		provider := &prewriteThrottleProvider{releaseProvider: f.provider, throttled: true}
		f.service.providers = prewriteThrottleRegistry{releaseProviders: releaseProviders{provider: f.provider}, provider: provider}
		if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil {
			t.Fatal(err)
		}
		due := assertPrewriteDeferred(t, f, intent.ID, 0, 0, 0, 0)
		if f.provider.restrictions != 0 {
			t.Fatalf("restricted before pre-write proof: %d", f.provider.restrictions)
		}
		provider.throttled = false
		f.clock.at = due
		if done := f.executeUntilNotPending(t, intent.ID); done.State != writeintent.Done || f.provider.shells != 1 || f.provider.restrictions != 1 || f.provider.uploads != 1 || f.provider.writes != 1 {
			t.Fatalf("restrictions recovery=%+v provider=%+v", done, f.provider)
		}
	})
	t.Run("attachments", func(t *testing.T) {
		f := newReleaseFixture(t)
		intent := f.publish(t)
		advanceReleaseToAttachments(t, f, intent.ID)
		provider := &prewriteThrottleProvider{releaseProvider: f.provider, throttled: true}
		f.service.providers = prewriteThrottleRegistry{releaseProviders: releaseProviders{provider: f.provider}, provider: provider}
		if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil {
			t.Fatal(err)
		}
		due := assertPrewriteDeferred(t, f, intent.ID, 0, 0, 0, 0)
		provider.throttled = false
		f.clock.at = due
		if done := f.executeUntilNotPending(t, intent.ID); done.State != writeintent.Done || f.provider.uploads != 1 || f.provider.writes != 1 {
			t.Fatalf("attachments recovery=%+v provider=%+v", done, f.provider)
		}
	})
	t.Run("body", func(t *testing.T) {
		f := newReleaseFixture(t)
		intent := f.publish(t)
		advanceReleaseToAttachments(t, f, intent.ID)
		if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || f.provider.uploads != 1 {
			t.Fatalf("checkpoint attachment err=%v uploads=%d", err, f.provider.uploads)
		}
		provider := &prewriteThrottleProvider{releaseProvider: f.provider, throttled: true}
		f.service.providers = prewriteThrottleRegistry{releaseProviders: releaseProviders{provider: f.provider}, provider: provider}
		if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil {
			t.Fatal(err)
		}
		due := assertPrewriteDeferred(t, f, intent.ID, 0, 1, 0, 0)
		provider.throttled = false
		f.clock.at = due
		if done := f.executeUntilNotPending(t, intent.ID); done.State != writeintent.Done || f.provider.uploads != 1 || f.provider.writes != 1 {
			t.Fatalf("body recovery=%+v provider=%+v", done, f.provider)
		}
	})
	t.Run("purge", func(t *testing.T) {
		f := newReleaseFixture(t)
		created := f.publish(t)
		if done := f.executeUntilNotPending(t, created.ID); done.State != writeintent.Done {
			t.Fatalf("create=%+v", done)
		}
		links, err := f.store.ListLinks(context.Background(), "tenant", domain.Engagement, "assessment", 10)
		if err != nil || len(links) != 1 {
			t.Fatalf("published links=%+v err=%v", links, err)
		}
		unpublish, err := f.service.Unpublish(context.Background(), "tenant", f.actor, links[0].ID, "purge-prewrite")
		if err != nil || unpublish.Intent == nil {
			t.Fatalf("unpublish=%+v err=%v", unpublish, err)
		}
		provider := &prewriteThrottleProvider{releaseProvider: f.provider, throttled: true}
		f.service.providers = prewriteThrottleRegistry{releaseProviders: releaseProviders{provider: f.provider}, provider: provider}
		if _, err := f.service.Execute(context.Background(), "tenant", unpublish.Intent.ID); err != nil {
			t.Fatal(err)
		}
		due := assertPrewriteDeferred(t, f, unpublish.Intent.ID, 0, 1, 1, 0)
		provider.throttled = false
		f.clock.at = due
		if done := f.executeUntilNotPending(t, unpublish.Intent.ID); done.State != writeintent.Done || f.provider.purges != 1 {
			t.Fatalf("purge recovery=%+v provider=%+v", done, f.provider)
		}
	})
}

func TestReconcileResumesCleanInitialShellAfterClaimCrash(t *testing.T) {
	for _, checkpoint := range []string{"before_progress_bind", "after_progress_bind"} {
		t.Run(checkpoint, func(t *testing.T) {
			f := newReleaseFixture(t)
			intent := f.publish(t)
			command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
			if err != nil {
				t.Fatal(err)
			}
			lease := f.clock.Now().Add(time.Minute)
			claimed, err := f.store.TransitionIntent(context.Background(), "tenant", intent.ID, command.Intent.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, f.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			if checkpoint == "after_progress_bind" {
				progress := command.Progress
				progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, f.clock.Now()
				if _, err = f.store.SaveDocumentProgress(context.Background(), "tenant", intent.ID, progress.Version, progress); err != nil {
					t.Fatal(err)
				}
			}
			f.clock.at = lease
			if expired, err := f.store.TransitionIntent(context.Background(), "tenant", intent.ID, claimed.Version, domain.IntentTransition{Event: writeintent.LeaseExpired}, lease); err != nil || expired.State != writeintent.Uncertain {
				t.Fatalf("lease expiry=%+v err=%v", expired, err)
			}

			resumed, err := f.service.Execute(context.Background(), "tenant", intent.ID)
			if err != nil || resumed.State != writeintent.Pending || f.provider.shells != 0 {
				t.Fatalf("clean shell recovery=%+v shells=%d err=%v", resumed, f.provider.shells, err)
			}
			stored, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
			if err != nil || stored.Progress.Step != "shell" || stored.Progress.Remote.ID != "" || stored.Progress.OutstandingOperation != "" {
				t.Fatalf("resumed checkpoint=%+v err=%v", stored.Progress, err)
			}
			if next, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || next.State != writeintent.Pending || f.provider.shells != 1 {
				t.Fatalf("first shell after recovery=%+v shells=%d err=%v", next, f.provider.shells, err)
			}
		})
	}
}

func TestReconcileInitialShellWithOutstandingMarkerNeverBlindCreates(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	lease := f.clock.Now().Add(time.Minute)
	claimed, err := f.store.TransitionIntent(context.Background(), "tenant", intent.ID, command.Intent.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	progress := command.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, f.clock.Now()
	progress.OutstandingOperation, progress.OutstandingKey, progress.OutstandingDigest = "shell", intent.Marker, intent.PayloadDigest
	if _, err = f.store.SaveDocumentProgress(context.Background(), "tenant", intent.ID, progress.Version, progress); err != nil {
		t.Fatal(err)
	}
	f.clock.at = lease
	if _, err = f.store.TransitionIntent(context.Background(), "tenant", intent.ID, claimed.Version, domain.IntentTransition{Event: writeintent.LeaseExpired}, lease); err != nil {
		t.Fatal(err)
	}
	got, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || got.State != writeintent.Uncertain || f.provider.shells != 0 {
		t.Fatalf("outstanding marker recovery=%+v shells=%d err=%v", got, f.provider.shells, err)
	}
}

package docpublish

import (
	"context"
	"errors"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type retryCountingProviders struct {
	provider  *releaseProvider
	construct int
	preflight int
}

func (p *retryCountingProviders) DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error) {
	p.construct++
	return p.provider, nil
}

func (p *retryCountingProviders) DocumentReleasePreflighter(context.Context, integration.Integration) (ports.DocumentReleasePreflighter, error) {
	p.preflight++
	return p.provider, nil
}

func TestExecuteDefersProviderThrottleUntilDueWithoutBurningAttempt(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	registry := &retryCountingProviders{provider: f.provider}
	f.service.providers = registry
	f.provider.preflight = &ports.DocumentProviderError{Code: "rate_limited", Status: 429, RetryAfter: 2 * time.Minute}

	got, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || got.State != writeintent.Pending || got.Attempts != 0 {
		t.Fatalf("first execute intent=%+v err=%v", got, err)
	}
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantDue := f.clock.Now().Add(2 * time.Minute)
	if !command.NextAttemptAt.Equal(wantDue) || command.QueueVersion < 2 {
		t.Fatalf("command delay=%s queue=%d, want %s and advanced queue", command.NextAttemptAt, command.QueueVersion, wantDue)
	}
	if registry.construct != 1 || registry.preflight != 1 {
		t.Fatalf("first execute registry calls construct=%d preflight=%d", registry.construct, registry.preflight)
	}
	if due, err := f.store.ListDocumentCommands(context.Background(), "tenant", 1, f.clock.Now().Add(time.Minute)); err != nil || len(due) != 0 {
		t.Fatalf("early worker selection commands=%d err=%v", len(due), err)
	}

	f.clock.at = f.clock.Now().Add(time.Minute)
	_, err = f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if registry.construct != 1 || registry.preflight != 1 || f.provider.shells != 0 {
		t.Fatalf("early direct execute performed provider work: construct=%d preflight=%d shells=%d", registry.construct, registry.preflight, f.provider.shells)
	}

	f.clock.at = wantDue
	f.provider.preflight = nil
	due, err := f.store.ListDocumentCommands(context.Background(), "tenant", 1, f.clock.Now())
	if err != nil || len(due) != 1 || due[0].Intent.ID != intent.ID {
		t.Fatalf("due worker selection commands=%+v err=%v", due, err)
	}
	got, err = f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || got.State != writeintent.Pending || f.provider.shells != 1 {
		t.Fatalf("due execute intent=%+v shells=%d err=%v", got, f.provider.shells, err)
	}
}

func TestWriteFailureDefersAmbiguousThrottleWithOutstandingReceipt(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	lease := f.clock.Now().Add(time.Minute)
	claimed, err := f.store.TransitionIntent(context.Background(), "tenant", intent.ID, intent.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	progress := command.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, f.clock.Now()
	progress.Step = "attachments"
	progress.Remote = domain.RemotePage{ID: "page", Version: 1, Revision: "opaque", URL: "https://example.test/page"}
	progress.OutstandingOperation = "attachment"
	progress.OutstandingKey = "attachment:0"
	progress.OutstandingDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	progress.ExpectedRemoteVersion = 1
	progress.ExpectedRemoteRevision = "opaque"
	command, err = f.store.SaveDocumentProgress(context.Background(), "tenant", intent.ID, progress.Version, progress)
	if err != nil {
		t.Fatal(err)
	}

	got, err := f.service.writeFailure(context.Background(), command, &ports.DocumentProviderError{Code: "rate_limited", Status: 429, RetryAfter: 2 * time.Minute, Ambiguous: true})
	if err != nil || got.State != writeintent.Uncertain {
		t.Fatalf("ambiguous throttle intent=%+v err=%v", got, err)
	}
	saved, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.NextAttemptAt.Equal(f.clock.Now().Add(2*time.Minute)) || saved.Progress.OutstandingOperation != "attachment" || saved.Progress.OutstandingKey != "attachment:0" || saved.Progress.OutstandingDigest != progress.OutstandingDigest {
		t.Fatalf("ambiguous throttle lost uncertainty fence: %+v", saved)
	}
	if due, err := f.store.ListDocumentCommands(context.Background(), "tenant", 1, f.clock.Now().Add(time.Minute)); err != nil || len(due) != 0 {
		t.Fatalf("ambiguous throttle selected early commands=%d err=%v", len(due), err)
	}
}

func TestExecuteShellPreflightThrottleAfterClaimCrash(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_progress_bind", true: "after_progress_bind"}[bound], func(t *testing.T) {
			f := newReleaseFixture(t)
			intent := f.publish(t)
			lease := f.clock.Now().Add(time.Minute)
			claimed, err := f.store.TransitionIntent(context.Background(), "tenant", intent.ID, intent.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, f.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			if bound {
				command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
				if err != nil {
					t.Fatal(err)
				}
				progress := command.Progress
				progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, f.clock.Now()
				if _, err := f.store.SaveDocumentProgress(context.Background(), "tenant", intent.ID, progress.Version, progress); err != nil {
					t.Fatal(err)
				}
			}
			registry := &retryCountingProviders{provider: f.provider}
			f.service.providers = registry
			f.provider.preflight = &ports.DocumentProviderError{Code: "rate_limited", Status: 429, RetryAfter: 2 * time.Minute}
			if got, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || got.State != writeintent.InFlight || registry.construct != 0 || registry.preflight != 0 {
				t.Fatalf("live lease performed provider work: intent=%+v err=%v registry=%+v", got, err, registry)
			}
			f.clock.at = lease
			got, err := f.service.Execute(context.Background(), "tenant", intent.ID)
			if err != nil || got.State != writeintent.Uncertain {
				t.Fatalf("expired claim throttle intent=%+v err=%v", got, err)
			}
			command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
			due := f.clock.Now().Add(2 * time.Minute)
			if err != nil || !command.NextAttemptAt.Equal(due) || command.Progress.OutstandingOperation != "" || f.provider.shells != 0 {
				t.Fatalf("expired shell delay missing or unsafe: command=%+v err=%v", command, err)
			}
			f.clock.at = due.Add(-time.Nanosecond)
			if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || registry.construct != 1 || registry.preflight != 1 {
				t.Fatalf("early retry err=%v registry=%+v", err, registry)
			}
			f.clock.at, f.provider.preflight = due, nil
			if got, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || got.State != writeintent.Pending || f.provider.shells != 0 {
				t.Fatalf("recovery intent=%+v shells=%d err=%v", got, f.provider.shells, err)
			}
			if got, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || got.State != writeintent.Pending || f.provider.shells != 1 {
				t.Fatalf("first shell intent=%+v shells=%d err=%v", got, f.provider.shells, err)
			}
		})
	}
}

func TestExecuteFailedShellPersistsPreflightThrottleBeforeNewClaim(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	lease := f.clock.Now().Add(time.Minute)
	claimed, err := f.store.TransitionIntent(context.Background(), "tenant", intent.ID, intent.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.TransitionIntent(context.Background(), "tenant", intent.ID, claimed.Version, domain.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_refused"}, f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	registry := &retryCountingProviders{provider: f.provider}
	f.service.providers = registry
	f.provider.preflight = &ports.DocumentProviderError{Code: "rate_limited", Status: 429, RetryAfter: 9 * time.Minute}
	got, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || got.State != writeintent.Pending || got.Attempts != claimed.Attempts {
		t.Fatalf("failed shell retry intent=%+v err=%v", got, err)
	}
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	due := f.clock.Now().Add(9 * time.Minute)
	if err != nil || !command.NextAttemptAt.Equal(due) || f.provider.shells != 0 {
		t.Fatalf("failed shell delay missing: command=%+v err=%v", command, err)
	}
	f.clock.at = due.Add(-time.Nanosecond)
	if _, err = f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || registry.construct != 1 || registry.preflight != 1 {
		t.Fatalf("early retry err=%v registry=%+v", err, registry)
	}
	f.clock.at, f.provider.preflight = due, nil
	if got, err = f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || got.State != writeintent.Pending || f.provider.shells != 1 {
		t.Fatalf("due shell intent=%+v shells=%d err=%v", got, f.provider.shells, err)
	}
}

func TestExecuteFailedShellRechecksAuthorityBeforeReactivatingIntent(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	lease := f.clock.Now().Add(time.Minute)
	claimed, err := f.store.TransitionIntent(context.Background(), "tenant", intent.ID, intent.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	failed, err := f.store.TransitionIntent(context.Background(), "tenant", intent.ID, claimed.Version, domain.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_refused"}, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	registry := &retryCountingProviders{provider: f.provider}
	f.service.providers = registry
	f.authority.allowed = false
	got, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if !errors.Is(err, shared.ErrForbidden) || got.State != writeintent.Failed || got.Version != failed.Version || registry.construct != 0 || registry.preflight != 0 {
		t.Fatalf("unauthorized failed shell reactivated: intent=%+v err=%v registry=%+v", got, err, registry)
	}
	stored, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil || stored.Intent.State != writeintent.Failed || stored.Intent.Version != failed.Version || !stored.NextAttemptAt.IsZero() {
		t.Fatalf("failed checkpoint mutated: %+v err=%v", stored, err)
	}
}

package docpublish

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type combinedRestrictedProvider struct {
	*releaseProvider
	reads   int
	mutate  func(ports.DocumentRemoteState) ports.DocumentRemoteState
	readErr error
}

func (p *combinedRestrictedProvider) ReadRestrictedDocument(_ context.Context, _, _, _ string) (ports.DocumentRemoteState, error) {
	p.reads++
	if p.readErr != nil {
		return ports.DocumentRemoteState{}, p.readErr
	}
	state := p.page
	if p.mutate != nil {
		state = p.mutate(state)
	}
	return state, nil
}

type combinedRestrictedRegistry struct {
	releaseProviders
	provider ports.DocumentProvider
}

func (r combinedRestrictedRegistry) DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error) {
	return r.provider, nil
}

func advanceReleaseToAttachments(t *testing.T, f *releaseFixture, id shared.ID) {
	t.Helper()
	for step := 0; step < 2; step++ {
		got, err := f.service.Execute(context.Background(), "tenant", id)
		if err != nil || got.State != writeintent.Pending {
			t.Fatalf("advance release step=%d intent=%+v err=%v", step, got, err)
		}
	}
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", id)
	if err != nil || command.Progress.Step != "attachments" {
		t.Fatalf("attachments checkpoint=%+v err=%v", command.Progress, err)
	}
}

func TestSensitiveGuardUsesCombinedRestrictedReaderAndPreservesFallback(t *testing.T) {
	t.Run("combined", func(t *testing.T) {
		f := newReleaseFixture(t)
		intent := f.publish(t)
		advanceReleaseToAttachments(t, f, intent.ID)
		combined := &combinedRestrictedProvider{releaseProvider: f.provider}
		f.service.providers = combinedRestrictedRegistry{releaseProviders: releaseProviders{provider: f.provider}, provider: combined}
		checks := f.provider.checks
		got, err := f.service.Execute(context.Background(), "tenant", intent.ID)
		if err != nil || got.State != writeintent.Pending || combined.reads != 1 || f.provider.checks != checks || f.provider.uploads != 1 {
			t.Fatalf("combined guard intent=%+v reads=%d checks=%d uploads=%d err=%v", got, combined.reads, f.provider.checks-checks, f.provider.uploads, err)
		}
	})
	t.Run("fallback", func(t *testing.T) {
		f := newReleaseFixture(t)
		intent := f.publish(t)
		advanceReleaseToAttachments(t, f, intent.ID)
		checks := f.provider.checks
		got, err := f.service.Execute(context.Background(), "tenant", intent.ID)
		if err != nil || got.State != writeintent.Pending || f.provider.checks != checks+1 || f.provider.uploads != 1 {
			t.Fatalf("fallback guard intent=%+v checks=%d uploads=%d err=%v", got, f.provider.checks-checks, f.provider.uploads, err)
		}
	})
	for _, fault := range []string{"identity", "container", "revision"} {
		t.Run(fault, func(t *testing.T) {
			f := newReleaseFixture(t)
			intent := f.publish(t)
			advanceReleaseToAttachments(t, f, intent.ID)
			combined := &combinedRestrictedProvider{releaseProvider: f.provider, mutate: func(state ports.DocumentRemoteState) ports.DocumentRemoteState {
				switch fault {
				case "identity":
					state.ID = "foreign"
				case "container":
					state.Container = "foreign"
				case "revision":
					state.Revision = "foreign"
				}
				return state
			}}
			f.service.providers = combinedRestrictedRegistry{releaseProviders: releaseProviders{provider: f.provider}, provider: combined}
			got, err := f.service.Execute(context.Background(), "tenant", intent.ID)
			if err != nil || got.State != writeintent.Failed || combined.reads != 1 || f.provider.uploads != 0 || f.provider.writes != 0 {
				t.Fatalf("combined %s intent=%+v reads=%d uploads=%d writes=%d err=%v", fault, got, combined.reads, f.provider.uploads, f.provider.writes, err)
			}
		})
	}
}

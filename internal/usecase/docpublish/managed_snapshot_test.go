package docpublish

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type managedSnapshotProviders struct{ provider *managedSnapshotProvider }

func (p managedSnapshotProviders) DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error) {
	return p.provider, nil
}

func (p managedSnapshotProviders) DocumentReleasePreflighter(context.Context, integration.Integration) (ports.DocumentReleasePreflighter, error) {
	return p.provider, nil
}

type managedSnapshotProvider struct {
	*releaseProvider
	pages     map[string]ports.DocumentRemoteState
	nextID    int
	allocated int
	sent      int
	appended  int
	titled    int
	trashed   int
	ambiguous string
	retry     map[string]int
}

func newManagedSnapshotProvider() *managedSnapshotProvider {
	return &managedSnapshotProvider{releaseProvider: &releaseProvider{sharing: true}, pages: map[string]ports.DocumentRemoteState{}, retry: map[string]int{}}
}

func (*managedSnapshotProvider) DocumentAccessProfile() string {
	return domain.DestinationManagedSnapshotProfile
}

func (*managedSnapshotProvider) ValidateDocumentSnapshot(ports.DocumentArtifact) error { return nil }

func (p *managedSnapshotProvider) CreateDocumentShell(_ context.Context, container, marker string) (domain.RemotePage, error) {
	p.nextID++
	page := domain.RemotePage{ID: fmt.Sprintf("snapshot-%d", p.nextID), Version: 1, URL: fmt.Sprintf("https://www.notion.so/snapshot-%d", p.nextID)}
	p.pages[page.ID] = ports.DocumentRemoteState{RemotePage: page, Container: container, Marker: marker, Neutral: true}
	return page, nil
}

func (p *managedSnapshotProvider) ObserveDocumentDestination(_ context.Context, id, container string) (ports.DocumentRemoteState, error) {
	page, ok := p.pages[id]
	if !ok || page.Container != container || page.Title == "trashed" {
		return ports.DocumentRemoteState{}, errors.New("destination unavailable")
	}
	stage := "pre_trash_guard"
	if page.Neutral {
		stage = "snapshot_observe"
	}
	if err := p.rateLimit(stage); err != nil {
		return ports.DocumentRemoteState{}, err
	}
	return page, nil
}

func (p *managedSnapshotProvider) AllocateDocumentUpload(context.Context, ports.DocumentImage) (string, error) {
	p.allocated++
	return fmt.Sprintf("upload-%d", p.allocated), nil
}

func (p *managedSnapshotProvider) SendDocumentUpload(context.Context, string, ports.DocumentImage) error {
	p.sent++
	if p.ambiguous == "send" {
		return &ports.DocumentProviderError{Code: "network", Ambiguous: true}
	}
	return nil
}

func (p *managedSnapshotProvider) AppendDocumentSnapshot(_ context.Context, remote domain.RemotePage, artifact ports.DocumentArtifact, _ []ports.DocumentUploadReceipt, _ string, contentHash string) (ports.DocumentSnapshotReceipt, error) {
	p.appended++
	if p.ambiguous == "append" {
		return ports.DocumentSnapshotReceipt{}, &ports.DocumentProviderError{Code: "network", Ambiguous: true}
	}
	page := p.pages[remote.ID]
	page.Version++
	page.Title = artifact.Title
	page.Neutral = false
	p.pages[remote.ID] = page
	return ports.DocumentSnapshotReceipt{BlockIDs: []string{"block-1"}, Digest: contentHash, Remote: page.RemotePage}, nil
}

func (p *managedSnapshotProvider) SetDocumentSnapshotTitle(_ context.Context, remote domain.RemotePage, title string) (domain.RemotePage, error) {
	p.titled++
	page := p.pages[remote.ID]
	page.Version++
	page.Title = title
	p.pages[remote.ID] = page
	return page.RemotePage, nil
}

func (p *managedSnapshotProvider) VerifyDocumentSnapshot(_ context.Context, id string, receipt ports.DocumentSnapshotReceipt, marker string) (domain.RemotePage, error) {
	if err := p.rateLimit("snapshot_verify"); err != nil {
		return domain.RemotePage{}, err
	}
	page, ok := p.pages[id]
	if !ok || page.Marker != marker || page.RemotePage != receipt.Remote || page.Neutral {
		return domain.RemotePage{}, errors.New("snapshot cannot be verified")
	}
	return page.RemotePage, nil
}

func (p *managedSnapshotProvider) TrashDocument(_ context.Context, remote domain.RemotePage) error {
	p.trashed++
	page := p.pages[remote.ID]
	page.Title = "trashed"
	p.pages[remote.ID] = page
	return nil
}

func (p *managedSnapshotProvider) ConfirmDocumentTrash(_ context.Context, id, _ string) (bool, error) {
	if err := p.rateLimit("trash_confirm"); err != nil {
		return false, err
	}
	page, ok := p.pages[id]
	return ok && page.Title == "trashed", nil
}

func (p *managedSnapshotProvider) rateLimit(stage string) error {
	if p.retry[stage] < 1 {
		return nil
	}
	p.retry[stage]--
	return &ports.DocumentProviderError{Code: "rate_limited", Status: 429, RetryAfter: 2 * time.Minute}
}

type managedSnapshotFixture struct {
	*releaseFixture
	provider *managedSnapshotProvider
}

func newManagedSnapshotFixture(t *testing.T) *managedSnapshotFixture {
	t.Helper()
	base := newReleaseFixture(t)
	base.integration.item.Provider = "notion"
	base.integration.item.Config = []byte(`{"space":"workspace","read_group":"destination-owner","data_class":"detail","publication_profile":"destination_managed_snapshot_v1"}`)
	provider := newManagedSnapshotProvider()
	service, err := NewService(base.store, base.integration, managedSnapshotProviders{provider}, base.source, base.authority, base.policy, base.audit, &releaseIDs{}, base.clock)
	if err != nil {
		t.Fatal(err)
	}
	base.service = service
	return &managedSnapshotFixture{releaseFixture: base, provider: provider}
}

func (f *managedSnapshotFixture) executeUntilTerminal(t *testing.T, executor interface {
	Execute(context.Context, shared.ID, shared.ID) (domain.Intent, error)
}, id shared.ID) domain.Intent {
	t.Helper()
	for n := 0; n < 32; n++ {
		intent, err := executor.Execute(context.Background(), "tenant", id)
		if err != nil {
			t.Fatal(err)
		}
		if intent.State != writeintent.Pending {
			return intent
		}
	}
	t.Fatalf("managed snapshot %s did not finish", id)
	return domain.Intent{}
}

func TestManagedSnapshotPublishesImmutablePagesAcrossRestartAndRepublish(t *testing.T) {
	f := newManagedSnapshotFixture(t)
	first := f.publish(t)
	// Shell, observation, allocation and send all return durable checkpoints.
	for n := 0; n < 4; n++ {
		if result, err := f.service.Execute(context.Background(), "tenant", first.ID); err != nil || result.State != writeintent.Pending {
			t.Fatalf("checkpoint %d result=%+v err=%v", n, result, err)
		}
	}
	if f.provider.allocated != 1 || f.provider.sent != 1 || f.provider.appended != 0 {
		t.Fatalf("unexpected effects before restart: %+v", f.provider)
	}
	executor, err := NewExecutor(f.store, f.integration, managedSnapshotProviders{f.provider}, f.authority, f.policy, f.audit, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	done := f.executeUntilTerminal(t, executor, first.ID)
	if done.State != writeintent.Done || f.provider.allocated != 1 || f.provider.sent != 1 || f.provider.appended != 1 || f.provider.titled != 1 {
		t.Fatalf("restart repeated a checkpoint or did not complete: intent=%+v provider=%+v", done, f.provider)
	}
	link, err := f.store.FindLink(context.Background(), "tenant", done.Target)
	if err != nil || link.ID != first.ID || link.RemotePageID != done.RemoteID || link.Revision != 1 {
		t.Fatalf("first snapshot link=%+v err=%v", link, err)
	}

	f.source.artifact.Paragraphs = []string{"changed immutable report"}
	f.input.RequestKey = "publish-managed-next"
	second := f.publish(t)
	if second.Action != domain.Snapshot || second.LinkID != link.ID || second.ExpectedLinkRevision != link.Revision {
		t.Fatalf("republish did not fence current link: %+v", second)
	}
	next := f.executeUntilTerminal(t, f.service, second.ID)
	updated, err := f.store.GetLink(context.Background(), "tenant", link.ID)
	if err != nil || next.State != writeintent.Done || updated.ID != link.ID || updated.RemotePageID == link.RemotePageID || updated.Revision != 2 {
		t.Fatalf("republish did not advance the same link to a new page: next=%+v link=%+v err=%v", next, updated, err)
	}
}

func TestManagedSnapshotQuarantinesAmbiguousWritesAndRevokedAuthority(t *testing.T) {
	for _, operation := range []string{"send", "append"} {
		t.Run(operation, func(t *testing.T) {
			f := newManagedSnapshotFixture(t)
			intent := f.publish(t)
			f.provider.ambiguous = operation
			result := f.executeUntilTerminal(t, f.service, intent.ID)
			command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
			wantOutstanding := "snapshot_upload_" + operation
			if operation == "append" {
				wantOutstanding = "snapshot_append"
			}
			if err != nil || result.State != writeintent.Uncertain || command.Progress.OutstandingOperation != wantOutstanding || command.Progress.OutstandingKey == "" {
				t.Fatalf("ambiguous %s lost its durable fence: intent=%+v progress=%+v err=%v", operation, result, command.Progress, err)
			}
			before := f.provider.allocated + f.provider.sent + f.provider.appended
			again, err := f.service.Execute(context.Background(), "tenant", intent.ID)
			if err != nil || again.State != writeintent.Uncertain || f.provider.allocated+f.provider.sent+f.provider.appended != before {
				t.Fatalf("ambiguous %s was retried: intent=%+v err=%v", operation, again, err)
			}
		})
	}

	f := newManagedSnapshotFixture(t)
	intent := f.publish(t)
	if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil { // shell
		t.Fatal(err)
	}
	if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil { // observe
		t.Fatal(err)
	}
	if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil { // allocate
		t.Fatal(err)
	}
	f.authority.allowed = false
	_, _ = f.service.Execute(context.Background(), "tenant", intent.ID)
	if f.provider.allocated != 1 || f.provider.sent != 0 || f.provider.appended != 0 {
		t.Fatalf("authority revocation allowed sensitive write: provider=%+v", f.provider)
	}
}

func TestManagedSnapshotTrashRequiresConfirmationAndMonitorReportsDestinationManaged(t *testing.T) {
	f := newManagedSnapshotFixture(t)
	intent := f.publish(t)
	done := f.executeUntilTerminal(t, f.service, intent.ID)
	link, err := f.store.FindLink(context.Background(), "tenant", done.Target)
	if err != nil {
		t.Fatal(err)
	}

	f.clock.at = f.clock.at.Add(16 * time.Minute)
	if err = f.service.Tick(context.Background(), "tenant", 1); err != nil {
		t.Fatal(err)
	}
	links, err := f.service.Links(context.Background(), "tenant", domain.Engagement, "assessment")
	if err != nil || len(links) != 1 || links[0].RestrictionStatus != "destination_managed" {
		t.Fatalf("managed destination was represented as verified access: links=%+v err=%v", links, err)
	}
	if _, err := f.service.PublishArtifact(context.Background(), "tenant", f.actor, f.input, f.source.artifact); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("schedule artifact admitted to managed destination: %v", err)
	}

	trash, err := f.service.Unpublish(context.Background(), "tenant", f.actor, link.ID, "trash-managed")
	if err != nil || trash.Intent.Action != domain.Trash || trash.Intent.ExpectedLinkRevision != link.Revision {
		t.Fatalf("managed unpublish=%+v err=%v", trash, err)
	}
	retired := f.executeUntilTerminal(t, f.service, trash.Intent.ID)
	current, err := f.store.GetLink(context.Background(), "tenant", link.ID)
	if err != nil || retired.State != writeintent.Done || f.provider.trashed != 1 || current.RetiredAt == nil || current.RemovalKind != domain.RemovalTrash {
		t.Fatalf("trash did not wait for exact confirmation: intent=%+v link=%+v provider=%+v err=%v", retired, current, f.provider, err)
	}
}

func TestManagedSnapshotDefersReadRateLimitsWithoutRepeatingAcknowledgedWrites(t *testing.T) {
	t.Run("snapshot observation", func(t *testing.T) {
		f := newManagedSnapshotFixture(t)
		intent := f.publish(t)
		if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil { // shell
			t.Fatal(err)
		}
		f.provider.retry["snapshot_observe"] = 1
		due := managedReadDeferred(t, f, intent.ID, 1, 0, 0, 0, 0)
		f.clock.at = due
		if done := f.executeUntilTerminal(t, f.service, intent.ID); done.State != writeintent.Done || f.provider.nextID != 1 || f.provider.allocated != 1 || f.provider.sent != 1 || f.provider.appended != 1 || f.provider.titled != 1 {
			t.Fatalf("observation retry replayed an acknowledged write: intent=%+v provider=%+v", done, f.provider)
		}
	})

	t.Run("snapshot verification", func(t *testing.T) {
		f := newManagedSnapshotFixture(t)
		intent := f.publish(t)
		advanceManagedToStep(t, f, intent.ID, "snapshot_verify")
		f.provider.retry["snapshot_verify"] = 1
		due := managedReadDeferred(t, f, intent.ID, 1, 1, 1, 1, 0)
		f.clock.at = due
		if done := f.executeUntilTerminal(t, f.service, intent.ID); done.State != writeintent.Done || f.provider.nextID != 1 || f.provider.allocated != 1 || f.provider.sent != 1 || f.provider.appended != 1 || f.provider.titled != 1 {
			t.Fatalf("verification retry replayed an acknowledged write: intent=%+v provider=%+v", done, f.provider)
		}
	})

	for _, scenario := range []struct {
		name            string
		stage           string
		prepareTrash    func(*testing.T, *managedSnapshotFixture, shared.ID) shared.ID
		trashBeforeRate int
	}{
		{
			name:  "pre-trash destination guard",
			stage: "pre_trash_guard",
			prepareTrash: func(t *testing.T, f *managedSnapshotFixture, publishedID shared.ID) shared.ID {
				published, err := f.store.GetDocumentCommand(context.Background(), "tenant", publishedID)
				if err != nil {
					t.Fatal(err)
				}
				link, err := f.store.FindLink(context.Background(), "tenant", published.Intent.Target)
				if err != nil {
					t.Fatal(err)
				}
				unpublish, err := f.service.Unpublish(context.Background(), "tenant", f.actor, link.ID, "rate-limit-pre-trash")
				if err != nil {
					t.Fatal(err)
				}
				return unpublish.Intent.ID
			},
		},
		{
			name:  "trash confirmation",
			stage: "trash_confirm",
			prepareTrash: func(t *testing.T, f *managedSnapshotFixture, publishedID shared.ID) shared.ID {
				published, err := f.store.GetDocumentCommand(context.Background(), "tenant", publishedID)
				if err != nil {
					t.Fatal(err)
				}
				link, err := f.store.FindLink(context.Background(), "tenant", published.Intent.Target)
				if err != nil {
					t.Fatal(err)
				}
				unpublish, err := f.service.Unpublish(context.Background(), "tenant", f.actor, link.ID, "rate-limit-confirm-trash")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.service.Execute(context.Background(), "tenant", unpublish.Intent.ID); err != nil { // trash
					t.Fatal(err)
				}
				return unpublish.Intent.ID
			},
			trashBeforeRate: 1,
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newManagedSnapshotFixture(t)
			published := f.publish(t)
			if done := f.executeUntilTerminal(t, f.service, published.ID); done.State != writeintent.Done {
				t.Fatalf("publish=%+v", done)
			}
			commandID := scenario.prepareTrash(t, f, published.ID)
			f.provider.retry[scenario.stage] = 1
			due := managedReadDeferred(t, f, commandID, 1, 1, 1, 1, scenario.trashBeforeRate)
			f.clock.at = due
			if done := f.executeUntilTerminal(t, f.service, commandID); done.State != writeintent.Done || f.provider.nextID != 1 || f.provider.allocated != 1 || f.provider.sent != 1 || f.provider.appended != 1 || f.provider.titled != 1 || f.provider.trashed != 1 {
				t.Fatalf("%s retry replayed a managed write: intent=%+v provider=%+v", scenario.name, done, f.provider)
			}
		})
	}
}

func advanceManagedToStep(t *testing.T, f *managedSnapshotFixture, id shared.ID, want string) {
	t.Helper()
	for n := 0; n < 16; n++ {
		command, err := f.store.GetDocumentCommand(context.Background(), "tenant", id)
		if err != nil {
			t.Fatal(err)
		}
		if command.Progress.Step == want {
			return
		}
		if _, err = f.service.Execute(context.Background(), "tenant", id); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatalf("managed command %s did not reach %s", id, want)
}

func managedReadDeferred(t *testing.T, f *managedSnapshotFixture, id shared.ID, shells, allocated, sent, appended, trashed int) time.Time {
	t.Helper()
	if result, err := f.service.Execute(context.Background(), "tenant", id); err != nil || result.State != writeintent.Pending {
		t.Fatalf("rate-limit execution result=%+v err=%v", result, err)
	}
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", id)
	if err != nil || command.NextAttemptAt.IsZero() || !command.NextAttemptAt.Equal(f.clock.at.Add(2*time.Minute)) || command.Intent.Attempts != 0 || f.provider.nextID != shells || f.provider.allocated != allocated || f.provider.sent != sent || f.provider.appended != appended || f.provider.trashed != trashed {
		t.Fatalf("read throttle was not durably deferred without remote mutation: command=%+v provider=%+v err=%v", command, f.provider, err)
	}
	if early, err := f.service.Execute(context.Background(), "tenant", id); err != nil || early.State != writeintent.Pending || f.provider.nextID != shells || f.provider.allocated != allocated || f.provider.sent != sent || f.provider.appended != appended || f.provider.trashed != trashed {
		t.Fatalf("early retry bypassed read throttle: intent=%+v provider=%+v err=%v", early, f.provider, err)
	}
	return command.NextAttemptAt
}

package docpublish

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type releaseClock struct{ at time.Time }

func (c *releaseClock) Now() time.Time { return c.at }

type releaseIDs struct{ n int }

func (i *releaseIDs) NewID() shared.ID { i.n++; return shared.ID(fmt.Sprintf("release-%d", i.n)) }

type releaseAuthority struct{ allowed bool }

func (a *releaseAuthority) CanReleaseDocument(context.Context, shared.ID, ports.DocumentActor) (bool, error) {
	return a.allowed, nil
}

type releasePolicy struct{ err error }

func (p *releasePolicy) CheckDocumentSource(context.Context, shared.ID, domain.Target) error {
	return p.err
}

type releaseIntegration struct {
	ports.IntegrationStore
	item integration.Integration
}

func (i *releaseIntegration) GetIntegration(context.Context, shared.ID) (integration.Integration, error) {
	return i.item, nil
}

type releaseSource struct {
	artifact ports.DocumentArtifact
	calls    int
}

func (s *releaseSource) BuildDocumentArtifact(context.Context, shared.ID, domain.Target) (ports.DocumentArtifact, error) {
	s.calls++
	return s.artifact, nil
}

type releaseAudit struct{ entries []ports.AuditEntry }

func (a *releaseAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type strictReleaseAudit struct{ entries map[string]ports.AuditEntry }

func (a *strictReleaseAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	key := entry.Metadata["idempotency_key"]
	if existing, ok := a.entries[key]; ok {
		if !reflect.DeepEqual(existing, entry) {
			return shared.ErrConflict
		}
		return nil
	}
	a.entries[key] = entry
	return nil
}

type releaseProviders struct{ provider *releaseProvider }

func (p releaseProviders) DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error) {
	return p.provider, nil
}

func (p releaseProviders) DocumentReleasePreflighter(context.Context, integration.Integration) (ports.DocumentReleasePreflighter, error) {
	return p.provider, nil
}

type releaseProvider struct {
	page                                                      ports.DocumentRemoteState
	shells, restrictions, uploads, writes, purges, checks     int
	restricted, sharing, refuseRestrictions, refuseAttachment bool
	ambiguous                                                 string
	partialRefusal                                            bool
	afterVerify                                               func()
	afterUpload                                               func()
	files                                                     []string
	preflight                                                 error
	opaque                                                    bool
	partialNeutral                                            bool
	revisionWrites                                            int
}

func (p *releaseProvider) CheckDocumentRelease(context.Context, string, string) error {
	return p.preflight
}

func (p *releaseProvider) CreateDocumentShell(_ context.Context, space, marker string) (domain.RemotePage, error) {
	p.shells++
	page := domain.RemotePage{ID: "123", Version: 1, URL: "https://lab.atlassian.net/wiki/spaces/LAB/pages/123"}
	if p.opaque && !p.partialNeutral {
		page.Revision = "opaque-shell"
	}
	p.page = ports.DocumentRemoteState{RemotePage: page, Container: space, Marker: marker, Neutral: true, Title: "Synapse publication in progress"}
	if p.ambiguous == "shell" {
		p.ambiguous = ""
		return domain.RemotePage{}, &ports.DocumentProviderError{Code: "network", Ambiguous: true}
	}
	return p.page.RemotePage, nil
}
func (p *releaseProvider) RestrictDocument(context.Context, string, string) error {
	if p.refuseRestrictions {
		return &ports.DocumentProviderError{Code: "destination_acl", Status: 400}
	}
	p.restrictions++
	p.restricted = true
	if p.partialNeutral {
		p.page.Revision = "opaque-restricted"
	}
	if p.ambiguous == "restrictions" {
		p.ambiguous = ""
		return &ports.DocumentProviderError{Code: "network", Ambiguous: true}
	}
	return nil
}
func (p *releaseProvider) VerifyDocumentRestriction(context.Context, string, string, string) error {
	p.checks++
	if !p.restricted || !p.sharing {
		return &ports.DocumentProviderError{Code: "public_sharing_unverifiable", Status: 403}
	}
	if p.afterVerify != nil {
		p.afterVerify()
	}
	return nil
}
func (p *releaseProvider) GetDocument(context.Context, string) (ports.DocumentRemoteState, error) {
	return p.page, nil
}
func (p *releaseProvider) FindDocumentMarker(context.Context, string, string) ([]ports.DocumentRemoteState, error) {
	if p.page.ID == "" {
		return nil, nil
	}
	return []ports.DocumentRemoteState{p.page}, nil
}
func (p *releaseProvider) UploadDocumentAttachment(_ context.Context, _ string, image ports.DocumentImage) error {
	if !p.restricted || !p.sharing || p.checks == 0 {
		return errors.New("unprotected upload")
	}
	if p.refuseAttachment {
		return &ports.DocumentProviderError{Code: "attachment_acl", Status: 400}
	}
	p.uploads++
	p.files = append(p.files, image.Name)
	if p.afterUpload != nil {
		p.afterUpload()
	}
	if p.ambiguous == "attachment" {
		p.ambiguous = ""
		if p.partialRefusal {
			return &ports.DocumentProviderError{Code: "attachment_ownership_incomplete", Status: 412, Ambiguous: true}
		}
		return &ports.DocumentProviderError{Code: "network", Ambiguous: true}
	}
	return nil
}
func (p *releaseProvider) WriteDocument(_ context.Context, _ string, version int, title, storage, marker string) (domain.RemotePage, error) {
	if p.opaque {
		return domain.RemotePage{}, &ports.DocumentProviderError{Code: "numeric_write_used", Status: 409}
	}
	if version != p.page.Version {
		return domain.RemotePage{}, &ports.DocumentProviderError{Code: "conflict", Status: 409}
	}
	p.writes++
	p.page.Version++
	p.page.Title = title
	p.page.Storage = storage
	p.page.Marker = marker
	p.page.Neutral = false
	if p.ambiguous == "body" {
		p.ambiguous = ""
		return domain.RemotePage{}, &ports.DocumentProviderError{Code: "network", Ambiguous: true}
	}
	return p.page.RemotePage, nil
}
func (p *releaseProvider) WriteDocumentRevision(_ context.Context, expected domain.RemotePage, title, storage, marker string) (domain.RemotePage, error) {
	if !p.opaque || expected.ID != p.page.ID || expected.Revision != p.page.Revision {
		return domain.RemotePage{}, &ports.DocumentProviderError{Code: "conflict", Status: 409}
	}
	p.revisionWrites++
	p.page.Revision = "opaque-body"
	p.page.Title = title
	p.page.Storage = storage
	p.page.Marker = marker
	p.page.Neutral = false
	if p.ambiguous == "body" {
		p.ambiguous = ""
		return domain.RemotePage{}, &ports.DocumentProviderError{Code: "network", Ambiguous: true}
	}
	return p.page.RemotePage, nil
}
func (p *releaseProvider) PurgeDocument(ctx context.Context, _ string, guard func(context.Context) error) error {
	if err := guard(ctx); err != nil {
		return err
	}
	p.purges++
	if p.ambiguous == "purge" {
		p.ambiguous = ""
		return &ports.DocumentProviderError{Code: "purge_incomplete", Status: 403, Ambiguous: true}
	}
	return nil
}
func (p *releaseProvider) ValidateDocumentText(text string) error {
	if strings.Contains(text, "configured-token") {
		return &ports.DocumentProviderError{Code: "credential_in_payload"}
	}
	return nil
}

type releaseFixture struct {
	service     *Service
	store       *memory.DocumentStore
	source      *releaseSource
	provider    *releaseProvider
	authority   *releaseAuthority
	policy      *releasePolicy
	integration *releaseIntegration
	clock       *releaseClock
	audit       *releaseAudit
	actor       ports.DocumentActor
	input       PublishInput
}

type documentCommandMutator struct {
	ports.DocumentCommandStore
	mutate func(*ports.DocumentCommand)
}

type failOnceDocumentTransitionStore struct {
	ports.DocumentCommandStore
	failed bool
}

type failCleanDocumentCheckpointStore struct {
	ports.DocumentCommandStore
	fail bool
}

func (s *failCleanDocumentCheckpointStore) SaveDocumentProgress(ctx context.Context, tenant, id shared.ID, version int, progress ports.DocumentProgress) (ports.DocumentCommand, error) {
	if s.fail && progress.OutstandingOperation == "" {
		return ports.DocumentCommand{}, shared.ErrConflict
	}
	return s.DocumentCommandStore.SaveDocumentProgress(ctx, tenant, id, version, progress)
}

func (s *failOnceDocumentTransitionStore) TransitionIntent(ctx context.Context, tenant, id shared.ID, version int, change domain.IntentTransition, at time.Time) (domain.Intent, error) {
	if !s.failed {
		s.failed = true
		return domain.Intent{}, shared.ErrConflict
	}
	return s.DocumentCommandStore.TransitionIntent(ctx, tenant, id, version, change, at)
}

func (s documentCommandMutator) GetDocumentCommand(ctx context.Context, tenant, id shared.ID) (ports.DocumentCommand, error) {
	command, err := s.DocumentCommandStore.GetDocumentCommand(ctx, tenant, id)
	if err == nil && s.mutate != nil {
		s.mutate(&command)
	}
	return command, err
}

func newReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	clock := &releaseClock{at: time.Date(2026, 10, 17, 1, 0, 0, 0, time.UTC)}
	engs := memory.NewEngagementRepository()
	projects := memory.NewProjectRepository()
	eng, err := engagement.New("assessment", "tenant", "Đánh giá bảo mật", "Lab", clock.at)
	if err != nil {
		t.Fatal(err)
	}
	if err = engs.Create(shared.WithTenant(context.Background(), "tenant"), eng); err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewDocumentStore(engs, projects)
	if err != nil {
		t.Fatal(err)
	}
	f := &releaseFixture{store: store, clock: clock, actor: ports.DocumentActor{UserID: "reviewer"}, authority: &releaseAuthority{allowed: true}, policy: &releasePolicy{}, provider: &releaseProvider{sharing: true}, audit: &releaseAudit{}, source: &releaseSource{artifact: ports.DocumentArtifact{Title: "Báo cáo <bảo mật>", Paragraphs: []string{"Dữ liệu lưu trữ & đã kiểm chứng"}, PDF: []byte("%PDF-1.7\nverified stored report"), EvidenceHead: strings.Repeat("a", 64), SourceRevision: "stored-revision", GeneratedAt: clock.at}}, integration: &releaseIntegration{item: integration.Integration{ID: "connection", TenantID: "tenant", Provider: "confluence-cloud", Endpoint: "https://lab.atlassian.net", Config: []byte(`{"space":"LAB","read_group":"restricted-group","data_class":"detail"}`), Enabled: true, ConnectionRevision: 1, CredentialRevision: 1}}}
	f.service, err = NewService(store, f.integration, releaseProviders{f.provider}, f.source, f.authority, f.policy, f.audit, &releaseIDs{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	f.input = PublishInput{IntegrationID: "connection", SourceKind: domain.EngagementReport, ScopeID: "assessment", SourceRef: EngagementSourceRef("assessment"), RequestKey: "publish-original"}
	return f
}
func (f *releaseFixture) publish(t *testing.T) domain.Intent {
	t.Helper()
	result, err := f.service.Publish(context.Background(), "tenant", f.actor, f.input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Intent == nil {
		t.Fatal("missing admitted intent")
	}
	return *result.Intent
}

func (f *releaseFixture) executeUntilNotPending(t *testing.T, id shared.ID) domain.Intent {
	t.Helper()
	for n := 0; n < 32; n++ {
		intent, err := f.service.Execute(context.Background(), "tenant", id)
		if err != nil {
			t.Fatal(err)
		}
		if intent.State != writeintent.Pending {
			return intent
		}
	}
	t.Fatalf("document command %s remained pending after bounded slices", id)
	return domain.Intent{}
}

func TestDocumentReleasePublishesUpdatesSkipsAndPurgesSamePage(t *testing.T) {
	f := newReleaseFixture(t)
	ctx := context.Background()
	intent := f.publish(t)
	done := f.executeUntilNotPending(t, intent.ID)
	if done.State != writeintent.Done {
		t.Fatalf("publish=%+v", done)
	}
	if f.provider.shells != 1 || f.provider.uploads != 1 || f.provider.writes != 1 || f.provider.checks < 3 {
		t.Fatalf("writes before verified sharing or wrong operation counts: %+v", f.provider)
	}
	if strings.Contains(f.provider.page.Storage, "<bảo mật>") || !strings.Contains(f.provider.page.Storage, "&lt;bảo mật&gt;") || !strings.Contains(f.provider.page.Storage, strings.Repeat("a", 64)) {
		t.Fatalf("unsafe or missing stored projection: %s", f.provider.page.Storage)
	}
	replay, err := f.service.Publish(ctx, "tenant", f.actor, f.input)
	if err != nil || replay.Intent.ID != intent.ID {
		t.Fatalf("exact replay=%+v %v", replay, err)
	}
	f.input.RequestKey = "unchanged"
	skip, err := f.service.Publish(ctx, "tenant", f.actor, f.input)
	if err != nil || !skip.Skipped {
		t.Fatalf("hash-equal skip=%+v %v", skip, err)
	}
	f.source.artifact.Paragraphs = []string{"Phiên bản mới"}
	f.input.RequestKey = "publish-next"
	next := f.publish(t)
	updated := f.executeUntilNotPending(t, next.ID)
	if updated.State != writeintent.Done || updated.RemoteID != done.RemoteID || updated.RemoteVersion != done.RemoteVersion+1 || f.provider.shells != 1 {
		t.Fatalf("republish=%+v", updated)
	}
	link, err := f.store.FindLink(ctx, "tenant", done.Target)
	if err != nil {
		t.Fatal(err)
	}
	unpublish, err := f.service.Unpublish(ctx, "tenant", f.actor, link.ID, "purge")
	if err != nil {
		t.Fatal(err)
	}
	purged := f.executeUntilNotPending(t, unpublish.Intent.ID)
	if purged.State != writeintent.Done || f.provider.purges != 1 {
		t.Fatalf("purge=%+v", purged)
	}
	retired, err := f.store.GetLink(ctx, "tenant", link.ID)
	if err != nil || retired.RetiredAt == nil {
		t.Fatalf("retirement=%+v %v", retired, err)
	}
	f.input.RequestKey = "after-purge"
	if _, err := f.service.Publish(ctx, "tenant", f.actor, f.input); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("retired target recreated: %v", err)
	}
}

func TestDocumentReleaseRefusesUnverifiedSharingAndCurrentAuthorityChanges(t *testing.T) {
	for _, scenario := range []string{"sharing", "role", "legal_hold", "destination"} {
		t.Run(scenario, func(t *testing.T) {
			f := newReleaseFixture(t)
			intent := f.publish(t)
			switch scenario {
			case "sharing":
				f.provider.sharing = false
			case "role":
				f.authority.allowed = false
			case "legal_hold":
				f.provider.afterVerify = func() { f.policy.err = shared.ErrForbidden }
			case "destination":
				f.integration.item.ConnectionRevision++
			}
			_, _ = f.service.Execute(context.Background(), "tenant", intent.ID)
			if f.provider.uploads != 0 || f.provider.writes != 0 {
				t.Fatalf("sensitive write after %s changed: %+v", scenario, f.provider)
			}
		})
	}
}

func TestDocumentReleaseKeepsPartialUploadAndPurgeQuarantined(t *testing.T) {
	for _, operation := range []string{"attachment", "purge"} {
		t.Run(operation, func(t *testing.T) {
			f := newReleaseFixture(t)
			intent := f.publish(t)
			var linkID shared.ID
			if operation == "purge" {
				published := f.executeUntilNotPending(t, intent.ID)
				link, err := f.store.FindLink(context.Background(), "tenant", published.Target)
				if err != nil {
					t.Fatal(err)
				}
				linkID = link.ID
				result, err := f.service.Unpublish(context.Background(), "tenant", f.actor, link.ID, "purge-partial")
				if err != nil {
					t.Fatal(err)
				}
				intent = *result.Intent
			}
			f.provider.ambiguous, f.provider.partialRefusal = operation, true
			uncertain := f.executeUntilNotPending(t, intent.ID)
			command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
			if err != nil || uncertain.State != writeintent.Uncertain || command.Progress.OutstandingOperation != operation || command.Progress.OutstandingKey == "" {
				t.Fatalf("partial effect lost its fence: intent=%+v progress=%+v err=%v", uncertain, command.Progress, err)
			}
			before := f.provider.uploads + f.provider.purges + f.provider.writes
			reconciled, err := f.service.Execute(context.Background(), "tenant", intent.ID)
			if err != nil || reconciled.State != writeintent.Uncertain || f.provider.uploads+f.provider.purges+f.provider.writes != before {
				t.Fatalf("partial effect was retried or completed: intent=%+v err=%v", reconciled, err)
			}
			if operation == "purge" {
				link, err := f.store.GetLink(context.Background(), "tenant", linkID)
				if err != nil || link.RetiredAt != nil {
					t.Fatalf("partial purge retired the link: %+v err=%v", link, err)
				}
			} else if _, err := f.store.FindLink(context.Background(), "tenant", intent.Target); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("partial upload became a published link: %v", err)
			}
		})
	}
}

func TestDocumentReleaseYieldsOneAcknowledgedEffectPerInvocation(t *testing.T) {
	f := newReleaseFixture(t)
	// Exercise the artifact maximum: one PDF and ten verified images must be
	// released in independent durable slices, not in one long-held lease.
	pdf := make([]byte, maxArtifactPDFBytes)
	copy(pdf, "%PDF-1.7\n")
	f.source.artifact.PDF = pdf
	f.source.artifact.Images = make([]ports.DocumentImage, 0, maxArtifactImages)
	for n := 0; n < maxArtifactImages; n++ {
		f.source.artifact.Images = append(f.source.artifact.Images, ports.DocumentImage{
			Name: fmt.Sprintf("evidence-%d.png", n), MediaType: "image/png", Data: []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'},
		})
	}
	intent := f.publish(t)
	previousEffects := 0
	for tick := 0; tick < 32; tick++ {
		result, err := f.service.Execute(context.Background(), "tenant", intent.ID)
		if err != nil {
			t.Fatal(err)
		}
		effects := f.provider.shells + f.provider.restrictions + f.provider.uploads + f.provider.writes + f.provider.purges
		if effects-previousEffects > 1 {
			t.Fatalf("tick %d acknowledged %d provider effects", tick, effects-previousEffects)
		}
		previousEffects = effects
		if result.State == writeintent.Done {
			if f.provider.uploads != 1+maxArtifactImages || f.provider.shells != 1 || f.provider.writes != 1 {
				t.Fatalf("bounded artifact operations=%+v", f.provider)
			}
			return
		}
		if result.State != writeintent.Pending || result.Attempts != 0 {
			t.Fatalf("successful slice was not immediately requeueable: %+v", result)
		}
	}
	t.Fatal("maximum artifact did not complete in bounded slices")
}

func TestDocumentReleaseSuccessfulSlicesDoNotExhaustFailureBudget(t *testing.T) {
	f := newReleaseFixture(t)
	for n := 0; n < maxArtifactImages; n++ {
		f.source.artifact.Images = append(f.source.artifact.Images, ports.DocumentImage{
			Name: fmt.Sprintf("evidence-%d.png", n), MediaType: "image/png", Data: []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'},
		})
	}
	intent := f.publish(t)
	// Shell, restriction, PDF, and five image uploads have each yielded a
	// clean checkpoint. The later definite refusal remains the first failure.
	for n := 0; n < 8; n++ {
		result, err := f.service.Execute(context.Background(), "tenant", intent.ID)
		if err != nil || result.State != writeintent.Pending || result.Attempts != 0 {
			t.Fatalf("successful slice %d result=%+v err=%v", n, result, err)
		}
	}
	f.provider.refuseAttachment = true
	failed, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || failed.State != writeintent.Failed || failed.Attempts != 1 || f.provider.uploads != 6 {
		t.Fatalf("failure after successful slices=%+v err=%v provider=%+v", failed, err, f.provider)
	}
}

func TestDocumentReleaseCheckpointsAcknowledgedUploadAfterCallerCancellation(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	// Advance through shell and sharing setup before cancelling from the upload
	// acknowledgement itself.
	for n := 0; n < 2; n++ {
		if result, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || result.State != writeintent.Pending {
			t.Fatalf("setup slice %d result=%+v err=%v", n, result, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.provider.afterUpload = cancel
	result, err := f.service.Execute(ctx, "tenant", intent.ID)
	if err != nil || result.State != writeintent.Pending || f.provider.uploads != 1 {
		t.Fatalf("canceled acknowledgement result=%+v err=%v provider=%+v", result, err, f.provider)
	}
	f.provider.afterUpload = nil
	completed := f.executeUntilNotPending(t, intent.ID)
	if completed.State != writeintent.Done || f.provider.uploads != 1 {
		t.Fatalf("upload repeated after cancelled caller: completed=%+v provider=%+v", completed, f.provider)
	}
}

func TestDocumentReleaseRefreshesOpaqueRevisionAfterPartialNeutralShellRestriction(t *testing.T) {
	f := newReleaseFixture(t)
	f.provider.opaque = true
	f.provider.partialNeutral = true
	intent := f.publish(t)
	completed := f.executeUntilNotPending(t, intent.ID)
	if completed.State != writeintent.Done || completed.RemoteRevision != "opaque-body" || f.provider.revisionWrites != 1 || f.provider.shells != 1 {
		t.Fatalf("partial shell did not converge safely: completed=%+v provider=%+v", completed, f.provider)
	}
}

func TestDocumentReleaseReconcilesLostPartialNeutralRestrictionAcknowledgement(t *testing.T) {
	f := newReleaseFixture(t)
	f.provider.opaque = true
	f.provider.partialNeutral = true
	f.provider.ambiguous = "restrictions"
	intent := f.publish(t)
	if first, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || first.State != writeintent.Pending {
		t.Fatalf("shell=%+v err=%v", first, err)
	}
	uncertain, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || uncertain.State != writeintent.Uncertain || f.provider.page.Revision != "opaque-restricted" {
		t.Fatalf("lost restriction acknowledgement=%+v err=%v provider=%+v", uncertain, err, f.provider)
	}
	resumed, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || resumed.State != writeintent.Pending {
		t.Fatalf("restriction reconciliation=%+v err=%v", resumed, err)
	}
	checkpoint, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil || checkpoint.Progress.Step != "attachments" || checkpoint.Progress.Remote.Revision != "opaque-restricted" {
		t.Fatalf("reconciled checkpoint=%+v err=%v", checkpoint.Progress, err)
	}
	completed := f.executeUntilNotPending(t, intent.ID)
	if completed.State != writeintent.Done || completed.RemoteRevision != "opaque-body" || f.provider.restrictions != 1 {
		t.Fatalf("partial restriction was repeated or did not complete: completed=%+v provider=%+v", completed, f.provider)
	}
}

func TestDocumentReleaseReconcilesCleanPartialRestrictionCheckpointAfterLeaseExpiry(t *testing.T) {
	f := newReleaseFixture(t)
	f.provider.opaque = true
	f.provider.partialNeutral = true
	intent := f.publish(t)
	if first, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || first.State != writeintent.Pending {
		t.Fatalf("shell=%+v err=%v", first, err)
	}
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
	if _, err = f.store.SaveDocumentProgress(context.Background(), "tenant", intent.ID, progress.Version, progress); err != nil {
		t.Fatal(err)
	}
	// The provider completed its neutral body before the worker stopped, but no
	// restriction acknowledgement was persisted by that worker.
	f.provider.restricted = true
	f.provider.page.Revision = "opaque-restricted"
	f.clock.at = lease
	uncertain, err := f.store.TransitionIntent(context.Background(), "tenant", intent.ID, claimed.Version, domain.IntentTransition{Event: writeintent.LeaseExpired}, lease)
	if err != nil || uncertain.State != writeintent.Uncertain {
		t.Fatalf("expired clean checkpoint=%+v err=%v", uncertain, err)
	}
	resumed, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || resumed.State != writeintent.Pending {
		t.Fatalf("clean restriction reconciliation=%+v err=%v", resumed, err)
	}
	stored, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil || stored.Progress.Step != "attachments" || stored.Progress.Remote.Revision != "opaque-restricted" {
		t.Fatalf("clean restriction checkpoint=%+v err=%v", stored.Progress, err)
	}
}

func TestDocumentReleaseDoesNotAdoptUnprovenChangedRestrictionRemote(t *testing.T) {
	for _, scenario := range []string{"foreign_marker", "non_neutral"} {
		t.Run(scenario, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.provider.opaque = true
			f.provider.partialNeutral = true
			f.provider.ambiguous = "restrictions"
			intent := f.publish(t)
			if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil {
				t.Fatal(err)
			}
			if uncertain, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || uncertain.State != writeintent.Uncertain {
				t.Fatalf("restriction outcome=%+v err=%v", uncertain, err)
			}
			switch scenario {
			case "foreign_marker":
				f.provider.page.Marker = "other-intent"
			case "non_neutral":
				f.provider.page.Neutral = false
			}
			if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("scenario %s adopted unproven remote: %v", scenario, err)
			}
			stored, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
			if err != nil || stored.Intent.State != writeintent.Uncertain {
				t.Fatalf("scenario %s changed uncertainty=%+v err=%v", scenario, stored.Intent, err)
			}
		})
	}
}

func TestDocumentReleaseDoesNotAdoptChangedRevisionForRestrictionUpdate(t *testing.T) {
	f := newReleaseFixture(t)
	first := f.publish(t)
	if completed := f.executeUntilNotPending(t, first.ID); completed.State != writeintent.Done {
		t.Fatalf("initial publication=%+v", completed)
	}
	f.source.artifact.Paragraphs = []string{"updated"}
	f.input.RequestKey = "updated-restriction"
	f.provider.ambiguous = "restrictions"
	update := f.publish(t)
	if uncertain := f.executeUntilNotPending(t, update.ID); uncertain.State != writeintent.Uncertain {
		t.Fatalf("update restriction=%+v", uncertain)
	}
	f.provider.page.Version++
	if _, err := f.service.Execute(context.Background(), "tenant", update.ID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale update revision accepted: %v", err)
	}
}

func TestDocumentReleaseFailedAcknowledgementCheckpointRetainsLeaseAndUncertaintyPath(t *testing.T) {
	f := newReleaseFixture(t)
	intent := f.publish(t)
	f.service.store = &failCleanDocumentCheckpointStore{DocumentCommandStore: f.store, fail: true}
	if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("checkpoint failure err=%v, want conflict", err)
	}
	stored, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil || stored.Intent.State != writeintent.InFlight || stored.Intent.LeaseUntil == nil || stored.Progress.OutstandingOperation != "shell" || f.provider.shells != 1 {
		t.Fatalf("acknowledgement was not fenced=%+v err=%v provider=%+v", stored, err, f.provider)
	}
	if _, err := f.service.Execute(context.Background(), "tenant", intent.ID); err != nil || f.provider.shells != 1 {
		t.Fatalf("active uncertain checkpoint repeated shell err=%v provider=%+v", err, f.provider)
	}
}

func prepareRefusedPublication(t *testing.T, f *releaseFixture) domain.Intent {
	t.Helper()
	f.provider.refuseRestrictions = true
	intent := f.publish(t)
	failed := f.executeUntilNotPending(t, intent.ID)
	if failed.State != writeintent.Failed || failed.ErrorCode != "provider_refused" || failed.Attempts != 1 {
		t.Fatalf("prepared refusal=%+v", failed)
	}
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil || command.Progress.Step != "restrictions" || command.Progress.Remote.ID == "" || command.Progress.OutstandingOperation != "" {
		t.Fatalf("prepared checkpoint=%+v err=%v", command.Progress, err)
	}
	f.provider.refuseRestrictions = false
	f.provider.restricted = true // operator repaired the destination ACL outside Synapse.
	return failed
}

func prepareRefusedAttachmentPublication(t *testing.T, f *releaseFixture) domain.Intent {
	t.Helper()
	f.provider.refuseAttachment = true
	intent := f.publish(t)
	failed := f.executeUntilNotPending(t, intent.ID)
	if failed.State != writeintent.Failed || failed.ErrorCode != "provider_refused" || failed.Attempts != 1 {
		t.Fatalf("attachment refusal=%+v", failed)
	}
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
	if err != nil || command.Progress.Step != "attachments" || command.Progress.Uploaded != 0 || len(command.Progress.UploadedReceipts) != 0 || command.Progress.OutstandingOperation != "" {
		t.Fatalf("attachment checkpoint=%+v err=%v", command.Progress, err)
	}
	f.provider.refuseAttachment = false
	return failed
}

func TestResumePreparedPublicationQueuesOnlyVerifiedNeutralShell(t *testing.T) {
	f := newReleaseFixture(t)
	failed := prepareRefusedPublication(t, f)
	resumed, err := f.service.ResumePreparedPublication(context.Background(), "tenant", f.actor, failed.ID, failed.Version)
	if err != nil || resumed.State != writeintent.Pending || resumed.Version != failed.Version+1 || resumed.Attempts != failed.Attempts || resumed.ErrorCode != "" {
		t.Fatalf("resume=%+v err=%v", resumed, err)
	}
	if f.provider.shells != 1 || f.provider.uploads != 0 || f.provider.writes != 0 || f.provider.purges != 0 {
		t.Fatalf("resume wrote content: %+v", f.provider)
	}
	if len(f.audit.entries) < 2 {
		t.Fatalf("resume audit missing: %+v", f.audit.entries)
	}
	entry := f.audit.entries[len(f.audit.entries)-1]
	if entry.Action != "document.prepared_publication_resumed" || entry.Target != failed.ID.String() || entry.Metadata["expected_version"] != fmt.Sprintf("%d", failed.Version) || entry.Metadata["idempotency_key"] != fmt.Sprintf("%s:resume:%d", failed.ID, failed.Version) {
		t.Fatalf("resume audit=%+v", entry)
	}
}

func TestStrictResumeAuditRejectsSameKeyWithDifferentContent(t *testing.T) {
	audit := &strictReleaseAudit{entries: map[string]ports.AuditEntry{}}
	first := ports.AuditEntry{Actor: "reviewer", Action: "document.prepared_publication_resumed", Target: "intent", At: time.Date(2026, 10, 17, 1, 0, 0, 0, time.UTC), Metadata: map[string]string{"idempotency_key": "intent:resume:4", "expected_version": "4"}}
	if err := audit.Record(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	changed := first
	changed.Metadata = map[string]string{"idempotency_key": "intent:resume:4", "expected_version": "5"}
	if err := audit.Record(context.Background(), changed); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same key accepted changed resume admission: %v", err)
	}
}

func TestResumePreparedPublicationUsesNewAuditKeyForSecondFailedEpisode(t *testing.T) {
	f := newReleaseFixture(t)
	failed := prepareRefusedPublication(t, f)
	audit := &strictReleaseAudit{entries: map[string]ports.AuditEntry{}}
	f.service.audit = audit
	first, err := f.service.ResumePreparedPublication(context.Background(), "tenant", f.actor, failed.ID, failed.Version)
	if err != nil || first.State != writeintent.Pending {
		t.Fatalf("first resume=%+v err=%v", first, err)
	}
	f.provider.refuseAttachment = true
	failedAgain := f.executeUntilNotPending(t, first.ID)
	if failedAgain.State != writeintent.Failed || failedAgain.ErrorCode != "provider_refused" || failedAgain.Version <= first.Version {
		t.Fatalf("second episode refusal=%+v", failedAgain)
	}
	f.provider.refuseAttachment = false
	second, err := f.service.ResumePreparedPublication(context.Background(), "tenant", f.actor, failedAgain.ID, failedAgain.Version)
	if err != nil || second.State != writeintent.Pending {
		t.Fatalf("second resume=%+v err=%v", second, err)
	}
	if len(audit.entries) != 2 {
		t.Fatalf("resume audit entries=%+v", audit.entries)
	}
	if _, ok := audit.entries[fmt.Sprintf("%s:resume:%d", failed.ID, failed.Version)]; !ok {
		t.Fatalf("first episode key missing: %+v", audit.entries)
	}
	if _, ok := audit.entries[fmt.Sprintf("%s:resume:%d", failedAgain.ID, failedAgain.Version)]; !ok {
		t.Fatalf("second episode key missing: %+v", audit.entries)
	}
}

func TestResumePreparedPublicationRetriesCASWithStableAuditPayload(t *testing.T) {
	f := newReleaseFixture(t)
	failed := prepareRefusedPublication(t, f)
	audit := &strictReleaseAudit{entries: map[string]ports.AuditEntry{}}
	f.service.audit = audit
	f.service.store = &failOnceDocumentTransitionStore{DocumentCommandStore: f.store}
	if _, err := f.service.ResumePreparedPublication(context.Background(), "tenant", f.actor, failed.ID, failed.Version); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("first resume CAS failure=%v", err)
	}
	f.clock.at = f.clock.at.Add(time.Minute)
	resumed, err := f.service.ResumePreparedPublication(context.Background(), "tenant", f.actor, failed.ID, failed.Version)
	if err != nil || resumed.State != writeintent.Pending {
		t.Fatalf("same-version retry=%+v err=%v", resumed, err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit retry appended instead of replaying=%+v", audit.entries)
	}
	entry := audit.entries[fmt.Sprintf("%s:resume:%d", failed.ID, failed.Version)]
	if !entry.At.Equal(failed.UpdatedAt) {
		t.Fatalf("audit timestamp=%s, want persisted failed timestamp=%s", entry.At, failed.UpdatedAt)
	}
}

func TestResumePreparedPublicationAllowsOnlyPreUploadCheckpoints(t *testing.T) {
	for _, scenario := range []string{"attachments", "upload_count", "receipt", "outstanding", "uncertain", "body"} {
		t.Run(scenario, func(t *testing.T) {
			f := newReleaseFixture(t)
			failed := prepareRefusedAttachmentPublication(t, f)
			if scenario == "attachments" {
				resumed, err := f.service.ResumePreparedPublication(context.Background(), "tenant", f.actor, failed.ID, failed.Version)
				if err != nil || resumed.State != writeintent.Pending || resumed.Attempts != failed.Attempts {
					t.Fatalf("attachments resume=%+v err=%v", resumed, err)
				}
				stored, err := f.store.GetDocumentCommand(context.Background(), "tenant", failed.ID)
				if err != nil || stored.Progress.Step != "attachments" || stored.Progress.Uploaded != 0 || len(stored.Progress.UploadedReceipts) != 0 {
					t.Fatalf("attachments checkpoint was not preserved=%+v err=%v", stored.Progress, err)
				}
				return
			}
			f.service.store = documentCommandMutator{DocumentCommandStore: f.store, mutate: func(command *ports.DocumentCommand) {
				switch scenario {
				case "upload_count":
					command.Progress.Uploaded = 1
				case "receipt":
					command.Progress.UploadedReceipts = []ports.DocumentUploadReceipt{{Key: "attachment:0", Digest: strings.Repeat("a", 64)}}
				case "outstanding":
					command.Progress.OutstandingOperation = "attachment"
				case "uncertain":
					command.Intent.State = writeintent.Uncertain
				case "body":
					command.Progress.Step = "body"
				}
			}}
			if _, err := f.service.ResumePreparedPublication(context.Background(), "tenant", f.actor, failed.ID, failed.Version); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("scenario %s err=%v", scenario, err)
			}
			if f.provider.uploads != 0 || f.provider.writes != 0 || f.provider.purges != 0 {
				t.Fatalf("scenario %s wrote remote content: %+v", scenario, f.provider)
			}
		})
	}
}

func TestResumePreparedPublicationPreservesAttemptHistoryForOneNewClaim(t *testing.T) {
	f := newReleaseFixture(t)
	failed := prepareRefusedPublication(t, f)
	at := f.clock.Now()
	for failed.Attempts < 5 {
		at = at.Add(time.Second)
		pending, err := f.store.TransitionIntent(context.Background(), "tenant", failed.ID, failed.Version, domain.IntentTransition{Event: writeintent.RetryFailed}, at)
		if err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Second)
		lease := at.Add(time.Minute)
		inFlight, err := f.store.TransitionIntent(context.Background(), "tenant", failed.ID, pending.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, at)
		if err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Second)
		failed, err = f.store.TransitionIntent(context.Background(), "tenant", failed.ID, inFlight.Version, domain.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_refused"}, at)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.clock.at = at.Add(time.Second)
	resumed, err := f.service.ResumePreparedPublication(context.Background(), "tenant", f.actor, failed.ID, failed.Version)
	if err != nil || resumed.State != writeintent.Pending || resumed.Attempts != 5 {
		t.Fatalf("resume after exhausted refusal=%+v err=%v", resumed, err)
	}
	f.provider.refuseRestrictions = true
	first := f.executeUntilNotPending(t, resumed.ID)
	if first.State != writeintent.Failed || first.Attempts != 6 || f.provider.uploads != 0 || f.provider.writes != 0 {
		t.Fatalf("explicit post-resume attempt=%+v provider=%+v", first, f.provider)
	}
	second, err := f.service.Execute(context.Background(), "tenant", resumed.ID)
	if err != nil || second.State != writeintent.Failed || second.Attempts != first.Attempts {
		t.Fatalf("post-resume refusal was retried automatically=%+v err=%v", second, err)
	}
}

func TestResumePreparedPublicationRejectsWrongAuthorityOrVersion(t *testing.T) {
	for _, scenario := range []string{"authority", "actor", "stale_version", "configuration_drift"} {
		t.Run(scenario, func(t *testing.T) {
			f := newReleaseFixture(t)
			failed := prepareRefusedPublication(t, f)
			actor, version := f.actor, failed.Version
			switch scenario {
			case "authority":
				f.authority.allowed = false
			case "actor":
				actor.UserID = "another-reviewer"
			case "stale_version":
				version++
			case "configuration_drift":
				f.provider.afterVerify = func() { f.integration.item.CredentialRevision++ }
			}
			if _, err := f.service.ResumePreparedPublication(context.Background(), "tenant", actor, failed.ID, version); !errors.Is(err, shared.ErrForbidden) && !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("scenario %s err=%v", scenario, err)
			}
			stored, err := f.store.GetDocumentCommand(context.Background(), "tenant", failed.ID)
			if err != nil || stored.Intent.State != writeintent.Failed || stored.Intent.Version != failed.Version {
				t.Fatalf("scenario %s changed command=%+v err=%v", scenario, stored.Intent, err)
			}
		})
	}
}

func TestResumePreparedPublicationRequiresExactNeutralAndRestrictedDestination(t *testing.T) {
	for _, scenario := range []string{"acl", "non_neutral", "version", "marker", "uncertain"} {
		t.Run(scenario, func(t *testing.T) {
			f := newReleaseFixture(t)
			failed := prepareRefusedPublication(t, f)
			switch scenario {
			case "acl":
				f.provider.restricted = false
			case "non_neutral":
				f.provider.page.Neutral = false
			case "version":
				f.provider.page.Version++
			case "marker":
				f.provider.page.Marker = "another-marker"
			case "uncertain":
				lease := f.clock.Now().Add(time.Minute)
				inFlight, err := f.store.TransitionIntent(context.Background(), "tenant", failed.ID, failed.Version, domain.IntentTransition{Event: writeintent.RetryFailed}, f.clock.Now().Add(time.Second))
				if err != nil {
					t.Fatal(err)
				}
				claimed, err := f.store.TransitionIntent(context.Background(), "tenant", failed.ID, inFlight.Version, domain.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, f.clock.Now().Add(2*time.Second))
				if err != nil {
					t.Fatal(err)
				}
				failed, err = f.store.TransitionIntent(context.Background(), "tenant", failed.ID, claimed.Version, domain.IntentTransition{Event: writeintent.Ambiguous}, f.clock.Now().Add(3*time.Second))
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err := f.service.ResumePreparedPublication(context.Background(), "tenant", f.actor, failed.ID, failed.Version)
			var providerErr *ports.DocumentProviderError
			if !errors.Is(err, shared.ErrConflict) && !errors.As(err, &providerErr) {
				t.Fatalf("scenario %s err=%v", scenario, err)
			}
			if f.provider.uploads != 0 || f.provider.writes != 0 || f.provider.purges != 0 {
				t.Fatalf("scenario %s wrote remote content: %+v", scenario, f.provider)
			}
		})
	}
}

func TestDocumentReleaseRecoversShellAndFinalBodyWithoutDuplicateWrites(t *testing.T) {
	for _, stage := range []string{"shell", "body"} {
		t.Run(stage, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.provider.ambiguous = stage
			intent := f.publish(t)
			first := f.executeUntilNotPending(t, intent.ID)
			if first.State != writeintent.Uncertain {
				t.Fatalf("ambiguous=%+v", first)
			}
			if _, err := f.store.FindLink(context.Background(), "tenant", intent.Target); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("partial publication became link: %v", err)
			}
			second, err := f.service.Execute(context.Background(), "tenant", intent.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "shell" {
				if second.State != writeintent.Pending {
					t.Fatalf("neutral shell completed publication: %+v", second)
				}
				second = f.executeUntilNotPending(t, intent.ID)
			} else {
				second = f.executeUntilNotPending(t, intent.ID)
			}
			if second.State != writeintent.Done || f.provider.shells != 1 || f.provider.uploads != 1 || f.provider.writes != 1 {
				t.Fatalf("recovered=%+v operations=%+v", second, f.provider)
			}
		})
	}
}

func TestDocumentReleaseUsesOpaqueRevisionAndRecoversOnlyAfterTokenChanges(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("revision_changed=%t", changed), func(t *testing.T) {
			f := newReleaseFixture(t)
			f.provider.opaque = true
			f.provider.ambiguous = "body"
			intent := f.publish(t)
			first := f.executeUntilNotPending(t, intent.ID)
			if first.State != writeintent.Uncertain || f.provider.revisionWrites != 1 {
				t.Fatalf("first opaque write=%+v provider=%+v", first, f.provider)
			}
			if !changed {
				f.provider.page.Revision = "opaque-shell"
			}
			result, err := f.service.Execute(context.Background(), "tenant", intent.ID)
			if err != nil {
				t.Fatal(err)
			}
			if changed {
				result = f.executeUntilNotPending(t, intent.ID)
			}
			if changed && (result.State != writeintent.Done || result.RemoteRevision != "opaque-body") {
				t.Fatalf("changed opaque token did not reconcile: %+v", result)
			}
			if !changed && result.State != writeintent.Uncertain {
				t.Fatalf("unchanged opaque token resolved a body write: %+v", result)
			}
		})
	}
}

func TestDocumentReleasePreflightRejectsBeforeArtifactOrShell(t *testing.T) {
	f := newReleaseFixture(t)
	f.provider.preflight = &ports.DocumentProviderError{Code: "unsupported_release_contract"}
	if _, err := f.service.Publish(context.Background(), "tenant", f.actor, f.input); err == nil {
		t.Fatal("unsupported provider contract admitted a publish")
	}
	if f.provider.shells != 0 {
		t.Fatalf("preflight created a shell: %+v", f.provider)
	}
	if f.source.calls != 0 {
		t.Fatalf("preflight built an artifact: calls=%d", f.source.calls)
	}
}

func TestDocumentReleaseUnresolvedAttachmentAndZeroSearchStayFenced(t *testing.T) {
	for _, stage := range []string{"shell", "attachment"} {
		t.Run(stage, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.provider.ambiguous = stage
			intent := f.publish(t)
			_ = f.executeUntilNotPending(t, intent.ID)
			if stage == "shell" {
				f.provider.page = ports.DocumentRemoteState{}
			}
			result, err := f.service.Execute(context.Background(), "tenant", intent.ID)
			if err != nil || result.State != writeintent.Uncertain {
				t.Fatalf("unresolved effect retried=%+v %v", result, err)
			}
			f.input.RequestKey = "another-command"
			if _, err := f.service.Publish(context.Background(), "tenant", f.actor, f.input); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("uncertainty fence bypassed: %v", err)
			}
			if f.provider.shells != 1 || f.provider.uploads > 1 || f.provider.writes != 0 {
				t.Fatalf("repeated unresolved write: %+v", f.provider)
			}
		})
	}
}

func TestScheduledPublishUsesFrozenArtifactAndRejectsChangedReplay(t *testing.T) {
	f := newReleaseFixture(t)
	frozen := f.source.artifact
	frozen.Title = "Bản lưu lịch gửi"
	frozen.PDF = []byte("%PDF-1.7\nfrozen occurrence bytes")
	result, err := f.service.PublishArtifact(context.Background(), "tenant", f.actor, f.input, frozen)
	if err != nil || result.Intent == nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	command, err := f.store.GetDocumentCommand(context.Background(), "tenant", result.Intent.ID)
	if err != nil || string(command.Artifact.PDF) != string(frozen.PDF) || command.Artifact.Title != frozen.Title {
		t.Fatalf("stored artifact did not retain frozen occurrence: %v", err)
	}
	f.source.artifact.Title = "Changed live source"
	replay, err := f.service.PublishArtifact(context.Background(), "tenant", f.actor, f.input, frozen)
	if err != nil || replay.Intent == nil || replay.Intent.ID != result.Intent.ID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	frozen.PDF = []byte("%PDF-1.7\nother bytes")
	if _, err = f.service.PublishArtifact(context.Background(), "tenant", f.actor, f.input, frozen); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed frozen replay: %v", err)
	}
}

func TestDocumentReleaseUsesRegisteredNativeProviderWithoutConfluenceGuard(t *testing.T) {
	f := newReleaseFixture(t)
	f.integration.item.Provider = "google-drive"
	f.integration.item.Endpoint = "https://www.googleapis.com"
	f.provider.opaque = true
	result, err := f.service.Publish(context.Background(), "tenant", f.actor, f.input)
	if err != nil || result.Intent == nil {
		t.Fatalf("native admission=%+v err=%v", result, err)
	}
	delivered := f.executeUntilNotPending(t, result.Intent.ID)
	if delivered.State != writeintent.Done || delivered.RemoteRevision != "opaque-body" {
		t.Fatalf("native execution=%+v", delivered)
	}
}

func TestUnsupportedNativeReleaseRefusesBeforeArtifactBuild(t *testing.T) {
	for _, provider := range []integration.Provider{"notion", "sharepoint", "onedrive"} {
		t.Run(string(provider), func(t *testing.T) {
			f := newReleaseFixture(t)
			f.integration.item.Provider = provider
			f.provider.preflight = &ports.DocumentProviderError{Code: "unsupported_release_contract"}
			_, err := f.service.Publish(context.Background(), "tenant", f.actor, f.input)
			if err == nil || f.source.calls != 0 || f.provider.shells != 0 {
				t.Fatalf("unsupported provider released content: err=%v builds=%d shells=%d", err, f.source.calls, f.provider.shells)
			}
		})
	}
}

type restrictionReadbackProvider struct {
	*releaseProvider
	fault string
}

func (p *restrictionReadbackProvider) VerifyDocumentRestriction(ctx context.Context, page, container, group string) error {
	if p.restrictions > 0 && p.fault == "verify" {
		return &ports.DocumentProviderError{Code: "permission_denied", Status: 403}
	}
	return p.releaseProvider.VerifyDocumentRestriction(ctx, page, container, group)
}
func (p *restrictionReadbackProvider) GetDocument(ctx context.Context, page string) (ports.DocumentRemoteState, error) {
	remote, err := p.releaseProvider.GetDocument(ctx, page)
	if err != nil || p.restrictions == 0 {
		return remote, err
	}
	switch p.fault {
	case "read":
		return ports.DocumentRemoteState{}, &ports.DocumentProviderError{Code: "permission_denied", Status: 403}
	case "identity":
		remote.ID = "foreign"
	case "container":
		remote.Container = "foreign"
	case "marker":
		remote.Marker = "synapse-intent-foreign"
	case "content":
		remote.Neutral = false
	}
	return remote, nil
}

type restrictionReadbackRegistry struct {
	releaseProviders
	provider ports.DocumentProvider
}

func (r restrictionReadbackRegistry) DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error) {
	return r.provider, nil
}
func TestDocumentReleaseRetainsFenceAfterRestrictionReadbackFailure(t *testing.T) {
	for _, fault := range []string{"verify", "read", "identity", "container", "marker", "content"} {
		t.Run(fault, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.provider.opaque = true
			f.provider.partialNeutral = true
			wrapped := &restrictionReadbackProvider{releaseProvider: f.provider, fault: fault}
			f.service.providers = restrictionReadbackRegistry{releaseProviders: releaseProviders{f.provider}, provider: wrapped}
			intent := f.publish(t)
			result := f.executeUntilNotPending(t, intent.ID)
			command, err := f.store.GetDocumentCommand(context.Background(), "tenant", intent.ID)
			if err != nil || result.State != writeintent.Uncertain || command.Progress.OutstandingOperation != "restrictions" || command.Progress.Remote.Revision != "" || f.provider.page.Revision != "opaque-restricted" {
				t.Fatalf("acknowledged restriction lost uncertainty: intent=%+v progress=%+v err=%v", result, command.Progress, err)
			}
			if f.provider.uploads != 0 || f.provider.writes != 0 {
				t.Fatal("unverified restriction released content")
			}
			wrapped.fault = ""
			recovered := f.executeUntilNotPending(t, intent.ID)
			if recovered.State != writeintent.Done || f.provider.shells != 1 || f.provider.restrictions != 1 || f.provider.uploads != 1 || f.provider.revisionWrites != 1 {
				t.Fatalf("exact neutral restriction did not recover once: %+v provider=%+v", recovered, f.provider)
			}
		})
	}
}

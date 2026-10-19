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

type releaseSource struct{ artifact ports.DocumentArtifact }

func (s *releaseSource) BuildDocumentArtifact(context.Context, shared.ID, domain.Target) (ports.DocumentArtifact, error) {
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

type releaseProvider struct {
	page                                                      ports.DocumentRemoteState
	shells, uploads, writes, purges, checks                   int
	restricted, sharing, refuseRestrictions, refuseAttachment bool
	ambiguous                                                 string
	afterVerify                                               func()
	files                                                     []string
}

func (p *releaseProvider) CreateDocumentShell(_ context.Context, space, marker string) (domain.RemotePage, error) {
	p.shells++
	p.page = ports.DocumentRemoteState{RemotePage: domain.RemotePage{ID: "123", Version: 1, URL: "https://lab.atlassian.net/wiki/spaces/LAB/pages/123"}, Container: space, Marker: marker, Neutral: true, Title: "Synapse publication in progress"}
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
	p.restricted = true
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
	if p.ambiguous == "attachment" {
		p.ambiguous = ""
		return &ports.DocumentProviderError{Code: "network", Ambiguous: true}
	}
	return nil
}
func (p *releaseProvider) WriteDocument(_ context.Context, _ string, version int, title, storage, marker string) (domain.RemotePage, error) {
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
func (p *releaseProvider) PurgeDocument(ctx context.Context, _ string, guard func(context.Context) error) error {
	if err := guard(ctx); err != nil {
		return err
	}
	p.purges++
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

func TestDocumentReleasePublishesUpdatesSkipsAndPurgesSamePage(t *testing.T) {
	f := newReleaseFixture(t)
	ctx := context.Background()
	intent := f.publish(t)
	done, err := f.service.Execute(ctx, "tenant", intent.ID)
	if err != nil || done.State != writeintent.Done {
		t.Fatalf("publish=%+v %v", done, err)
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
	updated, err := f.service.Execute(ctx, "tenant", next.ID)
	if err != nil || updated.State != writeintent.Done || updated.RemoteID != done.RemoteID || updated.RemoteVersion != done.RemoteVersion+1 || f.provider.shells != 1 {
		t.Fatalf("republish=%+v %v", updated, err)
	}
	link, err := f.store.FindLink(ctx, "tenant", done.Target)
	if err != nil {
		t.Fatal(err)
	}
	unpublish, err := f.service.Unpublish(ctx, "tenant", f.actor, link.ID, "purge")
	if err != nil {
		t.Fatal(err)
	}
	purged, err := f.service.Execute(ctx, "tenant", unpublish.Intent.ID)
	if err != nil || purged.State != writeintent.Done || f.provider.purges != 1 {
		t.Fatalf("purge=%+v %v", purged, err)
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

func prepareRefusedPublication(t *testing.T, f *releaseFixture) domain.Intent {
	t.Helper()
	f.provider.refuseRestrictions = true
	intent := f.publish(t)
	failed, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || failed.State != writeintent.Failed || failed.ErrorCode != "provider_refused" || failed.Attempts != 1 {
		t.Fatalf("prepared refusal=%+v err=%v", failed, err)
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
	failed, err := f.service.Execute(context.Background(), "tenant", intent.ID)
	if err != nil || failed.State != writeintent.Failed || failed.ErrorCode != "provider_refused" || failed.Attempts != 1 {
		t.Fatalf("attachment refusal=%+v err=%v", failed, err)
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
	failedAgain, err := f.service.Execute(context.Background(), "tenant", first.ID)
	if err != nil || failedAgain.State != writeintent.Failed || failedAgain.ErrorCode != "provider_refused" || failedAgain.Version <= first.Version {
		t.Fatalf("second episode refusal=%+v err=%v", failedAgain, err)
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
	first, err := f.service.Execute(context.Background(), "tenant", resumed.ID)
	if err != nil || first.State != writeintent.Failed || first.Attempts != 6 || f.provider.uploads != 0 || f.provider.writes != 0 {
		t.Fatalf("explicit post-resume attempt=%+v err=%v provider=%+v", first, err, f.provider)
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
			first, err := f.service.Execute(context.Background(), "tenant", intent.ID)
			if err != nil || first.State != writeintent.Uncertain {
				t.Fatalf("ambiguous=%+v %v", first, err)
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
				second, err = f.service.Execute(context.Background(), "tenant", intent.ID)
			}
			if err != nil || second.State != writeintent.Done || f.provider.shells != 1 || f.provider.uploads != 1 || f.provider.writes != 1 {
				t.Fatalf("recovered=%+v err=%v operations=%+v", second, err, f.provider)
			}
		})
	}
}

func TestDocumentReleaseUnresolvedAttachmentAndZeroSearchStayFenced(t *testing.T) {
	for _, stage := range []string{"shell", "attachment"} {
		t.Run(stage, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.provider.ambiguous = stage
			intent := f.publish(t)
			_, _ = f.service.Execute(context.Background(), "tenant", intent.ID)
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

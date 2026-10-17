package docpublish

import (
	"context"
	"errors"
	"fmt"
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

type releaseProviders struct{ provider *releaseProvider }

func (p releaseProviders) DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error) {
	return p.provider, nil
}

type releaseProvider struct {
	page                                    ports.DocumentRemoteState
	shells, uploads, writes, purges, checks int
	restricted, sharing                     bool
	ambiguous                               string
	afterVerify                             func()
	files                                   []string
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

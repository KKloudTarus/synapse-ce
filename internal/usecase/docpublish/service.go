package docpublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ProviderRegistry interface {
	DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error)
}

// DocumentReleasePreflightRegistry is optional so legacy provider registries
// remain compatible while a provider can refuse before any remote shell exists.
type DocumentReleasePreflightRegistry interface {
	DocumentReleasePreflighter(context.Context, integration.Integration) (ports.DocumentReleasePreflighter, error)
}

type Service struct {
	store        ports.DocumentCommandStore
	integrations ports.IntegrationStore
	providers    ProviderRegistry
	sources      ports.DocumentArtifactSource
	authority    ports.DocumentAuthorityReader
	policy       ports.DocumentSourceReleaseReader
	audit        ports.AuditLogger
	ids          ports.IDGenerator
	clock        ports.Clock
	transactions ports.TenantTransactionRunner
	events       ports.NotificationOutbox
}

// SetNotifications makes newly persisted publication commands and their
// report.generated records one transaction. It is optional so compositions
// without notifications retain their existing command path.
func (s *Service) SetNotifications(transactions ports.TenantTransactionRunner, outbox ports.NotificationOutbox) error {
	if transactions == nil || outbox == nil {
		return fmt.Errorf("%w: document notification transaction and outbox are required", shared.ErrValidation)
	}
	s.transactions = transactions
	s.events = outbox
	return nil
}

func NewService(store ports.DocumentCommandStore, integrations ports.IntegrationStore, providers ProviderRegistry, sources ports.DocumentArtifactSource, authority ports.DocumentAuthorityReader, policy ports.DocumentSourceReleaseReader, audit ports.AuditLogger, ids ports.IDGenerator, clock ports.Clock) (*Service, error) {
	if store == nil || integrations == nil || providers == nil || sources == nil || authority == nil || policy == nil || audit == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: document publication dependencies required", shared.ErrValidation)
	}
	return &Service{store: store, integrations: integrations, providers: providers, sources: sources, authority: authority, policy: policy, audit: audit, ids: ids, clock: clock}, nil
}

type PublishInput struct {
	IntegrationID shared.ID         `json:"integration_id"`
	SourceKind    domain.SourceKind `json:"source_kind"`
	ScopeID       shared.ID         `json:"scope_id"`
	SourceRef     string            `json:"source_ref"`
	RequestKey    string            `json:"request_key"`
}

type ReleaseResult struct {
	Intent  *domain.Intent `json:"intent,omitempty"`
	Link    *domain.Link   `json:"link,omitempty"`
	Skipped bool           `json:"skipped"`
}

func (s *Service) Publish(ctx context.Context, tenant shared.ID, actor ports.DocumentActor, input PublishInput) (ReleaseResult, error) {
	return s.publish(ctx, tenant, actor, input, nil)
}

// PublishArtifact admits the immutable artifact already generated and verified
// for a durable schedule occurrence. It is absent from the HTTP capability.
func (s *Service) PublishArtifact(ctx context.Context, tenant shared.ID, actor ports.DocumentActor, input PublishInput, artifact ports.DocumentArtifact) (ReleaseResult, error) {
	// Scheduled occurrences cannot truthfully verify destination-managed sharing.
	// They are intentionally unavailable for that profile.
	ctx = shared.WithTenant(ctx, tenant)
	if err := s.authorize(ctx, tenant, actor); err != nil {
		return ReleaseResult{}, err
	}
	in, err := s.integration(ctx, tenant, input.IntegrationID)
	if err != nil {
		return ReleaseResult{}, err
	}
	if documentAccessProfile(in) == domain.DestinationManagedSnapshotProfile {
		return ReleaseResult{}, shared.ErrForbidden
	}
	return s.publish(ctx, tenant, actor, input, &artifact)
}

// ValidateDocumentDestination admits an enabled document integration before a
// schedule freezes an artifact. It keeps scheduled releases on the same
// current integration, destination, provider, and optional release-preflight
// boundary as direct publication.
func (s *Service) ValidateDocumentDestination(ctx context.Context, tenant, integrationID shared.ID) error {
	if tenant.IsZero() || integrationID.IsZero() {
		return shared.ErrValidation
	}
	ctx = shared.WithTenant(ctx, tenant)
	in, err := s.integration(ctx, tenant, integrationID)
	if err != nil {
		return err
	}
	if documentAccessProfile(in) == domain.DestinationManagedSnapshotProfile {
		return shared.ErrForbidden
	}
	container, group, err := destination(in)
	if err != nil {
		return err
	}
	if err := s.preflightDocumentRelease(ctx, in, container, group); err != nil {
		return err
	}
	provider, err := s.providers.DocumentProvider(ctx, in)
	if err != nil {
		return err
	}
	defer closeProvider(provider)
	return nil
}

func (s *Service) publish(ctx context.Context, tenant shared.ID, actor ports.DocumentActor, input PublishInput, frozen *ports.DocumentArtifact) (ReleaseResult, error) {
	ctx = shared.WithTenant(ctx, tenant)
	if err := s.authorize(ctx, tenant, actor); err != nil {
		return ReleaseResult{}, err
	}
	if input.IntegrationID.IsZero() || input.ScopeID.IsZero() || !input.SourceKind.Valid() || !validKey(input.RequestKey) {
		return ReleaseResult{}, shared.ErrValidation
	}
	if old, err := s.store.FindDocumentCommand(ctx, tenant, input.IntegrationID, input.RequestKey); err == nil {
		if old.Actor != actor || old.Intent.SourceKind != input.SourceKind || old.Intent.ScopeID != input.ScopeID || old.Intent.SourceRef != input.SourceRef || old.Intent.Action == domain.Purge || old.Intent.Action == domain.Trash {
			return ReleaseResult{}, shared.ErrConflict
		}
		if frozen != nil {
			normalized, normalizeErr := normalizeArtifact(*frozen)
			if normalizeErr != nil || artifactHash(normalized) != old.Intent.ContentHash {
				return ReleaseResult{}, shared.ErrConflict
			}
		}
		return ReleaseResult{Intent: &old.Intent}, nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		return ReleaseResult{}, err
	}
	in, err := s.integration(ctx, tenant, input.IntegrationID)
	if err != nil {
		return ReleaseResult{}, err
	}
	space, group, err := destination(in)
	if err != nil {
		return ReleaseResult{}, err
	}
	scope, _ := input.SourceKind.Scope()
	target := domain.Target{IntegrationID: in.ID, SourceKind: input.SourceKind, Scope: scope, ScopeID: input.ScopeID, SourceRef: input.SourceRef, Container: space}
	if err := target.Validate(); err != nil {
		return ReleaseResult{}, err
	}
	if err := s.policy.CheckDocumentSource(ctx, tenant, target); err != nil {
		return ReleaseResult{}, err
	}
	if err := s.preflightDocumentRelease(ctx, in, space, group); err != nil {
		return ReleaseResult{}, err
	}
	var artifact ports.DocumentArtifact
	if frozen != nil {
		artifact, err = normalizeArtifact(*frozen)
	} else {
		artifact, err = s.sources.BuildDocumentArtifact(ctx, tenant, target)
	}
	if err != nil {
		return ReleaseResult{}, err
	}
	if err := validateArtifact(artifact); err != nil {
		return ReleaseResult{}, err
	}
	provider, err := s.providers.DocumentProvider(ctx, in)
	if err != nil {
		return ReleaseResult{}, err
	}
	defer closeProvider(provider)
	if err := validateLiterals(provider, artifact); err != nil {
		return ReleaseResult{}, err
	}
	profile := documentAccessProfile(in)
	if profile == domain.DestinationManagedSnapshotProfile {
		snapshot, ok := provider.(ports.DocumentSnapshotProvider)
		if !ok || snapshot.DocumentAccessProfile() != profile || snapshot.ValidateDocumentSnapshot(artifact) != nil {
			return ReleaseResult{}, shared.ErrForbidden
		}
	}
	hash := artifactHash(artifact)
	now := s.clock.Now().UTC()
	id := s.ids.NewID()
	intent := domain.Intent{ID: id, TenantID: tenant, Target: target, Action: domain.Create, RequestKey: input.RequestKey, ContentHash: hash, AccessProfile: profile, Marker: domain.MarkerFor(id), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	progress := ports.DocumentProgress{Version: 1, IntentVersion: 1, Step: "shell", UpdatedAt: now}
	if profile == domain.DestinationManagedSnapshotProfile {
		progress.Step = "snapshot_shell"
	}
	if link, err := s.store.FindLink(ctx, tenant, target); err == nil {
		if link.AccessProfile != profile {
			return ReleaseResult{}, shared.ErrConflict
		}
		if link.RetiredAt != nil && (profile != domain.DestinationManagedSnapshotProfile || link.RemovalKind != domain.RemovalTrash) {
			return ReleaseResult{}, shared.ErrConflict
		}
		if link.ContentHash == hash {
			if profile == domain.DestinationManagedSnapshotProfile {
				snapshot, ok := provider.(ports.DocumentSnapshotProvider)
				if ok && snapshot.DocumentAccessProfile() == profile {
					remote, readErr := snapshot.ObserveDocumentDestination(ctx, link.RemotePageID, target.Container)
					if readErr == nil && remote.ID == link.RemotePageID && remote.Container == target.Container && sameRemoteRevision(remote.RemotePage, domain.RemotePage{ID: link.RemotePageID, Version: link.RemoteVersion, Revision: link.RemoteRevision, URL: link.RemoteURL}) {
						return ReleaseResult{Link: &link, Skipped: true}, nil
					}
				}
			} else {
				remote, readErr := provider.GetDocument(ctx, link.RemotePageID)
				if readErr == nil && remote.ID == link.RemotePageID && remote.Container == target.Container && sameRemoteRevision(remote.RemotePage, domain.RemotePage{ID: link.RemotePageID, Version: link.RemoteVersion, Revision: link.RemoteRevision, URL: link.RemoteURL}) && provider.VerifyDocumentRestriction(ctx, remote.ID, target.Container, group) == nil {
					return ReleaseResult{Link: &link, Skipped: true}, nil
				}
			}
		}
		if profile == domain.DestinationManagedSnapshotProfile {
			intent.Action, intent.ExpectedLinkRevision = domain.Snapshot, link.Revision
			progress.Step, progress.Remote = "snapshot_shell", domain.RemotePage{}
		} else {
			intent.Action = domain.Update
		}
		intent.LinkID = link.ID
		if profile != domain.DestinationManagedSnapshotProfile {
			progress.Step = "restrictions"
			progress.Remote = domain.RemotePage{ID: link.RemotePageID, Version: link.RemoteVersion, Revision: link.RemoteRevision, URL: link.RemoteURL}
		}
	} else if !errors.Is(err, shared.ErrNotFound) {
		return ReleaseResult{}, err
	}
	command := ports.DocumentCommand{Intent: intent, Actor: actor, ConnectionRevision: in.ConnectionRevision, CredentialRevision: in.CredentialRevision, ReadGroup: group, AccessProfile: profile, Artifact: artifact, Progress: progress}
	command.Intent.PayloadDigest = commandDigest(command)
	saved, err := s.persistReleaseCommand(ctx, tenant, command)
	if err != nil {
		return ReleaseResult{}, err
	}
	return ReleaseResult{Intent: &saved.Intent}, nil
}

func (s *Service) persistReleaseCommand(ctx context.Context, tenant shared.ID, command ports.DocumentCommand) (ports.DocumentCommand, error) {
	if s.transactions == nil || s.events == nil {
		if err := s.record(ctx, command, "document.release_requested", ""); err != nil {
			return ports.DocumentCommand{}, err
		}
		saved, _, err := s.store.CreateDocumentCommand(ctx, tenant, command)
		return saved, err
	}
	var saved ports.DocumentCommand
	err := s.transactions.Run(ctx, tenant, func(txCtx context.Context) error {
		var created bool
		var err error
		saved, created, err = s.store.CreateDocumentCommand(txCtx, tenant, command)
		if err != nil || !created {
			return err
		}
		record, err := reportGeneratedRecord(tenant, saved.Intent.Source(), saved.Artifact)
		if err != nil {
			return err
		}
		if err = s.events.Append(txCtx, record); err != nil {
			return fmt.Errorf("append report notification: %w", err)
		}
		if err = s.record(txCtx, saved, "document.release_requested", ""); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return ports.DocumentCommand{}, err
	}
	return saved, nil
}

func (s *Service) Unpublish(ctx context.Context, tenant shared.ID, actor ports.DocumentActor, linkID shared.ID, requestKey string) (ReleaseResult, error) {
	ctx = shared.WithTenant(ctx, tenant)
	if err := s.authorize(ctx, tenant, actor); err != nil {
		return ReleaseResult{}, err
	}
	if !validKey(requestKey) {
		return ReleaseResult{}, shared.ErrValidation
	}
	link, err := s.store.GetLink(ctx, tenant, linkID)
	if err != nil {
		return ReleaseResult{}, err
	}
	if old, err := s.store.FindDocumentCommand(ctx, tenant, link.IntegrationID, requestKey); err == nil {
		if (old.Intent.Action != domain.Purge && old.Intent.Action != domain.Trash) || old.Intent.LinkID != linkID || old.Actor != actor {
			return ReleaseResult{}, shared.ErrConflict
		}
		return ReleaseResult{Intent: &old.Intent}, nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		return ReleaseResult{}, err
	}
	if link.RetiredAt != nil {
		return ReleaseResult{Link: &link, Skipped: true}, nil
	}
	in, err := s.integration(ctx, tenant, link.IntegrationID)
	if err != nil {
		return ReleaseResult{}, err
	}
	space, group, err := destination(in)
	if err != nil {
		return ReleaseResult{}, err
	}
	if space != link.Container {
		return ReleaseResult{}, shared.ErrConflict
	}
	if err := s.policy.CheckDocumentSource(ctx, tenant, link.Target); err != nil {
		return ReleaseResult{}, err
	}
	now := s.clock.Now().UTC()
	id := s.ids.NewID()
	profile := documentAccessProfile(in)
	action, step := domain.Purge, "purge"
	expectedRevision := 0
	if profile == domain.DestinationManagedSnapshotProfile {
		action, step = domain.Trash, "trash"
		expectedRevision = link.Revision
	}
	command := ports.DocumentCommand{Intent: domain.Intent{ID: id, TenantID: tenant, Target: link.Target, LinkID: link.ID, ExpectedLinkRevision: expectedRevision, Action: action, RequestKey: requestKey, ContentHash: link.ContentHash, AccessProfile: profile, Marker: domain.MarkerFor(id), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}, Actor: actor, ReadGroup: group, AccessProfile: profile, ConnectionRevision: in.ConnectionRevision, CredentialRevision: in.CredentialRevision, Progress: ports.DocumentProgress{Version: 1, IntentVersion: 1, Step: step, Remote: domain.RemotePage{ID: link.RemotePageID, Version: link.RemoteVersion, Revision: link.RemoteRevision, URL: link.RemoteURL}, UpdatedAt: now}}
	command.Intent.PayloadDigest = commandDigest(command)
	if err := s.record(ctx, command, "document.unpublish_requested", link.RemotePageID); err != nil {
		return ReleaseResult{}, err
	}
	saved, _, err := s.store.CreateDocumentCommand(ctx, tenant, command)
	if err != nil {
		return ReleaseResult{}, err
	}
	return ReleaseResult{Intent: &saved.Intent}, nil
}

// ResumePreparedPublication admits one additional attempt only after the same
// reviewer has corrected destination access for a neutral, content-free shell.
// It never writes remote content itself.
func (s *Service) ResumePreparedPublication(ctx context.Context, tenant shared.ID, actor ports.DocumentActor, id shared.ID, expectedVersion int) (domain.Intent, error) {
	ctx = shared.WithTenant(ctx, tenant)
	if tenant.IsZero() || id.IsZero() || expectedVersion < 1 {
		return domain.Intent{}, shared.ErrValidation
	}
	if err := s.authorize(ctx, tenant, actor); err != nil {
		return domain.Intent{}, err
	}
	c, err := s.store.GetDocumentCommand(ctx, tenant, id)
	if err != nil {
		return domain.Intent{}, err
	}
	if c.Actor != actor {
		return domain.Intent{}, shared.ErrForbidden
	}
	if c.Intent.Version != expectedVersion {
		return domain.Intent{}, shared.ErrConflict
	}
	if c.Intent.State != writeintent.Failed || c.Intent.ErrorCode != "provider_refused" || c.Intent.Action != domain.Create ||
		(c.Progress.Step != "restrictions" && c.Progress.Step != "attachments") || c.Progress.Remote.ID == "" || c.Progress.Remote.Version < 1 ||
		c.Progress.Uploaded != 0 || len(c.Progress.UploadedReceipts) != 0 || c.Progress.OutstandingOperation != "" ||
		c.Progress.OutstandingKey != "" || c.Progress.OutstandingDigest != "" || c.Progress.ExpectedRemoteVersion != 0 || c.Progress.ExpectedRemoteRevision != "" {
		return domain.Intent{}, shared.ErrConflict
	}
	in, err := s.guard(ctx, c)
	if err != nil {
		return domain.Intent{}, err
	}
	if err := s.preflightDocumentRelease(ctx, in, c.Intent.Container, c.ReadGroup); err != nil {
		return domain.Intent{}, err
	}
	p, err := s.providers.DocumentProvider(ctx, in)
	if err != nil {
		return domain.Intent{}, err
	}
	defer closeProvider(p)
	remote, err := p.GetDocument(ctx, c.Progress.Remote.ID)
	if err != nil {
		return domain.Intent{}, err
	}
	if remote.ID != c.Progress.Remote.ID || remote.Container != c.Intent.Container || !sameRemoteRevision(remote.RemotePage, c.Progress.Remote) || remote.Marker != c.Intent.Marker || !remote.Neutral {
		return domain.Intent{}, shared.ErrConflict
	}
	if err := p.VerifyDocumentRestriction(ctx, remote.ID, c.Intent.Container, c.ReadGroup); err != nil {
		return domain.Intent{}, err
	}
	// Re-read the release guard after the provider observations. This fences a
	// concurrent credentials, destination, authority, or hold change before CAS.
	if _, err := s.guard(ctx, c); err != nil {
		return domain.Intent{}, err
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor.UserID.String(), Action: "document.prepared_publication_resumed", Target: id.String(), At: c.Intent.UpdatedAt.UTC(), Metadata: map[string]string{"expected_version": fmt.Sprintf("%d", expectedVersion), "page_id": remote.ID, "space": c.Intent.Container, "idempotency_key": fmt.Sprintf("%s:resume:%d", id, expectedVersion)}}); err != nil {
		return domain.Intent{}, err
	}
	return s.store.TransitionIntent(ctx, tenant, id, expectedVersion, domain.IntentTransition{Event: writeintent.RetryFailed}, s.clock.Now().UTC())
}

func (s *Service) authorize(ctx context.Context, tenant shared.ID, actor ports.DocumentActor) error {
	if tenant.IsZero() || actor.UserID.IsZero() {
		return shared.ErrForbidden
	}
	allowed, err := s.authority.CanReleaseDocument(ctx, tenant, actor)
	if err != nil {
		return err
	}
	if !allowed {
		return shared.ErrForbidden
	}
	return nil
}
func (s *Service) integration(ctx context.Context, tenant, id shared.ID) (integration.Integration, error) {
	in, err := s.integrations.GetIntegration(ctx, id)
	if err != nil {
		return in, err
	}
	if in.TenantID != tenant {
		return in, shared.ErrNotFound
	}
	if !in.Enabled || in.Archived {
		return in, shared.ErrForbidden
	}
	return in, nil
}
func destination(in integration.Integration) (string, string, error) {
	var config struct {
		Space string `json:"space"`
		Group string `json:"read_group"`
		Class string `json:"data_class"`
	}
	if json.Unmarshal(in.Config, &config) != nil || strings.TrimSpace(config.Space) == "" || len(config.Space) > 255 || strings.TrimSpace(config.Group) == "" || len(config.Group) > 255 || config.Class != "detail" {
		return "", "", shared.ErrForbidden
	}
	return config.Space, config.Group, nil
}
func documentAccessProfile(in integration.Integration) string {
	var config struct {
		Profile string `json:"publication_profile"`
	}
	if json.Unmarshal(in.Config, &config) != nil {
		return ""
	}
	return strings.TrimSpace(config.Profile)
}
func (s *Service) guard(ctx context.Context, c ports.DocumentCommand) (integration.Integration, error) {
	if err := s.authorize(ctx, c.Intent.TenantID, c.Actor); err != nil {
		return integration.Integration{}, err
	}
	if err := s.policy.CheckDocumentSource(ctx, c.Intent.TenantID, c.Intent.Target); err != nil {
		return integration.Integration{}, err
	}
	in, err := s.integration(ctx, c.Intent.TenantID, c.Intent.IntegrationID)
	if err != nil {
		return in, err
	}
	space, group, err := destination(in)
	if err != nil {
		return in, err
	}
	if in.ConnectionRevision != c.ConnectionRevision || in.CredentialRevision != c.CredentialRevision || space != c.Intent.Container || group != c.ReadGroup || documentAccessProfile(in) != c.AccessProfile || c.Intent.AccessProfile != c.AccessProfile {
		return in, shared.ErrConflict
	}
	return in, nil
}
func (s *Service) preflightDocumentRelease(ctx context.Context, in integration.Integration, container, group string) error {
	registry, ok := s.providers.(DocumentReleasePreflightRegistry)
	if !ok {
		return nil
	}
	preflighter, err := registry.DocumentReleasePreflighter(ctx, in)
	if err != nil || preflighter == nil {
		return err
	}
	if closer, ok := preflighter.(interface{ Close() }); ok {
		defer closer.Close()
	}
	return preflighter.CheckDocumentRelease(ctx, container, group)
}

func sameRemoteRevision(left, right domain.RemotePage) bool {
	return left.Version == right.Version && left.Revision == right.Revision
}
func validKey(v string) bool {
	return utf8.ValidString(v) && len(v) > 0 && len(v) <= 128 && strings.TrimSpace(v) == v && !strings.ContainsAny(v, "\x00\r\n\t")
}
func digest(data []byte) string                    { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func artifactHash(a ports.DocumentArtifact) string { raw, _ := json.Marshal(a); return digest(raw) }
func commandDigest(c ports.DocumentCommand) string {
	raw, _ := json.Marshal(struct {
		Target                 domain.Target
		Actor                  ports.DocumentActor
		Connection, Credential int
		Group, Hash            string
		Action                 domain.Action
		Link                   shared.ID
		ExpectedLinkRevision   int
		AccessProfile          string
	}{c.Intent.Target, c.Actor, c.ConnectionRevision, c.CredentialRevision, c.ReadGroup, c.Intent.ContentHash, c.Intent.Action, c.Intent.LinkID, c.Intent.ExpectedLinkRevision, c.AccessProfile})
	return digest(raw)
}
func closeProvider(p ports.DocumentProvider) {
	if closer, ok := p.(interface{ Close() }); ok {
		closer.Close()
	}
}
func (s *Service) record(ctx context.Context, c ports.DocumentCommand, action, page string) error {
	return s.audit.Record(ctx, ports.AuditEntry{Actor: c.Actor.UserID.String(), Action: action, Target: c.Intent.ID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"content_hash": c.Intent.ContentHash, "page_id": page, "space": c.Intent.Container, "source_kind": string(c.Intent.SourceKind), "idempotency_key": c.Intent.ID.String() + ":" + action}})
}

func (s *Service) Links(ctx context.Context, tenant shared.ID, scope domain.Scope, id shared.ID) ([]domain.Link, error) {
	return s.store.ListLinks(shared.WithTenant(ctx, tenant), tenant, scope, id, 100)
}
func (s *Service) Intent(ctx context.Context, tenant, id shared.ID) (domain.Intent, error) {
	return s.store.GetIntent(shared.WithTenant(ctx, tenant), tenant, id)
}
func (s *Service) Snapshots(ctx context.Context, tenant, linkID shared.ID) ([]domain.Intent, error) {
	return s.store.ListDocumentSnapshots(shared.WithTenant(ctx, tenant), tenant, linkID, domain.MaxListLimit)
}

// Tick is bounded by the caller's tenant loop. It performs no global tenant read.
func (s *Service) Tick(ctx context.Context, tenant shared.ID, limit int) error {
	ctx = shared.WithTenant(ctx, tenant)
	if limit < 1 || limit > 100 {
		return shared.ErrValidation
	}
	// Reserve the bounded read-only sweep before command execution, so a busy
	// publication queue cannot indefinitely hide post-publication sharing drift.
	checkErr := s.checkRestrictions(ctx, tenant, limit)
	commands, err := s.store.ListDocumentCommands(ctx, tenant, limit, s.clock.Now().UTC())
	if err != nil {
		return errors.Join(checkErr, err)
	}
	failures := []error{checkErr}
	for _, c := range commands {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := s.Execute(ctx, tenant, c.Intent.ID); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Surface a failed pass without returning provider text or credentials.
			failures = append(failures, errors.New("document command execution failed"))
		}
	}
	return errors.Join(failures...)
}

const documentLease = 15 * time.Minute

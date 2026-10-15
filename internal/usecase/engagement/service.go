// Package engagement (use case) implements engagement application logic.
package engagement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service implements engagement use cases.
type Service struct {
	repo                      ports.EngagementRepository
	clock                     ports.Clock
	ids                       ports.IDGenerator
	audit                     ports.AuditLogger
	sources                   ports.EngagementSourceStore
	snapshots                 ports.AssessmentSnapshotDefaultReader
	requireCompletionSnapshot func(string) bool
	notificationTx            ports.TenantTransactionRunner
	notifications             ports.NotificationOutbox
	notificationFacts         ports.NotificationLifecycleFactsReader
	notificationLocker        ports.EngagementMutationLocker
}

// NewService wires the engagement use case with its driven ports.
func NewService(repo ports.EngagementRepository, clock ports.Clock, ids ports.IDGenerator, audit ports.AuditLogger) *Service {
	return &Service{repo: repo, clock: clock, ids: ids, audit: audit}
}

func (s *Service) SetSourceStore(store ports.EngagementSourceStore) { s.sources = store }

func (s *Service) SetCompletionSnapshotReader(reader ports.AssessmentSnapshotDefaultReader) {
	s.snapshots = reader
	s.requireCompletionSnapshot = func(string) bool { return true }
}

// SetCompletionSnapshotPolicy enables the finalized-Snapshot completion guard
// only for tenants that have passed the lifecycle rollout. A disabled policy
// preserves legacy completion behavior.
func (s *Service) SetCompletionSnapshotPolicy(reader ports.AssessmentSnapshotDefaultReader, required func(string) bool) {
	s.snapshots = reader
	s.requireCompletionSnapshot = required
}

// SetNotifications enables transactional engagement lifecycle capture. The
// supplied transaction runner must be the one used by the engagement, audit,
// facts and outbox adapters; a mutation locker is mandatory so status and
// window reads cannot race a competing aggregate write.
func (s *Service) SetNotifications(tx ports.TenantTransactionRunner, outbox ports.NotificationOutbox, facts ports.NotificationLifecycleFactsReader) error {
	locker, ok := s.repo.(ports.EngagementMutationLocker)
	if tx == nil || outbox == nil || facts == nil || !ok {
		return fmt.Errorf("%w: engagement notification dependencies are required", shared.ErrValidation)
	}
	s.notificationTx, s.notifications, s.notificationFacts, s.notificationLocker = tx, outbox, facts, locker
	return nil
}

// CreateInput is the input for creating an engagement.
type CreateInput struct {
	AssessmentProjectID                    shared.ID
	TenantID                               shared.ID
	BusinessAssetID                        shared.ID
	CreatedBy                              string // the authenticated actor that owns the engagement (ownership)
	Name                                   string
	Client                                 string
	InScope                                []domain.Target
	OutOfScope                             []domain.Target
	AuthorizedFrom                         *time.Time
	AuthorizedTo                           *time.Time
	Timezone                               string
	RoE                                    *domain.RoE
	RequiresExplicitExecutionAuthorization bool
}

// Create validates and persists a new engagement with its scope.
func (s *Service) Create(ctx context.Context, in CreateInput) (*domain.Engagement, error) {
	if s.notificationTx == nil || s.notifications == nil {
		return s.create(ctx, in, s.ids.NewID())
	}
	tenantID, err := s.notificationTenant(ctx, in.TenantID)
	if err != nil {
		return nil, err
	}
	in.TenantID = tenantID
	var created *domain.Engagement
	err = s.notificationTx.Run(ctx, tenantID, func(txCtx context.Context) error {
		created, err = s.create(txCtx, in, s.ids.NewID())
		if err != nil {
			return err
		}
		if err := s.appendEngagementCreated(txCtx, tenantID, created, in.CreatedBy); err != nil {
			return err
		}
		return s.auditChange(txCtx, in.CreatedBy, "engagement.created", created.ID, nil, s.clock.Now())
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (s *Service) CreateFromSourcePackage(ctx context.Context, in CreateInput, filename string, size int64, sha256hex string, src io.Reader) (*domain.Engagement, sourcepackage.Package, error) {
	if s.sources == nil {
		return nil, sourcepackage.Package{}, fmt.Errorf("%w: engagement source uploads are not configured", shared.ErrValidation)
	}
	id := s.ids.NewID()
	metadata := sourcepackage.Package{
		TenantID: shared.TenantOrDefault(in.TenantID), EngagementID: id, Filename: sourcepackage.BaseFilename(filename),
		Size: size, SHA256: strings.ToLower(strings.TrimSpace(sha256hex)), CreatedBy: in.CreatedBy, CreatedAt: s.clock.Now(),
	}
	if err := metadata.Validate(); err != nil || src == nil {
		if err != nil {
			return nil, sourcepackage.Package{}, err
		}
		return nil, sourcepackage.Package{}, fmt.Errorf("%w: source upload is required", shared.ErrValidation)
	}
	if s.lifecycleNotificationsEnabled() {
		tenantID, err := s.notificationTenant(ctx, in.TenantID)
		if err != nil {
			return nil, sourcepackage.Package{}, err
		}
		preparer, ok := s.sources.(ports.EngagementSourcePreparer)
		if !ok {
			return nil, sourcepackage.Package{}, fmt.Errorf("%w: transactional source preparation is not configured", shared.ErrValidation)
		}
		in.TenantID, metadata.TenantID = tenantID, tenantID
		prepared, err := preparer.Prepare(ctx, tenantID, id, metadata.Filename, in.CreatedBy, metadata.CreatedAt, size, metadata.SHA256, src)
		if err != nil {
			return nil, prepared, err
		}
		in.InScope = append([]domain.Target{{Kind: domain.TargetRepo, Value: prepared.Target()}}, in.InScope...)
		return s.createWithPreparedSource(ctx, tenantID, in, id, prepared, "engagement.source_uploaded", func(item sourcepackage.Package) map[string]string {
			return map[string]string{
				"filename": item.Filename, "sha256": item.SHA256, "size": strconv.FormatInt(item.Size, 10), "source_version_id": item.VersionID.String(),
			}
		})
	}
	// Persist the draft owner before its source association so metadata stores
	// can enforce the engagement foreign key. No scan can execute this draft.
	in.InScope = append([]domain.Target{{Kind: domain.TargetRepo, Value: metadata.Target()}}, in.InScope...)
	engagement, err := s.create(ctx, in, id)
	if err != nil {
		return nil, sourcepackage.Package{}, err
	}
	item, err := s.sources.Save(ctx, metadata.TenantID, id, metadata.Filename, in.CreatedBy, metadata.CreatedAt, size, metadata.SHA256, src)
	if err != nil {
		return nil, item, errors.Join(err, s.CompensateCreate(context.WithoutCancel(ctx), metadata.TenantID, id, item))
	}
	// Chain-of-custody: record the ingest of untrusted source bytes in the append-only, hash-chained
	// audit log (who uploaded which archive to which engagement), not only in the manifest metadata.
	if err := s.auditChange(ctx, in.CreatedBy, "engagement.source_uploaded", id, map[string]string{
		"filename":          item.Filename,
		"sha256":            item.SHA256,
		"size":              strconv.FormatInt(item.Size, 10),
		"source_version_id": item.VersionID.String(),
	}, s.clock.Now()); err != nil {
		// Reject an unaudited upload and remove both the newly created engagement
		// and external source bytes, including when the request was cancelled.
		return nil, item, errors.Join(err, s.CompensateCreate(context.WithoutCancel(ctx), item.TenantID, id, item))
	}
	return engagement, item, nil
}

// SourcePackage resolves metadata only through the tenant-scoped engagement.
// Storage locators remain internal; callers use the immutable version identity.
func (s *Service) SourcePackage(ctx context.Context, tenantID, engagementID shared.ID) (sourcepackage.Package, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if _, err := s.Get(ctx, tenantID, engagementID); err != nil {
		return sourcepackage.Package{}, err
	}
	if s.sources == nil {
		return sourcepackage.Package{}, shared.ErrNotFound
	}
	return s.sources.Get(ctx, tenantID, engagementID)
}

// CreateFromReusedSource creates a child-owned immutable association to the
// selected predecessor archive. Reuse never changes the predecessor package or
// inherits its execution authorization, and original upload attribution is kept.
func (s *Service) CreateFromReusedSource(ctx context.Context, in CreateInput, predecessorID, expectedVersionID shared.ID) (*domain.Engagement, sourcepackage.Package, error) {
	if s.lifecycleNotificationsEnabled() {
		tenantID, err := s.notificationTenant(ctx, in.TenantID)
		if err != nil {
			return nil, sourcepackage.Package{}, err
		}
		preparer, ok := s.sources.(ports.EngagementSourcePreparer)
		if !ok {
			return nil, sourcepackage.Package{}, fmt.Errorf("%w: transactional source preparation is not configured", shared.ErrValidation)
		}
		parent, err := s.SourcePackage(ctx, tenantID, predecessorID)
		if err != nil {
			return nil, sourcepackage.Package{}, err
		}
		if !expectedVersionID.IsZero() && parent.VersionID != expectedVersionID {
			return nil, sourcepackage.Package{}, fmt.Errorf("%w: selected source version no longer matches the predecessor", shared.ErrConflict)
		}
		id := s.ids.NewID()
		prepared, err := preparer.PrepareReuse(ctx, tenantID, predecessorID, id, parent.VersionID, in.CreatedBy, s.clock.Now())
		if err != nil {
			return nil, prepared, err
		}
		in.TenantID = tenantID
		in.InScope = append([]domain.Target{{Kind: domain.TargetRepo, Value: prepared.Target()}}, in.InScope...)
		return s.createWithPreparedSource(ctx, tenantID, in, id, prepared, "engagement.source_reused", func(item sourcepackage.Package) map[string]string {
			return map[string]string{
				"source_version_id": item.VersionID.String(), "sha256": item.SHA256,
				"source_assessment_id": predecessorID.String(), "reused_from_version_id": parent.VersionID.String(),
			}
		})
	}

	reuser, ok := s.sources.(ports.EngagementSourceReuser)
	if !ok {
		return nil, sourcepackage.Package{}, fmt.Errorf("%w: source reuse is not configured", shared.ErrValidation)
	}
	parent, err := s.SourcePackage(ctx, in.TenantID, predecessorID)
	if err != nil {
		return nil, sourcepackage.Package{}, err
	}
	if !expectedVersionID.IsZero() && parent.VersionID != expectedVersionID {
		return nil, sourcepackage.Package{}, fmt.Errorf("%w: selected source version no longer matches the predecessor", shared.ErrConflict)
	}
	id := s.ids.NewID()
	in.InScope = append([]domain.Target{{Kind: domain.TargetRepo, Value: parent.Target()}}, in.InScope...)
	assessment, err := s.create(ctx, in, id)
	if err != nil {
		return nil, sourcepackage.Package{}, err
	}
	item, err := reuser.Reuse(ctx, shared.TenantOrDefault(in.TenantID), predecessorID, id, parent.VersionID, in.CreatedBy, s.clock.Now())
	if err != nil {
		return nil, item, errors.Join(err, s.CompensateCreate(context.WithoutCancel(ctx), parent.TenantID, id, item))
	}
	if err := s.auditChange(ctx, in.CreatedBy, "engagement.source_reused", id, map[string]string{
		"source_version_id": item.VersionID.String(), "sha256": item.SHA256,
		"source_assessment_id": predecessorID.String(), "reused_from_version_id": parent.VersionID.String(),
	}, s.clock.Now()); err != nil {
		return nil, item, errors.Join(err, s.CompensateCreate(context.WithoutCancel(ctx), item.TenantID, id, item))
	}
	return assessment, item, nil
}

// createWithPreparedSource atomically binds a previously prepared archive with
// the engagement, custody audit entries, and created-event outbox record. The
// prepared archive is cleaned up only after a definite callback failure; an
// unknown transaction outcome retains bytes to avoid deleting a committed source.
func (s *Service) createWithPreparedSource(ctx context.Context, tenantID shared.ID, in CreateInput, id shared.ID, prepared sourcepackage.Package, sourceAction string, metadata func(sourcepackage.Package) map[string]string) (*domain.Engagement, sourcepackage.Package, error) {
	preparer, ok := s.sources.(ports.EngagementSourcePreparer)
	if !ok {
		return nil, prepared, fmt.Errorf("%w: transactional source preparation is not configured", shared.ErrValidation)
	}
	var created *domain.Engagement
	item := prepared
	callbackFailed := false
	err := s.notificationTx.Run(ctx, tenantID, func(txCtx context.Context) error {
		var err error
		created, err = s.create(txCtx, in, id)
		if err != nil {
			callbackFailed = true
			return err
		}
		item, err = preparer.Bind(txCtx, prepared)
		if err != nil {
			callbackFailed = true
			return err
		}
		if err := s.appendEngagementCreated(txCtx, tenantID, created, in.CreatedBy); err != nil {
			callbackFailed = true
			return err
		}
		if err := s.auditChange(txCtx, in.CreatedBy, sourceAction, id, metadata(item), s.clock.Now()); err != nil {
			callbackFailed = true
			return err
		}
		if err := s.auditChange(txCtx, in.CreatedBy, "engagement.created", id, nil, s.clock.Now()); err != nil {
			callbackFailed = true
			return err
		}
		return nil
	})
	if err != nil {
		if callbackFailed {
			return nil, item, errors.Join(err, s.DiscardUnpublishedSource(context.WithoutCancel(ctx), prepared))
		}
		return nil, item, err
	}
	return created, item, nil
}

func (s *Service) lifecycleNotificationsEnabled() bool {
	return s.notificationTx != nil && s.notifications != nil && s.notificationFacts != nil && s.notificationLocker != nil
}
func (s *Service) CompensateCreate(ctx context.Context, tenantID, engagementID shared.ID, createdSources ...sourcepackage.Package) error {
	for _, item := range createdSources {
		if !item.VersionID.IsZero() && (item.TenantID != shared.TenantOrDefault(tenantID) || item.EngagementID != engagementID) {
			return fmt.Errorf("%w: source cleanup ownership mismatch", shared.ErrValidation)
		}
	}
	var cleanupErr error
	if s.sources != nil {
		cleanupErr = s.sources.Delete(context.WithoutCancel(ctx), shared.TenantOrDefault(tenantID), engagementID)
	}
	deleteErr := s.repo.Delete(ctx, engagementID)
	if cleanupErr != nil || deleteErr != nil {
		return errors.Join(cleanupErr, deleteErr)
	}
	if compensator, ok := s.sources.(ports.EngagementSourceCompensator); ok {
		for _, item := range createdSources {
			if item.VersionID.IsZero() {
				continue
			}
			// A retained-command transaction may already have rolled back its
			// metadata. The captured package identifies only this child's bytes.
			if err := compensator.DiscardUnpublished(ctx, item); err != nil {
				return err
			}
		}
	}
	return nil
}

// DiscardUnpublishedSource releases only the private object captured by a failed
// create command, after its enclosing transaction has rolled back. It never
// removes engagement or source metadata; the store verifies that no durable
// reference remains and retains bytes if that outcome cannot be established.
func (s *Service) DiscardUnpublishedSource(ctx context.Context, item sourcepackage.Package) error {
	if item.VersionID.IsZero() {
		return nil
	}
	if compensator, ok := s.sources.(ports.EngagementSourceCompensator); ok {
		return compensator.DiscardUnpublished(ctx, item)
	}
	return nil
}

func (s *Service) create(ctx context.Context, in CreateInput, id shared.ID) (*domain.Engagement, error) {
	now := s.clock.Now()
	e, err := domain.New(id, in.TenantID, in.Name, in.Client, now)
	if err != nil {
		return nil, err
	}
	e.BusinessAssetID = in.BusinessAssetID
	e.AssessmentProjectID = in.AssessmentProjectID
	e.RequiresExplicitExecutionAuthorization = in.RequiresExplicitExecutionAuthorization
	if err := e.SetScope(in.InScope, in.OutOfScope, now); err != nil {
		return nil, err
	}
	if err := e.SetAuthorizationWindow(in.AuthorizedFrom, in.AuthorizedTo, in.Timezone, now); err != nil {
		return nil, err
	}
	if in.RoE != nil {
		if err := e.SetRoE(*in.RoE, now); err != nil {
			return nil, err
		}
	}
	// Ownership: the creating actor owns the engagement; updated_by starts equal.
	e.Audit.CreatedBy = in.CreatedBy
	e.Audit.UpdatedBy = in.CreatedBy
	if err := s.repo.Create(ctx, e); err != nil {
		return nil, fmt.Errorf("persist engagement: %w", err)
	}
	return e, nil
}

// Get returns one engagement with its scope, scoped to the caller's tenant:
// tenantID ” (single-tenant / default-tenant admin) sees any engagement; a non-empty tenant
// sees only its own. shared.ErrNotFound if it doesn't exist OR belongs to another tenant
// (existence is not revealed cross-tenant).
func (s *Service) Get(ctx context.Context, tenantID, id shared.ID) (*domain.Engagement, error) {
	return s.repo.GetByIDInTenant(ctx, tenantID, id)
}

// List returns engagements for a tenant (zero tenant = all, single-tenant mode).
func (s *Service) List(ctx context.Context, tenantID shared.ID) ([]*domain.Engagement, error) {
	return s.repo.List(ctx, tenantID)
}

// UpdateScope validates and replaces an engagement's in/out-of-scope target sets,
// persists, and records an append-only audit entry. The execution
// gate reads scope live, so the change takes effect on the next tool run – no
// restart. ErrNotFound if the engagement is missing; ErrValidation on a bad target.
func (s *Service) UpdateScope(ctx context.Context, actor string, tenantID, id shared.ID, in, out []domain.Target) (*domain.Engagement, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	var updated *domain.Engagement
	err := s.withNotificationMutation(ctx, tenantID, id, func(writeCtx context.Context, _ shared.ID, current *domain.Engagement) error {
		now := s.clock.Now()
		cp := *current
		if err := cp.SetScope(in, out, now); err != nil {
			return err
		}
		cp.Audit.UpdatedBy = actor
		if err := s.repo.Update(writeCtx, &cp); err != nil {
			return fmt.Errorf("persist scope: %w", err)
		}
		if err := s.auditChange(writeCtx, actor, "engagement.scope.update", id, map[string]string{"in_scope": strconv.Itoa(len(in)), "out_of_scope": strconv.Itoa(len(out))}, now); err != nil {
			return err
		}
		updated = &cp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// SetWindow validates and sets the legal authorization window, persists, and
// audits. The execution gate enforces the window on every tool run (±2m skew).
func (s *Service) SetWindow(ctx context.Context, actor string, tenantID, id shared.ID, from, to *time.Time, tz string) (*domain.Engagement, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	var updated *domain.Engagement
	err := s.withNotificationMutation(ctx, tenantID, id, func(writeCtx context.Context, tenant shared.ID, current *domain.Engagement) error {
		now := s.clock.Now()
		cp := *current
		if err := cp.SetAuthorizationWindow(from, to, tz, now); err != nil {
			return err
		}
		cp.Audit.UpdatedBy = actor
		if err := s.repo.Update(writeCtx, &cp); err != nil {
			return fmt.Errorf("persist authorization window: %w", err)
		}
		if err := s.auditChange(writeCtx, actor, "engagement.window.update", id, nil, now); err != nil {
			return err
		}
		updated = &cp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// Transition validates and applies a lifecycle status change (activate, complete,
// archive), persists, and audits. ErrValidation on an illegal transition.
func (s *Service) Transition(ctx context.Context, actor string, tenantID, id shared.ID, to domain.Status) (*domain.Engagement, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	var updated *domain.Engagement
	err := s.withNotificationMutation(ctx, tenantID, id, func(writeCtx context.Context, tenant shared.ID, current *domain.Engagement) error {
		if to == domain.StatusCompleted && current.Status != domain.StatusCompleted {
			required := s.requireCompletionSnapshot != nil && s.requireCompletionSnapshot(tenant.String())
			if required {
				if s.snapshots == nil {
					return fmt.Errorf("%w: assessment snapshot completion guard is not configured", shared.ErrValidation)
				}
				snapshot, _, err := s.snapshots.GetDefault(writeCtx, tenant, id)
				if err != nil {
					if errors.Is(err, shared.ErrNotFound) {
						return fmt.Errorf("%w: engagement requires a default finalized assessment snapshot before completion", shared.ErrValidation)
					}
					return fmt.Errorf("load default assessment snapshot: %w", err)
				}
				if snapshot.Lifecycle != assessmentsnapshot.LifecycleFinalized {
					return fmt.Errorf("%w: engagement default assessment snapshot is not finalized", shared.ErrValidation)
				}
			}
		}
		from := current.Status
		now := s.clock.Now()
		cp := *current
		if err := cp.Transition(to, now); err != nil {
			return err
		}
		cp.Audit.UpdatedBy = actor
		if err := s.repo.Update(writeCtx, &cp); err != nil {
			return fmt.Errorf("persist transition: %w", err)
		}
		if s.notifications != nil && from != cp.Status {
			if err := s.appendEngagementStatusChanged(writeCtx, tenant, &cp, from, actor); err != nil {
				return err
			}
		}
		if err := s.auditChange(writeCtx, actor, "engagement.transition", id, map[string]string{"to": string(to)}, now); err != nil {
			return err
		}
		updated = &cp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// SetRoE validates and sets the engagement's rules of engagement (allowed tool
// classes + blackout windows), persists, and audits. The execution gate enforces
// the RoE on every tool run.
// SetLiveRecon toggles the engagement's live-recon enablement. Enabling
// it is the moment live execution against real targets becomes possible, so it
// requires the operator to RE-CONFIRM the AUP and record a lab-authorization
// attestation at that moment – a plain boolean flip is not
// enough. Both are required to enable (refused otherwise) and captured in the append-only,
// hash-chained, signed audit log, so enabling live execution is an
// attributable, tamper-evident, non-repudiable act. Disabling needs neither.
func (s *Service) SetLiveRecon(ctx context.Context, actor string, tenantID, id shared.ID, enabled bool, aupVersion, attestation string) (*domain.Engagement, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	if enabled {
		if strings.TrimSpace(aupVersion) == "" {
			return nil, fmt.Errorf("%w: enabling live recon requires re-confirming the AUP version", shared.ErrValidation)
		}
		if strings.TrimSpace(attestation) == "" {
			return nil, fmt.Errorf("%w: enabling live recon requires a recorded lab-authorization attestation", shared.ErrValidation)
		}
	}
	var updated *domain.Engagement
	err := s.withNotificationMutation(ctx, tenantID, id, func(writeCtx context.Context, _ shared.ID, current *domain.Engagement) error {
		now := s.clock.Now()
		cp := *current
		cp.SetLiveRecon(enabled, now)
		cp.Audit.UpdatedBy = actor
		if err := s.repo.Update(writeCtx, &cp); err != nil {
			return fmt.Errorf("persist live-recon flag: %w", err)
		}
		meta := map[string]string{"enabled": strconv.FormatBool(enabled)}
		if enabled {
			meta["aup_version"], meta["attestation"] = strings.TrimSpace(aupVersion), strings.TrimSpace(attestation)
		}
		if err := s.auditChange(writeCtx, actor, "engagement.live_recon.update", id, meta, now); err != nil {
			return err
		}
		updated = &cp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// SetOffensiveRoE records the offensive rules of engagement (customer + emergency contact, risk ceiling,
// exclusions reviewed) that the offensive governance policy requires before adversary emulation or
// exploitation chains may run. It is tenant-scoped through the repository, so a cross-tenant write returns
// ErrNotFound. Validation of the fields (risk ceiling in range) lives on the domain mutator.
func (s *Service) SetOffensiveRoE(ctx context.Context, actor string, tenantID, id shared.ID, customerContact, emergencyContact, riskCeiling string, exclusionsChecked bool) (*domain.Engagement, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	var updated *domain.Engagement
	err := s.withNotificationMutation(ctx, tenantID, id, func(writeCtx context.Context, _ shared.ID, current *domain.Engagement) error {
		now := s.clock.Now()
		cp := *current
		if err := cp.SetOffensiveRoE(customerContact, emergencyContact, riskCeiling, exclusionsChecked, now); err != nil {
			return err
		}
		cp.Audit.UpdatedBy = actor
		if err := s.repo.Update(writeCtx, &cp); err != nil {
			return fmt.Errorf("persist offensive roe: %w", err)
		}
		meta := map[string]string{"risk_ceiling": cp.RiskCeiling, "exclusions_checked": strconv.FormatBool(cp.ExclusionsChecked)}
		if err := s.auditChange(writeCtx, actor, "engagement.offensive_roe.update", id, meta, now); err != nil {
			return err
		}
		updated = &cp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}
func (s *Service) SetRoE(ctx context.Context, actor string, tenantID, id shared.ID, roe domain.RoE) (*domain.Engagement, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	var updated *domain.Engagement
	err := s.withNotificationMutation(ctx, tenantID, id, func(writeCtx context.Context, _ shared.ID, current *domain.Engagement) error {
		now := s.clock.Now()
		cp := *current
		if err := cp.SetRoE(roe, now); err != nil {
			return err
		}
		cp.Audit.UpdatedBy = actor
		if err := s.repo.Update(writeCtx, &cp); err != nil {
			return fmt.Errorf("persist roe: %w", err)
		}
		if err := s.auditChange(writeCtx, actor, "engagement.roe.update", id, map[string]string{"allowed_tool_classes": strconv.Itoa(len(roe.AllowedToolClasses)), "blackouts": strconv.Itoa(len(roe.Blackouts))}, now); err != nil {
			return err
		}
		updated = &cp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// withNotificationMutation takes the visible engagement row lock only when
// lifecycle capture is configured. Legacy callers retain their existing path;
// capture-enabled mutations always execute the aggregate update, audit and
// source snapshot under the same tenant transaction.
func (s *Service) withNotificationMutation(ctx context.Context, tenantID, id shared.ID, write func(context.Context, shared.ID, *domain.Engagement) error) error {
	if s.notificationTx == nil || s.notifications == nil || s.notificationLocker == nil {
		current, err := s.repo.GetByIDInTenant(ctx, tenantID, id)
		if err != nil {
			return err
		}
		return write(ctx, shared.TenantOrDefault(tenantID), current)
	}
	tenant, err := s.notificationTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	return s.notificationTx.Run(ctx, tenant, func(txCtx context.Context) error {
		current, err := s.notificationLocker.GetByIDInTenantForUpdate(txCtx, tenant, id)
		if err != nil {
			return err
		}
		return write(txCtx, tenant, current)
	})
}

func (s *Service) notificationTenant(ctx context.Context, tenantID shared.ID) (shared.ID, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if current, ok := shared.TenantFrom(ctx); ok && shared.TenantOrDefault(current) != tenantID {
		return "", fmt.Errorf("%w: engagement belongs to another tenant", shared.ErrValidation)
	}
	return tenantID, nil
}

func (s *Service) appendEngagementCreated(ctx context.Context, tenant shared.ID, item *domain.Engagement, actor string) error {
	return s.appendEngagementEvent(ctx, tenant, notification.EventEngagementCreated, "engagement_created", item.ID.String(), item, "", actor)
}

func (s *Service) appendEngagementStatusChanged(ctx context.Context, tenant shared.ID, item *domain.Engagement, from domain.Status, actor string) error {
	return s.appendEngagementEvent(ctx, tenant, notification.EventEngagementStatusChanged, "engagement_status_changed", item.ID.String()+":"+string(item.Status), item, from, actor)
}

func (s *Service) appendEngagementEvent(ctx context.Context, tenant shared.ID, eventType notification.EventType, sourceKind, sourceID string, item *domain.Engagement, from domain.Status, actor string) error {
	if item == nil || item.ID.IsZero() {
		return fmt.Errorf("%w: engagement notification source is required", shared.ErrValidation)
	}
	facts, err := s.notificationFacts.SnapshotNotificationLifecycleFacts(ctx, tenant, item.ID, actor)
	if err != nil {
		return fmt.Errorf("snapshot engagement notification facts: %w", err)
	}
	if facts.EngagementName != "" && facts.EngagementName != item.Name {
		return fmt.Errorf("%w: engagement notification facts changed during mutation", shared.ErrConflict)
	}
	name := privacy.ScrubURLCredentials(notification.ScrubPersonalText(item.Name, 500))
	tz := privacy.ScrubURLCredentials(notification.ScrubPersonalText(item.Timezone, 100))
	actorName := privacy.ScrubURLCredentials(notification.ScrubPersonalText(facts.ActorName, 500))
	data := map[string]any{
		"title": engagementEventTitle(eventType), "summary": engagementEventSummary(eventType),
		"engagement_id": item.ID, "lead_user_id": facts.LeadUserID.String(),
		"status": item.Status, "from_status": from, "to_status": item.Status,
		"timezone": tz, "engagement_name": name,
	}
	if item.AuthorizedFrom != nil {
		data["authorized_from"] = item.AuthorizedFrom.UTC()
	}
	if item.AuthorizedTo != nil {
		data["authorized_to"] = item.AuthorizedTo.UTC()
	}
	if !facts.ActorUserID.IsZero() {
		data["actor_user_id"] = facts.ActorUserID
	}
	if facts.ActorName != "" {
		data["actor"] = actorName
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode engagement notification data: %w", err)
	}
	occurredAt := s.clock.Now().UTC()
	vars := map[string]string{
		"event_type": string(eventType), "event_label": notificationEventLabel(eventType),
		"occurred_at": occurredAt.Format(time.RFC3339), "title": engagementEventTitle(eventType), "summary": engagementEventSummary(eventType),
		"status": string(item.Status), "from_status": string(from), "to_status": string(item.Status),
		"timezone": tz, "engagement_name": name, "actor": actorName,
	}
	if item.AuthorizedFrom != nil {
		vars["authorized_from"] = item.AuthorizedFrom.UTC().Format(time.RFC3339)
	}
	if item.AuthorizedTo != nil {
		vars["authorized_to"] = item.AuthorizedTo.UTC().Format(time.RFC3339)
	}
	record, err := notification.SnapshotSourceRecord(notification.SourceRecord{
		TenantID: tenant, SourceKind: sourceKind, SourceID: sourceID, EventType: eventType,
		EngagementID: item.ID, OccurredAt: occurredAt, Data: raw, SubjectKind: "engagement", SubjectID: item.ID.String(),
	}, vars)
	if err != nil {
		return fmt.Errorf("snapshot engagement notification: %w", err)
	}
	if err := s.notifications.Append(ctx, record); err != nil {
		return fmt.Errorf("append engagement notification: %w", err)
	}
	return nil
}

func notificationEventLabel(eventType notification.EventType) string {
	if spec, ok := notification.LookupEvent(eventType); ok {
		return spec.Label
	}
	return ""
}

func engagementEventTitle(eventType notification.EventType) string {
	if eventType == notification.EventEngagementStatusChanged {
		return "Engagement status changed"
	}
	return "Engagement created"
}

func engagementEventSummary(eventType notification.EventType) string {
	if eventType == notification.EventEngagementStatusChanged {
		return "An engagement lifecycle status changed."
	}
	return "An engagement was created."
}

// requireActor enforces attributability: never apply an audited
// change without a principal, even if a caller omits one.
func requireActor(actor string) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	return nil
}

// auditChange records an attributable, append-only audit entry for a config
// change. The change is already persisted; a failed audit write is surfaced as an
// error (matching the finding-triage path) rather than silently dropped.
func (s *Service) auditChange(ctx context.Context, actor, action string, id shared.ID, md map[string]string, now time.Time) error {
	if md == nil {
		md = map[string]string{}
	}
	md["engagement"] = id.String()
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: id.String(), Metadata: md, At: now}); err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}

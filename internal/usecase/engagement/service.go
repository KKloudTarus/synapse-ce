// Package engagement (use case) implements engagement application logic.
package engagement

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service implements engagement use cases.
type Service struct {
	repo  ports.EngagementRepository
	clock ports.Clock
	ids   ports.IDGenerator
	audit ports.AuditLogger
}

// NewService wires the engagement use case with its driven ports.
func NewService(repo ports.EngagementRepository, clock ports.Clock, ids ports.IDGenerator, audit ports.AuditLogger) *Service {
	return &Service{repo: repo, clock: clock, ids: ids, audit: audit}
}

// CreateInput is the input for creating an engagement.
type CreateInput struct {
	TenantID       shared.ID
	CreatedBy      string // the authenticated actor that owns the engagement (ownership)
	Name           string
	Client         string
	InScope        []domain.Target
	OutOfScope     []domain.Target
	AuthorizedFrom *time.Time
	AuthorizedTo   *time.Time
	Timezone       string
}

// Create validates and persists a new engagement with its scope.
func (s *Service) Create(ctx context.Context, in CreateInput) (*domain.Engagement, error) {
	now := s.clock.Now()
	e, err := domain.New(s.ids.NewID(), in.TenantID, in.Name, in.Client, now)
	if err != nil {
		return nil, err
	}
	if err := e.SetScope(in.InScope, in.OutOfScope, now); err != nil {
		return nil, err
	}
	if err := e.SetAuthorizationWindow(in.AuthorizedFrom, in.AuthorizedTo, in.Timezone, now); err != nil {
		return nil, err
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
	e, err := s.repo.GetByIDInTenant(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	cp := *e // copy-then-mutate: never mutate the repo's returned aggregate in place
	if err := cp.SetScope(in, out, now); err != nil {
		return nil, err
	}
	cp.Audit.UpdatedBy = actor // attribute the last modifier
	if err := s.repo.Update(ctx, &cp); err != nil {
		return nil, fmt.Errorf("persist scope: %w", err)
	}
	if err := s.auditChange(ctx, actor, "engagement.scope.update", id, map[string]string{
		"in_scope": strconv.Itoa(len(in)), "out_of_scope": strconv.Itoa(len(out)),
	}, now); err != nil {
		return nil, err
	}
	return &cp, nil
}

// SetWindow validates and sets the legal authorization window, persists, and
// audits. The execution gate enforces the window on every tool run (±2m skew).
func (s *Service) SetWindow(ctx context.Context, actor string, tenantID, id shared.ID, from, to *time.Time, tz string) (*domain.Engagement, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	e, err := s.repo.GetByIDInTenant(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	cp := *e
	if err := cp.SetAuthorizationWindow(from, to, tz, now); err != nil {
		return nil, err
	}
	cp.Audit.UpdatedBy = actor // attribute the last modifier
	if err := s.repo.Update(ctx, &cp); err != nil {
		return nil, fmt.Errorf("persist authorization window: %w", err)
	}
	if err := s.auditChange(ctx, actor, "engagement.window.update", id, nil, now); err != nil {
		return nil, err
	}
	return &cp, nil
}

// Transition validates and applies a lifecycle status change (activate, complete,
// archive), persists, and audits. ErrValidation on an illegal transition.
func (s *Service) Transition(ctx context.Context, actor string, tenantID, id shared.ID, to domain.Status) (*domain.Engagement, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	e, err := s.repo.GetByIDInTenant(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	cp := *e
	if err := cp.Transition(to, now); err != nil {
		return nil, err
	}
	cp.Audit.UpdatedBy = actor // attribute the last modifier
	if err := s.repo.Update(ctx, &cp); err != nil {
		return nil, fmt.Errorf("persist transition: %w", err)
	}
	if err := s.auditChange(ctx, actor, "engagement.transition", id, map[string]string{"to": string(to)}, now); err != nil {
		return nil, err
	}
	return &cp, nil
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
	e, err := s.repo.GetByIDInTenant(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	cp := *e
	cp.SetLiveRecon(enabled, now)
	cp.Audit.UpdatedBy = actor // attribute the last modifier
	if err := s.repo.Update(ctx, &cp); err != nil {
		return nil, fmt.Errorf("persist live-recon flag: %w", err)
	}
	meta := map[string]string{"enabled": strconv.FormatBool(enabled)}
	if enabled {
		// The re-confirmation + attestation become part of the immutable custody record.
		meta["aup_version"] = strings.TrimSpace(aupVersion)
		meta["attestation"] = strings.TrimSpace(attestation)
	}
	if err := s.auditChange(ctx, actor, "engagement.live_recon.update", id, meta, now); err != nil {
		return nil, err
	}
	return &cp, nil
}

func (s *Service) SetRoE(ctx context.Context, actor string, tenantID, id shared.ID, roe domain.RoE) (*domain.Engagement, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	e, err := s.repo.GetByIDInTenant(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	cp := *e
	if err := cp.SetRoE(roe, now); err != nil {
		return nil, err
	}
	cp.Audit.UpdatedBy = actor // attribute the last modifier
	if err := s.repo.Update(ctx, &cp); err != nil {
		return nil, fmt.Errorf("persist roe: %w", err)
	}
	if err := s.auditChange(ctx, actor, "engagement.roe.update", id, map[string]string{
		"allowed_tool_classes": strconv.Itoa(len(roe.AllowedToolClasses)),
		"blackouts":            strconv.Itoa(len(roe.Blackouts)),
	}, now); err != nil {
		return nil, err
	}
	return &cp, nil
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

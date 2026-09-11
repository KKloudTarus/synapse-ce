// Package ownership exposes tenant-bound ownership administration and human triage.
package ownership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var ErrWorkerUnavailable = errors.New("ownership routing worker is not configured")

type Service struct {
	repo     ports.OwnershipRepository
	read     ports.OwnershipReader
	findings ports.FindingRepository
	tx       ports.TenantTransactionRunner
	audit    ports.AuditLogger
	clock    ports.Clock
	ids      ports.IDGenerator
	notify   bool
	mode     string
	runtime  ports.OwnershipRunStarter
}

func NewService(repo ports.OwnershipRepository, read ports.OwnershipReader, findings ports.FindingRepository, tx ports.TenantTransactionRunner, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator, mode string, notify bool) (*Service, error) {
	if repo == nil || read == nil || findings == nil || tx == nil || audit == nil || clock == nil || ids == nil || mode != "observe" && mode != "enforce" {
		return nil, fmt.Errorf("%w: invalid ownership dependencies or mode", shared.ErrValidation)
	}
	return &Service{repo: repo, read: read, findings: findings, tx: tx, audit: audit, clock: clock, ids: ids, mode: mode, notify: notify}, nil
}

// SetRunStarter is composition-time wiring, alongside production worker support.
func (s *Service) SetRunStarter(runtime ports.OwnershipRunStarter) { s.runtime = runtime }

type Capability struct {
	Enabled          bool   `json:"enabled"`
	Mode             string `json:"mode"`
	RoutingAvailable bool   `json:"routing_available"`
	Reason           string `json:"reason,omitempty"`
}

func (s *Service) Capability() Capability {
	return Capability{Enabled: true, Mode: s.mode, RoutingAvailable: s.runtime != nil, Reason: func() string {
		if s.runtime == nil {
			return "worker_not_configured"
		}
		return ""
	}()}
}

func (s *Service) check(ctx context.Context, actor string, permission user.Permission, eng shared.ID) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return shared.ErrValidation
	}
	if actor == "" {
		return shared.ErrForbidden
	}
	if err := s.read.AuthorizeOwnership(ctx, shared.ID(actor), permission); err != nil {
		return err
	}
	if !eng.IsZero() {
		return s.read.VisibleOwnershipEngagement(ctx, eng)
	}
	return nil
}
func (s *Service) mutate(ctx context.Context, actor string, eng shared.ID, action, target string, fn func(context.Context) error) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return shared.ErrValidation
	}
	return s.tx.Run(ctx, tenant, func(ctx context.Context) error {
		if err := s.check(ctx, actor, user.PermAdminister, eng); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		return s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target, At: s.clock.Now().UTC()})
	})
}
func validID(id shared.ID) bool {
	return !id.IsZero() && len(id.String()) <= 200 && strings.TrimSpace(id.String()) == id.String() && !strings.ContainsAny(id.String(), "\x00\r\n")
}
func validKey(key string) bool { return validID(shared.ID(key)) }
func validPage(after shared.ID, limit int) bool {
	return (after.IsZero() || validID(after)) && limit > 0 && limit <= 200
}

type TeamInput struct {
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Archived bool   `json:"archived"`
	Revision int    `json:"revision"`
}

func (s *Service) SaveTeam(ctx context.Context, actor string, id shared.ID, in TeamInput) (out domain.Team, err error) {
	if id.IsZero() {
		id = s.ids.NewID()
		if in.Revision != 0 || in.Archived {
			return out, shared.ErrValidation
		}
	}
	err = s.mutate(ctx, actor, "", "ownership.team.saved", id.String(), func(ctx context.Context) error {
		now := s.clock.Now().UTC()
		out = domain.Team{ID: id, Slug: in.Slug, Name: strings.TrimSpace(in.Name), Archived: in.Archived, Revision: 1, CreatedAt: now, UpdatedAt: now}
		out.TenantID, _ = shared.TenantFrom(ctx)
		var e error
		if in.Revision == 0 {
			out, e = s.repo.CreateTeam(ctx, out)
		} else {
			current, e := s.repo.GetTeam(ctx, id)
			if e != nil {
				return e
			}
			out.CreatedAt = current.CreatedAt
			out.Revision = in.Revision + 1
			out, e = s.repo.UpdateTeam(ctx, out, in.Revision)
			return e
		}
		return e
	})
	return
}
func (s *Service) Team(ctx context.Context, actor string, id shared.ID) (domain.Team, error) {
	if err := s.check(ctx, actor, user.PermView, ""); err != nil {
		return domain.Team{}, err
	}
	return s.repo.GetTeam(ctx, id)
}
func (s *Service) Teams(ctx context.Context, actor string, after shared.ID, limit int) ([]domain.Team, error) {
	if !validPage(after, limit) {
		return nil, shared.ErrValidation
	}
	if err := s.check(ctx, actor, user.PermView, ""); err != nil {
		return nil, err
	}
	return s.repo.ListTeams(ctx, after, limit)
}
func (s *Service) Members(ctx context.Context, actor string, team, after shared.ID, limit int) ([]domain.Membership, error) {
	if !validPage(after, limit) {
		return nil, shared.ErrValidation
	}
	if _, err := s.Team(ctx, actor, team); err != nil {
		return nil, err
	}
	return s.repo.ListMembers(ctx, team, after, limit)
}
func (s *Service) Member(ctx context.Context, actor string, team, member shared.ID, revision int, remove bool) error {
	if !validID(team) || !validID(member) || revision < 1 {
		return shared.ErrValidation
	}
	return s.mutate(ctx, actor, "", "ownership.membership.changed", team.String(), func(ctx context.Context) error {
		t, err := s.repo.GetTeam(ctx, team)
		if err != nil {
			return err
		}
		if t.Revision != revision {
			return shared.ErrConflict
		}
		t.Revision++
		t.UpdatedAt = s.clock.Now().UTC()
		if _, err := s.repo.UpdateTeam(ctx, t, revision); err != nil {
			return err
		}
		if remove {
			return s.repo.RemoveMember(ctx, team, member)
		}
		return s.repo.AddMember(ctx, team, member, s.clock.Now().UTC())
	})
}

func (s *Service) Mappings(ctx context.Context, actor string, eng shared.ID, repository, after string, limit int) ([]ports.OwnershipMapping, error) {
	if !validID(eng) || strings.TrimSpace(repository) == "" || len(repository) > 2048 || strings.ContainsAny(repository, "\x00\r\n") || limit < 1 || limit > 200 || after != "" && !domain.ValidOwner(after) {
		return nil, shared.ErrValidation
	}
	if err := s.check(ctx, actor, user.PermAdminister, eng); err != nil {
		return nil, err
	}
	return s.repo.ListMappings(ctx, eng, repository, after, limit)
}
func (s *Service) SaveMapping(ctx context.Context, actor string, eng shared.ID, m ports.OwnershipMapping, remove bool) error {
	if !validID(eng) || m.Revision < 1 {
		return shared.ErrValidation
	}
	return s.mutate(ctx, actor, eng, "ownership.mapping.changed", eng.String(), func(ctx context.Context) error {
		if remove {
			return s.repo.DeleteMapping(ctx, eng, m.Mapping.Repository, m.Mapping.Owner, m.Revision)
		}
		return s.repo.SaveMapping(ctx, eng, m)
	})
}
func (s *Service) AssetMappings(ctx context.Context, actor string, after shared.ID, limit int) ([]ports.OwnershipAssetMapping, error) {
	if !validPage(after, limit) {
		return nil, shared.ErrValidation
	}
	if err := s.check(ctx, actor, user.PermAdminister, ""); err != nil {
		return nil, err
	}
	return s.repo.ListAssetMappings(ctx, after, limit)
}
func (s *Service) SaveAssetMapping(ctx context.Context, actor string, m ports.OwnershipAssetMapping, remove bool) error {
	if !validID(m.Mapping.AssetID) || m.Revision < 1 {
		return shared.ErrValidation
	}
	return s.mutate(ctx, actor, "", "ownership.asset_mapping.changed", m.Mapping.AssetID.String(), func(ctx context.Context) error {
		if remove {
			return s.repo.DeleteAssetMapping(ctx, m.Mapping.AssetID, m.Revision)
		}
		return s.repo.SaveAssetMapping(ctx, m)
	})
}

type SnapshotInput struct {
	EngagementID      shared.ID `json:"engagement_id"`
	Repository        string    `json:"repository"`
	SourceRevision    string    `json:"source_revision"`
	FilePath          string    `json:"file_path"`
	Content           string    `json:"content"`
	Approve           bool      `json:"approve"`
	AcceptDiagnostics bool      `json:"accept_diagnostics"`
}
type SnapshotView struct {
	domain.Snapshot
	Diagnostics []domain.Diagnostic `json:"diagnostics"`
}

func snapshotView(snap domain.Snapshot) (SnapshotView, error) {
	p, err := snap.Parse()
	if p.Diagnostics == nil {
		p.Diagnostics = []domain.Diagnostic{}
	}
	return SnapshotView{Snapshot: snap, Diagnostics: p.Diagnostics}, err
}
func (s *Service) ImportSnapshot(ctx context.Context, actor string, in SnapshotInput) (out SnapshotView, err error) {
	if !validID(in.EngagementID) {
		return out, shared.ErrValidation
	}
	id := s.ids.NewID()
	err = s.mutate(ctx, actor, in.EngagementID, "ownership.snapshot.imported", id.String(), func(ctx context.Context) error {
		tenant, _ := shared.TenantFrom(ctx)
		snap := domain.Snapshot{TenantID: tenant, ID: id, EngagementID: in.EngagementID, Repository: in.Repository, Revision: in.SourceRevision, FilePath: in.FilePath, Content: in.Content, Hash: domain.ContentHash(in.Content), ParserVersion: domain.ParserVersion, Trust: "untrusted", CreatedAt: s.clock.Now().UTC(), AcceptDiagnostics: in.AcceptDiagnostics}
		if in.Approve {
			snap.Trust = "admin_import"
			snap.ApprovedBy = actor
		}
		var e error
		out, e = snapshotView(snap)
		if e != nil {
			return e
		}
		return s.repo.CreateSnapshot(ctx, snap)
	})
	return
}
func (s *Service) Snapshot(ctx context.Context, actor string, id shared.ID) (SnapshotView, error) {
	if err := s.check(ctx, actor, user.PermAdminister, ""); err != nil {
		return SnapshotView{}, err
	}
	snap, err := s.repo.GetSnapshot(ctx, id)
	if err != nil {
		return SnapshotView{}, err
	}
	if err = s.read.VisibleOwnershipEngagement(ctx, snap.EngagementID); err != nil {
		return SnapshotView{}, err
	}
	return snapshotView(snap)
}
func (s *Service) Snapshots(ctx context.Context, actor string, eng, after shared.ID, limit int) ([]domain.Snapshot, error) {
	if !validID(eng) || !validPage(after, limit) {
		return nil, shared.ErrValidation
	}
	if err := s.check(ctx, actor, user.PermAdminister, eng); err != nil {
		return nil, err
	}
	return s.read.ListOwnershipSnapshots(ctx, eng, after, limit)
}
func (s *Service) ApproveSnapshot(ctx context.Context, actor string, id shared.ID, hash string, accept bool) (out SnapshotView, err error) {
	err = s.mutate(ctx, actor, "", "ownership.snapshot.approved", id.String(), func(ctx context.Context) error {
		snap, e := s.repo.GetSnapshot(ctx, id)
		if e != nil {
			return e
		}
		if e = s.read.VisibleOwnershipEngagement(ctx, snap.EngagementID); e != nil {
			return e
		}
		if snap.Hash != hash {
			return shared.ErrConflict
		}
		snap.ID = s.ids.NewID()
		snap.Trust = "admin_import"
		snap.ApprovedBy = actor
		snap.AcceptDiagnostics = accept
		snap.CreatedAt = s.clock.Now().UTC()
		out, e = snapshotView(snap)
		if e != nil {
			return e
		}
		return s.repo.CreateSnapshot(ctx, snap)
	})
	return
}

type PolicyInput struct {
	EngagementID shared.ID             `json:"engagement_id"`
	Repository   string                `json:"repository"`
	Version      int                   `json:"version"`
	SnapshotID   shared.ID             `json:"snapshot_id"`
	Rules        []domain.Rule         `json:"rules"`
	Mappings     []domain.Mapping      `json:"mappings"`
	Assets       []domain.AssetMapping `json:"assets"`
}

func (s *Service) SavePolicy(ctx context.Context, actor string, id shared.ID, in PolicyInput) (out domain.PolicyVersion, err error) {
	if !validID(in.EngagementID) || in.Version < 1 {
		return out, shared.ErrValidation
	}
	if id.IsZero() {
		if in.Version != 1 {
			return out, shared.ErrValidation
		}
		id = s.ids.NewID()
	}
	err = s.mutate(ctx, actor, in.EngagementID, "ownership.policy.version_created", id.String(), func(ctx context.Context) error {
		tenant, _ := shared.TenantFrom(ctx)
		out = domain.PolicyVersion{TenantID: tenant, PolicyID: id, EngagementID: in.EngagementID, Repository: in.Repository, Version: in.Version, SnapshotID: in.SnapshotID, Rules: in.Rules, Mappings: in.Mappings, Assets: in.Assets, CreatedBy: actor, CreatedAt: s.clock.Now().UTC()}
		var snap *domain.Snapshot
		if !in.SnapshotID.IsZero() {
			v, e := s.repo.GetSnapshot(ctx, in.SnapshotID)
			if e != nil {
				return e
			}
			snap = &v
		}
		if _, e := domain.NewResolver(out, snap); e != nil {
			return e
		}
		return s.repo.CreatePolicyVersion(ctx, out)
	})
	return
}
func (s *Service) Policy(ctx context.Context, actor string, id shared.ID) (ports.OwnershipPolicyHeader, error) {
	if err := s.check(ctx, actor, user.PermAdminister, ""); err != nil {
		return ports.OwnershipPolicyHeader{}, err
	}
	p, err := s.read.GetOwnershipPolicy(ctx, id)
	if err != nil {
		return p, err
	}
	if err = s.read.VisibleOwnershipEngagement(ctx, p.EngagementID); err != nil {
		return ports.OwnershipPolicyHeader{}, err
	}
	return p, nil
}
func (s *Service) PolicyVersion(ctx context.Context, actor string, id shared.ID, version int) (domain.PolicyVersion, error) {
	if version < 1 {
		return domain.PolicyVersion{}, shared.ErrValidation
	}
	if _, err := s.Policy(ctx, actor, id); err != nil {
		return domain.PolicyVersion{}, err
	}
	return s.repo.GetPolicyVersion(ctx, id, version)
}
func (s *Service) Policies(ctx context.Context, actor string, eng, after shared.ID, limit int) ([]ports.OwnershipPolicyHeader, error) {
	if !validID(eng) || !validPage(after, limit) {
		return nil, shared.ErrValidation
	}
	if err := s.check(ctx, actor, user.PermAdminister, eng); err != nil {
		return nil, err
	}
	return s.read.ListOwnershipPolicies(ctx, eng, after, limit)
}
func (s *Service) Activate(ctx context.Context, actor string, a ports.OwnershipActivation) error {
	return s.mutate(ctx, actor, "", "ownership.policy.activated", a.PolicyID.String(), func(ctx context.Context) error {
		p, e := s.read.GetOwnershipPolicy(ctx, a.PolicyID)
		if e != nil {
			return e
		}
		if e = s.read.VisibleOwnershipEngagement(ctx, p.EngagementID); e != nil {
			return e
		}
		return s.repo.ActivatePolicy(ctx, a)
	})
}

func (s *Service) Inbox(ctx context.Context, actor string, f ports.OwnershipInboxFilter) (ports.OwnershipInboxPage, error) {
	for _, id := range []shared.ID{f.EngagementID, f.TeamID, f.AssigneeID} {
		if !id.IsZero() && !validID(id) {
			return ports.OwnershipInboxPage{}, shared.ErrValidation
		}
	}
	if f.SLAStatus != "" && !sla.RemediationStatus(f.SLAStatus).Valid() || len(f.Kind) > 80 {
		return ports.OwnershipInboxPage{}, shared.ErrValidation
	}
	if !validPage(f.After, f.Limit) || f.Severity != "" && shared.SeverityRank(f.Severity) == 0 || f.Status != "" && !f.Status.Valid() {
		return ports.OwnershipInboxPage{}, shared.ErrValidation
	}
	if err := s.check(ctx, actor, user.PermView, f.EngagementID); err != nil {
		return ports.OwnershipInboxPage{}, err
	}
	f.MemberID = shared.ID(actor)
	return s.read.OwnershipInbox(ctx, f)
}
func (s *Service) Current(ctx context.Context, actor string, eng, id shared.ID) (ports.OwnershipCurrent, error) {
	if !validID(eng) || !validID(id) {
		return ports.OwnershipCurrent{}, shared.ErrValidation
	}
	if err := s.check(ctx, actor, user.PermView, eng); err != nil {
		return ports.OwnershipCurrent{}, err
	}
	return s.repo.GetAssignment(ctx, eng, id)
}
func (s *Service) History(ctx context.Context, actor string, eng, id shared.ID, c ports.OwnershipHistoryCursor) ([]domain.Decision, error) {
	if c.Limit < 1 || c.Limit > 200 {
		return nil, shared.ErrValidation
	}
	if _, err := s.Current(ctx, actor, eng, id); err != nil {
		return nil, err
	}
	return s.repo.ListDecisions(ctx, eng, id, c)
}

type AssignmentInput struct {
	EngagementID      shared.ID `json:"engagement_id"`
	FindingID         shared.ID `json:"finding_id"`
	Action            string    `json:"action"`
	TeamID            shared.ID `json:"team_id,omitempty"`
	AssigneeID        shared.ID `json:"assignee_id,omitempty"`
	ClearAssignee     bool      `json:"clear_assignee,omitempty"`
	FindingVersion    int       `json:"finding_version"`
	OwnershipRevision int       `json:"ownership_revision"`
	ManualGeneration  int64     `json:"manual_generation"`
}

func validateAssignment(in AssignmentInput) error {
	if in.ClearAssignee && (in.Action != "transfer" || !in.AssigneeID.IsZero()) {
		return shared.ErrValidation
	}
	for _, id := range []shared.ID{in.TeamID, in.AssigneeID} {
		if !id.IsZero() && !validID(id) {
			return shared.ErrValidation
		}
	}
	if !validID(in.EngagementID) || !validID(in.FindingID) || in.FindingVersion < 1 || in.OwnershipRevision < 0 || in.ManualGeneration < 0 {
		return shared.ErrValidation
	}
	switch in.Action {
	case "assign", "transfer", "claim":
	case "clear", "release":
		if !in.TeamID.IsZero() || !in.AssigneeID.IsZero() {
			return shared.ErrValidation
		}
	default:
		return shared.ErrValidation
	}
	return nil
}
func (s *Service) Assign(ctx context.Context, actor, key string, in AssignmentInput) (domain.Decision, error) {
	if err := validateAssignment(in); err != nil {
		return domain.Decision{}, err
	}
	if !validKey(key) {
		return domain.Decision{}, shared.ErrValidation
	}
	if err := s.check(ctx, actor, user.PermTriage, in.EngagementID); err != nil {
		return domain.Decision{}, err
	}
	if in.Action == "release" && s.runtime == nil {
		return domain.Decision{}, ErrWorkerUnavailable
	}
	kind := in.Action
	if kind == "transfer" {
		if in.TeamID.IsZero() {
			return domain.Decision{}, shared.ErrValidation
		}
	}
	if kind == "claim" {
		if !in.AssigneeID.IsZero() && in.AssigneeID.String() != actor {
			return domain.Decision{}, shared.ErrValidation
		}
		in.AssigneeID = shared.ID(actor)
	}
	tenant, _ := shared.TenantFrom(ctx)
	source, _ := json.Marshal([]string{tenant.String(), actor, key})
	return s.repo.ApplyAssignment(ctx, ports.OwnershipMutation{EngagementID: in.EngagementID, FindingID: in.FindingID, Actor: actor, Kind: kind, Key: domain.ContentHash(string(source)), DecisionID: s.ids.NewID(), TeamID: in.TeamID, AssigneeID: in.AssigneeID, LegacyAssignee: in.AssigneeID.String(), ClearAssignee: in.ClearAssignee, ExpectedFindingVersion: in.FindingVersion, ExpectedRevision: in.OwnershipRevision, ExpectedManualGeneration: in.ManualGeneration, Notify: s.notify, At: s.clock.Now().UTC()})
}

var _ ports.FindingAssigneeWriter = (*Service)(nil)

func (s *Service) SetLegacyAssignee(ctx context.Context, eng, id shared.ID, assignee, actor string, version int) (out finding.Finding, err error) {
	if !validID(eng) || !validID(id) || version < 1 || len(assignee) > 4096 {
		return out, shared.ErrValidation
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return out, shared.ErrValidation
	}
	err = s.tx.Run(ctx, tenant, func(ctx context.Context) error {
		if e := s.check(ctx, actor, user.PermTriage, eng); e != nil {
			return e
		}
		current, e := s.repo.GetAssignment(ctx, eng, id)
		if e != nil {
			return e
		}
		// Free text remains free text. Never infer identity from a display name or token.
		out, e = s.findings.GetByEngagementAndID(ctx, eng, id)
		if e != nil {
			return e
		}
		at := s.clock.Now().UTC()
		_, e = s.repo.ApplyAssignment(ctx, ports.OwnershipMutation{EngagementID: eng, FindingID: id, Actor: actor, Kind: "assign", Key: "legacy:" + s.ids.NewID().String(), DecisionID: s.ids.NewID(), TeamID: current.Assignment.TeamID, LegacyAssignee: strings.TrimSpace(assignee), ExpectedFindingVersion: version, ExpectedRevision: current.Assignment.Revision, ExpectedManualGeneration: current.Assignment.ManualGeneration, Notify: s.notify, LegacyEndpoint: true, At: at})
		if e != nil {
			return e
		}
		// ApplyAssignment holds the finding CAS and appends audit last. No I/O after it.
		out.Assignee = strings.TrimSpace(assignee)
		out.Version = version + 1
		out.Audit.UpdatedAt = at
		return nil
	})
	return
}

type BulkResult struct {
	FindingID    shared.ID        `json:"finding_id"`
	EngagementID shared.ID        `json:"engagement_id"`
	Decision     *domain.Decision `json:"decision,omitempty"`
	Status       int              `json:"status"`
	Error        string           `json:"error,omitempty"`
}

func (s *Service) Bulk(ctx context.Context, actor, key string, items []AssignmentInput) ([]BulkResult, error) {
	if len(items) < 1 || len(items) > 200 || !validKey(key) {
		return nil, shared.ErrValidation
	}
	if err := s.check(ctx, actor, user.PermTriage, ""); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, in := range items {
		if err := validateAssignment(in); err != nil {
			return nil, err
		}
		id := in.EngagementID.String() + "\x00" + in.FindingID.String()
		if seen[id] {
			return nil, shared.ErrValidation
		}
		seen[id] = true
	}
	payload, _ := json.Marshal(items)
	if err := s.read.ReserveOwnershipBulk(ctx, shared.ID(actor), key, domain.ContentHash(string(payload)), s.clock.Now().UTC()); err != nil {
		return nil, err
	}
	out := make([]BulkResult, 0, len(items))
	for _, in := range items {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		source, _ := json.Marshal([]string{key, in.EngagementID.String(), in.FindingID.String()})
		d, err := s.Assign(ctx, actor, "bulk:"+domain.ContentHash(string(source)), in)
		r := BulkResult{FindingID: in.FindingID, EngagementID: in.EngagementID, Status: 200}
		switch {
		case err == nil:
			r.Decision = &d
		case errors.Is(err, shared.ErrNotFound):
			r.Status = 404
			r.Error = "not_found"
		case errors.Is(err, shared.ErrForbidden):
			r.Status = 403
			r.Error = "forbidden"
		case errors.Is(err, shared.ErrConflict):
			r.Status = 409
			r.Error = "conflict"
		case errors.Is(err, shared.ErrValidation):
			r.Status = 400
			r.Error = "invalid_assignment"
		case errors.Is(err, ErrWorkerUnavailable):
			r.Status = 503
			r.Error = "worker_not_configured"
		default:
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}

type RunInput struct {
	Version        int                        `json:"version"`
	PolicyRevision int                        `json:"policy_revision"`
	PolicyHash     string                     `json:"policy_hash"`
	Filter         ports.OwnershipInboxFilter `json:"filter"`
}

func (s *Service) StartRun(ctx context.Context, actor, key string, id shared.ID, mode string, in RunInput) (ports.OwnershipRun, error) {
	if !validKey(key) || in.Version < 1 || in.PolicyRevision < 1 || len(in.PolicyHash) != 64 || mode != "preview" && mode != "reroute" {
		return ports.OwnershipRun{}, shared.ErrValidation
	}
	p, err := s.Policy(ctx, actor, id)
	if err != nil {
		return ports.OwnershipRun{}, err
	}
	v, err := s.repo.GetPolicyVersion(ctx, id, in.Version)
	if err != nil {
		return ports.OwnershipRun{}, err
	}
	if p.Revision != in.PolicyRevision || v.Hash() != in.PolicyHash {
		return ports.OwnershipRun{}, shared.ErrConflict
	}
	if !in.Filter.EngagementID.IsZero() && in.Filter.EngagementID != p.EngagementID {
		return ports.OwnershipRun{}, shared.ErrValidation
	}
	in.Filter.EngagementID = p.EngagementID
	in.Filter.Limit = 1
	if _, err := s.Inbox(ctx, actor, in.Filter); err != nil {
		return ports.OwnershipRun{}, err
	}
	if s.runtime == nil || mode == "reroute" && s.mode != "enforce" {
		return ports.OwnershipRun{}, ErrWorkerUnavailable
	}
	data, _ := json.Marshal(in.Filter)
	return s.runtime.StartOwnershipRun(ctx, ports.OwnershipRunRequest{Policy: p, Version: v, Actor: shared.ID(actor), Key: key, Mode: mode, Filter: data})
}
func (s *Service) Run(ctx context.Context, actor string, id shared.ID) (ports.OwnershipRun, error) {
	if err := s.check(ctx, actor, user.PermAdminister, ""); err != nil {
		return ports.OwnershipRun{}, err
	}
	run, err := s.repo.GetRun(ctx, id)
	if err != nil {
		return run, err
	}
	if err = s.read.VisibleOwnershipEngagement(ctx, run.EngagementID); err != nil {
		return ports.OwnershipRun{}, err
	}
	return run, nil
}
func (s *Service) RunItems(ctx context.Context, actor string, id, after shared.ID, limit int) ([]ports.OwnershipRunItem, error) {
	if !validPage(after, limit) {
		return nil, shared.ErrValidation
	}
	if _, err := s.Run(ctx, actor, id); err != nil {
		return nil, err
	}
	return s.repo.ListRunItems(ctx, id, after, limit)
}
func (s *Service) CancelRun(ctx context.Context, actor string, id shared.ID, revision int) error {
	return s.mutate(ctx, actor, "", "ownership.run.cancelled", id.String(), func(ctx context.Context) error {
		run, e := s.repo.GetRun(ctx, id)
		if e != nil {
			return e
		}
		if e = s.read.VisibleOwnershipEngagement(ctx, run.EngagementID); e != nil {
			return e
		}
		return s.repo.SetRunState(ctx, id, revision, "cancelled")
	})
}

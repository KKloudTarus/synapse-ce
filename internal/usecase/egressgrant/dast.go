package egressgrant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastprobe"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const ExecutionKindDASTVerifier = "dast-verifier"

func (s *Service) SetDAST(reader ports.DASTRunAuthority) error {
	if reader == nil {
		return fmt.Errorf("%w: durable DAST grant authority is missing", shared.ErrValidation)
	}
	s.dastRuns = reader
	return nil
}

func (s *Service) authorizeDAST(ctx context.Context, tenant shared.ID, req Request) (string, error) {
	if s.dastRuns == nil || req.ExecutionID == "" || req.ExecutionID != strings.TrimSpace(req.ExecutionID) {
		return "", fmt.Errorf("%w: durable DAST grant authority is unavailable", shared.ErrForbidden)
	}
	runID := shared.ID(req.ExecutionID)
	loadAndGuard := func() (ports.DASTRunAuthorization, error) {
		auth, err := s.dastRuns.GetDASTRunAuthorization(ctx, tenant, runID)
		if err != nil {
			return auth, fmt.Errorf("load DAST authority: %w", err)
		}
		if err := validateDASTAuthority(auth, tenant, runID); err != nil {
			return auth, err
		}
		eng, err := s.engagements.GetByIDInTenant(ctx, tenant, auth.Run.EngagementID)
		if err != nil || eng.TenantID != tenant {
			return auth, fmt.Errorf("%w: DAST engagement unavailable", shared.ErrForbidden)
		}
		_, err = s.guard.Authorize(ctx, ports.ExecutionRequest{
			Actor: "synapse-egress-authority", EngagementID: auth.Run.EngagementID,
			Action: dastprobe.ActionSafeHTTPProbe, Target: auth.Action.Target,
			Metadata: map[string]string{"execution_kind": req.ExecutionKind, "execution_id": req.ExecutionID, "grant_run": req.RunID},
		})
		if err != nil {
			return auth, fmt.Errorf("authorize DAST execution: %w", err)
		}
		return auth, nil
	}
	auth, err := loadAndGuard()
	if err != nil {
		return "", err
	}
	u, err := dastprobe.ParseURL(auth.Job.Probe.URL)
	if err != nil {
		return "", err
	}
	// Independently resolve the approved host. A worker may select one current
	// public address, never an unrelated address, wider network or extra port.
	resolved, err := s.canonicalizer.Canonicalize(ctx, ports.EgressPolicy{AllowDomainRules: []ports.DomainRule{{Host: u.Hostname(), Ports: []uint16{dastprobe.Port(u)}}}})
	if err != nil {
		return "", fmt.Errorf("derive DAST egress rules: %w", err)
	}
	matched := false
	if len(resolved) == 0 || len(req.Rules) != 1 {
		return "", fmt.Errorf("%w: DAST requires one public pinned destination", shared.ErrForbidden)
	}
	for _, rule := range resolved {
		prefix, parseErr := netip.ParsePrefix(rule.CIDR)
		if parseErr != nil || !rule.Allow || prefix.Bits() != prefix.Addr().BitLen() || !dastprobe.PublicAddress(prefix.Addr()) || len(rule.Ports) != 1 || rule.Ports[0] != dastprobe.Port(u) {
			return "", fmt.Errorf("%w: DAST host resolved to an unsafe destination", shared.ErrForbidden)
		}
		if CanonicalRulesEqual([]CanonicalRule{rule}, req.Rules) {
			matched = true
		}
	}
	if !matched {
		return "", fmt.Errorf("%w: requested DAST rule differs from approved host", shared.ErrForbidden)
	}
	current, err := loadAndGuard()
	if err != nil {
		return "", err
	}
	if !reflect.DeepEqual(auth, current) {
		return "", fmt.Errorf("%w: DAST authority changed during resolution", shared.ErrForbidden)
	}
	token, err := s.signer.Sign(req, s.clock.Now(), GrantLifetime)
	if err != nil {
		return "", fmt.Errorf("sign DAST egress grant: %w", err)
	}
	// Signing is local and outside locks. A losing or commit-uncertain token is
	// discarded. A lost response burns the committed attempt rather than retrying.
	if err := s.dastRuns.ClaimDASTRunGrant(ctx, current, s.clock.Now()); err != nil {
		return "", fmt.Errorf("claim DAST egress grant: %w", err)
	}
	return token, nil
}

func validateDASTAuthority(a ports.DASTRunAuthorization, tenant, runID shared.ID) error {
	deny := func() error {
		return fmt.Errorf("%w: DAST run, approval or sealed custody is invalid", shared.ErrForbidden)
	}
	r, p, d, probe := a.Run, a.Action, a.Decision, a.Job.Probe
	if r.Validate() != nil || r.ID != runID || r.TenantID != tenant || r.Status != dastrun.RunRunning || r.FinishedAt != nil || a.GrantIssued || a.ConsumedBy != runID || a.Job.TenantID != tenant || a.Job.RunID != runID || !probe.RunID.IsZero() {
		return deny()
	}
	if p.ID != r.ActionID || p.EngagementID != r.EngagementID || p.Tool != dastprobe.ToolRunDASTVerifier || p.Action != dastprobe.ActionSafeHTTPProbe || p.Risk != agent.RiskIntrusive || p.Target.Kind != engagement.TargetURL || p.Target.Value != probe.URL || probe.JudgmentID.IsZero() || (probe.NormalizedMethod() != "GET" && probe.NormalizedMethod() != "HEAD") {
		return deny()
	}
	if dastprobe.ValidateURL(probe.URL) != nil || len(p.Argv) != 2 || p.Argv[0] != "synapse-dast-probe" || p.Argv[1] != "--config-sha256="+probe.ApprovalDigest() || d.ActionID != p.ID || d.State != agent.ApprovalConsumed || strings.TrimSpace(d.DecidedBy) == "" || d.DecidedBy == "auto" {
		return deny()
	}
	validSeal := func(e evidence.Evidence, kind string) bool {
		return !e.ID.IsZero() && e.EngagementID == r.EngagementID && e.Kind == kind && e.CreatedBy == r.Actor && e.FindingID.IsZero() && e.StorageRef == "" && e.Hash != "" && evidence.ComputeHash(e) == e.Hash
	}
	var consumed ports.DASTApprovalConsumption
	if !validSeal(a.Consumption, "agent_approval_consumed") || a.Consumption.ID != ports.DASTConsumptionEvidenceID(runID) || json.Unmarshal(a.Consumption.Content, &consumed) != nil || consumed.TenantID != tenant || consumed.EngagementID != r.EngagementID || consumed.RunID != runID || consumed.ActionID != p.ID || consumed.Actor != r.Actor || consumed.AdmissionID != a.Admission.ID {
		return deny()
	}
	// The stored admission uses snake_case field names; keep its wire contract
	// explicit while comparing every approved execution field below.
	var admitted struct {
		ActionID  string   `json:"action_id"`
		SessionID string   `json:"session_id"`
		Tool      string   `json:"tool"`
		Action    string   `json:"action"`
		Target    string   `json:"target"`
		Argv      []string `json:"argv"`
		Risk      string   `json:"risk"`
		DecidedBy string   `json:"decided_by"`
	}
	if !validSeal(a.Admission, "agent_admission") || json.Unmarshal(a.Admission.Content, &admitted) != nil {
		return deny()
	}
	if admitted.ActionID != p.ID.String() || admitted.SessionID != p.SessionID.String() || admitted.Tool != p.Tool || admitted.Action != p.Action || admitted.Target != p.Target.Value || admitted.Risk != string(p.Risk) || admitted.DecidedBy != d.DecidedBy || !reflect.DeepEqual(admitted.Argv, p.Argv) {
		return deny()
	}
	return nil
}

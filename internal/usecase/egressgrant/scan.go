package egressgrant

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastprobe"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastconfig"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const ExecutionKindDASTSession = "dast-session"

type scanPolicy struct {
	helperPath, helperSHA256 string
	ceilings                 dastconfig.ScanCeilings
}

// SetDASTScan installs the control-plane policy, independently of worker input.
func (s *Service) SetDASTScan(authority ports.DASTScanAuthority, helperPath, helperSHA256 string, ceilings dastconfig.ScanCeilings) error {
	if authority == nil || !filepath.IsAbs(helperPath) || len(helperSHA256) != 64 || strings.ToLower(helperSHA256) != helperSHA256 || ceilings.MaxReauth < 0 || ceilings.RatePerSec < 1 || ceilings.Concurrency < 1 || ceilings.Limits.Depth < 1 || ceilings.Limits.Pages < 1 || ceilings.Limits.Requests < 1 || ceilings.Limits.WallClock < 1 {
		return fmt.Errorf("%w: invalid DAST scan grant policy", shared.ErrValidation)
	}
	if _, err := hex.DecodeString(helperSHA256); err != nil {
		return fmt.Errorf("%w: invalid DAST helper SHA-256", shared.ErrValidation)
	}
	s.dastScan, s.scanPolicy = authority, scanPolicy{helperPath, helperSHA256, ceilings}
	return nil
}

func (s *Service) authorizeDASTScan(ctx context.Context, tenant shared.ID, req Request) (string, error) {
	if s.dastScan == nil {
		return "", fmt.Errorf("%w: DAST scan authority unavailable", shared.ErrForbidden)
	}
	execution, err := ports.ParseDASTScanExecutionID(req.ExecutionID)
	if err != nil || execution.TenantID != tenant {
		return "", fmt.Errorf("%w: invalid DAST scan execution", shared.ErrForbidden)
	}
	guard := func(c context.Context, auth ports.DASTScanAuthorization) error {
		eng, err := s.engagements.GetByIDInTenant(c, tenant, auth.Run.EngagementID)
		if err != nil || eng.TenantID != tenant {
			return fmt.Errorf("%w: DAST scan engagement unavailable", shared.ErrForbidden)
		}
		_, err = s.guard.Authorize(c, ports.ExecutionRequest{Actor: "synapse-egress-authority", EngagementID: auth.Run.EngagementID, Action: auth.Action.Action, Target: auth.Action.Target, Metadata: map[string]string{"execution_kind": req.ExecutionKind, "execution_id": req.ExecutionID, "grant_run": req.RunID, "agent_action_id": auth.Action.ID.String(), "agent_session": auth.Action.SessionID.String()}})
		return err
	}
	load := func() (ports.DASTScanAuthorization, error) {
		auth, err := s.dastScan.GetDASTScanAuthorization(ctx, execution)
		if err != nil {
			return auth, fmt.Errorf("load DAST scan authority: %w", err)
		}
		if err = s.validateDASTScanAuthority(auth, execution); err != nil {
			return auth, err
		}
		if err = guard(ctx, auth); err != nil {
			return auth, fmt.Errorf("authorize DAST scan: %w", err)
		}
		return auth, nil
	}
	auth, err := load()
	if err != nil {
		return "", err
	}
	u, err := dastprobe.ParseURL(auth.Action.Target.Value)
	if err != nil {
		return "", err
	}
	rules, err := s.canonicalizer.Canonicalize(ctx, dastOriginPolicy(u))
	if err != nil {
		return "", fmt.Errorf("derive DAST scan egress rules: %w", err)
	}
	if len(rules) == 0 {
		return "", fmt.Errorf("%w: no DAST scan destinations", shared.ErrForbidden)
	}
	for _, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.CIDR)
		if err != nil || !rule.Allow || prefix.Bits() != prefix.Addr().BitLen() || !dastprobe.PublicAddress(prefix.Addr()) || len(rule.Ports) != 1 || rule.Ports[0] != dastprobe.Port(u) {
			return "", fmt.Errorf("%w: unsafe DAST scan destination", shared.ErrForbidden)
		}
	}
	if !CanonicalRulesEqual(rules, req.Rules) {
		return "", fmt.Errorf("%w: DAST scan destinations differ from approved origin", shared.ErrForbidden)
	}
	current, err := load()
	if err != nil {
		return "", err
	}
	if !reflect.DeepEqual(auth, current) {
		return "", fmt.Errorf("%w: DAST scan authority changed during resolution", shared.ErrForbidden)
	}
	signedAt := s.clock.Now()
	token, err := s.signer.Sign(req, signedAt, GrantLifetime)
	if err != nil {
		return "", fmt.Errorf("sign DAST scan egress grant: %w", err)
	}
	if err = s.dastScan.ClaimDASTScanGrant(ctx, current, s.clock.Now(), func(txctx context.Context) error { return guard(txctx, current) }); err != nil {
		return "", fmt.Errorf("claim DAST scan egress grant: %w", err)
	}
	now := s.clock.Now()
	if ctx.Err() != nil || now.Before(signedAt) || !now.Before(signedAt.Add(GrantLifetime)) {
		return "", fmt.Errorf("%w: DAST scan grant expired or canceled during claim", shared.ErrForbidden)
	}
	return token, nil
}

func (s *Service) validateDASTScanAuthority(a ports.DASTScanAuthorization, execution ports.DASTScanExecution) error {
	deny := func() error { return fmt.Errorf("%w: DAST scan approval or custody invalid", shared.ErrForbidden) }
	r, p, d, job := a.Run, a.Action, a.Decision, a.Job
	if a.Execution != execution || r.Validate() != nil || r.Kind != dastrun.KindAuthenticatedScan || r.ID != execution.RunID || r.TenantID != execution.TenantID || r.Status != dastrun.RunRunning || r.FinishedAt != nil || a.GrantIssued || a.ConsumedBy != r.ID || job.TenantID != r.TenantID || job.RunID != r.ID || job.HelperPath != s.scanPolicy.helperPath || job.HelperSHA256 != s.scanPolicy.helperSHA256 {
		return deny()
	}
	config, canonical, digest, err := dastconfig.Decode(job.Config, s.scanPolicy.ceilings)
	if err != nil || !bytes.Equal(canonical, job.Config) || digest != job.ConfigSHA256 {
		return deny()
	}
	if p.ID != r.ActionID || p.SessionID != shared.ID("dast-scan:"+digest) || p.EngagementID != r.EngagementID ||
		p.Tool != "run_authenticated_dast" || p.Action != "dast.authenticated_scan" || p.Risk != agent.RiskIntrusive ||
		p.Target.Kind != engagement.TargetURL || p.Target.Value != config.Target ||
		!reflect.DeepEqual(p.Argv, []string{s.scanPolicy.helperPath, "run", "--config-sha256=" + digest, "--helper-sha256=" + s.scanPolicy.helperSHA256}) ||
		d.ActionID != p.ID || d.State != agent.ApprovalConsumed || strings.TrimSpace(d.DecidedBy) == "" ||
		d.DecidedBy != strings.TrimSpace(d.DecidedBy) || d.DecidedBy == "auto" || shared.IsMachineActor(d.DecidedBy) {
		return deny()
	}
	validSeal := func(e evidence.Evidence, kind string) bool {
		return !e.ID.IsZero() && e.EngagementID == r.EngagementID && e.Kind == kind && e.CreatedBy == r.Actor && e.FindingID.IsZero() && e.StorageRef == "" && e.Hash != "" && evidence.ComputeHash(e) == e.Hash
	}
	var consumed ports.DASTApprovalConsumption
	if !validSeal(a.Consumption, "agent_approval_consumed") || a.Consumption.ID != ports.DASTConsumptionEvidenceID(r.ID) || json.Unmarshal(a.Consumption.Content, &consumed) != nil || consumed.TenantID != r.TenantID || consumed.EngagementID != r.EngagementID || consumed.RunID != r.ID || consumed.ActionID != p.ID || consumed.Actor != r.Actor || consumed.AdmissionID != a.Admission.ID {
		return deny()
	}
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
	if !validSeal(a.Admission, "agent_admission") || json.Unmarshal(a.Admission.Content, &admitted) != nil || admitted.ActionID != p.ID.String() || admitted.SessionID != p.SessionID.String() || admitted.Tool != p.Tool || admitted.Action != p.Action || admitted.Target != p.Target.Value || admitted.Risk != string(p.Risk) || admitted.DecidedBy != d.DecidedBy || !reflect.DeepEqual(admitted.Argv, p.Argv) {
		return deny()
	}
	return nil
}

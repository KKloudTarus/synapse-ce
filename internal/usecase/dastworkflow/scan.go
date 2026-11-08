package dastworkflow

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastcrawl"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

const (
	ToolAuthenticatedScan   = "run_authenticated_dast"
	ActionAuthenticatedScan = "dast.authenticated_scan"
	evidenceKindScanProofs  = "dast_scan_proofs"
	evidenceKindScanProof   = "dast_scan_proof"
	scanProposerIdentity    = "system:dast-engine"
	scanVerifierIdentity    = "system:dast-verifier"
)

type scanSession interface {
	CrawlWithRate(context.Context, safety.AdmittedAction, string, string, dastsession.Config, dastcrawl.Input, dastcrawl.Limits, int, int) (dastcrawl.Result, error)
}

type scanJudgmentProposer interface {
	Propose(context.Context, string, shared.ID, judgment.Capability, judgment.SubjectKind, shared.ID, judgment.Claim) (judgment.Judgment, error)
}

type scanProofVerifier interface {
	Apply(context.Context, shared.ID, dastverifier.Result) (judgment.Judgment, error)
}

type ScanCeilings struct {
	MaxReauth   int
	RatePerSec  int
	Concurrency int
	Limits      dastcrawl.Limits
}

func DefaultScanCeilings() ScanCeilings {
	return ScanCeilings{MaxReauth: dastsession.DefaultMaxReauth, RatePerSec: ports.DefaultDASTRatePerSec, Concurrency: ports.DefaultDASTConcurrency,
		Limits: dastcrawl.Limits{Depth: dastcrawl.DefaultDepth, Pages: dastcrawl.DefaultPages, Requests: dastcrawl.DefaultRequests, WallClock: dastcrawl.DefaultWallClock}}
}

// ScanConfig is the complete secret-free DAST run input. Credential references are
// names in the engagement vault; plaintext values and secret placeholders are invalid.
type ScanConfig struct {
	Target           string             `json:"target"`
	Session          dastsession.Config `json:"session"`
	Crawler          dastcrawl.Input    `json:"crawler"`
	Limits           dastcrawl.Limits   `json:"limits"`
	RatePerSec       int                `json:"rate_per_sec"`
	Concurrency      int                `json:"concurrency"`
	SelectedCheckIDs []string           `json:"selected_check_ids,omitempty"`
}

type ScanResult struct {
	Digest     string               `json:"config_sha256"`
	Surface    dastsurface.Surface  `json:"surface"`
	Coverage   dastsurface.Coverage `json:"coverage"`
	Incomplete bool                 `json:"incomplete"`
	Reason     string               `json:"reason,omitempty"`
	Proofs     []ports.DASTProof    `json:"proofs"`
}

func (c ScanConfig) canonical(ceilings ScanCeilings) ([]byte, error) {
	if strings.TrimSpace(c.Target) == "" || c.Target != c.Crawler.Target {
		return nil, fmt.Errorf("%w: DAST target must match crawler target", shared.ErrValidation)
	}
	if err := validateDASTURL(c.Target); err != nil {
		return nil, err
	}
	if strings.Contains(strings.ToLower(string(mustJSON(c))), "{{secret:") {
		return nil, fmt.Errorf("%w: DAST configuration cannot contain secret placeholders", shared.ErrValidation)
	}
	if c.Session.MaxReauth == 0 {
		c.Session.MaxReauth = ceilings.MaxReauth
	}
	if c.RatePerSec == 0 {
		c.RatePerSec = ceilings.RatePerSec
	}
	if c.Concurrency == 0 {
		c.Concurrency = ceilings.Concurrency
	}
	if c.Limits.Depth == 0 {
		c.Limits.Depth = ceilings.Limits.Depth
	}
	if c.Limits.Pages == 0 {
		c.Limits.Pages = ceilings.Limits.Pages
	}
	if c.Limits.Requests == 0 {
		c.Limits.Requests = ceilings.Limits.Requests
	}
	if c.Limits.WallClock == 0 {
		c.Limits.WallClock = ceilings.Limits.WallClock
	}
	if c.Session.MaxReauth < 0 || c.Session.MaxReauth > ceilings.MaxReauth || c.RatePerSec < 1 || c.RatePerSec > ceilings.RatePerSec || c.Concurrency < 1 || c.Concurrency > ceilings.Concurrency || c.Limits.Depth < 1 || c.Limits.Depth > ceilings.Limits.Depth || c.Limits.Pages < 1 || c.Limits.Pages > ceilings.Limits.Pages || c.Limits.Requests < 1 || c.Limits.Requests > ceilings.Limits.Requests || c.Limits.WallClock < 1 || c.Limits.WallClock > ceilings.Limits.WallClock {
		return nil, fmt.Errorf("%w: DAST scan configuration exceeds configured ceilings", shared.ErrValidation)
	}
	if err := c.Session.Validate(); err != nil {
		return nil, err
	}
	for _, binding := range c.Session.Credentials {
		if strings.Contains(binding.Reference, "{{") || strings.ContainsAny(binding.Reference, "\r\n") {
			return nil, fmt.Errorf("%w: invalid vault credential reference", shared.ErrValidation)
		}
	}
	seen := map[string]struct{}{}
	for _, id := range c.SelectedCheckIDs {
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("%w: duplicate DAST check %q", shared.ErrValidation, id)
		}
		seen[id] = struct{}{}
	}
	sort.Strings(c.SelectedCheckIDs)
	return json.Marshal(c)
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func (s *Service) SetScan(session scanSession, helperBin string, ev *evidence.Service, evaluator ports.DASTCheckEvaluator, proofVerifier ports.DASTProofVerifier, judgments scanJudgmentProposer, verifier scanProofVerifier, ceilings ScanCeilings) error {
	if session == nil || strings.TrimSpace(helperBin) == "" || ev == nil || evaluator == nil || proofVerifier == nil || judgments == nil || verifier == nil || ceilings.MaxReauth < 0 || ceilings.RatePerSec < 1 || ceilings.Concurrency < 1 || ceilings.Limits.Depth < 1 || ceilings.Limits.Pages < 1 || ceilings.Limits.Requests < 1 || ceilings.Limits.WallClock < 1 {
		return fmt.Errorf("%w: DAST scan configuration is invalid", shared.ErrValidation)
	}
	s.session, s.helperBin, s.evaluator, s.proofVerifier, s.judgments, s.verifier, s.ceilings = session, helperBin, evaluator, proofVerifier, judgments, verifier, ceilings
	return nil
}

func (s *Service) normalizeScanConfig(config ScanConfig) ScanConfig {
	if config.Session.MaxReauth == 0 {
		config.Session.MaxReauth = s.ceilings.MaxReauth
	}
	if config.RatePerSec == 0 {
		config.RatePerSec = s.ceilings.RatePerSec
	}
	if config.Concurrency == 0 {
		config.Concurrency = s.ceilings.Concurrency
	}
	if config.Limits.Depth == 0 {
		config.Limits.Depth = s.ceilings.Limits.Depth
	}
	if config.Limits.Pages == 0 {
		config.Limits.Pages = s.ceilings.Limits.Pages
	}
	if config.Limits.Requests == 0 {
		config.Limits.Requests = s.ceilings.Limits.Requests
	}
	if config.Limits.WallClock == 0 {
		config.Limits.WallClock = s.ceilings.Limits.WallClock
	}
	return config
}

func (s *Service) ProposeScan(ctx context.Context, actor string, engagementID shared.ID, config ScanConfig) (Proposal, error) {
	if s.session == nil || s.evaluator == nil {
		return Proposal{}, fmt.Errorf("%w: DAST scan workflow is unavailable", shared.ErrNotFound)
	}
	config = s.normalizeScanConfig(config)
	canonical, err := config.canonical(s.ceilings)
	if err != nil {
		return Proposal{}, err
	}
	digest := sha256.Sum256(canonical)
	encoded := hex.EncodeToString(digest[:])
	p := agent.ProposedAction{ID: s.ids.NewID(), SessionID: shared.ID("dast-scan:" + encoded), EngagementID: engagementID,
		Tool: ToolAuthenticatedScan, Action: ActionAuthenticatedScan, Target: engagement.Target{Kind: engagement.TargetURL, Value: config.Target},
		Argv: []string{s.helperBin, "run", "--config-sha256=" + encoded}, Risk: agent.RiskIntrusive, Rationale: "authenticated DAST scan", ProposedAt: s.clock.Now()}
	_, err = s.gate.Admit(ctx, p, actor)
	if err != nil && !errors.Is(err, safety.ErrPendingApproval) {
		return Proposal{}, err
	}
	_, dec, err := s.store.Get(ctx, p.ID)
	if err != nil {
		return Proposal{}, err
	}
	return Proposal{Action: p, Decision: dec}, nil
}

func (s *Service) RunScan(ctx context.Context, actor string, engagementID, actionID shared.ID, config ScanConfig) (ScanResult, error) {
	if s.session == nil {
		return ScanResult{}, fmt.Errorf("%w: DAST scan workflow is unavailable", shared.ErrNotFound)
	}
	config = s.normalizeScanConfig(config)
	canonical, err := config.canonical(s.ceilings)
	if err != nil {
		return ScanResult{}, err
	}
	digest := sha256.Sum256(canonical)
	encoded := hex.EncodeToString(digest[:])
	p, _, err := s.store.Get(ctx, actionID)
	if err != nil {
		return ScanResult{}, err
	}
	if p.EngagementID != engagementID || p.Tool != ToolAuthenticatedScan || p.Action != ActionAuthenticatedScan || len(p.Argv) != 3 || p.Argv[0] != s.helperBin || p.Argv[1] != "run" || subtle.ConstantTimeCompare([]byte(p.Argv[2]), []byte("--config-sha256="+encoded)) != 1 {
		return ScanResult{}, fmt.Errorf("%w: DAST approval does not bind this scan configuration", shared.ErrValidation)
	}
	admitted, err := s.gate.Admit(ctx, p, actor)
	if err != nil {
		return ScanResult{}, err
	}
	if err := s.consume(ctx, engagementID, actionID, actor); err != nil {
		return ScanResult{}, err
	}
	result, err := s.session.CrawlWithRate(ctx, admitted, p.Argv[0], encoded, config.Session, config.Crawler, config.Limits, config.RatePerSec, config.Concurrency)
	if err != nil {
		return ScanResult{}, err
	}
	if result.Incomplete {
		return ScanResult{Digest: encoded, Surface: result.Surface, Coverage: result.Coverage, Incomplete: true, Reason: result.Reason}, nil
	}
	findings, err := s.evaluator.Evaluate(result.Observations, config.SelectedCheckIDs)
	if err != nil {
		return ScanResult{}, err
	}
	proofs := make([]ports.DASTProof, 0, len(findings))
	for _, finding := range findings {
		proofPayload, err := json.Marshal(finding.Proof)
		if err != nil {
			return ScanResult{}, fmt.Errorf("marshal DAST proof: %w", err)
		}
		proofEvidence, err := s.evidence.Seal(ctx, engagementID, evidenceKindScanProof, proofPayload, scanProposerIdentity)
		if err != nil {
			return ScanResult{}, fmt.Errorf("seal DAST proof: %w", err)
		}
		sealedProof, err := s.evidence.Get(ctx, engagementID, proofEvidence.ID)
		if err != nil {
			return ScanResult{}, fmt.Errorf("load sealed DAST proof: %w", err)
		}
		var verifierProof ports.DASTProof
		if err := json.Unmarshal(sealedProof.Content, &verifierProof); err != nil {
			return ScanResult{}, fmt.Errorf("decode sealed DAST proof: %w", err)
		}
		if err := s.proofVerifier.VerifyProof(verifierProof); err != nil {
			return ScanResult{}, fmt.Errorf("verify DAST proof: %w", err)
		}
		claim := judgment.DASTClaim{
			CWE: finding.CWE, Location: finding.Endpoint, Rule: finding.CheckID,
			Source: "first_party", Fingerprint: "sha256_" + finding.Proof.Hash, ProofEvidenceID: proofEvidence.ID.String(),
		}
		proposed, err := s.judgments.Propose(ctx, scanProposerIdentity, engagementID, judgment.CapDAST, judgment.SubjectEngagement, engagementID, claim)
		if err != nil {
			return ScanResult{}, fmt.Errorf("propose DAST judgment: %w", err)
		}
		if _, err := s.verifier.Apply(ctx, engagementID, dastverifier.Result{
			JudgmentID: proposed.ID, Verifier: scanVerifierIdentity, Score: verdict.EvidenceThreshold,
			ProofClass: dastverifier.ProofClassRuntimeConfirmed,
			Rationale:  "closed first-party proof re-evaluated from sealed evidence " + proofEvidence.ID.String(), ExpectedVersion: proposed.Version,
		}); err != nil {
			return ScanResult{}, fmt.Errorf("apply DAST verifier judgment: %w", err)
		}
		proofs = append(proofs, finding.Proof)
	}
	payload, err := json.Marshal(proofs)
	if err != nil {
		return ScanResult{}, fmt.Errorf("marshal DAST proofs: %w", err)
	}
	if _, err := s.evidence.Seal(ctx, engagementID, evidenceKindScanProofs, payload, admitted.DecidedBy()); err != nil {
		return ScanResult{}, fmt.Errorf("seal DAST proofs: %w", err)
	}
	return ScanResult{Digest: encoded, Surface: result.Surface, Coverage: result.Coverage, Proofs: proofs}, nil
}

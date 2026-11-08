package dastworkflow

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastconfig"
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
	CrawlWithRate(context.Context, safety.AdmittedAction, string, string, dastsession.Config, dastcrawl.Input, dastcrawl.Limits, int, int, ports.DASTScanExecution, ports.DASTScanRunStore) (dastcrawl.Result, error)
}

type scanJudgmentProposer interface {
	Propose(context.Context, string, shared.ID, judgment.Capability, judgment.SubjectKind, shared.ID, judgment.Claim) (judgment.Judgment, error)
}

type scanProofVerifier interface {
	Apply(context.Context, shared.ID, dastverifier.Result) (judgment.Judgment, error)
}

type ScanResult struct {
	Digest     string               `json:"config_sha256"`
	Surface    dastsurface.Surface  `json:"surface"`
	Coverage   dastsurface.Coverage `json:"coverage"`
	Incomplete bool                 `json:"incomplete"`
	Reason     string               `json:"reason,omitempty"`
	Proofs     []ports.DASTProof    `json:"proofs"`
}

// SetScanPolicy configures an operator-controlled helper pin independently of execution.
func (s *Service) SetScanPolicy(helperBin, helperSHA256 string, ceilings dastconfig.ScanCeilings) error {
	if !filepath.IsAbs(helperBin) || len(helperSHA256) != 64 || strings.ToLower(helperSHA256) != helperSHA256 || ceilings.MaxReauth < 0 || ceilings.RatePerSec < 1 || ceilings.Concurrency < 1 || ceilings.Limits.Depth < 1 || ceilings.Limits.Pages < 1 || ceilings.Limits.Requests < 1 || ceilings.Limits.WallClock < 1 {
		return fmt.Errorf("%w: invalid DAST scan policy", shared.ErrValidation)
	}
	if _, err := hex.DecodeString(helperSHA256); err != nil {
		return fmt.Errorf("%w: invalid DAST helper SHA-256", shared.ErrValidation)
	}
	s.helperBin, s.helperSHA256, s.ceilings = helperBin, helperSHA256, ceilings
	return nil
}

func (s *Service) SetScan(session scanSession, helperBin string, ev *evidence.Service, evaluator ports.DASTCheckEvaluator, proofVerifier ports.DASTProofVerifier, judgments scanJudgmentProposer, verifier scanProofVerifier, ceilings dastconfig.ScanCeilings) error {
	if session == nil || ev == nil || evaluator == nil || proofVerifier == nil || judgments == nil || verifier == nil || s.helperSHA256 == "" || helperBin != s.helperBin || ceilings != s.ceilings {
		return fmt.Errorf("%w: DAST scan executor must match configured policy", shared.ErrValidation)
	}
	s.session, s.evaluator, s.proofVerifier, s.judgments, s.verifier = session, evaluator, proofVerifier, judgments, verifier
	return nil
}

// SetScanOwnerStore enables independently committed, owner-fenced scan custody.
func (s *Service) SetScanOwnerStore(store ports.DASTScanRunStore) error {
	if store == nil {
		return fmt.Errorf("%w: DAST scan owner store required", shared.ErrValidation)
	}
	s.scanOwners = store
	return nil
}

func (s *Service) ProposeScan(ctx context.Context, actor string, engagementID shared.ID, config dastconfig.ScanConfig) (Proposal, error) {
	if s.helperBin == "" || s.helperSHA256 == "" {
		return Proposal{}, fmt.Errorf("%w: DAST scan workflow is unavailable", shared.ErrNotFound)
	}
	config, _, encoded, err := dastconfig.Canonical(config, s.ceilings)
	if err != nil {
		return Proposal{}, err
	}
	p := agent.ProposedAction{ID: s.ids.NewID(), SessionID: shared.ID("dast-scan:" + encoded), EngagementID: engagementID,
		Tool: ToolAuthenticatedScan, Action: ActionAuthenticatedScan, Target: engagement.Target{Kind: engagement.TargetURL, Value: config.Target},
		Argv: []string{s.helperBin, "run", "--config-sha256=" + encoded, "--helper-sha256=" + s.helperSHA256}, Risk: agent.RiskIntrusive, Rationale: "authenticated DAST scan", ProposedAt: s.clock.Now()}
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

// ExecuteScan performs one durable scan; every custody mutation is fenced by
// the current queue claim in an independent tenant transaction.
func (s *Service) ExecuteScan(ctx context.Context, execution ports.DASTScanExecution, job ports.DASTScanJob, run dastrun.Run) (shared.ID, bool, error) {
	consumer, ok := s.store.(ports.DASTApprovalConsumer)
	if !ok || s.scanOwners == nil || s.session == nil || s.evaluator == nil || s.proofVerifier == nil || s.judgments == nil || s.verifier == nil {
		return "", false, fmt.Errorf("%w: durable DAST custody or executor unavailable", shared.ErrForbidden)
	}
	if run.Kind != dastrun.KindAuthenticatedScan || run.Status != dastrun.RunRunning || run.ID != execution.RunID || run.TenantID != execution.TenantID || job.RunID != run.ID || job.TenantID != run.TenantID || job.HelperPath != s.helperBin || job.HelperSHA256 != s.helperSHA256 || s.helperSHA256 == "" {
		return "", false, fmt.Errorf("%w: DAST scan execution binding mismatch", shared.ErrForbidden)
	}
	config, canonical, digest, err := dastconfig.Decode(job.Config, s.ceilings)
	if err != nil || !bytes.Equal(canonical, job.Config) || digest != job.ConfigSHA256 {
		return "", false, fmt.Errorf("%w: invalid DAST scan configuration", shared.ErrValidation)
	}
	var admitted safety.AdmittedAction
	err = evidence.AnchorAfterCommit(ctx, func(anchorctx context.Context) error {
		return s.scanOwners.WithDASTScanOwner(anchorctx, execution, func(txctx context.Context) error {
			p, _, err := s.store.Get(txctx, run.ActionID)
			if err != nil {
				return err
			}
			if p.EngagementID != run.EngagementID || p.Target.Kind != engagement.TargetURL || p.Target.Value != config.Target || p.Tool != ToolAuthenticatedScan || p.Action != ActionAuthenticatedScan || len(p.Argv) != 4 || p.Argv[0] != job.HelperPath || p.Argv[1] != "run" || subtle.ConstantTimeCompare([]byte(p.Argv[2]), []byte("--config-sha256="+digest)) != 1 || subtle.ConstantTimeCompare([]byte(p.Argv[3]), []byte("--helper-sha256="+job.HelperSHA256)) != 1 {
				return fmt.Errorf("%w: DAST approval does not bind this scan", shared.ErrForbidden)
			}
			admitted, err = s.gate.Admit(txctx, p, run.Actor)
			if err != nil {
				return err
			}
			if shared.IsMachineActor(admitted.DecidedBy()) {
				return fmt.Errorf("%w: human approval required", shared.ErrForbidden)
			}
			if err := consumer.ConsumeForDASTRun(txctx, run.ActionID, run.ID); err != nil {
				return err
			}
			payload, err := json.Marshal(ports.DASTApprovalConsumption{TenantID: run.TenantID, EngagementID: run.EngagementID, RunID: run.ID, ActionID: run.ActionID, Actor: run.Actor, AdmissionID: admitted.EvidenceID()})
			if err != nil {
				return err
			}
			if _, err := s.evidence.SealWithID(txctx, ports.DASTConsumptionEvidenceID(run.ID), run.EngagementID, "agent_approval_consumed", payload, run.Actor); err != nil {
				return err
			}
			return s.gate.Reauthorize(txctx, admitted)
		})
	})
	if err != nil {
		return "", false, err
	}
	crawl, err := s.session.CrawlWithRate(ctx, admitted, job.HelperPath, digest, config.Session, config.Crawler, config.Limits, config.RatePerSec, config.Concurrency, execution, s.scanOwners)
	if err != nil {
		return "", false, err
	}
	if crawl.Incomplete && strings.TrimSpace(crawl.Reason) == "" {
		return "", false, fmt.Errorf("%w: incomplete DAST scan missing reason", shared.ErrValidation)
	}
	var findings []ports.DASTFinding
	if !crawl.Incomplete {
		findings, err = s.evaluator.Evaluate(crawl.Observations, config.SelectedCheckIDs)
		if err != nil {
			return "", false, err
		}
	}
	result := ScanResult{Digest: digest, Surface: crawl.Surface, Coverage: crawl.Coverage, Incomplete: crawl.Incomplete, Reason: crawl.Reason, Proofs: make([]ports.DASTProof, 0, len(findings))}
	var resultID shared.ID
	err = evidence.AnchorAfterCommit(ctx, func(anchorctx context.Context) error {
		return s.scanOwners.WithDASTScanOwner(anchorctx, execution, func(txctx context.Context) error {
			if err := s.gate.Reauthorize(txctx, admitted); err != nil {
				return err
			}
			for _, finding := range findings {
				payload, err := json.Marshal(finding.Proof)
				if err != nil {
					return err
				}
				proof, err := s.evidence.Seal(txctx, run.EngagementID, evidenceKindScanProof, payload, scanProposerIdentity)
				if err != nil {
					return err
				}
				sealed, found, err := s.evidence.LookupSealedByID(txctx, run.EngagementID, proof.ID)
				if err != nil {
					return err
				}
				if !found {
					return fmt.Errorf("%w: sealed DAST proof unavailable", shared.ErrNotFound)
				}
				var verifierProof ports.DASTProof
				if err := json.Unmarshal(sealed.Content, &verifierProof); err != nil {
					return err
				}
				if err := s.proofVerifier.VerifyProof(verifierProof); err != nil {
					return err
				}
				claim := judgment.DASTClaim{CWE: finding.CWE, Location: finding.Endpoint, Rule: finding.CheckID, Source: "first_party", Fingerprint: "sha256_" + finding.Proof.Hash, ProofEvidenceID: proof.ID.String()}
				proposed, err := s.judgments.Propose(txctx, scanProposerIdentity, run.EngagementID, judgment.CapDAST, judgment.SubjectEngagement, run.EngagementID, claim)
				if err != nil {
					return err
				}
				if _, err := s.verifier.Apply(txctx, run.EngagementID, dastverifier.Result{JudgmentID: proposed.ID, Verifier: scanVerifierIdentity, Score: verdict.EvidenceThreshold, ProofClass: dastverifier.ProofClassRuntimeConfirmed, Rationale: "closed first-party proof re-evaluated from sealed evidence " + proof.ID.String(), ExpectedVersion: proposed.Version}); err != nil {
					return err
				}
				result.Proofs = append(result.Proofs, finding.Proof)
			}
			proofs, err := json.Marshal(result.Proofs)
			if err != nil {
				return err
			}
			if _, err := s.evidence.Seal(txctx, run.EngagementID, evidenceKindScanProofs, proofs, admitted.DecidedBy()); err != nil {
				return err
			}
			payload, err := json.Marshal(sealedScanResult{TenantID: run.TenantID, RunID: run.ID, EngagementID: run.EngagementID, ActionID: run.ActionID, Result: result})
			if err != nil {
				return err
			}
			sealed, err := s.evidence.Seal(txctx, run.EngagementID, "dast_scan_result", payload, admitted.DecidedBy())
			if err != nil {
				return err
			}
			resultID = sealed.ID
			return s.gate.Reauthorize(txctx, admitted)
		})
	})
	if err != nil {
		return "", false, err
	}
	return resultID, result.Incomplete, nil
}

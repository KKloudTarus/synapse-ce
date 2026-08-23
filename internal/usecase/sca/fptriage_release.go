package sca

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
)

const (
	AIEvaluationReleaseManifestSchema = "synapse-ai-triage-release-manifest-v1"
	aiEvaluationReleaseLedgerSchema   = "synapse-ai-triage-release-ledger-v2"
	aiEvaluationReleaseApprovalSchema = "synapse-ai-triage-release-approval-v1"
	AIEvaluationReleasePromote        = "promote"
	AIEvaluationReleaseRollback       = "rollback"
)

var releaseVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// AIEvaluationReleaseApproval records one independent human approval over the exact release
// manifest, comparison, and current ledger head. PM and Security must approve separately.
type AIEvaluationReleaseApproval struct {
	Role           string    `json:"role"`
	Reviewer       string    `json:"reviewer"`
	Approved       bool      `json:"approved"`
	Rationale      string    `json:"rationale"`
	ReviewedAt     time.Time `json:"reviewed_at"`
	ReviewedSHA256 string    `json:"reviewed_sha256"`
}

// AIEvaluationReleaseManifest is operator-owned approval input. A promotion binds a passing
// comparison; a rollback binds an earlier approved decision (or the initial baseline).
type AIEvaluationReleaseManifest struct {
	SchemaVersion string                        `json:"schema_version"`
	Version       string                        `json:"version"`
	Action        string                        `json:"action"`
	Provenance    string                        `json:"provenance"`
	ComparisonID  string                        `json:"comparison_id,omitempty"`
	RollbackTo    string                        `json:"rollback_to,omitempty"`
	Approvals     []AIEvaluationReleaseApproval `json:"approvals"`
}

// AIEvaluationReleaseDecision is an append-only, versioned governance event. It has no runtime
// authority: operators apply the approved configuration through their normal deployment controls.
type AIEvaluationReleaseDecision struct {
	DecisionID            string                        `json:"decision_id"`
	Sequence              int                           `json:"sequence"`
	Version               string                        `json:"version"`
	Action                string                        `json:"action"`
	Status                string                        `json:"status"`
	Provenance            string                        `json:"provenance"`
	PreviousDecisionID    string                        `json:"previous_decision_id,omitempty"`
	ComparisonID          string                        `json:"comparison_id,omitempty"`
	RollbackTo            string                        `json:"rollback_to,omitempty"`
	BaselineEvaluationRun *AIEvaluationRun              `json:"baseline_evaluation_run,omitempty"`
	BaselineEvaluationID  string                        `json:"baseline_evaluation_run_id,omitempty"`
	PromotionPolicy       *AIEvaluationPromotionPolicy  `json:"promotion_policy,omitempty"`
	PreviousActiveRunID   string                        `json:"previous_active_run_id"`
	ActiveRun             AIEvaluationRun               `json:"active_run"`
	ActiveRunID           string                        `json:"active_run_id"`
	ApprovalDigest        string                        `json:"approval_digest"`
	Approvals             []AIEvaluationReleaseApproval `json:"approvals"`
}

// AIEvaluationReleaseLedger is a deterministic hash-chained promotion/rollback history.
type AIEvaluationReleaseLedger struct {
	SchemaVersion  string                        `json:"schema_version"`
	InitialRun     AIEvaluationRun               `json:"initial_run"`
	InitialRunID   string                        `json:"initial_run_id"`
	HeadDecisionID string                        `json:"head_decision_id"`
	Decisions      []AIEvaluationReleaseDecision `json:"decisions"`
}

// AIEvaluationPromotionEvidence keeps both shadow reports beside their comparison so the release
// boundary can recompute every metric and invariant instead of trusting a stored status or digest.
type AIEvaluationPromotionEvidence struct {
	BaselineReport  AIEvaluationReport     `json:"baseline_report"`
	CandidateReport AIEvaluationReport     `json:"candidate_report"`
	Comparison      AIEvaluationComparison `json:"comparison"`
}

func (e AIEvaluationPromotionEvidence) Validate() error {
	if err := validateReleasePromotionPolicy(e.Comparison.Policy); err != nil {
		return err
	}
	if err := e.Comparison.Validate(); err != nil {
		return err
	}
	recomputed, err := CompareAIEvaluationReports(e.BaselineReport, e.CandidateReport, e.Comparison.Policy)
	if err != nil {
		return fmt.Errorf("recompute AI evaluation comparison: %w", err)
	}
	if !reflect.DeepEqual(recomputed, e.Comparison) {
		return fmt.Errorf("AI evaluation comparison does not match its baseline and candidate reports")
	}
	return nil
}

// LoadAIEvaluationComparison strictly decodes and validates comparison identity and status.
func LoadAIEvaluationComparison(data []byte) (AIEvaluationComparison, error) {
	var comparison AIEvaluationComparison
	if err := decodeReleaseJSON(data, &comparison); err != nil {
		return comparison, fmt.Errorf("decode AI evaluation comparison: %w", err)
	}
	if err := comparison.Validate(); err != nil {
		return comparison, err
	}
	return comparison, nil
}

// Validate rechecks the deterministic comparison identity and promotion-review invariants.
func (c AIEvaluationComparison) Validate() error {
	if c.SchemaVersion != aiEvaluationComparisonSchema || !validEvaluationSHA256(c.ComparisonID) ||
		c.ComparisonID != evaluationComparisonID(c) {
		return fmt.Errorf("AI evaluation comparison has an invalid schema or canonical identity")
	}
	if c.Status != "review_required" || !c.ApprovalRequired || len(c.Failures) != 0 {
		return fmt.Errorf("AI evaluation comparison is not eligible for human promotion approval")
	}
	if err := c.Policy.Validate(); err != nil {
		return fmt.Errorf("AI evaluation comparison policy: %w", err)
	}
	if strings.TrimSpace(c.DatasetVersion) == "" || !validEvaluationSHA256(c.DatasetSHA256) ||
		strings.TrimSpace(c.Provenance) == "" || strings.TrimSpace(c.Reviewer) == "" ||
		!validEvaluationSHA256(c.BaselineRunID) || !validEvaluationSHA256(c.CandidateRunID) {
		return fmt.Errorf("AI evaluation comparison has incomplete evidence identity")
	}
	if err := validateReleaseRun(c.BaselineRun); err != nil {
		return fmt.Errorf("AI evaluation comparison baseline: %w", err)
	}
	if err := validateReleaseRun(c.CandidateRun); err != nil {
		return fmt.Errorf("AI evaluation comparison candidate: %w", err)
	}
	if sameEvaluationConfiguration(c.BaselineRun, c.CandidateRun) {
		return fmt.Errorf("AI evaluation comparison does not change the evaluated configuration")
	}
	return nil
}

func LoadAIEvaluationReleaseManifest(data []byte) (AIEvaluationReleaseManifest, error) {
	var manifest AIEvaluationReleaseManifest
	if err := decodeReleaseJSON(data, &manifest); err != nil {
		return manifest, fmt.Errorf("decode AI evaluation release manifest: %w", err)
	}
	if err := validateReleaseManifestHeader(manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func LoadAIEvaluationReleaseLedger(data []byte) (AIEvaluationReleaseLedger, error) {
	var ledger AIEvaluationReleaseLedger
	if err := decodeReleaseJSON(data, &ledger); err != nil {
		return ledger, fmt.Errorf("decode AI evaluation release ledger: %w", err)
	}
	if err := ledger.Validate(); err != nil {
		return ledger, err
	}
	return ledger, nil
}

// AIEvaluationReleaseReviewDigest returns the exact digest PM and Security approve. It binds the
// current ledger head, so an approval cannot be replayed after another release decision lands.
func AIEvaluationReleaseReviewDigest(ledger AIEvaluationReleaseLedger, evidence *AIEvaluationPromotionEvidence, manifest AIEvaluationReleaseManifest) (string, error) {
	if err := validateReleaseManifestHeader(manifest); err != nil {
		return "", err
	}
	if len(ledger.Decisions) != 0 || ledger.SchemaVersion != "" {
		if err := ledger.Validate(); err != nil {
			return "", err
		}
	}
	for _, decision := range ledger.Decisions {
		if strings.EqualFold(decision.Version, manifest.Version) {
			return "", fmt.Errorf("AI evaluation release version %q already exists", manifest.Version)
		}
	}
	var targetRun AIEvaluationRun
	var targetRunID string
	if manifest.Action == AIEvaluationReleasePromote {
		if evidence == nil {
			return "", fmt.Errorf("AI evaluation promotion requires a passing comparison")
		}
		if err := evidence.Validate(); err != nil {
			return "", err
		}
		comparison := evidence.Comparison
		if manifest.ComparisonID != comparison.ComparisonID {
			return "", fmt.Errorf("AI evaluation release manifest comparison_id does not match the reviewed comparison")
		}
		if manifest.RollbackTo != "" {
			return "", fmt.Errorf("AI evaluation promotion must not set rollback_to")
		}
		if len(ledger.Decisions) != 0 && (comparison.BaselineRunID != currentReleaseRunID(ledger) ||
			!reflect.DeepEqual(currentReleaseRun(ledger), comparison.BaselineRun)) {
			return "", fmt.Errorf("AI evaluation promotion baseline does not match the exact active approved run")
		}
		targetRun, targetRunID = comparison.CandidateRun, comparison.CandidateRunID
	} else {
		if evidence != nil || manifest.ComparisonID != "" {
			return "", fmt.Errorf("AI evaluation rollback must not carry a promotion comparison")
		}
		if len(ledger.Decisions) == 0 {
			return "", fmt.Errorf("AI evaluation rollback requires an existing release ledger")
		}
		var err error
		targetRun, targetRunID, err = rollbackReleaseTarget(ledger, manifest.RollbackTo)
		if err != nil {
			return "", err
		}
		if sameEvaluationConfiguration(currentReleaseRun(ledger), targetRun) {
			return "", fmt.Errorf("AI evaluation rollback target is already active")
		}
	}

	payload := struct {
		Schema       string          `json:"schema"`
		LedgerHead   string          `json:"ledger_head"`
		Version      string          `json:"version"`
		Action       string          `json:"action"`
		Provenance   string          `json:"provenance"`
		ComparisonID string          `json:"comparison_id,omitempty"`
		RollbackTo   string          `json:"rollback_to,omitempty"`
		TargetRun    AIEvaluationRun `json:"target_run"`
		TargetRunID  string          `json:"target_run_id"`
	}{aiEvaluationReleaseApprovalSchema, ledger.HeadDecisionID, manifest.Version, manifest.Action,
		manifest.Provenance, manifest.ComparisonID, manifest.RollbackTo, targetRun, targetRunID}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal AI evaluation release approval digest: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ApplyAIEvaluationRelease appends an approved promotion or rollback. It does not mutate runtime
// configuration, model clients, prompts, thresholds, findings, or gate state.
//
// allowedHumanApprovers is the operator-owned allowlist an approver identity must appear in. The
// manifest is operator-supplied input that names its own approvers, so on its own "these two are human"
// is a claim the manifest makes about itself: the machine-prefix denylist can only reject the identity
// families this codebase already mints, and fails open on any other. The allowlist is what admits an
// identity from outside the artifact being validated.
//
// It is required here, at admission, and deliberately not consulted by Validate. A decision keeps the
// approvers it was admitted with, so an approver who later leaves the allowlist must not retroactively
// invalidate the ledger they signed, nor stop that ledger from loading.
func ApplyAIEvaluationRelease(ledger AIEvaluationReleaseLedger, evidence *AIEvaluationPromotionEvidence, manifest AIEvaluationReleaseManifest, allowedHumanApprovers []string) (AIEvaluationReleaseLedger, error) {
	digest, err := AIEvaluationReleaseReviewDigest(ledger, evidence, manifest)
	if err != nil {
		return AIEvaluationReleaseLedger{}, err
	}
	models := releaseModelIdentities(ledger, evidence, manifest)
	if err := validateReleaseApprovals(manifest.Approvals, digest, models); err != nil {
		return AIEvaluationReleaseLedger{}, err
	}
	if err := validateReleaseApproverAllowlist(manifest.Approvals, allowedHumanApprovers, models); err != nil {
		return AIEvaluationReleaseLedger{}, err
	}
	for _, decision := range ledger.Decisions {
		if strings.EqualFold(decision.Version, manifest.Version) {
			return AIEvaluationReleaseLedger{}, fmt.Errorf("AI evaluation release version %q already exists", manifest.Version)
		}
	}

	if ledger.SchemaVersion == "" {
		if evidence == nil || manifest.Action != AIEvaluationReleasePromote {
			return AIEvaluationReleaseLedger{}, fmt.Errorf("AI evaluation release ledger must start with a promotion")
		}
		comparison := evidence.Comparison
		ledger = AIEvaluationReleaseLedger{SchemaVersion: aiEvaluationReleaseLedgerSchema,
			InitialRun: comparison.BaselineRun, InitialRunID: comparison.BaselineRunID,
			Decisions: []AIEvaluationReleaseDecision{}}
	}
	var comparison *AIEvaluationComparison
	if evidence != nil {
		comparison = &evidence.Comparison
	}
	previousRun, previousRunID := currentReleaseRun(ledger), currentReleaseRunID(ledger)
	decision := AIEvaluationReleaseDecision{
		Sequence: len(ledger.Decisions) + 1, Version: manifest.Version, Action: manifest.Action,
		Status: "approved", Provenance: manifest.Provenance, PreviousDecisionID: ledger.HeadDecisionID,
		ComparisonID: manifest.ComparisonID, RollbackTo: manifest.RollbackTo,
		PreviousActiveRunID: previousRunID, ApprovalDigest: digest,
		Approvals: append([]AIEvaluationReleaseApproval(nil), manifest.Approvals...),
	}
	if manifest.Action == AIEvaluationReleasePromote {
		baseline := comparison.BaselineRun
		decision.BaselineEvaluationRun, decision.BaselineEvaluationID = &baseline, comparison.BaselineRunID
		policy := comparison.Policy
		decision.PromotionPolicy = &policy
		decision.ActiveRun, decision.ActiveRunID = comparison.CandidateRun, comparison.CandidateRunID
	} else {
		decision.ActiveRun, decision.ActiveRunID, err = rollbackReleaseTarget(ledger, manifest.RollbackTo)
		if err != nil {
			return AIEvaluationReleaseLedger{}, err
		}
	}
	if sameEvaluationConfiguration(previousRun, decision.ActiveRun) {
		return AIEvaluationReleaseLedger{}, fmt.Errorf("AI evaluation release decision would not change the active configuration")
	}
	decision.DecisionID, err = releaseDecisionID(decision)
	if err != nil {
		return AIEvaluationReleaseLedger{}, err
	}
	ledger.Decisions = append(ledger.Decisions, decision)
	ledger.HeadDecisionID = decision.DecisionID
	if err := ledger.Validate(); err != nil {
		return AIEvaluationReleaseLedger{}, err
	}
	return ledger, nil
}

func (l AIEvaluationReleaseLedger) Validate() error {
	if l.SchemaVersion != aiEvaluationReleaseLedgerSchema || len(l.Decisions) == 0 ||
		!validEvaluationSHA256(l.InitialRunID) || strings.TrimSpace(l.HeadDecisionID) == "" {
		return fmt.Errorf("AI evaluation release ledger has an incomplete header")
	}
	if err := validateReleaseRun(l.InitialRun); err != nil {
		return fmt.Errorf("AI evaluation release initial run: %w", err)
	}
	versions := map[string]struct{}{}
	previousDecisionID, activeRun, activeRunID := "", l.InitialRun, l.InitialRunID
	for i, decision := range l.Decisions {
		expectedDecisionID, err := releaseDecisionID(decision)
		if err != nil {
			return fmt.Errorf("AI evaluation release decision %d identity: %w", i+1, err)
		}
		if decision.Sequence != i+1 || decision.PreviousDecisionID != previousDecisionID ||
			decision.PreviousActiveRunID != activeRunID || decision.Status != "approved" ||
			!releaseVersionPattern.MatchString(decision.Version) || strings.TrimSpace(decision.Provenance) == "" ||
			decision.DecisionID != expectedDecisionID || !validEvaluationSHA256(decision.ActiveRunID) {
			return fmt.Errorf("AI evaluation release decision %d has invalid version, chain, status, or identity", i+1)
		}
		key := strings.ToLower(decision.Version)
		if _, duplicate := versions[key]; duplicate {
			return fmt.Errorf("AI evaluation release version %q is duplicated", decision.Version)
		}
		versions[key] = struct{}{}
		if err := validateReleaseRun(decision.ActiveRun); err != nil {
			return fmt.Errorf("AI evaluation release decision %d active run: %w", i+1, err)
		}
		if sameEvaluationConfiguration(activeRun, decision.ActiveRun) {
			return fmt.Errorf("AI evaluation release decision %d does not change configuration", i+1)
		}
		if decision.Action == AIEvaluationReleasePromote {
			if !validEvaluationSHA256(decision.ComparisonID) || decision.RollbackTo != "" ||
				!validEvaluationSHA256(decision.BaselineEvaluationID) || decision.BaselineEvaluationRun == nil ||
				!validEvaluationSHA256(decision.ActiveRunID) || decision.PromotionPolicy == nil ||
				!sameEvaluationConfiguration(activeRun, *decision.BaselineEvaluationRun) {
				return fmt.Errorf("AI evaluation promotion decision %d has invalid comparison or baseline", i+1)
			}
			if err := validateReleaseRun(*decision.BaselineEvaluationRun); err != nil {
				return fmt.Errorf("AI evaluation promotion decision %d baseline: %w", i+1, err)
			}
			if err := validateReleasePromotionPolicy(*decision.PromotionPolicy); err != nil {
				return fmt.Errorf("AI evaluation promotion decision %d policy: %w", i+1, err)
			}
			if decision.BaselineEvaluationID != activeRunID ||
				!reflect.DeepEqual(*decision.BaselineEvaluationRun, activeRun) {
				return fmt.Errorf("AI evaluation promotion decision %d does not bind the exact previous active run", i+1)
			}
		} else if decision.Action == AIEvaluationReleaseRollback {
			if decision.ComparisonID != "" || strings.TrimSpace(decision.RollbackTo) == "" ||
				decision.BaselineEvaluationID != "" || decision.BaselineEvaluationRun != nil || decision.PromotionPolicy != nil {
				return fmt.Errorf("AI evaluation rollback decision %d has invalid target metadata", i+1)
			}
			targetRun, targetRunID, err := rollbackReleaseTarget(AIEvaluationReleaseLedger{
				SchemaVersion: l.SchemaVersion, InitialRun: l.InitialRun, InitialRunID: l.InitialRunID,
				HeadDecisionID: previousDecisionID, Decisions: l.Decisions[:i],
			}, decision.RollbackTo)
			if err != nil || targetRunID != decision.ActiveRunID || !reflect.DeepEqual(targetRun, decision.ActiveRun) {
				return fmt.Errorf("AI evaluation rollback decision %d does not match its approved target", i+1)
			}
		} else {
			return fmt.Errorf("AI evaluation release decision %d has invalid action", i+1)
		}
		expectedApprovalDigest, err := releaseDecisionApprovalDigest(decision)
		if err != nil {
			return fmt.Errorf("AI evaluation release decision %d approval digest: %w", i+1, err)
		}
		if decision.ApprovalDigest != expectedApprovalDigest {
			return fmt.Errorf("AI evaluation release decision %d approval digest is invalid", i+1)
		}
		models := []string{activeRun.ProposerModel, activeRun.VerifierModel, decision.ActiveRun.ProposerModel, decision.ActiveRun.VerifierModel}
		if err := validateReleaseApprovals(decision.Approvals, decision.ApprovalDigest, models); err != nil {
			return fmt.Errorf("AI evaluation release decision %d: %w", i+1, err)
		}
		previousDecisionID, activeRun, activeRunID = decision.DecisionID, decision.ActiveRun, decision.ActiveRunID
	}
	if l.HeadDecisionID != previousDecisionID {
		return fmt.Errorf("AI evaluation release ledger head does not match the decision chain")
	}
	return nil
}

func validateReleaseManifestHeader(manifest AIEvaluationReleaseManifest) error {
	if manifest.SchemaVersion != AIEvaluationReleaseManifestSchema || !releaseVersionPattern.MatchString(manifest.Version) ||
		strings.TrimSpace(manifest.Provenance) == "" || manifest.Provenance != strings.TrimSpace(manifest.Provenance) ||
		len([]rune(manifest.Provenance)) > 2000 {
		return fmt.Errorf("AI evaluation release manifest requires canonical schema, version, and provenance")
	}
	if manifest.Action != AIEvaluationReleasePromote && manifest.Action != AIEvaluationReleaseRollback {
		return fmt.Errorf("AI evaluation release action must be promote or rollback")
	}
	if manifest.Action == AIEvaluationReleasePromote {
		if !validEvaluationSHA256(manifest.ComparisonID) || manifest.RollbackTo != "" {
			return fmt.Errorf("AI evaluation promotion requires comparison_id and no rollback target")
		}
	} else if manifest.ComparisonID != "" || strings.TrimSpace(manifest.RollbackTo) == "" {
		return fmt.Errorf("AI evaluation rollback requires rollback_to and no comparison_id")
	}
	return nil
}

// validateReleasePromotionPolicy pins release authority to a conservative policy floor. Comparison
// tooling may evaluate exploratory thresholds, but a release cannot weaken the built-in defaults.
func validateReleasePromotionPolicy(policy AIEvaluationPromotionPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	floor := DefaultAIEvaluationPromotionPolicy()
	if policy.MinimumPrecisionBasisPoints < floor.MinimumPrecisionBasisPoints ||
		policy.MaximumFalseNegativeEscapeRateBasisPoints > floor.MaximumFalseNegativeEscapeRateBasisPoints ||
		policy.MaximumPrecisionDropBasisPoints > floor.MaximumPrecisionDropBasisPoints ||
		policy.MaximumRecallDropBasisPoints > floor.MaximumRecallDropBasisPoints ||
		policy.MaximumCoverageDropBasisPoints > floor.MaximumCoverageDropBasisPoints ||
		policy.MaximumVerifierCoverageDropBasisPoints > floor.MaximumVerifierCoverageDropBasisPoints ||
		policy.MaximumDisagreementIncreaseBasisPoints > floor.MaximumDisagreementIncreaseBasisPoints ||
		policy.MinimumCounterfactualCoverageBasisPoints < floor.MinimumCounterfactualCoverageBasisPoints ||
		policy.MinimumCounterfactualVerifierCoverageBasisPoints < floor.MinimumCounterfactualVerifierCoverageBasisPoints ||
		policy.MaximumCounterfactualProposerFlipRateBasisPoints > floor.MaximumCounterfactualProposerFlipRateBasisPoints ||
		policy.MaximumCounterfactualVerifierFlipRateBasisPoints > floor.MaximumCounterfactualVerifierFlipRateBasisPoints ||
		policy.MaximumCounterfactualConsensusFlipRateBasisPoints > floor.MaximumCounterfactualConsensusFlipRateBasisPoints ||
		policy.MaximumCounterfactualPolicyFlipRateBasisPoints > floor.MaximumCounterfactualPolicyFlipRateBasisPoints {
		return fmt.Errorf("AI evaluation release promotion policy is weaker than the built-in safety floor")
	}
	return nil
}

func validateReleaseApprovals(approvals []AIEvaluationReleaseApproval, digest string, models []string) error {
	if len(approvals) != 2 {
		return fmt.Errorf("AI evaluation release requires exactly one PM and one Security approval")
	}
	roles, reviewers := map[string]struct{}{}, map[string]struct{}{}
	for _, approval := range approvals {
		role := strings.ToLower(strings.TrimSpace(approval.Role))
		reviewer := strings.TrimSpace(approval.Reviewer)
		_, offset := approval.ReviewedAt.Zone()
		if (role != "pm" && role != "security") || approval.Role != role || reviewer == "" || approval.Reviewer != reviewer ||
			!approval.Approved || len([]rune(strings.TrimSpace(approval.Rationale))) < 3 ||
			len([]rune(approval.Rationale)) > 2000 || approval.Rationale != strings.TrimSpace(approval.Rationale) ||
			approval.ReviewedAt.IsZero() || offset != 0 || approval.ReviewedSHA256 != digest ||
			aitriagereview.IsMachineOrModelActor(reviewer, models...) {
			return fmt.Errorf("AI evaluation release contains an invalid or non-human approval")
		}
		if _, exists := roles[role]; exists {
			return fmt.Errorf("AI evaluation release approval role %q is duplicated", role)
		}
		roles[role] = struct{}{}
		identity := strings.ToLower(reviewer)
		if _, exists := reviewers[identity]; exists {
			return fmt.Errorf("AI evaluation release approvals require distinct humans")
		}
		reviewers[identity] = struct{}{}
	}
	if approvals[0].Role != "pm" || approvals[1].Role != "security" {
		return fmt.Errorf("AI evaluation release approvals must be ordered pm then security")
	}
	return nil
}

// validateReleaseApproverAllowlist requires every approver to appear in the operator-owned allowlist.
// It is the positive counterpart to the machine-prefix denylist in validateReleaseApprovals, which can
// only name the non-human families this codebase already mints.
//
// An empty list is a refusal rather than a skip: a release recorded without an allowlist to check
// against would carry exactly the self-asserted approval this exists to prevent.
//
// The match is exact, not the case-insensitive comparison used for approver distinctness, so an
// allowlist entry admits one spelling of one identity. Each entry is re-checked against the denylist so
// the allowlist cannot launder a machine principal, mirroring validateBlindFPTriageReviewer.
func validateReleaseApproverAllowlist(approvals []AIEvaluationReleaseApproval, allowedHumanApprovers, models []string) error {
	if len(allowedHumanApprovers) == 0 {
		return fmt.Errorf("AI evaluation release requires an operator-supplied human approver allowlist")
	}
	for _, approval := range approvals {
		if !releaseApproverIsAllowed(approval.Reviewer, allowedHumanApprovers, models) {
			return fmt.Errorf("AI evaluation release approver %q is not an allowlisted human", approval.Reviewer)
		}
	}
	return nil
}

func releaseApproverIsAllowed(reviewer string, allowedHumanApprovers, models []string) bool {
	for _, allowed := range allowedHumanApprovers {
		if reviewer == allowed && allowed == strings.TrimSpace(allowed) &&
			!aitriagereview.IsMachineOrModelActor(allowed, models...) {
			return true
		}
	}
	return false
}

func validateReleaseRun(run AIEvaluationRun) error {
	if run.ProposerProvider == "" || run.ProposerProvider != agent.CanonicalProviderID(run.ProposerProvider) ||
		strings.TrimSpace(run.ProposerModel) == "" || run.ProposerModel != strings.TrimSpace(run.ProposerModel) ||
		run.VerifierProvider == "" || run.VerifierProvider != agent.CanonicalProviderID(run.VerifierProvider) ||
		strings.TrimSpace(run.VerifierModel) == "" || run.VerifierModel != strings.TrimSpace(run.VerifierModel) ||
		strings.TrimSpace(run.PromptVersion) == "" || run.PromptVersion != strings.TrimSpace(run.PromptVersion) ||
		strings.TrimSpace(run.PolicyVersion) == "" || run.PolicyVersion != strings.TrimSpace(run.PolicyVersion) ||
		!agent.IndependentLLMs(run.ProposerProvider, run.ProposerModel, run.VerifierProvider, run.VerifierModel, string(run.IndependencePolicy)) {
		return fmt.Errorf("run identity is incomplete or non-independent")
	}
	return nil
}

func currentReleaseRun(ledger AIEvaluationReleaseLedger) AIEvaluationRun {
	if len(ledger.Decisions) == 0 {
		return ledger.InitialRun
	}
	return ledger.Decisions[len(ledger.Decisions)-1].ActiveRun
}

func currentReleaseRunID(ledger AIEvaluationReleaseLedger) string {
	if len(ledger.Decisions) == 0 {
		return ledger.InitialRunID
	}
	return ledger.Decisions[len(ledger.Decisions)-1].ActiveRunID
}

func rollbackReleaseTarget(ledger AIEvaluationReleaseLedger, target string) (AIEvaluationRun, string, error) {
	if target == "initial" {
		return ledger.InitialRun, ledger.InitialRunID, nil
	}
	for _, decision := range ledger.Decisions {
		if decision.DecisionID == target {
			return decision.ActiveRun, decision.ActiveRunID, nil
		}
	}
	return AIEvaluationRun{}, "", fmt.Errorf("AI evaluation rollback target %q is not in the approved release ledger", target)
}

func releaseModelIdentities(ledger AIEvaluationReleaseLedger, evidence *AIEvaluationPromotionEvidence, manifest AIEvaluationReleaseManifest) []string {
	models := []string{}
	if ledger.SchemaVersion != "" {
		run := currentReleaseRun(ledger)
		models = append(models, run.ProposerModel, run.VerifierModel)
	}
	if evidence != nil {
		comparison := evidence.Comparison
		models = append(models, comparison.BaselineRun.ProposerModel, comparison.BaselineRun.VerifierModel,
			comparison.CandidateRun.ProposerModel, comparison.CandidateRun.VerifierModel)
	}
	if manifest.Action == AIEvaluationReleaseRollback && ledger.SchemaVersion != "" {
		if target, _, err := rollbackReleaseTarget(ledger, manifest.RollbackTo); err == nil {
			models = append(models, target.ProposerModel, target.VerifierModel)
		}
	}
	return models
}

func releaseDecisionApprovalDigest(decision AIEvaluationReleaseDecision) (string, error) {
	payload := struct {
		Schema       string          `json:"schema"`
		LedgerHead   string          `json:"ledger_head"`
		Version      string          `json:"version"`
		Action       string          `json:"action"`
		Provenance   string          `json:"provenance"`
		ComparisonID string          `json:"comparison_id,omitempty"`
		RollbackTo   string          `json:"rollback_to,omitempty"`
		TargetRun    AIEvaluationRun `json:"target_run"`
		TargetRunID  string          `json:"target_run_id"`
	}{aiEvaluationReleaseApprovalSchema, decision.PreviousDecisionID, decision.Version, decision.Action,
		decision.Provenance, decision.ComparisonID, decision.RollbackTo, decision.ActiveRun, decision.ActiveRunID}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal AI evaluation release approval digest: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func releaseDecisionID(decision AIEvaluationReleaseDecision) (string, error) {
	copyDecision := decision
	copyDecision.DecisionID = ""
	b, err := json.Marshal(copyDecision)
	if err != nil {
		return "", fmt.Errorf("marshal AI evaluation release decision identity: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func decodeReleaseJSON(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

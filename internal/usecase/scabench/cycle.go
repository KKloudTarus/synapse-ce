package scabench

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Cycle-level contracts are deliberately separate from the published benchmark
// contracts. They describe a fresh, auditable evidence cycle and do not change
// the historical catalog, oracle, observation, result, or ratchet schemas.
const (
	SourceFreezeSchemaVersion             = "synapse-sca-benchmark-source-freeze-v1"
	OracleCandidateSchemaVersion          = "synapse-sca-benchmark-oracle-candidate-v1"
	CrossCheckSchemaVersion               = "synapse-sca-benchmark-cross-check-v1"
	AdjudicationSchemaVersion             = "synapse-sca-benchmark-adjudication-v1"
	AccountableReviewSchemaVersion        = "synapse-sca-benchmark-accountable-review-v3"
	GitHubReviewCaptureSchemaVersion      = "synapse-sca-benchmark-github-review-capture-v1"
	FinalOracleFreezeSchemaVersion        = "synapse-sca-benchmark-final-oracle-freeze-v1"
	CyclePlanSchemaVersion                = "synapse-sca-benchmark-cycle-plan-v1"
	CycleLedgerSchemaVersion              = "synapse-sca-benchmark-cycle-ledger-v1"
	NativeComparisonSchemaVersion         = "synapse-sca-benchmark-native-comparison-v2"
	PublicationManifestSchemaVersion      = "synapse-sca-benchmark-publication-manifest-v1"
	PublicationControlSchemaVersion       = "synapse-sca-benchmark-publication-control-v1"
	CandidateEvidenceSummarySchemaVersion = "synapse-sca-benchmark-candidate-evidence-summary-v1"
	FalsifierSpecSchemaVersion            = "synapse-sca-benchmark-falsifier-spec-v1"
)

// ContentReference identifies a committed, repository-relative asset. Its
// filesystem resolution is performed by the infrastructure asset verifier
// before capture; the contract itself prohibits every locator form that could
// escape the repository.
type ContentReference struct {
	Locator string `json:"locator"`
	Digest  string `json:"digest"`
	Size    int64  `json:"size"`
}

func (reference ContentReference) Validate() error {
	if err := validateRepositoryLocator(reference.Locator); err != nil {
		return err
	}
	if !validSHA256Digest(reference.Digest) {
		return fmt.Errorf("content reference %q has an invalid digest", reference.Locator)
	}
	if reference.Size < 0 {
		return fmt.Errorf("content reference %q has a negative size", reference.Locator)
	}
	return nil
}

// SourceFreeze is immutable cycle input. Its assets must be resolved and
// digested before an oracle candidate or any scanner capture is accepted.
type SourceFreeze struct {
	SchemaVersion string             `json:"schema_version"`
	CycleID       string             `json:"cycle_id"`
	Assets        []ContentReference `json:"assets"`
	ContentDigest string             `json:"content_digest"`
}

func (freeze SourceFreeze) Validate() error {
	if freeze.SchemaVersion != SourceFreezeSchemaVersion {
		return fmt.Errorf("unsupported source freeze schema %q", freeze.SchemaVersion)
	}
	if err := validateCycleID(freeze.CycleID); err != nil {
		return err
	}
	if len(freeze.Assets) == 0 {
		return fmt.Errorf("source freeze requires at least one asset")
	}
	if !validSHA256Digest(freeze.ContentDigest) {
		return fmt.Errorf("source freeze content digest is invalid")
	}
	seen := make(map[string]struct{}, len(freeze.Assets))
	for _, asset := range freeze.Assets {
		if err := asset.Validate(); err != nil {
			return fmt.Errorf("source freeze asset: %w", err)
		}
		if _, exists := seen[asset.Locator]; exists {
			return fmt.Errorf("source freeze has duplicate asset %q", asset.Locator)
		}
		seen[asset.Locator] = struct{}{}
	}
	digest, err := DigestContentReferences(freeze.Assets)
	if err != nil {
		return err
	}
	if freeze.ContentDigest != digest {
		return fmt.Errorf("source freeze content digest does not bind its assets")
	}
	return nil
}

// OracleCandidate contains scanner-free proposed truth. It intentionally has
// no scanner observation, bundle, score, or reviewer decision field.
type OracleCandidate struct {
	SchemaVersion      string                `json:"schema_version"`
	CycleID            string                `json:"cycle_id"`
	SourceFreezeDigest string                `json:"source_freeze_digest"`
	Cases              []OracleCandidateCase `json:"cases"`
}

type OracleCandidateCase struct {
	ID         string             `json:"id"`
	TargetID   string             `json:"target_id"`
	Component  Component          `json:"component"`
	AdvisoryID string             `json:"advisory_id"`
	Truth      Truth              `json:"truth"`
	Rationale  string             `json:"rationale"`
	Citations  []ContentReference `json:"citations"`
}

func (candidate OracleCandidate) Validate() error {
	if candidate.SchemaVersion != OracleCandidateSchemaVersion {
		return fmt.Errorf("unsupported oracle candidate schema %q", candidate.SchemaVersion)
	}
	if err := validateCycleID(candidate.CycleID); err != nil {
		return err
	}
	if !validSHA256Digest(candidate.SourceFreezeDigest) {
		return fmt.Errorf("oracle candidate source freeze digest is invalid")
	}
	if len(candidate.Cases) == 0 {
		return fmt.Errorf("oracle candidate requires at least one case")
	}
	seen := make(map[string]struct{}, len(candidate.Cases))
	for _, item := range candidate.Cases {
		if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.TargetID) == "" {
			return fmt.Errorf("oracle candidate case requires an id and target id")
		}
		if containsControlCharacter(item.ID) || containsControlCharacter(item.TargetID) {
			return fmt.Errorf("oracle candidate case contains a control character")
		}
		if _, exists := seen[item.ID]; exists {
			return fmt.Errorf("oracle candidate has duplicate case %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		if strings.TrimSpace(item.Component.PURL) == "" || strings.TrimSpace(item.Component.Version) == "" {
			return fmt.Errorf("oracle candidate case %q requires a component", item.ID)
		}
		if strings.TrimSpace(item.AdvisoryID) == "" || strings.TrimSpace(item.Rationale) == "" {
			return fmt.Errorf("oracle candidate case %q requires an advisory and rationale", item.ID)
		}
		if item.Truth != TruthAffected && item.Truth != TruthFixed && item.Truth != TruthNotAffected && item.Truth != TruthWithdrawn {
			return fmt.Errorf("oracle candidate case %q has an invalid truth value", item.ID)
		}
		if len(item.Citations) == 0 {
			return fmt.Errorf("oracle candidate case %q requires citations", item.ID)
		}
		citationLocators := make(map[string]struct{}, len(item.Citations))
		for _, citation := range item.Citations {
			if err := citation.Validate(); err != nil {
				return fmt.Errorf("oracle candidate case %q citation: %w", item.ID, err)
			}
			if _, exists := citationLocators[citation.Locator]; exists {
				return fmt.Errorf("oracle candidate case %q has a duplicate citation", item.ID)
			}
			citationLocators[citation.Locator] = struct{}{}
		}
	}
	return nil
}

// AutomatedCrossCheck is an automated, scanner-blinded cross-check. It is not
// a human review record, and it intentionally cannot carry scanner material.
type AutomatedCrossCheck struct {
	SchemaVersion         string           `json:"schema_version"`
	CycleID               string           `json:"cycle_id"`
	OracleCandidateDigest string           `json:"oracle_candidate_digest"`
	Method                string           `json:"method"`
	InputDigest           string           `json:"input_digest"`
	ResultDigest          string           `json:"result_digest"`
	Status                string           `json:"status"`
	Cases                 []CrossCheckCase `json:"cases"`
}

// CrossCheckCase is the independent, scanner-blinded determination for one
// source-evidence case. It never embeds scanner output or scoring material.
type CrossCheckCase struct {
	ID    string `json:"id"`
	Truth Truth  `json:"truth"`
}

func (check AutomatedCrossCheck) Validate() error {
	if check.SchemaVersion != CrossCheckSchemaVersion {
		return fmt.Errorf("unsupported cross-check schema %q", check.SchemaVersion)
	}
	if err := validateCycleID(check.CycleID); err != nil {
		return err
	}
	if check.Method != "automated_scanner_blinded_cross_check" {
		return fmt.Errorf("cross-check method must identify the automated scanner-blinded cross-check")
	}
	if check.Status != "passed" && check.Status != "failed" {
		return fmt.Errorf("cross-check status must be passed or failed")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{"oracle candidate", check.OracleCandidateDigest},
		{"input", check.InputDigest},
		{"result", check.ResultDigest},
	} {
		if !validSHA256Digest(digest.value) {
			return fmt.Errorf("cross-check %s digest is invalid", digest.name)
		}
	}
	if len(check.Cases) == 0 {
		return fmt.Errorf("cross-check requires independent case results")
	}
	seen := make(map[string]struct{}, len(check.Cases))
	for _, item := range check.Cases {
		if strings.TrimSpace(item.ID) == "" || containsControlCharacter(item.ID) {
			return fmt.Errorf("cross-check case requires an id")
		}
		if item.Truth != TruthAffected && item.Truth != TruthFixed && item.Truth != TruthNotAffected && item.Truth != TruthWithdrawn {
			return fmt.Errorf("cross-check case %q has invalid truth", item.ID)
		}
		if _, exists := seen[item.ID]; exists {
			return fmt.Errorf("cross-check has duplicate case %q", item.ID)
		}
		seen[item.ID] = struct{}{}
	}
	return nil
}

// AdjudicationRecord resolves the relationship between a candidate and an
// automated cross-check. It is separate from the accountable publication
// decision below.
type AdjudicationRecord struct {
	SchemaVersion         string `json:"schema_version"`
	CycleID               string `json:"cycle_id"`
	OracleCandidateDigest string `json:"oracle_candidate_digest"`
	CrossCheckDigest      string `json:"cross_check_digest"`
	ResolutionDigest      string `json:"resolution_digest"`
	Status                string `json:"status"`
}

func (record AdjudicationRecord) Validate() error {
	if record.SchemaVersion != AdjudicationSchemaVersion {
		return fmt.Errorf("unsupported adjudication schema %q", record.SchemaVersion)
	}
	if err := validateCycleID(record.CycleID); err != nil {
		return err
	}
	if record.Status != "resolved" && record.Status != "unresolved" {
		return fmt.Errorf("adjudication status must be resolved or unresolved")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{"oracle candidate", record.OracleCandidateDigest},
		{"cross-check", record.CrossCheckDigest},
		{"resolution", record.ResolutionDigest},
	} {
		if !validSHA256Digest(digest.value) {
			return fmt.Errorf("adjudication %s digest is invalid", digest.name)
		}
	}
	return nil
}

// AccountableReview is the distinct explicit decision required for
// publication. An automated cross-check can never substitute for this record.
// AccountableReview is a submitted GitHub decision captured as a sanitized,
// digest-pinned repository asset. It binds the exact reviewed commit and final
// oracle before any capture can proceed.
type AccountableReview struct {
	SchemaVersion      string           `json:"schema_version"`
	CycleID            string           `json:"cycle_id"`
	AdjudicationDigest string           `json:"adjudication_digest"`
	FinalOracleDigest  string           `json:"final_oracle_digest"`
	ReviewerIdentity   string           `json:"reviewer_identity"`
	SubmittedAt        string           `json:"submitted_at"`
	ReviewedCommit     string           `json:"reviewed_commit"`
	GitHubReviewID     string           `json:"github_review_id"`
	GitHubReviewURL    string           `json:"github_review_url"`
	ReviewCapture      ContentReference `json:"review_capture"`
	Decision           string           `json:"decision"`
	DecisionDigest     string           `json:"decision_digest"`
}

// GitHubReviewCapture is the only allowed on-disk form of a submitted GitHub
// review. The ingestion boundary must discard every credential, account profile,
// transport header, and non-decision body text before this record is created.
type GitHubReviewCapture struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	URL           string `json:"url"`
	Login         string `json:"login"`
	State         string `json:"state"`
	SubmittedAt   string `json:"submitted_at"`
	CommitID      string `json:"commit_id"`
	Body          string `json:"body"`
}

func (capture GitHubReviewCapture) Validate() error {
	if capture.SchemaVersion != GitHubReviewCaptureSchemaVersion {
		return fmt.Errorf("unsupported github review capture schema %q", capture.SchemaVersion)
	}
	if err := validateGitHubReview(capture.ID, capture.URL); err != nil {
		return err
	}
	if !validGitHubLogin(capture.Login) {
		return fmt.Errorf("github review capture login is invalid")
	}
	if _, err := time.Parse(time.RFC3339, capture.SubmittedAt); err != nil {
		return fmt.Errorf("github review capture submitted time: %w", err)
	}
	if !validCommitSHA(capture.CommitID) {
		return fmt.Errorf("github review capture commit is invalid")
	}
	if capture.State != "APPROVED" && capture.State != "CHANGES_REQUESTED" && capture.State != "COMMENTED" {
		return fmt.Errorf("github review capture state is invalid")
	}
	if _, err := githubReviewBodyDecision(capture.Body); err != nil {
		return err
	}
	return nil
}

// ValidateAgainstAccountableReview binds the sanitized captured review fields to
// the separately supplied accountable decision before scanner dispatch.
func (capture GitHubReviewCapture) ValidateAgainstAccountableReview(review AccountableReview) error {
	if err := capture.Validate(); err != nil {
		return err
	}
	if capture.ID != review.GitHubReviewID || capture.URL != review.GitHubReviewURL || "github:"+capture.Login != review.ReviewerIdentity || capture.SubmittedAt != review.SubmittedAt || capture.CommitID != review.ReviewedCommit {
		return fmt.Errorf("github review capture does not match accountable review provenance")
	}
	decision, err := githubReviewBodyDecision(capture.Body)
	if err != nil {
		return err
	}
	if decision != review.Decision {
		return fmt.Errorf("github review capture body decision does not match accountable review")
	}
	if (decision == "approved" && capture.State != "APPROVED") || (decision == "rejected" && capture.State != "CHANGES_REQUESTED") || (decision == "unresolved" && capture.State != "COMMENTED") {
		return fmt.Errorf("github review capture state does not match its decision")
	}
	return nil
}

func githubReviewBodyDecision(body string) (string, error) {
	const prefix = "decision: "
	if !strings.HasPrefix(body, prefix) {
		return "", fmt.Errorf("github review capture body must contain only a canonical decision")
	}
	decision := strings.TrimPrefix(body, prefix)
	if decision != "approved" && decision != "rejected" && decision != "unresolved" {
		return "", fmt.Errorf("github review capture body decision is invalid")
	}
	return decision, nil
}

func validGitHubLogin(login string) bool {
	if len(login) == 0 || len(login) > 39 || login[0] == '-' || login[len(login)-1] == '-' {
		return false
	}
	for _, character := range login {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-') {
			return false
		}
	}
	return true
}

func (review AccountableReview) Validate() error {
	if review.SchemaVersion != AccountableReviewSchemaVersion {
		return fmt.Errorf("unsupported accountable review schema %q", review.SchemaVersion)
	}
	if err := validateCycleID(review.CycleID); err != nil {
		return err
	}
	if !strings.HasPrefix(review.ReviewerIdentity, "github:") || len(review.ReviewerIdentity) == len("github:") || containsControlCharacter(review.ReviewerIdentity) {
		return fmt.Errorf("accountable review requires a submitted github reviewer identity")
	}
	if _, err := time.Parse(time.RFC3339, review.SubmittedAt); err != nil {
		return fmt.Errorf("accountable review submitted time: %w", err)
	}
	if !validCommitSHA(review.ReviewedCommit) {
		return fmt.Errorf("accountable review reviewed commit is invalid")
	}
	if err := validateGitHubReview(review.GitHubReviewID, review.GitHubReviewURL); err != nil {
		return err
	}
	if err := review.ReviewCapture.Validate(); err != nil {
		return fmt.Errorf("accountable review capture: %w", err)
	}
	if !strings.HasPrefix(review.ReviewCapture.Locator, "reviews/github/") {
		return fmt.Errorf("accountable review capture must be a sanitized repository-backed github review asset")
	}
	if review.Decision != "approved" && review.Decision != "rejected" && review.Decision != "unresolved" {
		return fmt.Errorf("accountable review decision is invalid")
	}
	if !validSHA256Digest(review.AdjudicationDigest) || !validSHA256Digest(review.FinalOracleDigest) || !validSHA256Digest(review.DecisionDigest) {
		return fmt.Errorf("accountable review digests are invalid")
	}
	if review.DecisionDigest != review.ReviewCapture.Digest {
		return fmt.Errorf("accountable review decision digest must bind its immutable review capture")
	}
	return nil
}

func validateGitHubReview(reviewID, reviewURL string) error {
	if reviewID == "" || containsControlCharacter(reviewID) {
		return fmt.Errorf("accountable review github review id is invalid")
	}
	parsedID, err := strconv.ParseUint(reviewID, 10, 64)
	if err != nil || parsedID == 0 {
		return fmt.Errorf("accountable review github review id is invalid")
	}
	parsedURL, err := url.Parse(reviewURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host != "github.com" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "pullrequestreview-"+reviewID {
		return fmt.Errorf("accountable review github review url is invalid")
	}
	path := strings.Split(parsedURL.EscapedPath(), "/")
	if len(path) != 5 || path[0] != "" || path[1] == "" || path[2] == "" || path[3] != "pull" {
		return fmt.Errorf("accountable review github review url is not a pull-request review")
	}
	pullNumber, err := strconv.ParseUint(path[4], 10, 64)
	if err != nil || pullNumber == 0 {
		return fmt.Errorf("accountable review github pull request number is invalid")
	}
	return nil
}

// CyclePlan declares the whole matrix before capture. Counts remain plan data:
// generic validation only ensures that the plan is internally complete.
// FinalOracleFreeze is the immutable, review-gated binding of an approved legacy
// Oracle to the scanner-free construction records. It is the only final-oracle
// identity that a capture plan may use.
type FinalOracleFreeze struct {
	SchemaVersion           string `json:"schema_version"`
	CycleID                 string `json:"cycle_id"`
	SourceFreezeDigest      string `json:"source_freeze_digest"`
	OracleCandidateDigest   string `json:"oracle_candidate_digest"`
	CrossCheckDigest        string `json:"cross_check_digest"`
	AdjudicationDigest      string `json:"adjudication_digest"`
	AccountableReviewDigest string `json:"accountable_review_digest"`
	OracleDigest            string `json:"oracle_digest"`
}

func (freeze FinalOracleFreeze) Validate() error {
	if freeze.SchemaVersion != FinalOracleFreezeSchemaVersion {
		return fmt.Errorf("unsupported final oracle freeze schema %q", freeze.SchemaVersion)
	}
	if err := validateCycleID(freeze.CycleID); err != nil {
		return err
	}
	for _, value := range []struct {
		name   string
		digest string
	}{
		{"source freeze", freeze.SourceFreezeDigest},
		{"oracle candidate", freeze.OracleCandidateDigest},
		{"cross-check", freeze.CrossCheckDigest},
		{"adjudication", freeze.AdjudicationDigest},
		{"accountable review", freeze.AccountableReviewDigest},
		{"final oracle", freeze.OracleDigest},
	} {
		if !validSHA256Digest(value.digest) {
			return fmt.Errorf("final oracle freeze %s digest is invalid", value.name)
		}
	}
	return nil
}

type CyclePlan struct {
	SchemaVersion           string      `json:"schema_version"`
	CycleID                 string      `json:"cycle_id"`
	SourceFreezeDigest      string      `json:"source_freeze_digest"`
	OracleCandidateDigest   string      `json:"oracle_candidate_digest"`
	CrossCheckDigest        string      `json:"cross_check_digest"`
	AdjudicationDigest      string      `json:"adjudication_digest"`
	AccountableReviewDigest string      `json:"accountable_review_digest"`
	FinalOracleDigest       string      `json:"final_oracle_digest"`
	Repetitions             int         `json:"repetitions"`
	Cells                   []CycleCell `json:"cells"`
}

type CycleCell struct {
	TargetID          string           `json:"target_id"`
	Engine            Engine           `json:"engine"`
	ExpectedState     ObservationState `json:"expected_state"`
	ScannerDispatches int              `json:"scanner_dispatches"`
}

func (plan CyclePlan) Validate() error {
	if plan.SchemaVersion != CyclePlanSchemaVersion {
		return fmt.Errorf("unsupported cycle plan schema %q", plan.SchemaVersion)
	}
	if err := validateCycleID(plan.CycleID); err != nil {
		return err
	}
	for _, item := range []struct {
		name   string
		digest string
	}{
		{"source freeze", plan.SourceFreezeDigest},
		{"oracle candidate", plan.OracleCandidateDigest},
		{"cross-check", plan.CrossCheckDigest},
		{"adjudication", plan.AdjudicationDigest},
		{"accountable review", plan.AccountableReviewDigest},
		{"final oracle", plan.FinalOracleDigest},
	} {
		if !validSHA256Digest(item.digest) {
			return fmt.Errorf("cycle plan %s digest is invalid", item.name)
		}
	}
	if plan.Repetitions < 1 {
		return fmt.Errorf("cycle plan requires at least one repetition")
	}
	if len(plan.Cells) == 0 {
		return fmt.Errorf("cycle plan requires cells")
	}
	seen := make(map[string]struct{}, len(plan.Cells))
	for _, cell := range plan.Cells {
		if err := cell.Validate(); err != nil {
			return err
		}
		key := cycleCellKey(cell.TargetID, cell.Engine)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("cycle plan has duplicate cell %q", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (cell CycleCell) Validate() error {
	if !validPortableTargetID(cell.TargetID) {
		return fmt.Errorf("cycle cell target id must be a portable path segment")
	}
	if !knownCycleEngine(cell.Engine) {
		return fmt.Errorf("cycle cell has an unknown engine %q", cell.Engine)
	}
	switch cell.ExpectedState {
	case ObservationComplete:
		if cell.ScannerDispatches < 1 {
			return fmt.Errorf("complete cycle cell requires scanner dispatch")
		}
	case ObservationUnsupported:
		if cell.ScannerDispatches != 0 {
			return fmt.Errorf("unsupported cycle cell must have zero scanner dispatch")
		}
	default:
		return fmt.Errorf("cycle cell state %q is not permitted", cell.ExpectedState)
	}
	return nil
}

// BundleEvidenceIdentity binds score-adjacent publication state to the whole
// capture identity. It is derived from an existing capture bundle; it does not
// add another capture format.
type BundleEvidenceIdentity struct {
	TargetID                    string `json:"target_id"`
	Engine                      Engine `json:"engine"`
	BundleManifestDigest        string `json:"bundle_manifest_digest"`
	BundleRootDigest            string `json:"bundle_root_digest"`
	RawStdoutDigest             string `json:"raw_stdout_digest,omitempty"`
	RawStderrDigest             string `json:"raw_stderr_digest,omitempty"`
	RawOutputDigest             string `json:"raw_output_digest,omitempty"`
	NormalizedObservationDigest string `json:"normalized_observation_digest"`
	SBOMDigest                  string `json:"sbom_digest"`
	NativeComparisonDigest      string `json:"native_comparison_digest"`
	ProcessEvidenceDigest       string `json:"process_evidence_digest"`
	EnvironmentDigest           string `json:"environment_digest"`
}

func (identity BundleEvidenceIdentity) Validate() error {
	if strings.TrimSpace(identity.TargetID) == "" || !knownCycleEngine(identity.Engine) {
		return fmt.Errorf("bundle evidence identity requires a known target and engine")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{"bundle manifest", identity.BundleManifestDigest},
		{"bundle root", identity.BundleRootDigest},
		{"normalized observation", identity.NormalizedObservationDigest},
		{"SBOM", identity.SBOMDigest},
		{"native comparison", identity.NativeComparisonDigest},
		{"process evidence", identity.ProcessEvidenceDigest},
		{"environment", identity.EnvironmentDigest},
	} {
		if !validSHA256Digest(digest.value) {
			return fmt.Errorf("bundle evidence identity %s digest is invalid", digest.name)
		}
	}
	if identity.RawStdoutDigest == "" && identity.RawStderrDigest == "" && identity.RawOutputDigest == "" {
		return fmt.Errorf("bundle evidence identity requires a raw output digest")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{"raw stdout", identity.RawStdoutDigest},
		{"raw stderr", identity.RawStderrDigest},
		{"raw output", identity.RawOutputDigest},
	} {
		if digest.value != "" && !validSHA256Digest(digest.value) {
			return fmt.Errorf("bundle evidence identity %s digest is invalid", digest.name)
		}
	}
	return nil
}

// ProtectedBundleReference points at retained, non-committed raw evidence.
// ProtectedBundleDestination identifies protected storage before a fresh raw
// bundle is written. Capture derives the stored reference digest from the
// resulting full bundle root.
type ProtectedBundleDestination struct {
	Locator   string `json:"locator"`
	Retention string `json:"retention"`
}

func (destination ProtectedBundleDestination) Validate() error {
	return validateProtectedBundleDestination(destination.Locator, destination.Retention)
}

// BindRootDigest creates a retained evidence reference that is bound to the
// actual root of the written bundle.
func (destination ProtectedBundleDestination) BindRootDigest(rootDigest string) (ProtectedBundleReference, error) {
	if err := destination.Validate(); err != nil {
		return ProtectedBundleReference{}, err
	}
	reference := ProtectedBundleReference{Locator: destination.Locator, Digest: rootDigest, Retention: destination.Retention}
	if err := reference.Validate(); err != nil {
		return ProtectedBundleReference{}, fmt.Errorf("bind protected bundle root digest: %w", err)
	}
	return reference, nil
}

type ProtectedBundleReference struct {
	Locator   string `json:"locator"`
	Digest    string `json:"digest"`
	Retention string `json:"retention"`
}

func (reference ProtectedBundleReference) Validate() error {
	if err := validateProtectedBundleDestination(reference.Locator, reference.Retention); err != nil {
		return err
	}
	if !validSHA256Digest(reference.Digest) {
		return fmt.Errorf("protected bundle reference requires a digest")
	}
	return nil
}

func validateProtectedBundleDestination(locator, retention string) error {
	if strings.TrimSpace(locator) == "" || containsControlCharacter(locator) || strings.HasPrefix(strings.ToLower(locator), "file:") {
		return fmt.Errorf("protected bundle locator is invalid")
	}
	if strings.TrimSpace(retention) == "" {
		return fmt.Errorf("protected bundle retention is required")
	}
	return nil
}

type CycleAttemptOutcome string

const (
	CycleAttemptAccepted CycleAttemptOutcome = "accepted"
	CycleAttemptFailed   CycleAttemptOutcome = "failed"
	CycleAttemptRetry    CycleAttemptOutcome = "retry"
)

// CycleAttempt preserves every capture attempt. Only a final accepted attempt
// can satisfy a planned slot; failed and retry attempts remain retained.
type CycleAttempt struct {
	AttemptID         string                   `json:"attempt_id"`
	Sequence          int                      `json:"sequence"`
	Outcome           CycleAttemptOutcome      `json:"outcome"`
	ObservationState  ObservationState         `json:"observation_state,omitempty"`
	ScannerDispatches int                      `json:"scanner_dispatches"`
	ProtectedBundle   ProtectedBundleReference `json:"protected_bundle"`
	EvidenceIdentity  *BundleEvidenceIdentity  `json:"evidence_identity,omitempty"`
}

func (attempt CycleAttempt) Validate() error {
	if strings.TrimSpace(attempt.AttemptID) == "" || containsControlCharacter(attempt.AttemptID) || attempt.Sequence < 1 {
		return fmt.Errorf("cycle attempt requires an id and positive sequence")
	}
	if attempt.ScannerDispatches < 0 {
		return fmt.Errorf("cycle attempt scanner dispatches cannot be negative")
	}
	if err := attempt.ProtectedBundle.Validate(); err != nil {
		return fmt.Errorf("cycle attempt protected bundle: %w", err)
	}
	switch attempt.Outcome {
	case CycleAttemptAccepted:
		if attempt.ObservationState != ObservationComplete && attempt.ObservationState != ObservationUnsupported {
			return fmt.Errorf("accepted cycle attempt must be complete or unsupported")
		}
		if attempt.EvidenceIdentity == nil {
			return fmt.Errorf("accepted cycle attempt requires a full evidence identity")
		}
		if err := attempt.EvidenceIdentity.Validate(); err != nil {
			return err
		}
		if attempt.ProtectedBundle.Digest != attempt.EvidenceIdentity.BundleRootDigest {
			return fmt.Errorf("accepted cycle attempt protected bundle digest does not bind its full evidence root")
		}
	case CycleAttemptFailed, CycleAttemptRetry:
		if attempt.EvidenceIdentity != nil {
			return fmt.Errorf("non-accepted cycle attempt cannot claim a publication evidence identity")
		}
	default:
		return fmt.Errorf("cycle attempt has an invalid outcome %q", attempt.Outcome)
	}
	return nil
}

type CycleSlot struct {
	Repetition        int              `json:"repetition"`
	TargetID          string           `json:"target_id"`
	Engine            Engine           `json:"engine"`
	ExpectedState     ObservationState `json:"expected_state"`
	ScannerDispatches int              `json:"scanner_dispatches"`
	Attempts          []CycleAttempt   `json:"attempts"`
}

// CycleLedger is the complete append-only attempt record for a planned matrix.
type CycleLedger struct {
	SchemaVersion   string      `json:"schema_version"`
	CycleID         string      `json:"cycle_id"`
	CyclePlanDigest string      `json:"cycle_plan_digest"`
	Slots           []CycleSlot `json:"slots"`
}

func (ledger CycleLedger) ValidateAgainstPlan(plan CyclePlan) error {
	if err := ledger.validateBasic(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("validate cycle plan: %w", err)
	}
	if ledger.CycleID != plan.CycleID {
		return fmt.Errorf("cycle ledger belongs to a different cycle")
	}
	planDigest, err := DigestCyclePlan(plan)
	if err != nil {
		return err
	}
	if ledger.CyclePlanDigest != planDigest {
		return fmt.Errorf("cycle ledger does not bind the cycle plan")
	}
	expected := make(map[string]CycleCell, len(plan.Cells)*plan.Repetitions)
	for repetition := 1; repetition <= plan.Repetitions; repetition++ {
		for _, cell := range plan.Cells {
			expected[cycleSlotKey(repetition, cell.TargetID, cell.Engine)] = cell
		}
	}
	if len(ledger.Slots) != len(expected) {
		return fmt.Errorf("cycle ledger slot count does not match the plan")
	}
	seenSlots := make(map[string]struct{}, len(ledger.Slots))
	seenAttempts := make(map[string]struct{})
	for _, slot := range ledger.Slots {
		key := cycleSlotKey(slot.Repetition, slot.TargetID, slot.Engine)
		cell, known := expected[key]
		if !known {
			return fmt.Errorf("cycle ledger contains an unknown slot %q", key)
		}
		if _, exists := seenSlots[key]; exists {
			return fmt.Errorf("cycle ledger contains duplicate slot %q", key)
		}
		seenSlots[key] = struct{}{}
		if slot.ExpectedState != cell.ExpectedState || slot.ScannerDispatches != cell.ScannerDispatches {
			return fmt.Errorf("cycle ledger slot %q differs from the plan", key)
		}
		if err := validateCycleSlotAttempts(slot, seenAttempts); err != nil {
			return fmt.Errorf("cycle ledger slot %q: %w", key, err)
		}
		final := latestCycleAttempt(slot.Attempts)
		if final.Outcome != CycleAttemptAccepted {
			return fmt.Errorf("cycle ledger slot %q has no final accepted attempt", key)
		}
		if final.ObservationState != cell.ExpectedState || final.ScannerDispatches != cell.ScannerDispatches {
			return fmt.Errorf("cycle ledger slot %q final attempt does not match the planned capability", key)
		}
		if final.EvidenceIdentity == nil || final.EvidenceIdentity.TargetID != slot.TargetID || final.EvidenceIdentity.Engine != slot.Engine {
			return fmt.Errorf("cycle ledger slot %q has a mismatched full evidence identity", key)
		}
	}
	return nil
}

func (ledger CycleLedger) validateBasic() error {
	if ledger.SchemaVersion != CycleLedgerSchemaVersion {
		return fmt.Errorf("unsupported cycle ledger schema %q", ledger.SchemaVersion)
	}
	if err := validateCycleID(ledger.CycleID); err != nil {
		return err
	}
	if !validSHA256Digest(ledger.CyclePlanDigest) {
		return fmt.Errorf("cycle ledger plan digest is invalid")
	}
	if len(ledger.Slots) == 0 {
		return fmt.Errorf("cycle ledger requires slots")
	}
	return nil
}

func validateCycleSlotAttempts(slot CycleSlot, seenAttempts map[string]struct{}) error {
	if slot.Repetition < 1 || strings.TrimSpace(slot.TargetID) == "" || !knownCycleEngine(slot.Engine) || len(slot.Attempts) == 0 {
		return fmt.Errorf("cycle slot is incomplete")
	}
	sequences := make(map[int]struct{}, len(slot.Attempts))
	accepted := 0
	for _, attempt := range slot.Attempts {
		if err := attempt.Validate(); err != nil {
			return err
		}
		if _, exists := seenAttempts[attempt.AttemptID]; exists {
			return fmt.Errorf("cycle attempt %q is duplicated", attempt.AttemptID)
		}
		seenAttempts[attempt.AttemptID] = struct{}{}
		if _, exists := sequences[attempt.Sequence]; exists {
			return fmt.Errorf("cycle attempt sequence %d is duplicated", attempt.Sequence)
		}
		sequences[attempt.Sequence] = struct{}{}
		if attempt.Outcome == CycleAttemptAccepted {
			accepted++
		}
	}
	if accepted != 1 {
		return fmt.Errorf("cycle slot must retain exactly one accepted attempt")
	}
	return nil
}

func latestCycleAttempt(attempts []CycleAttempt) CycleAttempt {
	latest := attempts[0]
	for _, attempt := range attempts[1:] {
		if attempt.Sequence > latest.Sequence {
			latest = attempt
		}
	}
	return latest
}

const (
	// NativePredicateEVRLessThan identifies a vendor EVR vulnerability range.
	NativePredicateEVRLessThan = "evr_less_than"
	// NativePredicateVersionEqualsZero identifies the SLES explicit not-affected sentinel.
	NativePredicateVersionEqualsZero = "version_equals_zero"
)

// NativeComparisonRecord binds a normalized package relationship to execution
// by a target-native comparator. It has no host or semantic fallback field.
// NativeComparisonRecord binds one generated source predicate to its
// target-native execution. PackageIdentity records whether the comparison used
// the binary package identity or an explicit mapped source-package identity.
type NativeComparisonRecord struct {
	SchemaVersion   string `json:"schema_version"`
	ID              string `json:"id"`
	TargetID        string `json:"target_id"`
	TargetDigest    string `json:"target_digest"`
	PackageFamily   string `json:"package_family"`
	PackageIdentity string `json:"package_identity"`
	CandidateEVR    string `json:"candidate_evr"`
	FixedEVR        string `json:"fixed_evr"`
	PredicateKind   string `json:"predicate_kind,omitempty"`
	Relation        string `json:"relation"`
	Method          string `json:"method"`
	ExecutionDigest string `json:"execution_digest"`
}

func (record NativeComparisonRecord) Validate() error {
	if record.SchemaVersion != NativeComparisonSchemaVersion {
		return fmt.Errorf("unsupported native comparison schema %q", record.SchemaVersion)
	}
	if strings.TrimSpace(record.ID) == "" || containsControlCharacter(record.ID) || strings.TrimSpace(record.TargetID) == "" || !validSHA256Digest(record.TargetDigest) {
		return fmt.Errorf("native comparison requires an id and target identity")
	}
	if record.PackageFamily != "deb" && record.PackageFamily != "rpm" {
		return fmt.Errorf("native comparison package family is invalid")
	}
	if strings.TrimSpace(record.PackageIdentity) == "" || containsControlCharacter(record.PackageIdentity) || strings.TrimSpace(record.CandidateEVR) == "" || strings.TrimSpace(record.FixedEVR) == "" || containsControlCharacter(record.CandidateEVR) || containsControlCharacter(record.FixedEVR) {
		return fmt.Errorf("native comparison requires an explicit package identity and exact EVRs")
	}
	switch record.PredicateKind {
	case "", NativePredicateEVRLessThan:
		// Empty is the immutable v2 encoding for the legacy EVR-less-than predicate.
	case NativePredicateVersionEqualsZero:
		if record.PackageFamily != "rpm" || record.FixedEVR != "0" {
			return fmt.Errorf("native zero-version predicate requires an RPM package and zero comparator value")
		}
	default:
		return fmt.Errorf("native comparison predicate kind is invalid")
	}
	if record.Relation != "before" && record.Relation != "equal" && record.Relation != "after" {
		return fmt.Errorf("native comparison relation is invalid")
	}
	if (record.PackageFamily == "deb" && record.Method != "target-native-dpkg") || (record.PackageFamily == "rpm" && record.Method != "target-native-rpm") {
		return fmt.Errorf("native comparison method is not valid for the package family")
	}
	if !validSHA256Digest(record.ExecutionDigest) {
		return fmt.Errorf("native comparison execution digest is invalid")
	}
	return nil
}

// PublicationArtifact is a compact committed identity. Raw bundles, scanner
// databases, caches, OCI layers, and raw scanner output are intentionally not
// valid publication artifact kinds.
type PublicationArtifact struct {
	Kind      string           `json:"kind"`
	Reference ContentReference `json:"reference"`
}

// PublicationControl is the trusted, immutable subset of a publication that
// exists before reduction. Generated outcome artifacts are added only after
// their bytes have been written, so the final manifest never contains a
// predicted digest.
type PublicationControl struct {
	SchemaVersion        string                `json:"schema_version"`
	ImplementationCommit string                `json:"implementation_commit"`
	Artifacts            []PublicationArtifact `json:"artifacts"`
}

func (control PublicationControl) Validate() error {
	if control.SchemaVersion != PublicationControlSchemaVersion {
		return fmt.Errorf("unsupported publication control schema %q", control.SchemaVersion)
	}
	if !validCommitSHA(control.ImplementationCommit) {
		return fmt.Errorf("publication control implementation commit is invalid")
	}
	required := map[string]struct{}{
		"source_snapshot": {}, "pin": {}, "sbom": {}, "normalized_observation": {}, "native_comparison": {}, "process_identity": {}, "ratchet": {},
	}
	seen := make(map[string]struct{}, len(control.Artifacts))
	for _, artifact := range control.Artifacts {
		if _, known := required[artifact.Kind]; !known {
			return fmt.Errorf("publication control has an unknown artifact kind %q", artifact.Kind)
		}
		if err := artifact.Reference.Validate(); err != nil {
			return fmt.Errorf("publication control artifact %q: %w", artifact.Kind, err)
		}
		key := artifact.Kind + "\x00" + artifact.Reference.Locator
		if _, exists := seen[key]; exists {
			return fmt.Errorf("publication control has a duplicate artifact %q", artifact.Reference.Locator)
		}
		seen[key] = struct{}{}
		delete(required, artifact.Kind)
	}
	if len(required) != 0 {
		missing := make([]string, 0, len(required))
		for kind := range required {
			missing = append(missing, kind)
		}
		sort.Strings(missing)
		return fmt.Errorf("publication control is missing required artifact kinds: %s", strings.Join(missing, ", "))
	}
	return nil
}

type RepetitionEvidence struct {
	Repetition int                      `json:"repetition"`
	Bundles    []BundleEvidenceIdentity `json:"bundles"`
}

// PublicationManifest is the single cycle-level publication manifest. It
// binds the final result to both repetitions' complete evidence identities.
type PublicationManifest struct {
	SchemaVersion        string                `json:"schema_version"`
	CycleID              string                `json:"cycle_id"`
	ImplementationCommit string                `json:"implementation_commit"`
	CyclePlanDigest      string                `json:"cycle_plan_digest"`
	CycleLedgerDigest    string                `json:"cycle_ledger_digest"`
	AccountableReview    AccountableReview     `json:"accountable_review"`
	Artifacts            []PublicationArtifact `json:"artifacts"`
	Repetitions          []RepetitionEvidence  `json:"repetitions"`
}

func (manifest PublicationManifest) Validate() error {
	if manifest.SchemaVersion != PublicationManifestSchemaVersion {
		return fmt.Errorf("unsupported publication manifest schema %q", manifest.SchemaVersion)
	}
	if err := validateCycleID(manifest.CycleID); err != nil {
		return err
	}
	if !validCommitSHA(manifest.ImplementationCommit) {
		return fmt.Errorf("publication manifest implementation commit is invalid")
	}
	if !validSHA256Digest(manifest.CyclePlanDigest) || !validSHA256Digest(manifest.CycleLedgerDigest) {
		return fmt.Errorf("publication manifest must bind cycle plan and ledger")
	}
	if err := manifest.AccountableReview.Validate(); err != nil {
		return fmt.Errorf("publication accountable review: %w", err)
	}
	if manifest.AccountableReview.CycleID != manifest.CycleID || manifest.AccountableReview.Decision != "approved" {
		return fmt.Errorf("publication requires a distinct explicit accountable approval")
	}
	if err := validatePublicationArtifacts(manifest.Artifacts); err != nil {
		return err
	}
	if len(manifest.Repetitions) == 0 {
		return fmt.Errorf("publication manifest requires repetition evidence")
	}
	seen := make(map[int]struct{}, len(manifest.Repetitions))
	for _, repetition := range manifest.Repetitions {
		if repetition.Repetition < 1 || len(repetition.Bundles) == 0 {
			return fmt.Errorf("publication repetition is incomplete")
		}
		if _, exists := seen[repetition.Repetition]; exists {
			return fmt.Errorf("publication has duplicate repetition %d", repetition.Repetition)
		}
		seen[repetition.Repetition] = struct{}{}
		bundleKeys := make(map[string]struct{}, len(repetition.Bundles))
		for _, identity := range repetition.Bundles {
			if err := identity.Validate(); err != nil {
				return fmt.Errorf("publication repetition %d: %w", repetition.Repetition, err)
			}
			key := cycleCellKey(identity.TargetID, identity.Engine)
			if _, exists := bundleKeys[key]; exists {
				return fmt.Errorf("publication repetition %d has duplicate bundle %q", repetition.Repetition, key)
			}
			bundleKeys[key] = struct{}{}
		}
	}
	return nil
}

func (manifest PublicationManifest) ValidateAgainstPlan(plan CyclePlan) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if manifest.CycleID != plan.CycleID {
		return fmt.Errorf("publication manifest belongs to a different cycle")
	}
	planDigest, err := DigestCyclePlan(plan)
	if err != nil {
		return err
	}
	if manifest.CyclePlanDigest != planDigest {
		return fmt.Errorf("publication manifest does not bind the cycle plan")
	}
	if len(manifest.Repetitions) != plan.Repetitions {
		return fmt.Errorf("publication must bind every planned repetition")
	}
	expected := make(map[string]struct{}, len(plan.Cells))
	for _, cell := range plan.Cells {
		expected[cycleCellKey(cell.TargetID, cell.Engine)] = struct{}{}
	}
	for _, repetition := range manifest.Repetitions {
		if repetition.Repetition > plan.Repetitions || len(repetition.Bundles) != len(expected) {
			return fmt.Errorf("publication repetition %d does not bind the full planned matrix", repetition.Repetition)
		}
		for _, identity := range repetition.Bundles {
			if _, exists := expected[cycleCellKey(identity.TargetID, identity.Engine)]; !exists {
				return fmt.Errorf("publication has an unplanned bundle identity")
			}
		}
	}
	return nil
}

// BuildPublicationManifest combines trusted pre-reduction controls with
// artifacts that were measured after finalization. The candidate evidence
// summary deliberately is not an artifact of this manifest: it commits this
// manifest's digest, and including it here would create a self-reference.
func BuildPublicationManifest(plan CyclePlan, ledger CycleLedger, review AccountableReview, control PublicationControl, generated []PublicationArtifact) (PublicationManifest, error) {
	if err := plan.Validate(); err != nil {
		return PublicationManifest{}, err
	}
	if err := ledger.ValidateAgainstPlan(plan); err != nil {
		return PublicationManifest{}, err
	}
	if err := review.Validate(); err != nil {
		return PublicationManifest{}, fmt.Errorf("validate accountable review: %w", err)
	}
	if review.CycleID != plan.CycleID || review.Decision != "approved" {
		return PublicationManifest{}, fmt.Errorf("publication requires an approved accountable review for the cycle")
	}
	reviewDigest, err := DigestAccountableReview(review)
	if err != nil {
		return PublicationManifest{}, err
	}
	if reviewDigest != plan.AccountableReviewDigest || review.FinalOracleDigest != plan.FinalOracleDigest {
		return PublicationManifest{}, fmt.Errorf("publication accountable review does not bind the planned final oracle")
	}
	if err := control.Validate(); err != nil {
		return PublicationManifest{}, err
	}
	generatedKinds := map[string]struct{}{
		"source_evidence": {}, "native_evidence": {}, "oracle_candidate": {}, "cross_check": {}, "adjudication": {}, "accountable_review": {}, "oracle_freeze": {}, "comparison": {}, "falsifier_result": {}, "result": {}, "report": {}, "ledger": {},
	}
	seenGenerated := make(map[string]struct{}, len(generated))
	for _, artifact := range generated {
		if _, known := generatedKinds[artifact.Kind]; !known {
			return PublicationManifest{}, fmt.Errorf("generated publication artifact has an unknown kind %q", artifact.Kind)
		}
		if _, exists := seenGenerated[artifact.Kind]; exists {
			return PublicationManifest{}, fmt.Errorf("generated publication artifact kind %q is duplicated", artifact.Kind)
		}
		if err := artifact.Reference.Validate(); err != nil {
			return PublicationManifest{}, fmt.Errorf("generated publication artifact %q: %w", artifact.Kind, err)
		}
		seenGenerated[artifact.Kind] = struct{}{}
	}
	if len(seenGenerated) != len(generatedKinds) {
		missing := make([]string, 0, len(generatedKinds)-len(seenGenerated))
		for kind := range generatedKinds {
			if _, exists := seenGenerated[kind]; !exists {
				missing = append(missing, kind)
			}
		}
		sort.Strings(missing)
		return PublicationManifest{}, fmt.Errorf("publication is missing generated artifact kinds: %s", strings.Join(missing, ", "))
	}
	planDigest, err := DigestCyclePlan(plan)
	if err != nil {
		return PublicationManifest{}, err
	}
	ledgerDigest, err := DigestCycleLedger(ledger)
	if err != nil {
		return PublicationManifest{}, err
	}
	slots := make(map[string]CycleSlot, len(ledger.Slots))
	for _, slot := range ledger.Slots {
		slots[cycleSlotKey(slot.Repetition, slot.TargetID, slot.Engine)] = slot
	}
	repetitions := make([]RepetitionEvidence, 0, plan.Repetitions)
	for repetition := 1; repetition <= plan.Repetitions; repetition++ {
		bundles := make([]BundleEvidenceIdentity, 0, len(plan.Cells))
		for _, cell := range plan.Cells {
			slot := slots[cycleSlotKey(repetition, cell.TargetID, cell.Engine)]
			accepted := latestCycleAttempt(slot.Attempts)
			if accepted.EvidenceIdentity == nil {
				return PublicationManifest{}, fmt.Errorf("cycle slot %q has no accepted evidence identity", cycleSlotKey(repetition, cell.TargetID, cell.Engine))
			}
			bundles = append(bundles, *accepted.EvidenceIdentity)
		}
		sort.Slice(bundles, func(left, right int) bool {
			return cycleCellKey(bundles[left].TargetID, bundles[left].Engine) < cycleCellKey(bundles[right].TargetID, bundles[right].Engine)
		})
		repetitions = append(repetitions, RepetitionEvidence{Repetition: repetition, Bundles: bundles})
	}
	artifacts := make([]PublicationArtifact, 0, len(control.Artifacts)+len(generated))
	artifacts = append(artifacts, control.Artifacts...)
	artifacts = append(artifacts, generated...)
	sort.Slice(artifacts, func(left, right int) bool {
		if artifacts[left].Kind != artifacts[right].Kind {
			return artifacts[left].Kind < artifacts[right].Kind
		}
		return artifacts[left].Reference.Locator < artifacts[right].Reference.Locator
	})
	manifest := PublicationManifest{
		SchemaVersion: PublicationManifestSchemaVersion, CycleID: plan.CycleID,
		ImplementationCommit: control.ImplementationCommit, CyclePlanDigest: planDigest,
		CycleLedgerDigest: ledgerDigest, AccountableReview: review, Artifacts: artifacts,
		Repetitions: repetitions,
	}
	if err := manifest.ValidateAgainstPlan(plan); err != nil {
		return PublicationManifest{}, err
	}
	return manifest, nil
}

func validatePublicationArtifacts(artifacts []PublicationArtifact) error {
	if len(artifacts) == 0 {
		return fmt.Errorf("publication manifest requires committed artifacts")
	}
	required := map[string]struct{}{
		"source_snapshot": {}, "pin": {}, "sbom": {}, "source_evidence": {}, "native_evidence": {}, "oracle_candidate": {}, "cross_check": {}, "adjudication": {}, "accountable_review": {}, "oracle_freeze": {}, "normalized_observation": {}, "native_comparison": {}, "process_identity": {}, "comparison": {}, "falsifier_result": {}, "result": {}, "ratchet": {}, "report": {}, "ledger": {},
	}
	forbidden := map[string]struct{}{
		"raw_bundle": {}, "raw_scanner_output": {}, "scanner_database": {}, "scanner_cache": {}, "oci_layer": {}, "corrupt_tree": {},
	}
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if _, invalid := forbidden[artifact.Kind]; invalid {
			return fmt.Errorf("publication manifest cannot commit %q", artifact.Kind)
		}
		if _, known := required[artifact.Kind]; !known {
			return fmt.Errorf("publication manifest has an unknown artifact kind %q", artifact.Kind)
		}
		if err := artifact.Reference.Validate(); err != nil {
			return fmt.Errorf("publication artifact %q: %w", artifact.Kind, err)
		}
		key := artifact.Kind + "\x00" + artifact.Reference.Locator
		if _, exists := seen[key]; exists {
			return fmt.Errorf("publication manifest has a duplicate artifact %q", artifact.Reference.Locator)
		}
		seen[key] = struct{}{}
		delete(required, artifact.Kind)
	}
	if len(required) != 0 {
		missing := make([]string, 0, len(required))
		for kind := range required {
			missing = append(missing, kind)
		}
		sort.Strings(missing)
		return fmt.Errorf("publication manifest is missing required artifact kinds: %s", strings.Join(missing, ", "))
	}
	return nil
}

// FalsifierSpec declares deterministic, executable semantic-comparison tests.
// It intentionally stores an expected outcome, not a pass boolean.
type FalsifierSpec struct {
	SchemaVersion string           `json:"schema_version"`
	Entries       []FalsifierEntry `json:"entries"`
}

type FalsifierEntry struct {
	ID              string `json:"id"`
	Capability      string `json:"capability"`
	Engine          Engine `json:"engine"`
	Baseline        string `json:"baseline"`
	Mutation        string `json:"mutation"`
	ExpectedOutcome string `json:"expected_outcome"`
	Operation       string `json:"operation"`
}

func (spec FalsifierSpec) Validate() error {
	if spec.SchemaVersion != FalsifierSpecSchemaVersion {
		return fmt.Errorf("unsupported falsifier spec schema %q", spec.SchemaVersion)
	}
	if len(spec.Entries) == 0 {
		return fmt.Errorf("falsifier spec requires entries")
	}
	seen := make(map[string]struct{}, len(spec.Entries))
	for _, entry := range spec.Entries {
		if strings.TrimSpace(entry.ID) == "" || containsControlCharacter(entry.ID) {
			return fmt.Errorf("falsifier entry requires an id")
		}
		if _, exists := seen[entry.ID]; exists {
			return fmt.Errorf("falsifier spec has duplicate id %q", entry.ID)
		}
		seen[entry.ID] = struct{}{}
		if strings.TrimSpace(entry.Capability) == "" || !knownCycleEngine(entry.Engine) || strings.TrimSpace(entry.Baseline) == "" || strings.TrimSpace(entry.Mutation) == "" {
			return fmt.Errorf("falsifier %q is incomplete", entry.ID)
		}
		if entry.ExpectedOutcome != "accepted" && entry.ExpectedOutcome != "rejected" {
			return fmt.Errorf("falsifier %q has an invalid expected outcome", entry.ID)
		}
		if entry.Operation != "semantic_bundle_comparator" {
			return fmt.Errorf("falsifier %q has an invalid operation", entry.ID)
		}
	}
	return nil
}

func DigestContentReferences(references []ContentReference) (string, error) {
	copyReferences := append([]ContentReference(nil), references...)
	sort.Slice(copyReferences, func(left, right int) bool { return copyReferences[left].Locator < copyReferences[right].Locator })
	for _, reference := range copyReferences {
		if err := reference.Validate(); err != nil {
			return "", err
		}
	}
	encoded, err := CanonicalJSON(copyReferences)
	if err != nil {
		return "", fmt.Errorf("encode content references: %w", err)
	}
	return SHA256Digest(encoded), nil
}

// DigestSourceFreeze returns the canonical identity used to bind a candidate and plan.
func DigestSourceFreeze(freeze SourceFreeze) (string, error) {
	if err := freeze.Validate(); err != nil {
		return "", err
	}
	copyFreeze := freeze
	copyFreeze.Assets = append([]ContentReference(nil), freeze.Assets...)
	sort.Slice(copyFreeze.Assets, func(left, right int) bool { return copyFreeze.Assets[left].Locator < copyFreeze.Assets[right].Locator })
	encoded, err := CanonicalJSON(copyFreeze)
	if err != nil {
		return "", fmt.Errorf("encode source freeze: %w", err)
	}
	return SHA256Digest(encoded), nil
}

// DigestOracleCandidate returns the scanner-free candidate identity.
func DigestOracleCandidate(candidate OracleCandidate) (string, error) {
	if err := candidate.Validate(); err != nil {
		return "", err
	}
	copyCandidate := candidate
	copyCandidate.Cases = append([]OracleCandidateCase(nil), candidate.Cases...)
	sort.Slice(copyCandidate.Cases, func(left, right int) bool { return copyCandidate.Cases[left].ID < copyCandidate.Cases[right].ID })
	for index := range copyCandidate.Cases {
		copyCandidate.Cases[index].Citations = append([]ContentReference(nil), copyCandidate.Cases[index].Citations...)
		sort.Slice(copyCandidate.Cases[index].Citations, func(left, right int) bool {
			return copyCandidate.Cases[index].Citations[left].Locator < copyCandidate.Cases[index].Citations[right].Locator
		})
	}
	encoded, err := CanonicalJSON(copyCandidate)
	if err != nil {
		return "", fmt.Errorf("encode oracle candidate: %w", err)
	}
	return SHA256Digest(encoded), nil
}

func DigestAutomatedCrossCheck(check AutomatedCrossCheck) (string, error) {
	if err := check.Validate(); err != nil {
		return "", err
	}
	copyCheck := check
	copyCheck.Cases = append([]CrossCheckCase(nil), check.Cases...)
	sort.Slice(copyCheck.Cases, func(left, right int) bool { return copyCheck.Cases[left].ID < copyCheck.Cases[right].ID })
	encoded, err := CanonicalJSON(copyCheck)
	if err != nil {
		return "", fmt.Errorf("encode automated cross-check: %w", err)
	}
	return SHA256Digest(encoded), nil
}

func DigestAdjudicationRecord(record AdjudicationRecord) (string, error) {
	if err := record.Validate(); err != nil {
		return "", err
	}
	encoded, err := CanonicalJSON(record)
	if err != nil {
		return "", fmt.Errorf("encode adjudication record: %w", err)
	}
	return SHA256Digest(encoded), nil
}

func DigestAccountableReview(review AccountableReview) (string, error) {
	if err := review.Validate(); err != nil {
		return "", err
	}
	encoded, err := CanonicalJSON(review)
	if err != nil {
		return "", fmt.Errorf("encode accountable review: %w", err)
	}
	return SHA256Digest(encoded), nil
}

func DigestFinalOracleFreeze(freeze FinalOracleFreeze) (string, error) {
	if err := freeze.Validate(); err != nil {
		return "", err
	}
	encoded, err := CanonicalJSON(freeze)
	if err != nil {
		return "", fmt.Errorf("encode final oracle freeze: %w", err)
	}
	return SHA256Digest(encoded), nil
}

// ValidateCycleInputs proves the complete scanner-free oracle gate is resolved
// and frozen before any capture runner may be constructed.
func ValidateCycleInputs(plan CyclePlan, freeze SourceFreeze, candidate OracleCandidate, crossCheck AutomatedCrossCheck, adjudication AdjudicationRecord, review AccountableReview, finalOracle FinalOracleFreeze) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := freeze.Validate(); err != nil {
		return err
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	if err := crossCheck.Validate(); err != nil {
		return err
	}
	if err := adjudication.Validate(); err != nil {
		return err
	}
	if err := review.Validate(); err != nil {
		return err
	}
	if err := finalOracle.Validate(); err != nil {
		return err
	}
	if review.Decision != "approved" || adjudication.Status != "resolved" || crossCheck.Status != "passed" {
		return fmt.Errorf("cycle capture requires passed cross-check, resolved adjudication, and explicit accountable approval")
	}
	if plan.CycleID != freeze.CycleID || plan.CycleID != candidate.CycleID || plan.CycleID != crossCheck.CycleID || plan.CycleID != adjudication.CycleID || plan.CycleID != review.CycleID || plan.CycleID != finalOracle.CycleID {
		return fmt.Errorf("cycle inputs belong to different cycles")
	}
	freezeDigest, err := DigestSourceFreeze(freeze)
	if err != nil {
		return err
	}
	candidateDigest, err := DigestOracleCandidate(candidate)
	if err != nil {
		return err
	}
	crossCheckDigest, err := DigestAutomatedCrossCheck(crossCheck)
	if err != nil {
		return err
	}
	adjudicationDigest, err := DigestAdjudicationRecord(adjudication)
	if err != nil {
		return err
	}
	reviewDigest, err := DigestAccountableReview(review)
	if err != nil {
		return err
	}
	if candidate.SourceFreezeDigest != freezeDigest || crossCheck.OracleCandidateDigest != candidateDigest || adjudication.OracleCandidateDigest != candidateDigest || adjudication.CrossCheckDigest != crossCheckDigest || review.AdjudicationDigest != adjudicationDigest {
		return fmt.Errorf("cycle oracle records do not form a bound scanner-free chain")
	}
	if finalOracle.SourceFreezeDigest != freezeDigest || finalOracle.OracleCandidateDigest != candidateDigest || finalOracle.CrossCheckDigest != crossCheckDigest || finalOracle.AdjudicationDigest != adjudicationDigest || finalOracle.AccountableReviewDigest != reviewDigest || review.FinalOracleDigest != finalOracle.OracleDigest {
		return fmt.Errorf("final oracle freeze does not bind the scanner-free chain and exact accountable decision")
	}
	if plan.SourceFreezeDigest != freezeDigest || plan.OracleCandidateDigest != candidateDigest || plan.CrossCheckDigest != crossCheckDigest || plan.AdjudicationDigest != adjudicationDigest || plan.AccountableReviewDigest != reviewDigest || plan.FinalOracleDigest != finalOracle.OracleDigest {
		return fmt.Errorf("cycle plan does not bind the complete final oracle gate")
	}
	return nil
}

func DigestCyclePlan(plan CyclePlan) (string, error) {
	copyPlan := plan
	copyPlan.Cells = append([]CycleCell(nil), plan.Cells...)
	sort.Slice(copyPlan.Cells, func(left, right int) bool {
		return cycleCellKey(copyPlan.Cells[left].TargetID, copyPlan.Cells[left].Engine) < cycleCellKey(copyPlan.Cells[right].TargetID, copyPlan.Cells[right].Engine)
	})
	if err := copyPlan.Validate(); err != nil {
		return "", err
	}
	encoded, err := CanonicalJSON(copyPlan)
	if err != nil {
		return "", fmt.Errorf("encode cycle plan: %w", err)
	}
	return SHA256Digest(encoded), nil
}

func DigestCycleLedger(ledger CycleLedger) (string, error) {
	if err := ledger.validateBasic(); err != nil {
		return "", err
	}
	copyLedger := ledger
	copyLedger.Slots = append([]CycleSlot(nil), ledger.Slots...)
	sort.Slice(copyLedger.Slots, func(left, right int) bool {
		return cycleSlotKey(copyLedger.Slots[left].Repetition, copyLedger.Slots[left].TargetID, copyLedger.Slots[left].Engine) < cycleSlotKey(copyLedger.Slots[right].Repetition, copyLedger.Slots[right].TargetID, copyLedger.Slots[right].Engine)
	})
	for index := range copyLedger.Slots {
		copyLedger.Slots[index].Attempts = append([]CycleAttempt(nil), copyLedger.Slots[index].Attempts...)
		sort.Slice(copyLedger.Slots[index].Attempts, func(left, right int) bool {
			return copyLedger.Slots[index].Attempts[left].Sequence < copyLedger.Slots[index].Attempts[right].Sequence
		})
	}
	encoded, err := CanonicalJSON(copyLedger)
	if err != nil {
		return "", fmt.Errorf("encode cycle ledger: %w", err)
	}
	return SHA256Digest(encoded), nil
}

// DigestNativeComparisonRecord returns the identity bound into cycle evidence.
func DigestNativeComparisonRecord(record NativeComparisonRecord) (string, error) {
	if err := record.Validate(); err != nil {
		return "", err
	}
	encoded, err := CanonicalJSON(record)
	if err != nil {
		return "", fmt.Errorf("encode native comparison record: %w", err)
	}
	return SHA256Digest(encoded), nil
}

// DigestPublicationManifest returns the identity published alongside a result.
// It includes raw evidence identities even though numeric scoring is normalized.
func DigestPublicationManifest(manifest PublicationManifest) (string, error) {
	if err := manifest.Validate(); err != nil {
		return "", err
	}
	copyManifest := manifest
	copyManifest.Artifacts = append([]PublicationArtifact(nil), manifest.Artifacts...)
	sort.Slice(copyManifest.Artifacts, func(left, right int) bool {
		if copyManifest.Artifacts[left].Kind != copyManifest.Artifacts[right].Kind {
			return copyManifest.Artifacts[left].Kind < copyManifest.Artifacts[right].Kind
		}
		return copyManifest.Artifacts[left].Reference.Locator < copyManifest.Artifacts[right].Reference.Locator
	})
	copyManifest.Repetitions = append([]RepetitionEvidence(nil), manifest.Repetitions...)
	sort.Slice(copyManifest.Repetitions, func(left, right int) bool {
		return copyManifest.Repetitions[left].Repetition < copyManifest.Repetitions[right].Repetition
	})
	for index := range copyManifest.Repetitions {
		copyManifest.Repetitions[index].Bundles = append([]BundleEvidenceIdentity(nil), copyManifest.Repetitions[index].Bundles...)
		sort.Slice(copyManifest.Repetitions[index].Bundles, func(left, right int) bool {
			return cycleCellKey(copyManifest.Repetitions[index].Bundles[left].TargetID, copyManifest.Repetitions[index].Bundles[left].Engine) < cycleCellKey(copyManifest.Repetitions[index].Bundles[right].TargetID, copyManifest.Repetitions[index].Bundles[right].Engine)
		})
	}
	encoded, err := CanonicalJSON(copyManifest)
	if err != nil {
		return "", fmt.Errorf("encode publication manifest: %w", err)
	}
	return SHA256Digest(encoded), nil
}

func validateCycleID(value string) error {
	if strings.TrimSpace(value) == "" || containsControlCharacter(value) {
		return fmt.Errorf("cycle id is required")
	}
	return nil
}

func validCommitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validateRepositoryLocator(locator string) error {
	if strings.TrimSpace(locator) == "" || containsControlCharacter(locator) || strings.HasPrefix(strings.ToLower(locator), "file:") {
		return fmt.Errorf("repository locator is invalid")
	}
	if strings.Contains(locator, "\\") || strings.HasPrefix(locator, "/") || strings.HasPrefix(locator, "//") || strings.Contains(locator, ":") {
		return fmt.Errorf("repository locator must be repository-relative")
	}
	segments := strings.Split(locator, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("repository locator has an invalid path segment")
		}
	}
	return nil
}

func knownCycleEngine(engine Engine) bool {
	for _, known := range Engines() {
		if engine == known {
			return true
		}
	}
	return false
}

func cycleCellKey(target string, engine Engine) string {
	return target + "\x00" + string(engine)
}

func cycleSlotKey(repetition int, target string, engine Engine) string {
	return fmt.Sprintf("%d\x00%s", repetition, cycleCellKey(target, engine))
}

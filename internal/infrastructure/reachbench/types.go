// Package reachbench runs the trusted reachability measurement lifecycle.
package reachbench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const (
	LifecycleSchemaVersion         = "synapse-reachability-lifecycle-v1"
	EnvelopeSchemaVersion          = "synapse-reachability-run-envelope-v1"
	BundleSchemaVersion            = "synapse-reachability-trusted-bundle-v1"
	RepeatSchemaVersion            = "synapse-reachability-repeat-result-v1"
	ArtifactSchemaVersion          = "synapse-reachability-artifact-manifest-v1"
	BaselineAllowlistSchemaVersion = "synapse-reachability-baseline-allowlist-v1"
	BaselineAllowlistResultVersion = "synapse-reachability-baseline-allowlist-result-v1"

	ControllerEnvelopeEnvironment = "SYNAPSE_REACHABILITY_CONTROLLER_ENVELOPE"
	TrustedBundleRelativePath     = "internal/usecase/reachbench/trusted"
	controllerRootDirectory       = "synapse-reachability-controller"
	controllerEnvelopeDirectory   = controllerRootDirectory + "/envelopes"
	controllerBundleDirectory     = controllerRootDirectory + "/trusted-bundle"
	privateRunDirectory           = "synapse-reachability/private"
	publishedRunDirectory         = "synapse-reachability/published"

	ReviewedHarnessID = "synapse-reachability-cycle-v1"
	AnalyzerSubjectID = "synapse-reachability-analyzer"

	// maxCells is the publication-safe end-to-end lifecycle bound, not the
	// generic two-pass executor limit. Each accepted cell is budgeted across
	// the canonical input, report, lifecycle, and repeat documents so every
	// published JSON artifact remains below benchmark.MaxJSONBytes.
	maxCells                          = 512
	maxPublishedCellBytes       int64 = 12 << 10
	publicationDocumentReserve  int64 = 2 << 20
	maxRawEvidenceArtifactBytes int64 = 1 << 20
	maxRawEvidenceTotalBytes    int64 = 512 << 20
	maxRawEvidenceFiles               = maxCells * fixedRepetitions
	maxArtifactFiles                  = 32
	maxIdentifierBytes                = 160
)

// Route names the closed lifecycle ingress. A route is not authority by itself.
type Route string

const (
	RouteProtectedBaseline Route = "protected_baseline"
	RouteCandidate         Route = "candidate"
	RouteLocalDiagnostic   Route = "local_diagnostic"
)

// FinalMode records how a completed measurement can be used. It is independent of its transport.
type FinalMode string

const (
	FinalBaseline   FinalMode = "baseline"
	FinalAcceptance FinalMode = "acceptance"
	FinalDiagnostic FinalMode = "diagnostic"
)

// RevisionIdentity binds a source subject to independent commit and Git-tree identities.
type RevisionIdentity struct {
	ID     string `json:"id"`
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
}

// HarnessIdentity identifies the lifecycle evaluator separately from the analyzer source subject.
type HarnessIdentity struct {
	ID     string `json:"id"`
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
}

// ProceduralAuthority records the controller's reviewed procedure. It intentionally does not claim GitHub-origin authority.
type ProceduralAuthority struct {
	Class                     string                        `json:"class"`
	Controller                string                        `json:"controller"`
	ReviewEvidence            measurement.ArtifactReference `json:"review_evidence"`
	GitHubOriginAuthenticated bool                          `json:"github_origin_authenticated"`
	ReviewedHarness           bool                          `json:"reviewed_harness"`
	ReviewedHarnessID         string                        `json:"reviewed_harness_id"`
}

// BundleAsset is a fixed regular file within the trusted bundle.
type BundleAsset struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// TrustedBundle identifies route-owned contract templates and reviewed baseline evidence. It carries no scores or authority claim.
type TrustedBundle struct {
	SchemaVersion     string       `json:"schema_version"`
	ID                string       `json:"id"`
	BaselineInput     BundleAsset  `json:"baseline_input"`
	CandidateInput    *BundleAsset `json:"candidate_input,omitempty"`
	BaselineAllowlist BundleAsset  `json:"baseline_allowlist"`
}

// BaselineAllowlistEntry is one exact permitted harness change.
type BaselineAllowlistEntry struct {
	Status string `json:"status"`
	Path   string `json:"path"`
}

// BaselineAllowlist is the reviewed, exact harness-only delta permitted for a protected baseline.
type BaselineAllowlist struct {
	SchemaVersion string                   `json:"schema_version"`
	ID            string                   `json:"id"`
	Entries       []BaselineAllowlistEntry `json:"entries"`
}

// BaselineAllowlistResult binds an allowed baseline delta without publishing raw or absolute paths.
type BaselineAllowlistResult struct {
	SchemaVersion      string                        `json:"schema_version"`
	Allowlist          measurement.ArtifactReference `json:"allowlist"`
	Harness            HarnessIdentity               `json:"harness"`
	Analyzer           RevisionIdentity              `json:"analyzer"`
	ChangedEntryCount  int                           `json:"changed_entry_count"`
	ChangedEntryDigest string                        `json:"changed_entry_digest"`
}

// RunEnvelope is controller execution provenance, not an alternative measurement contract.
type RunEnvelope struct {
	SchemaVersion string                        `json:"schema_version"`
	Route         Route                         `json:"route"`
	Purpose       measurement.RunPurpose        `json:"purpose"`
	FinalMode     FinalMode                     `json:"final_mode"`
	Harness       HarnessIdentity               `json:"harness"`
	Analyzer      RevisionIdentity              `json:"analyzer"`
	Snapshot      measurement.SnapshotIdentity  `json:"snapshot"`
	Bundle        measurement.ArtifactReference `json:"bundle"`
	Authority     ProceduralAuthority           `json:"authority"`
}

// ExecutionCell is one required corpus/binding measurement; it cannot be substituted by no_analysis.
type ExecutionCell struct {
	CaseID        string                        `json:"case_id"`
	CohortID      string                        `json:"cohort_id"`
	ModeID        string                        `json:"mode_id"`
	BindingID     string                        `json:"binding_id"`
	AnalyzerID    string                        `json:"analyzer_id"`
	Configuration measurement.ArtifactReference `json:"configuration"`
	SubjectID     string                        `json:"subject_id"`
	Fixture       measurement.ArtifactReference `json:"fixture"`
	BoundaryID    string                        `json:"boundary_id"`
}

// CaptureRequest is the narrow production-boundary input. The callback reports output derived at the publication boundary.
type CaptureRequest struct {
	Repetition int                          `json:"repetition"`
	Cell       ExecutionCell                `json:"cell"`
	Analyzer   RevisionIdentity             `json:"analyzer"`
	Snapshot   measurement.SnapshotIdentity `json:"snapshot"`
	WorkRoot   string                       `json:"-"`

	profile                      measurement.ReachabilityProfile
	attempt                      benchcycle.AttemptAddress
	evidence                     *benchcycle.EvidenceStore
	projectionConformanceControl bool
}

// StoreRawEvidence streams the attempt's single raw capture artifact to private storage.
func (request CaptureRequest) StoreRawEvidence(ctx context.Context, source io.Reader) (benchcycle.EvidenceReceipt, error) {
	if request.evidence == nil {
		return benchcycle.EvidenceReceipt{}, errors.New("reachability evidence store is unavailable")
	}
	return request.evidence.Write(ctx, request.attempt, "capture.raw", source)
}

// CaptureResult contains a measured production output and only bounded private-evidence receipts.
// Suppression.Effects and each proof's MissingProvenance must describe the actual derived output; callers must not
// infer absence of an effect or provenance from a proof-generation event.
type CaptureResult struct {
	Observation            measurement.MeasuredObservation          `json:"observation"`
	EvidenceReceipts       []benchcycle.EvidenceReceipt             `json:"-"`
	SuppressionConformance *SuppressionProjectionConformanceControl `json:"-"`
}

// CaptureAdapter is implemented later by package-local adapters at the actual output authority.
type CaptureAdapter interface {
	Capture(context.Context, CaptureRequest) (CaptureResult, error)
}

// CommandRunner executes a fixed argv vector. Implementations must not invoke a shell.
type CommandRunner func(context.Context, string, ...string) ([]byte, error)

// Environment looks up process state without making identity a CLI surface.
type Environment func(string) (string, bool)

// Dependencies make command, environment, and filesystem roots deterministic in focused tests.
type Dependencies struct {
	Command        CommandRunner
	Environment    Environment
	TempRoot       func() string
	RandomSegment  func() (string, error)
	RuntimeCleanup func(context.Context) error
}

// Runner owns the lifecycle orchestration and no production analyzer implementation.
type Runner struct {
	dependencies Dependencies
	capture      CaptureAdapter
}

// Result is intentionally small: callers receive only sanitized bundle identity, not raw evidence paths.
type Result struct {
	RunKey        string
	Authoritative bool
	Output        string
	Manifest      LifecycleManifest
}

// LifecycleManifest is the public execution provenance and bound output summary.
type LifecycleManifest struct {
	SchemaVersion          string                        `json:"schema_version"`
	Route                  Route                         `json:"route"`
	Purpose                measurement.RunPurpose        `json:"purpose"`
	FinalMode              FinalMode                     `json:"final_mode"`
	Authoritative          bool                          `json:"authoritative"`
	Harness                HarnessIdentity               `json:"harness"`
	Analyzer               RevisionIdentity              `json:"analyzer"`
	Authority              ProceduralAuthority           `json:"authority"`
	Snapshot               measurement.SnapshotIdentity  `json:"snapshot"`
	Bundle                 measurement.ArtifactReference `json:"bundle"`
	BaselineAllowlist      *BaselineAllowlistResult      `json:"baseline_allowlist,omitempty"`
	RunKey                 string                        `json:"run_key"`
	Repetitions            int                           `json:"repetitions"`
	Cells                  []ExecutionCell               `json:"cells"`
	ReportIDs              []string                      `json:"report_ids"`
	SuppressionConformance []PublishedArtifact           `json:"suppression_projection_conformance,omitempty"`
}

// SemanticRepeatResult binds the two canonical capture projections and reports.
type SemanticRepeatResult struct {
	SchemaVersion          string                        `json:"schema_version"`
	Repetitions            int                           `json:"repetitions"`
	SemanticallyEqual      bool                          `json:"semantically_equal"`
	ReportIDs              []string                      `json:"report_ids"`
	Cells                  []CellRepeatDigest            `json:"cells"`
	SuppressionConformance *SuppressionConformanceRepeat `json:"suppression_projection_conformance,omitempty"`
}

// CellRepeatDigest contains no raw evidence or runtime filesystem location.
type CellRepeatDigest struct {
	CaseID           string `json:"case_id"`
	BindingID        string `json:"binding_id"`
	ProjectionDigest string `json:"projection_digest"`
}

// PublishedArtifact is an exact, relative file-to-digest entry in the sanitized output.
type PublishedArtifact struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// ArtifactManifest lists every published content file other than itself, which cannot hash itself without a cycle.
type ArtifactManifest struct {
	SchemaVersion string              `json:"schema_version"`
	Files         []PublishedArtifact `json:"files"`
}

func NewRunner(dependencies Dependencies, capture CaptureAdapter) (*Runner, error) {
	if capture == nil {
		return nil, errors.New("reachability capture adapter is required")
	}
	if dependencies.Command == nil {
		return nil, errors.New("reachability command runner is required")
	}
	if dependencies.Environment == nil {
		return nil, errors.New("reachability environment lookup is required")
	}
	if dependencies.TempRoot == nil {
		return nil, errors.New("reachability temporary root is required")
	}
	if dependencies.RandomSegment == nil {
		return nil, errors.New("reachability local run-key generator is required")
	}
	return &Runner{dependencies: dependencies, capture: capture}, nil
}

func (route Route) authoritative() bool {
	return route == RouteProtectedBaseline || route == RouteCandidate
}

func (envelope RunEnvelope) Validate() error {
	if envelope.SchemaVersion != EnvelopeSchemaVersion {
		return errors.New("unsupported reachability run envelope")
	}
	if err := validateHarness(envelope.Harness); err != nil {
		return fmt.Errorf("envelope harness: %w", err)
	}
	if err := validateRevision(envelope.Analyzer); err != nil {
		return fmt.Errorf("envelope analyzer: %w", err)
	}
	if envelope.Harness.ID == envelope.Analyzer.ID {
		return errors.New("harness and analyzer subject identities must remain separate")
	}
	if err := envelope.Snapshot.Validate(); err != nil {
		return fmt.Errorf("envelope snapshot: %w", err)
	}
	if err := validateArtifact(envelope.Bundle); err != nil {
		return fmt.Errorf("envelope bundle: %w", err)
	}
	if err := envelope.Authority.Validate(); err != nil {
		return err
	}
	switch envelope.Route {
	case RouteProtectedBaseline:
		if envelope.Purpose != measurement.BaselineMeasurement || envelope.FinalMode != FinalBaseline || envelope.Analyzer.ID != AnalyzerSubjectID || envelope.Analyzer.Commit != measurement.TrustedBaselineRevision {
			return errors.New("protected baseline route requires the trusted analyzer identity")
		}
	case RouteCandidate:
		if envelope.Purpose != measurement.CandidateAcceptance || envelope.FinalMode != FinalAcceptance || envelope.Analyzer.ID != AnalyzerSubjectID {
			return errors.New("candidate route has an invalid purpose, final mode, or analyzer identity")
		}
	default:
		return errors.New("unknown reachability lifecycle route")
	}
	return nil
}

func (authority ProceduralAuthority) Validate() error {
	if authority.GitHubOriginAuthenticated {
		return errors.New("GitHub origin authentication is not lifecycle authority")
	}
	if authority.Class != "procedural" || !bounded(authority.Controller) || validateArtifact(authority.ReviewEvidence) != nil || !authority.ReviewedHarness || authority.ReviewedHarnessID != ReviewedHarnessID {
		return errors.New("authoritative route requires the identified reviewed harness procedure")
	}
	return nil
}

func (bundle TrustedBundle) Validate() error {
	if bundle.SchemaVersion != BundleSchemaVersion || !bounded(bundle.ID) {
		return errors.New("unsupported trusted reachability bundle")
	}
	if err := bundle.BaselineInput.validate("baseline-input.json"); err != nil {
		return err
	}
	if err := bundle.BaselineAllowlist.validate("baseline-allowlist.json"); err != nil {
		return err
	}
	if bundle.CandidateInput != nil {
		if err := bundle.CandidateInput.validate("candidate-input.json"); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRoute requires only the trusted assets that the selected lifecycle
// route can consume. A protected baseline intentionally has no candidate asset.
func (bundle TrustedBundle) ValidateRoute(route Route) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	switch route {
	case RouteProtectedBaseline:
		return nil
	case RouteCandidate, RouteLocalDiagnostic:
		if bundle.CandidateInput == nil {
			return errors.New("candidate route requires a trusted candidate input asset")
		}
		return bundle.CandidateInput.validate("candidate-input.json")
	default:
		return errors.New("unknown reachability lifecycle route")
	}
}

func (allowlist BaselineAllowlist) Validate() error {
	if allowlist.SchemaVersion != BaselineAllowlistSchemaVersion || !bounded(allowlist.ID) || len(allowlist.Entries) == 0 || len(allowlist.Entries) > maxCells {
		return errors.New("invalid baseline allowlist")
	}
	previousPath := ""
	for _, entry := range allowlist.Entries {
		if !validBaselineChangeStatus(entry.Status) || !safeHarnessPath(entry.Path) || entry.Path <= previousPath {
			return errors.New("baseline allowlist contains an unsafe, duplicate, unsorted, or unsupported change entry")
		}
		previousPath = entry.Path
	}
	return nil
}

func (result BaselineAllowlistResult) Validate() error {
	if result.SchemaVersion != BaselineAllowlistResultVersion || validateArtifact(result.Allowlist) != nil || validateHarness(result.Harness) != nil || validateRevision(result.Analyzer) != nil || result.Harness.ID == result.Analyzer.ID || result.ChangedEntryCount < 1 || result.ChangedEntryCount > maxCells || !validDigest(result.ChangedEntryDigest) {
		return errors.New("invalid baseline allowlist result")
	}
	if result.Analyzer.ID != AnalyzerSubjectID || result.Analyzer.Commit != measurement.TrustedBaselineRevision {
		return errors.New("baseline allowlist result does not bind the trusted analyzer")
	}
	return nil
}

func validBaselineChangeStatus(status string) bool {
	return status == "A" || status == "M"
}

func baselineAllowlistEntryKey(entry BaselineAllowlistEntry) string {
	return entry.Path + "\x00" + entry.Status
}

func (asset BundleAsset) validate(expectedPath string) error {
	if asset.Path != expectedPath || !validDigest(asset.Digest) {
		return fmt.Errorf("trusted bundle asset %q is invalid", expectedPath)
	}
	return nil
}

func validateHarness(identity HarnessIdentity) error {
	if !bounded(identity.ID) || !benchcycle.FullSHA(identity.Commit) || !benchcycle.FullSHA(identity.Tree) {
		return errors.New("harness identity must have a bounded ID and lowercase full commit and tree SHAs")
	}
	return nil
}

func validateRevision(identity RevisionIdentity) error {
	if !bounded(identity.ID) || !benchcycle.FullSHA(identity.Commit) || !benchcycle.FullSHA(identity.Tree) {
		return errors.New("analyzer identity must have a bounded ID and lowercase full commit and tree SHAs")
	}
	return nil
}

func safeHarnessPath(path string) bool {
	if !fs.ValidPath(path) || !utf8.ValidString(path) || strings.Contains(path, "\\") || strings.TrimSpace(path) != path {
		return false
	}
	for _, item := range path {
		if unicode.IsControl(item) {
			return false
		}
	}
	for _, component := range strings.Split(path, "/") {
		if component == ".git" || component == ".claude" || component == ".serena" || component == "CLAUDE.md" || component == "AGENTS.md" || component == ".mcp.json" || component == ".gitignore" {
			return false
		}
	}
	return true
}

func validateArtifact(ref measurement.ArtifactReference) error {
	if !bounded(ref.ID) || !validDigest(ref.Digest) {
		return errors.New("artifact reference is invalid")
	}
	return nil
}

func bounded(value string) bool {
	return value != "" && len(value) <= maxIdentifierBytes && strings.TrimSpace(value) == value
}

func validDigest(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, item := range value[len(prefix):] {
		if (item < '0' || item > '9') && (item < 'a' || item > 'f') {
			return false
		}
	}
	return true
}

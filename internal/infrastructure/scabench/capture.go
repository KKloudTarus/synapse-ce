// Package scabench captures one fully pinned SCA benchmark observation.
package scabench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/advisoryingest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scainput "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const (
	// CaptureManifestSchemaVersion identifies the strict capture input contract.
	CaptureManifestSchemaVersion                   = "synapse-sca-benchmark-capture-manifest-v1"
	CapabilityStatementSchemaVersion               = "synapse-sca-benchmark-capability-statement-v1"
	CapabilityDecisionRuleRevision                 = "osv-scanner-v2.5.1-suse-rpm-same-sbom-v1"
	CapabilityScopeSameSBOMOSPackageMatching       = "same-sbom-os-package-vulnerability-matching"
	EvidenceSchemaVersion                          = "synapse-sca-benchmark-evidence-v1"
	ProfileSchemaVersion                           = "synapse-sca-benchmark-execution-profile-v1"
	SandboxIdentityBubblewrapSeccompCgroupV2       = "bubblewrap+seccomp+cgroup-v2"
	maxManifestBytes                         int64 = 1 << 20
	maxBundleArtifactBytes                   int64 = 512 << 20
	// maxNormalizationInputBytes bounds retained redacted process stdout before parsing.
	// It is an implementation normalization boundary, distinct from scanner-output truncation.
	maxNormalizationInputBytes int64 = bench.MaxJSONBytes
	maxManifestDepth                 = 64
)

// DatabaseFormat selects the sole importer and fixed database contract for one engine.
// Values are part of the pinned execution profile and are intentionally stable.
type DatabaseFormat string

const (
	DatabaseFormatOSVJSON           DatabaseFormat = "osv-json"
	DatabaseFormatOVAL              DatabaseFormat = "oval"
	DatabaseFormatGrypeDBV6         DatabaseFormat = "grype-db-v6"
	DatabaseFormatTrivyDBV2         DatabaseFormat = "trivy-db-v2"
	DatabaseFormatOSVScannerOffline DatabaseFormat = "osv-scanner-offline-v1"
)

var (
	errVersionMismatch         = errors.New("engine version mismatch")
	errParser                  = errors.New("engine output parser failure")
	capabilitySourceReferences = []string{
		"https://github.com/google/osv-scanner/blob/c84fa4568f2526d0333e9a914ea8a0a5f74ad68b/internal/utility/purl/purl_to_package.go",
		"https://github.com/google/osv-scalibr/blob/23fa66ca68dd17bfdbe0b8b3536d1887a3a940da/purl/ecosystem/ecosystem.go",
	}
)

// Artifact identifies a local artifact and the catalog pin that binds its bytes.
type Artifact struct {
	Reference string `json:"reference"`
	Path      string `json:"path"`
}

// DatabaseArtifact is a locally available advisory database, explicit importer, and immutable build identity.
type DatabaseArtifact struct {
	Reference string         `json:"reference"`
	Path      string         `json:"path"`
	Build     string         `json:"build"`
	Format    DatabaseFormat `json:"format"`
}

// EnvironmentDescriptor contains only stable facts that identify a capture environment.
// ImageDigest is the SHA-256 digest of the exact environment attestation retained with a capture.
type EnvironmentDescriptor struct {
	ID              string `json:"id"`
	GOOS            string `json:"goos"`
	GOARCH          string `json:"goarch"`
	ImageDigest     string `json:"image_digest"`
	SandboxIdentity string `json:"sandbox_identity"`
}

// RuntimeLimits are explicit process limits, not runner defaults.
type RuntimeLimits struct {
	TimeoutSeconds int   `json:"timeout_seconds"`
	MaxOutputBytes int   `json:"max_output_bytes"`
	MemoryBytes    int64 `json:"memory_bytes"`
	PIDsMax        int   `json:"pids_max"`
}

// CaptureManifest binds exactly one scanner attempt to a catalog and local artifacts.
type CaptureManifest struct {
	SchemaVersion           string                `json:"schema_version"`
	CatalogRevision         string                `json:"catalog_revision"`
	CatalogDigest           string                `json:"catalog_digest"`
	TargetID                string                `json:"target_id"`
	SBOMPath                string                `json:"sbom_path"`
	Engine                  bench.Engine          `json:"engine"`
	EngineVersion           string                `json:"engine_version"`
	Binary                  Artifact              `json:"binary"`
	Database                DatabaseArtifact      `json:"database"`
	Environment             EnvironmentDescriptor `json:"environment"`
	EnvironmentAttestation  Artifact              `json:"environment_attestation"`
	EnvironmentPinReference string                `json:"environment_pin_reference"`
	ProfilePinReference     string                `json:"profile_pin_reference"`
	Limits                  RuntimeLimits         `json:"limits"`
	Capability              *CapabilityManifest   `json:"capability,omitempty"`
}

// CapabilityArtifact identifies retained capability evidence by an immutable reference,
// local source path, and exact byte digest.
type CapabilityArtifact struct {
	Reference string `json:"reference"`
	Path      string `json:"path"`
	Digest    string `json:"digest"`
}

// CapabilityManifest points to the capability statement and source artifacts it retains.
type CapabilityManifest struct {
	Statement CapabilityArtifact   `json:"statement"`
	Sources   []CapabilityArtifact `json:"sources"`
}

// CapabilityStatementSource names one immutable authoritative source artifact.
type CapabilityStatementSource struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

// CapabilityStatement binds a narrowly scoped capability decision to verified inputs.
type CapabilityStatement struct {
	SchemaVersion        string                      `json:"schema_version"`
	Kind                 bench.CapabilityKind        `json:"kind"`
	DecisionRuleRevision string                      `json:"decision_rule_revision"`
	Scope                string                      `json:"scope"`
	CatalogRevision      string                      `json:"catalog_revision"`
	CatalogDigest        string                      `json:"catalog_digest"`
	TargetID             string                      `json:"target_id"`
	TargetDigest         string                      `json:"target_digest"`
	SBOMDigest           string                      `json:"sbom_digest"`
	Engine               bench.Engine                `json:"engine"`
	EngineVersion        string                      `json:"engine_version"`
	EngineBinaryDigest   string                      `json:"engine_binary_digest"`
	DatabaseBuild        string                      `json:"database_build"`
	DatabaseDigest       string                      `json:"database_digest"`
	EnvironmentID        string                      `json:"environment_id"`
	EnvironmentDigest    string                      `json:"environment_digest"`
	ConfigDigest         string                      `json:"config_digest"`
	Components           []bench.Component           `json:"components"`
	Sources              []CapabilityStatementSource `json:"sources"`
}

// CapabilityEvidence makes an attested, zero-dispatch decision explicit in capture evidence.
type CapabilityEvidence struct {
	Kind                 bench.CapabilityKind `json:"kind"`
	StatementDigest      string               `json:"statement_digest"`
	DecisionRuleRevision string               `json:"decision_rule_revision"`
	Decision             string               `json:"decision"`
}

// ExecutionProfile is the logical, path-free command contract that is pinned by ConfigDigest.
type ExecutionProfile struct {
	SchemaVersion            string         `json:"schema_version"`
	Engine                   bench.Engine   `json:"engine"`
	DatabaseFormat           DatabaseFormat `json:"database_format"`
	ExecutionMode            string         `json:"execution_mode"`
	ArgvTemplate             []string       `json:"argv_template"`
	VersionProbeArgvTemplate []string       `json:"version_probe_argv_template"`
	EnvironmentTemplate      []string       `json:"environment_template"`
	OutputFormat             string         `json:"output_format"`
	NoNetwork                bool           `json:"no_network"`
	AutoUpdateDisabled       bool           `json:"auto_update_disabled"`
	Limits                   RuntimeLimits  `json:"limits"`
	ConfigContentDigest      string         `json:"config_content_digest"`
	IgnoreContentDigest      string         `json:"ignore_content_digest"`
}

// FailureCode is a closed capture state-machine failure vocabulary.
type FailureCode string

const (
	FailureNone                       FailureCode = ""
	FailureCancelled                  FailureCode = "cancelled"
	FailureTimeout                    FailureCode = "timeout"
	FailureRunnerError                FailureCode = "runner_error"
	FailureOutputTruncated            FailureCode = "output_truncated"
	FailureConnectEvent               FailureCode = "connect_event"
	FailureUnacceptedExit             FailureCode = "unaccepted_exit"
	FailureVersionMismatch            FailureCode = "version_mismatch"
	FailureParser                     FailureCode = "parser_failure"
	FailureInputMutated               FailureCode = "input_mutated"
	FailureNormalizationInputTooLarge FailureCode = "normalization_input_too_large"
	FailureObservationTooLarge        FailureCode = "observation_too_large"
)

type ParserStatus string

const (
	ParserNotRun ParserStatus = "not_run"
	ParserOK     ParserStatus = "ok"
	ParserFailed ParserStatus = "failed"
)

type InputIntegrityStatus string

const (
	InputsVerified InputIntegrityStatus = "verified"
	InputsMutated  InputIntegrityStatus = "mutated"
)

// ProcessEvidence is one redacted, bounded process result. Its bytes are redacted
// before parsing and canonical framing, so retained claim-bearing output is replayable.
type ProcessEvidence struct {
	ExitKnown           bool   `json:"exit_known"`
	ExitCode            int    `json:"exit_code"`
	RunnerError         bool   `json:"runner_error"`
	Cancelled           bool   `json:"cancelled"`
	TimedOut            bool   `json:"timed_out"`
	Truncated           bool   `json:"truncated"`
	ConnectEventCount   int    `json:"connect_event_count"`
	Redacted            bool   `json:"redacted"`
	ParsedEngineVersion string `json:"parsed_engine_version"`
	Stdout              []byte `json:"stdout"`
	Stderr              []byte `json:"stderr"`
}

// Evidence preserves separately attributable probe and scan processes plus the closed
// parser/input state. Nil process records mean that process was not dispatched.
type Evidence struct {
	SchemaVersion  string               `json:"schema_version"`
	Engine         bench.Engine         `json:"engine"`
	TargetID       string               `json:"target_id"`
	VersionProbe   *ProcessEvidence     `json:"version_probe"`
	Scan           *ProcessEvidence     `json:"scan"`
	ParserStatus   ParserStatus         `json:"parser_status"`
	InputIntegrity InputIntegrityStatus `json:"input_integrity"`
	FailureCode    FailureCode          `json:"failure_code"`
	Capability     *CapabilityEvidence  `json:"capability,omitempty"`
}

// CaptureResult is opaque outside this package. Publication relies on a private replay
// binding, so callers cannot construct or mutate a valid result.
type CaptureResult struct {
	observation                bench.Observation
	evidence                   Evidence
	evidenceJSON               []byte
	profileJSON                []byte
	environmentJSON            []byte
	environmentAttestationJSON []byte
	capabilityStatementJSON    []byte
	capabilitySources          []retainedCapabilitySource
	binding                    resultBinding
}

type retainedCapabilitySource struct {
	Reference string
	Digest    string
	Data      []byte
}

type resultBinding struct {
	valid                      bool
	observation                bench.Observation
	target                     bench.Target
	components                 []sbom.Component
	profile                    ExecutionProfile
	evidence                   Evidence
	evidenceJSON               []byte
	profileJSON                []byte
	environmentJSON            []byte
	environmentAttestationJSON []byte
	capabilityStatementJSON    []byte
	capabilitySources          []retainedCapabilitySource
}

// Observation returns a deep copy of the captured observation.
func (r CaptureResult) Observation() bench.Observation { return cloneObservation(r.observation) }

// EvidenceJSON returns a copy of canonical retained evidence bytes.
func (r CaptureResult) EvidenceJSON() []byte { return append([]byte(nil), r.evidenceJSON...) }

// ProfileJSON returns a copy of canonical execution-profile bytes.
func (r CaptureResult) ProfileJSON() []byte { return append([]byte(nil), r.profileJSON...) }

// CapabilityStatementJSON returns the retained statement bytes, when present.
func (r CaptureResult) CapabilityStatementJSON() []byte {
	return append([]byte(nil), r.capabilityStatementJSON...)
}

// Capturer runs every benchmark engine through the caller-owned ToolRunner.
type Capturer struct {
	runner  ports.ToolRunner
	tempDir string
}

// NewCapturer creates a strict capture adapter.
func NewCapturer(runner ports.ToolRunner) *Capturer { return &Capturer{runner: runner} }

// WithTempDir directs generated config files to dir. It is primarily useful to tests.
func (c *Capturer) WithTempDir(dir string) *Capturer {
	c.tempDir = dir
	return c
}

// Preflight verifies every catalog-bound local identity without dispatching an engine.
func Preflight(catalog bench.Catalog, manifest CaptureManifest) error {
	prepared, err := Prepare(catalog, manifest)
	if prepared != nil {
		defer func() { _ = prepared.Close() }()
	}
	return err
}

// Prepare verifies every catalog-bound local identity without dispatching an engine.
// The opaque result can be passed to CapturePrepared after a caller constructs its
// sandbox, without re-hashing large pinned artifacts.
func Prepare(catalog bench.Catalog, manifest CaptureManifest) (*PreparedCapture, error) {
	prepared, err := NewCapturer(nil).preflight(catalog, manifest)
	if err != nil {
		return nil, err
	}
	return &PreparedCapture{capture: prepared}, nil
}

// DecodeCaptureManifest strictly decodes one bounded, versioned manifest.
func DecodeCaptureManifest(reader io.Reader) (CaptureManifest, error) {
	var manifest CaptureManifest
	if err := strictDecodeManifest(reader, &manifest); err != nil {
		return CaptureManifest{}, fmt.Errorf("decode capture manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return CaptureManifest{}, err
	}
	return manifest, nil
}

// Validate verifies the manifest without accessing its physical paths.
func (m CaptureManifest) Validate() error {
	if m.SchemaVersion != CaptureManifestSchemaVersion {
		return fmt.Errorf("unsupported capture manifest schema %q", m.SchemaVersion)
	}
	if strings.TrimSpace(m.CatalogRevision) == "" || !validDigest(m.CatalogDigest) {
		return fmt.Errorf("catalog revision and immutable catalog digest are required")
	}
	if strings.TrimSpace(m.TargetID) == "" || strings.TrimSpace(m.SBOMPath) == "" {
		return fmt.Errorf("target ID and SBOM path are required")
	}
	if !knownEngine(m.Engine) || strings.TrimSpace(m.EngineVersion) == "" {
		return fmt.Errorf("a supported engine and expected engine version are required")
	}
	if err := validateArtifact(m.Binary, "binary"); err != nil {
		return err
	}
	if err := validateArtifact(Artifact{Reference: m.Database.Reference, Path: m.Database.Path}, "database"); err != nil {
		return err
	}
	if err := validateArtifact(m.EnvironmentAttestation, "environment attestation"); err != nil {
		return err
	}
	if strings.TrimSpace(m.Database.Build) == "" {
		return fmt.Errorf("database build is required")
	}
	if !validDatabaseFormatForEngine(m.Engine, m.Database.Format) {
		return fmt.Errorf("database format %q is not supported by engine %q", m.Database.Format, m.Engine)
	}
	if strings.TrimSpace(m.EnvironmentPinReference) == "" || strings.TrimSpace(m.ProfilePinReference) == "" {
		return fmt.Errorf("environment and profile pin references are required")
	}
	if err := m.Environment.validate(); err != nil {
		return err
	}
	if err := m.Limits.validate(); err != nil {
		return err
	}
	if m.Capability != nil {
		return m.Capability.validate()
	}
	return nil
}

func (m CapabilityManifest) validate() error {
	if err := validateCapabilityArtifact(m.Statement, "capability statement"); err != nil {
		return err
	}
	if len(m.Sources) != len(capabilitySourceReferences) {
		return fmt.Errorf("capability evidence must retain %d authoritative source artifacts", len(capabilitySourceReferences))
	}
	seen := make(map[string]struct{}, len(m.Sources))
	for i, source := range m.Sources {
		if err := validateCapabilityArtifact(source, "capability source"); err != nil {
			return fmt.Errorf("capability source %d: %w", i, err)
		}
		if _, exists := seen[source.Reference]; exists {
			return fmt.Errorf("capability source reference %q is duplicated", source.Reference)
		}
		seen[source.Reference] = struct{}{}
	}
	return nil
}

func validateCapabilityArtifact(artifact CapabilityArtifact, name string) error {
	if strings.TrimSpace(artifact.Reference) != artifact.Reference || artifact.Reference == "" || strings.TrimSpace(artifact.Path) == "" || !validDigest(artifact.Digest) {
		return fmt.Errorf("%s reference, path, and immutable digest are required", name)
	}
	return nil
}

func validateArtifact(artifact Artifact, name string) error {
	if strings.TrimSpace(artifact.Reference) == "" || strings.TrimSpace(artifact.Path) == "" {
		return fmt.Errorf("%s reference and path are required", name)
	}
	return nil
}

func (e EnvironmentDescriptor) validate() error {
	if strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.GOOS) == "" || strings.TrimSpace(e.GOARCH) == "" {
		return fmt.Errorf("environment ID, GOOS, and GOARCH are required")
	}
	if e.SandboxIdentity != SandboxIdentityBubblewrapSeccompCgroupV2 {
		return fmt.Errorf("sandbox identity must be %q", SandboxIdentityBubblewrapSeccompCgroupV2)
	}
	if !validDigest(e.ImageDigest) {
		return fmt.Errorf("environment image digest must be an immutable sha256 digest")
	}
	return nil
}

func (l RuntimeLimits) validate() error {
	if l.TimeoutSeconds <= 0 || l.TimeoutSeconds > 3600 {
		return fmt.Errorf("timeout seconds must be between 1 and 3600")
	}
	if l.MaxOutputBytes <= 0 || l.MaxOutputBytes > 128<<20 {
		return fmt.Errorf("max output bytes must be between 1 and %d", 128<<20)
	}
	if l.MemoryBytes <= 0 || l.MemoryBytes > 64<<30 {
		return fmt.Errorf("memory bytes must be between 1 and %d", int64(64<<30))
	}
	if l.PIDsMax <= 0 || l.PIDsMax > 65536 {
		return fmt.Errorf("PIDs max must be between 1 and 65536")
	}
	return nil
}

// PreparedCapture owns private verified artifact snapshots until capture or Close.
// Snapshots close ordinary caller/source-path mutation. Hostile same-UID host mutation is
// not cryptographically prevented; trusted exact-image hosts and host-enforced controls
// are required.
type PreparedCapture struct {
	mu      sync.Mutex
	capture preparedCapture
	closed  bool
	used    bool
}

// Close removes the private snapshot. It is idempotent and serializes with capture.
func (p *PreparedCapture) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeLocked()
}

func (p *PreparedCapture) closeLocked() error {
	if p.capture.snapshotRoot == "" {
		p.closed = true
		return nil
	}
	p.closed = true
	if err := os.RemoveAll(p.capture.snapshotRoot); err != nil {
		return err
	}
	p.capture.snapshotRoot = ""
	return nil
}

type preparedCapture struct {
	snapshotRoot                 string
	catalog                      bench.Catalog
	manifest                     CaptureManifest
	target                       bench.Target
	binaryPath                   string
	sbomPath                     string
	databasePath                 string
	binaryDigest                 string
	databaseDigest               string
	environmentDigest            string
	environmentPath              string
	environmentAttestationDigest string
	environmentJSON              []byte
	environmentAttestationJSON   []byte
	profile                      ExecutionProfile
	profileJSON                  []byte
	configDigest                 string
	configBytes                  []byte
	ignoreBytes                  []byte
	components                   []sbom.Component
	capability                   *preparedCapability
}

type preparedCapability struct {
	statementJSON []byte
	sources       []retainedCapabilitySource
}

// Capture performs preflight before dispatch. Preflight errors return no observation;
// every post-dispatch problem is encoded as an incomplete observation.
func (c *Capturer) Capture(ctx context.Context, catalog bench.Catalog, manifest CaptureManifest) (CaptureResult, error) {
	captured, err := c.preflight(catalog, manifest)
	if err != nil {
		return CaptureResult{}, err
	}
	prepared := &PreparedCapture{capture: captured}
	defer func() { _ = prepared.Close() }()
	return c.CapturePrepared(ctx, prepared)
}

// CapturePrepared dispatches a prior verified capture without repeating preflight hashing.
func (c *Capturer) CapturePrepared(ctx context.Context, prepared *PreparedCapture) (result CaptureResult, err error) {
	if prepared == nil {
		return CaptureResult{}, errors.New("prepared capture is required")
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.closed || strings.TrimSpace(prepared.capture.manifest.TargetID) == "" {
		return CaptureResult{}, errors.New("prepared capture is closed")
	}
	if prepared.used {
		return CaptureResult{}, errors.New("prepared capture was already used")
	}
	prepared.used = true
	defer func() {
		if closeErr := prepared.closeLocked(); closeErr != nil && err == nil {
			result = CaptureResult{}
			err = fmt.Errorf("cleanup private capture snapshot: %w", closeErr)
		}
	}()
	if prepared.capture.capability != nil {
		return CaptureResult{}, errors.New("capability capture must not dispatch an engine")
	}
	if c.runner == nil {
		return CaptureResult{}, errors.New("engine runner is required")
	}
	return c.captureExternal(ctx, prepared.capture)
}

// CaptureCapability captures a verified unsupported capability without creating a ToolRunner.
func CaptureCapability(catalog bench.Catalog, manifest CaptureManifest) (CaptureResult, error) {
	prepared, err := Prepare(catalog, manifest)
	if err != nil {
		return CaptureResult{}, err
	}
	defer func() { _ = prepared.Close() }()
	return CaptureCapabilityPrepared(prepared)
}

// CaptureCapabilityPrepared completes a verified capability path without process dispatch.
func CaptureCapabilityPrepared(prepared *PreparedCapture) (result CaptureResult, err error) {
	if prepared == nil {
		return CaptureResult{}, errors.New("prepared capture is required")
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.closed || strings.TrimSpace(prepared.capture.manifest.TargetID) == "" {
		return CaptureResult{}, errors.New("prepared capture is closed")
	}
	if prepared.used {
		return CaptureResult{}, errors.New("prepared capture was already used")
	}
	prepared.used = true
	defer func() {
		if closeErr := prepared.closeLocked(); closeErr != nil && err == nil {
			result = CaptureResult{}
			err = fmt.Errorf("cleanup private capture snapshot: %w", closeErr)
		}
	}()
	if prepared.capture.capability == nil {
		return CaptureResult{}, errors.New("prepared capture does not contain a capability statement")
	}
	return captureCapability(prepared.capture)
}

func (c *Capturer) preflight(catalog bench.Catalog, manifest CaptureManifest) (prepared preparedCapture, err error) {
	catalog = cloneCatalog(catalog)
	if err := catalog.Validate(); err != nil {
		return preparedCapture{}, fmt.Errorf("validate catalog: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return preparedCapture{}, err
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return preparedCapture{}, fmt.Errorf("digest catalog: %w", err)
	}
	if catalog.Revision != manifest.CatalogRevision || catalogDigest != manifest.CatalogDigest {
		return preparedCapture{}, errors.New("manifest catalog identity does not match catalog")
	}
	target, ok := targetByID(catalog, manifest.TargetID)
	if !ok {
		return preparedCapture{}, fmt.Errorf("manifest target %q is not in catalog", manifest.TargetID)
	}
	root, err := os.MkdirTemp(c.tempDir, "synapse-sca-bench-snapshot-")
	if err != nil {
		return preparedCapture{}, errors.New("create private capture snapshot")
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(root)
		}
	}()
	binaryPath := filepath.Join(root, "binary")
	binaryDigest, err := copyExecutableSnapshot(manifest.Binary.Path, binaryPath)
	if err != nil {
		return preparedCapture{}, fmt.Errorf("snapshot binary: %w", err)
	}
	if err := requirePin(catalog, manifest.Binary.Reference, binaryDigest, "binary"); err != nil {
		return preparedCapture{}, err
	}
	sbomPath := filepath.Join(root, "bom.cdx.json")
	sbomDigest, err := copyRegularSnapshot(manifest.SBOMPath, sbomPath)
	if err != nil {
		return preparedCapture{}, fmt.Errorf("snapshot SBOM: %w", err)
	}
	if sbomDigest != target.SBOMDigest {
		return preparedCapture{}, errors.New("SBOM digest does not match catalog target")
	}
	sbomBytes, err := os.ReadFile(sbomPath)
	if err != nil {
		return preparedCapture{}, errors.New("read verified SBOM snapshot")
	}
	components, err := scainput.ParseCycloneDXComponents(sbomBytes)
	if err != nil {
		return preparedCapture{}, fmt.Errorf("parse CycloneDX SBOM: %w", err)
	}
	if err := verifyCatalogComponents(target.Components, components); err != nil {
		return preparedCapture{}, err
	}
	databasePath := filepath.Join(root, "database")
	databaseDigest, files, err := copyDatabaseSnapshot(manifest.Database.Path, databasePath)
	if err != nil {
		return preparedCapture{}, fmt.Errorf("snapshot database: %w", err)
	}
	if files == 0 {
		return preparedCapture{}, errors.New("database snapshot is empty")
	}
	if err := requirePin(catalog, manifest.Database.Reference, databaseDigest, "database"); err != nil {
		return preparedCapture{}, err
	}
	if manifest.Engine == bench.EngineOwned {
		if err := inspectOwnedCorpusLayout(databasePath, manifest.Database.Format); err != nil {
			return preparedCapture{}, fmt.Errorf("inspect owned advisory corpus: %w", err)
		}
	}
	environmentJSON, err := canonicalJSON(manifest.Environment)
	if err != nil {
		return preparedCapture{}, fmt.Errorf("encode environment descriptor: %w", err)
	}
	environmentDigest := bench.SHA256Digest(environmentJSON)
	if err := requirePin(catalog, manifest.EnvironmentPinReference, environmentDigest, "environment"); err != nil {
		return preparedCapture{}, err
	}
	if manifest.Environment.GOOS != runtime.GOOS || manifest.Environment.GOARCH != runtime.GOARCH {
		return preparedCapture{}, errors.New("manifest environment GOOS/GOARCH does not match runtime")
	}
	environmentPath := filepath.Join(root, "environment-attestation.json")
	environmentAttestationDigest, environmentAttestationJSON, err := copyBoundedRegularSnapshot(manifest.EnvironmentAttestation.Path, environmentPath, true)
	if err != nil {
		return preparedCapture{}, fmt.Errorf("snapshot environment attestation: %w", err)
	}
	if environmentAttestationDigest != manifest.Environment.ImageDigest {
		return preparedCapture{}, errors.New("environment attestation digest does not match environment image digest")
	}
	if err := requirePin(catalog, manifest.EnvironmentAttestation.Reference, environmentAttestationDigest, "environment attestation"); err != nil {
		return preparedCapture{}, err
	}
	profile, configBytes, ignoreBytes, err := buildProfile(manifest.Engine, manifest.Database.Format, manifest.Limits)
	if err != nil {
		return preparedCapture{}, err
	}
	profileJSON, err := canonicalJSON(profile)
	if err != nil {
		return preparedCapture{}, fmt.Errorf("encode execution profile: %w", err)
	}
	configDigest := bench.SHA256Digest(profileJSON)
	if err := requirePin(catalog, manifest.ProfilePinReference, configDigest, "execution profile"); err != nil {
		return preparedCapture{}, err
	}
	prepared = preparedCapture{
		snapshotRoot: root,
		catalog:      catalog, manifest: manifest, target: target, binaryPath: binaryPath, sbomPath: sbomPath,
		databasePath: databasePath, binaryDigest: binaryDigest, databaseDigest: databaseDigest,
		environmentDigest: environmentDigest, environmentPath: environmentPath, environmentAttestationDigest: environmentAttestationDigest,
		environmentJSON: append([]byte(nil), environmentJSON...), environmentAttestationJSON: append([]byte(nil), environmentAttestationJSON...),
		profile: profile, profileJSON: profileJSON, configDigest: configDigest,
		configBytes: configBytes, ignoreBytes: ignoreBytes, components: append([]sbom.Component(nil), components...),
	}
	if manifest.Capability != nil {
		capability, capabilityErr := prepareCapability(root, *manifest.Capability, prepared)
		if capabilityErr != nil {
			return preparedCapture{}, capabilityErr
		}
		prepared.capability = capability
	}
	return prepared, nil
}

func prepareCapability(root string, manifest CapabilityManifest, prepared preparedCapture) (*preparedCapability, error) {
	statementPath := filepath.Join(root, "capability-statement.json")
	statementDigest, statementJSON, err := copyCapabilityArtifact(manifest.Statement, statementPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot capability statement: %w", err)
	}
	if statementDigest != manifest.Statement.Digest {
		return nil, errors.New("capability statement digest does not match manifest")
	}
	statement, err := decodeCapabilityStatement(statementJSON)
	if err != nil {
		return nil, err
	}
	if err := verifyCapabilityStatement(statement, prepared); err != nil {
		return nil, err
	}
	sources := make([]retainedCapabilitySource, 0, len(capabilitySourceReferences))
	for i, reference := range capabilitySourceReferences {
		artifact, ok := capabilityArtifactByReference(manifest.Sources, reference)
		if !ok || statement.Sources[i].Reference != reference || statement.Sources[i].Digest != artifact.Digest {
			return nil, errors.New("capability statement sources do not match manifest")
		}
		destination := filepath.Join(root, fmt.Sprintf("capability-source-%02d", i))
		digest, data, err := copyCapabilityArtifact(artifact, destination)
		if err != nil {
			return nil, fmt.Errorf("snapshot capability source %d: %w", i, err)
		}
		if digest != artifact.Digest || digest != statement.Sources[i].Digest {
			return nil, fmt.Errorf("capability source %d digest does not match its pin", i)
		}
		sources = append(sources, retainedCapabilitySource{Reference: reference, Digest: digest, Data: data})
	}
	return &preparedCapability{statementJSON: statementJSON, sources: sources}, nil
}

func copyCapabilityArtifact(artifact CapabilityArtifact, destination string) (string, []byte, error) {
	info, err := os.Lstat(artifact.Path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return "", nil, errors.New("capability artifact must be a bounded regular non-symlink file")
	}
	digest, err := copyRegularSnapshot(artifact.Path, destination)
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(destination)
	if err != nil || int64(len(data)) > maxManifestBytes || bench.SHA256Digest(data) != digest {
		return "", nil, errors.New("read private capability artifact snapshot")
	}
	return digest, data, nil
}

func capabilityArtifactByReference(artifacts []CapabilityArtifact, reference string) (CapabilityArtifact, bool) {
	for _, artifact := range artifacts {
		if artifact.Reference == reference {
			return artifact, true
		}
	}
	return CapabilityArtifact{}, false
}

func decodeCapabilityStatement(data []byte) (CapabilityStatement, error) {
	var statement CapabilityStatement
	if err := strictDecodeCapabilityStatement(bytes.NewReader(data), &statement); err != nil {
		return CapabilityStatement{}, fmt.Errorf("decode capability statement: %w", err)
	}
	if err := statement.Validate(); err != nil {
		return CapabilityStatement{}, err
	}
	canonical, err := canonicalJSON(statement)
	if err != nil || !bytes.Equal(canonical, data) {
		return CapabilityStatement{}, errors.New("capability statement is not canonical")
	}
	return statement, nil
}

// Validate verifies the statement's fixed rule identity and canonical declared inputs.
func (statement CapabilityStatement) Validate() error {
	if statement.SchemaVersion != CapabilityStatementSchemaVersion ||
		statement.Kind != bench.CapabilityKindOSVScannerSUSERPM ||
		statement.DecisionRuleRevision != CapabilityDecisionRuleRevision ||
		statement.Scope != CapabilityScopeSameSBOMOSPackageMatching ||
		statement.Engine != bench.EngineOSVScanner || statement.EngineVersion != "v2.5.1" {
		return errors.New("capability statement has an unsupported rule identity")
	}
	for _, value := range []string{statement.CatalogRevision, statement.TargetID, statement.DatabaseBuild, statement.EnvironmentID} {
		if strings.TrimSpace(value) != value || value == "" {
			return errors.New("capability statement has an invalid text identity")
		}
	}
	for _, digest := range []string{statement.CatalogDigest, statement.TargetDigest, statement.SBOMDigest, statement.EngineBinaryDigest, statement.DatabaseDigest, statement.EnvironmentDigest, statement.ConfigDigest} {
		if !validDigest(digest) {
			return errors.New("capability statement has an invalid immutable digest")
		}
	}
	if len(statement.Components) == 0 {
		return errors.New("capability statement requires PURL-bearing components")
	}
	previous := ""
	seen := make(map[bench.ComponentBenchmarkKey]struct{}, len(statement.Components))
	for i, component := range statement.Components {
		key, err := capabilityComponentKey(component)
		if err != nil {
			return fmt.Errorf("capability component %d: %w", i, err)
		}
		text := key.Ecosystem + "\x00" + key.Package + "\x00" + key.Version
		if previous != "" && previous >= text {
			return errors.New("capability components must be strictly canonical")
		}
		previous = text
		if _, exists := seen[key]; exists {
			return errors.New("capability statement has duplicate component identities")
		}
		seen[key] = struct{}{}
	}
	if len(statement.Sources) != len(capabilitySourceReferences) {
		return errors.New("capability statement has an incomplete authoritative source set")
	}
	for i, source := range statement.Sources {
		if source.Reference != capabilitySourceReferences[i] || !validDigest(source.Digest) {
			return errors.New("capability statement has a non-canonical authoritative source")
		}
	}
	return nil
}

type componentPackageScope struct {
	Ecosystem string
	Package   string
}

func purlComponentScope(purl string) (componentPackageScope, error) {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		return componentPackageScope{}, errors.New("component purl must begin with pkg")
	}
	path := purl[len("pkg:"):]
	if delimiter := strings.IndexAny(path, "?#"); delimiter >= 0 {
		path = path[:delimiter]
	}
	slash := strings.IndexByte(path, '/')
	if slash <= 0 || slash == len(path)-1 {
		return componentPackageScope{}, errors.New("component purl must contain a type and package")
	}
	ecosystem, err := url.PathUnescape(path[:slash])
	if err != nil || ecosystem == "" || hasControlCharacter(ecosystem) {
		return componentPackageScope{}, errors.New("component purl type is invalid")
	}
	for _, character := range ecosystem {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '-') {
			return componentPackageScope{}, errors.New("component purl type is invalid")
		}
	}
	packageAndVersion := path[slash+1:]
	if separator := strings.LastIndexByte(packageAndVersion, '@'); separator >= 0 {
		packageAndVersion = packageAndVersion[:separator]
	}
	packageName, err := url.PathUnescape(packageAndVersion)
	if err != nil || packageName == "" || hasControlCharacter(packageName) {
		return componentPackageScope{}, errors.New("component purl package is invalid")
	}
	for _, segment := range strings.Split(packageName, "/") {
		if strings.TrimSpace(segment) == "" {
			return componentPackageScope{}, errors.New("component purl package is invalid")
		}
	}
	return componentPackageScope{Ecosystem: ecosystem, Package: packageName}, nil
}

func hasControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func isSLESRPMCandidate(purl string) bool {
	return strings.HasPrefix(strings.TrimSpace(purl), "pkg:rpm/sles/")
}

func capabilityComponentKey(component bench.Component) (bench.ComponentBenchmarkKey, error) {
	purl := component.PURL
	if delimiter := strings.IndexAny(purl, "?#"); delimiter >= 0 {
		purl = purl[:delimiter]
	}
	if component.PURL != strings.TrimSpace(component.PURL) || component.Version != strings.TrimSpace(component.Version) ||
		!strings.HasPrefix(purl, "pkg:rpm/sles/") || strings.Count(purl, "@") != 1 {
		return bench.ComponentBenchmarkKey{}, errors.New("must be an exact pkg:rpm/sles PURL with an embedded version")
	}
	key, err := bench.ComponentKey(component, "capability")
	if err != nil {
		return bench.ComponentBenchmarkKey{}, err
	}
	if key.Ecosystem != "rpm" || !strings.HasPrefix(key.Package, "sles/") || key.Version != component.Version {
		return bench.ComponentBenchmarkKey{}, errors.New("must be an exact SLES RPM component identity")
	}
	return key, nil
}

func verifyCapabilityStatement(statement CapabilityStatement, prepared preparedCapture) error {
	if statement.CatalogRevision != prepared.catalog.Revision || statement.CatalogDigest != prepared.manifest.CatalogDigest ||
		statement.TargetID != prepared.target.ID || statement.TargetDigest != prepared.target.Digest || statement.SBOMDigest != prepared.target.SBOMDigest ||
		statement.Engine != prepared.manifest.Engine || statement.EngineVersion != prepared.manifest.EngineVersion || statement.EngineBinaryDigest != prepared.binaryDigest ||
		statement.DatabaseBuild != prepared.manifest.Database.Build || statement.DatabaseDigest != prepared.databaseDigest ||
		statement.EnvironmentID != prepared.manifest.Environment.ID || statement.EnvironmentDigest != prepared.environmentDigest || statement.ConfigDigest != prepared.configDigest {
		return errors.New("capability statement pins do not match verified capture inputs")
	}
	actual := make(map[bench.ComponentBenchmarkKey]struct{}, len(prepared.components))
	for _, component := range prepared.components {
		if !isSLESRPMCandidate(component.PURL) {
			continue
		}
		key, err := capabilityComponentKey(bench.Component{PURL: component.PURL, Version: component.Version})
		if err != nil {
			return fmt.Errorf("SBOM SLES RPM component: %w", err)
		}
		if _, exists := actual[key]; exists {
			return errors.New("SBOM has duplicate SLES RPM component identities")
		}
		actual[key] = struct{}{}
	}
	if len(actual) == 0 {
		return errors.New("SBOM has no applicable SLES RPM components")
	}
	declared := make(map[bench.ComponentBenchmarkKey]struct{}, len(statement.Components))
	for _, component := range statement.Components {
		key, err := capabilityComponentKey(component)
		if err != nil {
			return err
		}
		if _, exists := declared[key]; exists {
			return errors.New("capability statement has duplicate component identities")
		}
		if _, exists := actual[key]; !exists {
			return errors.New("capability statement omits or adds an SBOM component")
		}
		declared[key] = struct{}{}
	}
	if len(actual) != len(declared) {
		return errors.New("capability component set does not exactly match the applicable SLES RPM SBOM components")
	}
	return nil
}

func captureCapability(prepared preparedCapture) (CaptureResult, error) {
	if err := verifyPreparedInputs(prepared); err != nil {
		return CaptureResult{}, err
	}
	capability := prepared.capability
	if capability == nil {
		return CaptureResult{}, errors.New("capability statement is required")
	}
	statement, err := decodeCapabilityStatement(capability.statementJSON)
	if err != nil {
		return CaptureResult{}, err
	}
	if err := verifyCapabilityStatement(statement, prepared); err != nil {
		return CaptureResult{}, err
	}
	evidence := Evidence{
		SchemaVersion: EvidenceSchemaVersion, Engine: prepared.manifest.Engine, TargetID: prepared.target.ID,
		VersionProbe: nil, Scan: nil, ParserStatus: ParserNotRun, InputIntegrity: InputsVerified, FailureCode: FailureNone,
		Capability: &CapabilityEvidence{Kind: statement.Kind, StatementDigest: bench.SHA256Digest(capability.statementJSON), DecisionRuleRevision: statement.DecisionRuleRevision, Decision: string(bench.ObservationUnsupported)},
	}
	evidenceJSON, err := canonicalJSON(evidence)
	if err != nil {
		return CaptureResult{}, fmt.Errorf("encode capability evidence: %w", err)
	}
	observation := observationFromPrepared(prepared, bench.ObservationUnsupported, rawOutputDigest(evidenceJSON), nil)
	observation.CapabilityKind = statement.Kind
	observation.CapabilityDigest = bench.SHA256Digest(capability.statementJSON)
	set := bench.ObservationSet{SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: prepared.catalog.Revision, CatalogDigest: prepared.manifest.CatalogDigest, Observations: []bench.Observation{observation}}
	if err := set.Validate(); err != nil {
		return CaptureResult{}, fmt.Errorf("validate capability observation: %w", err)
	}
	return newCaptureResult(observation, evidence, evidenceJSON, prepared.profileJSON, prepared), nil
}

func (c *Capturer) captureExternal(ctx context.Context, prepared preparedCapture) (CaptureResult, error) {
	configDir, err := os.MkdirTemp(c.tempDir, "synapse-sca-bench-config-")
	if err != nil {
		return CaptureResult{}, errors.New("create generated configuration directory")
	}
	defer func() { _ = os.RemoveAll(configDir) }()
	configName := "config.yaml"
	if prepared.manifest.Engine == bench.EngineOSVScanner {
		configName = "config.toml"
	}
	configPath, err := writeVerifiedConfig(configDir, configName, prepared.configBytes, prepared.profile.ConfigContentDigest)
	if err != nil {
		return CaptureResult{}, err
	}
	ignorePath, err := writeVerifiedConfig(configDir, "ignore.txt", prepared.ignoreBytes, prepared.profile.IgnoreContentDigest)
	if err != nil {
		return CaptureResult{}, err
	}
	knownPaths := []string{prepared.binaryPath, prepared.sbomPath, prepared.databasePath, configPath, ignorePath}
	args, env, err := instantiateProfile(prepared.profile, prepared.sbomPath, prepared.databasePath, configPath, ignorePath)
	if err != nil {
		return CaptureResult{}, err
	}
	spec := toolSpec(prepared, args, env, knownPaths)
	var probe *ProcessEvidence
	if prepared.manifest.Engine == bench.EngineOSVScanner {
		probeProfile := prepared.profile
		probeProfile.ArgvTemplate = probeProfile.VersionProbeArgvTemplate
		probeArgs, _, err := instantiateProfile(probeProfile, prepared.sbomPath, prepared.databasePath, configPath, ignorePath)
		if err != nil {
			return CaptureResult{}, err
		}
		probeResult, probeErr := c.runner.Run(ctx, toolSpec(prepared, probeArgs, nil, []string{prepared.binaryPath}))
		probe = newProcessEvidence(probeResult, probeErr, ctx.Err(), knownPaths, prepared.manifest.Limits.MaxOutputBytes)
		if failure := classifyProcessFailure(probe, prepared.manifest.Engine, true); failure != FailureNone {
			return c.finishExternal(prepared, probe, nil, failure, configPath, ignorePath)
		}
		version, versionErr := parseOSVVersion(probe.Stdout)
		probe.ParsedEngineVersion = version
		if versionErr != nil || version != prepared.manifest.EngineVersion {
			return c.finishExternal(prepared, probe, nil, FailureVersionMismatch, configPath, ignorePath)
		}
	}
	runResult, runErr := c.runner.Run(ctx, spec)
	scan := newProcessEvidence(runResult, runErr, ctx.Err(), knownPaths, prepared.manifest.Limits.MaxOutputBytes)
	return c.finishExternal(prepared, probe, scan, FailureNone, configPath, ignorePath)
}

func toolSpec(prepared preparedCapture, args, env, readOnlyPaths []string) ports.ToolSpec {
	return ports.ToolSpec{
		Name:           prepared.binaryPath,
		Args:           args,
		Timeout:        time.Duration(prepared.manifest.Limits.TimeoutSeconds) * time.Second,
		MaxOutputBytes: prepared.manifest.Limits.MaxOutputBytes,
		ReadOnlyPaths:  readOnlyPaths,
		MemMaxBytes:    prepared.manifest.Limits.MemoryBytes,
		PidsMax:        prepared.manifest.Limits.PIDsMax,
		Env:            env,
		HostNetwork:    false,
		EgressPolicy:   nil,
		CapAdd:         nil,
	}
}

func (c *Capturer) finishExternal(prepared preparedCapture, probe, scan *ProcessEvidence, initialFailure FailureCode, generatedPaths ...string) (CaptureResult, error) {
	failure := initialFailure
	parserStatus := ParserNotRun
	inputIntegrity := InputsVerified
	var findings []bench.Finding
	if failure == FailureNone && scan != nil {
		failure = classifyProcessFailure(scan, prepared.manifest.Engine, false)
	}
	if failure == FailureNone && scan != nil {
		parserStatus = ParserOK
		version, _ := reportedEngineVersion(prepared.manifest.Engine, scan.Stdout)
		scan.ParsedEngineVersion = version
		var parseErr error
		findings, parseErr = parseEngine(prepared.manifest.Engine, prepared.manifest.EngineVersion, scan.Stdout, prepared.target, prepared.components, prepared.manifest.Database.Format)
		if parseErr == nil {
			findings = canonicalFindings(findings)
		}
		if parseErr != nil {
			parserStatus = ParserFailed
			if errors.Is(parseErr, errVersionMismatch) {
				failure = FailureVersionMismatch
			} else {
				failure = FailureParser
			}
		}
	}
	if err := verifyPostflight(prepared, generatedPaths...); err != nil {
		inputIntegrity = InputsMutated
		if failure == FailureNone {
			failure = FailureInputMutated
		}
	}
	evidence := Evidence{
		SchemaVersion:  EvidenceSchemaVersion,
		Engine:         prepared.manifest.Engine,
		TargetID:       prepared.target.ID,
		VersionProbe:   cloneProcessEvidence(probe),
		Scan:           cloneProcessEvidence(scan),
		ParserStatus:   parserStatus,
		InputIntegrity: inputIntegrity,
		FailureCode:    failure,
	}
	if failure == FailureNone && parserStatus == ParserOK && inputIntegrity == InputsVerified {
		provisionalEvidence, err := canonicalJSON(evidence)
		if err != nil {
			return CaptureResult{}, fmt.Errorf("encode evidence: %w", err)
		}
		provisional := observationFromPrepared(prepared, bench.ObservationComplete, rawOutputDigest(provisionalEvidence), findings)
		over, err := observationExceedsLimit(provisional)
		if err != nil {
			return CaptureResult{}, err
		}
		if over {
			failure = FailureObservationTooLarge
			evidence.FailureCode = failure
			findings = nil
		}
	}
	evidenceJSON, err := canonicalJSON(evidence)
	if err != nil {
		return CaptureResult{}, fmt.Errorf("encode evidence: %w", err)
	}
	state := bench.ObservationComplete
	if failure != FailureNone {
		state = bench.ObservationIncomplete
		findings = nil
	}
	observation := observationFromPrepared(prepared, state, rawOutputDigest(evidenceJSON), findings)
	set := bench.ObservationSet{SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: prepared.catalog.Revision, CatalogDigest: prepared.manifest.CatalogDigest, Observations: []bench.Observation{observation}}
	if err := set.Validate(); err != nil {
		return CaptureResult{}, fmt.Errorf("validate captured observation: %w", err)
	}
	return newCaptureResult(observation, evidence, evidenceJSON, prepared.profileJSON, prepared), nil
}

func newProcessEvidence(result ports.ToolResult, runErr, contextErr error, paths []string, maxOutputBytes int) *ProcessEvidence {
	stdout, stderr, redacted := redactOutput(result.Stdout, result.Stderr, paths)
	stdout, stderr, locallyTruncated := boundProcessStreams(stdout, stderr, maxOutputBytes)
	if stdout == nil {
		stdout = []byte{}
	}
	if stderr == nil {
		stderr = []byte{}
	}
	exitKnown := runErr == nil && contextErr == nil
	exitCode := 0
	if exitKnown {
		exitCode = result.ExitCode
	}
	return &ProcessEvidence{
		ExitKnown:         exitKnown,
		ExitCode:          exitCode,
		RunnerError:       runErr != nil,
		Cancelled:         contextErr != nil,
		TimedOut:          result.TimedOut,
		Truncated:         result.Truncated || locallyTruncated,
		ConnectEventCount: len(result.ConnectLog),
		Redacted:          redacted,
		Stdout:            stdout,
		Stderr:            stderr,
	}
}

func boundProcessStreams(stdout, stderr []byte, maxOutputBytes int) ([]byte, []byte, bool) {
	if maxOutputBytes < 0 {
		return nil, nil, true
	}
	if len(stdout) <= maxOutputBytes {
		remaining := maxOutputBytes - len(stdout)
		if len(stderr) <= remaining {
			return stdout, stderr, false
		}
		return stdout, append([]byte(nil), stderr[:remaining]...), true
	}
	return append([]byte(nil), stdout[:maxOutputBytes]...), nil, true
}

func cloneProcessEvidence(process *ProcessEvidence) *ProcessEvidence {
	if process == nil {
		return nil
	}
	copy := *process
	copy.Stdout = append([]byte(nil), process.Stdout...)
	copy.Stderr = append([]byte(nil), process.Stderr...)
	return &copy
}

func cloneEvidence(evidence Evidence) Evidence {
	copy := evidence
	copy.VersionProbe = cloneProcessEvidence(evidence.VersionProbe)
	copy.Scan = cloneProcessEvidence(evidence.Scan)
	if evidence.Capability != nil {
		capability := *evidence.Capability
		copy.Capability = &capability
	}
	return copy
}

func cloneCapabilitySources(sources []retainedCapabilitySource) []retainedCapabilitySource {
	out := make([]retainedCapabilitySource, len(sources))
	for i, source := range sources {
		out[i] = retainedCapabilitySource{Reference: source.Reference, Digest: source.Digest, Data: append([]byte(nil), source.Data...)}
	}
	return out
}

func classifyProcessFailure(process *ProcessEvidence, engine bench.Engine, probe bool) FailureCode {
	if process == nil {
		return FailureNone
	}
	switch {
	case normalizationInputTooLarge(process):
		return FailureNormalizationInputTooLarge
	case process.Cancelled:
		return FailureCancelled
	case process.TimedOut:
		return FailureTimeout
	case process.RunnerError:
		return FailureRunnerError
	case process.Truncated:
		return FailureOutputTruncated
	case process.ConnectEventCount != 0:
		return FailureConnectEvent
	case !process.ExitKnown:
		return FailureRunnerError
	case probe && process.ExitCode != 0:
		return FailureUnacceptedExit
	case !probe && !acceptedExit(engine, process.ExitCode):
		return FailureUnacceptedExit
	default:
		return FailureNone
	}
}

func normalizationInputTooLarge(process *ProcessEvidence) bool {
	return process != nil && int64(len(process.Stdout)) > maxNormalizationInputBytes
}

func parseOSVVersion(data []byte) (string, error) {
	const prefix = "osv-scanner version: "
	line, _, _ := bytes.Cut(data, []byte("\n"))
	if !bytes.HasPrefix(line, []byte(prefix)) {
		return "", errVersionMismatch
	}
	version := string(line[len(prefix):])
	fields := strings.Fields(version)
	if len(fields) != 1 || fields[0] != version {
		return "", errVersionMismatch
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return version, nil
}

func reportedEngineVersion(engine bench.Engine, data []byte) (string, error) {
	switch engine {
	case bench.EngineGrype:
		var wire grypeWire
		if err := decodeEngineJSON(data, &wire, "descriptor", "matches"); err != nil {
			return "", err
		}
		return wire.Descriptor.Version, nil
	case bench.EngineTrivy:
		var wire trivyWire
		if err := decodeEngineJSON(data, &wire, "SchemaVersion", "Trivy", "Results"); err != nil {
			return "", err
		}
		return wire.Trivy.Version, nil
	case bench.EngineOwned:
		var wire ownedWire
		if err := decodeEngineJSON(data, &wire, "schema_version", "engine_version", "advisories_ingested", "advisories_skipped", "findings"); err != nil {
			return "", err
		}
		return wire.EngineVersion, nil
	default:
		return "", nil
	}
}

func observationFromPrepared(prepared preparedCapture, state bench.ObservationState, rawOutputDigest string, findings []bench.Finding) bench.Observation {
	return bench.Observation{
		SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: prepared.catalog.Revision,
		CatalogDigest: prepared.manifest.CatalogDigest, Engine: prepared.manifest.Engine,
		EngineVersion: prepared.manifest.EngineVersion, EngineBinaryDigest: prepared.binaryDigest,
		DatabaseBuild: prepared.manifest.Database.Build, DatabaseDigest: prepared.databaseDigest,
		EnvironmentID: prepared.manifest.Environment.ID, EnvironmentDigest: prepared.environmentDigest,
		TargetID: prepared.target.ID, TargetDigest: prepared.target.Digest, SBOMDigest: prepared.target.SBOMDigest,
		State: state, RawOutputDigest: rawOutputDigest, ConfigDigest: prepared.configDigest,
		Findings: findings,
	}
}

func observationExceedsLimit(observation bench.Observation) (bool, error) {
	set := bench.ObservationSet{SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: observation.CatalogRevision, CatalogDigest: observation.CatalogDigest, Observations: []bench.Observation{observation}}
	if err := set.Validate(); err != nil {
		return false, fmt.Errorf("validate provisional observation: %w", err)
	}
	encoded, err := bench.CanonicalJSON(set)
	if err != nil {
		return false, fmt.Errorf("encode provisional observation: %w", err)
	}
	encoded = append(encoded, '\n')
	return int64(len(encoded)) > bench.MaxJSONBytes, nil
}

func cloneTarget(target bench.Target) bench.Target {
	copy := target
	copy.Components = append([]bench.Component(nil), target.Components...)
	return copy
}

func cloneProfile(profile ExecutionProfile) ExecutionProfile {
	copy := profile
	copy.ArgvTemplate = cloneStrings(profile.ArgvTemplate)
	copy.VersionProbeArgvTemplate = cloneStrings(profile.VersionProbeArgvTemplate)
	copy.EnvironmentTemplate = cloneStrings(profile.EnvironmentTemplate)
	return copy
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func newCaptureResult(observation bench.Observation, evidence Evidence, evidenceJSON, profileJSON []byte, prepared preparedCapture) CaptureResult {
	var statementJSON []byte
	var sources []retainedCapabilitySource
	if prepared.capability != nil {
		statementJSON = append([]byte(nil), prepared.capability.statementJSON...)
		sources = cloneCapabilitySources(prepared.capability.sources)
	}
	binding := resultBinding{
		valid: true, observation: cloneObservation(observation), target: cloneTarget(prepared.target),
		components: append([]sbom.Component(nil), prepared.components...), profile: cloneProfile(prepared.profile), evidence: cloneEvidence(evidence),
		evidenceJSON: append([]byte(nil), evidenceJSON...), profileJSON: append([]byte(nil), profileJSON...),
		environmentJSON: append([]byte(nil), prepared.environmentJSON...), environmentAttestationJSON: append([]byte(nil), prepared.environmentAttestationJSON...),
		capabilityStatementJSON: append([]byte(nil), statementJSON...), capabilitySources: cloneCapabilitySources(sources),
	}
	return CaptureResult{
		observation: cloneObservation(observation), evidence: cloneEvidence(evidence), evidenceJSON: append([]byte(nil), evidenceJSON...), profileJSON: append([]byte(nil), profileJSON...),
		environmentJSON: append([]byte(nil), prepared.environmentJSON...), environmentAttestationJSON: append([]byte(nil), prepared.environmentAttestationJSON...),
		capabilityStatementJSON: append([]byte(nil), statementJSON...), capabilitySources: cloneCapabilitySources(sources), binding: binding,
	}
}

func verifyPreparedInputs(prepared preparedCapture) error {
	_, binaryDigest, err := verifyRegularFile(prepared.binaryPath)
	if err != nil || binaryDigest != prepared.binaryDigest {
		return errors.New("binary changed after dispatch")
	}
	_, sbomDigest, err := verifyRegularFile(prepared.sbomPath)
	if err != nil || sbomDigest != prepared.target.SBOMDigest {
		return errors.New("SBOM changed after dispatch")
	}
	_, databaseDigest, err := verifyDatabasePath(prepared.databasePath)
	if err != nil || databaseDigest != prepared.databaseDigest {
		return errors.New("database changed after dispatch")
	}
	_, environmentAttestationDigest, err := verifyRegularFile(prepared.environmentPath)
	if err != nil || environmentAttestationDigest != prepared.environmentAttestationDigest {
		return errors.New("environment attestation changed after dispatch")
	}
	return nil
}

func verifyPostflight(prepared preparedCapture, generatedPaths ...string) error {
	if err := verifyPreparedInputs(prepared); err != nil {
		return err
	}
	if len(generatedPaths) != 2 {
		return errors.New("generated configuration paths are incomplete")
	}
	_, configDigest, err := verifyRegularFile(generatedPaths[0])
	if err != nil || configDigest != prepared.profile.ConfigContentDigest {
		return errors.New("generated configuration changed after dispatch")
	}
	_, ignoreDigest, err := verifyRegularFile(generatedPaths[1])
	if err != nil || ignoreDigest != prepared.profile.IgnoreContentDigest {
		return errors.New("generated ignore file changed after dispatch")
	}
	return nil
}

func buildProfile(engine bench.Engine, databaseFormat DatabaseFormat, limits RuntimeLimits) (ExecutionProfile, []byte, []byte, error) {
	if err := limits.validate(); err != nil {
		return ExecutionProfile{}, nil, nil, err
	}
	if !validDatabaseFormatForEngine(engine, databaseFormat) {
		return ExecutionProfile{}, nil, nil, fmt.Errorf("database format %q is not supported by engine %q", databaseFormat, engine)
	}
	config, ignore := []byte{}, []byte{}
	profile := ExecutionProfile{
		SchemaVersion:      ProfileSchemaVersion,
		Engine:             engine,
		DatabaseFormat:     databaseFormat,
		NoNetwork:          true,
		AutoUpdateDisabled: true,
		Limits:             limits,
	}
	switch engine {
	case bench.EngineGrype:
		profile.ExecutionMode = "external"
		profile.ArgvTemplate = []string{"sbom:{sbom}", "-o", "json", "-q", "--config", "{config}"}
		profile.EnvironmentTemplate = []string{"GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_CACHE_DIR={db}", "GRYPE_DB_AUTO_UPDATE=false", "GRYPE_DB_VALIDATE_AGE=false", "GRYPE_DB_VALIDATE_BY_HASH_ON_START=true"}
		profile.OutputFormat = "grype-json"
	case bench.EngineTrivy:
		config = []byte("{}\n")
		profile.ExecutionMode = "external"
		profile.ArgvTemplate = []string{"sbom", "--format", "json", "--scanners", "vuln", "--cache-dir", "{db}", "--config", "{config}", "--ignorefile", "{ignore}", "--skip-db-update", "--skip-java-db-update", "--skip-version-check", "--skip-vex-repo-update", "--offline-scan", "--disable-telemetry", "--quiet", "--exit-code", "0", "{sbom}"}
		profile.EnvironmentTemplate = []string{}
		profile.OutputFormat = "trivy-json"
	case bench.EngineOSVScanner:
		// osv-scanner expects TOML; empty bytes are a valid empty TOML document.
		config = []byte{}
		profile.ExecutionMode = "external"
		profile.ArgvTemplate = []string{"scan", "source", "--offline", "--offline-vulnerabilities", "--experimental-no-default-plugins", "--experimental-plugins=lockfile", "--experimental-plugins=sbom", "--format", "json", "--config={config}", "--lockfile={sbom}"}
		profile.VersionProbeArgvTemplate = []string{"--version"}
		profile.EnvironmentTemplate = []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={db}"}
		profile.OutputFormat = "osv-scanner-v2-json"
	case bench.EngineOwned:
		profile.ExecutionMode = "external"
		profile.ArgvTemplate = []string{"--owned-helper", "--database", "{db}", "--database-format", "{database_format}", "--sbom", "{sbom}"}
		profile.EnvironmentTemplate = []string{}
		profile.OutputFormat = "synapse-owned-wire-v2"
	default:
		return ExecutionProfile{}, nil, nil, fmt.Errorf("unsupported engine %q", engine)
	}
	profile.ConfigContentDigest = bench.SHA256Digest(config)
	profile.IgnoreContentDigest = bench.SHA256Digest(ignore)
	return profile, config, ignore, nil
}

func instantiateProfile(profile ExecutionProfile, sbomPath, databasePath, configPath, ignorePath string) ([]string, []string, error) {
	replace := func(value string) (string, error) {
		template := value
		for _, placeholder := range []string{"{sbom}", "{db}", "{config}", "{ignore}", "{database_format}"} {
			template = strings.ReplaceAll(template, placeholder, "")
		}
		if strings.Contains(template, "{") || strings.Contains(template, "}") {
			return "", fmt.Errorf("unrecognized profile placeholder in %q", value)
		}
		replacer := strings.NewReplacer(
			"{sbom}", sbomPath,
			"{db}", databasePath,
			"{config}", configPath,
			"{ignore}", ignorePath,
			"{database_format}", string(profile.DatabaseFormat),
		)
		return replacer.Replace(value), nil
	}
	args := make([]string, len(profile.ArgvTemplate))
	for i, arg := range profile.ArgvTemplate {
		value, err := replace(arg)
		if err != nil {
			return nil, nil, err
		}
		args[i] = value
	}
	env := make([]string, len(profile.EnvironmentTemplate))
	for i, value := range profile.EnvironmentTemplate {
		resolved, err := replace(value)
		if err != nil {
			return nil, nil, err
		}
		env[i] = resolved
	}
	return args, env, nil
}

func writeVerifiedConfig(dir, name string, data []byte, wantDigest string) (string, error) {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write generated %s", name)
	}
	verified, digest, err := verifyRegularFile(path)
	if err != nil {
		return "", fmt.Errorf("verify generated %s", name)
	}
	if digest != wantDigest {
		return "", fmt.Errorf("generated %s digest does not match execution profile", name)
	}
	return verified, nil
}

func acceptedExit(engine bench.Engine, exitCode int) bool {
	return exitCode == 0 || (engine == bench.EngineOSVScanner && exitCode == 1)
}

func knownEngine(engine bench.Engine) bool {
	for _, candidate := range bench.Engines() {
		if engine == candidate {
			return true
		}
	}
	return false
}

func validDatabaseFormatForEngine(engine bench.Engine, format DatabaseFormat) bool {
	switch engine {
	case bench.EngineOwned:
		return format == DatabaseFormatOSVJSON || format == DatabaseFormatOVAL
	case bench.EngineGrype:
		return format == DatabaseFormatGrypeDBV6
	case bench.EngineTrivy:
		return format == DatabaseFormatTrivyDBV2
	case bench.EngineOSVScanner:
		return format == DatabaseFormatOSVScannerOffline
	default:
		return false
	}
}

func targetByID(catalog bench.Catalog, id string) (bench.Target, bool) {
	for _, target := range catalog.Targets {
		if target.ID == id {
			return target, true
		}
	}
	return bench.Target{}, false
}

func requirePin(catalog bench.Catalog, reference, want, subject string) error {
	for _, pin := range catalog.Pins {
		if pin.Reference == reference {
			if pin.Digest != want {
				return fmt.Errorf("catalog %s pin does not match verified digest", subject)
			}
			return nil
		}
	}
	return fmt.Errorf("catalog %s pin %q is required", subject, reference)
}

func verifyCatalogComponents(want []bench.Component, got []sbom.Component) error {
	type expectedComponent struct {
		component bench.Component
		key       bench.ComponentBenchmarkKey
	}
	expected := make([]expectedComponent, 0, len(want))
	benchmarkScopes := make(map[componentPackageScope]struct{}, len(want))
	seenExpected := make(map[bench.ComponentBenchmarkKey]struct{}, len(want))
	for _, component := range want {
		key, err := bench.ComponentKey(component, "capture-component")
		if err != nil {
			return fmt.Errorf("catalog component has invalid structural identity: %w", err)
		}
		if _, exists := seenExpected[key]; exists {
			return fmt.Errorf("catalog component %q@%q has a duplicate structural identity", component.PURL, component.Version)
		}
		seenExpected[key] = struct{}{}
		benchmarkScopes[componentPackageScope{Ecosystem: key.Ecosystem, Package: key.Package}] = struct{}{}
		expected = append(expected, expectedComponent{component: component, key: key})
	}

	present := make(map[bench.ComponentBenchmarkKey]int, len(got))
	for _, component := range got {
		if strings.TrimSpace(component.PURL) == "" {
			continue
		}
		scope, err := purlComponentScope(component.PURL)
		if err != nil {
			return fmt.Errorf("SBOM component has invalid package scope: %w", err)
		}
		if _, benchmarked := benchmarkScopes[scope]; !benchmarked {
			continue
		}
		key, err := bench.ComponentKey(bench.Component{PURL: component.PURL, Version: component.Version}, "capture-component")
		if err != nil {
			return fmt.Errorf("SBOM component has invalid structural identity: %w", err)
		}
		present[key]++
	}
	for _, component := range expected {
		switch present[component.key] {
		case 0:
			return fmt.Errorf("catalog component %q@%q is absent from SBOM", component.component.PURL, component.component.Version)
		case 1:
			// Exact structural identity is present.
		default:
			return fmt.Errorf("catalog component %q@%q maps to ambiguous SBOM components", component.component.PURL, component.component.Version)
		}
	}
	return nil
}

func cloneCatalog(catalog bench.Catalog) bench.Catalog {
	copy := catalog
	copy.Targets = make([]bench.Target, len(catalog.Targets))
	for i, target := range catalog.Targets {
		copy.Targets[i] = target
		copy.Targets[i].Components = append([]bench.Component(nil), target.Components...)
	}
	copy.Pins = append([]bench.ArtifactPin(nil), catalog.Pins...)
	return copy
}

func cloneObservation(observation bench.Observation) bench.Observation {
	copy := observation
	copy.Findings = append([]bench.Finding(nil), observation.Findings...)
	return copy
}

func copyRegularSnapshot(source, destination string) (string, error) {
	before, err := os.Lstat(source)
	if err != nil {
		return "", errors.New("inspect source regular file")
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return "", errors.New("source path must be a regular non-symlink file")
	}
	input, err := os.Open(source)
	if err != nil {
		return "", errors.New("open source regular file")
	}
	defer func() { _ = input.Close() }()
	opened, err := input.Stat()
	if err != nil || !sameStableFile(before, opened) {
		return "", errors.New("source regular file changed while opening")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", errors.New("create private snapshot file")
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return "", errors.New("copy private snapshot file")
	}
	after, err := os.Lstat(source)
	if err != nil || !sameStableFile(before, after) {
		return "", errors.New("source regular file changed while copying")
	}
	_, digest, err := verifyRegularFile(destination)
	if err != nil || digest != "sha256:"+hex.EncodeToString(hash.Sum(nil)) {
		return "", errors.New("verify private snapshot file")
	}
	return digest, nil
}

type boundedSnapshotWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *boundedSnapshotWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("regular file exceeds bounded snapshot limit")
	}
	written, err := w.writer.Write(data)
	w.remaining -= int64(written)
	return written, err
}

func copyBoundedRegularSnapshot(source, destination string, requireNonEmpty bool) (string, []byte, error) {
	before, err := os.Lstat(source)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > maxManifestBytes || (requireNonEmpty && before.Size() == 0) {
		return "", nil, errors.New("source must be a bounded regular non-symlink file")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", nil, errors.New("create private bounded snapshot file")
	}
	hash := sha256.New()
	writer := &boundedSnapshotWriter{writer: io.MultiWriter(output, hash), remaining: maxManifestBytes}
	_, copyErr := streamStableRegularFile(source, before, writer)
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return "", nil, errors.New("copy private bounded snapshot file")
	}
	_, digest, err := verifyRegularFile(destination)
	if err != nil || digest != "sha256:"+hex.EncodeToString(hash.Sum(nil)) {
		return "", nil, errors.New("verify private bounded snapshot file")
	}
	data, err := os.ReadFile(destination)
	if err != nil || int64(len(data)) > maxManifestBytes || (requireNonEmpty && len(data) == 0) || bench.SHA256Digest(data) != digest {
		return "", nil, errors.New("read private bounded snapshot file")
	}
	return digest, data, nil
}

func copyExecutableSnapshot(source, destination string) (string, error) {
	digest, err := copyRegularSnapshot(source, destination)
	if err != nil {
		return "", err
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		return "", errors.New("make private binary snapshot executable")
	}
	return digest, nil
}

func copyDatabaseSnapshot(source, destination string) (string, int, error) {
	before, err := os.Lstat(source)
	if err != nil {
		return "", 0, errors.New("inspect source database")
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return "", 0, errors.New("database source must be a non-symlink directory")
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return "", 0, errors.New("create private database snapshot")
	}
	files, err := copyDatabaseTree(source, destination, before)
	if err != nil {
		return "", 0, err
	}
	after, err := os.Lstat(source)
	if err != nil || !sameStableFile(before, after) {
		return "", 0, errors.New("source database changed while copying")
	}
	digest, err := HashTree(destination)
	if err != nil {
		return "", 0, errors.New("verify private database snapshot")
	}
	return digest, files, nil
}

func copyDatabaseTree(source, destination string, expected os.FileInfo) (int, error) {
	entries, err := os.ReadDir(source)
	if err != nil {
		return 0, errors.New("read source database directory")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	files := 0
	for _, entry := range entries {
		sourcePath := filepath.Join(source, entry.Name())
		destinationPath := filepath.Join(destination, entry.Name())
		info, err := os.Lstat(sourcePath)
		if err != nil {
			return 0, errors.New("inspect source database entry")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return 0, errors.New("source database contains symlink")
		}
		switch {
		case info.IsDir():
			if err := os.Mkdir(destinationPath, 0o700); err != nil {
				return 0, errors.New("create private database directory")
			}
			count, err := copyDatabaseTree(sourcePath, destinationPath, info)
			if err != nil {
				return 0, err
			}
			files += count
		case info.Mode().IsRegular():
			if _, err := copyRegularSnapshot(sourcePath, destinationPath); err != nil {
				return 0, err
			}
			files++
		default:
			return 0, errors.New("source database contains special file")
		}
	}
	after, err := os.Lstat(source)
	if err != nil || !sameStableFile(expected, after) {
		return 0, errors.New("source database directory changed while copying")
	}
	return files, nil
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func verifyRegularFile(path string) (string, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", errors.New("resolve regular file path")
	}
	hash := sha256.New()
	if _, err := streamStableRegularFile(absolute, nil, hash); err != nil {
		return "", "", errors.New("verify regular file")
	}
	return absolute, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyDatabasePath(path string) (string, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", errors.New("resolve database path")
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", "", errors.New("inspect database path")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", fmt.Errorf("database path must be a non-symlink directory")
	}
	digest, err := hashTree(absolute)
	if err != nil {
		return "", "", errors.New("verify database tree")
	}
	return absolute, digest, nil
}

// HashTree deterministically hashes a directory tree. Each path and file size is
// framed before that file's bytes stream into the hash, so adjacent names or files
// cannot create an ambiguous hash input.
func HashTree(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("resolve tree path")
	}
	return hashTree(absolute)
}

func hashTree(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return "", errors.New("inspect tree root")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("tree root must be a non-symlink directory")
	}
	hash := sha256.New()
	if err := hashTreeDir(hash, root, "", info); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func hashTreeDir(hash io.Writer, dir, relative string, expected os.FileInfo) error {
	if expected.Mode()&os.ModeSymlink != 0 || !expected.IsDir() {
		return fmt.Errorf("tree contains non-directory at %q", filepath.ToSlash(relative))
	}
	if err := writeFrame(hash, "directory", filepath.ToSlash(relative)); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.New("read tree directory")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(dir, name)
		rel := name
		if relative != "" {
			rel = filepath.Join(relative, name)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return errors.New("inspect tree entry")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("tree contains symlink %q", filepath.ToSlash(rel))
		}
		switch {
		case info.IsDir():
			if err := hashTreeDir(hash, path, rel, info); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := writeFrame(hash, "file", filepath.ToSlash(rel), strconv.FormatInt(info.Size(), 10)); err != nil {
				return err
			}
			if _, err := streamStableRegularFile(path, info, hash); err != nil {
				return fmt.Errorf("hash tree file %q", filepath.ToSlash(rel))
			}
		default:
			return fmt.Errorf("tree contains special file %q", filepath.ToSlash(rel))
		}
	}
	after, err := os.Lstat(dir)
	if err != nil || !sameStableFile(expected, after) {
		return fmt.Errorf("tree directory changed while hashing %q", filepath.ToSlash(relative))
	}
	return nil
}

// streamStableRegularFile streams a regular file after pinning its path identity and
// metadata. It rejects replacement or mutation while hashing instead of loading a
// competitor database artifact into memory.
func streamStableRegularFile(path string, expected os.FileInfo, writer io.Writer) (int64, error) {
	if expected == nil {
		info, err := os.Lstat(path)
		if err != nil {
			return 0, errors.New("inspect regular file")
		}
		expected = info
	}
	if expected.Mode()&os.ModeSymlink != 0 || !expected.Mode().IsRegular() {
		return 0, fmt.Errorf("path must be a regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, errors.New("open regular file")
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return 0, errors.New("inspect opened regular file")
	}
	if !sameStableFile(expected, opened) {
		_ = file.Close()
		return 0, fmt.Errorf("file changed while opening")
	}
	written, copyErr := io.Copy(writer, file)
	closeErr := file.Close()
	if copyErr != nil {
		return 0, errors.New("read regular file")
	}
	if closeErr != nil {
		return 0, errors.New("close regular file")
	}
	after, err := os.Lstat(path)
	if err != nil || !sameStableFile(expected, after) || written != expected.Size() {
		return 0, fmt.Errorf("file changed while verifying")
	}
	return written, nil
}

func sameStableFile(before, after os.FileInfo) bool {
	return before != nil && after != nil &&
		before.Mode()&os.ModeSymlink == 0 && after.Mode()&os.ModeSymlink == 0 &&
		before.Mode().IsRegular() == after.Mode().IsRegular() &&
		before.IsDir() == after.IsDir() &&
		os.SameFile(before, after) &&
		before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime())
}

func writeFrame(writer io.Writer, parts ...string) error {
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		if _, err := writer.Write(length[:]); err != nil {
			return err
		}
		if _, err := io.WriteString(writer, part); err != nil {
			return err
		}
	}
	return nil
}

func redactOutput(stdout, stderr []byte, paths []string) ([]byte, []byte, bool) {
	pattern := pathRedactionPattern(paths)
	redactedStdout := redactPathsAndURLCredentials(stdout, pattern)
	redactedStderr := redactPathsAndURLCredentials(stderr, pattern)
	return redactedStdout, redactedStderr, !bytes.Equal(stdout, redactedStdout) || !bytes.Equal(stderr, redactedStderr)
}

func pathRedactionPattern(paths []string) *regexp.Regexp {
	forms := make(map[string]struct{}, len(paths)*6)
	for _, path := range paths {
		for _, variant := range []string{path, filepath.ToSlash(path), strings.ReplaceAll(path, "/", "\\")} {
			if variant == "" {
				continue
			}
			forms[variant] = struct{}{}
			quoted := strconv.Quote(variant)
			forms[quoted[1:len(quoted)-1]] = struct{}{}
		}
	}
	patterns := make([]string, 0, len(forms))
	for form := range forms {
		patterns = append(patterns, form)
	}
	sort.Slice(patterns, func(i, j int) bool {
		if len(patterns[i]) != len(patterns[j]) {
			return len(patterns[i]) > len(patterns[j])
		}
		return patterns[i] < patterns[j]
	})
	var expression strings.Builder
	// One expression covers every physical path form and credential-bearing URL. This keeps bounded scanner
	// output to one redaction traversal rather than copying it once per known path.
	expression.WriteString(`[a-zA-Z][a-zA-Z0-9+.-]*://[^/@\s]+@`)
	for _, pattern := range patterns {
		expression.WriteByte('|')
		expression.WriteString(regexp.QuoteMeta(pattern))
	}
	return regexp.MustCompile(expression.String())
}

func redactPathsAndURLCredentials(data []byte, pattern *regexp.Regexp) []byte {
	if len(data) == 0 {
		return data
	}
	return pattern.ReplaceAllFunc(data, func(match []byte) []byte {
		if schemeEnd := bytes.Index(match, []byte("://")); schemeEnd >= 0 {
			redacted := make([]byte, 0, schemeEnd+3+len("***@"))
			redacted = append(redacted, match[:schemeEnd+3]...)
			return append(redacted, "***@"...)
		}
		return []byte(redact.Placeholder)
	})
}

// rawOutputDigest binds the exact canonical Evidence JSON bytes, including retained
// redacted streams and stable execution metadata, to an observation.
func rawOutputDigest(evidenceJSON []byte) string {
	return bench.SHA256Digest(evidenceJSON)
}

func canonicalJSON(value any) ([]byte, error) { return json.Marshal(value) }

func canonicalFindings(findings []bench.Finding) []bench.Finding {
	type entry struct {
		key     string
		finding bench.Finding
	}
	seen := make(map[string]entry, len(findings))
	for _, finding := range findings {
		key, canonical := canonicalFinding(finding)
		seen[key] = entry{key: key, finding: canonical}
	}
	entries := make([]entry, 0, len(seen))
	for _, finding := range seen {
		entries = append(entries, finding)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	out := make([]bench.Finding, len(entries))
	for i, finding := range entries {
		out[i] = finding.finding
	}
	return out
}

func canonicalFinding(finding bench.Finding) (string, bench.Finding) {
	key, err := bench.ComponentKey(finding.Component, finding.AdvisoryID)
	if err != nil {
		return finding.Component.PURL + "\x00" + finding.Component.Version + "\x00" + finding.AdvisoryID, finding
	}
	finding.AdvisoryID = key.Advisory
	return key.Ecosystem + "\x00" + key.Package + "\x00" + key.Version + "\x00" + key.Advisory, finding
}

func canonicalAdvisoryID(component bench.Component, identifier string) string {
	key, err := bench.ComponentKey(component, identifier)
	if err != nil {
		return strings.TrimSpace(identifier)
	}
	return key.Advisory
}

func strictDecodeManifest(reader io.Reader, destination any) error {
	return strictDecodeCaptureJSON(reader, destination, validateManifestShape)
}

func strictDecodeCapabilityStatement(reader io.Reader, destination any) error {
	return strictDecodeCaptureJSON(reader, destination, validateCapabilityStatementShape)
}

func strictDecodeCaptureJSON(reader io.Reader, destination any, validateShape func(any, string) error) error {
	raw, err := io.ReadAll(io.LimitReader(reader, maxManifestBytes+1))
	if err != nil {
		return fmt.Errorf("read JSON: %w", err)
	}
	if int64(len(raw)) > maxManifestBytes {
		return fmt.Errorf("JSON input exceeds %d byte limit", maxManifestBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("JSON input is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeManifestValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("JSON input must contain exactly one top-level value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	shapeDecoder := json.NewDecoder(bytes.NewReader(raw))
	shapeDecoder.UseNumber()
	var shape any
	if err := shapeDecoder.Decode(&shape); err != nil {
		return fmt.Errorf("decode JSON shape: %w", err)
	}
	if err := validateShape(shape, ""); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid JSON shape: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON input must contain exactly one top-level value")
	}
	return nil
}

func consumeManifestValue(decoder *json.Decoder, depth int) error {
	if depth > maxManifestDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxManifestDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeManifestValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeManifestValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delimiter)
	}
	return nil
}

func validateManifestShape(value any, path string) error {
	object, ok := value.(map[string]any)
	if !ok {
		if path == "" {
			return errors.New("capture manifest must be a JSON object")
		}
		return nil
	}
	allowed := map[string]map[string]struct{}{
		"": {
			"schema_version": {}, "catalog_revision": {}, "catalog_digest": {}, "target_id": {}, "sbom_path": {}, "engine": {}, "engine_version": {}, "binary": {}, "database": {}, "environment": {}, "environment_attestation": {}, "environment_pin_reference": {}, "profile_pin_reference": {}, "limits": {}, "capability": {},
		},
		"binary":                  {"reference": {}, "path": {}},
		"database":                {"reference": {}, "path": {}, "build": {}, "format": {}},
		"environment":             {"id": {}, "goos": {}, "goarch": {}, "image_digest": {}, "sandbox_identity": {}},
		"environment_attestation": {"reference": {}, "path": {}},
		"limits":                  {"timeout_seconds": {}, "max_output_bytes": {}, "memory_bytes": {}, "pids_max": {}},
	}
	fields, known := allowed[path]
	if !known {
		return fmt.Errorf("capture manifest contains an object at invalid path %q", path)
	}
	for name, child := range object {
		if _, known := fields[name]; !known {
			return fmt.Errorf("capture manifest contains unknown field %q", name)
		}
		switch name {
		case "binary", "database", "environment", "environment_attestation", "limits":
			if err := validateManifestShape(child, name); err != nil {
				return err
			}
		case "capability":
			if err := validateCapabilityManifestShape(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCapabilityManifestShape(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return errors.New("capability must be a JSON object")
	}
	for name, child := range object {
		switch name {
		case "statement":
			if err := validateCapabilityArtifactShape(child); err != nil {
				return err
			}
		case "sources":
			array, ok := child.([]any)
			if !ok {
				return errors.New("capability sources must be an array")
			}
			for _, source := range array {
				if err := validateCapabilityArtifactShape(source); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("capture manifest contains unknown capability field %q", name)
		}
	}
	return nil
}

func validateCapabilityArtifactShape(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return errors.New("capability artifact must be a JSON object")
	}
	for name := range object {
		if name != "reference" && name != "path" && name != "digest" {
			return fmt.Errorf("capture manifest contains unknown capability artifact field %q", name)
		}
	}
	return nil
}

func validateCapabilityStatementShape(value any, path string) error {
	object, ok := value.(map[string]any)
	if !ok {
		if path == "" {
			return errors.New("capability statement must be a JSON object")
		}
		return nil
	}
	allowed := map[string]map[string]struct{}{
		"": {
			"schema_version": {}, "kind": {}, "decision_rule_revision": {}, "scope": {}, "catalog_revision": {}, "catalog_digest": {}, "target_id": {}, "target_digest": {}, "sbom_digest": {}, "engine": {}, "engine_version": {}, "engine_binary_digest": {}, "database_build": {}, "database_digest": {}, "environment_id": {}, "environment_digest": {}, "config_digest": {}, "components": {}, "sources": {},
		},
		"components": {"purl": {}, "version": {}},
		"sources":    {"reference": {}, "digest": {}},
	}
	fields, known := allowed[path]
	if !known {
		return fmt.Errorf("capability statement contains an object at invalid path %q", path)
	}
	for name, child := range object {
		if _, known := fields[name]; !known {
			return fmt.Errorf("capability statement contains unknown field %q", name)
		}
		switch name {
		case "components", "sources":
			array, ok := child.([]any)
			if !ok {
				return fmt.Errorf("capability statement field %q must be an array", name)
			}
			for _, item := range array {
				if err := validateCapabilityStatementShape(item, name); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// simpleCaseFoldKey canonicalizes Unicode simple-fold equivalence classes, matching the
// case-insensitive matching semantics used by encoding/json without an O(n²) key scan.
func simpleCaseFoldKey(value string) string {
	var folded strings.Builder
	folded.Grow(len(value))
	for _, runeValue := range value {
		canonical := runeValue
		for next := unicode.SimpleFold(runeValue); next != runeValue; next = unicode.SimpleFold(next) {
			if next < canonical {
				canonical = next
			}
		}
		folded.WriteRune(canonical)
	}
	return folded.String()
}

func consumeEngineJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxManifestDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxManifestDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]string{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			folded := simpleCaseFoldKey(key)
			if prior, exists := seen[folded]; exists {
				if prior == key {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				return fmt.Errorf("case-fold duplicate JSON keys %q and %q", prior, key)
			}
			seen[folded] = key
			if err := consumeEngineJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeEngineJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delimiter)
	}
	return nil
}

func decodeEngineJSON(data []byte, destination any, required ...string) error {
	if !utf8.Valid(data) {
		return errors.New("engine output is not valid UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeEngineJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("engine output must contain exactly one top-level value")
		}
		return fmt.Errorf("invalid trailing engine output: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decode engine output fields: %w", err)
	}
	for _, name := range required {
		value, present := fields[name]
		if !present || len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("engine output requires %q", name)
		}
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode engine output: %w", err)
	}
	return nil
}

type grypeWire struct {
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
	Matches []struct {
		Vulnerability struct {
			ID string `json:"id"`
		} `json:"vulnerability"`
		Artifact struct {
			PURL    string `json:"purl"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

type trivyWire struct {
	SchemaVersion json.RawMessage `json:"SchemaVersion"`
	Trivy         struct {
		Version string `json:"Version"`
	} `json:"Trivy"`
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			PkgIdentifier   struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			InstalledVersion string `json:"InstalledVersion"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type osvGroup struct {
	IDs     []string `json:"ids"`
	Aliases []string `json:"aliases"`
}

type osvVulnerability struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type osvPackageIdentity struct {
	Name          string `json:"name"`
	Ecosystem     string `json:"ecosystem"`
	Version       string `json:"version"`
	OSPackageName string `json:"os_package_name"`
}

type osvPackage struct {
	Package         osvPackageIdentity `json:"package"`
	OSPackageName   string             `json:"os_package_name"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
	Groups          []osvGroup         `json:"groups"`
}

type osvResult struct {
	Packages []osvPackage `json:"packages"`
	Groups   []osvGroup   `json:"groups"`
}

type osvWire struct {
	Results []osvResult `json:"results"`
}

type ownedWireFinding struct {
	PURL       string `json:"purl"`
	Version    string `json:"version"`
	AdvisoryID string `json:"advisory_id"`
}

type ownedWire struct {
	SchemaVersion      string             `json:"schema_version"`
	EngineVersion      string             `json:"engine_version"`
	AdvisoriesIngested int                `json:"advisories_ingested"`
	AdvisoriesSkipped  int                `json:"advisories_skipped"`
	Findings           []ownedWireFinding `json:"findings"`
}

func parseEngine(engine bench.Engine, expectedVersion string, data []byte, target bench.Target, components []sbom.Component, databaseFormat DatabaseFormat) ([]bench.Finding, error) {
	switch engine {
	case bench.EngineGrype:
		return parseGrype(expectedVersion, data, target)
	case bench.EngineTrivy:
		return parseTrivy(expectedVersion, data, target)
	case bench.EngineOSVScanner:
		return parseOSV(data, target)
	case bench.EngineOwned:
		return parseOwned(expectedVersion, data, target, databaseFormat)
	default:
		return nil, errParser
	}
}

func catalogEcosystems(target bench.Target) (map[string]struct{}, error) {
	ecosystems := make(map[string]struct{}, len(target.Components))
	for _, component := range target.Components {
		key, err := bench.ComponentKey(component, "capture-component")
		if err != nil {
			return nil, fmt.Errorf("catalog component has invalid structural identity: %w", err)
		}
		ecosystems[normalizedEcosystem(key.Ecosystem)] = struct{}{}
	}
	return ecosystems, nil
}

func findingEcosystem(purl, version string) (string, error) {
	scope, err := purlComponentScope(purl)
	if err != nil {
		return "", err
	}
	_, _, parsedVersion, ok := purlIdentity(purl, version)
	if !ok || strings.TrimSpace(parsedVersion) == "" || hasControlCharacter(parsedVersion) {
		return "", errors.New("finding purl version is invalid")
	}
	return normalizedEcosystem(scope.Ecosystem), nil
}

func parseGrype(expectedVersion string, data []byte, target bench.Target) ([]bench.Finding, error) {
	var wire grypeWire
	if err := decodeEngineJSON(data, &wire, "descriptor", "matches"); err != nil || wire.Matches == nil {
		return nil, fmt.Errorf("%w: decode grype JSON", errParser)
	}
	if wire.Descriptor.Name != "grype" {
		return nil, fmt.Errorf("%w: descriptor name", errVersionMismatch)
	}
	if wire.Descriptor.Version != expectedVersion {
		return nil, fmt.Errorf("%w: descriptor version", errVersionMismatch)
	}
	ecosystems, err := catalogEcosystems(target)
	if err != nil {
		return nil, fmt.Errorf("%w: grype catalog ecosystem: %v", errParser, err)
	}
	catalog := indexCatalogComponents(target)
	findings := make([]bench.Finding, 0, len(wire.Matches))
	for _, match := range wire.Matches {
		if strings.TrimSpace(match.Vulnerability.ID) == "" || strings.TrimSpace(match.Artifact.PURL) == "" || strings.TrimSpace(match.Artifact.Version) == "" {
			return nil, fmt.Errorf("%w: incomplete grype match", errParser)
		}
		ecosystem, err := findingEcosystem(match.Artifact.PURL, match.Artifact.Version)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid grype component PURL", errParser)
		}
		if _, inScope := ecosystems[ecosystem]; !inScope {
			continue
		}
		component, ok := catalog.component(match.Artifact.PURL, match.Artifact.Version)
		if !ok {
			return nil, fmt.Errorf("%w: grype component is not a catalog component", errParser)
		}
		findings = append(findings, bench.Finding{Component: component, AdvisoryID: match.Vulnerability.ID})
	}
	return findings, nil
}

func parseTrivy(expectedVersion string, data []byte, target bench.Target) ([]bench.Finding, error) {
	var wire trivyWire
	if err := decodeEngineJSON(data, &wire, "SchemaVersion", "Trivy", "Results"); err != nil || wire.Results == nil {
		return nil, fmt.Errorf("%w: decode trivy JSON", errParser)
	}
	if string(bytes.TrimSpace(wire.SchemaVersion)) != "2" || strings.TrimSpace(wire.Trivy.Version) == "" {
		return nil, fmt.Errorf("%w: unsupported or incomplete trivy descriptor", errParser)
	}
	if wire.Trivy.Version != expectedVersion {
		return nil, fmt.Errorf("%w: trivy version", errVersionMismatch)
	}
	ecosystems, err := catalogEcosystems(target)
	if err != nil {
		return nil, fmt.Errorf("%w: trivy catalog ecosystem: %v", errParser, err)
	}
	catalog := indexCatalogComponents(target)
	var findings []bench.Finding
	for _, result := range wire.Results {
		for _, vulnerability := range result.Vulnerabilities {
			if strings.TrimSpace(vulnerability.VulnerabilityID) == "" || strings.TrimSpace(vulnerability.PkgIdentifier.PURL) == "" || strings.TrimSpace(vulnerability.InstalledVersion) == "" {
				return nil, fmt.Errorf("%w: incomplete trivy vulnerability", errParser)
			}
			ecosystem, err := findingEcosystem(vulnerability.PkgIdentifier.PURL, vulnerability.InstalledVersion)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid trivy component PURL", errParser)
			}
			if _, inScope := ecosystems[ecosystem]; !inScope {
				continue
			}
			component, ok := catalog.component(vulnerability.PkgIdentifier.PURL, vulnerability.InstalledVersion)
			if !ok {
				return nil, fmt.Errorf("%w: trivy component is not a catalog component", errParser)
			}
			findings = append(findings, bench.Finding{Component: component, AdvisoryID: vulnerability.VulnerabilityID})
		}
	}
	return findings, nil
}

func parseOSV(data []byte, target bench.Target) ([]bench.Finding, error) {
	var wire osvWire
	if err := decodeEngineJSON(data, &wire, "results"); err != nil || wire.Results == nil {
		return nil, fmt.Errorf("%w: decode osv-scanner JSON", errParser)
	}
	ecosystems, err := catalogEcosystems(target)
	if err != nil {
		return nil, fmt.Errorf("%w: OSV catalog ecosystem: %v", errParser, err)
	}
	catalog := make(map[string][]bench.Component, len(target.Components))
	for _, component := range target.Components {
		ecosystem, packageName, version, ok := purlIdentity(component.PURL, component.Version)
		if !ok {
			return nil, fmt.Errorf("%w: catalog component has unusable PURL", errParser)
		}
		key := normalizedPackageKey(ecosystem, packageName, version)
		catalog[key] = append(catalog[key], component)
	}
	var findings []bench.Finding
	for _, result := range wire.Results {
		for _, group := range result.Groups {
			if err := validateOSVGroup(group); err != nil {
				return nil, err
			}
		}
		for _, pkg := range result.Packages {
			for _, group := range pkg.Groups {
				if err := validateOSVGroup(group); err != nil {
					return nil, err
				}
			}
			if len(pkg.Vulnerabilities) == 0 {
				continue
			}
			name := pkg.Package.Name
			if strings.TrimSpace(pkg.Package.OSPackageName) != "" {
				name = pkg.Package.OSPackageName
			}
			if strings.TrimSpace(pkg.OSPackageName) != "" {
				name = pkg.OSPackageName
			}
			if strings.TrimSpace(pkg.Package.Ecosystem) == "" || strings.TrimSpace(name) == "" || strings.TrimSpace(pkg.Package.Version) == "" {
				return nil, fmt.Errorf("%w: incomplete OSV package", errParser)
			}
			for _, vulnerability := range pkg.Vulnerabilities {
				if strings.TrimSpace(vulnerability.ID) == "" {
					return nil, fmt.Errorf("%w: OSV vulnerability id is required", errParser)
				}
				for _, alias := range vulnerability.Aliases {
					if strings.TrimSpace(alias) == "" {
						return nil, fmt.Errorf("%w: OSV vulnerability alias is invalid", errParser)
					}
				}
			}
			ecosystem := normalizedEcosystem(pkg.Package.Ecosystem)
			if _, inScope := ecosystems[ecosystem]; !inScope {
				continue
			}
			key := normalizedPackageKey(ecosystem, name, pkg.Package.Version)
			matches := catalog[key]
			if len(matches) != 1 {
				return nil, fmt.Errorf("%w: OSV package does not map to exactly one catalog component", errParser)
			}
			groups := append(append([]osvGroup(nil), result.Groups...), pkg.Groups...)
			representatives := groupRepresentatives(pkg.Vulnerabilities, groups, matches[0])
			for _, representative := range representatives {
				findings = append(findings, bench.Finding{Component: matches[0], AdvisoryID: representative})
			}
		}
	}
	return findings, nil
}

func validateOSVGroup(group osvGroup) error {
	for _, id := range append(append([]string(nil), group.IDs...), group.Aliases...) {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("%w: OSV group identifier is invalid", errParser)
		}
	}
	return nil
}

func groupRepresentatives(vulnerabilities []osvVulnerability, groups []osvGroup, component bench.Component) []string {
	representativeForID := make(map[string]string, len(groups))
	for _, group := range groups {
		ids := append(append([]string(nil), group.IDs...), group.Aliases...)
		representative := deterministicRepresentative(ids, component)
		for _, id := range ids {
			representativeForID[canonicalAdvisoryID(component, id)] = representative
		}
	}
	seen := map[string]struct{}{}
	for _, vulnerability := range vulnerabilities {
		id := strings.TrimSpace(vulnerability.ID)
		if id == "" {
			continue
		}
		representative, exists := representativeForID[canonicalAdvisoryID(component, id)]
		if !exists {
			representative = deterministicRepresentative(append([]string{id}, vulnerability.Aliases...), component)
		}
		if representative != "" {
			seen[representative] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for representative := range seen {
		out = append(out, representative)
	}
	sort.Strings(out)
	return out
}

func deterministicRepresentative(ids []string, component bench.Component) string {
	type candidate struct {
		canonical string
		raw       string
	}
	seen := map[string]candidate{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		canonical := canonicalAdvisoryID(component, id)
		seen[canonical+"\x00"+id] = candidate{canonical: canonical, raw: id}
	}
	if len(seen) == 0 {
		return ""
	}
	candidates := make([]candidate, 0, len(seen))
	for _, candidate := range seen {
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].canonical != candidates[j].canonical {
			return candidates[i].canonical < candidates[j].canonical
		}
		return candidates[i].raw < candidates[j].raw
	})
	return candidates[0].canonical
}

func parseOwned(expectedVersion string, data []byte, target bench.Target, databaseFormat DatabaseFormat) ([]bench.Finding, error) {
	var wire ownedWire
	if err := decodeEngineJSON(data, &wire, "schema_version", "engine_version", "advisories_ingested", "advisories_skipped", "findings"); err != nil || wire.SchemaVersion != "synapse-sca-benchmark-owned-wire-v2" || strings.TrimSpace(wire.EngineVersion) == "" || wire.Findings == nil || wire.AdvisoriesIngested <= 0 || wire.AdvisoriesSkipped < 0 {
		return nil, fmt.Errorf("%w: decode owned wire result", errParser)
	}
	if !validDatabaseFormatForEngine(bench.EngineOwned, databaseFormat) || (wire.AdvisoriesSkipped != 0 && databaseFormat != DatabaseFormatOVAL) {
		return nil, fmt.Errorf("%w: owned advisory ingestion is incomplete", errParser)
	}
	if wire.EngineVersion != expectedVersion {
		return nil, fmt.Errorf("%w: owned helper version", errVersionMismatch)
	}
	catalog := indexCatalogComponents(target)
	findings := make([]bench.Finding, 0, len(wire.Findings))
	for _, finding := range wire.Findings {
		if strings.TrimSpace(finding.PURL) == "" || strings.TrimSpace(finding.Version) == "" || strings.TrimSpace(finding.AdvisoryID) == "" {
			return nil, fmt.Errorf("%w: incomplete owned finding", errParser)
		}
		component, ok := catalog.component(finding.PURL, finding.Version)
		if !ok {
			return nil, fmt.Errorf("%w: owned component is not a catalog component", errParser)
		}
		findings = append(findings, bench.Finding{Component: component, AdvisoryID: finding.AdvisoryID})
	}
	return findings, nil
}

type catalogComponentIndex struct {
	components map[bench.ComponentBenchmarkKey]bench.Component
	ambiguous  map[bench.ComponentBenchmarkKey]struct{}
}

func indexCatalogComponents(target bench.Target) catalogComponentIndex {
	index := catalogComponentIndex{
		components: make(map[bench.ComponentBenchmarkKey]bench.Component, len(target.Components)),
		ambiguous:  make(map[bench.ComponentBenchmarkKey]struct{}),
	}
	for _, component := range target.Components {
		key, err := bench.ComponentKey(component, "capture-component")
		if err != nil {
			continue
		}
		if _, exists := index.components[key]; exists {
			delete(index.components, key)
			index.ambiguous[key] = struct{}{}
			continue
		}
		if _, ambiguous := index.ambiguous[key]; !ambiguous {
			index.components[key] = component
		}
	}
	return index
}

func (index catalogComponentIndex) component(purl, version string) (bench.Component, bool) {
	candidate, err := bench.ComponentKey(bench.Component{PURL: purl, Version: version}, "capture-component")
	if err != nil {
		return bench.Component{}, false
	}
	component, ok := index.components[candidate]
	return component, ok
}

func purlIdentity(purl, fallbackVersion string) (string, string, string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return "", "", "", false
	}
	if delimiter := strings.IndexAny(rest, "?#"); delimiter >= 0 {
		rest = rest[:delimiter]
	}
	typeName, remainder, ok := strings.Cut(rest, "/")
	if !ok || typeName == "" || remainder == "" {
		return "", "", "", false
	}
	version := fallbackVersion
	if before, after, exists := strings.Cut(remainder, "@"); exists {
		remainder, version = before, after
	}
	parts := strings.Split(remainder, "/")
	for i, part := range parts {
		decoded, decodeErr := url.PathUnescape(part)
		if decodeErr != nil || decoded == "" {
			return "", "", "", false
		}
		parts[i] = decoded
	}
	decodedVersion, decodeErr := url.PathUnescape(version)
	if decodeErr != nil || decodedVersion == "" {
		return "", "", "", false
	}
	ecosystem := normalizedEcosystem(typeName)
	name := parts[len(parts)-1]
	switch ecosystem {
	case "npm", "go":
		name = strings.Join(parts, "/")
	case "maven":
		name = strings.Join(parts, ":")
	}
	return ecosystem, strings.ToLower(name), decodedVersion, true
}

func normalizedPackageKey(ecosystem, packageName, version string) string {
	return normalizedEcosystem(ecosystem) + "\x00" + strings.ToLower(strings.TrimSpace(packageName)) + "\x00" + strings.TrimSpace(version)
}

func normalizedEcosystem(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case value == "go" || value == "golang":
		return "go"
	case value == "pypi" || value == "python":
		return "pypi"
	case value == "maven" || value == "mvn":
		return "maven"
	case value == "npm":
		return "npm"
	case value == "deb" || value == "debian" || value == "ubuntu" || strings.HasPrefix(value, "debian:") || strings.HasPrefix(value, "ubuntu:"):
		return "deb"
	case value == "apk" || value == "alpine" || strings.HasPrefix(value, "alpine:"):
		return "apk"
	case value == "rpm" || value == "redhat" || value == "rocky" || value == "fedora" || value == "suse" || strings.HasPrefix(value, "red hat:") || strings.HasPrefix(value, "redhat:") || strings.HasPrefix(value, "rocky:") || strings.HasPrefix(value, "fedora:") || strings.HasPrefix(value, "suse:"):
		return "rpm"
	default:
		return value
	}
}

// RunOwnedWire runs the pinned owned helper operation without acquiring network data.
// It is called only by the sandboxed helper process composed in synapse-sca-bench.
func RunOwnedWire(ctx context.Context, databasePath string, databaseFormat DatabaseFormat, sbomPath, engineVersion string) ([]byte, error) {
	if !validDatabaseFormatForEngine(bench.EngineOwned, databaseFormat) {
		return nil, fmt.Errorf("owned helper does not support database format %q", databaseFormat)
	}
	if strings.TrimSpace(engineVersion) == "" {
		return nil, errors.New("owned helper engine version is required")
	}
	raw, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("read owned SBOM: %w", err)
	}
	components, err := scainput.ParseCycloneDXComponents(raw)
	if err != nil {
		return nil, fmt.Errorf("parse owned CycloneDX SBOM: %w", err)
	}
	findings, stats, err := runOwned(ctx, databasePath, databaseFormat, raw, components)
	if err != nil {
		return nil, err
	}
	wire := ownedWire{SchemaVersion: "synapse-sca-benchmark-owned-wire-v2", EngineVersion: engineVersion, AdvisoriesIngested: stats.Ingested, AdvisoriesSkipped: stats.Skipped, Findings: findings}
	data, err := canonicalJSON(wire)
	if err != nil {
		return nil, fmt.Errorf("encode owned wire result: %w", err)
	}
	return data, nil
}

func runOwned(ctx context.Context, databasePath string, databaseFormat DatabaseFormat, rawSBOM []byte, components []sbom.Component) ([]ownedWireFinding, advisoryingest.Stats, error) {
	feed, err := ownedFeed(databasePath, databaseFormat)
	if err != nil {
		return nil, advisoryingest.Stats{}, err
	}
	store := memory.NewAdvisoryStore()
	ingester, err := advisoryingest.NewService(feed, store)
	if err != nil {
		return nil, advisoryingest.Stats{}, fmt.Errorf("create owned advisory ingester: %w", err)
	}
	stats, err := ingester.Ingest(ctx)
	if err != nil {
		return nil, stats, fmt.Errorf("ingest owned advisory directory: %w", err)
	}
	if stats.Ingested == 0 || (stats.Skipped != 0 && databaseFormat != DatabaseFormatOVAL) {
		return nil, stats, errors.New("owned advisory corpus is incomplete")
	}
	source := ownadvisory.New(store)
	findings, err := source.Scan(ctx, &sbom.SBOM{Components: components, Raw: rawSBOM})
	if err != nil {
		return nil, stats, fmt.Errorf("scan owned advisories: %w", err)
	}
	out := make([]ownedWireFinding, 0, len(findings))
	for _, finding := range findings {
		id := finding.AdvisoryID
		if id == "" {
			id = deterministicRepresentative(finding.Aliases, bench.Component{PURL: finding.PackagePURL, Version: finding.Version})
		}
		if finding.PackagePURL == "" || finding.Version == "" || id == "" {
			return nil, stats, errors.New("owned scanner emitted incomplete finding")
		}
		out = append(out, ownedWireFinding{PURL: finding.PackagePURL, Version: finding.Version, AdvisoryID: id})
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].PURL + "\x00" + out[i].Version + "\x00" + out[i].AdvisoryID
		right := out[j].PURL + "\x00" + out[j].Version + "\x00" + out[j].AdvisoryID
		return left < right
	})
	return out, stats, nil
}

func ownedFeed(directory string, format DatabaseFormat) (ports.AdvisoryFeed, error) {
	if err := inspectOwnedCorpusLayout(directory, format); err != nil {
		return nil, err
	}
	switch format {
	case DatabaseFormatOSVJSON:
		return ownadvisory.NewDirFeed(directory), nil
	case DatabaseFormatOVAL:
		return ownadvisory.NewOVALDirFeed(directory), nil
	default:
		return nil, fmt.Errorf("owned helper does not support database format %q", format)
	}
}

// inspectOwnedCorpusLayout validates only corpus layout and extensions. It intentionally
// does not parse advisory contents; that untrusted work remains inside the owned helper.
func inspectOwnedCorpusLayout(directory string, format DatabaseFormat) error {
	if !validDatabaseFormatForEngine(bench.EngineOwned, format) {
		return fmt.Errorf("owned helper does not support database format %q", format)
	}
	files := 0
	var visit func(string, string) error
	visit = func(path, relative string) error {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			entryPath := filepath.Join(path, entry.Name())
			relativePath := entry.Name()
			if relative != "" {
				relativePath = filepath.Join(relative, entry.Name())
			}
			info, err := os.Lstat(entryPath)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("owned advisory corpus contains symlink %q", filepath.ToSlash(relativePath))
			}
			if info.IsDir() {
				if err := visit(entryPath, relativePath); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("owned advisory corpus contains special file %q", filepath.ToSlash(relativePath))
			}
			actual, ok := ownedFileFormat(entry.Name())
			if !ok {
				return fmt.Errorf("owned advisory corpus contains unsupported file %q", filepath.ToSlash(relativePath))
			}
			if actual != format {
				return fmt.Errorf("owned advisory corpus format %q conflicts with declared format %q", actual, format)
			}
			files++
		}
		return nil
	}
	if err := visit(directory, ""); err != nil {
		return fmt.Errorf("inspect owned advisory corpus: %w", err)
	}
	if files == 0 {
		return fmt.Errorf("owned advisory corpus has no files for declared format %q", format)
	}
	return nil
}

func ownedFileFormat(name string) (DatabaseFormat, bool) {
	name = strings.ToLower(name)
	switch {
	case strings.HasSuffix(name, ".json"):
		return DatabaseFormatOSVJSON, true
	case strings.HasSuffix(name, ".xml"), strings.HasSuffix(name, ".xml.gz"), strings.HasSuffix(name, ".xml.bz2"):
		return DatabaseFormatOVAL, true
	default:
		return "", false
	}
}

// WriteBundle atomically publishes a new capture bundle and refuses to overwrite one.
// validateEvidenceObservation verifies that evidence can truthfully support its observation.
// validateEvidenceObservation verifies the closed process/evidence state machine.
func validateEvidenceObservation(observation bench.Observation, evidenceJSON []byte) (Evidence, error) {
	var evidence Evidence
	required := []string{"schema_version", "engine", "target_id", "parser_status", "input_integrity", "failure_code"}
	if err := decodeEngineJSON(evidenceJSON, &evidence, required...); err != nil {
		return Evidence{}, fmt.Errorf("decode evidence bundle: %w", err)
	}
	if err := requireJSONFields(evidenceJSON, "version_probe", "scan"); err != nil {
		return Evidence{}, err
	}
	canonical, err := canonicalJSON(evidence)
	if err != nil || !bytes.Equal(canonical, evidenceJSON) {
		return Evidence{}, errors.New("evidence bundle is not canonical")
	}
	if evidence.SchemaVersion != EvidenceSchemaVersion || evidence.Engine != observation.Engine || evidence.TargetID != observation.TargetID {
		return Evidence{}, errors.New("evidence identity does not match observation")
	}
	if evidence.InputIntegrity != InputsVerified && evidence.InputIntegrity != InputsMutated {
		return Evidence{}, errors.New("evidence input integrity is invalid")
	}
	if evidence.ParserStatus != ParserNotRun && evidence.ParserStatus != ParserOK && evidence.ParserStatus != ParserFailed {
		return Evidence{}, errors.New("evidence parser status is invalid")
	}
	if !knownFailureCode(evidence.FailureCode) {
		return Evidence{}, errors.New("evidence failure code is invalid")
	}
	if evidence.VersionProbe != nil {
		if err := validateProcessEvidence(*evidence.VersionProbe); err != nil {
			return Evidence{}, fmt.Errorf("version probe evidence: %w", err)
		}
	}
	if evidence.Scan != nil {
		if err := validateProcessEvidence(*evidence.Scan); err != nil {
			return Evidence{}, fmt.Errorf("scan evidence: %w", err)
		}
	}
	if evidence.Capability != nil {
		return validateCapabilityEvidenceObservation(observation, evidence, evidenceJSON)
	}

	if evidence.Engine == bench.EngineOSVScanner {
		if evidence.VersionProbe == nil {
			return Evidence{}, errors.New("OSV evidence requires a version probe")
		}
		probeFailure := classifyProcessFailure(evidence.VersionProbe, evidence.Engine, true)
		if probeFailure != FailureNone {
			if evidence.VersionProbe.ParsedEngineVersion != "" || evidence.Scan != nil || evidence.ParserStatus != ParserNotRun || evidence.FailureCode != probeFailure {
				return Evidence{}, errors.New("OSV probe failure state is inconsistent")
			}
			return validateEvidenceObservationState(observation, evidence, evidenceJSON)
		}
		parsedVersion, parseErr := parseOSVVersion(evidence.VersionProbe.Stdout)
		if parseErr != nil || parsedVersion != evidence.VersionProbe.ParsedEngineVersion || parsedVersion != observation.EngineVersion {
			if evidence.Scan != nil || evidence.ParserStatus != ParserNotRun || evidence.FailureCode != FailureVersionMismatch {
				return Evidence{}, errors.New("OSV version mismatch state is inconsistent")
			}
			return validateEvidenceObservationState(observation, evidence, evidenceJSON)
		}
	} else if evidence.VersionProbe != nil {
		return Evidence{}, errors.New("non-OSV evidence must not contain a version probe")
	}

	if evidence.Scan == nil {
		return Evidence{}, errors.New("evidence lacks a scan process")
	}
	scanFailure := classifyProcessFailure(evidence.Scan, evidence.Engine, false)
	if scanFailure != FailureNone {
		if evidence.Scan.ParsedEngineVersion != "" || evidence.ParserStatus != ParserNotRun || evidence.FailureCode != scanFailure {
			return Evidence{}, errors.New("scan process failure state is inconsistent")
		}
		return validateEvidenceObservationState(observation, evidence, evidenceJSON)
	}
	reportedVersion, reportedErr := reportedEngineVersion(evidence.Engine, evidence.Scan.Stdout)
	if reportedErr != nil {
		reportedVersion = ""
	}
	if reportedVersion != evidence.Scan.ParsedEngineVersion {
		return Evidence{}, errors.New("scan parsed version is not reproducible from retained redacted output")
	}
	if evidence.ParserStatus == ParserNotRun {
		return Evidence{}, errors.New("successful scan lacks a parser outcome")
	}
	if evidence.ParserStatus == ParserFailed {
		if evidence.Engine == bench.EngineOSVScanner && evidence.FailureCode == FailureVersionMismatch {
			return Evidence{}, errors.New("OSV scan cannot report an engine version mismatch")
		}
		if evidence.FailureCode != FailureParser && evidence.FailureCode != FailureVersionMismatch {
			return Evidence{}, errors.New("parser failure state is inconsistent")
		}
		return validateEvidenceObservationState(observation, evidence, evidenceJSON)
	}
	if evidence.Engine == bench.EngineOSVScanner && evidence.Scan.ParsedEngineVersion != "" {
		return Evidence{}, errors.New("OSV scan must not claim an engine version")
	}
	if evidence.Engine != bench.EngineOSVScanner && evidence.Scan.ParsedEngineVersion != observation.EngineVersion {
		return Evidence{}, errors.New("successful scan parsed version does not match observation")
	}
	switch evidence.InputIntegrity {
	case InputsMutated:
		if evidence.FailureCode != FailureInputMutated {
			return Evidence{}, errors.New("mutated successful scan lacks input-mutation failure")
		}
	case InputsVerified:
		if evidence.FailureCode != FailureNone && evidence.FailureCode != FailureObservationTooLarge {
			return Evidence{}, errors.New("successful verified scan has an invalid failure")
		}
	}
	return validateEvidenceObservationState(observation, evidence, evidenceJSON)
}

func requireJSONFields(data []byte, names ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return errors.New("decode evidence fields")
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return fmt.Errorf("evidence requires %q", name)
		}
	}
	return nil
}

func validateCapabilityEvidenceObservation(observation bench.Observation, evidence Evidence, evidenceJSON []byte) (Evidence, error) {
	capability := evidence.Capability
	if capability == nil || capability.Kind != bench.CapabilityKindOSVScannerSUSERPM ||
		capability.DecisionRuleRevision != CapabilityDecisionRuleRevision || capability.Decision != string(bench.ObservationUnsupported) ||
		!validDigest(capability.StatementDigest) {
		return Evidence{}, errors.New("capability evidence has an invalid decision identity")
	}
	if evidence.VersionProbe != nil || evidence.Scan != nil || evidence.ParserStatus != ParserNotRun || evidence.InputIntegrity != InputsVerified || evidence.FailureCode != FailureNone {
		return Evidence{}, errors.New("capability evidence must record an honest zero-dispatch observation")
	}
	if observation.State != bench.ObservationUnsupported || observation.CapabilityKind != capability.Kind || observation.CapabilityDigest != capability.StatementDigest || len(observation.Findings) != 0 {
		return Evidence{}, errors.New("capability evidence does not match an unsupported observation")
	}
	return validateEvidenceObservationState(observation, evidence, evidenceJSON)
}

func knownFailureCode(code FailureCode) bool {
	switch code {
	case FailureNone, FailureCancelled, FailureTimeout, FailureRunnerError, FailureOutputTruncated,
		FailureConnectEvent, FailureUnacceptedExit, FailureVersionMismatch, FailureParser,
		FailureInputMutated, FailureNormalizationInputTooLarge, FailureObservationTooLarge:
		return true
	default:
		return false
	}
}

func validateProcessEvidence(process ProcessEvidence) error {
	if process.ConnectEventCount < 0 {
		return errors.New("connect event count is invalid")
	}
	if process.RunnerError && process.ExitKnown {
		return errors.New("runner error cannot have a known exit")
	}
	if process.Cancelled && process.ExitKnown {
		return errors.New("cancelled process cannot have a known exit")
	}
	if !process.ExitKnown && process.ExitCode != 0 {
		return errors.New("unknown process exit must have zero exit code")
	}
	if process.ParsedEngineVersion != "" && strings.TrimSpace(process.ParsedEngineVersion) != process.ParsedEngineVersion {
		return errors.New("parsed engine version has surrounding whitespace")
	}
	return nil
}

func validateEvidenceObservationState(observation bench.Observation, evidence Evidence, evidenceJSON []byte) (Evidence, error) {
	if rawOutputDigest(evidenceJSON) != observation.RawOutputDigest {
		return Evidence{}, errors.New("raw output digest does not match exact evidence JSON")
	}
	if evidence.Capability != nil {
		if observation.State != bench.ObservationUnsupported || len(observation.Findings) != 0 {
			return Evidence{}, errors.New("capability evidence does not produce an unsupported observation")
		}
		return evidence, nil
	}
	complete := evidence.FailureCode == FailureNone && evidence.ParserStatus == ParserOK && evidence.InputIntegrity == InputsVerified && evidence.Scan != nil
	if complete {
		if observation.State != bench.ObservationComplete {
			return Evidence{}, errors.New("successful evidence does not produce a complete observation")
		}
	} else {
		if observation.State != bench.ObservationIncomplete {
			return Evidence{}, errors.New("failed evidence does not produce an incomplete observation")
		}
		if len(observation.Findings) != 0 {
			return Evidence{}, errors.New("incomplete observation must not contain findings")
		}
	}
	return evidence, nil
}

func validateProfileBundle(observation bench.Observation, profileJSON []byte) error {
	var profile ExecutionProfile
	if err := json.Unmarshal(profileJSON, &profile); err != nil {
		return errors.New("invalid profile bundle")
	}
	if profile.Engine != observation.Engine {
		return errors.New("profile engine does not match observation")
	}
	expected, _, _, err := buildProfile(profile.Engine, profile.DatabaseFormat, profile.Limits)
	if err != nil {
		return fmt.Errorf("reconstruct profile bundle: %w", err)
	}
	expectedJSON, err := canonicalJSON(expected)
	if err != nil || !bytes.Equal(expectedJSON, profileJSON) {
		return errors.New("profile bundle does not match the allowed execution profile")
	}
	if bench.SHA256Digest(profileJSON) != observation.ConfigDigest {
		return errors.New("profile digest does not match observation")
	}
	return nil
}

func validateEnvironmentBundle(observation bench.Observation, environmentJSON, attestationJSON []byte) error {
	var environment EnvironmentDescriptor
	if err := strictDecodeCaptureJSON(bytes.NewReader(environmentJSON), &environment, func(value any, _ string) error {
		return validateManifestShape(value, "environment")
	}); err != nil {
		return fmt.Errorf("decode environment bundle: %w", err)
	}
	canonicalEnvironmentJSON, err := canonicalJSON(environment)
	if err != nil || !bytes.Equal(canonicalEnvironmentJSON, environmentJSON) {
		return errors.New("environment bundle is not canonical")
	}
	if err := environment.validate(); err != nil {
		return fmt.Errorf("validate environment bundle: %w", err)
	}
	if environment.ID != observation.EnvironmentID || bench.SHA256Digest(environmentJSON) != observation.EnvironmentDigest {
		return errors.New("environment bundle does not match observation identity")
	}
	if len(attestationJSON) == 0 || int64(len(attestationJSON)) > maxManifestBytes || bench.SHA256Digest(attestationJSON) != environment.ImageDigest {
		return errors.New("environment attestation does not match environment image digest")
	}
	return nil
}

func WriteBundle(output string, result CaptureResult) error {
	if strings.TrimSpace(output) == "" {
		return errors.New("output bundle directory is required")
	}
	if err := validateResultBinding(result); err != nil {
		return err
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output bundle already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect output bundle: %w", err)
	}
	set := bench.ObservationSet{
		SchemaVersion:   bench.ObservationSchemaVersion,
		CatalogRevision: result.observation.CatalogRevision,
		CatalogDigest:   result.observation.CatalogDigest,
		Observations:    []bench.Observation{cloneObservation(result.observation)},
	}
	var observation bytes.Buffer
	if err := bench.EncodeObservationSet(&observation, set); err != nil {
		return fmt.Errorf("encode observation bundle: %w", err)
	}
	if _, err := bench.DecodeObservationSet(bytes.NewReader(observation.Bytes())); err != nil {
		return fmt.Errorf("validate observation bundle: %w", err)
	}
	evidence, err := validateEvidenceObservation(result.observation, result.evidenceJSON)
	if err != nil {
		return err
	}
	if err := validateProfileBundle(result.observation, result.profileJSON); err != nil {
		return err
	}
	if err := replayPublication(result, evidence); err != nil {
		return err
	}
	parent := filepath.Dir(output)
	base := filepath.Base(output)
	stage, err := os.MkdirTemp(parent, "."+base+".tmp-")
	if err != nil {
		return fmt.Errorf("create bundle staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	artifacts := []struct {
		name string
		data []byte
	}{
		{name: "observation.json", data: observation.Bytes()},
		{name: "evidence.json", data: result.evidenceJSON},
		{name: "profile.json", data: result.profileJSON},
		{name: "environment.json", data: result.environmentJSON},
		{name: "environment-attestation.json", data: result.environmentAttestationJSON},
	}
	if evidence.Capability != nil {
		artifacts = append(artifacts, struct {
			name string
			data []byte
		}{name: "capability-statement.json", data: result.capabilityStatementJSON})
		for i, source := range result.capabilitySources {
			artifacts = append(artifacts, struct {
				name string
				data []byte
			}{name: capabilitySourceBundleName(i), data: source.Data})
		}
	}
	for _, artifact := range artifacts {
		if err := writeBundleFile(filepath.Join(stage, artifact.name), artifact.data); err != nil {
			return err
		}
	}
	if err := ValidateBundle(stage); err != nil {
		return fmt.Errorf("validate staged bundle: %w", err)
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	if err := publishBundle(stage, output); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	return nil
}

// ValidateBundle validates a published bundle without relying on the mutable caller state.
func ValidateBundle(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("bundle directory is required")
	}
	observationJSON, err := readBundleArtifact(path, "observation.json")
	if err != nil {
		return err
	}
	set, err := bench.DecodeObservationSet(bytes.NewReader(observationJSON))
	if err != nil || len(set.Observations) != 1 {
		return errors.New("bundle must contain one valid observation")
	}
	observation := set.Observations[0]
	evidenceJSON, err := readBundleArtifact(path, "evidence.json")
	if err != nil {
		return err
	}
	evidence, err := validateEvidenceObservation(observation, evidenceJSON)
	if err != nil {
		return err
	}
	profileJSON, err := readBundleArtifact(path, "profile.json")
	if err != nil {
		return err
	}
	if err := validateProfileBundle(observation, profileJSON); err != nil {
		return err
	}
	environmentJSON, err := readBundleArtifact(path, "environment.json")
	if err != nil {
		return err
	}
	environmentAttestationJSON, err := readBundleArtifact(path, "environment-attestation.json")
	if err != nil {
		return err
	}
	if err := validateEnvironmentBundle(observation, environmentJSON, environmentAttestationJSON); err != nil {
		return err
	}
	expected := map[string]struct{}{"observation.json": {}, "evidence.json": {}, "profile.json": {}, "environment.json": {}, "environment-attestation.json": {}}
	if evidence.Capability != nil {
		statementJSON, err := readBundleArtifact(path, "capability-statement.json")
		if err != nil {
			return err
		}
		expected["capability-statement.json"] = struct{}{}
		sources := make([]retainedCapabilitySource, 0, len(capabilitySourceReferences))
		for i, reference := range capabilitySourceReferences {
			name := capabilitySourceBundleName(i)
			data, err := readBundleArtifact(path, name)
			if err != nil {
				return err
			}
			expected[name] = struct{}{}
			sources = append(sources, retainedCapabilitySource{Reference: reference, Data: data})
		}
		if err := validateCapabilityBundle(observation, evidence, statementJSON, sources); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != len(expected) {
		return errors.New("bundle artifact set is incomplete or contains unexpected files")
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return errors.New("bundle contains an unexpected artifact")
		}
	}
	return nil
}

func validateCapabilityBundle(observation bench.Observation, evidence Evidence, statementJSON []byte, sources []retainedCapabilitySource) error {
	statement, err := decodeCapabilityStatement(statementJSON)
	if err != nil {
		return err
	}
	if evidence.Capability == nil || bench.SHA256Digest(statementJSON) != observation.CapabilityDigest || observation.CapabilityDigest != evidence.Capability.StatementDigest {
		return errors.New("capability bundle statement does not bind observation evidence")
	}
	components := make([]sbom.Component, len(statement.Components))
	for i, component := range statement.Components {
		components[i] = sbom.Component{PURL: component.PURL, Version: component.Version}
	}
	prepared := preparedCapture{
		catalog:      bench.Catalog{Revision: observation.CatalogRevision},
		manifest:     CaptureManifest{CatalogDigest: observation.CatalogDigest, Engine: observation.Engine, EngineVersion: observation.EngineVersion, Database: DatabaseArtifact{Build: observation.DatabaseBuild}, Environment: EnvironmentDescriptor{ID: observation.EnvironmentID}},
		target:       bench.Target{ID: observation.TargetID, Digest: observation.TargetDigest, SBOMDigest: observation.SBOMDigest},
		binaryDigest: observation.EngineBinaryDigest, databaseDigest: observation.DatabaseDigest, environmentDigest: observation.EnvironmentDigest, configDigest: observation.ConfigDigest, components: components,
	}
	if err := verifyCapabilityStatement(statement, prepared); err != nil {
		return err
	}
	if len(sources) != len(statement.Sources) {
		return errors.New("capability bundle has an incomplete source set")
	}
	for i := range sources {
		if sources[i].Reference != statement.Sources[i].Reference || bench.SHA256Digest(sources[i].Data) != statement.Sources[i].Digest {
			return errors.New("capability bundle source bytes do not match statement pins")
		}
	}
	return nil
}

func capabilitySourceBundleName(index int) string {
	return fmt.Sprintf("capability-source-%02d", index)
}

func readBundleArtifact(root, name string) ([]byte, error) {
	path := filepath.Join(root, name)
	limit := maxBundleArtifactBytes
	if name == "environment.json" || name == "environment-attestation.json" || name == "capability-statement.json" || strings.HasPrefix(name, "capability-source-") {
		limit = maxManifestBytes
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("bundle artifact %q is not a bounded regular file", name)
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("read bundle artifact %q", name)
	}
	return data, nil
}

func validateResultBinding(result CaptureResult) error {
	binding := result.binding
	if !binding.valid {
		return errors.New("capture result is unbound")
	}
	if len(result.evidenceJSON) == 0 || len(result.profileJSON) == 0 || len(result.environmentJSON) == 0 || len(result.environmentAttestationJSON) == 0 ||
		len(binding.evidenceJSON) == 0 || len(binding.profileJSON) == 0 || len(binding.environmentJSON) == 0 || len(binding.environmentAttestationJSON) == 0 {
		return errors.New("capture result is missing retained artifacts")
	}
	if !sameObservation(result.observation, binding.observation) {
		return errors.New("capture result observation does not match immutable binding")
	}
	if !bytes.Equal(result.evidenceJSON, binding.evidenceJSON) || !bytes.Equal(result.profileJSON, binding.profileJSON) ||
		!bytes.Equal(result.environmentJSON, binding.environmentJSON) || !bytes.Equal(result.environmentAttestationJSON, binding.environmentAttestationJSON) ||
		!bytes.Equal(result.capabilityStatementJSON, binding.capabilityStatementJSON) || !sameCapabilitySources(result.capabilitySources, binding.capabilitySources) {
		return errors.New("capture result serialized artifacts do not match immutable binding")
	}
	if err := validateEnvironmentBundle(result.observation, result.environmentJSON, result.environmentAttestationJSON); err != nil {
		return fmt.Errorf("validate capture result environment: %w", err)
	}
	encodedEvidence, err := canonicalJSON(result.evidence)
	if err != nil || !bytes.Equal(encodedEvidence, result.evidenceJSON) {
		return errors.New("capture result evidence does not match canonical evidence JSON")
	}
	boundEvidence, err := canonicalJSON(binding.evidence)
	if err != nil || !bytes.Equal(encodedEvidence, boundEvidence) {
		return errors.New("capture result evidence does not match immutable binding")
	}
	boundProfile, err := canonicalJSON(binding.profile)
	if err != nil || !bytes.Equal(boundProfile, result.profileJSON) {
		return errors.New("capture result profile does not match immutable binding")
	}
	return nil
}

func sameCapabilitySources(left, right []retainedCapabilitySource) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Reference != right[i].Reference || left[i].Digest != right[i].Digest || !bytes.Equal(left[i].Data, right[i].Data) {
			return false
		}
	}
	return true
}

func sameObservation(left, right bench.Observation) bool {
	leftJSON, leftErr := canonicalJSON(left)
	rightJSON, rightErr := canonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func replayPublication(result CaptureResult, evidence Evidence) error {
	if err := validateEnvironmentBundle(result.observation, result.environmentJSON, result.environmentAttestationJSON); err != nil {
		return fmt.Errorf("replay environment artifacts: %w", err)
	}
	if evidence.Capability != nil {
		return replayCapabilityPublication(result, evidence)
	}
	if result.observation.State == bench.ObservationIncomplete && len(result.observation.Findings) != 0 {
		return errors.New("incomplete observation must not contain findings")
	}
	probeFailure := classifyProcessFailure(evidence.VersionProbe, evidence.Engine, true)
	scanFailure := classifyProcessFailure(evidence.Scan, evidence.Engine, false)
	oversizedProbe := probeFailure == FailureNormalizationInputTooLarge
	oversizedScan := scanFailure == FailureNormalizationInputTooLarge
	if oversizedProbe || oversizedScan {
		if evidence.FailureCode != FailureNormalizationInputTooLarge {
			return errors.New("oversized normalization input lacks its dedicated failure code")
		}
	}
	if evidence.FailureCode == FailureNormalizationInputTooLarge {
		if result.observation.State != bench.ObservationIncomplete || evidence.ParserStatus != ParserNotRun {
			return errors.New("normalization input size replay state is inconsistent")
		}
		switch {
		case oversizedProbe:
			if evidence.Engine != bench.EngineOSVScanner || evidence.VersionProbe == nil || evidence.Scan != nil || evidence.VersionProbe.ParsedEngineVersion != "" {
				return errors.New("OSV probe normalization input size replay state is inconsistent")
			}
		case oversizedScan:
			if evidence.Scan == nil || evidence.Scan.ParsedEngineVersion != "" {
				return errors.New("scan normalization input size replay state is inconsistent")
			}
		default:
			return errors.New("normalization input size replay state has no oversized source")
		}
		return nil
	}
	if evidence.ParserStatus != ParserOK {
		return nil
	}
	if evidence.Scan == nil {
		return errors.New("successful parser evidence lacks scan output")
	}
	findings, err := parseEngine(result.binding.profile.Engine, result.binding.observation.EngineVersion, evidence.Scan.Stdout, result.binding.target, result.binding.components, result.binding.profile.DatabaseFormat)
	if err != nil {
		return fmt.Errorf("replay retained redacted scan output: %w", err)
	}
	findings = canonicalFindings(findings)
	switch evidence.FailureCode {
	case FailureNone:
		if result.observation.State != bench.ObservationComplete || !sameFindings(result.observation.Findings, findings) {
			return errors.New("complete observation findings do not match retained redacted scan output")
		}
	case FailureObservationTooLarge:
		candidate := cloneObservation(result.binding.observation)
		candidate.State = bench.ObservationComplete
		candidate.Findings = findings
		over, err := observationExceedsLimit(candidate)
		if err != nil {
			return err
		}
		if !over {
			return errors.New("observation-too-large claim does not exceed the observation size limit")
		}
	case FailureInputMutated:
		if result.observation.State != bench.ObservationIncomplete {
			return errors.New("input mutation replay has an invalid observation state")
		}
	default:
		return errors.New("parser-success evidence has an invalid failure code")
	}
	return nil
}

func replayCapabilityPublication(result CaptureResult, evidence Evidence) error {
	if evidence.Capability == nil || len(result.capabilityStatementJSON) == 0 || len(result.capabilitySources) != len(capabilitySourceReferences) {
		return errors.New("capability publication lacks retained statement or sources")
	}
	statement, err := decodeCapabilityStatement(result.capabilityStatementJSON)
	if err != nil {
		return err
	}
	if bench.SHA256Digest(result.capabilityStatementJSON) != evidence.Capability.StatementDigest || evidence.Capability.StatementDigest != result.observation.CapabilityDigest {
		return errors.New("capability statement digest does not bind observation evidence")
	}
	prepared := preparedCapture{
		catalog:  bench.Catalog{Revision: result.observation.CatalogRevision},
		manifest: CaptureManifest{CatalogDigest: result.observation.CatalogDigest, Engine: result.observation.Engine, EngineVersion: result.observation.EngineVersion, Database: DatabaseArtifact{Build: result.observation.DatabaseBuild}, Environment: EnvironmentDescriptor{ID: result.observation.EnvironmentID}},
		target:   result.binding.target, binaryDigest: result.observation.EngineBinaryDigest, databaseDigest: result.observation.DatabaseDigest,
		environmentDigest: result.observation.EnvironmentDigest, configDigest: result.observation.ConfigDigest, components: result.binding.components,
	}
	if err := verifyCapabilityStatement(statement, prepared); err != nil {
		return err
	}
	for i, source := range result.capabilitySources {
		if source.Reference != capabilitySourceReferences[i] || source.Digest != statement.Sources[i].Digest || bench.SHA256Digest(source.Data) != source.Digest {
			return errors.New("retained capability source does not match its statement pin")
		}
	}
	return nil
}

func sameFindings(left, right []bench.Finding) bool {
	leftJSON, leftErr := canonicalJSON(canonicalFindings(left))
	rightJSON, rightErr := canonicalJSON(canonicalFindings(right))
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func writeBundleFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create bundle artifact: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write bundle artifact: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync bundle artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close bundle artifact: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open bundle directory for sync: %w", err)
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync bundle directory: %w", err)
	}
	return nil
}

package reachbench

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const (
	protectedBaselineBundleID = "synapse-reachability-protected-baseline-bundle-v1"
	candidateBundleID         = "synapse-reachability-candidate-bundle-v1"
	harnessContractID         = "synapse-reachability-harness-contract-v1"
	harnessContractSchema     = "synapse-reachability-harness-contract-v1"
)

// ProtectedBaselineControllerAssets is a write-ready controller bundle for the
// protected baseline route. JSON fields include their required trailing newline;
// references deliberately digest the canonical JSON value without that newline,
// which is exactly how readCanonicalJSON verifies bundle assets.
type ProtectedBaselineControllerAssets struct {
	BaselineInput     measurement.MeasurementInput
	BaselineAllowlist BaselineAllowlist
	TrustedBundle     TrustedBundle
	Envelope          RunEnvelope
	EnvelopeFileName  string

	BaselineInputJSON     []byte
	BaselineAllowlistJSON []byte
	TrustedBundleJSON     []byte
	EnvelopeJSON          []byte

	BaselineInputRef     measurement.ArtifactReference
	BaselineAllowlistRef measurement.ArtifactReference
	BundleRef            measurement.ArtifactReference
	EnvelopeRef          measurement.ArtifactReference
}

// CheckpointActors names the independent procedural roles required to construct
// a candidate checkpoint. The strings are validated by the measurement package.
type CheckpointActors struct {
	Producer   string
	Reviewer   string
	Maintainer string
}

// CandidateControllerAssets is the complete candidate bundle and its explicit
// reviewable baseline, checkpoint, and ratchet evidence. JSON fields are
// write-ready canonical documents with one trailing newline.
type CandidateControllerAssets struct {
	BaselineInput           measurement.MeasurementInput
	CandidateInput          measurement.MeasurementInput
	BaselineAllowlist       BaselineAllowlist
	BaselineAllowlistResult BaselineAllowlistResult
	TrustedBundle           TrustedBundle
	BaselineReport          measurement.MeasurementReport
	Checkpoint              measurement.ProceduralBaselineCheckpoint
	Ratchet                 measurement.CandidateRatchet

	BaselineInputJSON           []byte
	CandidateInputJSON          []byte
	BaselineAllowlistJSON       []byte
	BaselineAllowlistResultJSON []byte
	TrustedBundleJSON           []byte
	BaselineReportJSON          []byte
	CheckpointJSON              []byte
	RatchetJSON                 []byte

	BaselineInputRef           measurement.ArtifactReference
	CandidateInputRef          measurement.ArtifactReference
	BaselineAllowlistRef       measurement.ArtifactReference
	BaselineAllowlistResultRef measurement.ArtifactReference
	BundleRef                  measurement.ArtifactReference
	BaselineReportRef          measurement.ArtifactReference
	CheckpointRef              measurement.ArtifactReference
	RatchetRef                 measurement.ArtifactReference
}

// BuildBaselineAllowlist converts the exact NUL-delimited output of
// git diff --name-status --no-renames -z into the closed, sorted allowlist used
// by a protected baseline. Empty, malformed, deleting, copied, renamed, and
// unsafe changes fail closed in normalizeChangedEntries.
func BuildBaselineAllowlist(id string, normalizedDiff []byte) (BaselineAllowlist, error) {
	entries, err := normalizeChangedEntries(normalizedDiff)
	if err != nil {
		return BaselineAllowlist{}, fmt.Errorf("normalize protected baseline delta: %w", err)
	}
	allowlist := BaselineAllowlist{
		SchemaVersion: BaselineAllowlistSchemaVersion,
		ID:            id,
		Entries:       entries,
	}
	if err := allowlist.Validate(); err != nil {
		return BaselineAllowlist{}, fmt.Errorf("validate protected baseline allowlist: %w", err)
	}
	return allowlist, nil
}

// BuildProtectedBaselineControllerAssets produces the exact three-file trusted
// baseline bundle and its controller envelope. It accepts validated values only;
// callers never supply a run key, path, purpose, or final mode.
func BuildProtectedBaselineControllerAssets(
	allowlist BaselineAllowlist,
	harness HarnessIdentity,
	baselineAnalyzer RevisionIdentity,
	controller string,
	reviewEvidence measurement.ArtifactReference,
) (ProtectedBaselineControllerAssets, error) {
	if err := allowlist.Validate(); err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("validate baseline allowlist: %w", err)
	}
	if err := validateHarness(harness); err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("validate baseline harness: %w", err)
	}
	if err := validateRevision(baselineAnalyzer); err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("validate fixed baseline analyzer: %w", err)
	}
	if baselineAnalyzer.ID != AnalyzerSubjectID || baselineAnalyzer.Commit != measurement.TrustedBaselineRevision {
		return ProtectedBaselineControllerAssets{}, errors.New("protected baseline requires the fixed trusted analyzer identity")
	}
	if !bounded(controller) || validateArtifact(reviewEvidence) != nil {
		return ProtectedBaselineControllerAssets{}, errors.New("protected baseline requires a bounded controller and review evidence reference")
	}

	baseline, err := measurement.DefaultBaselineMeasurementInput()
	if err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("build default baseline input: %w", err)
	}
	baselineJSON, baselineCanonical, err := canonicalJSONFile(baseline)
	if err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("encode default baseline input: %w", err)
	}
	allowlistJSON, allowlistCanonical, err := canonicalJSONFile(allowlist)
	if err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("encode baseline allowlist: %w", err)
	}
	baselineRef := canonicalReference("baseline-input.json", baselineCanonical)
	allowlistRef := canonicalReference(allowlist.ID, allowlistCanonical)
	bundle := TrustedBundle{
		SchemaVersion:     BundleSchemaVersion,
		ID:                protectedBaselineBundleID,
		BaselineInput:     BundleAsset{Path: "baseline-input.json", Digest: baselineRef.Digest},
		BaselineAllowlist: BundleAsset{Path: "baseline-allowlist.json", Digest: allowlistRef.Digest},
	}
	if err := bundle.ValidateRoute(RouteProtectedBaseline); err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("validate protected baseline trusted bundle: %w", err)
	}
	bundleJSON, bundleCanonical, err := canonicalJSONFile(bundle)
	if err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("encode protected baseline trusted bundle: %w", err)
	}
	bundleRef := canonicalReference(bundle.ID, bundleCanonical)
	envelope := RunEnvelope{
		SchemaVersion: EnvelopeSchemaVersion,
		Route:         RouteProtectedBaseline,
		Purpose:       measurement.BaselineMeasurement,
		FinalMode:     FinalBaseline,
		Harness:       harness,
		Analyzer:      baselineAnalyzer,
		Snapshot:      baseline.ActiveSnapshot,
		Bundle:        bundleRef,
		Authority: ProceduralAuthority{
			Class: "procedural", Controller: controller, ReviewEvidence: reviewEvidence,
			ReviewedHarness: true, ReviewedHarnessID: harness.ID,
		},
	}
	if err := envelope.Validate(); err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("validate protected baseline envelope: %w", err)
	}
	if err := validateEnvelopeMeasurement(envelope, baseline, bundleRef); err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("bind protected baseline envelope to input: %w", err)
	}
	envelopeJSON, envelopeCanonical, err := canonicalJSONFile(envelope)
	if err != nil {
		return ProtectedBaselineControllerAssets{}, fmt.Errorf("encode protected baseline envelope: %w", err)
	}
	return ProtectedBaselineControllerAssets{
		BaselineInput: baseline, BaselineAllowlist: allowlist, TrustedBundle: bundle, Envelope: envelope,
		EnvelopeFileName:  "baseline-" + harness.Commit + ".json",
		BaselineInputJSON: baselineJSON, BaselineAllowlistJSON: allowlistJSON, TrustedBundleJSON: bundleJSON, EnvelopeJSON: envelopeJSON,
		BaselineInputRef: baselineRef, BaselineAllowlistRef: allowlistRef, BundleRef: bundleRef,
		EnvelopeRef: canonicalReference("baseline-"+harness.Commit+".json", envelopeCanonical),
	}, nil
}

// BuildCandidateControllerAssets constructs the full candidate bundle only after
// a captured baseline, its published protected-baseline manifest, and independent
// review/disposition evidence have all bound to the frozen default contract.
func BuildCandidateControllerAssets(
	baseline measurement.MeasurementReport,
	manifest LifecycleManifest,
	allowlistResult BaselineAllowlistResult,
	allowlist BaselineAllowlist,
	reviewEvidence measurement.ArtifactReference,
	dispositionEvidence measurement.ArtifactReference,
	actors CheckpointActors,
) (CandidateControllerAssets, error) {
	if err := validatePublishedDefaultBaseline(baseline, manifest, allowlistResult, allowlist); err != nil {
		return CandidateControllerAssets{}, err
	}
	if validateArtifact(reviewEvidence) != nil || validateArtifact(dispositionEvidence) != nil {
		return CandidateControllerAssets{}, errors.New("candidate checkpoint requires valid review and disposition evidence references")
	}
	if reviewEvidence == dispositionEvidence {
		return CandidateControllerAssets{}, errors.New("candidate checkpoint review and disposition evidence must be independent")
	}

	baselineInput, err := measurement.DefaultBaselineMeasurementInput()
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("build default baseline input: %w", err)
	}
	harnessContract, err := harnessContractReference(manifest.Harness)
	if err != nil {
		return CandidateControllerAssets{}, err
	}
	allowlistJSON, allowlistCanonical, err := canonicalJSONFile(allowlist)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("encode baseline allowlist: %w", err)
	}
	allowlistResultJSON, allowlistResultCanonical, err := canonicalJSONFile(allowlistResult)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("encode published baseline allowlist result: %w", err)
	}
	allowlistRef := canonicalReference(allowlist.ID, allowlistCanonical)
	allowlistResultRef := canonicalReference(baselineAllowlistResultPath(), allowlistResultCanonical)
	checkpoint := measurement.ProceduralBaselineCheckpoint{
		SchemaVersion:       measurement.BaselineCheckpointSchemaVersion,
		AuthorityClass:      "procedural",
		StartingRevision:    measurement.TrustedBaselineRevision,
		Policy:              baseline.Policy,
		BaselineResult:      measurement.ArtifactReference{ID: baseline.ID, Digest: baseline.ID},
		HarnessContract:     harnessContract,
		AllowlistEvidence:   allowlistResultRef,
		ReviewEvidence:      reviewEvidence,
		DispositionEvidence: dispositionEvidence,
		Producer:            actors.Producer,
		Reviewer:            actors.Reviewer,
		Maintainer:          actors.Maintainer,
	}
	checkpointID, err := measurement.DigestProceduralBaselineCheckpoint(checkpoint)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("digest procedural baseline checkpoint: %w", err)
	}
	checkpoint.ID = checkpointID
	if err := checkpoint.Validate(baselineInput.Policy, baseline); err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("validate procedural baseline checkpoint: %w", err)
	}
	candidate, err := measurement.BuildCandidateMeasurementInput(baseline, checkpoint)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("build candidate measurement input: %w", err)
	}

	baselineInputJSON, baselineInputCanonical, err := canonicalJSONFile(baselineInput)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("encode baseline measurement input: %w", err)
	}
	candidateInputJSON, candidateInputCanonical, err := canonicalJSONFile(candidate)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("encode candidate measurement input: %w", err)
	}
	checkpointJSON, checkpointCanonical, err := canonicalJSONFile(checkpoint)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("encode procedural baseline checkpoint: %w", err)
	}
	ratchetJSON, ratchetCanonical, err := canonicalJSONFile(*candidate.Ratchet)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("encode candidate ratchet: %w", err)
	}
	baselineReportJSON, baselineReportCanonical, err := canonicalMeasurementReportFile(baseline)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("encode baseline report: %w", err)
	}
	baselineInputRef := canonicalReference("baseline-input.json", baselineInputCanonical)
	candidateInputRef := canonicalReference("candidate-input.json", candidateInputCanonical)
	bundle := TrustedBundle{
		SchemaVersion:     BundleSchemaVersion,
		ID:                candidateBundleID,
		BaselineInput:     BundleAsset{Path: "baseline-input.json", Digest: baselineInputRef.Digest},
		CandidateInput:    &BundleAsset{Path: "candidate-input.json", Digest: candidateInputRef.Digest},
		BaselineAllowlist: BundleAsset{Path: "baseline-allowlist.json", Digest: allowlistRef.Digest},
	}
	if err := bundle.ValidateRoute(RouteCandidate); err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("validate candidate trusted bundle: %w", err)
	}
	bundleJSON, bundleCanonical, err := canonicalJSONFile(bundle)
	if err != nil {
		return CandidateControllerAssets{}, fmt.Errorf("encode candidate trusted bundle: %w", err)
	}
	return CandidateControllerAssets{
		BaselineInput: baselineInput, CandidateInput: candidate, BaselineAllowlist: allowlist, BaselineAllowlistResult: allowlistResult,
		TrustedBundle: bundle, BaselineReport: baseline, Checkpoint: checkpoint, Ratchet: *candidate.Ratchet,
		BaselineInputJSON: baselineInputJSON, CandidateInputJSON: candidateInputJSON, BaselineAllowlistJSON: allowlistJSON,
		BaselineAllowlistResultJSON: allowlistResultJSON, TrustedBundleJSON: bundleJSON, BaselineReportJSON: baselineReportJSON,
		CheckpointJSON: checkpointJSON, RatchetJSON: ratchetJSON,
		BaselineInputRef: baselineInputRef, CandidateInputRef: candidateInputRef, BaselineAllowlistRef: allowlistRef,
		BaselineAllowlistResultRef: allowlistResultRef, BundleRef: canonicalReference(bundle.ID, bundleCanonical),
		BaselineReportRef: canonicalReference(baseline.ID, baselineReportCanonical),
		CheckpointRef:     canonicalReference(checkpoint.ID, checkpointCanonical),
		RatchetRef:        canonicalReference(candidate.Ratchet.ID, ratchetCanonical),
	}, nil
}

type harnessContractDescriptor struct {
	SchemaVersion string          `json:"schema_version"`
	ID            string          `json:"id"`
	Harness       HarnessIdentity `json:"harness"`
}

func harnessContractReference(harness HarnessIdentity) (measurement.ArtifactReference, error) {
	if err := validateHarness(harness); err != nil {
		return measurement.ArtifactReference{}, fmt.Errorf("validate checkpoint harness: %w", err)
	}
	_, canonical, err := canonicalJSONFile(harnessContractDescriptor{
		SchemaVersion: harnessContractSchema,
		ID:            harnessContractID,
		Harness:       harness,
	})
	if err != nil {
		return measurement.ArtifactReference{}, fmt.Errorf("encode checkpoint harness contract: %w", err)
	}
	return canonicalReference(harnessContractID, canonical), nil
}

func validatePublishedDefaultBaseline(
	baseline measurement.MeasurementReport,
	manifest LifecycleManifest,
	allowlistResult BaselineAllowlistResult,
	allowlist BaselineAllowlist,
) error {
	if err := baseline.Validate(); err != nil {
		return fmt.Errorf("validate captured baseline report: %w", err)
	}
	if err := validateDefaultBaselineReport(baseline); err != nil {
		return err
	}
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("validate published baseline manifest: %w", err)
	}
	if manifest.Route != RouteProtectedBaseline || manifest.Purpose != measurement.BaselineMeasurement || manifest.FinalMode != FinalBaseline || !manifest.Authoritative {
		return errors.New("published manifest is not an authoritative protected baseline")
	}
	if !reportIDsBindBaseline(manifest.ReportIDs, baseline.ID) {
		return errors.New("published baseline manifest does not bind the supplied baseline report")
	}
	if manifest.Snapshot != baseline.ActiveSnapshot {
		return errors.New("published baseline manifest snapshot does not bind the supplied baseline report")
	}
	if err := allowlist.Validate(); err != nil {
		return fmt.Errorf("validate original baseline allowlist: %w", err)
	}
	_, allowlistCanonical, err := canonicalJSONFile(allowlist)
	if err != nil {
		return fmt.Errorf("encode original baseline allowlist: %w", err)
	}
	allowlistRef := canonicalReference(allowlist.ID, allowlistCanonical)
	if err := allowlistResult.Validate(); err != nil {
		return fmt.Errorf("validate published baseline allowlist result: %w", err)
	}
	if manifest.BaselineAllowlist == nil || !sameCanonical(*manifest.BaselineAllowlist, allowlistResult) {
		return errors.New("published baseline manifest does not bind the supplied allowlist result")
	}
	if allowlistResult.Allowlist != allowlistRef || allowlistResult.Harness != manifest.Harness || allowlistResult.Analyzer != manifest.Analyzer {
		return errors.New("published baseline allowlist result does not bind the original allowlist and manifest identities")
	}
	entriesCanonical, err := benchmark.CanonicalJSON(allowlist.Entries)
	if err != nil {
		return fmt.Errorf("encode baseline allowlist entries: %w", err)
	}
	if allowlistResult.ChangedEntryCount != len(allowlist.Entries) || allowlistResult.ChangedEntryDigest != benchmark.SHA256Digest(entriesCanonical) {
		return errors.New("published baseline allowlist result does not bind the original allowlist entries")
	}
	expectedAssets, err := BuildProtectedBaselineControllerAssets(
		allowlist,
		manifest.Harness,
		manifest.Analyzer,
		manifest.Authority.Controller,
		manifest.Authority.ReviewEvidence,
	)
	if err != nil {
		return fmt.Errorf("rebuild protected baseline contract: %w", err)
	}
	if manifest.Bundle != expectedAssets.BundleRef {
		return errors.New("published baseline manifest does not bind the deterministic protected baseline bundle")
	}
	return nil
}

func validateDefaultBaselineReport(report measurement.MeasurementReport) error {
	input, err := measurement.DefaultBaselineMeasurementInput()
	if err != nil {
		return fmt.Errorf("load default measurement contract: %w", err)
	}
	policyDigest, err := measurement.DigestMeasurementPolicy(input.Policy)
	if err != nil {
		return err
	}
	inventoryDigest, err := measurement.DigestProductionInventory(input.Inventory)
	if err != nil {
		return err
	}
	corpusDigest, err := measurement.DigestContractCorpus(input.Corpus)
	if err != nil {
		return err
	}
	oracleDigest, err := measurement.DigestReachabilityOracle(input.Oracle)
	if err != nil {
		return err
	}
	exceptionsDigest, err := measurement.DigestExceptionManifest(input.Exceptions)
	if err != nil {
		return err
	}
	if report.Purpose != measurement.BaselineMeasurement || report.RatchetDigest != "" ||
		report.Policy != (measurement.ArtifactReference{ID: input.Policy.ID, Digest: policyDigest}) ||
		report.Inventory != (measurement.ArtifactReference{ID: input.Inventory.ID, Digest: inventoryDigest}) ||
		report.Corpus != (measurement.ArtifactReference{ID: input.Corpus.ID, Digest: corpusDigest}) ||
		report.Oracle != (measurement.ArtifactReference{ID: input.Oracle.ID, Digest: oracleDigest}) ||
		report.ExceptionManifest != (measurement.ArtifactReference{ID: input.Exceptions.ID, Digest: exceptionsDigest}) ||
		report.ActiveSnapshot != input.ActiveSnapshot {
		return errors.New("captured baseline report does not bind the frozen default measurement contract")
	}
	return nil
}

func reportIDsBindBaseline(ids []string, baselineID string) bool {
	if len(ids) != fixedRepetitions {
		return false
	}
	for _, id := range ids {
		if id != baselineID {
			return false
		}
	}
	return true
}

func canonicalJSONFile(value any) (file []byte, canonical []byte, err error) {
	canonical, err = benchmark.CanonicalJSON(value)
	if err != nil {
		return nil, nil, err
	}
	file = make([]byte, len(canonical)+1)
	copy(file, canonical)
	file[len(canonical)] = '\n'
	return file, canonical, nil
}

func canonicalMeasurementReportFile(report measurement.MeasurementReport) (file []byte, canonical []byte, err error) {
	var output bytes.Buffer
	if err := measurement.EncodeMeasurementReport(&output, report); err != nil {
		return nil, nil, err
	}
	file = output.Bytes()
	if len(file) == 0 || file[len(file)-1] != '\n' {
		return nil, nil, errors.New("measurement report canonical encoding has no newline")
	}
	canonical = append([]byte(nil), file[:len(file)-1]...)
	return file, canonical, nil
}

func canonicalReference(id string, canonical []byte) measurement.ArtifactReference {
	return measurement.ArtifactReference{ID: id, Digest: benchmark.SHA256Digest(canonical)}
}

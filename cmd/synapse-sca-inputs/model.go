package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const (
	sourceFreezeTemplateSchemaVersion     = "synapse-sca-benchmark-source-freeze-template-v1"
	sourcePlanTemplateSchemaVersion       = "synapse-sca-benchmark-source-evidence-plan-template-v1"
	captureTemplateSchemaVersion          = "synapse-sca-benchmark-capture-manifest-template-v1"
	cyclePolicySchemaVersion              = "synapse-sca-benchmark-cycle-policy-v1"
	cleanupReceiptSchemaVersion           = "synapse-sca-benchmark-cleanup-receipt-v1"
	candidateReceiptSchemaVersion         = "synapse-sca-benchmark-candidate-receipt-v1"
	publicationArtifactIndexSchemaVersion = "synapse-sca-benchmark-publication-artifact-index-v1"
	candidateFileInventorySchemaVersion   = "synapse-sca-benchmark-candidate-file-inventory-v1"
)

type sourceFreezeTemplate struct {
	SchemaVersion string                      `json:"schema_version"`
	CycleID       string                      `json:"cycle_id"`
	Assets        []sourceFreezeTemplateAsset `json:"assets"`
}

type sourceFreezeTemplateAsset struct {
	Locator string `json:"locator"`
}

func (template sourceFreezeTemplate) validate() error {
	if template.SchemaVersion != sourceFreezeTemplateSchemaVersion {
		return fmt.Errorf("unsupported source freeze template schema %q", template.SchemaVersion)
	}
	if strings.TrimSpace(template.CycleID) == "" || len(template.Assets) == 0 {
		return fmt.Errorf("source freeze template requires a cycle and assets")
	}
	seen := make(map[string]struct{}, len(template.Assets))
	for _, asset := range template.Assets {
		if strings.TrimSpace(asset.Locator) == "" {
			return fmt.Errorf("source freeze template contains an empty locator")
		}
		if _, exists := seen[asset.Locator]; exists {
			return fmt.Errorf("source freeze template duplicates locator %q", asset.Locator)
		}
		seen[asset.Locator] = struct{}{}
	}
	return nil
}

type sourcePlanTemplate struct {
	SchemaVersion string                       `json:"schema_version"`
	CycleID       string                       `json:"cycle_id"`
	Targets       []bench.SourceEvidenceTarget `json:"targets"`
}

func (template sourcePlanTemplate) validate() error {
	if template.SchemaVersion != sourcePlanTemplateSchemaVersion {
		return fmt.Errorf("unsupported source evidence plan template schema %q", template.SchemaVersion)
	}
	plan := bench.SourceEvidencePlan{
		SchemaVersion:      bench.SourceEvidencePlanSchemaVersion,
		CycleID:            template.CycleID,
		SourceFreezeDigest: "sha256:" + strings.Repeat("0", 64),
		Targets:            template.Targets,
	}
	return plan.Validate()
}

type captureManifestTemplate struct {
	SchemaVersion           string                        `json:"schema_version"`
	TargetID                string                        `json:"target_id"`
	Engine                  bench.Engine                  `json:"engine"`
	EngineVersion           string                        `json:"engine_version"`
	Binary                  capture.Artifact              `json:"binary"`
	Database                capture.DatabaseArtifact      `json:"database"`
	Environment             capture.EnvironmentDescriptor `json:"environment"`
	EnvironmentAttestation  capture.Artifact              `json:"environment_attestation"`
	EnvironmentPinReference string                        `json:"environment_pin_reference"`
	ProfilePinReference     string                        `json:"profile_pin_reference"`
	Limits                  capture.RuntimeLimits         `json:"limits"`
	Capability              *capabilityTemplate           `json:"capability,omitempty"`
}

type capabilityTemplate struct {
	StatementReference string                     `json:"statement_reference"`
	Sources            []capabilitySourceTemplate `json:"sources"`
}

type capabilitySourceTemplate struct {
	Reference string `json:"reference"`
	Locator   string `json:"locator"`
	Digest    string `json:"digest"`
}

func (template captureManifestTemplate) validate() error {
	if template.SchemaVersion != captureTemplateSchemaVersion {
		return fmt.Errorf("unsupported capture manifest template schema %q", template.SchemaVersion)
	}
	placeholder := capture.CaptureManifest{
		SchemaVersion:           capture.CaptureManifestSchemaVersion,
		CatalogRevision:         "placeholder",
		CatalogDigest:           "sha256:" + strings.Repeat("0", 64),
		TargetID:                template.TargetID,
		SBOMPath:                "placeholder.cdx.json",
		Engine:                  template.Engine,
		EngineVersion:           template.EngineVersion,
		Binary:                  template.Binary,
		Database:                template.Database,
		Environment:             template.Environment,
		EnvironmentAttestation:  template.EnvironmentAttestation,
		EnvironmentPinReference: template.EnvironmentPinReference,
		ProfilePinReference:     template.ProfilePinReference,
		Limits:                  template.Limits,
	}
	if template.Capability != nil {
		if strings.TrimSpace(template.Capability.StatementReference) == "" {
			return fmt.Errorf("capability template requires a statement reference")
		}
		sources := make([]capture.CapabilityArtifact, 0, len(template.Capability.Sources))
		for _, source := range template.Capability.Sources {
			cleanLocator := filepath.Clean(filepath.FromSlash(source.Locator))
			if strings.TrimSpace(source.Locator) == "" || filepath.IsAbs(cleanLocator) || cleanLocator == "." || cleanLocator == ".." || strings.HasPrefix(cleanLocator, ".."+string(filepath.Separator)) || !validDigest(source.Digest) {
				return fmt.Errorf("capability source template requires a safe relative locator and immutable digest")
			}
			sources = append(sources, capture.CapabilityArtifact{Reference: source.Reference, Path: source.Locator, Digest: source.Digest})
		}
		placeholder.Capability = &capture.CapabilityManifest{
			Statement: capture.CapabilityArtifact{Reference: template.Capability.StatementReference, Path: "placeholder.json", Digest: "sha256:" + strings.Repeat("0", 64)},
			Sources:   sources,
		}
	}
	return placeholder.Validate()
}

type cyclePolicy struct {
	SchemaVersion                      string `json:"schema_version"`
	Repetitions                        int    `json:"repetitions"`
	MaxAttempts                        int    `json:"max_attempts"`
	RawRetention                       string `json:"raw_retention"`
	AcceptedArtifactRetentionDays      int    `json:"accepted_artifact_retention_days"`
	FailedAttemptArtifactRetentionDays int    `json:"failed_attempt_artifact_retention_days"`
}

func (policy cyclePolicy) validate() error {
	if policy.SchemaVersion != cyclePolicySchemaVersion {
		return fmt.Errorf("unsupported cycle policy schema %q", policy.SchemaVersion)
	}
	if policy.Repetitions != 2 {
		return fmt.Errorf("cycle policy requires exactly two accepted repetitions")
	}
	if policy.MaxAttempts < 1 {
		return fmt.Errorf("cycle policy requires a positive attempt bound")
	}
	if policy.RawRetention != "delete_after_verification" {
		return fmt.Errorf("cycle policy must delete raw retention after verification")
	}
	if policy.AcceptedArtifactRetentionDays < 1 || policy.AcceptedArtifactRetentionDays > 90 {
		return fmt.Errorf("accepted artifact retention must be between 1 and 90 days")
	}
	if policy.FailedAttemptArtifactRetentionDays < 1 || policy.FailedAttemptArtifactRetentionDays > policy.AcceptedArtifactRetentionDays {
		return fmt.Errorf("failed-attempt artifact retention is invalid")
	}
	return nil
}

type cleanupReceipt struct {
	SchemaVersion             string `json:"schema_version"`
	RawRunLocator             string `json:"raw_run_locator"`
	RawRunRootRemoved         bool   `json:"raw_run_root_removed"`
	DockerContainersRemaining int    `json:"docker_containers_remaining"`
	DockerImagesRemaining     int    `json:"docker_images_remaining"`
	DockerVolumesRemaining    int    `json:"docker_volumes_remaining"`
	DockerBuildCachePruned    bool   `json:"docker_build_cache_pruned"`
}

func (receipt cleanupReceipt) validate() error {
	if receipt.SchemaVersion != cleanupReceiptSchemaVersion || strings.TrimSpace(receipt.RawRunLocator) == "" {
		return fmt.Errorf("cleanup receipt is incomplete")
	}
	if !receipt.RawRunRootRemoved || receipt.DockerContainersRemaining != 0 || receipt.DockerImagesRemaining != 0 || receipt.DockerVolumesRemaining != 0 || !receipt.DockerBuildCachePruned {
		return fmt.Errorf("cleanup receipt does not prove bounded runner cleanup")
	}
	return nil
}

type matrixCounts struct {
	Repetitions       int `json:"repetitions"`
	Cells             int `json:"cells_per_repetition"`
	PlannedSlots      int `json:"planned_slots"`
	ScannerDispatches int `json:"scanner_dispatches"`
	Unsupported       int `json:"unsupported_records"`
}

type candidateDigests struct {
	Catalog             string `json:"catalog"`
	Oracle              string `json:"oracle"`
	Ratchet             string `json:"ratchet"`
	Plan                string `json:"plan"`
	Ledger              string `json:"ledger"`
	Result              string `json:"result"`
	PublicationManifest string `json:"publication_manifest"`
}

type publicationArtifactIndex struct {
	SchemaVersion string                   `json:"schema_version"`
	Kind          string                   `json:"kind"`
	Files         []bench.ContentReference `json:"files"`
}

func (index publicationArtifactIndex) validate() error {
	if index.SchemaVersion != publicationArtifactIndexSchemaVersion || strings.TrimSpace(index.Kind) == "" || len(index.Files) == 0 {
		return fmt.Errorf("publication artifact index is incomplete")
	}
	previous := ""
	for _, file := range index.Files {
		if err := file.Validate(); err != nil {
			return err
		}
		if file.Locator <= previous {
			return fmt.Errorf("publication artifact index files must be strictly canonical")
		}
		previous = file.Locator
	}
	return nil
}

type candidateFileInventory struct {
	SchemaVersion string                   `json:"schema_version"`
	Files         []bench.ContentReference `json:"files"`
}

type candidateReceipt struct {
	SchemaVersion        string           `json:"schema_version"`
	CycleID              string           `json:"cycle_id"`
	ImplementationCommit string           `json:"implementation_commit"`
	ArtifactName         string           `json:"artifact_name"`
	ArtifactRetention    int              `json:"artifact_retention_days"`
	Counts               matrixCounts     `json:"counts"`
	Digests              candidateDigests `json:"digests"`
	GatePassed           bool             `json:"gate_passed"`
	Cleanup              cleanupReceipt   `json:"cleanup"`
	InventoryDigest      string           `json:"inventory_digest"`
}

func (receipt candidateReceipt) validate() error {
	if receipt.SchemaVersion != candidateReceiptSchemaVersion || strings.TrimSpace(receipt.CycleID) == "" || !validCommitSHA(receipt.ImplementationCommit) || strings.TrimSpace(receipt.ArtifactName) == "" {
		return fmt.Errorf("candidate receipt identity is incomplete")
	}
	if receipt.ArtifactRetention < 1 || receipt.ArtifactRetention > 90 || receipt.Counts.Repetitions < 1 || receipt.Counts.Cells < 1 || receipt.Counts.PlannedSlots != receipt.Counts.Repetitions*receipt.Counts.Cells {
		return fmt.Errorf("candidate receipt policy or matrix counts are invalid")
	}
	if receipt.Counts.ScannerDispatches+receipt.Counts.Unsupported != receipt.Counts.PlannedSlots {
		return fmt.Errorf("candidate receipt dispatch and unsupported counts do not cover the plan")
	}
	for name, digest := range map[string]string{
		"catalog": receipt.Digests.Catalog, "oracle": receipt.Digests.Oracle, "ratchet": receipt.Digests.Ratchet,
		"plan": receipt.Digests.Plan, "ledger": receipt.Digests.Ledger, "result": receipt.Digests.Result,
		"publication manifest": receipt.Digests.PublicationManifest, "inventory": receipt.InventoryDigest,
	} {
		if !validDigest(digest) {
			return fmt.Errorf("candidate receipt %s digest is invalid", name)
		}
	}
	if !receipt.GatePassed {
		return fmt.Errorf("candidate receipt requires a passing ratchet gate")
	}
	return receipt.Cleanup.validate()
}

func canonicalCells(cells []bench.CycleCell) []bench.CycleCell {
	out := append([]bench.CycleCell(nil), cells...)
	order := make(map[bench.Engine]int, len(bench.Engines()))
	for index, engine := range bench.Engines() {
		order[engine] = index
	}
	sort.Slice(out, func(left, right int) bool {
		if out[left].TargetID != out[right].TargetID {
			return out[left].TargetID < out[right].TargetID
		}
		return order[out[left].Engine] < order[out[right].Engine]
	})
	return out
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validCommitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

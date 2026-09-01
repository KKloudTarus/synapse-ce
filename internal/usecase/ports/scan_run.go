package ports

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (run ScanRun) ValidateBegin() error {
	if strings.TrimSpace(run.TenantID) == "" || strings.TrimSpace(run.ID) == "" || strings.TrimSpace(run.EngagementID) == "" || run.CreatedAt.IsZero() {
		return fmt.Errorf("%w: scan run tenant, identity, engagement, and creation time are required", shared.ErrValidation)
	}
	if run.Provenance != scanrun.ProvenanceNative || run.TerminalStatus != scanrun.StatusBuilding || run.ManifestSchemaVersion != 0 || run.ManifestHash != "" || run.SealedAt != nil || len(run.Lanes) != 0 {
		return fmt.Errorf("%w: native scan run must begin unsealed and building", shared.ErrValidation)
	}
	return nil
}

func (run *ScanRun) Seal(status scanrun.TerminalStatus, schemaVersion int, sealedAt time.Time) error {
	if run == nil || run.Provenance != scanrun.ProvenanceNative || schemaVersion < 1 || sealedAt.IsZero() {
		return fmt.Errorf("%w: native scan run seal is invalid", shared.ErrValidation)
	}
	switch status {
	case scanrun.StatusSucceeded, scanrun.StatusPartial, scanrun.StatusFailed, scanrun.StatusCancelled:
	default:
		return fmt.Errorf("%w: scan run terminal status is invalid", shared.ErrValidation)
	}
	sealedAt = sealedAt.UTC().Truncate(time.Microsecond)
	run.CreatedAt = run.CreatedAt.UTC().Truncate(time.Microsecond)
	sealedLanes, err := scanrun.SealLanes(run.Lanes, sealedAt)
	if err != nil {
		return err
	}
	if status == scanrun.StatusSucceeded {
		if len(sealedLanes) == 0 {
			return fmt.Errorf("%w: successful scan run requires provenance lanes", shared.ErrValidation)
		}
		for _, lane := range sealedLanes {
			if lane.TerminalStatus != scanrun.StatusSucceeded {
				return fmt.Errorf("%w: successful scan run contains incomplete lane", shared.ErrValidation)
			}
		}
	}
	run.TerminalStatus = status
	run.ManifestSchemaVersion = schemaVersion
	run.SealedAt = timePointer(sealedAt.UTC())
	run.Lanes = sealedLanes
	run.FindingKeys = sortedStrings(run.FindingKeys)
	hash, err := run.canonicalHash()
	if err != nil {
		return err
	}
	run.ManifestHash = hash
	return nil
}

func (run ScanRun) ValidateSealed() error {
	if strings.TrimSpace(run.TenantID) == "" || strings.TrimSpace(run.ID) == "" || strings.TrimSpace(run.EngagementID) == "" || run.CreatedAt.IsZero() {
		return fmt.Errorf("%w: scan run identity is invalid", shared.ErrValidation)
	}
	if run.Provenance != scanrun.ProvenanceNative || run.SealedAt == nil || run.ManifestSchemaVersion < 1 || !validRunHash(run.ManifestHash) {
		return fmt.Errorf("%w: scan run is not sealed native provenance", shared.ErrValidation)
	}
	switch run.TerminalStatus {
	case scanrun.StatusSucceeded, scanrun.StatusPartial, scanrun.StatusFailed, scanrun.StatusCancelled:
	default:
		return fmt.Errorf("%w: scan run terminal status is invalid", shared.ErrValidation)
	}
	want, err := run.canonicalHash()
	if err != nil {
		return err
	}
	if run.ManifestHash != want {
		return fmt.Errorf("%w: scan run manifest hash mismatch", shared.ErrValidation)
	}
	if run.TerminalStatus == scanrun.StatusSucceeded && len(run.Lanes) == 0 {
		return fmt.Errorf("%w: successful scan run requires lanes", shared.ErrValidation)
	}
	for _, lane := range run.Lanes {
		if err := scanrun.ValidateSealedLane(lane); err != nil {
			return err
		}
		if !lane.SealedAt.Equal(*run.SealedAt) {
			return fmt.Errorf("%w: scan run lane seal time mismatch", shared.ErrValidation)
		}
	}
	return nil
}

func (run ScanRun) canonicalHash() (string, error) {
	type hashPayload struct {
		TenantID              string                 `json:"tenant_id"`
		ID                    string                 `json:"id"`
		EngagementID          string                 `json:"engagement_id"`
		CreatedAt             time.Time              `json:"created_at"`
		Manifest              ScanManifest           `json:"manifest"`
		FindingKeys           []string               `json:"finding_keys"`
		Provenance            scanrun.Provenance     `json:"provenance"`
		TerminalStatus        scanrun.TerminalStatus `json:"terminal_status"`
		ManifestSchemaVersion int                    `json:"manifest_schema_version"`
		SealedAt              *time.Time             `json:"sealed_at"`
		Lanes                 []scanrun.Lane         `json:"lanes"`
	}
	sealedAt := run.SealedAt
	if sealedAt != nil {
		value := sealedAt.UTC().Truncate(time.Microsecond)
		sealedAt = &value
	}
	lanes := append([]scanrun.Lane(nil), run.Lanes...)
	for index := range lanes {
		lanes[index].StartedAt = lanes[index].StartedAt.UTC().Truncate(time.Microsecond)
		if lanes[index].FinishedAt != nil {
			value := lanes[index].FinishedAt.UTC().Truncate(time.Microsecond)
			lanes[index].FinishedAt = &value
		}
		if lanes[index].SealedAt != nil {
			value := lanes[index].SealedAt.UTC().Truncate(time.Microsecond)
			lanes[index].SealedAt = &value
		}
		lanes[index].Stages = append([]scanrun.Stage(nil), lanes[index].Stages...)
		for stageIndex := range lanes[index].Stages {
			if lanes[index].Stages[stageIndex].StartedAt != nil {
				value := lanes[index].Stages[stageIndex].StartedAt.UTC().Truncate(time.Microsecond)
				lanes[index].Stages[stageIndex].StartedAt = &value
			}
			if lanes[index].Stages[stageIndex].FinishedAt != nil {
				value := lanes[index].Stages[stageIndex].FinishedAt.UTC().Truncate(time.Microsecond)
				lanes[index].Stages[stageIndex].FinishedAt = &value
			}
		}
	}
	return scanrun.CanonicalHash(hashPayload{
		TenantID: run.TenantID, ID: run.ID, EngagementID: run.EngagementID, CreatedAt: run.CreatedAt.UTC(),
		Manifest: run.Manifest, FindingKeys: sortedStrings(run.FindingKeys), Provenance: run.Provenance,
		TerminalStatus: run.TerminalStatus, ManifestSchemaVersion: run.ManifestSchemaVersion, SealedAt: sealedAt, Lanes: lanes,
	})
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func validRunHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func timePointer(value time.Time) *time.Time { return &value }

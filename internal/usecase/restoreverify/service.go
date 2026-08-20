// Package restoreverify verifies the read-only integrity surface of a restored
// deployment: evidence chains and their content-addressed objects, the global
// audit chain, and applied migration metadata.
package restoreverify

import (
	"context"
	"errors"
	"fmt"
	"sort"

	auditdom "github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ObjectResult struct {
	EvidenceID    string `json:"evidence_id"`
	Reference     string `json:"reference,omitempty"`
	Exists        bool   `json:"exists"`
	IdentityMatch bool   `json:"identity_match"`
	SHA256        string `json:"sha256,omitempty"`
	Error         string `json:"error,omitempty"`
}

type EvidenceChainResult struct {
	EngagementID string         `json:"engagement_id"`
	Intact       bool           `json:"intact"`
	Head         string         `json:"head"`
	Count        int            `json:"count"`
	Error        string         `json:"error,omitempty"`
	Objects      []ObjectResult `json:"objects"`
}

type AuditResult struct {
	Intact    bool   `json:"intact"`
	Verified  int    `json:"verified"`
	Unchained int    `json:"unchained"`
	Head      string `json:"head"`
	Error     string `json:"error,omitempty"`
}

type Result struct {
	Intact         bool                      `json:"intact"`
	Completeness   string                    `json:"completeness"`
	EvidenceChains []EvidenceChainResult     `json:"evidence_chains"`
	Audit          AuditResult               `json:"audit"`
	Migrations     []ports.MigrationMetadata `json:"migrations"`
}

const (
	completenessVerified   = "verified_against_expected_state"
	completenessIncomplete = "incomplete_no_expected_state"
	completenessMismatch   = "expected_state_mismatch"
)

type Service struct {
	evidence   ports.RestoreEvidenceReader
	blobs      ports.RestoreBlobReader
	migrations ports.RestoreMigrationReader
	audit      ports.RestoreAuditReader
	expected   *ports.RestoreExpectedState
}

// NewService validates read-only dependencies. At most one expected-state manifest may be supplied.
func NewService(evidenceReader ports.RestoreEvidenceReader, blobs ports.RestoreBlobReader, migrations ports.RestoreMigrationReader, auditReader ports.RestoreAuditReader, expected ...ports.RestoreExpectedState) (*Service, error) {
	if evidenceReader == nil || blobs == nil || migrations == nil || auditReader == nil || len(expected) > 1 {
		return nil, fmt.Errorf("%w: restore verification requires evidence, blob, migration, and audit readers", shared.ErrValidation)
	}
	s := &Service{evidence: evidenceReader, blobs: blobs, migrations: migrations, audit: auditReader}
	if len(expected) == 1 {
		state := expected[0]
		s.expected = &state
	}
	return s, nil
}

func (s *Service) Verify(ctx context.Context) (Result, error) {
	chains, err := s.evidence.ListEvidenceChains(ctx)
	if err != nil {
		return Result{}, contextOr(ctx, "list evidence chains", err)
	}
	migrations, err := s.migrations.MigrationMetadata(ctx)
	if err != nil {
		return Result{}, contextOr(ctx, "read migration metadata", err)
	}
	auditReport, err := s.audit.VerifyGlobal(ctx)
	if err != nil {
		return Result{}, contextOr(ctx, "verify global audit chain", err)
	}

	chains = append([]ports.RestoreEvidenceChain(nil), chains...)
	migrations = append([]ports.MigrationMetadata(nil), migrations...)
	sort.Slice(chains, func(i, j int) bool { return chains[i].ID < chains[j].ID })
	for i := 1; i < len(chains); i++ {
		if chains[i-1].ID == chains[i].ID {
			return Result{}, errors.New("duplicate evidence chain")
		}
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	for i := 1; i < len(migrations); i++ {
		if migrations[i-1].Version == migrations[i].Version {
			return Result{}, errors.New("duplicate migration version")
		}
	}

	result := Result{Intact: auditReport.Intact && auditReport.Unchained == 0, Audit: auditResult(auditReport), Migrations: migrations}
	if auditReport.Unchained != 0 {
		result.Audit.Error = "unchained_records"
	}
	if s.expected == nil {
		result.Completeness = completenessIncomplete
	} else {
		result.Completeness = completenessVerified
	}
	stats := make(map[string]objectStat)
	seenEvidence := make(map[shared.ID]struct{})
	for _, chain := range chains {
		chainResult, err := s.verifyEvidenceChain(ctx, chain, seenEvidence, stats)
		if err != nil {
			return Result{}, err
		}
		result.EvidenceChains = append(result.EvidenceChains, chainResult)
		if !chainResult.Intact {
			result.Intact = false
		}
	}
	if s.expected != nil && !matchesExpectedState(result, *s.expected) {
		result.Intact = false
		result.Completeness = completenessMismatch
	}
	return result, nil
}

type objectStat struct {
	metadata ports.ObjectMetadata
	err      error
}

func (s *Service) verifyEvidenceChain(ctx context.Context, chain ports.RestoreEvidenceChain, seen map[shared.ID]struct{}, stats map[string]objectStat) (EvidenceChainResult, error) {
	result := EvidenceChainResult{EngagementID: chain.ID.String(), Intact: true, Count: len(chain.Items)}
	if chain.ID.IsZero() {
		result.Intact = false
		result.Error = "identity_mismatch"
		return result, nil
	}
	if len(chain.Items) > 0 {
		result.Head = chain.Items[len(chain.Items)-1].Hash
	}
	for _, item := range chain.Items {
		if item.ID.IsZero() || item.EngagementID != chain.ID {
			result.Intact = false
			result.Error = "identity_mismatch"
			return result, nil
		}
		if _, exists := seen[item.ID]; exists {
			result.Intact = false
			result.Error = "identity_mismatch"
			return result, nil
		}
		seen[item.ID] = struct{}{}
	}
	if err := evidence.VerifyChain(chain.Items); err != nil {
		result.Intact = false
		result.Error = "chain_invalid"
	}
	for _, item := range chain.Items {
		if item.StorageRef == "" {
			continue
		}
		object := ObjectResult{EvidenceID: item.ID.String()}
		if !validSHA256(item.StorageRef) {
			object.Error = "invalid_reference"
			result.Intact = false
			result.Objects = append(result.Objects, object)
			continue
		}
		object.Reference = item.StorageRef
		cached, ok := stats[item.StorageRef]
		if !ok {
			metadata, err := s.blobs.Stat(ctx, item.StorageRef)
			if err != nil {
				if isContextError(ctx, err) {
					return EvidenceChainResult{}, fmt.Errorf("stat evidence object: %w", contextError(ctx, err))
				}
				cached = objectStat{err: err}
			} else {
				cached = objectStat{metadata: metadata}
			}
			stats[item.StorageRef] = cached
		}
		if cached.err != nil {
			if errors.Is(cached.err, shared.ErrNotFound) {
				object.Error = "not_found"
			} else {
				object.Error = "stat_failed"
			}
			result.Intact = false
			result.Objects = append(result.Objects, object)
			continue
		}
		object.Exists = true
		object.SHA256 = cached.metadata.SHA256
		object.IdentityMatch = cached.metadata.SHA256 == item.StorageRef
		if !object.IdentityMatch {
			object.Error = "identity_mismatch"
			result.Intact = false
		}
		result.Objects = append(result.Objects, object)
	}
	return result, nil
}

func matchesExpectedState(result Result, expected ports.RestoreExpectedState) bool {
	if result.Audit.Head != expected.AuditHead || len(result.EvidenceChains) != len(expected.EvidenceChains) || len(result.Migrations) != len(expected.MigrationVersions) {
		return false
	}
	expectedChains := append([]ports.RestoreExpectedEvidenceChain(nil), expected.EvidenceChains...)
	sort.Slice(expectedChains, func(i, j int) bool { return expectedChains[i].EngagementID < expectedChains[j].EngagementID })
	for i, actual := range result.EvidenceChains {
		want := expectedChains[i]
		if actual.EngagementID != want.EngagementID.String() || actual.Head != want.Head || actual.Count != want.Count {
			return false
		}
	}
	expectedVersions := append([]int64(nil), expected.MigrationVersions...)
	sort.Slice(expectedVersions, func(i, j int) bool { return expectedVersions[i] < expectedVersions[j] })
	for i, actual := range result.Migrations {
		if actual.Version != expectedVersions[i] || !actual.Applied {
			return false
		}
	}
	return true
}

func auditResult(report auditdom.Report) AuditResult {
	return AuditResult{Intact: report.Intact && report.Unchained == 0, Verified: report.Verified, Unchained: report.Unchained, Head: report.Head, Error: report.Error}
}
func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func isContextError(ctx context.Context, err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil
}
func contextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
func contextOr(ctx context.Context, operation string, err error) error {
	if isContextError(ctx, err) {
		return fmt.Errorf("%s: %w", operation, contextError(ctx, err))
	}
	return fmt.Errorf("%s: %w", operation, err)
}

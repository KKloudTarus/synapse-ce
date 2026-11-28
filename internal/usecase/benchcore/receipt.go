package benchcore

import (
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// ReceiptSchemaVersion names the run-start receipt document.
const ReceiptSchemaVersion = "synapse-benchmark-run-start-receipt-v1"

// ManifestRef names one manifest revision by id, revision and digest.
type ManifestRef struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
	Digest   string `json:"digest"`
}

// RunStartReceipt is written before any adapter runs. It copies the profile's frozen input digests, so
// preregistration is proven by digest equality between the receipt and the run, not by a timestamp.
type RunStartReceipt struct {
	SchemaVersion        string      `json:"schema_version"`
	Manifest             ManifestRef `json:"manifest"`
	ProfileID            string      `json:"profile_id"`
	RunKey               string      `json:"run_key"`
	ImplementationCommit string      `json:"implementation_commit"`
	SourceTreeDigest     string      `json:"source_tree_digest"`
	WorktreeDirty        bool        `json:"worktree_dirty"`
	CorpusDigest         string      `json:"corpus_digest"`
	TruthDigest          string      `json:"truth_digest"`
	Scorer               Identity    `json:"scorer"`
	EnrollmentDigest     string      `json:"enrollment_digest"`
	RunnerIdentity       string      `json:"runner_identity"`
	// RecordedAt is informational. It is not evidence of order; the digests are.
	RecordedAt string `json:"recorded_at"`
}

// ErrInvalidReceipt is wrapped by every receipt failure.
var ErrInvalidReceipt = errors.New("invalid run-start receipt")

// RunStart describes the run about to begin.
type RunStart struct {
	ProfileID            string
	RunKey               string
	ImplementationCommit string
	SourceTreeDigest     string
	WorktreeDirty        bool
	RunnerIdentity       string
	RecordedAt           string
}

// NewRunStartReceipt binds a run to a manifest revision and copies the profile's frozen digests.
func NewRunStartReceipt(m ClosureManifest, start RunStart) (RunStartReceipt, error) {
	if err := m.Validate(); err != nil {
		return RunStartReceipt{}, err
	}
	profile, ok := m.Profile(start.ProfileID)
	if !ok {
		return RunStartReceipt{}, fmt.Errorf("%w: profile %q is not in manifest %s revision %d", ErrInvalidReceipt, start.ProfileID, m.ManifestID, m.Revision)
	}
	if strings.TrimSpace(start.RunKey) == "" || strings.TrimSpace(start.ImplementationCommit) == "" || strings.TrimSpace(start.RunnerIdentity) == "" {
		return RunStartReceipt{}, fmt.Errorf("%w: run_key, implementation_commit and runner_identity are required", ErrInvalidReceipt)
	}
	digest, err := DigestManifest(m)
	if err != nil {
		return RunStartReceipt{}, err
	}
	enrollment, err := DigestEnrollment(profile)
	if err != nil {
		return RunStartReceipt{}, err
	}
	return RunStartReceipt{
		SchemaVersion:        ReceiptSchemaVersion,
		Manifest:             ManifestRef{ID: m.ManifestID, Revision: m.Revision, Digest: digest},
		ProfileID:            profile.ID,
		RunKey:               start.RunKey,
		ImplementationCommit: start.ImplementationCommit,
		SourceTreeDigest:     start.SourceTreeDigest,
		WorktreeDirty:        start.WorktreeDirty,
		CorpusDigest:         profile.Corpus.Digest,
		TruthDigest:          profile.Truth.Digest,
		Scorer:               profile.Scorer,
		EnrollmentDigest:     enrollment,
		RunnerIdentity:       start.RunnerIdentity,
		RecordedAt:           start.RecordedAt,
	}, nil
}

// DigestReceipt is the receipt's identity.
func DigestReceipt(r RunStartReceipt) (string, error) {
	encoded, err := benchmark.CanonicalJSON(r)
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(encoded), nil
}

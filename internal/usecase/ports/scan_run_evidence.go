package ports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const MaxScanRunEvidenceBytes = 128 << 20

// ScanRunEvidence retains redacted comparison inputs, never the mutable latest
// result cache. ContentHash is included in the sealed lane manifest.
type ScanRunEvidence struct {
	TenantID    shared.ID
	RunID       string
	ContentHash string
	Payload     []byte
}

func (e ScanRunEvidence) Validate() error {
	if e.TenantID.IsZero() || e.RunID == "" || len(e.Payload) == 0 || len(e.Payload) > MaxScanRunEvidenceBytes || !json.Valid(e.Payload) {
		return fmt.Errorf("%w: invalid immutable scan evidence", shared.ErrValidation)
	}
	digest := sha256.Sum256(e.Payload)
	if hex.EncodeToString(digest[:]) != e.ContentHash {
		return fmt.Errorf("%w: scan evidence content hash mismatch", shared.ErrValidation)
	}
	return nil
}

type ScanRunEvidenceStore interface {
	SaveScanRunEvidence(context.Context, ScanRunEvidence) error
	GetScanRunEvidence(context.Context, shared.ID, string) (ScanRunEvidence, error)
}

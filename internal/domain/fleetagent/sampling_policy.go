package fleetagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SamplingPolicyDigest commits the complete sampling-policy tuple named by A3.
// Length-prefixing every field makes the commitment unambiguous without relying
// on JSON key ordering or whitespace, and keeps future policy changes explicit.
const (
	NoSamplingAlgorithm = "none"
	NoSamplingPolicyID  = "none"
	NoSamplingVersion   = uint64(1)
)

func SamplingPolicyDigest(algorithm, policyID, seed string, version uint64) (string, error) {
	if algorithm == "" || policyID == "" || version == 0 {
		return "", fmt.Errorf("%w: sampling policy commitment requires algorithm, policy id and positive version", shared.ErrValidation)
	}
	h := sha256.New()
	writeTelemetryCommitField(h, "synapse-sampling-policy:v1")
	writeTelemetryCommitField(h, algorithm)
	writeTelemetryCommitField(h, policyID)
	writeTelemetryCommitField(h, seed)
	writeTelemetryCommitField(h, strconv.FormatUint(version, 10))
	return hex.EncodeToString(h.Sum(nil)), nil
}

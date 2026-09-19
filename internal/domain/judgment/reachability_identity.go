package judgment

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ArtifactIdentity identifies one immutable input artifact by its stable identity
// and content digest. It does not establish where the artifact originated.
type ArtifactIdentity struct {
	id     string
	digest string
}

// NewArtifactIdentity validates an artifact's stable identity and SHA-256 content
// digest. Digest values are intentionally canonical lowercase sha256: digests.
func NewArtifactIdentity(id, digest string) (ArtifactIdentity, error) {
	identity := ArtifactIdentity{id: id, digest: digest}
	if !identity.Valid() {
		return ArtifactIdentity{}, fmt.Errorf("%w: invalid artifact identity", shared.ErrValidation)
	}
	return identity, nil
}

// ID returns the artifact's stable identity.
func (i ArtifactIdentity) ID() string { return i.id }

// Digest returns the canonical SHA-256 content digest.
func (i ArtifactIdentity) Digest() string { return i.digest }

// Valid reports whether the artifact identity is complete and canonical.
func (i ArtifactIdentity) Valid() bool {
	return validStableIdentity(i.id) && validSHA256Digest(i.digest)
}

// Equal reports whether two immutable artifact identities name identical content.
func (i ArtifactIdentity) Equal(other ArtifactIdentity) bool {
	return i.id == other.id && i.digest == other.digest
}

// Matches reports whether this identity has the supplied stable identity and digest.
func (i ArtifactIdentity) Matches(id, digest string) bool {
	return i.Valid() && i.id == id && i.digest == digest
}

// ReachabilitySnapshotIdentity binds a reachability conclusion to all of its
// immutable source inputs. A snapshot is valid only with source, SBOM, and run
// identities present.
type ReachabilitySnapshotIdentity struct {
	source ArtifactIdentity
	sbom   ArtifactIdentity
	run    ArtifactIdentity
}

// NewReachabilitySnapshotIdentity builds a complete immutable reachability snapshot.
func NewReachabilitySnapshotIdentity(source, sbom, run ArtifactIdentity) (ReachabilitySnapshotIdentity, error) {
	snapshot := ReachabilitySnapshotIdentity{source: source, sbom: sbom, run: run}
	if !snapshot.Valid() {
		return ReachabilitySnapshotIdentity{}, fmt.Errorf("%w: reachability snapshot requires source, sbom, and run identities", shared.ErrValidation)
	}
	return snapshot, nil
}

// Source returns the source artifact identity.
func (s ReachabilitySnapshotIdentity) Source() ArtifactIdentity { return s.source }

// SBOM returns the SBOM artifact identity.
func (s ReachabilitySnapshotIdentity) SBOM() ArtifactIdentity { return s.sbom }

// Run returns the analysis-run artifact identity.
func (s ReachabilitySnapshotIdentity) Run() ArtifactIdentity { return s.run }

// Valid reports whether every immutable input identity is present and valid.
func (s ReachabilitySnapshotIdentity) Valid() bool {
	return s.source.Valid() && s.sbom.Valid() && s.run.Valid()
}

// Equal reports whether two snapshots refer to the exact same source, SBOM, and run.
func (s ReachabilitySnapshotIdentity) Equal(other ReachabilitySnapshotIdentity) bool {
	return s.source.Equal(other.source) && s.sbom.Equal(other.sbom) && s.run.Equal(other.run)
}

// Matches reports whether this snapshot has the supplied component identities.
func (s ReachabilitySnapshotIdentity) Matches(source, sbom, run ArtifactIdentity) bool {
	return s.Valid() && s.source.Equal(source) && s.sbom.Equal(sbom) && s.run.Equal(run)
}

// ValidateMatch fails closed unless both snapshots are complete and identify the
// exact same source, SBOM, and run inputs.
func (s ReachabilitySnapshotIdentity) ValidateMatch(expected ReachabilitySnapshotIdentity) error {
	if !s.Valid() || !expected.Valid() {
		return fmt.Errorf("%w: reachability snapshot requires source, sbom, and run identities", shared.ErrValidation)
	}
	if !s.Equal(expected) {
		return fmt.Errorf("%w: stale or mismatched reachability snapshot identity", shared.ErrValidation)
	}
	return nil
}

func validStableIdentity(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			continue
		}
		if index > 0 && (character == '-' || character == '_' || character == '.' || character == '/') {
			continue
		}
		return false
	}
	return true
}

func validSHA256Digest(digest string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(digest, prefix) || len(digest) != len(prefix)+sha256.Size*2 {
		return false
	}
	for index := len(prefix); index < len(digest); index++ {
		character := digest[index]
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

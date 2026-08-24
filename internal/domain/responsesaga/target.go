package responsesaga

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FingerprintKind is the sort of target a response acts on.
type FingerprintKind string

const (
	FingerprintProcess FingerprintKind = "process"
	FingerprintFile    FingerprintKind = "file"
	FingerprintHost    FingerprintKind = "host"
)

// TargetFingerprint stably identifies what a response acts on, so a re-issued action cannot hit the wrong
// thing after a PID/path is recycled. It is NEVER a bare PID: a process target is the A1 ProcessEntityID
// (hash of asset+boot+pid+start-time); a file target is device+inode (+optional content hash), not just a
// rebindable path; a host target is the host id plus the network-policy generation the action assumes, so
// a stale management-channel change is detectable.
type TargetFingerprint struct {
	Kind FingerprintKind
	// process
	ProcessEntityID shared.ID
	// file
	FilePath   string
	FileDevice uint64
	FileInode  uint64
	FileHash   string
	// host
	HostID           shared.ID
	NetpolGeneration int64
}

// Validate enforces a stable, non-PID identity appropriate to the kind.
func (f TargetFingerprint) Validate() error {
	switch f.Kind {
	case FingerprintProcess:
		if f.ProcessEntityID.IsZero() {
			return fmt.Errorf("%w: process target requires a stable ProcessEntityID (never a bare PID)", shared.ErrValidation)
		}
	case FingerprintFile:
		if f.FilePath == "" {
			return fmt.Errorf("%w: file target requires a path", shared.ErrValidation)
		}
		// A stable file identity is the device+inode PAIR (a device alone names a whole filesystem, an
		// inode alone is ambiguous across filesystems) or a content hash — never a partial of either.
		if (f.FileDevice == 0 || f.FileInode == 0) && f.FileHash == "" {
			return fmt.Errorf("%w: file target requires the device+inode pair or a content hash (a path alone is rebindable)", shared.ErrValidation)
		}
	case FingerprintHost:
		if f.HostID.IsZero() {
			return fmt.Errorf("%w: host target requires a host id", shared.ErrValidation)
		}
		// The netpol generation the action assumes is what makes a stale management-channel change
		// detectable, so it must be a real (>=1) generation, not the unset zero.
		if f.NetpolGeneration < 1 {
			return fmt.Errorf("%w: host target requires the assumed network-policy generation (>=1)", shared.ErrValidation)
		}
	default:
		return fmt.Errorf("%w: unknown target fingerprint kind %q", shared.ErrValidation, f.Kind)
	}
	return nil
}

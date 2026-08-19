package telemetry

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FileObservation is a raw sensitive-path file observation — telemetry's own type, distinct from
// detection.FileEvent. It carries the fields that make a file TARGET a stable identity (device + inode +
// optional content hash) rather than a bare, rebindable path, and it links to the acting process by
// stable entity id. The operation is a real verb (open/write/rename), never the hardcoded "open" the thin
// decode path used to stamp.
type FileObservation struct {
	// Op is "open", "write", or "rename".
	Op   string
	Path string
	// Device / Inode pin the concrete filesystem object behind Path (which is rebindable). Zero is
	// allowed when the sensor could not stat the target; TargetID then falls back to path+hash.
	Device uint64
	Inode  uint64
	// ContentHash is an optional sha256 of the file's contents at observation time.
	ContentHash   string
	PathTruncated bool
	PID           int
	// ProcessEntityID links the access to its process; empty when it could not be correlated.
	ProcessEntityID shared.ID
	Comm            string
}

// Validate enforces a well-formed file observation.
func (f FileObservation) Validate() error {
	switch f.Op {
	case "open", "write", "rename":
	default:
		return fmt.Errorf("%w: file observation has unknown op %q", shared.ErrValidation, f.Op)
	}
	if f.Path == "" {
		return fmt.Errorf("%w: file observation has no path", shared.ErrValidation)
	}
	return nil
}

// TargetID returns the stable file-target identity for this observation.
func (f FileObservation) TargetID() shared.ID {
	return FileTargetID(f.Path, f.Device, f.Inode, f.ContentHash)
}

func (f FileObservation) clone() *FileObservation {
	c := f
	return &c
}

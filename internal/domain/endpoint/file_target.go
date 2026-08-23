package endpoint

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FileTarget is a stable file object reconstructed from file telemetry (B3, File Integrity Monitoring).
// Its identity is the A1 FileTargetID (path + device + inode + optional content hash), so a rebindable
// path (rename/symlink/bind-mount) does not alias two distinct objects, and the concrete object is tracked
// across accesses. The last operation and content hash are resolved latest-by-event-time; the seen window
// is a min/max, so the projection is order-independent.
type FileTarget struct {
	TargetID            shared.ID
	TenantID            shared.ID
	AssetID             shared.ID
	Path                string
	Device              uint64
	Inode               uint64
	ContentHash         string
	PathTruncated       bool
	LastOp              string
	LastProcessEntityID shared.ID
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
	// lastOpEventID is the EventID of the access that last set LastOp/LastProcessEntityID — the tiebreak
	// that keeps them reorder-invariant across same-instant accesses of one target. Unexported bookkeeping.
	lastOpEventID shared.ID
}

// Validate enforces a well-formed file target.
func (f FileTarget) Validate() error {
	if f.TargetID.IsZero() {
		return fmt.Errorf("%w: file target has no target id", shared.ErrValidation)
	}
	if f.AssetID.IsZero() {
		return fmt.Errorf("%w: file target has no asset id", shared.ErrValidation)
	}
	if f.Path == "" {
		return fmt.Errorf("%w: file target has no path", shared.ErrValidation)
	}
	return nil
}

func (f FileTarget) clone() FileTarget { return f }

// fileTimelineKind maps a file op to its timeline transition kind.
func fileTimelineKind(op string) TimelineEntryKind {
	switch op {
	case "write":
		return TimelineFileWrite
	case "rename":
		return TimelineFileRename
	default:
		return TimelineFileOpen
	}
}

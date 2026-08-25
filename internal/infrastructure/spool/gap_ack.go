package spool

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AckGap removes one durable gap only when the local object still equals the exact
// snapshot the server acknowledged. This closes the coalescing race: if another loss
// extended Count/range/time while the older report was in flight, the newer evidence
// remains on disk and is shipped again instead of being deleted by a stale ACK.
func (s *Spool) AckGap(ctx context.Context, reported ports.SpoolGap) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := reported.Validate(); err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return false, err
	}

	index := -1
	for i := range s.gaps {
		if s.gaps[i].ID == reported.ID {
			index = i
			break
		}
	}
	if index < 0 {
		return true, nil // idempotent ACK after a prior successful delete
	}
	if !s.gaps[index].SameSnapshot(reported) {
		return false, nil
	}

	// Keep a rollback snapshot until the compacted journal has been atomically
	// rewritten + fsynced. A persistence failure puts the spool into fail-closed
	// state, but restoring memory still prevents an in-process silent deletion.
	before := append([]ports.SpoolGap(nil), s.gaps...)
	wasDirty := s.gapDirty
	wasPending := s.gapPending
	kept := make([]ports.SpoolGap, 0, len(s.gaps)-1)
	kept = append(kept, s.gaps[:index]...)
	kept = append(kept, s.gaps[index+1:]...)
	s.gaps = kept
	s.gapDirty = true
	if err := s.flushGapJournalLocked(); err != nil {
		s.gaps = before
		s.gapDirty = wasDirty
		s.gapPending = wasPending
		return false, err
	}
	return true, nil
}

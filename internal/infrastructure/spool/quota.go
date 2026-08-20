package spool

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (s *Spool) ensureCapacityLocked(required int64, incoming fleetagent.DeliveryPriority) error {
	if required > s.cfg.SegmentBytes || required > s.walMaxBytesLocked() {
		return fmt.Errorf("%w: encoded WAL frame is %d bytes, maximum permanent capacity is %d",
			shared.ErrValidation, required, min(s.cfg.SegmentBytes, s.walMaxBytesLocked()))
	}
	if _, err := s.removeEmptySegmentsLocked(); err != nil {
		return err
	}
	if s.totalBytes+required <= s.walMaxBytesLocked() {
		return nil
	}
	segments := append([]*segment(nil), s.segments...)
	sort.SliceStable(segments, func(i, j int) bool {
		if segments[i].epoch != segments[j].epoch {
			return segments[i].epoch < segments[j].epoch
		}
		return segments[i].start < segments[j].start
	})
	for _, seg := range segments {
		if seg.priority != fleetagent.PriorityP3 || seg.live == 0 {
			continue
		}
		refs := s.segmentRefsLocked(seg)
		if err := s.recordEvictionGapsLocked(refs); err != nil {
			return fmt.Errorf("persist P3 eviction evidence: %w", err)
		}
		s.evictedRecords += uint64(len(refs))
		if err := s.deleteSegmentLocked(seg); err != nil {
			return err
		}
		if s.totalBytes+required <= s.walMaxBytesLocked() {
			return nil
		}
	}
	return s.saturatedLocked(required, incoming)
}

func (s *Spool) saturatedLocked(required int64, incoming fleetagent.DeliveryPriority) error {
	// P0..P2 apply backpressure and retain the item at the producer, so no loss
	// gap exists yet. P3 is explicitly shed by its adapter and needs one durable,
	// coalesced record for the ongoing saturation interval.
	if incoming == fleetagent.PriorityP3 {
		if err := s.recordP3LossLocked(ports.SpoolGapQuotaEviction); err != nil {
			return fmt.Errorf("record quota saturation evidence: %w", err)
		}
	}
	return &SaturatedError{UsedBytes: s.usedBytesLocked(), MaxBytes: s.cfg.MaxBytes, RequiredBytes: required}
}

func (s *Spool) walMaxBytesLocked() int64 { return s.cfg.MaxBytes - s.cfg.MaxGapBytes }

func (s *Spool) usedBytesLocked() int64 { return s.totalBytes + s.gapBytes }

func (s *Spool) recordEvictionGapsLocked(refs []*recordRef) error {
	if len(refs) == 0 {
		return nil
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].header.Epoch != refs[j].header.Epoch {
			return refs[i].header.Epoch < refs[j].header.Epoch
		}
		return refs[i].header.Sequence < refs[j].header.Sequence
	})
	start := refs[0].header.Sequence
	end := start
	epoch := refs[0].header.Epoch
	flush := func() error {
		return s.appendKnownGapLocked(fleetagent.PriorityP3, epoch, start, end, ports.SpoolGapQuotaEviction)
	}
	for _, ref := range refs[1:] {
		if ref.header.Epoch == epoch && ref.header.Sequence == end+1 {
			end = ref.header.Sequence
			continue
		}
		if err := flush(); err != nil {
			return err
		}
		epoch, start, end = ref.header.Epoch, ref.header.Sequence, ref.header.Sequence
	}
	return flush()
}

func (s *Spool) segmentRefsLocked(target *segment) []*recordRef {
	var result []*recordRef
	for _, ref := range s.records[target.priority] {
		if ref.segment == target {
			result = append(result, ref)
		}
	}
	return result
}

func (s *Spool) deleteSegmentLocked(target *segment) error {
	if writer := s.writers[target.priority]; writer == target {
		if err := s.syncSegmentLocked(target); err != nil {
			return err
		}
		if target.file != nil {
			if err := target.file.Close(); err != nil {
				return err
			}
			target.file = nil
		}
		s.writers[target.priority] = nil
	}
	keptRefs := s.records[target.priority][:0]
	for _, ref := range s.records[target.priority] {
		if ref.segment != target {
			keptRefs = append(keptRefs, ref)
		}
	}
	s.records[target.priority] = keptRefs
	keptSegments := s.segments[:0]
	for _, seg := range s.segments {
		if seg != target {
			keptSegments = append(keptSegments, seg)
		}
	}
	s.segments = keptSegments
	if err := os.Remove(target.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete WAL segment: %w", err)
	}
	s.totalBytes -= target.size
	if s.totalBytes < 0 {
		s.totalBytes = 0
	}
	return syncDirectory(s.cfg.Dir)
}

func (s *Spool) removeEmptySegmentsLocked() (int64, error) {
	var reclaimed int64
	for _, seg := range append([]*segment(nil), s.segments...) {
		if seg.live != 0 {
			continue
		}
		size := seg.size
		if err := s.deleteSegmentLocked(seg); err != nil {
			return reclaimed, err
		}
		reclaimed += size
	}
	return reclaimed, nil
}

package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recoveredFrame struct {
	bytes    []byte
	header   frameHeader
	observed int64
}

func (s *Spool) recoverSegmentsLocked() (uint64, error) {
	entries, err := os.ReadDir(s.cfg.Dir)
	if err != nil {
		return 0, fmt.Errorf("list spool directory: %w", err)
	}
	type candidate struct {
		name     string
		priority fleetagent.DeliveryPriority
		epoch    uint64
		start    uint64
	}
	var candidates []candidate
	var maxEpoch uint64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		priority, epoch, start, ok := parseSegmentName(entry.Name())
		if !ok {
			continue
		}
		candidates = append(candidates, candidate{entry.Name(), priority, epoch, start})
		if epoch > maxEpoch {
			maxEpoch = epoch
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority < candidates[j].priority
		}
		if candidates[i].epoch != candidates[j].epoch {
			return candidates[i].epoch < candidates[j].epoch
		}
		return candidates[i].start < candidates[j].start
	})

	seen := make(map[string]struct{})
	for _, candidate := range candidates {
		path := filepath.Join(s.cfg.Dir, candidate.name)
		if err := securePath(path, 0o600); err != nil {
			return 0, fmt.Errorf("secure WAL segment: %w", err)
		}
		frames, damaged, err := s.scanSegmentLocked(path, candidate.priority, candidate.epoch)
		if err != nil {
			return 0, err
		}
		kept := frames[:0]
		for _, frame := range frames {
			key := fmt.Sprintf("%d:%d:%d", frame.header.Priority, frame.header.Epoch, frame.header.Sequence)
			if _, duplicate := seen[key]; duplicate {
				return 0, fmt.Errorf("duplicate WAL coordinate %s across segments", key)
			}
			seen[key] = struct{}{}
			acked := s.state.ACK[ackKey(candidate.priority, candidate.epoch)]
			if frame.header.Sequence <= acked {
				damaged = true // compact already-ACKed bytes during startup
				continue
			}
			kept = append(kept, frame)
		}
		frames = kept
		if len(frames) == 0 {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return 0, fmt.Errorf("remove empty WAL segment: %w", err)
			}
			continue
		}
		if damaged {
			if err := rewriteRecoveredSegment(path, frames); err != nil {
				return 0, err
			}
		}
		seg := &segment{
			priority: candidate.priority, epoch: candidate.epoch, start: frames[0].header.Sequence,
			path: path,
		}
		var offset int64
		for _, frame := range frames {
			length := int64(len(frame.bytes))
			seg.live++
			s.records[candidate.priority] = append(s.records[candidate.priority], &recordRef{
				segment: seg, offset: offset, length: length, header: frame.header,
				observed: unixNanoUTC(frame.observed),
			})
			offset += length
		}
		seg.size = offset
		s.totalBytes += offset
		s.segments = append(s.segments, seg)
	}
	for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP3; priority++ {
		sortRecords(s.records[priority])
	}
	if err := syncDirectory(s.cfg.Dir); err != nil {
		return 0, fmt.Errorf("sync recovered spool directory: %w", err)
	}
	return maxEpoch, nil
}

func (s *Spool) scanSegmentLocked(path string, expectedPriority fleetagent.DeliveryPriority, expectedEpoch uint64) ([]recoveredFrame, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, fmt.Errorf("stat WAL segment: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("refuse symlink WAL segment %s", filepath.Base(path))
	}
	// Older versions allowed metadata headroom outside SegmentBytes. Keep that
	// bounded compatibility window, but inspect the file size before ReadFile so
	// a hostile sparse/large segment cannot force an unbounded allocation.
	maxSegmentRead := s.cfg.SegmentBytes + (256 << 10) + frameHeaderSize
	if info.Size() > maxSegmentRead {
		return nil, false, fmt.Errorf("WAL segment exceeds recovery bound: size=%d bound=%d", info.Size(), maxSegmentRead)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read WAL segment: %w", err)
	}
	if int64(len(data)) > maxSegmentRead {
		return nil, false, fmt.Errorf("WAL segment exceeds recovery bound: size=%d bound=%d", len(data), maxSegmentRead)
	}
	if len(data) == 0 {
		return nil, true, nil
	}
	var frames []recoveredFrame
	damaged := false
	for offset := 0; offset < len(data); {
		remaining := len(data) - offset
		if remaining < frameHeaderSize {
			if err := s.appendUnknownGapLocked(expectedPriority, expectedEpoch, ports.SpoolGapTornWrite); err != nil {
				return nil, damaged, err
			}
			s.corruptionEvents++
			damaged = true
			break
		}
		header := unmarshalHeader(data[offset : offset+frameHeaderSize])
		headerTrusted := header.Magic == frameMagic && header.Version == frameVersion &&
			header.HeaderSize == frameHeaderSize && header.Epoch == expectedEpoch &&
			fleetagent.DeliveryPriority(header.Priority) == expectedPriority && header.Sequence > 0
		if err := validateHeader(header); err != nil || !headerTrusted || int64(header.BodySize) > s.cfg.MaxRecordBytes+maxFrameMetadataBytes {
			if headerTrusted {
				if gapErr := s.appendKnownGapLocked(expectedPriority, expectedEpoch, header.Sequence, header.Sequence, ports.SpoolGapCorruptFrame); gapErr != nil {
					return nil, damaged, gapErr
				}
			} else if gapErr := s.appendUnknownGapLocked(expectedPriority, expectedEpoch, ports.SpoolGapCorruptFrame); gapErr != nil {
				return nil, damaged, gapErr
			}
			s.corruptionEvents++
			damaged = true
			next := nextMagic(data, offset+1)
			if next < 0 {
				break
			}
			offset = next
			continue
		}
		length := frameHeaderSize + int(header.BodySize)
		if length > remaining {
			if err := s.appendKnownGapLocked(expectedPriority, expectedEpoch, header.Sequence, header.Sequence, ports.SpoolGapTornWrite); err != nil {
				return nil, damaged, err
			}
			s.corruptionEvents++
			damaged = true
			break
		}
		frameBytes := append([]byte(nil), data[offset:offset+length]...)
		record, decodedHeader, err := decodeFrame(frameBytes)
		if err != nil || decodedHeader.Priority != header.Priority || record.Position.Epoch != expectedEpoch {
			if gapErr := s.appendKnownGapLocked(expectedPriority, expectedEpoch, header.Sequence, header.Sequence, ports.SpoolGapCorruptFrame); gapErr != nil {
				return nil, damaged, gapErr
			}
			s.corruptionEvents++
			damaged = true
			next := nextMagic(data, offset+1)
			if next < 0 {
				break
			}
			offset = next
			continue
		}
		frames = append(frames, recoveredFrame{bytes: frameBytes, header: header, observed: header.ObservedNS})
		offset += length
	}
	return frames, damaged, nil
}

func rewriteRecoveredSegment(path string, frames []recoveredFrame) error {
	tmp := path + ".repair"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		if removeErr := os.Remove(tmp); removeErr != nil {
			return fmt.Errorf("remove abandoned WAL repair: %w", removeErr)
		}
		f, err = os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	}
	if err != nil {
		return fmt.Errorf("create repaired WAL segment: %w", err)
	}
	for _, frame := range frames {
		if _, err := f.Write(frame.bytes); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("write repaired WAL segment: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync repaired WAL segment: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install repaired WAL segment: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func (s *Spool) reconcileAssignedTailLocked() error {
	for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP3; priority++ {
		assigned := s.state.AssignedThrough[priority]
		covered := s.state.ACK[ackKey(priority, s.state.CurrentEpoch)]
		for _, ref := range s.records[priority] {
			if ref.header.Epoch == s.state.CurrentEpoch && ref.header.Sequence > covered {
				covered = ref.header.Sequence
			}
		}
		for _, gap := range s.gaps {
			if gap.Priority == priority && gap.Epoch == s.state.CurrentEpoch && gap.KnownSequence && gap.ToSequence > covered {
				covered = gap.ToSequence
			}
		}
		if covered > assigned {
			s.state.AssignedThrough[priority] = covered
			continue
		}
		if assigned > covered {
			if err := s.appendKnownGapLocked(priority, s.state.CurrentEpoch, covered+1, assigned, ports.SpoolGapUnsyncedTail); err != nil {
				return err
			}
		}
	}
	return nil
}

func unixNanoUTC(value int64) time.Time { return time.Unix(0, value).UTC() }

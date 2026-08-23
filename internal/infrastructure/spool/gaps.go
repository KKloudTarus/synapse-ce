package spool

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	gapMagic         uint32 = 0x53594750 // SYGP
	gapHeaderSize           = 12
	maxGapBody              = 64 << 10
	gapCoalesceBatch        = 256
)

func openGapJournal(dir string) (*os.File, []ports.SpoolGap, int64, error) {
	path := filepath.Join(dir, "gaps.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("open gap journal: %w", err)
	}
	if err := securePath(path, 0o600); err != nil {
		_ = f.Close()
		return nil, nil, 0, fmt.Errorf("secure gap journal: %w", err)
	}
	gaps, validBytes, err := readGapJournal(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, 0, err
	}
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, 0, err
	}
	if stat.Size() != validBytes {
		if err := f.Truncate(validBytes); err != nil {
			_ = f.Close()
			return nil, nil, 0, fmt.Errorf("truncate torn gap journal: %w", err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil, nil, 0, fmt.Errorf("sync repaired gap journal: %w", err)
		}
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, nil, 0, err
	}
	return f, gaps, validBytes, nil
}

func readGapJournal(f *os.File) ([]ports.SpoolGap, int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}
	var gaps []ports.SpoolGap
	var offset int64
	header := make([]byte, gapHeaderSize)
	for {
		n, err := io.ReadFull(f, header)
		if errors.Is(err, io.EOF) {
			return gaps, offset, nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return gaps, offset, nil // a crash before Sync: safe to truncate
		}
		if err != nil {
			return nil, offset, fmt.Errorf("read gap journal header: %w", err)
		}
		if n != gapHeaderSize || binary.LittleEndian.Uint32(header[0:4]) != gapMagic {
			return nil, offset, fmt.Errorf("gap journal corruption at offset %d", offset)
		}
		length := binary.LittleEndian.Uint32(header[4:8])
		checksum := binary.LittleEndian.Uint32(header[8:12])
		if length == 0 || length > maxGapBody {
			return nil, offset, fmt.Errorf("invalid gap record length %d at offset %d", length, offset)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(f, body); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return gaps, offset, nil
			}
			return nil, offset, fmt.Errorf("read gap journal body: %w", err)
		}
		if crc32.Checksum(body, castagnoli) != checksum {
			return nil, offset, fmt.Errorf("gap journal checksum mismatch at offset %d", offset)
		}
		var gap ports.SpoolGap
		if err := json.Unmarshal(body, &gap); err != nil {
			return nil, offset, fmt.Errorf("decode gap at offset %d: %w", offset, err)
		}
		if err := gap.Validate(); err != nil {
			return nil, offset, fmt.Errorf("validate gap at offset %d: %w", offset, err)
		}
		gaps = append(gaps, gap)
		offset += int64(gapHeaderSize) + int64(length)
	}
}

func (s *Spool) appendGapLocked(gap ports.SpoolGap) error {
	if err := gap.Validate(); err != nil {
		return err
	}
	if len(s.gaps) > 0 && mergeGap(&s.gaps[len(s.gaps)-1], gap) {
		s.gapDirty = true
		return s.flushGapJournalLocked()
	}
	frame, err := encodeGapFrame(gap)
	if err != nil {
		return err
	}
	if s.gapBytes+int64(len(frame)) > s.gapJournalLimitLocked() {
		s.gaps = compactGaps(s.gaps)
		s.gapDirty = true
		if err := s.flushGapJournalLocked(); err != nil {
			return err
		}
	}
	if s.gapBytes+int64(len(frame)) > s.gapJournalLimitLocked() {
		return s.failLocked(fmt.Errorf("%w: used=%d max=%d required=%d", ErrGapJournalFull, s.gapBytes, s.gapJournalLimitLocked(), len(frame)))
	}
	written, writeErr := s.gapFile.Write(frame)
	if writeErr != nil || written != len(frame) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		truncateErr := s.gapFile.Truncate(s.gapBytes)
		_, seekErr := s.gapFile.Seek(0, io.SeekEnd)
		appendErr := errors.Join(fmt.Errorf("append spool gap: %w", writeErr), truncateErr, seekErr)
		return s.failLocked(appendErr)
	}
	started := s.cfg.Now()
	if err := s.syncFile(s.gapFile); err != nil {
		return s.failLocked(fmt.Errorf("sync spool gap: %w", err))
	}
	s.observeSyncLocked(started)
	s.gaps = append(s.gaps, gap)
	s.gapBytes += int64(len(frame))
	s.lastGapSync = s.cfg.Now().UTC()
	return nil
}

func (s *Spool) recordP3LossLocked(reason ports.SpoolGapReason) error {
	for index := len(s.gaps) - 1; index >= 0; index-- {
		gap := &s.gaps[index]
		if gap.Priority != fleetagent.PriorityP3 || gap.Epoch != s.state.CurrentEpoch ||
			gap.Reason != reason || gap.KnownSequence {
			continue
		}
		if gap.Count == ^uint64(0) {
			return s.failLocked(errors.New("P3 coalesced gap count overflow"))
		}
		gap.Count++
		s.gapDirty = true
		s.gapPending++
		now := s.cfg.Now().UTC()
		if s.gapPending >= gapCoalesceBatch || (!s.lastGapSync.IsZero() && now.Sub(s.lastGapSync) >= s.cfg.BatchInterval) {
			return s.flushGapJournalLocked()
		}
		return nil
	}
	return s.appendUnknownGapLocked(fleetagent.PriorityP3, s.state.CurrentEpoch, reason)
}

func encodeGapFrame(gap ports.SpoolGap) ([]byte, error) {
	body, err := json.Marshal(gap)
	if err != nil {
		return nil, fmt.Errorf("encode spool gap: %w", err)
	}
	if len(body) > maxGapBody {
		return nil, errors.New("encoded spool gap exceeds journal format limit")
	}
	frame := make([]byte, gapHeaderSize+len(body))
	binary.LittleEndian.PutUint32(frame[0:4], gapMagic)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(len(body)))
	binary.LittleEndian.PutUint32(frame[8:12], crc32.Checksum(body, castagnoli))
	copy(frame[gapHeaderSize:], body)
	return frame, nil
}

func (s *Spool) flushGapJournalLocked() error {
	if !s.gapDirty {
		return nil
	}
	if s.gapFile == nil {
		return s.failLocked(errors.New("gap journal is unavailable"))
	}
	started := s.cfg.Now()
	var snapshot bytes.Buffer
	for _, gap := range s.gaps {
		frame, err := encodeGapFrame(gap)
		if err != nil {
			return err
		}
		if _, err := snapshot.Write(frame); err != nil {
			return err
		}
	}
	if int64(snapshot.Len()) > s.gapJournalLimitLocked() {
		return s.failLocked(fmt.Errorf("%w: compacted=%d max=%d", ErrGapJournalFull, snapshot.Len(), s.gapJournalLimitLocked()))
	}
	path := filepath.Join(s.cfg.Dir, "gaps.log")
	tmp := path + ".tmp"
	if err := writeExclusiveSyncedFile(tmp, snapshot.Bytes(), 0o600); err != nil {
		return s.failLocked(fmt.Errorf("write compacted gap journal: %w", err))
	}
	if err := s.gapFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return s.failLocked(fmt.Errorf("close old gap journal: %w", err))
	}
	s.gapFile = nil
	if err := replaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		_ = s.reopenGapJournalLocked(path)
		return s.failLocked(fmt.Errorf("install compacted gap journal: %w", err))
	}
	if err := syncDirectory(s.cfg.Dir); err != nil {
		_ = s.reopenGapJournalLocked(path)
		return s.failLocked(fmt.Errorf("sync compacted gap journal: %w", err))
	}
	if err := s.reopenGapJournalLocked(path); err != nil {
		return s.failLocked(err)
	}
	s.gapBytes = int64(snapshot.Len())
	s.gapDirty = false
	s.gapPending = 0
	s.lastGapSync = s.cfg.Now().UTC()
	s.observeSyncLocked(started)
	return nil
}

func (s *Spool) gapJournalLimitLocked() int64 { return s.cfg.MaxGapBytes / 2 }

func (s *Spool) reopenGapJournalLocked(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("reopen gap journal: %w", err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return fmt.Errorf("seek reopened gap journal: %w", err)
	}
	s.gapFile = f
	return nil
}

func writeExclusiveSyncedFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if errors.Is(err, os.ErrExist) {
		if removeErr := os.Remove(path); removeErr != nil {
			return removeErr
		}
		f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func compactGaps(in []ports.SpoolGap) []ports.SpoolGap {
	out := make([]ports.SpoolGap, 0, len(in))
	for _, gap := range in {
		merged := false
		for index := len(out) - 1; index >= 0; index-- {
			if mergeGap(&out[index], gap) {
				merged = true
				break
			}
		}
		if !merged {
			out = append(out, gap)
		}
	}
	return out
}

func mergeGap(current *ports.SpoolGap, next ports.SpoolGap) bool {
	if current.Priority != next.Priority || current.Epoch != next.Epoch || current.Reason != next.Reason || current.KnownSequence != next.KnownSequence {
		return false
	}
	if !current.KnownSequence {
		if ^uint64(0)-current.Count < next.Count {
			return false
		}
		current.Count += next.Count
		return true
	}
	if next.FromSequence > current.ToSequence && (current.ToSequence == ^uint64(0) || next.FromSequence != current.ToSequence+1) {
		return false
	}
	if current.FromSequence > next.ToSequence && (next.ToSequence == ^uint64(0) || current.FromSequence != next.ToSequence+1) {
		return false
	}
	if next.FromSequence < current.FromSequence {
		current.FromSequence = next.FromSequence
	}
	if next.ToSequence > current.ToSequence {
		current.ToSequence = next.ToSequence
	}
	current.Count = current.ToSequence - current.FromSequence + 1
	return true
}

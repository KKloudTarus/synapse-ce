package spool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recordRef struct {
	segment  *segment
	offset   int64
	length   int64
	header   frameHeader
	observed time.Time
}

type segment struct {
	priority fleetagent.DeliveryPriority
	epoch    uint64
	start    uint64
	path     string
	size     int64
	file     *os.File
	live     int
}

// Spool is a priority-aware, crash-recoverable implementation of ports.TelemetrySpool.
// All mutable state is guarded by mu, including file offsets: callers may safely
// enqueue, peek, ACK, and scrape metrics concurrently.
type Spool struct {
	mu      sync.Mutex
	cfg     Config
	lock    *os.File
	gapFile *os.File
	state   diskState
	closed  bool
	failed  error

	syncFile     func(*os.File) error
	persistState func(string, *diskState) error

	records  [4][]*recordRef
	segments []*segment
	writers  [4]*segment
	gaps     []ports.SpoolGap

	totalBytes  int64
	gapBytes    int64
	batchBytes  [4]int64
	lastSync    [4]time.Time
	gapDirty    bool
	gapPending  uint64
	lastGapSync time.Time

	evictedRecords   uint64
	corruptionEvents uint64
	fsyncCount       uint64
	fsyncTotal       time.Duration
}

// Open exclusively opens or creates a spool and repairs recoverable torn or
// corrupt WAL frames before returning. The lock is held until Close.
func Open(input Config) (*Spool, error) {
	cfg, err := normalizeConfig(input)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create spool directory: %w", err)
	}
	if err := securePath(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure spool directory: %w", err)
	}
	lock, err := acquireDirectoryLock(filepath.Join(cfg.Dir, ".lock"))
	if err != nil {
		return nil, fmt.Errorf("lock spool directory: %w", err)
	}
	s := &Spool{
		cfg: cfg, lock: lock,
		syncFile:     func(file *os.File) error { return file.Sync() },
		persistState: persistState,
	}
	fail := func(openErr error) (*Spool, error) {
		if s.gapFile != nil {
			_ = s.gapFile.Close()
		}
		_ = releaseDirectoryLock(lock)
		return nil, openErr
	}

	s.gapFile, s.gaps, s.gapBytes, err = openGapJournal(cfg.Dir)
	if err != nil {
		return fail(err)
	}
	s.lastGapSync = cfg.Now().UTC()
	if s.gapBytes > s.gapJournalLimitLocked() {
		s.gaps = compactGaps(s.gaps)
		s.gapDirty = true
		if err := s.flushGapJournalLocked(); err != nil {
			return fail(err)
		}
	}
	state, found, stateErr := loadState(cfg.Dir)
	if stateErr != nil {
		// WAL records are still recoverable when both state copies are damaged.
		// Recovery starts a fresh incarnation and records that degraded fact.
		found = false
	}
	s.state = state
	maxEpoch, err := s.recoverSegmentsLocked()
	if err != nil {
		return fail(err)
	}
	for _, gap := range s.gaps {
		if gap.Epoch > maxEpoch {
			maxEpoch = gap.Epoch
		}
	}
	if !found {
		epoch := maxEpoch + 1
		s.state = newDiskState(cfg.Session, cfg.Boot, epoch)
		if stateErr != nil || maxEpoch > 0 {
			for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP3; priority++ {
				if err := s.appendUnknownGapLocked(priority, epoch, ports.SpoolGapStateRecovery); err != nil {
					return fail(err)
				}
			}
		}
	} else if s.state.Session != cfg.Session || s.state.Boot != cfg.Boot {
		s.state.Session = cfg.Session
		s.state.Boot = cfg.Boot
		s.state.CurrentEpoch++
		s.state.AssignedThrough = [4]uint64{}
	}
	if s.state.CurrentEpoch < maxEpoch {
		// This is possible when recovery used a valid backup which predates a WAL
		// frame. Never reuse an incarnation observed on disk.
		s.state.CurrentEpoch = maxEpoch + 1
		s.state.AssignedThrough = [4]uint64{}
	}
	if err := s.reconcileAssignedTailLocked(); err != nil {
		return fail(err)
	}
	if err := s.persistStateLocked(); err != nil {
		return fail(err)
	}
	return s, nil
}

// Enqueue durably assigns and appends an item. Returning nil guarantees that a
// later restart can recover the record or an explicit sequence gap.
func (s *Spool) Enqueue(ctx context.Context, item ports.SpoolItem) (fleetagent.StreamPosition, error) {
	if err := ctx.Err(); err != nil {
		return fleetagent.StreamPosition{}, err
	}
	if err := item.Validate(); err != nil {
		return fleetagent.StreamPosition{}, err
	}
	if int64(len(item.Payload)) > s.cfg.MaxRecordBytes {
		return fleetagent.StreamPosition{}, fmt.Errorf("%w: payload is %d bytes, maximum is %d", shared.ErrValidation, len(item.Payload), s.cfg.MaxRecordBytes)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return fleetagent.StreamPosition{}, err
	}
	priority := item.Priority
	position := fleetagent.StreamPosition{
		Priority: priority, Epoch: s.state.CurrentEpoch,
		Sequence: s.state.AssignedThrough[priority] + 1,
		Session:  s.state.Session, Boot: s.state.Boot,
	}
	now := s.cfg.Now().UTC()
	frame, err := encodeFrame(item, position, now)
	if err != nil {
		return fleetagent.StreamPosition{}, err
	}
	if int64(len(frame)) > s.cfg.MaxRecordBytes+FrameOverheadBudget {
		return fleetagent.StreamPosition{}, fmt.Errorf("%w: encoded WAL frame exceeds record plus metadata budget", shared.ErrValidation)
	}
	if err := s.ensureCapacityLocked(int64(len(frame)), priority); err != nil {
		return fleetagent.StreamPosition{}, err
	}
	seg, err := s.writerLocked(priority, position.Epoch, position.Sequence, int64(len(frame)))
	if err != nil {
		return fleetagent.StreamPosition{}, err
	}
	offset := seg.size
	written, writeErr := seg.file.Write(frame)
	if writeErr != nil || written != len(frame) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		rollbackErr := rollbackAppend(seg.file, offset)
		appendErr := fmt.Errorf("append %s WAL frame: %w", priority, writeErr)
		if errors.Is(writeErr, syscall.ENOSPC) {
			if rollbackErr != nil {
				return fleetagent.StreamPosition{}, s.failLocked(errors.Join(appendErr, rollbackErr))
			}
			if priority == fleetagent.PriorityP3 {
				if gapErr := s.recordP3LossLocked(ports.SpoolGapIOFailure); gapErr != nil {
					return fleetagent.StreamPosition{}, errors.Join(appendErr, gapErr)
				}
			}
			return fleetagent.StreamPosition{}, errors.Join(&SaturatedError{
				UsedBytes: s.usedBytesLocked(), MaxBytes: s.cfg.MaxBytes, RequiredBytes: int64(len(frame)),
			}, appendErr)
		}
		if rollbackErr != nil {
			return fleetagent.StreamPosition{}, s.failLocked(errors.Join(appendErr, rollbackErr))
		}
		return fleetagent.StreamPosition{}, appendErr
	}
	seg.size += int64(len(frame))
	seg.live++
	s.totalBytes += int64(len(frame))
	ref := &recordRef{segment: seg, offset: offset, length: int64(len(frame)), header: unmarshalHeader(frame[:frameHeaderSize]), observed: item.ObservedAt.UTC()}
	s.records[priority] = append(s.records[priority], ref)
	s.state.AssignedThrough[priority] = position.Sequence

	policy := s.cfg.Sync[priority]
	if policy == SyncAlways {
		if err := s.syncSegmentLocked(seg); err != nil {
			return fleetagent.StreamPosition{}, err
		}
	} else {
		s.batchBytes[priority] += int64(len(frame))
		if s.lastSync[priority].IsZero() {
			s.lastSync[priority] = now
		}
	}
	// State is forced before success even for batch mode. If the WAL tail is
	// lost, AssignedThrough is the exact upper bound used to emit a gap.
	if err := s.persistStateLocked(); err != nil {
		return fleetagent.StreamPosition{}, fmt.Errorf("commit assigned sequence: %w", err)
	}
	if policy == SyncBatch && (s.batchBytes[priority] >= s.cfg.BatchBytes || now.Sub(s.lastSync[priority]) >= s.cfg.BatchInterval) {
		if err := s.syncSegmentLocked(seg); err != nil {
			return fleetagent.StreamPosition{}, err
		}
		s.batchBytes[priority] = 0
		s.lastSync[priority] = now
	}
	return position, nil
}

// Peek returns records in strict priority order and sequence order within a
// lane. It does not mutate delivery state; records remain until ACKed.
func (s *Spool) Peek(ctx context.Context, req ports.PeekSpoolRequest) ([]ports.SpoolRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return nil, err
	}
	maxRecords := req.MaxRecords
	if maxRecords == 0 {
		maxRecords = s.cfg.PeekRecords
	}
	maxBytes := req.MaxBytes
	if maxBytes == 0 {
		maxBytes = s.cfg.PeekBytes
	}
	if maxRecords < 0 || maxBytes < 0 {
		return nil, fmt.Errorf("%w: negative peek limit", shared.ErrValidation)
	}
	firstPriority, lastPriority := fleetagent.PriorityP0, fleetagent.PriorityP3
	if req.OnlyPriority != nil {
		if !req.OnlyPriority.Valid() {
			return nil, fmt.Errorf("%w: invalid peek priority %d", shared.ErrValidation, int(*req.OnlyPriority))
		}
		firstPriority, lastPriority = *req.OnlyPriority, *req.OnlyPriority
	}
	result := make([]ports.SpoolRecord, 0, min(maxRecords, 64))
	var bytesRead int64
	for priority := firstPriority; priority <= lastPriority; priority++ {
		for _, ref := range s.records[priority] {
			if len(result) >= maxRecords {
				return result, nil
			}
			record, err := readRecordRef(ref)
			if err != nil {
				return nil, err
			}
			payloadBytes := int64(len(record.Payload))
			if len(result) > 0 && bytesRead+payloadBytes > maxBytes {
				return result, nil
			}
			result = append(result, record)
			bytesRead += payloadBytes
		}
	}
	return result, nil
}

// Ack commits a highest-contiguous ACK and reclaims fully acknowledged segments.
func (s *Spool) Ack(ctx context.Context, ack ports.SpoolACK) (ports.SpoolACKResult, error) {
	if err := ctx.Err(); err != nil {
		return ports.SpoolACKResult{}, err
	}
	if err := ack.Validate(); err != nil {
		return ports.SpoolACKResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return ports.SpoolACKResult{}, err
	}
	if ack.Epoch > s.state.CurrentEpoch {
		return ports.SpoolACKResult{}, ErrACKAhead
	}
	assigned := s.highestAssignedLocked(ack.Priority, ack.Epoch)
	if assigned == 0 && ack.Epoch < s.state.CurrentEpoch {
		return ports.SpoolACKResult{}, ErrStaleACK
	}
	if ack.Through > assigned {
		return ports.SpoolACKResult{}, fmt.Errorf("%w: through=%d assigned=%d", ErrACKAhead, ack.Through, assigned)
	}
	key := ackKey(ack.Priority, ack.Epoch)
	previous := s.state.ACK[key]
	if ack.Through <= previous {
		reclaimed, err := s.removeEmptySegmentsLocked()
		return ports.SpoolACKResult{HighestACKed: previous, ReclaimedBytes: reclaimed}, err
	}
	s.state.ACK[key] = ack.Through
	if err := s.persistStateLocked(); err != nil {
		s.state.ACK[key] = previous
		return ports.SpoolACKResult{}, fmt.Errorf("commit spool ACK: %w", err)
	}

	result := ports.SpoolACKResult{HighestACKed: ack.Through}
	refs := s.records[ack.Priority]
	kept := refs[:0]
	for _, ref := range refs {
		if ref.header.Epoch == ack.Epoch && ref.header.Sequence <= ack.Through {
			result.RemovedRecords++
			ref.segment.live--
			continue
		}
		kept = append(kept, ref)
	}
	s.records[ack.Priority] = kept
	reclaimed, err := s.removeEmptySegmentsLocked()
	result.ReclaimedBytes = reclaimed
	if err != nil {
		return result, err
	}
	return result, nil
}

// Flush synchronizes all active segments. It is safe to call repeatedly.
func (s *Spool) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return err
	}
	return s.flushLocked()
}

func (s *Spool) flushLocked() error {
	for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP3; priority++ {
		if writer := s.writers[priority]; writer != nil {
			if err := s.syncSegmentLocked(writer); err != nil {
				return err
			}
			s.batchBytes[priority] = 0
			s.lastSync[priority] = s.cfg.Now().UTC()
		}
	}
	return s.flushGapJournalLocked()
}

func (s *Spool) Gaps(ctx context.Context) ([]ports.SpoolGap, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return nil, err
	}
	return append([]ports.SpoolGap(nil), s.gaps...), nil
}

func (s *Spool) Stats(ctx context.Context) (ports.SpoolStats, error) {
	if err := ctx.Err(); err != nil {
		return ports.SpoolStats{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return ports.SpoolStats{}, err
	}
	stats := ports.SpoolStats{
		TotalBytes: s.usedBytesLocked(), GapRecords: int64(len(s.gaps)), GapBytes: s.gapBytes,
		EvictedRecords: s.evictedRecords, CorruptionEvents: s.corruptionEvents,
		FsyncCount: s.fsyncCount, FsyncTotal: s.fsyncTotal,
		Priorities: make([]ports.SpoolPriorityStats, 0, 4),
	}
	for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP3; priority++ {
		refs := s.records[priority]
		lane := ports.SpoolPriorityStats{
			Priority: priority, Records: int64(len(refs)), CurrentEpoch: s.state.CurrentEpoch,
			NextSequence: s.state.AssignedThrough[priority] + 1,
			HighestACKed: s.state.ACK[ackKey(priority, s.state.CurrentEpoch)],
		}
		for _, ref := range refs {
			lane.Bytes += ref.length
		}
		if len(refs) > 0 {
			lane.OldestUnacked = refs[0].observed
		}
		stats.TotalRecords += lane.Records
		stats.Priorities = append(stats.Priorities, lane)
	}
	for key, highest := range s.state.ACK {
		priority, epoch, err := parseACKKey(key)
		if err != nil {
			return ports.SpoolStats{}, fmt.Errorf("read spool ACK history: %w", err)
		}
		if highest > 0 {
			stats.EpochACKs = append(stats.EpochACKs, ports.SpoolEpochACK{
				Priority: priority, Epoch: epoch, HighestACKed: highest,
			})
		}
	}
	sort.Slice(stats.EpochACKs, func(i, j int) bool {
		if stats.EpochACKs[i].Priority != stats.EpochACKs[j].Priority {
			return stats.EpochACKs[i].Priority < stats.EpochACKs[j].Priority
		}
		return stats.EpochACKs[i].Epoch < stats.EpochACKs[j].Epoch
	})
	return stats, nil
}

// Close flushes data, closes descriptors, and releases directory ownership.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var errs []error
	if err := s.flushLocked(); err != nil {
		errs = append(errs, err)
	}
	for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP3; priority++ {
		if writer := s.writers[priority]; writer != nil && writer.file != nil {
			if err := writer.file.Close(); err != nil {
				errs = append(errs, err)
			}
			writer.file = nil
		}
	}
	if s.gapFile != nil {
		if err := s.gapFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.lock != nil {
		if err := releaseDirectoryLock(s.lock); err != nil {
			errs = append(errs, err)
		}
	}
	s.closed = true
	return errors.Join(errs...)
}

func (s *Spool) ensureOpenLocked() error {
	if s.closed {
		return ErrClosed
	}
	if s.failed != nil {
		return errors.Join(ErrFailed, s.failed)
	}
	return nil
}

func (s *Spool) failLocked(err error) error {
	if s.failed == nil {
		s.failed = err
	}
	return errors.Join(ErrFailed, err)
}

func (s *Spool) writerLocked(priority fleetagent.DeliveryPriority, epoch, sequence uint64, frameBytes int64) (*segment, error) {
	current := s.writers[priority]
	if current != nil && (current.epoch != epoch || (current.size > 0 && current.size+frameBytes > s.cfg.SegmentBytes)) {
		if err := s.syncSegmentLocked(current); err != nil {
			return nil, err
		}
		if err := current.file.Close(); err != nil {
			return nil, err
		}
		current.file = nil
		s.writers[priority] = nil
		current = nil
	}
	if current != nil {
		return current, nil
	}
	name := segmentName(priority, epoch, sequence)
	path := filepath.Join(s.cfg.Dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create WAL segment: %w", err)
	}
	if err := syncDirectory(s.cfg.Dir); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync new WAL segment: %w", err)
	}
	current = &segment{priority: priority, epoch: epoch, start: sequence, path: path, file: f}
	s.segments = append(s.segments, current)
	s.writers[priority] = current
	return current, nil
}

func (s *Spool) syncSegmentLocked(seg *segment) error {
	if seg == nil || seg.file == nil {
		return nil
	}
	started := s.cfg.Now()
	if err := s.syncFile(seg.file); err != nil {
		return s.failLocked(fmt.Errorf("sync %s WAL segment: %w", seg.priority, err))
	}
	s.observeSyncLocked(started)
	return nil
}

func (s *Spool) observeSyncLocked(started time.Time) {
	s.fsyncCount++
	duration := s.cfg.Now().Sub(started)
	if duration > 0 {
		s.fsyncTotal += duration
	}
}

func (s *Spool) persistStateLocked() error {
	started := s.cfg.Now()
	if err := s.persistState(s.cfg.Dir, &s.state); err != nil {
		return s.failLocked(err)
	}
	s.observeSyncLocked(started)
	return nil
}

func readRecordRef(ref *recordRef) (ports.SpoolRecord, error) {
	f, err := os.Open(ref.segment.path)
	if err != nil {
		return ports.SpoolRecord{}, fmt.Errorf("open WAL record: %w", err)
	}
	defer func() { _ = f.Close() }()
	frame := make([]byte, ref.length)
	if _, err := f.ReadAt(frame, ref.offset); err != nil {
		return ports.SpoolRecord{}, fmt.Errorf("read WAL record: %w", err)
	}
	record, _, err := decodeFrame(frame)
	if err != nil {
		return ports.SpoolRecord{}, fmt.Errorf("decode WAL record after recovery: %w", err)
	}
	return record, nil
}

func rollbackAppend(file *os.File, offset int64) error {
	if err := file.Truncate(offset); err != nil {
		return fmt.Errorf("truncate failed WAL append: %w", err)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek repaired WAL append: %w", err)
	}
	return nil
}

func (s *Spool) highestAssignedLocked(priority fleetagent.DeliveryPriority, epoch uint64) uint64 {
	high := s.state.ACK[ackKey(priority, epoch)]
	if epoch == s.state.CurrentEpoch && s.state.AssignedThrough[priority] > high {
		high = s.state.AssignedThrough[priority]
	}
	for _, ref := range s.records[priority] {
		if ref.header.Epoch == epoch && ref.header.Sequence > high {
			high = ref.header.Sequence
		}
	}
	for _, gap := range s.gaps {
		if gap.Priority == priority && gap.Epoch == epoch && gap.KnownSequence && gap.ToSequence > high {
			high = gap.ToSequence
		}
	}
	return high
}

func (s *Spool) appendUnknownGapLocked(priority fleetagent.DeliveryPriority, epoch uint64, reason ports.SpoolGapReason) error {
	return s.appendGapLocked(ports.SpoolGap{
		ID: shared.ID(uuid.NewString()), Priority: priority, Epoch: epoch,
		KnownSequence: false, Reason: reason, Count: 1, OccurredAt: s.cfg.Now().UTC(),
	})
}

func (s *Spool) appendKnownGapLocked(priority fleetagent.DeliveryPriority, epoch, from, to uint64, reason ports.SpoolGapReason) error {
	if from == 0 || to < from {
		return fmt.Errorf("invalid internal gap range %d..%d", from, to)
	}
	return s.appendGapLocked(ports.SpoolGap{
		ID: shared.ID(uuid.NewString()), Priority: priority, Epoch: epoch,
		FromSequence: from, ToSequence: to, KnownSequence: true, Reason: reason,
		Count: to - from + 1, OccurredAt: s.cfg.Now().UTC(),
	})
}

func segmentName(priority fleetagent.DeliveryPriority, epoch, start uint64) string {
	return fmt.Sprintf("p%d-e%020d-s%020d.wal", priority, epoch, start)
}

func parseSegmentName(name string) (fleetagent.DeliveryPriority, uint64, uint64, bool) {
	var p int
	var epoch, start uint64
	if _, err := fmt.Sscanf(name, "p%d-e%d-s%d.wal", &p, &epoch, &start); err != nil {
		return 0, 0, 0, false
	}
	priority := fleetagent.DeliveryPriority(p)
	if !priority.Valid() || epoch == 0 || start == 0 || name != segmentName(priority, epoch, start) {
		return 0, 0, 0, false
	}
	return priority, epoch, start, true
}

func nextMagic(data []byte, from int) int {
	needle := []byte{byte(frameMagic & 0xff), byte((frameMagic >> 8) & 0xff), byte((frameMagic >> 16) & 0xff), byte((frameMagic >> 24) & 0xff)}
	index := bytes.Index(data[from:], needle)
	if index < 0 {
		return -1
	}
	return from + index
}

func sortRecords(refs []*recordRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].header.Epoch != refs[j].header.Epoch {
			return refs[i].header.Epoch < refs[j].header.Epoch
		}
		return refs[i].header.Sequence < refs[j].header.Sequence
	})
}

var _ ports.TelemetrySpool = (*Spool)(nil)

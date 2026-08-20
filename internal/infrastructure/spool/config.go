package spool

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	defaultMaxBytes       = int64(512 << 20)
	defaultMaxGapBytes    = int64(8 << 20)
	defaultSegmentBytes   = int64(8 << 20)
	defaultMaxRecordBytes = int64(4 << 20)
	defaultPeekRecords    = 256
	defaultPeekBytes      = int64(2 << 20)
	defaultBatchInterval  = time.Second
	defaultBatchBytes     = int64(256 << 10)
	// FrameOverheadBudget bounds the header plus encoded record metadata. It is
	// exported so composition roots that shrink a spool can also shrink the
	// payload limit without creating a record that can never fit.
	FrameOverheadBudget   = int64(512)
	maxFrameMetadataBytes = FrameOverheadBudget - frameHeaderSize
	minimumGapReserve     = 8 * FrameOverheadBudget
)

// SyncPolicy controls when an accepted record is forced to stable storage.
// Always is the default for the non-sheddable P0..P2 lanes. Batch is intended
// only for P3: sequence reservations make a crash-visible gap explicit even
// when the operating system loses the last accepted, not-yet-synced frames.
type SyncPolicy string

const (
	SyncAlways SyncPolicy = "always"
	SyncBatch  SyncPolicy = "batch"
)

// Config is the bounded resource and durability policy for one spool.
type Config struct {
	// Dir must be service-owned and non-world-writable. Open tightens it to
	// 0700 and refuses symlink paths before reading spool contents.
	Dir      string
	Session  fleetagent.SessionID
	Boot     fleetagent.BootID
	MaxBytes int64
	// MaxGapBytes is reserved inside MaxBytes for durable loss evidence and its
	// atomic compaction scratch file. Zero selects a size-derived default; WAL
	// records cannot consume this reserve.
	MaxGapBytes    int64
	SegmentBytes   int64
	MaxRecordBytes int64
	PeekRecords    int
	PeekBytes      int64
	BatchInterval  time.Duration
	BatchBytes     int64
	Sync           map[fleetagent.DeliveryPriority]SyncPolicy
	Now            func() time.Time
}

// DefaultConfig returns conservative production defaults. It deliberately
// leaves identity and directory unset so a caller cannot accidentally open a
// spool whose incarnation cannot be attributed.
func DefaultConfig() Config {
	return Config{
		MaxBytes:       defaultMaxBytes,
		SegmentBytes:   defaultSegmentBytes,
		MaxRecordBytes: defaultMaxRecordBytes,
		PeekRecords:    defaultPeekRecords,
		PeekBytes:      defaultPeekBytes,
		BatchInterval:  defaultBatchInterval,
		BatchBytes:     defaultBatchBytes,
		Sync: map[fleetagent.DeliveryPriority]SyncPolicy{
			fleetagent.PriorityP0: SyncAlways,
			fleetagent.PriorityP1: SyncAlways,
			fleetagent.PriorityP2: SyncAlways,
			fleetagent.PriorityP3: SyncBatch,
		},
		Now: time.Now,
	}
}

func normalizeConfig(in Config) (Config, error) {
	cfg := DefaultConfig()
	if in.Dir != "" {
		cfg.Dir = in.Dir
	}
	if in.Session != "" {
		cfg.Session = in.Session
	}
	if in.Boot != "" {
		cfg.Boot = in.Boot
	}
	if in.MaxBytes != 0 {
		cfg.MaxBytes = in.MaxBytes
	}
	if in.MaxGapBytes != 0 {
		cfg.MaxGapBytes = in.MaxGapBytes
	} else {
		cfg.MaxGapBytes = RecommendedGapBytes(cfg.MaxBytes)
	}
	if in.SegmentBytes != 0 {
		cfg.SegmentBytes = in.SegmentBytes
	}
	if in.MaxRecordBytes != 0 {
		cfg.MaxRecordBytes = in.MaxRecordBytes
	}
	if in.PeekRecords != 0 {
		cfg.PeekRecords = in.PeekRecords
	}
	if in.PeekBytes != 0 {
		cfg.PeekBytes = in.PeekBytes
	}
	if in.BatchInterval != 0 {
		cfg.BatchInterval = in.BatchInterval
	}
	if in.BatchBytes != 0 {
		cfg.BatchBytes = in.BatchBytes
	}
	if in.Now != nil {
		cfg.Now = in.Now
	}
	if in.Sync != nil {
		cfg.Sync = make(map[fleetagent.DeliveryPriority]SyncPolicy, 4)
		for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP3; priority++ {
			cfg.Sync[priority] = in.Sync[priority]
		}
	}

	if cfg.Dir == "" {
		return Config{}, fmt.Errorf("%w: spool directory is required", shared.ErrValidation)
	}
	if cfg.Session == "" || cfg.Boot == "" {
		return Config{}, fmt.Errorf("%w: spool session and boot ids are required", shared.ErrValidation)
	}
	if cfg.MaxBytes <= 0 || cfg.MaxGapBytes <= 0 || cfg.SegmentBytes <= 0 || cfg.MaxRecordBytes <= 0 {
		return Config{}, fmt.Errorf("%w: spool byte limits must be positive", shared.ErrValidation)
	}
	if cfg.MaxGapBytes >= cfg.MaxBytes {
		return Config{}, fmt.Errorf("%w: gap journal budget must be smaller than spool quota", shared.ErrValidation)
	}
	if cfg.MaxGapBytes < minimumGapReserve {
		return Config{}, fmt.Errorf("%w: gap journal budget is too small for bounded atomic compaction", shared.ErrValidation)
	}
	walBytes := cfg.MaxBytes - cfg.MaxGapBytes
	if cfg.SegmentBytes > walBytes {
		return Config{}, fmt.Errorf("%w: segment limit cannot exceed WAL quota after gap reserve", shared.ErrValidation)
	}
	if cfg.MaxRecordBytes > cfg.SegmentBytes-FrameOverheadBudget {
		return Config{}, fmt.Errorf("%w: record limit plus frame overhead cannot exceed segment limit", shared.ErrValidation)
	}
	if cfg.PeekRecords < 1 || cfg.PeekBytes < 1 {
		return Config{}, fmt.Errorf("%w: peek limits must be positive", shared.ErrValidation)
	}
	if cfg.BatchInterval <= 0 || cfg.BatchBytes <= 0 {
		return Config{}, fmt.Errorf("%w: batch sync limits must be positive", shared.ErrValidation)
	}
	for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP3; priority++ {
		policy := cfg.Sync[priority]
		if policy != SyncAlways && policy != SyncBatch {
			return Config{}, fmt.Errorf("%w: priority %s has invalid sync policy %q", shared.ErrValidation, priority, policy)
		}
		if priority != fleetagent.PriorityP3 && policy != SyncAlways {
			return Config{}, fmt.Errorf("%w: non-sheddable priority %s must use always sync", shared.ErrValidation, priority)
		}
	}
	return cfg, nil
}

// RecommendedGapBytes returns the bounded loss-evidence reserve used when
// MaxGapBytes is zero. The reserve includes room for an atomic rewrite copy.
func RecommendedGapBytes(maxBytes int64) int64 {
	budget := maxBytes / 64
	if budget > defaultMaxGapBytes {
		budget = defaultMaxGapBytes
	}
	if budget < minimumGapReserve {
		budget = minimumGapReserve
	}
	return budget
}

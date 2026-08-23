// Package detectionship drains confirmed detections from the durable P1 agent WAL into independently
// signed detection batches. It owns the crash-safe batch sequence and key-rotation workflow; transport
// and local-secret persistence remain ports supplied by the composition root.
package detectionship

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultKeyValidity  = 90 * 24 * time.Hour
	defaultRotateBefore = 7 * 24 * time.Hour
	defaultBatchRecords = 32
	defaultBatchBytes   = int64(6 << 20)
	defaultIdleInterval = time.Second
)

var (
	// ErrSigningKeyRejected triggers one fail-closed key rotation for the current pending batch. A
	// second rejection for the same sequence is permanent, preventing an invalid payload from causing
	// an unbounded key-generation loop.
	ErrSigningKeyRejected = errors.New("detection signing key rejected")
	// ErrDeliveryState marks a local state/WAL disagreement. Guessing in this condition could ACK an
	// unsent detection, so the shipper stops and leaves the WAL intact for operator recovery.
	ErrDeliveryState = errors.New("detection delivery state inconsistent")
)

// ResponseError is implemented by transports that preserve an HTTP status and Retry-After value.
type ResponseError interface {
	error
	ResponseStatus() (status int, retryAfter string)
}

// RetryDecider classifies a transport failure. retry=false makes Run fail closed; retry=true waits for
// delay without removing anything from the WAL.
type RetryDecider func(err error, attempt uint) (retry bool, delay time.Duration)

func initialState() ports.DetectionDeliveryState {
	return ports.DetectionDeliveryState{Version: ports.DetectionDeliveryStateVersion, NextSequence: 1}
}

// Config binds one shipper to an enrolled agent and one engagement.
type Config struct {
	AgentID      shared.ID
	EngagementID shared.ID
	Token        string
	KeyValidity  time.Duration
	RotateBefore time.Duration
	BatchRecords int
	BatchBytes   int64
	IdleInterval time.Duration
	Now          func() time.Time
	GenerateKey  func() (ed25519.PublicKey, ed25519.PrivateKey, error)
	Retry        RetryDecider
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.AgentID.IsZero() || cfg.EngagementID.IsZero() || cfg.Token == "" {
		return Config{}, fmt.Errorf("%w: detection shipper requires agent, engagement and credential", shared.ErrValidation)
	}
	if cfg.KeyValidity == 0 {
		cfg.KeyValidity = defaultKeyValidity
	}
	if cfg.RotateBefore == 0 {
		cfg.RotateBefore = defaultRotateBefore
	}
	if cfg.BatchRecords == 0 {
		cfg.BatchRecords = defaultBatchRecords
	}
	if cfg.BatchBytes == 0 {
		cfg.BatchBytes = defaultBatchBytes
	}
	if cfg.IdleInterval == 0 {
		cfg.IdleInterval = defaultIdleInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.GenerateKey == nil {
		cfg.GenerateKey = func() (ed25519.PublicKey, ed25519.PrivateKey, error) {
			return ed25519.GenerateKey(rand.Reader)
		}
	}
	if cfg.Retry == nil {
		return Config{}, fmt.Errorf("%w: detection shipper requires a retry classifier", shared.ErrValidation)
	}
	if cfg.KeyValidity <= 0 || cfg.KeyValidity > 364*24*time.Hour || cfg.RotateBefore <= 0 || cfg.RotateBefore >= cfg.KeyValidity {
		return Config{}, fmt.Errorf("%w: invalid detection signing-key rotation window", shared.ErrValidation)
	}
	if cfg.BatchRecords < 1 || cfg.BatchBytes < 1 || cfg.IdleInterval <= 0 {
		return Config{}, fmt.Errorf("%w: invalid detection batch or idle limit", shared.ErrValidation)
	}
	return cfg, nil
}

// Service drains one durable detection lane.
type Service struct {
	spool     ports.TelemetrySpool
	transport ports.DetectionTransport
	store     ports.DetectionStateStore
	cfg       Config
	state     ports.DetectionDeliveryState
}

// NewService loads and validates durable state before any key registration or network delivery.
func NewService(spool ports.TelemetrySpool, transport ports.DetectionTransport, store ports.DetectionStateStore, cfg Config) (*Service, error) {
	if spool == nil || transport == nil || store == nil {
		return nil, fmt.Errorf("%w: detection shipper is missing a dependency", shared.ErrValidation)
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	state, ok, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("load detection delivery state: %w", err)
	}
	if !ok {
		state = initialState()
		if err := store.Save(state); err != nil {
			return nil, fmt.Errorf("initialize detection delivery state: %w", err)
		}
	}
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("load detection delivery state: %w", err)
	}
	if state.Key != nil && state.Key.Key.AgentID != normalized.AgentID {
		return nil, fmt.Errorf("%w: local signing key belongs to agent %s, not %s", shared.ErrForbidden, state.Key.Key.AgentID, normalized.AgentID)
	}
	if state.Pending != nil && state.Pending.EngagementID != normalized.EngagementID {
		return nil, fmt.Errorf("%w: pending detection batch belongs to engagement %s, not %s",
			shared.ErrForbidden, state.Pending.EngagementID, normalized.EngagementID)
	}
	return &Service{spool: spool, transport: transport, store: store, cfg: normalized, state: state}, nil
}

// Run continuously drains detections. It retries only when the injected policy permits it and rotates
// a rejected key at most once per pending sequence.
func (s *Service) Run(ctx context.Context) error {
	var attempt uint
	var rotatedSequence uint64
	for {
		delivered, err := s.DeliverOnce(ctx)
		if err == nil {
			attempt, rotatedSequence = 0, 0
			if delivered {
				continue
			}
			if err := wait(ctx, s.cfg.IdleInterval); err != nil {
				return err
			}
			continue
		}
		if errors.Is(err, ErrSigningKeyRejected) {
			sequence := s.state.NextSequence
			if rotatedSequence == sequence {
				return fmt.Errorf("detection batch sequence %d rejected after key rotation: %w", sequence, err)
			}
			if err := s.forgetRejectedKey(); err != nil {
				return err
			}
			rotatedSequence, attempt = sequence, 0
			continue
		}
		retry, delay := s.cfg.Retry(err, attempt)
		if !retry {
			return err
		}
		attempt++
		if err := wait(ctx, delay); err != nil {
			return err
		}
	}
}

// DeliverOnce sends at most one batch. delivered=false,nil means the P1 lane is empty.
func (s *Service) DeliverOnce(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.state.Pending != nil {
		if s.state.Pending.EngagementID != s.cfg.EngagementID {
			return false, fmt.Errorf("%w: pending detection batch belongs to engagement %s, not %s",
				shared.ErrForbidden, s.state.Pending.EngagementID, s.cfg.EngagementID)
		}
		acked, err := s.pendingAlreadyACKed(ctx)
		if err != nil {
			return false, err
		}
		if acked {
			return true, s.completePendingState()
		}
	}
	if err := s.ensureKey(ctx); err != nil {
		return false, err
	}
	records, err := s.recordsForBatch(ctx)
	if err != nil || len(records) == 0 {
		return false, err
	}
	items, refs, err := s.decodeRecords(records)
	if err != nil {
		return false, err
	}
	if s.state.Pending == nil {
		pending := &ports.DetectionPendingBatch{EngagementID: s.cfg.EngagementID,
			Sequence: s.state.NextSequence, Epoch: records[0].Position.Epoch,
			Through: records[len(records)-1].Position.Sequence, EventIDs: make([]shared.ID, len(records))}
		for i := range records {
			pending.EventIDs[i] = records[i].EventID
		}
		next := s.state
		next.Pending = pending
		if err := s.persist(next); err != nil {
			return false, fmt.Errorf("persist pending detection batch: %w", err)
		}
	}
	batch := fleetagent.AgentBatch{AgentID: s.cfg.AgentID, EngagementID: s.state.Pending.EngagementID,
		Sequence: s.state.Pending.Sequence, KeyID: s.state.Key.Key.KeyID, Detections: refs}
	batch.Signature = fleetagent.SignBatch(s.state.Key.PrivateKey, batch)
	if err := batch.Validate(); err != nil {
		return false, err
	}
	if err := s.transport.SendDetectionBatch(ctx, s.cfg.Token, batch, items); err != nil {
		if status, _, ok := responseStatus(err); ok && status == http.StatusForbidden {
			return false, fmt.Errorf("%w: %v", ErrSigningKeyRejected, err)
		}
		return false, fmt.Errorf("send detection batch: %w", err)
	}
	if _, err := s.spool.Ack(ctx, ports.SpoolACK{Priority: fleetagent.PriorityP1,
		Epoch: s.state.Pending.Epoch, Through: s.state.Pending.Through}); err != nil {
		return false, fmt.Errorf("ack delivered detection WAL: %w", err)
	}
	if err := s.completePendingState(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) ensureKey(ctx context.Context) error {
	now := s.cfg.Now().UTC()
	if s.state.Key != nil && s.state.RegisteredKeyID == s.state.Key.Key.KeyID &&
		s.state.Key.Key.StatusAt(now) == fleetagent.KeyActive && now.Add(s.cfg.RotateBefore).Before(s.state.Key.Key.NotAfter) {
		return nil
	}
	local := s.state.Key
	if local == nil || local.Key.StatusAt(now) != fleetagent.KeyActive || !now.Add(s.cfg.RotateBefore).Before(local.Key.NotAfter) {
		pub, privateKey, err := s.cfg.GenerateKey()
		if err != nil {
			return fmt.Errorf("generate detection signing key: %w", err)
		}
		key, err := fleetagent.NewSigningKey(s.cfg.AgentID, fleetagent.PurposeDetectionBatch, pub,
			now.Add(-time.Minute), now.Add(s.cfg.KeyValidity))
		if err != nil {
			return err
		}
		local = &ports.DetectionSigningKeyState{Key: key, PrivateKey: privateKey}
	}
	proof := fleetagent.ProveKeyPossession(local.PrivateKey, local.Key)
	if err := s.transport.RegisterDetectionKey(ctx, s.cfg.Token, local.Key, proof); err != nil {
		return fmt.Errorf("register detection signing key: %w", err)
	}
	next := s.state
	next.Key = local
	next.RegisteredKeyID = local.Key.KeyID
	return s.persist(next)
}

func (s *Service) recordsForBatch(ctx context.Context) ([]ports.SpoolRecord, error) {
	priority := fleetagent.PriorityP1
	maxRecords := s.cfg.BatchRecords
	if s.state.Pending != nil && len(s.state.Pending.EventIDs) > maxRecords {
		maxRecords = len(s.state.Pending.EventIDs)
	}
	records, err := s.spool.Peek(ctx, ports.PeekSpoolRequest{MaxRecords: maxRecords, MaxBytes: s.cfg.BatchBytes, OnlyPriority: &priority})
	if err != nil {
		return nil, fmt.Errorf("peek detection WAL: %w", err)
	}
	if s.state.Pending == nil {
		if len(records) == 0 {
			return nil, nil
		}
		epoch := records[0].Position.Epoch
		end := len(records)
		for i, record := range records {
			if record.Position.Epoch != epoch {
				end = i
				break
			}
		}
		return records[:end], nil
	}
	pending := s.state.Pending
	if len(records) < len(pending.EventIDs) {
		return nil, fmt.Errorf("%w: pending batch has %d records but WAL exposes %d", ErrDeliveryState, len(pending.EventIDs), len(records))
	}
	records = records[:len(pending.EventIDs)]
	for i, record := range records {
		if record.EventID != pending.EventIDs[i] || record.Position.Epoch != pending.Epoch ||
			(i == len(records)-1 && record.Position.Sequence != pending.Through) {
			return nil, fmt.Errorf("%w: pending membership no longer matches P1 WAL at index %d", ErrDeliveryState, i)
		}
	}
	return records, nil
}

func (s *Service) decodeRecords(records []ports.SpoolRecord) ([]fleetagent.DetectionBatchItem, []fleetagent.DetectionRef, error) {
	items := make([]fleetagent.DetectionBatchItem, 0, len(records))
	refs := make([]fleetagent.DetectionRef, 0, len(records))
	seen := make(map[shared.ID]string, len(records))
	for _, record := range records {
		if record.Kind != ports.SpoolRecordDetection || record.Position.Priority != fleetagent.PriorityP1 {
			return nil, nil, fmt.Errorf("%w: P1 lane contains non-detection record %s", ErrDeliveryState, record.EventID)
		}
		var value detection.Detection
		if err := json.Unmarshal(record.Payload, &value); err != nil {
			return nil, nil, fmt.Errorf("decode spooled detection %s: %w", record.EventID, err)
		}
		item := fleetagent.DetectionBatchItem{ID: record.EventID, Detection: value, AssetID: value.HostID}
		if err := item.Validate(); err != nil {
			return nil, nil, err
		}
		if value.AgentID != s.cfg.AgentID {
			return nil, nil, fmt.Errorf("%w: spooled detection %s belongs to agent %s, not %s", shared.ErrForbidden, record.EventID, value.AgentID, s.cfg.AgentID)
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			return nil, nil, fmt.Errorf("encode detection %s: %w", record.EventID, err)
		}
		digest := fleetagent.DetectionContentHash(canonical, item.AssetID)
		if previous, duplicate := seen[record.EventID]; duplicate {
			if previous != digest {
				return nil, nil, fmt.Errorf("%w: repeated detection id %s has different content", ErrDeliveryState, record.EventID)
			}
			// Sink retries can append the same deterministic detection more than once. One signed
			// item admits that content; ACKing through the pending WAL membership then removes all
			// identical copies without sending a server-invalid batch with duplicate refs.
			continue
		}
		seen[record.EventID] = digest
		items = append(items, item)
		refs = append(refs, fleetagent.DetectionRef{ID: record.EventID,
			ContentSHA256: digest})
	}
	return items, refs, nil
}

func (s *Service) pendingAlreadyACKed(ctx context.Context) (bool, error) {
	stats, err := s.spool.Stats(ctx)
	if err != nil {
		return false, fmt.Errorf("read detection WAL state: %w", err)
	}
	for _, ack := range stats.EpochACKs {
		if ack.Priority == fleetagent.PriorityP1 && ack.Epoch == s.state.Pending.Epoch {
			return ack.HighestACKed >= s.state.Pending.Through, nil
		}
	}
	return false, nil
}

func (s *Service) completePendingState() error {
	next := s.state
	next.NextSequence = s.state.Pending.Sequence + 1
	next.Pending = nil
	if err := s.persist(next); err != nil {
		return fmt.Errorf("commit delivered detection batch: %w", err)
	}
	return nil
}

func (s *Service) forgetRejectedKey() error {
	next := s.state
	next.Key = nil
	next.RegisteredKeyID = ""
	if err := s.persist(next); err != nil {
		return fmt.Errorf("rotate rejected detection signing key: %w", err)
	}
	return nil
}

func (s *Service) persist(next ports.DetectionDeliveryState) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if err := s.store.Save(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func responseStatus(err error) (int, string, bool) {
	var responseErr ResponseError
	if !errors.As(err, &responseErr) {
		return 0, "", false
	}
	status, retryAfter := responseErr.ResponseStatus()
	return status, retryAfter, true
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

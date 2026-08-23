package spool

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PeekPriority returns ordered live records from exactly one A2 lane without
// consuming them. A3 uses this instead of the global priority-ordered Peek so a
// future A4 P1 backlog cannot starve raw telemetry in P2/P3, while ACK ownership
// remains lane-specific.
func (s *Spool) PeekPriority(ctx context.Context, priority fleetagent.DeliveryPriority, req ports.PeekSpoolRequest) ([]ports.SpoolRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !priority.Valid() {
		return nil, fmt.Errorf("%w: invalid peek priority %d", shared.ErrValidation, int(priority))
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
	result := make([]ports.SpoolRecord, 0, min(maxRecords, 64))
	var bytesRead int64
	for _, ref := range s.records[priority] {
		if len(result) >= maxRecords {
			break
		}
		record, err := readRecordRef(ref)
		if err != nil {
			return nil, err
		}
		payloadBytes := int64(len(record.Payload))
		if len(result) > 0 && bytesRead+payloadBytes > maxBytes {
			break
		}
		result = append(result, record)
		bytesRead += payloadBytes
	}
	return result, nil
}

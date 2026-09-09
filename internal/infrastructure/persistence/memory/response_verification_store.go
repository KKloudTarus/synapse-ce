package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type portsReceipt = fleetagent.ResponseTargetEvidenceReceipt

type ResponseVerificationStore struct {
	mu             sync.Mutex
	byAttempt      map[shared.ID]map[string]ports.AcceptedResponseVerification
	byReport       map[shared.ID]map[shared.ID]string
	receipts       map[shared.ID]map[string]portsReceipt
	receiptIDs     map[shared.ID]map[shared.ID]string
	receiptDigests map[shared.ID]map[string]string
	auditIntents   map[fleetAuditKey]ports.FleetAuditIntent
	auditComplete  map[fleetAuditKey]bool
}

var _ ports.ResponseVerificationAuditStore = (*ResponseVerificationStore)(nil)
var _ ports.ResponseTargetEvidenceReceiptStore = (*ResponseVerificationStore)(nil)

func NewResponseVerificationStore() *ResponseVerificationStore {
	return &ResponseVerificationStore{
		byAttempt: map[shared.ID]map[string]ports.AcceptedResponseVerification{},
		byReport:  map[shared.ID]map[shared.ID]string{}, receipts: map[shared.ID]map[string]portsReceipt{}, receiptIDs: map[shared.ID]map[shared.ID]string{}, receiptDigests: map[shared.ID]map[string]string{}, auditIntents: map[fleetAuditKey]ports.FleetAuditIntent{},
		auditComplete: map[fleetAuditKey]bool{},
	}
}

func (s *ResponseVerificationStore) AppendResponseVerificationWithAudit(ctx context.Context, observation ports.AcceptedResponseVerification, intent ports.FleetAuditIntent) (ports.FleetAuditIntent, error) {
	if err := observation.Validate(); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	intent, err = intent.Normalize()
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	attemptKey := strings.TrimSpace(observation.Report.AttemptKey)
	auditKey := fleetAuditKey{tenant: tenant, id: intent.ID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byAttempt[tenant] == nil {
		s.byAttempt[tenant] = map[string]ports.AcceptedResponseVerification{}
		s.byReport[tenant] = map[shared.ID]string{}
	}
	if existingAttempt, exists := s.byReport[tenant][observation.Report.ReportID]; exists && existingAttempt != attemptKey {
		return ports.FleetAuditIntent{}, fmt.Errorf("%w: response-verification report id is already bound to another attempt", shared.ErrConflict)
	}
	if existing, exists := s.byAttempt[tenant][attemptKey]; exists {
		if !ports.SameAcceptedResponseVerification(existing, observation) {
			return ports.FleetAuditIntent{}, fmt.Errorf("%w: response-verification attempt already has different signed content", shared.ErrConflict)
		}
		observation = existing
	}
	if existingIntent, exists := s.auditIntents[auditKey]; exists {
		intent.Entry.At = existingIntent.Entry.At
		if !ports.SameFleetAuditIntent(existingIntent, intent) {
			return ports.FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention id already has different immutable content", shared.ErrConflict)
		}
	}
	s.byAttempt[tenant][attemptKey] = cloneAcceptedResponseVerification(observation)
	s.byReport[tenant][observation.Report.ReportID] = attemptKey
	s.auditIntents[auditKey] = cloneMemoryFleetAuditIntent(intent)
	return cloneMemoryFleetAuditIntent(intent), nil
}

func (s *ResponseVerificationStore) AppendResponseTargetEvidenceReceipt(ctx context.Context, receipt fleetagent.ResponseTargetEvidenceReceipt) (fleetagent.ResponseTargetEvidenceReceipt, error) {
	if err := receipt.Validate(); err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, err
	}
	if receipt.TenantID != tenant {
		return fleetagent.ResponseTargetEvidenceReceipt{}, shared.ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receipts[tenant] == nil {
		s.receipts[tenant] = map[string]portsReceipt{}
		s.receiptIDs[tenant] = map[shared.ID]string{}
		s.receiptDigests[tenant] = map[string]string{}
	}
	if attempt, found := s.receiptIDs[tenant][receipt.ReceiptID]; found && attempt != receipt.AttemptKey {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("%w: target evidence receipt id is already bound to another attempt", shared.ErrConflict)
	}
	if attempt, found := s.receiptDigests[tenant][receipt.Digest]; found && attempt != receipt.AttemptKey {
		return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("%w: target evidence receipt digest is already bound to another attempt", shared.ErrConflict)
	}
	if existing, found := s.receipts[tenant][receipt.AttemptKey]; found {
		if !fleetagent.SameResponseTargetEvidenceReceipt(existing, receipt) || existing.Digest != receipt.Digest || existing.ReceiptID != receipt.ReceiptID {
			return fleetagent.ResponseTargetEvidenceReceipt{}, fmt.Errorf("%w: target evidence receipt attempt equivocation", shared.ErrConflict)
		}
		return fleetagent.CloneResponseTargetEvidenceReceipt(existing), nil
	}
	stored := fleetagent.CloneResponseTargetEvidenceReceipt(receipt)
	s.receipts[tenant][receipt.AttemptKey] = stored
	s.receiptIDs[tenant][receipt.ReceiptID] = receipt.AttemptKey
	s.receiptDigests[tenant][receipt.Digest] = receipt.AttemptKey
	return fleetagent.CloneResponseTargetEvidenceReceipt(stored), nil
}

func (s *ResponseVerificationStore) GetResponseTargetEvidenceReceipt(ctx context.Context, attemptKey string) (fleetagent.ResponseTargetEvidenceReceipt, bool, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return fleetagent.ResponseTargetEvidenceReceipt{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, found := s.receipts[tenant][strings.TrimSpace(attemptKey)]
	return fleetagent.CloneResponseTargetEvidenceReceipt(receipt), found, nil
}

func (s *ResponseVerificationStore) GetResponseVerification(ctx context.Context, attemptKey string) (ports.AcceptedResponseVerification, bool, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.AcceptedResponseVerification{}, false, err
	}
	attemptKey = strings.TrimSpace(attemptKey)
	if attemptKey == "" {
		return ports.AcceptedResponseVerification{}, false, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	observation, found := s.byAttempt[tenant][attemptKey]
	return cloneAcceptedResponseVerification(observation), found, nil
}

func (s *ResponseVerificationStore) ListPendingFleetAudits(ctx context.Context) ([]ports.FleetAuditIntent, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.FleetAuditIntent, 0)
	for key, intent := range s.auditIntents {
		if key.tenant == tenant && !s.auditComplete[key] {
			out = append(out, cloneMemoryFleetAuditIntent(intent))
		}
	}
	slices.SortFunc(out, func(left, right ports.FleetAuditIntent) int {
		if order := left.Entry.At.Compare(right.Entry.At); order != 0 {
			return order
		}
		return strings.Compare(left.ID, right.ID)
	})
	return out, nil
}

func (s *ResponseVerificationStore) AcknowledgeFleetAudit(ctx context.Context, id string) error {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	key := fleetAuditKey{tenant: tenant, id: strings.TrimSpace(id)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.auditIntents[key]; !exists {
		return shared.ErrNotFound
	}
	s.auditComplete[key] = true
	return nil
}

func cloneAcceptedResponseVerification(observation ports.AcceptedResponseVerification) ports.AcceptedResponseVerification {
	return observation
}

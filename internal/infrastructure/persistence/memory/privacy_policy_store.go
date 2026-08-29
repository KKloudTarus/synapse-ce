package memory

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PrivacyPolicyStore is the in-memory adapter for immutable policy history and
// the tenant's independently mutable active policy pointer.
type PrivacyPolicyStore struct {
	mu sync.RWMutex

	policies      map[string]privacy.Assignment
	policyDigests map[string]string
	active        map[shared.ID]string
	activations   map[shared.ID][]privacy.Activation
	operations    map[string]privacy.Activation
	auditIntents  map[fleetAuditKey]ports.FleetAuditIntent
	auditComplete map[fleetAuditKey]bool
}

// fleetAuditKey identifies one audit obligation by SEPARATE tenant and intention
// fields. A concatenated "tenant:id" string key would be a tenant-isolation hole
// here: intention ids themselves contain colons, so tenant "a" with intention
// "b:x" and tenant "a:b" with intention "x" collide on one key, letting a prefix
// scan list — or an acknowledgement retire — another tenant's obligation.
type fleetAuditKey struct {
	tenant shared.ID
	id     string
}

func NewPrivacyPolicyStore() *PrivacyPolicyStore {
	return &PrivacyPolicyStore{
		policies:      make(map[string]privacy.Assignment),
		policyDigests: make(map[string]string),
		active:        make(map[shared.ID]string),
		activations:   make(map[shared.ID][]privacy.Activation),
		operations:    make(map[string]privacy.Activation),
		auditIntents:  make(map[fleetAuditKey]ports.FleetAuditIntent),
		auditComplete: make(map[fleetAuditKey]bool),
	}
}

var _ ports.PrivacyPolicyStore = (*PrivacyPolicyStore)(nil)
var _ ports.PrivacyPolicyAuditStore = (*PrivacyPolicyStore)(nil)

func (s *PrivacyPolicyStore) PutPrivacyPolicy(
	ctx context.Context,
	assignment privacy.Assignment,
) (bool, error) {
	tenantID, err := privacyPolicyMemoryTenant(ctx, assignment.TenantID)
	if err != nil {
		return false, err
	}
	assignment.TenantID = tenantID
	if err := assignment.Validate(); err != nil {
		return false, err
	}
	key := privacyPolicyKey(tenantID, assignment.Policy.Version)
	digestKey := privacyPolicyDigestKey(tenantID, assignment.Digest)
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, exists := s.policies[key]
	if exists && !privacy.SameAssignment(existing, assignment) {
		return false, fmt.Errorf("%w: privacy policy version already has different immutable content", shared.ErrConflict)
	}
	if existingVersion, ok := s.policyDigests[digestKey]; ok && existingVersion != assignment.Policy.Version {
		return false, fmt.Errorf("%w: privacy policy digest already belongs to another version", shared.ErrConflict)
	}
	if !exists {
		s.policies[key] = clonePrivacyAssignment(assignment)
		s.policyDigests[digestKey] = assignment.Policy.Version
	}
	return !exists, nil
}

func (s *PrivacyPolicyStore) ActivatePrivacyPolicy(
	ctx context.Context,
	activation privacy.Activation,
) (privacy.Activation, error) {
	tenantID, err := privacyPolicyMemoryTenant(ctx, activation.TenantID)
	if err != nil {
		return privacy.Activation{}, err
	}
	activation.TenantID = tenantID
	validation := activation
	if validation.Revision == 0 {
		validation.Revision = 1
	}
	if err := validation.Validate(); err != nil {
		return privacy.Activation{}, err
	}
	operationKey := tenantID.String() + ":" + activation.OperationID.String()

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.operations[operationKey]; ok {
		if existing.PolicyDigest != activation.PolicyDigest ||
			existing.PolicyVersion != activation.PolicyVersion ||
			existing.ActivatedBy != activation.ActivatedBy {
			return privacy.Activation{}, fmt.Errorf("%w: privacy activation operation already has different immutable content", shared.ErrConflict)
		}
		return existing, nil
	}
	assignment, ok := s.policies[privacyPolicyKey(tenantID, activation.PolicyVersion)]
	if !ok || assignment.Digest != activation.PolicyDigest {
		return privacy.Activation{}, shared.ErrNotFound
	}
	activation.Revision = uint64(len(s.activations[tenantID]) + 1)
	s.activations[tenantID] = append(s.activations[tenantID], activation)
	s.operations[operationKey] = activation
	s.active[tenantID] = activation.PolicyVersion
	return activation, nil
}

func (s *PrivacyPolicyStore) ActivatePrivacyPolicyWithAudit(
	ctx context.Context,
	activation privacy.Activation,
	intent ports.FleetAuditIntent,
) (privacy.Activation, ports.FleetAuditIntent, error) {
	tenantID, err := privacyPolicyMemoryTenant(ctx, activation.TenantID)
	if err != nil {
		return privacy.Activation{}, ports.FleetAuditIntent{}, err
	}
	activation.TenantID = tenantID
	validation := activation
	if validation.Revision == 0 {
		validation.Revision = 1
	}
	if err := validation.Validate(); err != nil {
		return privacy.Activation{}, ports.FleetAuditIntent{}, err
	}
	// Normalize returns a cloned metadata map, so the mutations below cannot reach the
	// caller's own copy of the intention.
	intent, err = validateMemoryFleetAuditIntent(intent)
	if err != nil {
		return privacy.Activation{}, ports.FleetAuditIntent{}, err
	}
	operationKey := tenantID.String() + ":" + activation.OperationID.String()
	auditKey := fleetAuditKey{tenant: tenantID, id: intent.ID}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.operations[operationKey]; ok {
		if existing.PolicyDigest != activation.PolicyDigest ||
			existing.PolicyVersion != activation.PolicyVersion ||
			existing.ActivatedBy != activation.ActivatedBy {
			return privacy.Activation{}, ports.FleetAuditIntent{}, fmt.Errorf("%w: privacy activation operation already has different immutable content", shared.ErrConflict)
		}
		intent.Entry.At = existing.ActivatedAt
		intent.Entry.Metadata["revision"] = fmt.Sprintf("%d", existing.Revision)
		if existingIntent, ok := s.auditIntents[auditKey]; ok {
			if !memoryFleetAuditIntentEqual(existingIntent, intent) {
				return privacy.Activation{}, ports.FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention id already has different immutable content", shared.ErrConflict)
			}
		} else {
			s.auditIntents[auditKey] = cloneMemoryFleetAuditIntent(intent)
		}
		return existing, cloneMemoryFleetAuditIntent(intent), nil
	}
	assignment, ok := s.policies[privacyPolicyKey(tenantID, activation.PolicyVersion)]
	if !ok || assignment.Digest != activation.PolicyDigest {
		return privacy.Activation{}, ports.FleetAuditIntent{}, shared.ErrNotFound
	}
	activation.Revision = uint64(len(s.activations[tenantID]) + 1)
	intent.Entry.Metadata["revision"] = fmt.Sprintf("%d", activation.Revision)
	if existingIntent, ok := s.auditIntents[auditKey]; ok && !memoryFleetAuditIntentEqual(existingIntent, intent) {
		return privacy.Activation{}, ports.FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention id already has different immutable content", shared.ErrConflict)
	}
	s.activations[tenantID] = append(s.activations[tenantID], activation)
	s.operations[operationKey] = activation
	s.active[tenantID] = activation.PolicyVersion
	s.auditIntents[auditKey] = cloneMemoryFleetAuditIntent(intent)
	return activation, cloneMemoryFleetAuditIntent(intent), nil
}

// ListPendingFleetAudits returns the bound tenant's undelivered audit obligations.
// It takes the tenant from context directly: there is no caller-supplied tenant to
// cross-check here, and routing an empty id through the request/context comparison
// would resolve to the DEFAULT tenant and reject every other tenant's own sweep.
func (s *PrivacyPolicyStore) ListPendingFleetAudits(ctx context.Context) ([]ports.FleetAuditIntent, error) {
	tenantID, err := requiredTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ports.FleetAuditIntent, 0)
	for key, intent := range s.auditIntents {
		if key.tenant == tenantID && !s.auditComplete[key] {
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

// AcknowledgeFleetAudit retires one of the bound tenant's obligations. The tenant
// comes from context for the same reason as the pending listing above.
func (s *PrivacyPolicyStore) AcknowledgeFleetAudit(ctx context.Context, id string) error {
	tenantID, err := requiredTenant(ctx)
	if err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: fleet audit intention id is required", shared.ErrValidation)
	}
	key := fleetAuditKey{tenant: tenantID, id: id}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.auditIntents[key]; !ok {
		return shared.ErrNotFound
	}
	s.auditComplete[key] = true
	return nil
}

// validateMemoryFleetAuditIntent canonicalizes through the single shared normalizer.
// This adapter must not normalize differently from the PostgreSQL one: the audit
// chain hashes the payload, so divergent rules would make one obligation hash
// differently depending on which backend is running.
func validateMemoryFleetAuditIntent(intent ports.FleetAuditIntent) (ports.FleetAuditIntent, error) {
	return intent.Normalize()
}

func cloneMemoryFleetAuditIntent(intent ports.FleetAuditIntent) ports.FleetAuditIntent {
	intent.Entry.Metadata = maps.Clone(intent.Entry.Metadata)
	return intent
}

func memoryFleetAuditIntentEqual(left, right ports.FleetAuditIntent) bool {
	return left.ID == right.ID && left.Entry.Actor == right.Entry.Actor &&
		left.Entry.Action == right.Entry.Action && left.Entry.Target == right.Entry.Target &&
		left.Entry.At.Equal(right.Entry.At) && maps.Equal(left.Entry.Metadata, right.Entry.Metadata) &&
		left.Entry.Hash == right.Entry.Hash && left.Entry.PreviousHash == right.Entry.PreviousHash
}

func (s *PrivacyPolicyStore) PrivacyPolicyActivationHistory(
	ctx context.Context,
	tenantID shared.ID,
) ([]privacy.Activation, error) {
	tenantID, err := privacyPolicyMemoryTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := append([]privacy.Activation(nil), s.activations[tenantID]...)
	return items, nil
}

func (s *PrivacyPolicyStore) ActivePrivacyPolicy(
	ctx context.Context,
	tenantID shared.ID,
) (privacy.Assignment, error) {
	tenantID, err := privacyPolicyMemoryTenant(ctx, tenantID)
	if err != nil {
		return privacy.Assignment{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	version, ok := s.active[tenantID]
	if !ok {
		return privacy.Assignment{}, shared.ErrNotFound
	}
	assignment, ok := s.policies[privacyPolicyKey(tenantID, version)]
	if !ok {
		return privacy.Assignment{}, shared.ErrNotFound
	}
	return clonePrivacyAssignment(assignment), nil
}

func (s *PrivacyPolicyStore) PrivacyPolicyByDigest(
	ctx context.Context,
	tenantID shared.ID,
	digest string,
) (privacy.Assignment, error) {
	tenantID, err := privacyPolicyMemoryTenant(ctx, tenantID)
	if err != nil {
		return privacy.Assignment{}, err
	}
	if digest == "" {
		return privacy.Assignment{}, fmt.Errorf("%w: privacy policy digest is required", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	version, ok := s.policyDigests[privacyPolicyDigestKey(tenantID, digest)]
	if !ok {
		return privacy.Assignment{}, shared.ErrNotFound
	}
	assignment, ok := s.policies[privacyPolicyKey(tenantID, version)]
	if !ok {
		return privacy.Assignment{}, shared.ErrNotFound
	}
	return clonePrivacyAssignment(assignment), nil
}

func (s *PrivacyPolicyStore) PrivacyPolicyHistory(
	ctx context.Context,
	tenantID shared.ID,
) ([]privacy.Assignment, error) {
	tenantID, err := privacyPolicyMemoryTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	items := make([]privacy.Assignment, 0)
	for _, assignment := range s.policies {
		if assignment.TenantID == tenantID {
			items = append(items, clonePrivacyAssignment(assignment))
		}
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].Policy.Version > items[j].Policy.Version
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items, nil
}

func privacyPolicyMemoryTenant(ctx context.Context, requested shared.ID) (shared.ID, error) {
	bound, err := requiredTenant(ctx)
	if err != nil {
		return "", err
	}
	requested = shared.TenantOrDefault(requested)
	if requested != bound {
		return "", fmt.Errorf("%w: privacy policy tenant does not match context", shared.ErrForbidden)
	}
	return bound, nil
}

func privacyPolicyKey(tenantID shared.ID, version string) string {
	return tenantID.String() + "\x00" + version
}

func privacyPolicyDigestKey(tenantID shared.ID, digest string) string {
	return tenantID.String() + "\x00" + digest
}

func clonePrivacyAssignment(value privacy.Assignment) privacy.Assignment {
	value.Policy.Dispositions = clonePrivacyDispositions(value.Policy.Dispositions)
	return value
}

func clonePrivacyDispositions(
	values map[privacy.FieldCategory]privacy.FieldDisposition,
) map[privacy.FieldCategory]privacy.FieldDisposition {
	if values == nil {
		return nil
	}
	copied := make(map[privacy.FieldCategory]privacy.FieldDisposition, len(values))
	for category, disposition := range values {
		copied[category] = disposition
	}
	return copied
}

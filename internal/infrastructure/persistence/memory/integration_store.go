package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type IntegrationStore struct {
	mu           sync.RWMutex
	queue        ports.JobQueue
	cipher       *vault.Cipher
	clock        ports.Clock
	integrations map[string]integration.Integration
	credentials  map[string]string
	bindings     map[string]integration.Binding
	operations   map[string]integration.Operation
	runs         map[string]integration.ExternalRun
}

func NewIntegrationStore(queue ports.JobQueue, cipher *vault.Cipher, clock ports.Clock) *IntegrationStore {
	return &IntegrationStore{
		queue: queue, cipher: cipher, clock: clock,
		integrations: map[string]integration.Integration{}, credentials: map[string]string{},
		bindings: map[string]integration.Binding{}, operations: map[string]integration.Operation{}, runs: map[string]integration.ExternalRun{},
	}
}

var _ ports.IntegrationStore = (*IntegrationStore)(nil)

func tenantKey(tenantID, id shared.ID) string { return tenantID.String() + "\x1f" + id.String() }

func integrationTenant(ctx context.Context) (shared.ID, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return shared.TenantOrDefault(tenantID), nil
}

func (store *IntegrationStore) CreateIntegration(ctx context.Context, item integration.Integration) error {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return err
	}
	if err := item.Normalize(); err != nil || item.TenantID != tenantID {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: integration tenant mismatch", shared.ErrValidation)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := tenantKey(tenantID, item.ID)
	if _, exists := store.integrations[key]; exists {
		return shared.ErrConflict
	}
	for _, existing := range store.integrations {
		if existing.TenantID == tenantID && !existing.Archived && existing.Provider == item.Provider && existing.Endpoint == item.Endpoint {
			return shared.ErrConflict
		}
	}
	store.integrations[key] = item.Clone()
	return nil
}

func (store *IntegrationStore) ListIntegrations(ctx context.Context, includeArchived bool) ([]integration.Integration, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return nil, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	items := make([]integration.Integration, 0)
	for _, item := range store.integrations {
		if item.TenantID == tenantID && (includeArchived || !item.Archived) {
			items = append(items, item.Clone())
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

func (store *IntegrationStore) GetIntegration(ctx context.Context, id shared.ID) (integration.Integration, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return integration.Integration{}, err
	}
	store.mu.RLock()
	item, exists := store.integrations[tenantKey(tenantID, id)]
	store.mu.RUnlock()
	if !exists {
		return integration.Integration{}, shared.ErrNotFound
	}
	return item.Clone(), nil
}

func (store *IntegrationStore) UpdateIntegration(ctx context.Context, item integration.Integration, expectedVersion int) (integration.Integration, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return integration.Integration{}, err
	}
	if err := item.Normalize(); err != nil || item.TenantID != tenantID {
		if err != nil {
			return integration.Integration{}, err
		}
		return integration.Integration{}, fmt.Errorf("%w: integration tenant mismatch", shared.ErrValidation)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := tenantKey(tenantID, item.ID)
	current, exists := store.integrations[key]
	if !exists {
		return integration.Integration{}, shared.ErrNotFound
	}
	if current.Archived || current.Version != expectedVersion {
		return integration.Integration{}, shared.ErrConflict
	}
	for otherKey, existing := range store.integrations {
		if otherKey != key && existing.TenantID == tenantID && !existing.Archived && existing.Provider == item.Provider && existing.Endpoint == item.Endpoint {
			return integration.Integration{}, shared.ErrConflict
		}
	}
	item.Enabled, item.Archived, item.CreatedAt = current.Enabled, current.Archived, current.CreatedAt
	item.Version = current.Version + 1
	item.UpdatedAt = store.clock.Now().UTC()
	store.integrations[key] = item.Clone()
	return item.Clone(), nil
}

func (store *IntegrationStore) SetIntegrationEnabled(ctx context.Context, id shared.ID, enabled bool, expectedVersion int) (integration.Integration, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return integration.Integration{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := tenantKey(tenantID, id)
	item, exists := store.integrations[key]
	if !exists {
		return integration.Integration{}, shared.ErrNotFound
	}
	if item.Archived || item.Version != expectedVersion {
		return integration.Integration{}, shared.ErrConflict
	}
	item.Enabled = enabled
	item.Version++
	item.UpdatedAt = store.clock.Now().UTC()
	store.integrations[key] = item
	return item.Clone(), nil
}

func (store *IntegrationStore) ArchiveIntegration(ctx context.Context, id shared.ID, expectedVersion int) error {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := tenantKey(tenantID, id)
	item, exists := store.integrations[key]
	if !exists {
		return shared.ErrNotFound
	}
	if item.Archived || item.Version != expectedVersion {
		return shared.ErrConflict
	}
	item.Enabled, item.Archived = false, true
	item.Version++
	item.UpdatedAt = store.clock.Now().UTC()
	store.integrations[key] = item
	return nil
}

func credentialKey(tenantID, integrationID shared.ID, credentialID string) string {
	return tenantID.String() + "\x1f" + integrationID.String() + "\x1f" + credentialID
}

func credentialAAD(tenantID, integrationID shared.ID, credentialID string) []byte {
	return []byte("synapse:integration-credential:" + tenantID.String() + ":" + integrationID.String() + ":" + credentialID)
}

func (store *IntegrationStore) PutIntegrationCredential(ctx context.Context, integrationID shared.ID, credentialID string, plaintext []byte) error {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return err
	}
	if len(plaintext) == 0 || len(plaintext) > integration.MaxCredentialBytes || credentialID == "" {
		return fmt.Errorf("%w: integration credential is invalid", shared.ErrValidation)
	}
	ciphertext, err := store.cipher.Seal(plaintext, credentialAAD(tenantID, integrationID, credentialID))
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	integrationKey := tenantKey(tenantID, integrationID)
	item, exists := store.integrations[integrationKey]
	if !exists {
		return shared.ErrNotFound
	}
	store.credentials[credentialKey(tenantID, integrationID, credentialID)] = ciphertext
	item.Enabled = false
	item.Version++
	item.UpdatedAt = store.clock.Now().UTC()
	store.integrations[integrationKey] = item
	return nil
}

func (store *IntegrationStore) DeleteIntegrationCredential(ctx context.Context, integrationID shared.ID, credentialID string) error {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := credentialKey(tenantID, integrationID, credentialID)
	if _, exists := store.credentials[key]; !exists {
		return shared.ErrNotFound
	}
	integrationKey := tenantKey(tenantID, integrationID)
	item, exists := store.integrations[integrationKey]
	if !exists {
		return shared.ErrNotFound
	}
	delete(store.credentials, key)
	item.Enabled = false
	item.Version++
	item.UpdatedAt = store.clock.Now().UTC()
	store.integrations[integrationKey] = item
	return nil
}

func (store *IntegrationStore) ResolveIntegrationCredential(ctx context.Context, integrationID shared.ID, credentialID string) ([]byte, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return nil, err
	}
	store.mu.RLock()
	ciphertext, exists := store.credentials[credentialKey(tenantID, integrationID, credentialID)]
	store.mu.RUnlock()
	if !exists {
		return nil, shared.ErrNotFound
	}
	return store.cipher.Open(ciphertext, credentialAAD(tenantID, integrationID, credentialID))
}

func (store *IntegrationStore) IntegrationCredentialConfigured(ctx context.Context, integrationID shared.ID, credentialID string) (bool, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return false, err
	}
	store.mu.RLock()
	_, exists := store.credentials[credentialKey(tenantID, integrationID, credentialID)]
	store.mu.RUnlock()
	return exists, nil
}

func (store *IntegrationStore) CreateIntegrationBinding(ctx context.Context, binding integration.Binding) error {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return err
	}
	if err := binding.Normalize(); err != nil || binding.TenantID != tenantID {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: integration binding tenant mismatch", shared.ErrValidation)
	}
	if _, err := store.GetIntegration(ctx, binding.IntegrationID); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, existing := range store.bindings {
		if existing.TenantID == tenantID && existing.IntegrationID == binding.IntegrationID && existing.ExternalKey == binding.ExternalKey {
			return shared.ErrConflict
		}
	}
	store.bindings[tenantKey(tenantID, binding.ID)] = binding
	return nil
}

func (store *IntegrationStore) ListIntegrationBindings(ctx context.Context, integrationID shared.ID) ([]integration.Binding, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return nil, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	items := make([]integration.Binding, 0)
	for _, binding := range store.bindings {
		if binding.TenantID == tenantID && binding.IntegrationID == integrationID {
			items = append(items, binding)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ExternalName < items[j].ExternalName })
	return items, nil
}

func (store *IntegrationStore) DeleteIntegrationBinding(ctx context.Context, integrationID, bindingID shared.ID) error {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := tenantKey(tenantID, bindingID)
	binding, exists := store.bindings[key]
	if !exists || binding.IntegrationID != integrationID {
		return shared.ErrNotFound
	}
	delete(store.bindings, key)
	return nil
}

func (store *IntegrationStore) StartIntegrationOperation(ctx context.Context, operation integration.Operation, jobKind string, payload []byte) (integration.Operation, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return integration.Operation{}, err
	}
	if operation.ID.IsZero() || operation.IntegrationID.IsZero() || operation.TenantID != tenantID || !operation.Type.Valid() || operation.State != integration.OperationQueued {
		return integration.Operation{}, fmt.Errorf("%w: integration operation is invalid", shared.ErrValidation)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, existing := range store.operations {
		if existing.TenantID == tenantID && existing.IntegrationID == operation.IntegrationID && !existing.State.Terminal() {
			return integration.Operation{}, shared.ErrConflict
		}
	}
	jobID, err := store.queue.Enqueue(ctx, jobKind, payload)
	if err != nil {
		return integration.Operation{}, err
	}
	operation.JobID = jobID
	store.operations[tenantKey(tenantID, operation.ID)] = operation.Clone()
	return operation.Clone(), nil
}

func (store *IntegrationStore) GetIntegrationOperation(ctx context.Context, id shared.ID) (integration.Operation, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return integration.Operation{}, err
	}
	store.mu.RLock()
	operation, exists := store.operations[tenantKey(tenantID, id)]
	store.mu.RUnlock()
	if !exists {
		return integration.Operation{}, shared.ErrNotFound
	}
	return operation.Clone(), nil
}

func (store *IntegrationStore) ListIntegrationOperations(ctx context.Context, integrationID shared.ID, limit int) ([]integration.Operation, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return nil, err
	}
	store.mu.RLock()
	items := make([]integration.Operation, 0)
	for _, operation := range store.operations {
		if operation.TenantID == tenantID && operation.IntegrationID == integrationID {
			items = append(items, operation.Clone())
		}
	}
	store.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (store *IntegrationStore) BeginIntegrationOperation(ctx context.Context, id shared.ID, startedAt time.Time) (integration.Operation, bool, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return integration.Operation{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := tenantKey(tenantID, id)
	operation, exists := store.operations[key]
	if !exists {
		return integration.Operation{}, false, shared.ErrNotFound
	}
	if operation.State.Terminal() {
		return operation.Clone(), false, nil
	}
	if operation.State == integration.OperationQueued {
		operation.State = integration.OperationRunning
		operation.StartedAt = &startedAt
		operation.UpdatedAt = startedAt
		store.operations[key] = operation
	}
	return operation.Clone(), true, nil
}

func (store *IntegrationStore) FinishIntegrationOperation(ctx context.Context, id shared.ID, state integration.OperationState, checkpoint string, counts integration.OperationCounts, errorsIn []string, pipelines []integration.Pipeline, finishedAt time.Time) (integration.Operation, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return integration.Operation{}, err
	}
	if !state.Terminal() || state == integration.OperationCancelled {
		return integration.Operation{}, fmt.Errorf("%w: terminal integration operation state is invalid", shared.ErrValidation)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := tenantKey(tenantID, id)
	operation, exists := store.operations[key]
	if !exists {
		return integration.Operation{}, shared.ErrNotFound
	}
	if operation.State == integration.OperationCancelled {
		return operation.Clone(), nil
	}
	operation.State, operation.Checkpoint, operation.Counts = state, checkpoint, counts
	operation.Errors = integration.BoundedErrors(errorsIn)
	operation.Pipelines = append([]integration.Pipeline(nil), pipelines...)
	operation.FinishedAt, operation.UpdatedAt = &finishedAt, finishedAt
	store.operations[key] = operation
	return operation.Clone(), nil
}

func (store *IntegrationStore) CancelIntegrationOperation(ctx context.Context, id shared.ID, finishedAt time.Time) (integration.Operation, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return integration.Operation{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := tenantKey(tenantID, id)
	operation, exists := store.operations[key]
	if !exists {
		return integration.Operation{}, shared.ErrNotFound
	}
	if operation.State.Terminal() {
		return integration.Operation{}, shared.ErrConflict
	}
	operation.State = integration.OperationCancelled
	operation.FinishedAt, operation.UpdatedAt = &finishedAt, finishedAt
	store.operations[key] = operation
	return operation.Clone(), nil
}

func (store *IntegrationStore) ListDueIntegrations(ctx context.Context, now time.Time, limit int) ([]integration.Integration, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return nil, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	items := make([]integration.Integration, 0)
	for _, item := range store.integrations {
		if item.TenantID != tenantID || !item.Enabled || item.Archived {
			continue
		}
		active := false
		var latest time.Time
		for _, operation := range store.operations {
			if operation.TenantID != tenantID || operation.IntegrationID != item.ID || operation.Type != integration.OperationPoll {
				continue
			}
			if !operation.State.Terminal() {
				active = true
				break
			}
			if operation.UpdatedAt.After(latest) {
				latest = operation.UpdatedAt
			}
		}
		if !active && (latest.IsZero() || !latest.Add(item.PollInterval).After(now)) {
			items = append(items, item.Clone())
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt.Before(items[j].UpdatedAt) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (store *IntegrationStore) UpsertIntegrationExternalRuns(ctx context.Context, runs []integration.ExternalRun) error {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return err
	}
	for index := range runs {
		if err := runs[index].Normalize(); err != nil || runs[index].TenantID != tenantID {
			if err != nil {
				return err
			}
			return fmt.Errorf("%w: external run tenant mismatch", shared.ErrValidation)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, run := range runs {
		key := tenantID.String() + "\x1f" + run.IntegrationID.String() + "\x1f" + run.ProviderKey
		if current, exists := store.runs[key]; exists {
			run.ID, run.CreatedAt = current.ID, current.CreatedAt
		}
		store.runs[key] = run
	}
	return nil
}

func (store *IntegrationStore) ListIntegrationExternalRuns(ctx context.Context, integrationID shared.ID, limit int) ([]integration.ExternalRun, error) {
	tenantID, err := integrationTenant(ctx)
	if err != nil {
		return nil, err
	}
	store.mu.RLock()
	items := make([]integration.ExternalRun, 0)
	for _, run := range store.runs {
		if run.TenantID == tenantID && run.IntegrationID == integrationID {
			items = append(items, run)
		}
	}
	store.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ProviderUpdatedAt.After(items[j].ProviderUpdatedAt) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

type MissingIntegrationAnalysisMatcher struct{}

func (MissingIntegrationAnalysisMatcher) MatchIntegrationAnalysis(context.Context, shared.ID, string) (shared.ID, integration.CorrelationState, error) {
	return "", integration.CorrelationMissing, nil
}

func cloneJSON[T any](value T) T {
	encoded, _ := json.Marshal(value)
	var clone T
	_ = json.Unmarshal(encoded, &clone)
	return clone
}

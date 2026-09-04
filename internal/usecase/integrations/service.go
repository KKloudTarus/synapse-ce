// Package integrations orchestrates provider-neutral CI/CD integrations.
package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	JobKind             = "integration.operation"
	credentialIdentity  = "default"
	defaultHistoryLimit = 50
)

type Job struct {
	OperationID shared.ID `json:"operation_id"`
}

type CreateInput struct {
	TenantID            shared.ID
	Provider            string
	Name                string
	Endpoint            string
	Config              map[string]any
	AllowPrivateNetwork bool
	PollInterval        time.Duration
	Actor               string
}

type UpdateInput struct {
	Name                string
	Endpoint            string
	Config              map[string]any
	AllowPrivateNetwork bool
	PollInterval        time.Duration
	Version             int
	Actor               string
}

type Service struct {
	store    ports.IntegrationStore
	registry *integration.Registry
	projects ports.ProjectRepository
	matcher  ports.IntegrationAnalysisMatcher
	ids      ports.IDGenerator
	clock    ports.Clock
	audit    ports.AuditLogger
	observer ports.IntegrationObserver
	runLock  ports.RunLocker
}

func (service *Service) SetObserver(observer ports.IntegrationObserver) { service.observer = observer }
func (service *Service) SetRunLock(runLock ports.RunLocker)             { service.runLock = runLock }

func NewService(store ports.IntegrationStore, registry *integration.Registry, projects ports.ProjectRepository, matcher ports.IntegrationAnalysisMatcher, ids ports.IDGenerator, clock ports.Clock, audit ports.AuditLogger) (*Service, error) {
	if store == nil || registry == nil || projects == nil || matcher == nil || ids == nil || clock == nil || audit == nil {
		return nil, fmt.Errorf("%w: integration service dependencies are required", shared.ErrValidation)
	}
	return &Service{store: store, registry: registry, projects: projects, matcher: matcher, ids: ids, clock: clock, audit: audit}, nil
}

func (service *Service) ProviderDescriptors() []integration.ProviderDescriptor {
	return service.registry.Descriptors()
}

func (service *Service) Create(ctx context.Context, input CreateInput) (integration.Integration, error) {
	provider, err := integration.NormalizeProvider(input.Provider)
	if err != nil {
		return integration.Integration{}, err
	}
	descriptor, err := service.registry.Descriptor(provider)
	if err != nil {
		return integration.Integration{}, err
	}
	if input.Config == nil {
		input.Config = map[string]any{}
	}
	if err := descriptor.ValidateConfig(input.Config); err != nil {
		return integration.Integration{}, err
	}
	config, err := json.Marshal(input.Config)
	if err != nil {
		return integration.Integration{}, fmt.Errorf("%w: integration configuration is invalid", shared.ErrValidation)
	}
	now := service.clock.Now().UTC()
	item := integration.Integration{
		ID: service.ids.NewID(), TenantID: shared.TenantOrDefault(input.TenantID), Provider: provider,
		Name: input.Name, Endpoint: input.Endpoint, Config: config, AllowPrivateNetwork: input.AllowPrivateNetwork,
		PollInterval: input.PollInterval, Version: 1, ConnectionRevision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := item.Normalize(); err != nil {
		return integration.Integration{}, err
	}
	tenantCtx := shared.WithTenant(ctx, item.TenantID)
	if err := service.store.CreateIntegration(tenantCtx, item); err != nil {
		return integration.Integration{}, err
	}
	if err := service.record(tenantCtx, input.Actor, "integration.created", item.ID, map[string]string{"provider": string(item.Provider)}); err != nil {
		return integration.Integration{}, err
	}
	return item, nil
}

func (service *Service) List(ctx context.Context, tenantID shared.ID, includeArchived bool) ([]integration.Integration, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	items, err := service.store.ListIntegrations(shared.WithTenant(ctx, tenantID), includeArchived)
	if err != nil {
		return nil, err
	}
	for index := range items {
		configured, credentialErr := service.store.IntegrationCredentialConfigured(shared.WithTenant(ctx, tenantID), items[index].ID, credentialIdentity)
		if credentialErr != nil {
			return nil, credentialErr
		}
		items[index].CredentialConfigured = configured
	}
	return items, nil
}

func (service *Service) Get(ctx context.Context, tenantID, id shared.ID) (integration.Integration, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	item, err := service.store.GetIntegration(shared.WithTenant(ctx, tenantID), id)
	if err != nil {
		return integration.Integration{}, err
	}
	item.CredentialConfigured, err = service.store.IntegrationCredentialConfigured(shared.WithTenant(ctx, tenantID), id, credentialIdentity)
	return item, err
}

func (service *Service) Update(ctx context.Context, tenantID, id shared.ID, input UpdateInput) (integration.Integration, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	tenantCtx := shared.WithTenant(ctx, tenantID)
	current, err := service.store.GetIntegration(tenantCtx, id)
	if err != nil {
		return integration.Integration{}, err
	}
	descriptor, err := service.registry.Descriptor(current.Provider)
	if err != nil {
		return integration.Integration{}, err
	}
	if input.Config == nil {
		input.Config = map[string]any{}
	}
	if err := descriptor.ValidateConfig(input.Config); err != nil {
		return integration.Integration{}, err
	}
	config, err := json.Marshal(input.Config)
	if err != nil {
		return integration.Integration{}, fmt.Errorf("%w: integration configuration is invalid", shared.ErrValidation)
	}
	current.Name = input.Name
	current.Endpoint = input.Endpoint
	current.Config = config
	current.AllowPrivateNetwork = input.AllowPrivateNetwork
	current.PollInterval = input.PollInterval
	current.Version = input.Version
	if err := current.Normalize(); err != nil {
		return integration.Integration{}, err
	}
	updated, err := service.store.UpdateIntegration(tenantCtx, current, input.Version)
	if err != nil {
		return integration.Integration{}, err
	}
	if err := service.record(tenantCtx, input.Actor, "integration.updated", id, map[string]string{"provider": string(current.Provider)}); err != nil {
		return integration.Integration{}, err
	}
	return updated, nil
}

func (service *Service) SetCredential(ctx context.Context, tenantID, integrationID shared.ID, secrets map[string]string, actor string) error {
	tenantID = shared.TenantOrDefault(tenantID)
	tenantCtx := shared.WithTenant(ctx, tenantID)
	item, err := service.store.GetIntegration(tenantCtx, integrationID)
	if err != nil {
		return err
	}
	descriptor, err := service.registry.Descriptor(item.Provider)
	if err != nil {
		return err
	}
	if err := descriptor.ValidateSecrets(secrets); err != nil {
		return err
	}
	plaintext, err := json.Marshal(secrets)
	if err != nil || len(plaintext) > integration.MaxCredentialBytes {
		return fmt.Errorf("%w: integration credential bundle is invalid", shared.ErrValidation)
	}
	if err := service.store.PutIntegrationCredential(tenantCtx, integrationID, credentialIdentity, plaintext); err != nil {
		return err
	}
	return service.record(tenantCtx, actor, "integration.credential_replaced", integrationID, map[string]string{"provider": string(item.Provider)})
}

func (service *Service) DeleteCredential(ctx context.Context, tenantID, integrationID shared.ID, actor string) error {
	tenantID = shared.TenantOrDefault(tenantID)
	tenantCtx := shared.WithTenant(ctx, tenantID)
	item, err := service.store.GetIntegration(tenantCtx, integrationID)
	if err != nil {
		return err
	}
	if err := service.store.DeleteIntegrationCredential(tenantCtx, integrationID, credentialIdentity); err != nil {
		return err
	}
	return service.record(tenantCtx, actor, "integration.credential_deleted", integrationID, map[string]string{"provider": string(item.Provider)})
}

func (service *Service) SetEnabled(ctx context.Context, tenantID, integrationID shared.ID, enabled bool, version int, actor string) (integration.Integration, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	tenantCtx := shared.WithTenant(ctx, tenantID)
	item, err := service.store.GetIntegration(tenantCtx, integrationID)
	if err != nil {
		return integration.Integration{}, err
	}
	if enabled {
		configured, err := service.store.IntegrationCredentialConfigured(tenantCtx, integrationID, credentialIdentity)
		if err != nil {
			return integration.Integration{}, err
		}
		if !configured {
			return integration.Integration{}, fmt.Errorf("%w: configure credentials before enabling the integration", shared.ErrConflict)
		}
	}
	updated, err := service.store.SetIntegrationEnabled(tenantCtx, integrationID, enabled, version)
	if err != nil {
		if enabled && errors.Is(err, shared.ErrConflict) {
			return integration.Integration{}, fmt.Errorf("%w: test the exact connection and credential revision successfully before enabling the integration", err)
		}
		return integration.Integration{}, err
	}
	action := "integration.disabled"
	if enabled {
		action = "integration.enabled"
	}
	if err := service.record(tenantCtx, actor, action, integrationID, map[string]string{"provider": string(item.Provider)}); err != nil {
		return integration.Integration{}, err
	}
	return updated, nil
}

func (service *Service) Archive(ctx context.Context, tenantID, integrationID shared.ID, version int, actor string) error {
	tenantID = shared.TenantOrDefault(tenantID)
	tenantCtx := shared.WithTenant(ctx, tenantID)
	item, err := service.store.GetIntegration(tenantCtx, integrationID)
	if err != nil {
		return err
	}
	if err := service.store.ArchiveIntegration(tenantCtx, integrationID, version); err != nil {
		return err
	}
	return service.record(tenantCtx, actor, "integration.archived", integrationID, map[string]string{"provider": string(item.Provider)})
}

func (service *Service) CreateBinding(ctx context.Context, tenantID, integrationID, projectID shared.ID, externalKey, externalName, actor string) (integration.Binding, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	tenantCtx := shared.WithTenant(ctx, tenantID)
	if _, err := service.store.GetIntegration(tenantCtx, integrationID); err != nil {
		return integration.Binding{}, err
	}
	if _, err := service.projects.GetByID(tenantCtx, tenantID, projectID); err != nil {
		return integration.Binding{}, err
	}
	now := service.clock.Now().UTC()
	binding := integration.Binding{ID: service.ids.NewID(), TenantID: tenantID, IntegrationID: integrationID, ProjectID: projectID, ExternalKey: externalKey, ExternalName: externalName, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := binding.Normalize(); err != nil {
		return integration.Binding{}, err
	}
	if err := service.store.CreateIntegrationBinding(tenantCtx, binding); err != nil {
		return integration.Binding{}, err
	}
	if err := service.record(tenantCtx, actor, "integration.binding_created", binding.ID, map[string]string{"integration_id": integrationID.String(), "project_id": projectID.String()}); err != nil {
		return integration.Binding{}, err
	}
	return binding, nil
}

func (service *Service) ListBindings(ctx context.Context, tenantID, integrationID shared.ID) ([]integration.Binding, error) {
	return service.store.ListIntegrationBindings(shared.WithTenant(ctx, shared.TenantOrDefault(tenantID)), integrationID)
}

func (service *Service) DeleteBinding(ctx context.Context, tenantID, integrationID, bindingID shared.ID, actor string) error {
	tenantCtx := shared.WithTenant(ctx, shared.TenantOrDefault(tenantID))
	if err := service.store.DeleteIntegrationBinding(tenantCtx, integrationID, bindingID); err != nil {
		return err
	}
	return service.record(tenantCtx, actor, "integration.binding_deleted", bindingID, map[string]string{"integration_id": integrationID.String()})
}

func (service *Service) StartOperation(ctx context.Context, tenantID, integrationID shared.ID, operationType integration.OperationType, actor string) (integration.Operation, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	tenantCtx := shared.WithTenant(ctx, tenantID)
	item, err := service.store.GetIntegration(tenantCtx, integrationID)
	if err != nil {
		return integration.Operation{}, err
	}
	if item.Archived || !operationType.Valid() {
		return integration.Operation{}, fmt.Errorf("%w: integration operation is invalid", shared.ErrValidation)
	}
	descriptor, err := service.registry.Descriptor(item.Provider)
	if err != nil {
		return integration.Operation{}, err
	}
	capability := map[integration.OperationType]integration.Capability{
		integration.OperationTest: integration.CapabilityTestConnection, integration.OperationDiscover: integration.CapabilityDiscover, integration.OperationPoll: integration.CapabilityReadRuns,
	}[operationType]
	if !descriptor.Supports(capability) {
		return integration.Operation{}, fmt.Errorf("%w: provider does not support %s", shared.ErrValidation, operationType)
	}
	if operationType == integration.OperationPoll && !item.Enabled {
		return integration.Operation{}, fmt.Errorf("%w: integration must be enabled before polling", shared.ErrConflict)
	}
	now := service.clock.Now().UTC()
	operation := integration.Operation{ID: service.ids.NewID(), TenantID: tenantID, IntegrationID: integrationID, Type: operationType, State: integration.OperationQueued, JobID: service.ids.NewID().String(), Actor: strings.TrimSpace(actor), CreatedAt: now, UpdatedAt: now}
	if operation.Actor == "" {
		operation.Actor = "system:integration"
	}
	payload, err := json.Marshal(Job{OperationID: operation.ID})
	if err != nil {
		return integration.Operation{}, fmt.Errorf("marshal integration job: %w", err)
	}
	audit := ports.AuditEntry{
		Actor: operation.Actor, Action: "integration.operation_started", Target: operation.ID.String(), At: now,
		Metadata: map[string]string{"integration_id": integrationID.String(), "operation": string(operationType), "provider": string(item.Provider)},
	}
	operation, err = service.store.StartIntegrationOperation(tenantCtx, operation, JobKind, payload, audit)
	if err != nil {
		return integration.Operation{}, err
	}
	return operation, nil
}

func (service *Service) GetOperation(ctx context.Context, tenantID, operationID shared.ID) (integration.Operation, error) {
	return service.store.GetIntegrationOperation(shared.WithTenant(ctx, shared.TenantOrDefault(tenantID)), operationID)
}

func (service *Service) ListOperations(ctx context.Context, tenantID, integrationID shared.ID, limit int) ([]integration.Operation, error) {
	if limit <= 0 || limit > 200 {
		limit = defaultHistoryLimit
	}
	return service.store.ListIntegrationOperations(shared.WithTenant(ctx, shared.TenantOrDefault(tenantID)), integrationID, limit)
}

func (service *Service) CancelOperation(ctx context.Context, tenantID, operationID shared.ID, actor string) (integration.Operation, error) {
	tenantCtx := shared.WithTenant(ctx, shared.TenantOrDefault(tenantID))
	operation, err := service.store.CancelIntegrationOperation(tenantCtx, operationID, service.clock.Now().UTC())
	if err != nil {
		return integration.Operation{}, err
	}
	if err := service.record(tenantCtx, actor, "integration.operation_cancelled", operationID, map[string]string{"integration_id": operation.IntegrationID.String(), "operation": string(operation.Type)}); err != nil {
		return integration.Operation{}, err
	}
	if item, getErr := service.store.GetIntegration(tenantCtx, operation.IntegrationID); getErr == nil {
		service.observe(item.Provider, operation.Type, operation.State)
	}
	return operation, nil
}

func (service *Service) ListExternalRuns(ctx context.Context, tenantID, integrationID shared.ID, limit int) ([]integration.ExternalRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return service.store.ListIntegrationExternalRuns(shared.WithTenant(ctx, shared.TenantOrDefault(tenantID)), integrationID, limit)
}

type integrationLeaseContextKey struct{}

func integrationRunLockKey(tenantID, operationID shared.ID) string {
	return "integration:" + tenantID.String() + ":" + operationID.String()
}

func acquireIntegrationRunLock(ctx context.Context, runLock ports.RunLocker, key string) (context.Context, func(), bool, error) {
	if runLock == nil {
		return ctx, nil, false, fmt.Errorf("%w: integration operation run lock is required", shared.ErrValidation)
	}
	if leased, ok := runLock.(ports.LeaseRunLocker); ok {
		leaseCtx, release, locked, err := leased.TryLockLeased(ctx, key)
		if locked {
			leaseCtx = context.WithValue(leaseCtx, integrationLeaseContextKey{}, ctx)
		}
		return leaseCtx, release, locked, err
	}
	release, locked, err := runLock.TryLock(ctx, key)
	return ctx, release, locked, err
}

func retryIntegrationLeaseLoss(ctx context.Context, err error) error {
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if parent, ok := ctx.Value(integrationLeaseContextKey{}).(context.Context); ok && parent.Err() == nil {
		return fmt.Errorf("integration operation execution lease lost: %w", ports.ErrRetryable)
	}
	return err
}

func (service *Service) HandleJob(ctx context.Context, jobID string, payload []byte) (err error) {
	var job Job
	if err := json.Unmarshal(payload, &job); err != nil || job.OperationID.IsZero() {
		return fmt.Errorf("%w: integration job payload is invalid", shared.ErrValidation)
	}
	operation, err := service.store.GetIntegrationOperation(ctx, job.OperationID)
	if err != nil {
		return err
	}
	if operation.JobID != jobID {
		return fmt.Errorf("%w: integration operation job identity mismatch", shared.ErrConflict)
	}
	if operation.State.Terminal() {
		return nil
	}
	executionCtx, release, locked, err := acquireIntegrationRunLock(ctx, service.runLock, integrationRunLockKey(operation.TenantID, operation.ID))
	if err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("integration operation is already executing: %w", ports.ErrRetryable)
	}
	defer release()
	defer func() { err = retryIntegrationLeaseLoss(executionCtx, err) }()
	operation, execute, err := service.store.BeginIntegrationOperation(executionCtx, operation.ID, service.clock.Now().UTC())
	if err != nil || !execute {
		return err
	}
	item, err := service.store.GetIntegration(executionCtx, operation.IntegrationID)
	if err != nil {
		return err
	}
	if item.Archived || item.ConnectionRevision != operation.ConnectionRevision || item.CredentialRevision != operation.CredentialRevision {
		return service.finishProviderFailure(executionCtx, item.Provider, operation, fmt.Errorf("integration operation revision is stale"))
	}
	credentials, err := service.credentials(executionCtx, item.ID, operation.CredentialRevision)
	if err != nil {
		return service.finishProviderFailure(executionCtx, item.Provider, operation, err)
	}
	adapter, err := service.registry.Resolve(item, credentials)
	if err != nil {
		return service.finishProviderFailure(executionCtx, item.Provider, operation, err)
	}
	switch operation.Type {
	case integration.OperationTest:
		return service.executeTest(executionCtx, item.Provider, operation, adapter)
	case integration.OperationDiscover:
		return service.executeDiscover(executionCtx, item.Provider, operation, adapter)
	case integration.OperationPoll:
		return service.executePoll(executionCtx, item.Provider, operation, adapter)
	default:
		return service.finishProviderFailure(executionCtx, item.Provider, operation, fmt.Errorf("unsupported operation"))
	}
}

func (service *Service) OnDeadLetter(ctx context.Context, payload []byte) error {
	var job Job
	if err := json.Unmarshal(payload, &job); err != nil || job.OperationID.IsZero() {
		return nil
	}
	operation, err := service.store.GetIntegrationOperation(ctx, job.OperationID)
	if err != nil || operation.State.Terminal() {
		return err
	}
	finished, err := service.store.FinishIntegrationOperation(ctx, operation.ID, integration.OperationFailed, operation.Checkpoint, operation.Counts, []string{"provider operation exhausted retries"}, nil, service.clock.Now().UTC())
	if err == nil && finished.State == integration.OperationFailed {
		if item, getErr := service.store.GetIntegration(ctx, operation.IntegrationID); getErr == nil {
			service.observe(item.Provider, operation.Type, integration.OperationFailed)
		}
	}
	return err
}

func (service *Service) executeTest(ctx context.Context, provider integration.Provider, operation integration.Operation, adapter integration.Adapter) error {
	tester, ok := adapter.(integration.ConnectionTester)
	if !ok {
		return service.finishProviderFailure(ctx, provider, operation, fmt.Errorf("provider lacks connection test capability"))
	}
	if err := tester.TestConnection(ctx); err != nil {
		return service.finishProviderFailure(ctx, provider, operation, err)
	}
	finished, err := service.store.FinishIntegrationOperation(ctx, operation.ID, integration.OperationSucceeded, operation.Checkpoint, integration.OperationCounts{}, nil, nil, service.clock.Now().UTC())
	if err == nil && finished.State == integration.OperationSucceeded {
		service.observe(provider, operation.Type, integration.OperationSucceeded)
	}
	return err
}

func (service *Service) executeDiscover(ctx context.Context, provider integration.Provider, operation integration.Operation, adapter integration.Adapter) error {
	discoverer, ok := adapter.(integration.PipelineDiscoverer)
	if !ok {
		return service.finishProviderFailure(ctx, provider, operation, fmt.Errorf("provider lacks discovery capability"))
	}
	pipelines, nextCheckpoint, err := discoverer.DiscoverPipelines(ctx, operation.Checkpoint)
	if err != nil {
		return service.finishProviderFailure(ctx, provider, operation, err)
	}
	if len(pipelines) > integration.MaxPipelines {
		return service.finishProviderFailure(ctx, provider, operation, fmt.Errorf("provider returned too many pipelines"))
	}
	for index := range pipelines {
		if err := pipelines[index].Normalize(); err != nil {
			return service.finishProviderFailure(ctx, provider, operation, err)
		}
	}
	counts := integration.OperationCounts{Pipelines: len(pipelines)}
	finished, err := service.store.FinishIntegrationOperation(ctx, operation.ID, integration.OperationSucceeded, nextCheckpoint, counts, nil, pipelines, service.clock.Now().UTC())
	if err == nil && finished.State == integration.OperationSucceeded {
		service.observe(provider, operation.Type, integration.OperationSucceeded)
	}
	return err
}

func (service *Service) executePoll(ctx context.Context, provider integration.Provider, operation integration.Operation, adapter integration.Adapter) error {
	reader, ok := adapter.(integration.RunReader)
	if !ok {
		return service.finishProviderFailure(ctx, provider, operation, fmt.Errorf("provider lacks run reader capability"))
	}
	bindings, err := service.store.ListIntegrationBindings(ctx, operation.IntegrationID)
	if err != nil {
		return err
	}
	checkpoints := decodeCheckpoints(operation.Checkpoint)
	nextCheckpoints := cloneCheckpoints(checkpoints)
	now := service.clock.Now().UTC()
	allRuns := make([]integration.ExternalRun, 0)
	counts := integration.OperationCounts{}
	errorSamples := make([]string, 0)
	retryableFailures := 0
	for _, binding := range bindings {
		runs, nextCheckpoint, readErr := reader.ReadRuns(ctx, binding, checkpoints[binding.ID.String()])
		if readErr != nil {
			counts.Errors++
			errorSamples = append(errorSamples, "failed to read runs for one bound pipeline")
			if integration.IsRetryable(readErr) {
				retryableFailures++
			}
			continue
		}
		if len(runs) > integration.MaxRunsPerPoll {
			counts.Errors++
			errorSamples = append(errorSamples, "provider returned too many runs for one pipeline")
			continue
		}
		for index := range runs {
			run := &runs[index]
			run.ID = service.ids.NewID()
			run.TenantID = operation.TenantID
			run.IntegrationID = operation.IntegrationID
			run.BindingID = binding.ID
			if run.PipelineKey == "" {
				run.PipelineKey = binding.ExternalKey
			}
			run.Correlation = integration.CorrelationMissing
			if run.Revision != "" {
				run.AnalysisID, run.Correlation, err = service.matcher.MatchIntegrationAnalysis(ctx, binding.ProjectID, run.Revision)
				if err != nil {
					return err
				}
			}
			if run.Correlation == integration.CorrelationLinked {
				counts.Linked++
			} else {
				counts.Unlinked++
			}
			if run.ProviderUpdatedAt.IsZero() {
				run.ProviderUpdatedAt = now
			}
			run.CreatedAt, run.UpdatedAt = now, now
			if err := run.Normalize(); err != nil {
				return service.finishProviderFailure(ctx, provider, operation, err)
			}
			allRuns = append(allRuns, *run)
		}
		nextCheckpoints[binding.ID.String()] = nextCheckpoint
	}
	counts.Runs = len(allRuns)
	if len(allRuns) == 0 && retryableFailures > 0 {
		return integration.RetryableError(fmt.Errorf("integration provider poll failed"))
	}
	if err := service.store.UpsertIntegrationExternalRuns(ctx, operation.ID, allRuns); err != nil {
		return err
	}
	state := integration.OperationSucceeded
	if counts.Errors > 0 {
		state = integration.OperationPartial
	}
	checkpoint, err := encodeCheckpoints(nextCheckpoints)
	if err != nil {
		return err
	}
	finished, err := service.store.FinishIntegrationOperation(ctx, operation.ID, state, checkpoint, counts, errorSamples, nil, now)
	if err == nil && finished.State == state {
		service.observe(provider, operation.Type, state)
	}
	return err
}

func (service *Service) finishProviderFailure(ctx context.Context, provider integration.Provider, operation integration.Operation, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if integration.IsRetryable(err) {
		return integration.RetryableError(fmt.Errorf("integration provider operation failed"))
	}
	finished, finishErr := service.store.FinishIntegrationOperation(ctx, operation.ID, integration.OperationFailed, operation.Checkpoint, operation.Counts, []string{"provider operation failed"}, nil, service.clock.Now().UTC())
	if finishErr == nil && finished.State == integration.OperationFailed {
		service.observe(provider, operation.Type, integration.OperationFailed)
	}
	return finishErr
}

func (service *Service) observe(provider integration.Provider, operation integration.OperationType, outcome integration.OperationState) {
	if service.observer != nil {
		service.observer.ObserveIntegrationOperation(string(provider), string(operation), string(outcome))
	}
}

func (service *Service) credentials(ctx context.Context, integrationID shared.ID, expectedRevision int) (integration.CredentialBundle, error) {
	plaintext, err := service.store.ResolveIntegrationCredential(ctx, integrationID, credentialIdentity, expectedRevision)
	if err != nil {
		return nil, err
	}
	var credentials map[string]string
	if err := json.Unmarshal(plaintext, &credentials); err != nil {
		return nil, fmt.Errorf("%w: stored integration credential is invalid", shared.ErrValidation)
	}
	return integration.CredentialBundle(credentials), nil
}

func (service *Service) record(ctx context.Context, actor, action string, target shared.ID, metadata map[string]string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system:integration"
	}
	return service.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target.String(), Metadata: metadata, At: service.clock.Now().UTC()})
}

func decodeCheckpoints(raw string) map[string]string {
	if raw == "" {
		return map[string]string{}
	}
	var checkpoints map[string]string
	if json.Unmarshal([]byte(raw), &checkpoints) != nil || checkpoints == nil {
		return map[string]string{}
	}
	return checkpoints
}

func cloneCheckpoints(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func encodeCheckpoints(checkpoints map[string]string) (string, error) {
	encoded, err := json.Marshal(checkpoints)
	if err != nil {
		return "", fmt.Errorf("marshal integration checkpoints: %w", err)
	}
	return string(encoded), nil
}

func IsRetryable(err error) bool {
	return integration.IsRetryable(err) || errors.Is(err, ports.ErrRetryable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

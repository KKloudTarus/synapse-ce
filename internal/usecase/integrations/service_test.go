package integrations

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type integrationTestClock struct{ now time.Time }

func (clock *integrationTestClock) Now() time.Time { return clock.now }
func (clock *integrationTestClock) advance()       { clock.now = clock.now.Add(time.Second) }

type integrationTestAudit struct{ entries []ports.AuditEntry }

func (audit *integrationTestAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	audit.entries = append(audit.entries, entry)
	return nil
}

type integrationTestMatcher struct{}

func (integrationTestMatcher) MatchIntegrationAnalysis(_ context.Context, _ shared.ID, revision string) (shared.ID, integration.CorrelationState, error) {
	if revision == "abc123" {
		return "analysis-1", integration.CorrelationLinked, nil
	}
	return "", integration.CorrelationMissing, nil
}

type integrationTestObserver struct{ events []string }

func (observer *integrationTestObserver) ObserveIntegrationOperation(provider, operation, outcome string) {
	observer.events = append(observer.events, provider+":"+operation+":"+outcome)
}

type integrationTestAdapter struct {
	descriptor     integration.ProviderDescriptor
	clock          *integrationTestClock
	readErrors     map[string]error
	runsPerBinding int
	testError      error
	onTest         func()
}

func (adapter *integrationTestAdapter) Descriptor() integration.ProviderDescriptor {
	return adapter.descriptor
}
func (adapter *integrationTestAdapter) TestConnection(ctx context.Context) error {
	if adapter.onTest != nil {
		adapter.onTest()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return adapter.testError
}
func (*integrationTestAdapter) DiscoverPipelines(context.Context, string) ([]integration.Pipeline, string, error) {
	return []integration.Pipeline{{ExternalKey: "/job/platform/job/main", Name: "main", FullName: "platform/main", Kind: "pipeline"}}, "discovery-v1", nil
}
func (adapter *integrationTestAdapter) ReadRuns(_ context.Context, binding integration.Binding, _ string) ([]integration.ExternalRun, string, error) {
	if err := adapter.readErrors[binding.ExternalKey]; err != nil {
		return nil, "", err
	}
	count := adapter.runsPerBinding
	if count == 0 {
		count = 1
	}
	runs := make([]integration.ExternalRun, count)
	for index := range runs {
		number := index + 1
		runs[index] = integration.ExternalRun{
			ProviderKey: fmt.Sprintf("%s:build:%d", binding.ExternalKey, number), PipelineKey: binding.ExternalKey, Number: fmt.Sprint(number), Lifecycle: integration.RunCompleted,
			Result: integration.ResultSuccess, Revision: "abc123", ProviderUpdatedAt: adapter.clock.Now(),
		}
	}
	return runs, fmt.Sprint(count), nil
}

type integrationTestLeaseLock struct{ cancel context.CancelFunc }

func (lock *integrationTestLeaseLock) TryLock(ctx context.Context, key string) (func(), bool, error) {
	_, release, locked, err := lock.TryLockLeased(ctx, key)
	return release, locked, err
}

func (lock *integrationTestLeaseLock) TryLockLeased(ctx context.Context, _ string) (context.Context, func(), bool, error) {
	leaseCtx, cancel := context.WithCancel(ctx)
	lock.cancel = cancel
	return leaseCtx, cancel, true, nil
}

func (lock *integrationTestLeaseLock) Cancel() {
	if lock.cancel != nil {
		lock.cancel()
	}
}

func TestServiceFullMemoryWorkflowIsIdempotentAndCancellationSafe(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.ID("tenant-1")
	clock := &integrationTestClock{now: time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)}
	ids := idgen.RandomID{}
	queue := memory.NewJobQueue(ids, clock.Now)
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	audit := &integrationTestAudit{}
	store := memory.NewIntegrationStore(queue, cipher, clock, audit)
	projects := memory.NewProjectRepository()
	projectItem, err := project.New("project-1", tenantID, "Platform", "platform", project.SourceBinding{Kind: project.SourceLocal, Value: "/tmp/platform"}, nil, "", clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := projects.Create(ctx, projectItem); err != nil {
		t.Fatal(err)
	}
	descriptor := integration.ProviderDescriptor{
		Provider: "fake-ci", Name: "Fake CI", Capabilities: []integration.Capability{integration.CapabilityTestConnection, integration.CapabilityDiscover, integration.CapabilityReadRuns},
		SecretFields: []integration.FieldDescriptor{{Name: "token", Label: "Token", Kind: integration.FieldPassword, Required: true}},
	}
	adapter := &integrationTestAdapter{descriptor: descriptor, clock: clock}
	registry := integration.NewRegistry()
	if err := registry.Register(descriptor, func(_ integration.Integration, credentials integration.CredentialBundle) (integration.Adapter, error) {
		if credentials["token"] != "secret" {
			t.Fatalf("resolved credentials = %#v", credentials)
		}
		return adapter, nil
	}); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, registry, projects, integrationTestMatcher{}, ids, clock)
	if err != nil {
		t.Fatal(err)
	}
	runLock := memory.NewRunLock()
	service.SetRunLock(runLock)
	observer := &integrationTestObserver{}
	service.SetObserver(observer)

	created, err := service.Create(ctx, CreateInput{TenantID: tenantID, Provider: "fake-ci", Name: "Fake", Endpoint: "https://ci.example.com", Config: map[string]any{}, PollInterval: time.Minute, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	initialVersion, initialConnectionRevision := created.Version, created.ConnectionRevision
	if err := service.SetCredential(ctx, tenantID, created.ID, map[string]string{"token": "secret"}, created.Version, created.ConnectionRevision, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetCredential(ctx, tenantID, created.ID, map[string]string{"token": "stale"}, initialVersion, initialConnectionRevision, "admin"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale credential replacement error=%v, want conflict", err)
	}
	created, err = service.Get(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	created, err = service.Update(ctx, tenantID, created.ID, UpdateInput{
		Name: created.Name, Endpoint: created.Endpoint, Config: map[string]any{}, AllowPrivateNetwork: created.AllowPrivateNetwork,
		PollInterval: created.PollInterval, Version: created.Version, Actor: "admin",
	})
	if err != nil || !created.CredentialConfigured {
		t.Fatalf("update credential presence = %+v, err=%v", created, err)
	}

	clock.advance()
	testOperation, err := service.StartOperation(ctx, tenantID, created.ID, integration.OperationTest, "admin")
	if err != nil {
		t.Fatal(err)
	}
	job, err := queue.Claim(ctx, time.Minute, JobKind)
	if err != nil || job == nil {
		t.Fatalf("claim test job = %+v, err=%v", job, err)
	}
	release, locked, err := runLock.TryLock(ctx, integrationRunLockKey(tenantID, testOperation.ID))
	if err != nil || !locked {
		t.Fatalf("pre-acquire operation lock: locked=%v err=%v", locked, err)
	}
	if err := service.HandleJob(shared.WithTenant(ctx, tenantID), job.ID, job.Payload); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("concurrent operation error=%v, want retryable", err)
	}
	testOperation, err = service.GetOperation(ctx, tenantID, testOperation.ID)
	if err != nil || testOperation.State != integration.OperationQueued {
		t.Fatalf("locked operation advanced = %+v, err=%v", testOperation, err)
	}
	release()

	adapter.testError = integration.RetryableError(errors.New("provider leaked secret-token"))
	handleErr := service.HandleJob(shared.WithTenant(ctx, tenantID), job.ID, job.Payload)
	if handleErr == nil || !integration.IsRetryable(handleErr) || strings.Contains(handleErr.Error(), "secret-token") {
		t.Fatalf("retryable provider error was not safely redacted: %v", handleErr)
	}
	testOperation, err = service.GetOperation(ctx, tenantID, testOperation.ID)
	if err != nil || testOperation.State != integration.OperationRunning || testOperation.FinishedAt != nil {
		t.Fatalf("retryable failure materialized terminal state = %+v, err=%v", testOperation, err)
	}
	adapter.testError = nil
	if err := service.HandleJob(shared.WithTenant(ctx, tenantID), job.ID, job.Payload); err != nil {
		t.Fatalf("retry test operation: %v", err)
	}
	if err := service.HandleJob(shared.WithTenant(ctx, tenantID), job.ID, job.Payload); err != nil {
		t.Fatalf("redeliver completed test operation: %v", err)
	}
	if err := queue.Complete(ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	testOperation, err = service.GetOperation(ctx, tenantID, testOperation.ID)
	if err != nil || testOperation.State != integration.OperationSucceeded {
		t.Fatalf("test operation = %+v, err=%v", testOperation, err)
	}

	clock.advance()
	leaseLostOperation, err := service.StartOperation(ctx, tenantID, created.ID, integration.OperationTest, "admin")
	if err != nil {
		t.Fatal(err)
	}
	job, err = queue.Claim(ctx, time.Minute, JobKind)
	if err != nil || job == nil {
		t.Fatalf("claim lease-loss job = %+v, err=%v", job, err)
	}
	leaseLock := &integrationTestLeaseLock{}
	service.SetRunLock(leaseLock)
	adapter.onTest = leaseLock.Cancel
	if err := service.HandleJob(shared.WithTenant(ctx, tenantID), job.ID, job.Payload); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("lease-loss operation error=%v, want retryable", err)
	}
	leaseLostOperation, err = service.GetOperation(ctx, tenantID, leaseLostOperation.ID)
	if err != nil || leaseLostOperation.State != integration.OperationRunning || leaseLostOperation.FinishedAt != nil || leaseLostOperation.Checkpoint != "" {
		t.Fatalf("lease-loss operation advanced = %+v, err=%v", leaseLostOperation, err)
	}
	adapter.onTest = nil
	service.SetRunLock(runLock)
	if err := service.HandleJob(shared.WithTenant(ctx, tenantID), job.ID, job.Payload); err != nil {
		t.Fatalf("retry after lease loss: %v", err)
	}
	if err := queue.Complete(ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}

	enabled, err := service.SetEnabled(ctx, tenantID, created.ID, true, created.Version, "admin")
	if err != nil || !enabled.Enabled || !enabled.CredentialConfigured {
		t.Fatalf("enable integration = %+v, err=%v", enabled, err)
	}

	clock.advance()
	discoverOperation, err := service.StartOperation(ctx, tenantID, created.ID, integration.OperationDiscover, "admin")
	if err != nil {
		t.Fatal(err)
	}
	executeNextIntegrationJob(t, ctx, tenantID, queue, service)
	discoverOperation, err = service.GetOperation(ctx, tenantID, discoverOperation.ID)
	if err != nil || discoverOperation.Checkpoint != "discovery-v1" || len(discoverOperation.Pipelines) != 1 {
		t.Fatalf("discover operation = %+v, err=%v", discoverOperation, err)
	}
	binding, err := service.CreateBinding(ctx, tenantID, created.ID, projectItem.ID, discoverOperation.Pipelines[0].ExternalKey, discoverOperation.Pipelines[0].FullName, "admin")
	if err != nil || binding.ProjectID != projectItem.ID {
		t.Fatalf("binding = %+v, err=%v", binding, err)
	}

	for range 2 {
		clock.advance()
		pollOperation, startErr := service.StartOperation(ctx, tenantID, created.ID, integration.OperationPoll, "admin")
		if startErr != nil {
			t.Fatal(startErr)
		}
		executeNextIntegrationJob(t, ctx, tenantID, queue, service)
		pollOperation, startErr = service.GetOperation(ctx, tenantID, pollOperation.ID)
		if startErr != nil || pollOperation.State != integration.OperationSucceeded || pollOperation.Counts.Linked != 1 {
			t.Fatalf("poll operation = %+v, err=%v", pollOperation, startErr)
		}
	}
	runs, err := service.ListExternalRuns(ctx, tenantID, created.ID, 100)
	if err != nil || len(runs) != 1 || runs[0].AnalysisID != "analysis-1" || runs[0].Correlation != integration.CorrelationLinked {
		t.Fatalf("external runs = %+v, err=%v", runs, err)
	}
	secondBinding, err := service.CreateBinding(ctx, tenantID, created.ID, projectItem.ID, "/job/platform/job/release", "platform/release", "admin")
	if err != nil {
		t.Fatal(err)
	}
	clock.advance()
	seedOperation, err := service.StartOperation(ctx, tenantID, created.ID, integration.OperationPoll, "admin")
	if err != nil {
		t.Fatal(err)
	}
	executeNextIntegrationJob(t, ctx, tenantID, queue, service)
	seedOperation, err = service.GetOperation(ctx, tenantID, seedOperation.ID)
	if err != nil || seedOperation.State != integration.OperationSucceeded || seedOperation.Counts.Runs != 2 {
		t.Fatalf("seed multi-binding poll = %+v, err=%v", seedOperation, err)
	}
	adapter.runsPerBinding = integration.MaxRunsPerPoll/2 + 1
	clock.advance()
	boundedOperation, err := service.StartOperation(ctx, tenantID, created.ID, integration.OperationPoll, "admin")
	if err != nil {
		t.Fatal(err)
	}
	executeNextIntegrationJob(t, ctx, tenantID, queue, service)
	boundedOperation, err = service.GetOperation(ctx, tenantID, boundedOperation.ID)
	if err != nil || boundedOperation.State != integration.OperationFailed {
		t.Fatalf("aggregate run budget operation = %+v, err=%v", boundedOperation, err)
	}
	boundedRuns, err := service.ListExternalRuns(ctx, tenantID, created.ID, 500)
	if err != nil || len(boundedRuns) != 2 {
		t.Fatalf("over-budget poll published partial runs = %+v, err=%v", boundedRuns, err)
	}
	adapter.runsPerBinding = 0
	adapter.readErrors = map[string]error{secondBinding.ExternalKey: integration.PermanentError(errors.New("provider pipeline unavailable"))}
	clock.advance()
	partialOperation, err := service.StartOperation(ctx, tenantID, created.ID, integration.OperationPoll, "admin")
	if err != nil {
		t.Fatal(err)
	}
	executeNextIntegrationJob(t, ctx, tenantID, queue, service)
	partialOperation, err = service.GetOperation(ctx, tenantID, partialOperation.ID)
	if err != nil || partialOperation.State != integration.OperationPartial || partialOperation.Counts.Runs != 1 || partialOperation.Counts.Errors != 1 {
		t.Fatalf("partial poll = %+v, err=%v", partialOperation, err)
	}
	runs, err = service.ListExternalRuns(ctx, tenantID, created.ID, 100)
	if err != nil || len(runs) != 2 {
		t.Fatalf("partial poll discarded last-known-good runs = %+v, err=%v", runs, err)
	}
	clock.advance()
	fencedPoll, err := service.StartOperation(ctx, tenantID, created.ID, integration.OperationPoll, "admin")
	if err != nil {
		t.Fatal(err)
	}
	fencedJob, err := queue.Claim(ctx, time.Minute, JobKind)
	if err != nil || fencedJob == nil {
		t.Fatalf("claim publication-fence job = %+v, err=%v", fencedJob, err)
	}
	if _, execute, beginErr := store.BeginIntegrationOperation(shared.WithTenant(ctx, tenantID), fencedPoll.ID, clock.Now()); beginErr != nil || !execute {
		t.Fatalf("begin publication-fence poll: execute=%v err=%v", execute, beginErr)
	}
	if _, err := service.CancelOperation(ctx, tenantID, fencedPoll.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	lateRun := integration.ExternalRun{
		ID: service.ids.NewID(), TenantID: tenantID, IntegrationID: created.ID, BindingID: binding.ID, ProviderKey: "late:build:1", PipelineKey: binding.ExternalKey,
		Lifecycle: integration.RunCompleted, Result: integration.ResultSuccess, Correlation: integration.CorrelationMissing, ProviderUpdatedAt: clock.Now(), CreatedAt: clock.Now(), UpdatedAt: clock.Now(),
	}
	if _, err := store.FinishIntegrationPoll(shared.WithTenant(ctx, tenantID), fencedPoll.ID, integration.OperationSucceeded, "late", integration.OperationCounts{Runs: 1}, nil, []integration.ExternalRun{lateRun}, clock.Now()); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("cancelled poll publication error=%v, want conflict", err)
	}
	runs, err = service.ListExternalRuns(ctx, tenantID, created.ID, 100)
	if err != nil || len(runs) != 2 {
		t.Fatalf("cancelled poll published runs = %+v, err=%v", runs, err)
	}
	clock.advance()
	if err := service.SetCredential(ctx, tenantID, created.ID, map[string]string{"token": "replacement"}, enabled.Version, enabled.ConnectionRevision, "admin"); err != nil {
		t.Fatal(err)
	}
	invalidated, err := service.Get(ctx, tenantID, created.ID)
	if err != nil || invalidated.Enabled || invalidated.Version <= enabled.Version {
		t.Fatalf("credential replacement did not invalidate integration: %+v err=%v", invalidated, err)
	}
	if _, err := service.SetEnabled(ctx, tenantID, created.ID, true, invalidated.Version, "admin"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale successful test enabled changed credentials: %v", err)
	}

	clock.advance()
	cancelled, err := service.StartOperation(ctx, tenantID, created.ID, integration.OperationDiscover, "admin")
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err = service.CancelOperation(ctx, tenantID, cancelled.ID, "admin")
	if err != nil || cancelled.State != integration.OperationCancelled {
		t.Fatalf("cancel operation = %+v, err=%v", cancelled, err)
	}
	if invalidatedJob, claimErr := queue.Claim(ctx, time.Minute, JobKind); claimErr != nil || invalidatedJob != nil {
		t.Fatalf("cancelled job remained claimable: job=%+v err=%v", invalidatedJob, claimErr)
	}
	cancelled, err = service.GetOperation(ctx, tenantID, cancelled.ID)
	if err != nil || cancelled.Checkpoint != "" || cancelled.State != integration.OperationCancelled {
		t.Fatalf("cancelled operation advanced = %+v, err=%v", cancelled, err)
	}
	if got := observer.events[len(observer.events)-1]; got != "fake-ci:discover:cancelled" {
		t.Fatalf("last metric event = %q", got)
	}

	clock.advance()
	deadLettered, err := service.StartOperation(ctx, tenantID, created.ID, integration.OperationTest, "admin")
	if err != nil {
		t.Fatal(err)
	}
	job, err = queue.Claim(ctx, time.Minute, JobKind)
	if err != nil || job == nil {
		t.Fatalf("claim dead-letter job = %+v, err=%v", job, err)
	}
	if err := service.OnDeadLetter(shared.WithTenant(ctx, tenantID), job.Payload); err != nil {
		t.Fatal(err)
	}
	if err := queue.Deadletter(ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	deadLettered, err = service.GetOperation(ctx, tenantID, deadLettered.ID)
	if err != nil || deadLettered.State != integration.OperationFailed || len(deadLettered.Errors) != 1 {
		t.Fatalf("dead-lettered operation = %+v, err=%v", deadLettered, err)
	}
}

func executeNextIntegrationJob(t *testing.T, ctx context.Context, tenantID shared.ID, queue *memory.JobQueue, service *Service) {
	t.Helper()
	job, err := queue.Claim(ctx, time.Minute, JobKind)
	if err != nil || job == nil {
		t.Fatalf("claim integration job = %+v, err=%v", job, err)
	}
	if err := service.HandleJob(shared.WithTenant(ctx, tenantID), job.ID, job.Payload); err != nil {
		t.Fatalf("handle integration job: %v", err)
	}
	if err := service.HandleJob(shared.WithTenant(ctx, tenantID), job.ID, job.Payload); err != nil {
		t.Fatalf("redeliver completed integration job: %v", err)
	}
	if err := queue.Complete(ctx, job.ID, job.Fence); err != nil {
		t.Fatalf("complete integration job: %v", err)
	}
}

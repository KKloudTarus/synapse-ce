// Package cspm orchestrates read-only live cloud posture scans.
package cspm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxTargets = 32
	JobKind    = "cspm"
)

var readOnlyAWSOperations = map[string]struct{}{
	"DescribeInstances": {}, "DescribeOrganization": {}, "DescribeSecurityGroups": {},
	"GetBucketEncryption": {}, "GetBucketPolicyStatus": {}, "ListAccounts": {},
	"ListBuckets": {}, "ListUsers": {}, "AssumeRole": {},
}

type RunInput struct {
	TenantID     shared.ID
	EngagementID shared.ID
	Actor        string
	Scopes       []ports.CloudScope
	Expectations []cloudposture.Expectation
}

type RunResult struct {
	Complete       bool                             `json:"complete"`
	Assets         int                              `json:"assets"`
	Findings       int                              `json:"findings"`
	CoverageIssues []cloudposture.CoverageIssue     `json:"coverage_issues,omitempty"`
	EvidenceRefs   []cloudposture.EvidenceReference `json:"evidence_refs,omitempty"`
}

type Service struct {
	connectors   map[cloudposture.Provider]ports.CloudConnector
	assets       ports.CloudAssetWriter
	findings     ports.FindingRepository
	attributor   ports.FindingAttributor
	expectations ports.CloudExpectationSource
	engagements  ports.EngagementRepository
	audit        ports.AuditLogger
	clock        ports.Clock
	ids          ports.IDGenerator
	evidence     ports.CloudEvidenceSealer
	executor     ports.CloudSandboxExecutor
	runs         ports.CloudRunStore
	runEnqueuer  ports.CloudRunEnqueuer
	observations ports.CloudObservationStore
	queue        ports.JobQueue
	runLock      ports.RunLocker
}

// Evaluator applies provider-neutral rules. Enumeration always requires CloudSandboxExecutor.
type Evaluator struct{}

func (Evaluator) Enumerate(context.Context, ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	return cloudposture.Inventory{}, nil, fmt.Errorf("%w: cloud enumeration requires the sandbox executor", shared.ErrForbidden)
}

func (Evaluator) Evaluate(ctx context.Context, inventory cloudposture.Inventory) ([]cloudposture.PostureFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cloudposture.Evaluate(inventory)
}

func NewService(connectors map[cloudposture.Provider]ports.CloudConnector, assets ports.CloudAssetWriter, findings ports.FindingRepository, engagements ports.EngagementRepository, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if len(connectors) == 0 || assets == nil || findings == nil || engagements == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: cspm requires connectors, assets, findings, engagements, audit, and clock", shared.ErrValidation)
	}
	copyConnectors := make(map[cloudposture.Provider]ports.CloudConnector, len(connectors))
	for provider, connector := range connectors {
		if !provider.Valid() || connector == nil {
			return nil, fmt.Errorf("%w: invalid cspm connector %q", shared.ErrValidation, provider)
		}
		copyConnectors[provider] = connector
	}
	return &Service{connectors: copyConnectors, assets: assets, findings: findings, engagements: engagements, audit: audit, clock: clock}, nil
}

func (s *Service) SetExpectationSource(source ports.CloudExpectationSource) { s.expectations = source }
func (s *Service) SetAttributor(attributor ports.FindingAttributor)         { s.attributor = attributor }
func (s *Service) SetEvidenceSealer(sealer ports.CloudEvidenceSealer)       { s.evidence = sealer }
func (s *Service) SetObservationStore(store ports.CloudObservationStore)    { s.observations = store }
func (s *Service) SetSandboxExecutor(executor ports.CloudSandboxExecutor)   { s.executor = executor }

func (s *Service) SetDurableExecution(runs ports.CloudRunStore, queue ports.JobQueue, ids ports.IDGenerator) error {
	if runs == nil || queue == nil || ids == nil {
		return fmt.Errorf("%w: CSPM durable execution requires run store, queue, and ids", shared.ErrValidation)
	}
	enqueuer, ok := runs.(ports.CloudRunEnqueuer)
	if !ok {
		return fmt.Errorf("%w: CSPM run store must support atomic enqueue", shared.ErrValidation)
	}
	if binder, ok := runs.(interface{ SetQueue(ports.JobQueue) }); ok {
		binder.SetQueue(queue)
	}
	s.runs, s.runEnqueuer, s.queue, s.ids = runs, enqueuer, queue, ids
	return nil
}

func (s *Service) SetRunLock(lock ports.RunLocker) { s.runLock = lock }

type cloudJob struct {
	TenantID        shared.ID          `json:"tenant_id"`
	RunID           shared.ID          `json:"run_id"`
	EngagementID    shared.ID          `json:"engagement_id"`
	Actor           string             `json:"actor"`
	Scopes          []ports.CloudScope `json:"scopes"`
	ApprovedTargets []string           `json:"approved_targets"`
}

func (s *Service) Submit(ctx context.Context, in RunInput) (cloudposture.Run, error) {
	if s.runs == nil || s.queue == nil || s.ids == nil {
		return cloudposture.Run{}, fmt.Errorf("%w: CSPM durable execution is not configured", shared.ErrValidation)
	}
	if _, err := s.prevalidate(ctx, &in); err != nil {
		return cloudposture.Run{}, err
	}
	now := s.clock.Now()
	run := cloudposture.Run{ID: s.ids.NewID(), TenantID: in.TenantID, EngagementID: in.EngagementID, Actor: in.Actor, Status: cloudposture.RunQueued, StartedAt: now}
	approvedTargets := make([]string, len(in.Scopes))
	for index := range in.Scopes {
		approvedTargets[index] = in.Scopes[index].ApprovedTarget
	}
	payload, err := json.Marshal(cloudJob{TenantID: in.TenantID, RunID: run.ID, EngagementID: in.EngagementID, Actor: in.Actor, Scopes: in.Scopes, ApprovedTargets: approvedTargets})
	if err != nil {
		return cloudposture.Run{}, fmt.Errorf("marshal CSPM job: %w", err)
	}
	tenantCtx := shared.WithTenant(ctx, in.TenantID)
	if err := s.audit.Record(tenantCtx, ports.AuditEntry{Actor: in.Actor, Action: "cspm.run_requested", Target: in.EngagementID.String(), Metadata: map[string]string{"run_id": run.ID.String(), "targets": fmt.Sprint(len(in.Scopes))}, At: now}); err != nil {
		return cloudposture.Run{}, fmt.Errorf("audit CSPM run request: %w", err)
	}
	if err := s.runEnqueuer.EnqueueCloudRun(tenantCtx, run, JobKind, payload); err != nil {
		finalCtx, cancel := context.WithTimeout(context.WithoutCancel(tenantCtx), 5*time.Second)
		defer cancel()
		_ = s.audit.Record(finalCtx, ports.AuditEntry{Actor: in.Actor, Action: "cspm.run_failed", Target: in.EngagementID.String(), Metadata: map[string]string{"run_id": run.ID.String(), "reason": "enqueue_failed"}, At: s.clock.Now()})
		return cloudposture.Run{}, fmt.Errorf("atomically enqueue CSPM run: %w", err)
	}
	return run, nil
}

func (s *Service) GetRun(ctx context.Context, tenantID, runID shared.ID) (cloudposture.Run, error) {
	if s.runs == nil {
		return cloudposture.Run{}, fmt.Errorf("%w: CSPM durable execution is not configured", shared.ErrValidation)
	}
	return s.runs.GetCloudRun(shared.WithTenant(ctx, tenantID), tenantID, runID)
}

type leaseContextKey struct{}

func acquireRunLock(ctx context.Context, lock ports.RunLocker, runID string) (context.Context, func(), bool, error) {
	if leased, ok := lock.(ports.LeaseRunLocker); ok {
		leaseCtx, release, locked, err := leased.TryLockLeased(ctx, runID)
		if locked {
			leaseCtx = context.WithValue(leaseCtx, leaseContextKey{}, ctx)
		}
		return leaseCtx, release, locked, err
	}
	release, locked, err := lock.TryLock(ctx, runID)
	return ctx, release, locked, err
}

func (s *Service) RunJob(ctx context.Context, payload []byte) error {
	var job cloudJob
	if err := json.Unmarshal(payload, &job); err != nil {
		return fmt.Errorf("%w: malformed CSPM job", shared.ErrValidation)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID != job.TenantID || len(job.ApprovedTargets) != len(job.Scopes) {
		return fmt.Errorf("%w: CSPM job tenant or scope metadata mismatch", shared.ErrValidation)
	}
	if s.runLock == nil {
		return fmt.Errorf("%w: CSPM run lock is required", shared.ErrValidation)
	}
	leaseCtx, release, locked, err := acquireRunLock(ctx, s.runLock, job.RunID.String())
	if err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer release()
	ctx = leaseCtx
	run, err := s.runs.GetCloudRun(ctx, job.TenantID, job.RunID)
	if err != nil {
		return err
	}
	if run.Status.Terminal() {
		return nil
	}
	run.Status = cloudposture.RunRunning
	if err := s.runs.SaveCloudRun(ctx, run); err != nil {
		return err
	}
	for index := range job.Scopes {
		job.Scopes[index].ApprovedTarget = job.ApprovedTargets[index]
		job.Scopes[index].EgressExecutionKind = "cspm"
		job.Scopes[index].EgressExecutionID = job.RunID.String()
	}
	result, runErr := s.Run(ctx, RunInput{TenantID: job.TenantID, EngagementID: job.EngagementID, Actor: job.Actor, Scopes: job.Scopes})
	if runErr != nil {
		finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			if parent, ok := ctx.Value(leaseContextKey{}).(context.Context); ok && parent.Err() == nil {
				run.Status, run.ErrorCode = cloudposture.RunQueued, "lease_lost"
				if saveErr := s.runs.SaveCloudRun(finalCtx, run); saveErr != nil {
					return fmt.Errorf("record CSPM lease loss: %w", saveErr)
				}
				return fmt.Errorf("CSPM execution lease lost: %w", runErr)
			}
			finished := s.clock.Now()
			run.Status, run.ErrorCode, run.FinishedAt = cloudposture.RunCancelled, "cancelled", &finished
			if saveErr := s.runs.SaveCloudRun(finalCtx, run); saveErr != nil {
				return fmt.Errorf("record cancelled CSPM run: %w", saveErr)
			}
			return nil
		}
		if errors.Is(runErr, shared.ErrForbidden) || errors.Is(runErr, shared.ErrValidation) {
			finished := s.clock.Now()
			run.Status, run.ErrorCode, run.FinishedAt = cloudposture.RunFailed, "permanent_execution_failure", &finished
			if saveErr := s.runs.SaveCloudRun(finalCtx, run); saveErr != nil {
				return fmt.Errorf("record failed CSPM run: %w", saveErr)
			}
			return nil
		}
		run.Status, run.ErrorCode = cloudposture.RunQueued, "retryable_execution_failure"
		if saveErr := s.runs.SaveCloudRun(finalCtx, run); saveErr != nil {
			return fmt.Errorf("record retryable CSPM failure: %w", saveErr)
		}
		return runErr
	}
	finished := s.clock.Now()
	run.Complete, run.Assets, run.Findings, run.CoverageIssues, run.EvidenceRefs, run.FinishedAt = result.Complete, result.Assets, result.Findings, result.CoverageIssues, result.EvidenceRefs, &finished
	if result.Complete {
		run.Status = cloudposture.RunSucceeded
	} else {
		run.Status = cloudposture.RunPartial
	}
	run.ErrorCode = ""
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.runs.SaveCloudRun(finalCtx, run); err != nil {
		return fmt.Errorf("finalize CSPM run: %w", err)
	}
	return nil
}

func (s *Service) FailStrandedJob(ctx context.Context, payload []byte, _ error) error {
	var job cloudJob
	if err := json.Unmarshal(payload, &job); err != nil {
		return fmt.Errorf("%w: malformed CSPM job", shared.ErrValidation)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID != job.TenantID {
		return fmt.Errorf("%w: CSPM job tenant mismatch", shared.ErrValidation)
	}
	if s.runLock == nil {
		return fmt.Errorf("%w: CSPM run lock is required", shared.ErrValidation)
	}
	leaseCtx, release, locked, err := acquireRunLock(ctx, s.runLock, job.RunID.String())
	if err != nil || !locked {
		return err
	}
	defer release()
	run, err := s.runs.GetCloudRun(leaseCtx, job.TenantID, job.RunID)
	if err != nil || run.Status.Terminal() {
		return err
	}
	finished := s.clock.Now()
	run.Status, run.ErrorCode, run.FinishedAt = cloudposture.RunFailed, "dead_lettered", &finished
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(leaseCtx), 5*time.Second)
	defer cancel()
	return s.runs.SaveCloudRun(finalCtx, run)
}

func (s *Service) prevalidate(ctx context.Context, in *RunInput) (*engagement.Engagement, error) {
	if in.TenantID.IsZero() || in.EngagementID.IsZero() || strings.TrimSpace(in.Actor) == "" || len(in.Scopes) == 0 || len(in.Scopes) > maxTargets {
		return nil, fmt.Errorf("%w: cspm run requires tenant, engagement, actor, and 1..%d scopes", shared.ErrValidation, maxTargets)
	}
	authorized, err := s.engagements.GetByIDInTenant(ctx, in.TenantID, in.EngagementID)
	if err != nil {
		return nil, fmt.Errorf("cspm authorize engagement: %w", err)
	}
	if !authorized.AllowsExecution() || !authorized.IsAuthorizedAt(s.clock.Now()) {
		return nil, fmt.Errorf("%w: engagement is not authorized for execution", shared.ErrForbidden)
	}
	seen := make(map[string]struct{}, len(in.Scopes))
	for index := range in.Scopes {
		scope := &in.Scopes[index]
		if s.connectors[scope.Provider] == nil || scope.EngagementID != in.EngagementID || strings.TrimSpace(scope.CredentialRef) == "" {
			return nil, fmt.Errorf("%w: invalid cspm scope", shared.ErrValidation)
		}
		root, scopeKey, err := cloudposture.NormalizeRoot(scope.Provider, scope.Root)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[scopeKey]; duplicate {
			return nil, fmt.Errorf("%w: duplicate cspm scope", shared.ErrValidation)
		}
		seen[scopeKey] = struct{}{}
		approvedTarget := ""
		for _, target := range authorized.Scope.InScope {
			if target.Kind != engagement.TargetCloudAccount {
				continue
			}
			if candidateKey, candidateErr := cloudposture.ScopeKey(scope.Provider, target.Value); candidateErr == nil && candidateKey == scopeKey {
				approvedTarget = target.Value
				break
			}
		}
		if approvedTarget == "" {
			return nil, fmt.Errorf("%w: cloud root is outside engagement scope", shared.ErrForbidden)
		}
		scope.Root, scope.ScopeKey, scope.ApprovedTarget = root, scopeKey, approvedTarget
	}
	return authorized, nil
}

func azureTokenEndpointIsReadOnly(target string) bool {
	const host = "login.microsoftonline.com/"
	if !strings.HasPrefix(target, host) {
		return false
	}
	path := strings.TrimPrefix(target, host)
	tenant, endpoint, ok := strings.Cut(path, "/")
	return ok && tenant != "" && !strings.ContainsAny(tenant, "/?#") && (endpoint == "oauth2/token" || endpoint == "oauth2/v2.0/token")
}

func gcpOperationIsReadOnly(method, target string) bool {
	if method == "POST" && target == "oauth2.googleapis.com/token" {
		return true
	}
	host, path, ok := strings.Cut(target, "/")
	if !ok {
		return false
	}
	switch host {
	case "cloudresourcemanager.googleapis.com":
		return method == "GET" && (path == "v1/projects" || strings.HasPrefix(path, "v3/folders")) || method == "POST" && strings.HasPrefix(path, "v1/projects/") && strings.HasSuffix(path, ":getIamPolicy")
	case "compute.googleapis.com":
		return method == "GET" && gcpComputePathIsReadOnly(path)
	case "storage.googleapis.com":
		return method == "GET" && (path == "storage/v1/b" || strings.HasPrefix(path, "storage/v1/b/"))
	case "iam.googleapis.com":
		return method == "GET" && strings.HasPrefix(path, "v1/projects/") && strings.Contains(path, "/serviceAccounts")
	default:
		return false
	}
}

func gcpComputePathIsReadOnly(path string) bool {
	if !strings.HasPrefix(path, "compute/v1/projects/") {
		return false
	}
	for _, suffix := range []string{"/aggregated/instances", "/global/routes", "/global/firewalls", "/global/networks"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func cloudOperationIsReadOnly(operation ports.CloudOperation) bool {
	method, target, hasTarget := strings.Cut(operation.Name, " ")
	switch operation.Provider {
	case cloudposture.ProviderAWS:
		_, allowed := readOnlyAWSOperations[method]
		return allowed && !hasTarget
	case cloudposture.ProviderAzure:
		return method == "POST" && hasTarget && (target == "management.azure.com/providers/Microsoft.ResourceGraph/resources" || azureTokenEndpointIsReadOnly(target))
	case cloudposture.ProviderGCP:
		return hasTarget && gcpOperationIsReadOnly(method, target)
	default:
		return false
	}
}

func (s *Service) authorizeOperation(ctx context.Context, in RunInput, scope ports.CloudScope, operation ports.CloudOperation) error {
	if operation.Provider != scope.Provider || operation.ScopeKey != scope.ScopeKey {
		return fmt.Errorf("%w: cloud operation scope mismatch", shared.ErrForbidden)
	}
	if !cloudOperationIsReadOnly(operation) {
		now := s.clock.Now()
		finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.audit.Record(finalCtx, ports.AuditEntry{Actor: in.Actor, Action: "cspm.operation.denied", Target: scope.ApprovedTarget, Metadata: map[string]string{"provider": string(operation.Provider), "operation": operation.Name, "reason": "operation_not_allowlisted"}, At: now})
		return fmt.Errorf("%w: cloud operation is not allowlisted as read-only", shared.ErrForbidden)
	}
	eng, err := s.engagements.GetByIDInTenant(ctx, in.TenantID, in.EngagementID)
	now := s.clock.Now()
	if err != nil || !eng.AllowsExecution() || !eng.IsAuthorizedAt(now) || !eng.Scope.AllowsTarget(engagement.Target{Kind: engagement.TargetCloudAccount, Value: scope.ApprovedTarget}) {
		finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.audit.Record(finalCtx, ports.AuditEntry{Actor: in.Actor, Action: "cspm.operation.denied", Target: scope.ApprovedTarget, Metadata: map[string]string{"provider": string(operation.Provider), "operation": operation.Name}, At: now})
		return fmt.Errorf("%w: cloud operation is no longer authorized", shared.ErrForbidden)
	}
	if ok, _ := eng.RoE.Permits(engagement.ToolClassOf("cspm."+operation.Name), now); !ok {
		return fmt.Errorf("%w: CSPM operation denied by rules of engagement", shared.ErrForbidden)
	}
	return s.audit.Record(ctx, ports.AuditEntry{Actor: in.Actor, Action: "cspm." + operation.Name, Target: scope.ApprovedTarget, Metadata: map[string]string{"provider": string(operation.Provider), "category": operation.Category}, At: now})
}

func (s *Service) Run(ctx context.Context, in RunInput) (result RunResult, runErr error) {
	authorized, err := s.prevalidate(ctx, &in)
	if err != nil {
		return RunResult{}, err
	}
	deadline := s.clock.Now().Add(15 * time.Minute)
	if authorized.AuthorizedTo != nil && authorized.AuthorizedTo.Before(deadline) {
		deadline = *authorized.AuthorizedTo
	}
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	runCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	started := false
	defer func() {
		if !started {
			return
		}
		finalCtx, finalCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer finalCancel()
		action := "cspm.run_completed"
		if runErr != nil {
			action = "cspm.run_failed"
		} else if !result.Complete {
			action = "cspm.run_partial"
		}
		if auditErr := s.audit.Record(finalCtx, ports.AuditEntry{Actor: in.Actor, Action: action, Target: in.EngagementID.String(), Metadata: map[string]string{"assets": fmt.Sprint(result.Assets), "findings": fmt.Sprint(result.Findings), "complete": fmt.Sprint(result.Complete)}, At: s.clock.Now()}); auditErr != nil && runErr == nil {
			runErr = fmt.Errorf("cspm audit terminal state: %w", auditErr)
		}
	}()
	if err := s.audit.Record(runCtx, ports.AuditEntry{Actor: in.Actor, Action: "cspm.run_started", Target: in.EngagementID.String(), Metadata: map[string]string{"targets": fmt.Sprint(len(in.Scopes))}, At: s.clock.Now()}); err != nil {
		return RunResult{}, err
	}
	started = true
	result.Complete = true
	var sourceGaps []cloudposture.CoverageIssue
	if s.expectations != nil {
		expectations, gaps, err := s.expectations.Expectations(runCtx, in.TenantID, in.EngagementID)
		if err != nil {
			return result, fmt.Errorf("cspm load IaC expectations: %w", err)
		}
		in.Expectations = append(in.Expectations, expectations...)
		sourceGaps = append(sourceGaps, gaps...)
		result.CoverageIssues = append(result.CoverageIssues, gaps...)
		result.Complete = result.Complete && len(gaps) == 0
	}
	for _, scope := range in.Scopes {
		scope.Authorize = func(operationCtx context.Context, operation ports.CloudOperation) error {
			return s.authorizeOperation(operationCtx, in, scope, operation)
		}
		connector := s.connectors[scope.Provider]
		var inventory cloudposture.Inventory
		var gaps []cloudposture.CoverageIssue
		if s.executor == nil {
			return result, fmt.Errorf("%w: CSPM sandbox executor is required", shared.ErrValidation)
		}
		inventory, gaps, err = s.executor.EnumerateCloud(runCtx, scope)
		if err != nil {
			return result, fmt.Errorf("cspm enumerate %s: %w", scope.Provider, err)
		}
		inventory.ScopeKey = scope.ScopeKey
		for index := range inventory.Resources {
			if inventory.Resources[index].ScopeKey == "" {
				inventory.Resources[index].ScopeKey = scope.ScopeKey
			}
		}
		for index := range inventory.Relationships {
			if inventory.Relationships[index].ScopeKey == "" {
				inventory.Relationships[index].ScopeKey = scope.ScopeKey
			}
		}
		if err := inventory.Validate(); err != nil {
			return result, err
		}
		matches, err := connector.Evaluate(runCtx, inventory)
		if err != nil {
			return result, err
		}
		drift, driftGaps := cloudposture.DetectDrift(inventory, in.Expectations)
		matches = append(matches, drift...)
		allTargetGaps := append(append([]cloudposture.CoverageIssue(nil), gaps...), driftGaps...)
		allTargetGaps = append(allTargetGaps, sourceGaps...)
		result.CoverageIssues = append(result.CoverageIssues, gaps...)
		result.CoverageIssues = append(result.CoverageIssues, driftGaps...)
		if !inventory.Complete || len(allTargetGaps) != 0 {
			result.Complete = false
		}
		if s.evidence == nil {
			return result, fmt.Errorf("%w: CSPM evidence sealer is required", shared.ErrValidation)
		}
		evidenceID, evidenceHash, err := s.evidence.SealCloudSnapshot(runCtx, in.EngagementID, inventory, allTargetGaps, in.Actor)
		if err != nil {
			return result, fmt.Errorf("cspm seal snapshot evidence: %w", err)
		}
		result.EvidenceRefs = append(result.EvidenceRefs, cloudposture.EvidenceReference{ScopeKey: scope.ScopeKey, ID: evidenceID, Hash: evidenceHash})
		assets, err := s.persistAssets(runCtx, in, inventory)
		if err != nil {
			return result, err
		}
		result.Assets += len(assets)
		standard := buildFindings(in.EngagementID, scope.Provider, scope.ScopeKey, matches, evidenceID, s.clock.Now())
		if err := s.findings.Upsert(runCtx, standard); err != nil {
			return result, err
		}
		// Reconcile observations BEFORE attribution. A cloud asset carries a scope_key, and the
		// asset repository deliberately hides such an asset until an ACTIVE cspm_observations row
		// vouches for it (no default-to-clean inventory). Attribution validates its asset through
		// that same tenant-scoped listing, so attributing first made every run with at least one
		// asset fail with "asset <id>: not found" - after real provider enumeration had already
		// succeeded - then retry twice and dead-letter. Reconciliation depends only on findings and
		// edges that are already persisted above, so it is safe to run first.
		if s.observations != nil {
			assetIDs := make([]shared.ID, 0, len(assets))
			for _, cloudAsset := range assets {
				assetIDs = append(assetIDs, cloudAsset.ID)
			}
			findingIDs := make([]shared.ID, 0, len(standard))
			for _, cloudFinding := range standard {
				findingIDs = append(findingIDs, cloudFinding.ID)
			}
			edgeIDs := make([]string, 0, len(inventory.Relationships))
			for _, relationship := range inventory.Relationships {
				from, fromOK := assets[relationship.FromID]
				to, toOK := assets[relationship.ToID]
				if fromOK && toOK {
					edgeIDs = append(edgeIDs, cloudEdgeID(from.ID, to.ID, relationship.Kind))
				}
			}
			if err := s.observations.ReconcileCloudObservations(runCtx, in.TenantID, in.EngagementID, producerID(scope.ScopeKey).String(), evidenceID, assetIDs, findingIDs, edgeIDs, inventory.Complete && len(allTargetGaps) == 0); err != nil {
				return result, err
			}
		}
		if s.attributor != nil {
			for resourceID, cloudAsset := range assets {
				producer := shared.ID("cspm:" + scopeDigest(scope.ScopeKey) + ":" + scopeDigest(resourceID))
				var targets []attackpath.FindingTarget
				for index, match := range matches {
					if match.ResourceID == resourceID {
						targets = append(targets, attackpath.FindingTarget{ID: standard[index].ID, Kind: attackpath.TargetCanonical})
					}
				}
				if err := s.attributor.RecordTargets(runCtx, in.EngagementID, cloudAsset.ID, producer, evidenceIDOrProducer(evidenceID, producer), asset.EdgeObserved, targets); err != nil {
					return result, err
				}
			}
		}
		result.Findings += len(standard)
	}
	deduplicateGaps(&result.CoverageIssues)
	sort.Slice(result.EvidenceRefs, func(i, j int) bool { return result.EvidenceRefs[i].ScopeKey < result.EvidenceRefs[j].ScopeKey })
	for _, gap := range result.CoverageIssues {
		if err := s.audit.Record(runCtx, ports.AuditEntry{Actor: in.Actor, Action: "cspm.coverage_gap", Target: gap.Scope, Metadata: map[string]string{"provider": string(gap.Provider), "category": gap.Category, "code": gap.Code}, At: s.clock.Now()}); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (s *Service) persistAssets(ctx context.Context, in RunInput, inventory cloudposture.Inventory) (map[string]*asset.Asset, error) {
	persisted := make(map[string]*asset.Asset, len(inventory.Resources))
	for _, resource := range inventory.Resources {
		attributes := map[string]string{"provider": string(resource.Provider), "scope_key": inventory.ScopeKey, "account_id": resource.AccountID, "region": resource.Region, "resource_type": resource.ResourceType, "public": string(resource.Public), "encrypted": string(resource.Encrypted)}
		cloudAsset, err := s.assets.UpsertCloudAsset(ctx, in.Actor, ports.CloudAssetInput{TenantID: in.TenantID, Kind: resource.Kind, Key: "cloud:" + string(resource.Provider) + ":" + scopeDigest(inventory.ScopeKey) + ":" + resource.ID, Name: resource.Name, Attributes: attributes})
		if err != nil {
			return nil, fmt.Errorf("cspm persist asset %s: %w", resource.ID, err)
		}
		persisted[resource.ID] = cloudAsset
	}
	for _, relationship := range inventory.Relationships {
		from, fromOK := persisted[relationship.FromID]
		to, toOK := persisted[relationship.ToID]
		if !fromOK || !toOK {
			continue
		}
		if err := s.assets.UpsertCloudEdge(ctx, in.Actor, ports.CloudEdgeInput{TenantID: in.TenantID, From: from.ID, To: to.ID, Kind: relationship.Kind, Provenance: producerID(inventory.ScopeKey), Confidence: asset.EdgeObserved}); err != nil {
			return nil, err
		}
	}
	return persisted, nil
}

func cloudEdgeID(from, to shared.ID, kind asset.EdgeKind) string {
	return from.String() + "|" + to.String() + "|" + string(kind)
}

func scopeDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func producerID(scopeKey string) shared.ID { return shared.ID("cspm:" + scopeDigest(scopeKey)) }

func evidenceIDOrProducer(evidenceID, producer shared.ID) shared.ID {
	if !evidenceID.IsZero() {
		return evidenceID
	}
	return producer
}

func buildFindings(engagementID shared.ID, provider cloudposture.Provider, scopeKey string, matches []cloudposture.PostureFinding, evidenceID shared.ID, now time.Time) []finding.Finding {
	out := make([]finding.Finding, 0, len(matches))
	for _, match := range matches {
		control := match.Control
		if control == "" {
			control = match.RuleKey
		}
		dedup := "cspm:" + string(provider) + ":" + scopeDigest(scopeKey) + ":" + match.RuleKey + ":" + match.ResourceID + ":" + control
		sum := sha256.Sum256([]byte(engagementID.String() + "|" + dedup))
		priority := 4
		if shared.SeverityRank(match.Severity) >= shared.SeverityRank(shared.SeverityHigh) {
			priority = 2
		} else if match.Severity == shared.SeverityMedium {
			priority = 3
		}
		out = append(out, finding.Finding{ID: shared.ID(hex.EncodeToString(sum[:16])), EngagementID: engagementID, Title: match.Title, Description: match.Description, Severity: match.Severity, Status: finding.StatusOpen, Kind: finding.KindCloudPosture, RuleKey: match.RuleKey, Sources: []string{"synapse-cspm-" + string(provider), "evidence:" + evidenceID.String()}, Confidence: "high", Class: match.Class, Scope: "production", Priority: priority, DedupKey: dedup, EvidenceScore: finding.EvidenceThreshold, ProposedBy: "cspm", Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}})
	}
	return out
}

func deduplicateGaps(gaps *[]cloudposture.CoverageIssue) {
	sort.Slice(*gaps, func(i, j int) bool {
		a, b := (*gaps)[i], (*gaps)[j]
		return string(a.Provider)+a.Scope+a.Category+a.Code < string(b.Provider)+b.Scope+b.Category+b.Code
	})
	out := (*gaps)[:0]
	for _, gap := range *gaps {
		if len(out) == 0 || out[len(out)-1] != gap {
			out = append(out, gap)
		}
	}
	*gaps = out
}

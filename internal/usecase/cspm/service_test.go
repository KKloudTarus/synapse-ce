package cspm_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/cspm"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type connectorStub struct {
	inventory cloudposture.Inventory
	gaps      []cloudposture.CoverageIssue
}

func (c connectorStub) Enumerate(context.Context, ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	return c.inventory, c.gaps, nil
}
func (c connectorStub) Evaluate(_ context.Context, inv cloudposture.Inventory) ([]cloudposture.PostureFinding, error) {
	return cloudposture.Evaluate(inv)
}

type executorStub struct {
	connector ports.CloudConnector
	observe   func(ports.CloudScope)
}

type operationExecutorStub struct{ operation ports.CloudOperation }

func (s operationExecutorStub) EnumerateCloud(ctx context.Context, scope ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	if err := scope.Authorize(ctx, s.operation); err != nil {
		return cloudposture.Inventory{}, nil, err
	}
	return cloudposture.Inventory{Provider: scope.Provider, ScopeKey: scope.ScopeKey, Complete: true}, nil, nil
}

func (s executorStub) EnumerateCloud(ctx context.Context, scope ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	if s.observe != nil {
		s.observe(scope)
	}
	return s.connector.Enumerate(ctx, scope)
}

type clockStub struct{ now time.Time }

func (c clockStub) Now() time.Time { return c.now }

type idsStub struct{ n int }

func (i *idsStub) NewID() shared.ID { i.n++; return shared.ID("id-" + string(rune('0'+i.n))) }

type auditStub struct{ entries []ports.AuditEntry }
type attributorStub struct{ assets map[shared.ID][]shared.ID }

func (a *attributorStub) ValidateAsset(context.Context, shared.ID, shared.ID) error { return nil }
func (a *attributorStub) InheritedAssetID(context.Context, shared.ID, []shared.ID) (shared.ID, error) {
	return "", nil
}
func (a *attributorStub) Record(_ context.Context, _ shared.ID, assetID, _, _ shared.ID, _ asset.EdgeConfidence, findingIDs []shared.ID) error {
	a.assets[assetID] = append(a.assets[assetID], findingIDs...)
	return nil
}
func (a *attributorStub) RecordTargets(_ context.Context, _ shared.ID, assetID, _, _ shared.ID, _ asset.EdgeConfidence, targets []attackpath.FindingTarget) error {
	for _, target := range targets {
		a.assets[assetID] = append(a.assets[assetID], target.ID)
	}
	return nil
}

func (a *auditStub) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type evidenceStub struct{}

func (evidenceStub) SealCloudSnapshot(context.Context, shared.ID, cloudposture.Inventory, []cloudposture.CoverageIssue, string) (shared.ID, string, error) {
	return "evidence", "hash", nil
}

func TestRunPersistsAssetsFindingsAndCoverageHonesty(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1, 0)
	audit := &auditStub{}
	store := memory.NewAssetStore()
	assets, err := assetuc.NewService(store, audit, clockStub{now}, &idsStub{})
	if err != nil {
		t.Fatal(err)
	}
	findings := memory.NewFindingRepository()
	engagements := memory.NewEngagementRepository()
	eng, _ := engagement.New("eng", "tenant", "cloud", "client", now)
	eng.Status = engagement.StatusActive
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetCloudAccount, Value: "organization/o-1"}}}
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	inv := cloudposture.Inventory{Provider: cloudposture.ProviderAWS, Complete: false, Resources: []cloudposture.Resource{
		{Provider: cloudposture.ProviderAWS, ID: "account", Name: "prod", Kind: asset.KindCloudAccount},
		{Provider: cloudposture.ProviderAWS, AccountID: "account", ID: "bucket", Name: "logs", Kind: asset.KindStorage, Public: cloudposture.StateEnabled, Encrypted: cloudposture.StateDisabled},
	}, Relationships: []cloudposture.Relationship{{FromID: "bucket", ToID: "account", Kind: asset.EdgeDependsOn}}}
	svc, err := cspm.NewService(map[cloudposture.Provider]ports.CloudConnector{cloudposture.ProviderAWS: connectorStub{inventory: inv, gaps: []cloudposture.CoverageIssue{{Provider: cloudposture.ProviderAWS, Scope: "child", Category: "compute", Code: "unreachable"}}}}, assets, findings, engagements, audit, clockStub{now})
	if err != nil {
		t.Fatal(err)
	}
	attributor := &attributorStub{assets: map[shared.ID][]shared.ID{}}
	svc.SetAttributor(attributor)
	svc.SetEvidenceSealer(evidenceStub{})
	svc.SetSandboxExecutor(executorStub{connector: connectorStub{inventory: inv, gaps: []cloudposture.CoverageIssue{{Provider: cloudposture.ProviderAWS, Scope: "child", Category: "compute", Code: "unreachable"}}}})
	result, err := svc.Run(ctx, cspm.RunInput{TenantID: "tenant", EngagementID: "eng", Actor: "operator", Scopes: []ports.CloudScope{{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "organization/o-1", CredentialRef: "aws-prod"}}, Expectations: []cloudposture.Expectation{{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-1", ResourceID: "bucket", Control: "encrypted", State: cloudposture.StateEnabled, Source: "main.tf:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.Assets != 2 || result.Findings != 3 || len(result.CoverageIssues) != 1 {
		t.Fatalf("result = %#v", result)
	}
	gotAssets, _ := store.ListAssets(ctx, "tenant")
	if len(gotAssets) != 2 {
		t.Fatalf("assets = %d", len(gotAssets))
	}
	gotFindings, _ := findings.ListByEngagement(ctx, "eng")
	if len(gotFindings) != 0 {
		t.Fatalf("unobserved cloud findings visible = %#v", gotFindings)
	}
	var attributed int
	for _, ids := range attributor.assets {
		attributed += len(ids)
	}
	if attributed != 3 {
		t.Fatalf("attributed findings = %d", attributed)
	}
	for _, f := range gotFindings {
		if string(f.Kind) == "" || f.RuleKey == "" {
			t.Fatalf("finding not governed: %#v", f)
		}
	}
	if len(audit.entries) < 2 || audit.entries[len(audit.entries)-2].Action != "cspm.coverage_gap" || audit.entries[len(audit.entries)-1].Action != "cspm.run_partial" {
		t.Fatalf("audit = %#v", audit.entries)
	}

	_, err = svc.Run(ctx, cspm.RunInput{TenantID: "tenant", EngagementID: "eng", Actor: "operator", Scopes: []ports.CloudScope{{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "organization/o-2", CredentialRef: "aws-prod"}}})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("out-of-scope run error = %v", err)
	}
}

func TestBuildFindingsSeparatesDriftControlsAndScopes(t *testing.T) {
	now := time.Unix(1, 0)
	a, _ := cloudposture.DetectDrift(cloudposture.Inventory{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-a", Resources: []cloudposture.Resource{{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-a", ID: "bucket", Public: cloudposture.StateDisabled, Encrypted: cloudposture.StateDisabled}}}, []cloudposture.Expectation{
		{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-a", ResourceID: "bucket", Control: "public", State: cloudposture.StateEnabled},
		{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-a", ResourceID: "bucket", Control: "encrypted", State: cloudposture.StateEnabled},
	})
	if len(a) != 2 || a[0].Control == a[1].Control {
		t.Fatalf("drift controls collided: %#v at %v", a, now)
	}
}

func TestRunPrevalidatesEveryScopeBeforeEnumeration(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1, 0)
	audit := &auditStub{}
	store := memory.NewAssetStore()
	assets, _ := assetuc.NewService(store, audit, clockStub{now}, &idsStub{})
	findings := memory.NewFindingRepository()
	engagements := memory.NewEngagementRepository()
	eng, _ := engagement.New("eng", "tenant", "cloud", "client", now)
	eng.Status = engagement.StatusActive
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetCloudAccount, Value: "organization/o-1"}}}
	_ = engagements.Create(ctx, eng)
	svc, _ := cspm.NewService(map[cloudposture.Provider]ports.CloudConnector{cloudposture.ProviderAWS: connectorStub{}}, assets, findings, engagements, audit, clockStub{now})
	_, err := svc.Run(ctx, cspm.RunInput{TenantID: "tenant", EngagementID: "eng", Actor: "operator", Scopes: []ports.CloudScope{
		{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "organization/o-1", CredentialRef: "aws-prod"},
		{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "organization/o-2", CredentialRef: "aws-prod"},
	}})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("error = %v", err)
	}
	gotAssets, _ := store.ListAssets(ctx, "tenant")
	if len(gotAssets) != 0 {
		t.Fatalf("prevalidation persisted %d assets", len(gotAssets))
	}
	if len(audit.entries) != 0 {
		t.Fatalf("prevalidation audited before rejecting request: %#v", audit.entries)
	}
}

func TestSubmitIgnoresClientApprovedTarget(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	now := time.Unix(1, 0)
	audit := &auditStub{}
	assetStore := memory.NewAssetStore()
	assets, _ := assetuc.NewService(assetStore, audit, clockStub{now}, &idsStub{})
	findings := memory.NewFindingRepository()
	engagements := memory.NewEngagementRepository()
	eng, _ := engagement.New("eng", "tenant", "cloud", "client", now)
	eng.Status = engagement.StatusActive
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetCloudAccount, Value: "organization/o-allowed"}}}
	_ = engagements.Create(ctx, eng)
	svc, _ := cspm.NewService(map[cloudposture.Provider]ports.CloudConnector{cloudposture.ProviderAWS: connectorStub{}}, assets, findings, engagements, audit, clockStub{now})
	runs, ids := memory.NewCloudRunStore(), &idsStub{}
	queue := memory.NewJobQueue(ids, func() time.Time { return now })
	_ = svc.SetDurableExecution(runs, queue, ids)
	_, err := svc.Submit(ctx, cspm.RunInput{TenantID: "tenant", EngagementID: "eng", Actor: "operator", Scopes: []ports.CloudScope{{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "organization/o-denied", CredentialRef: "aws", ApprovedTarget: "organization/o-allowed"}}})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("error = %v", err)
	}
}

func TestDurableSubmitAndRunJob(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	now := time.Unix(1, 0)
	audit := &auditStub{}
	assetStore := memory.NewAssetStore()
	assets, _ := assetuc.NewService(assetStore, audit, clockStub{now}, &idsStub{})
	findings := memory.NewFindingRepository()
	engagements := memory.NewEngagementRepository()
	eng, _ := engagement.New("eng", "tenant", "cloud", "client", now)
	eng.Status = engagement.StatusActive
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetCloudAccount, Value: "organization/o-1"}}}
	_ = engagements.Create(ctx, eng)
	inventory := cloudposture.Inventory{Provider: cloudposture.ProviderAWS, Complete: true, Resources: []cloudposture.Resource{{Provider: cloudposture.ProviderAWS, ID: "account", Kind: asset.KindCloudAccount}}}
	svc, _ := cspm.NewService(map[cloudposture.Provider]ports.CloudConnector{cloudposture.ProviderAWS: connectorStub{inventory: inventory}}, assets, findings, engagements, audit, clockStub{now})
	svc.SetEvidenceSealer(evidenceStub{})
	var observedScope ports.CloudScope
	svc.SetSandboxExecutor(executorStub{
		connector: connectorStub{inventory: inventory},
		observe:   func(scope ports.CloudScope) { observedScope = scope },
	})
	runs := memory.NewCloudRunStore()
	ids := &idsStub{}
	queue := memory.NewJobQueue(ids, func() time.Time { return now })
	if err := svc.SetDurableExecution(runs, queue, ids); err != nil {
		t.Fatal(err)
	}
	svc.SetRunLock(memory.NewRunLock())
	run, err := svc.Submit(ctx, cspm.RunInput{TenantID: "tenant", EngagementID: "eng", Actor: "operator", Scopes: []ports.CloudScope{{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "organization/o-1", CredentialRef: "aws", EgressExecutionKind: "caller-controlled", EgressExecutionID: "caller-controlled"}}})
	if err != nil || run.Status != cloudposture.RunQueued {
		t.Fatalf("run=%#v err=%v", run, err)
	}
	job, err := queue.Claim(ctx, time.Minute, cspm.JobKind)
	if err != nil || job == nil {
		t.Fatalf("job=%#v err=%v", job, err)
	}
	if err := svc.RunJob(ctx, job.Payload); err != nil {
		t.Fatal(err)
	}
	if observedScope.EgressExecutionKind != "cspm" || observedScope.EgressExecutionID != run.ID.String() {
		t.Fatalf("execution identity = %q/%q, want cspm/%s", observedScope.EgressExecutionKind, observedScope.EgressExecutionID, run.ID.String())
	}
	finished, err := svc.GetRun(ctx, "tenant", run.ID)
	if err != nil || finished.Status != cloudposture.RunSucceeded || finished.FinishedAt == nil {
		t.Fatalf("finished=%#v err=%v", finished, err)
	}
	payload := string(job.Payload)
	if strings.Contains(payload, "secret") || strings.Contains(payload, "caller-controlled") || !strings.Contains(payload, "credential_ref") {
		t.Fatalf("unsafe CSPM job payload: %s", payload)
	}
}

func TestRunDeniesCloudOperationOutsideReadOnlyAllowlist(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1, 0)
	audit := &auditStub{}
	assetStore := memory.NewAssetStore()
	assets, _ := assetuc.NewService(assetStore, audit, clockStub{now}, &idsStub{})
	engagements := memory.NewEngagementRepository()
	eng, _ := engagement.New("eng", "tenant", "cloud", "client", now)
	eng.Status = engagement.StatusActive
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetCloudAccount, Value: "organization/o-1"}}}
	_ = engagements.Create(ctx, eng)
	svc, _ := cspm.NewService(map[cloudposture.Provider]ports.CloudConnector{cloudposture.ProviderAWS: connectorStub{}}, assets, memory.NewFindingRepository(), engagements, audit, clockStub{now})
	svc.SetSandboxExecutor(operationExecutorStub{operation: ports.CloudOperation{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-1", Category: "storage", Name: "DeleteBucket"}})
	_, err := svc.Run(ctx, cspm.RunInput{TenantID: "tenant", EngagementID: "eng", Actor: "operator", Scopes: []ports.CloudScope{{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "organization/o-1", CredentialRef: "aws"}}})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("error = %v", err)
	}
	var denied bool
	for _, entry := range audit.entries {
		if entry.Action == "cspm.operation.denied" && entry.Metadata["reason"] == "operation_not_allowlisted" {
			denied = true
		}
	}
	if !denied {
		t.Fatalf("audit = %#v", audit.entries)
	}
}

// gatedAttributor models the REAL attribution boundary. A cloud asset carries a scope_key, and the
// asset repository hides such an asset until an ACTIVE cspm_observations row vouches for it, so
// ValidateAsset only ever sees assets that reconciliation has already published. attributorStub
// accepts every asset unconditionally, which is precisely why unit tests missed this.
type gatedAttributor struct {
	published  map[shared.ID]bool
	attributed map[shared.ID][]shared.ID
}

func (a *gatedAttributor) ValidateAsset(_ context.Context, _ shared.ID, assetID shared.ID) error {
	if !a.published[assetID] {
		return fmt.Errorf("asset %s: %w", assetID, shared.ErrNotFound)
	}
	return nil
}

func (a *gatedAttributor) InheritedAssetID(context.Context, shared.ID, []shared.ID) (shared.ID, error) {
	return "", nil
}

func (a *gatedAttributor) Record(ctx context.Context, engagementID shared.ID, assetID, producer, provenance shared.ID, confidence asset.EdgeConfidence, findingIDs []shared.ID) error {
	targets := make([]attackpath.FindingTarget, 0, len(findingIDs))
	for _, id := range findingIDs {
		targets = append(targets, attackpath.FindingTarget{ID: id, Kind: attackpath.TargetCanonical})
	}
	return a.RecordTargets(ctx, engagementID, assetID, producer, provenance, confidence, targets)
}

func (a *gatedAttributor) RecordTargets(ctx context.Context, engagementID shared.ID, assetID, _, _ shared.ID, _ asset.EdgeConfidence, targets []attackpath.FindingTarget) error {
	if err := a.ValidateAsset(ctx, engagementID, assetID); err != nil {
		return err
	}
	for _, target := range targets {
		a.attributed[assetID] = append(a.attributed[assetID], target.ID)
	}
	return nil
}

// publishingObservationStore is the other half: reconciliation is what makes a cloud asset visible.
type publishingObservationStore struct{ attributor *gatedAttributor }

func (s publishingObservationStore) ReconcileCloudObservations(_ context.Context, _, _ shared.ID, _ string, _ shared.ID, assetIDs, _ []shared.ID, _ []string, _ bool) error {
	for _, id := range assetIDs {
		s.attributor.published[id] = true
	}
	return nil
}

// TestRunReconcilesObservationsBeforeAttributing pins the ordering between reconciliation and
// attribution. Attributing FIRST validated each asset against a listing that still hid it, so every
// CSPM run carrying at least one asset failed with "asset <id>: not found" - after real provider
// enumeration had already succeeded - then retried twice and dead-lettered with zero assets and
// zero findings recorded.
func TestRunReconcilesObservationsBeforeAttributing(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1, 0)
	audit := &auditStub{}
	store := memory.NewAssetStore()
	assets, err := assetuc.NewService(store, audit, clockStub{now}, &idsStub{})
	if err != nil {
		t.Fatal(err)
	}
	engagements := memory.NewEngagementRepository()
	eng, _ := engagement.New("eng", "tenant", "cloud", "client", now)
	eng.Status = engagement.StatusActive
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetCloudAccount, Value: "organization/o-1"}}}
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	inv := cloudposture.Inventory{Provider: cloudposture.ProviderAWS, Complete: true, Resources: []cloudposture.Resource{
		{Provider: cloudposture.ProviderAWS, ID: "account", Name: "prod", Kind: asset.KindCloudAccount},
		{Provider: cloudposture.ProviderAWS, AccountID: "account", ID: "bucket", Name: "logs", Kind: asset.KindStorage, Public: cloudposture.StateEnabled, Encrypted: cloudposture.StateDisabled},
	}}
	connector := connectorStub{inventory: inv}
	svc, err := cspm.NewService(map[cloudposture.Provider]ports.CloudConnector{cloudposture.ProviderAWS: connector}, assets, memory.NewFindingRepository(), engagements, audit, clockStub{now})
	if err != nil {
		t.Fatal(err)
	}
	attributor := &gatedAttributor{published: map[shared.ID]bool{}, attributed: map[shared.ID][]shared.ID{}}
	svc.SetAttributor(attributor)
	svc.SetObservationStore(publishingObservationStore{attributor: attributor})
	svc.SetEvidenceSealer(evidenceStub{})
	svc.SetSandboxExecutor(executorStub{connector: connector})
	result, err := svc.Run(ctx, cspm.RunInput{TenantID: "tenant", EngagementID: "eng", Actor: "operator", Scopes: []ports.CloudScope{{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "organization/o-1", CredentialRef: "aws-prod"}}})
	if err != nil {
		t.Fatalf("run failed: %v (attribution ran before reconciliation published the assets)", err)
	}
	if result.Assets != 2 {
		t.Fatalf("assets = %d, want 2", result.Assets)
	}
	if len(attributor.attributed) == 0 {
		t.Fatal("no findings were attributed to any asset")
	}
}

package dastworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastconfig"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type scanTestApproval struct{ ports.ApprovalStore }

func (s scanTestApproval) ConsumeForDASTRun(ctx context.Context, actionID, _ shared.ID) error {
	if err := s.Consume(ctx, actionID); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			return fmt.Errorf("%w: consumed", shared.ErrForbidden)
		}
		return err
	}
	return nil
}

// This test double only exercises the workflow callbacks; it is not a durable authority.
type scanTestOwner struct{}

func (scanTestOwner) StartDASTScan(context.Context, ports.DASTScanExecution, ports.DASTScanJob) (bool, error) {
	return false, shared.ErrForbidden
}
func (scanTestOwner) FinishDASTScan(context.Context, ports.DASTScanExecution, dastrun.Run) (bool, error) {
	return false, shared.ErrForbidden
}
func (scanTestOwner) InterruptDASTScan(context.Context, ports.DASTScanExecution, time.Time) (bool, error) {
	return false, shared.ErrForbidden
}
func (scanTestOwner) FailDeadLetteredDASTScan(context.Context, ports.QueuedJob, string, time.Time) (bool, error) {
	return false, shared.ErrForbidden
}
func (scanTestOwner) WithDASTScanOwner(ctx context.Context, _ ports.DASTScanExecution, fn func(context.Context) error) error {
	return fn(ctx)
}

func workflowForScanTest(t *testing.T) (*Service, *memory.ApprovalStore) {
	t.Helper()
	wf, store := workflowForTest(t, &fakeRunner{}, &fakeApplier{})
	if err := wf.SetScanPolicy(filepath.Join(t.TempDir(), "synapse-dast-helper"), strings.Repeat("a", 64), dastconfig.DefaultScanCeilings()); err != nil {
		t.Fatal(err)
	}
	if err := wf.SetScanOwnerStore(scanTestOwner{}); err != nil {
		t.Fatal(err)
	}
	wf.store = scanTestApproval{store}
	return wf, store
}

func scanTestContext() context.Context {
	return shared.WithTenant(context.Background(), "tenant")
}

func runScanForTest(t *testing.T, wf *Service, ctx context.Context, actor string, engagementID, actionID shared.ID, config dastconfig.ScanConfig) (ScanResult, error) {
	t.Helper()
	ctx = shared.WithTenant(ctx, "tenant")
	_, canonical, digest, err := dastconfig.Canonical(config, wf.ceilings)
	if err != nil {
		return ScanResult{}, err
	}
	run, err := dastrun.NewScanRun("scan-test-run", "tenant", engagementID, actionID, actor, time.Unix(1_700_100_000, 0))
	if err != nil {
		return ScanResult{}, err
	}
	if err := run.Start(); err != nil {
		return ScanResult{}, err
	}
	job := ports.DASTScanJob{TenantID: run.TenantID, RunID: run.ID, Config: canonical, ConfigSHA256: digest, HelperPath: wf.helperBin, HelperSHA256: wf.helperSHA256}
	execution := ports.DASTScanExecution{TenantID: run.TenantID, RunID: run.ID, JobID: "job", Fence: 1}
	evidenceID, _, err := wf.ExecuteScan(ctx, execution, job, run)
	if err != nil {
		return ScanResult{}, err
	}
	ev, err := wf.evidence.Get(ctx, engagementID, evidenceID)
	if err != nil {
		return ScanResult{}, err
	}
	var envelope sealedScanResult
	if err := json.Unmarshal(ev.Content, &envelope); err != nil {
		return ScanResult{}, err
	}
	return envelope.Result, nil
}

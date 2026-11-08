package dastworkflow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastconfig"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestReadScanResultDoesNotInventPendingOrFailedResults(t *testing.T) {
	wf, _ := workflowForScanTest(t)
	run, err := dastrun.NewScanRun("run", "tenant", "eng-1", "action", "alice", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant")
	result, err := wf.ReadScanResult(ctx, run)
	if err != nil || result != nil {
		t.Fatalf("queued: result=%+v err=%v", result, err)
	}
	run.Fail("failed", time.Unix(2, 0))
	result, err = wf.ReadScanResult(ctx, run)
	if err != nil || result != nil {
		t.Fatalf("failed: result=%+v err=%v", result, err)
	}
	if _, err := wf.ReadScanResult(shared.WithTenant(ctx, "other"), run); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
}

func TestReadScanResultRejectsEvidenceFromDifferentRun(t *testing.T) {
	wf, approvals := workflowForScanTest(t)
	evaluator := &fakeScanEvaluator{}
	if err := wf.SetScan(&fakeScanSession{}, wf.helperBin, wf.evidence, evaluator, evaluator, &fakeScanJudgments{}, &fakeScanVerifier{}, dastconfig.DefaultScanCeilings()); err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant")
	config := validScanConfig()
	proposal, err := wf.ProposeScan(ctx, "alice", "eng-1", config)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvals.Decide(ctx, agent.ApprovalDecision{ActionID: proposal.Action.ID, State: agent.ApprovalApproved, DecidedBy: "alice", DecidedAt: time.Unix(1_700_100_000, 0)}); err != nil {
		t.Fatal(err)
	}
	_, canonical, digest, err := dastconfig.Canonical(config, dastconfig.DefaultScanCeilings())
	if err != nil {
		t.Fatal(err)
	}
	run, err := dastrun.NewScanRun("run-a", "tenant", "eng-1", proposal.Action.ID, "alice", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	job := ports.DASTScanJob{TenantID: "tenant", RunID: run.ID, Config: canonical, ConfigSHA256: digest, HelperPath: wf.helperBin, HelperSHA256: strings.Repeat("a", 64)}
	owner := ports.DASTScanExecution{TenantID: "tenant", RunID: run.ID, JobID: "job", Fence: 1}
	id, incomplete, err := wf.ExecuteScan(ctx, owner, job, run)
	if err != nil {
		t.Fatal(err)
	}
	if err := run.CompleteScan(id, incomplete, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := wf.ReadScanResult(ctx, run); err != nil {
		t.Fatal(err)
	}
	run.ID = "run-b"
	if _, err := wf.ReadScanResult(ctx, run); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("foreign evidence accepted: %v", err)
	}
}

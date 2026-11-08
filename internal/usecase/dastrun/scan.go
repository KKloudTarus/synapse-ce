package dastrun

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	ddast "github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastconfig"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const ScanJobKind = "dast_scan"

type scanPolicy struct {
	helperPath   string
	helperSHA256 string
	ceilings     dastconfig.ScanCeilings
}

// ScanExecutor performs admission, custody, the real crawl, and fenced result publication.
// Its evidence ID refers to the sealed full scan result, not a verifier verdict.
type ScanExecutor interface {
	ExecuteScan(context.Context, ports.DASTScanExecution, ports.DASTScanJob, ddast.Run) (evidenceID shared.ID, incomplete bool, err error)
}

// ConfigureScan binds the operator policy; the API may pass nil executor and locker.
func (s *Service) ConfigureScan(helperPath, helperSHA256 string, ceilings dastconfig.ScanCeilings, executor ScanExecutor, locker ports.LeaseRunLocker) error {
	if !filepath.IsAbs(helperPath) || len(helperSHA256) != 64 || strings.ToLower(helperSHA256) != helperSHA256 || ceilings.MaxReauth < 0 || ceilings.RatePerSec < 1 || ceilings.Concurrency < 1 || ceilings.Limits.Depth < 1 || ceilings.Limits.Pages < 1 || ceilings.Limits.Requests < 1 || ceilings.Limits.WallClock < 1 {
		return fmt.Errorf("%w: invalid DAST scan policy", shared.ErrValidation)
	}
	if _, err := hex.DecodeString(helperSHA256); err != nil {
		return fmt.Errorf("%w: invalid DAST helper hash", shared.ErrValidation)
	}
	s.scanPolicy = &scanPolicy{helperPath: helperPath, helperSHA256: helperSHA256, ceilings: ceilings}
	s.scanExecutor, s.scanLocker = executor, locker
	return nil
}

// SetScanLocker permits recovery of queued jobs even if scan policy is unavailable.
func (s *Service) SetScanLocker(locker ports.LeaseRunLocker) error {
	if locker == nil {
		return fmt.Errorf("%w: durable DAST scan lock required", shared.ErrValidation)
	}
	s.scanLocker = locker
	return nil
}

func (s *Service) SubmitScan(ctx context.Context, engagementID, actionID shared.ID, actor string, config dastconfig.ScanConfig) (ddast.Run, error) {
	if s.scanPolicy == nil {
		return ddast.Run{}, fmt.Errorf("%w: DAST scan policy unavailable", shared.ErrForbidden)
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return ddast.Run{}, fmt.Errorf("%w: DAST scan tenant required", shared.ErrValidation)
	}
	_, canonical, digest, err := dastconfig.Canonical(config, s.scanPolicy.ceilings)
	if err != nil {
		return ddast.Run{}, err
	}
	run, err := ddast.NewScanRun(s.ids.NewID(), tenant, engagementID, actionID, actor, s.clock.Now())
	if err != nil {
		return ddast.Run{}, err
	}
	job := ports.DASTScanJob{TenantID: tenant, RunID: run.ID, Config: canonical, ConfigSHA256: digest, HelperPath: s.scanPolicy.helperPath, HelperSHA256: s.scanPolicy.helperSHA256}
	payload, err := json.Marshal(job)
	if err != nil {
		return ddast.Run{}, err
	}
	if err := s.enqueuer.EnqueueDASTRun(ctx, run, ScanJobKind, payload); err != nil {
		return ddast.Run{}, fmt.Errorf("enqueue DAST scan: %w", err)
	}
	return run, nil
}

// RunScanJob requires the actual queue claim, not merely the job payload. The
// leased run lock excludes a live previous worker before interrupted recovery.
func (s *Service) RunScanJob(ctx context.Context, job ports.QueuedJob) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() || tenant != job.TenantID || job.Kind != ScanJobKind {
		return fmt.Errorf("%w: DAST scan claim mismatch", shared.ErrValidation)
	}
	if s.scanLocker == nil {
		return fmt.Errorf("%w: durable DAST scan run lock unavailable", shared.ErrForbidden)
	}
	store, ok := s.runs.(ports.DASTScanRunStore)
	if !ok {
		return fmt.Errorf("%w: durable DAST scan store unavailable", shared.ErrForbidden)
	}
	var payload ports.DASTScanJob
	dec := json.NewDecoder(bytes.NewReader(job.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return fmt.Errorf("%w: malformed DAST scan job", shared.ErrValidation)
	}
	canonicalJob, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonicalJob, job.Payload) {
		return fmt.Errorf("%w: noncanonical DAST scan job", shared.ErrValidation)
	}
	if payload.TenantID != tenant || payload.RunID.IsZero() {
		return fmt.Errorf("%w: DAST scan job tenant mismatch", shared.ErrForbidden)
	}
	execution := ports.DASTScanExecution{TenantID: tenant, RunID: payload.RunID, JobID: job.ID, Fence: job.Fence}
	if _, err := execution.ExecutionID(); err != nil {
		return err
	}
	lockKey := fmt.Sprintf("dast-scan:%d:%s%s", len(tenant.String()), tenant.String(), payload.RunID.String())
	leaseCtx, release, locked, err := s.scanLocker.TryLockLeased(ctx, lockKey)
	if err != nil {
		return err
	}
	if !locked {
		return ports.ErrRetryable
	}
	defer release()
	run, err := s.runs.GetDASTRun(leaseCtx, tenant, payload.RunID)
	if err != nil {
		return err
	}
	if run.Kind != ddast.KindAuthenticatedScan {
		return fmt.Errorf("%w: wrong DAST run kind", shared.ErrForbidden)
	}
	if run.Status.Terminal() {
		return nil
	}
	if run.Status == ddast.RunRunning {
		_, err = store.InterruptDASTScan(leaseCtx, execution, s.clock.Now())
		return err
	}
	won, err := store.StartDASTScan(leaseCtx, execution, payload)
	if err != nil || !won {
		return err
	}
	if err := run.Start(); err != nil {
		return err
	}
	if s.scanPolicy == nil {
		run.Fail("config_unavailable", s.clock.Now())
		_, err = store.FinishDASTScan(leaseCtx, execution, run)
		return err
	}
	_, canonical, digest, configErr := dastconfig.Decode(payload.Config, s.scanPolicy.ceilings)
	if payload.HelperPath != s.scanPolicy.helperPath || payload.HelperSHA256 != s.scanPolicy.helperSHA256 || configErr != nil || !bytes.Equal(canonical, payload.Config) || digest != payload.ConfigSHA256 {
		run.Fail("invalid_config", s.clock.Now())
		_, err = store.FinishDASTScan(leaseCtx, execution, run)
		return err
	}
	if s.scanExecutor == nil {
		run.Fail("egress_unavailable", s.clock.Now())
		_, err = store.FinishDASTScan(leaseCtx, execution, run)
		return err
	}
	evidenceID, incomplete, execErr := s.scanExecutor.ExecuteScan(leaseCtx, execution, payload, run)
	if leaseCtx.Err() != nil {
		return leaseCtx.Err()
	}
	if errors.Is(execErr, context.Canceled) || errors.Is(execErr, context.DeadlineExceeded) {
		return execErr
	}
	if execErr != nil {
		run.Fail(errorCode(execErr), s.clock.Now())
	} else if err := run.CompleteScan(evidenceID, incomplete, s.clock.Now()); err != nil {
		run.Fail("invalid_result", s.clock.Now())
	}
	_, err = store.FinishDASTScan(leaseCtx, execution, run)
	return err
}

// FailStrandedScanJob finalizes only the run bound to a fenced dead-lettered job.
// The store resolves that run from persisted queue identity, never job.Payload.
func (s *Service) FailStrandedScanJob(ctx context.Context, job ports.QueuedJob, cause error) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() || tenant != job.TenantID || job.Kind != ScanJobKind || job.ID == "" || job.Fence < 1 {
		return fmt.Errorf("%w: invalid dead-lettered DAST scan claim", shared.ErrValidation)
	}
	store, ok := s.runs.(ports.DASTScanRunStore)
	if !ok {
		return fmt.Errorf("%w: durable DAST scan store unavailable", shared.ErrForbidden)
	}
	_, err := store.FailDeadLetteredDASTScan(ctx, job, "queue_failed", s.clock.Now())
	return err
}

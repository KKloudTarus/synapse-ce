package dastworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type sealedScanResult struct {
	TenantID     shared.ID  `json:"tenant_id"`
	RunID        shared.ID  `json:"run_id"`
	EngagementID shared.ID  `json:"engagement_id"`
	ActionID     shared.ID  `json:"action_id"`
	Result       ScanResult `json:"result"`
}

// ReadScanResult returns only the actual, chain-verified terminal result.
func (s *Service) ReadScanResult(ctx context.Context, run dastrun.Run) (*ScanResult, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant != run.TenantID || run.Kind != dastrun.KindAuthenticatedScan {
		return nil, fmt.Errorf("%w: DAST scan result", shared.ErrNotFound)
	}
	if !run.Status.Terminal() || (run.Status == dastrun.RunFailed && run.EvidenceID.IsZero()) {
		return nil, nil
	}
	if run.EvidenceID.IsZero() {
		return nil, fmt.Errorf("%w: DAST scan result evidence missing", shared.ErrValidation)
	}
	report, err := s.evidence.Verify(ctx, run.EngagementID)
	if err != nil {
		return nil, err
	}
	if !report.Intact {
		return nil, fmt.Errorf("%w: DAST scan evidence chain invalid", shared.ErrForbidden)
	}
	action, decision, err := s.store.Get(ctx, run.ActionID)
	if err != nil {
		return nil, err
	}
	if action.EngagementID != run.EngagementID || action.Tool != ToolAuthenticatedScan || action.Action != ActionAuthenticatedScan || len(action.Argv) != 4 || decision.State != agent.ApprovalConsumed || strings.TrimSpace(decision.DecidedBy) == "" || decision.DecidedBy == "auto" || shared.IsMachineActor(decision.DecidedBy) {
		return nil, fmt.Errorf("%w: DAST scan approval binding invalid", shared.ErrForbidden)
	}
	for _, item := range report.Items {
		if item.ID != run.EvidenceID {
			continue
		}
		if item.EngagementID != run.EngagementID || item.Kind != "dast_scan_result" || item.CreatedBy != decision.DecidedBy || item.Hash == "" {
			return nil, fmt.Errorf("%w: invalid DAST scan result custody", shared.ErrForbidden)
		}
		var envelope sealedScanResult
		dec := json.NewDecoder(bytes.NewReader(item.Content))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&envelope); err != nil {
			return nil, fmt.Errorf("%w: invalid DAST scan result", shared.ErrValidation)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return nil, fmt.Errorf("%w: invalid DAST scan result", shared.ErrValidation)
		}
		if envelope.TenantID != run.TenantID || envelope.RunID != run.ID || envelope.EngagementID != run.EngagementID || envelope.ActionID != run.ActionID {
			return nil, fmt.Errorf("%w: DAST scan result owner mismatch", shared.ErrForbidden)
		}
		result := envelope.Result
		if len(result.Digest) != 64 || action.Argv[2] != "--config-sha256="+result.Digest || (result.Incomplete && strings.TrimSpace(result.Reason) == "") || (run.Status == dastrun.RunSucceeded && result.Incomplete) || (run.Status == dastrun.RunIncomplete && !result.Incomplete) || (run.Status == dastrun.RunFailed && !result.Incomplete) {
			return nil, fmt.Errorf("%w: DAST scan result does not match run", shared.ErrForbidden)
		}
		return &result, nil
	}
	return nil, fmt.Errorf("%w: DAST scan result evidence", shared.ErrNotFound)
}

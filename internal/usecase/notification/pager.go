package notification

import (
	"context"
	"errors"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func pagerLifecycleWork(work ports.NotificationWork) bool {
	return (work.Channel.Type == domain.ChannelPagerDuty || work.Channel.Type == domain.ChannelJSM) && work.Event.PagerLifecycle.Episode > 0
}

func (s *Service) sendPagerMutation(ctx context.Context, job ports.QueuedJob, attempt shared.ID, work *ports.NotificationWork, cfg ports.NotificationChannelConfig) (ports.NotificationSendResult, bool, error) {
	repo, ok := s.repo.(ports.NotificationPagerRepository)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "pager_gate_unavailable"}, false, nil
	}
	decision, err := repo.AdmitPagerMutation(ctx, job.TenantID, work.Delivery.ID, job.ID, job.Fence, attempt)
	if err != nil {
		return ports.NotificationSendResult{}, false, err
	}
	switch decision.Action {
	case "suppressed":
		return ports.NotificationSendResult{}, true, nil
	case "complete":
		return ports.NotificationSendResult{StatusCode: 200, RemoteRef: decision.RemoteRef}, false, nil
	case "blocked":
		code := decision.Code
		if code == "" {
			code = "pager_outcome_unknown"
		}
		return ports.NotificationSendResult{ErrorCode: code, ProviderRequestRef: decision.ProviderRequestRef}, false, nil
	case "send", "poll":
	default:
		return ports.NotificationSendResult{}, false, errors.New("invalid pager gate decision")
	}
	work.SubjectResolved = subjectResolved(work.Event)
	work.SubjectAnchor = decision.SubjectAnchor
	work.Delivery.ProviderRequestRef = decision.ProviderRequestRef
	result := s.sender.Send(ctx, *work, cfg)
	// Queue cancellation does not erase an accepted provider mutation. Store its
	// receipt with the immutable operation identity before attempting fenced completion.
	receiptCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := repo.RecordPagerReceipt(receiptCtx, job.TenantID, work.Delivery.ID, decision.OperationID, result); err != nil {
		return ports.NotificationSendResult{}, false, err
	}
	return result, false, nil
}

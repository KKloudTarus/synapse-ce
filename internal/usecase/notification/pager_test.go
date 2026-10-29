package notification

import (
	"context"
	"errors"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type pagerGateRepo struct {
	fakeRepo
	decision          ports.PagerMutation
	receipt           ports.NotificationSendResult
	receiptOp         shared.ID
	receiptContextErr error
	receiptErr        error
}

func (r *pagerGateRepo) ReconcilePagerAcknowledgement(context.Context, shared.ID, shared.ID, string, int64) (bool, error) {
	return false, nil
}

func (r *pagerGateRepo) AdmitPagerMutation(context.Context, shared.ID, shared.ID, string, int64, shared.ID) (ports.PagerMutation, error) {
	return r.decision, nil
}
func (r *pagerGateRepo) RecordPagerReceipt(ctx context.Context, tenant, delivery, operation shared.ID, result ports.NotificationSendResult) error {
	r.receipt, r.receiptOp, r.receiptContextErr = result, operation, ctx.Err()
	return r.receiptErr
}

type cancelPagerSender struct {
	cancel context.CancelFunc
	work   ports.NotificationWork
	calls  int
}

func (s *cancelPagerSender) Send(_ context.Context, w ports.NotificationWork, _ ports.NotificationChannelConfig) ports.NotificationSendResult {
	s.work = w
	s.calls++
	if s.cancel != nil {
		s.cancel()
	}
	return ports.NotificationSendResult{StatusCode: 202, ErrorCode: "jsm_request_unconfirmed", Retryable: true, ProviderRequestRef: "accepted-request"}
}

func TestPagerReceiptSurvivesCallerCancellationAndUsesOriginalOperation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repo := &pagerGateRepo{decision: ports.PagerMutation{Action: "poll", OperationID: "original-operation", ProviderRequestRef: "accepted-request", SubjectAnchor: "episode-alias"}}
	sender := &cancelPagerSender{cancel: cancel}
	svc := &Service{repo: repo, sender: sender}
	work := ports.NotificationWork{Delivery: domain.Delivery{ID: "delivery"}, Event: domain.Event{PagerLifecycle: domain.PagerLifecycle{Episode: 1, Revision: 2, Terminal: true}}}
	_, suppressed, err := svc.sendPagerMutation(ctx, ports.QueuedJob{TenantID: "tenant", ID: "job", Fence: 2}, "new-attempt", &work, ports.JSMChannelConfig{})
	if err != nil || suppressed || repo.receiptContextErr != nil || repo.receiptOp != "original-operation" || repo.receipt.ProviderRequestRef != "accepted-request" {
		t.Fatalf("receipt lost: %v %+v", err, repo)
	}
	if sender.work.Delivery.ProviderRequestRef != "accepted-request" || !sender.work.SubjectResolved || sender.work.SubjectAnchor != "episode-alias" {
		t.Fatalf("wrong resumed work: %+v", sender.work)
	}
}

func TestPagerGateNeverSendsSuppressedBlockedOrCompletedOperations(t *testing.T) {
	for _, action := range []string{"suppressed", "blocked", "complete"} {
		t.Run(action, func(t *testing.T) {
			repo := &pagerGateRepo{decision: ports.PagerMutation{Action: action, RemoteRef: "accepted-alias"}}
			sender := &cancelPagerSender{}
			svc := &Service{repo: repo, sender: sender}
			result, suppressed, err := svc.sendPagerMutation(context.Background(), ports.QueuedJob{TenantID: "tenant"}, "attempt", &ports.NotificationWork{}, ports.JSMChannelConfig{})
			if err != nil || sender.calls != 0 || !repo.receiptOp.IsZero() || suppressed != (action == "suppressed") {
				t.Fatalf("unexpected write %s: %v calls=%d", action, err, sender.calls)
			}
			if action == "complete" && result.RemoteRef != "accepted-alias" {
				t.Fatal("lost acknowledgement")
			}
			if action == "blocked" && (result.Retryable || result.ErrorCode == "") {
				t.Fatal("ambiguous operation allowed blind retry")
			}
		})
	}
}

func TestPagerReceiptFailureStopsQueueCompletion(t *testing.T) {
	want := errors.New("receipt store unavailable")
	repo := &pagerGateRepo{decision: ports.PagerMutation{Action: "send", OperationID: "operation"}, receiptErr: want}
	svc := &Service{repo: repo, sender: &cancelPagerSender{}}
	_, _, err := svc.sendPagerMutation(context.Background(), ports.QueuedJob{TenantID: "tenant"}, "attempt", &ports.NotificationWork{}, ports.JSMChannelConfig{})
	if !errors.Is(err, want) {
		t.Fatalf("receipt error lost: %v", err)
	}
}

package notification

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// finishedAttempt identifies the attempt HandleJob is finishing.
type finishedAttempt struct {
	job        ports.QueuedJob
	work       ports.NotificationWork
	deliveryID shared.ID
	attemptID  shared.ID
}

// finishAttempt records the attempt result and then its effect on channel health (#1464). With a
// transaction runner (the worker installs one) both commit together, so a crash cannot record a
// failure without counting it, and the pause, its history row, the cancelled queue, the admin
// notice and the audit entry are one unit.
func (s *Service) finishAttempt(ctx context.Context, a finishedAttempt, at time.Time, outcome string, status int, code string, next *time.Time, class domain.AttemptClass) error {
	run := func(ctx context.Context) error {
		if err := s.repo.FinishAttempt(ctx, a.job.TenantID, a.deliveryID, a.job.ID, a.job.Fence, a.attemptID, at, outcome, status, code, next); err != nil {
			return err
		}
		if class == domain.AttemptIgnored {
			return nil
		}
		transition, err := s.repo.RecordChannelOutcome(ctx, a.job.TenantID, ports.NotificationChannelOutcome{
			ChannelID: a.work.Channel.ID, DeliveryID: a.deliveryID, AttemptID: a.attemptID,
			Class: class, Code: code, At: at, Threshold: s.pauseThreshold,
		})
		if err != nil || !transition.Paused {
			return err
		}
		return s.record(ctx, "system", "notification.channel.paused", a.work.Channel.ID.String(), map[string]string{
			"type":         string(a.work.Channel.Type),
			"reason":       transition.Health.PausedReason,
			"failure_code": transition.Health.LastFailureCode,
			"failures":     strconv.Itoa(transition.Health.ConsecutiveFailures),
			"delivery_id":  a.deliveryID.String(),
			"attempt_id":   a.attemptID.String(),
		})
	}
	if s.tx == nil {
		return run(ctx)
	}
	return s.tx.Run(ctx, a.job.TenantID, run)
}

// ResumeInput is the body of POST /notifications/channels/{id}/resume.
type ResumeInput struct {
	Revision int `json:"revision"`
}

func (s *Service) resumeChannel(ctx context.Context, actor string, id shared.ID, in ResumeInput) (domain.Channel, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Channel{}, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return domain.Channel{}, fmt.Errorf("%w: resuming a channel requires an actor", shared.ErrValidation)
	}
	if in.Revision < 1 {
		return domain.Channel{}, fmt.Errorf("%w: positive channel revision is required", shared.ErrValidation)
	}
	previous, err := s.repo.GetChannel(ctx, tenant, id)
	if err != nil {
		return domain.Channel{}, err
	}
	resumed, err := s.repo.ResumeChannel(ctx, tenant, id, in.Revision, actor, s.clock.Now().UTC())
	if err != nil {
		return domain.Channel{}, err
	}
	if err := s.record(ctx, actor, "notification.channel.resumed", id.String(), channelAuditMetadata(resumed, map[string]string{
		"reason":       previous.Health.PausedReason,
		"failure_code": previous.Health.LastFailureCode,
		"failures":     strconv.Itoa(previous.Health.ConsecutiveFailures),
	})); err != nil {
		return domain.Channel{}, err
	}
	return resumed, nil
}

// ResumeChannel clears an automatic pause. It is an administrator action, guarded by the channel
// revision and audited; the next delivery to the channel starts counting from zero.
func (s *Service) ResumeChannel(ctx context.Context, actor string, id shared.ID, in ResumeInput) (domain.Channel, error) {
	return mutation(ctx, s, func(ctx context.Context) (domain.Channel, error) { return s.resumeChannel(ctx, actor, id, in) })
}

// ListChannelHealthEvents returns the channel's pause and resume history, newest first.
func (s *Service) ListChannelHealthEvents(ctx context.Context, id shared.ID) ([]domain.ChannelHealthEvent, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	return s.repo.ListChannelHealthEvents(ctx, tenant, id, 50)
}

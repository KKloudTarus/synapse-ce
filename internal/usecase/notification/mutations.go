package notification

import (
	"context"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SetTransactionRunner makes administration and its audit append atomic.
func (s *Service) SetTransactionRunner(tx ports.TenantTransactionRunner) { s.tx = tx }
func mutation[T any](ctx context.Context, s *Service, fn func(context.Context) (T, error)) (out T, err error) {
	if s.tx == nil {
		return fn(ctx)
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return out, err
	}
	err = s.tx.Run(ctx, tenant, func(ctx context.Context) error { var e error; out, e = fn(ctx); return e })
	return
}
func (s *Service) CreateChannel(ctx context.Context, actor string, in ChannelInput) (domain.Channel, error) {
	in, err := s.prepareDestination(ctx, in)
	if err != nil {
		return domain.Channel{}, err
	}
	return mutation(ctx, s, func(ctx context.Context) (domain.Channel, error) { return s.createChannel(ctx, actor, in) })
}
func (s *Service) UpdateChannel(ctx context.Context, actor string, id shared.ID, in ChannelInput) (domain.Channel, error) {
	// Only an administrator may re-point a channel, so only then is a provider asked first.
	if in.AllowDestinationChange {
		var err error
		if in, err = s.prepareDestination(ctx, in); err != nil {
			return domain.Channel{}, err
		}
	}
	return mutation(ctx, s, func(ctx context.Context) (domain.Channel, error) { return s.updateChannel(ctx, actor, id, in) })
}
func (s *Service) DeleteChannel(ctx context.Context, actor string, id shared.ID, revision int) error {
	_, err := mutation(ctx, s, func(ctx context.Context) (bool, error) { return true, s.deleteChannel(ctx, actor, id, revision) })
	return err
}
func (s *Service) CreateRule(ctx context.Context, actor string, in RuleInput) (domain.Rule, error) {
	return mutation(ctx, s, func(ctx context.Context) (domain.Rule, error) { return s.createRule(ctx, actor, in) })
}
func (s *Service) UpdateRule(ctx context.Context, actor string, id shared.ID, in RuleInput) (domain.Rule, error) {
	return mutation(ctx, s, func(ctx context.Context) (domain.Rule, error) { return s.updateRule(ctx, actor, id, in) })
}
func (s *Service) DeleteRule(ctx context.Context, actor string, id shared.ID, revision int) error {
	_, err := mutation(ctx, s, func(ctx context.Context) (bool, error) { return true, s.deleteRule(ctx, actor, id, revision) })
	return err
}
func (s *Service) TestChannel(ctx context.Context, actor string, id shared.ID) (shared.ID, error) {
	return mutation(ctx, s, func(ctx context.Context) (shared.ID, error) { return s.testChannel(ctx, actor, id) })
}

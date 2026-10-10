package notification

import (
	"fmt"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func channelRawEvent(channel domain.Channel, current bool, in ChannelInput) (bool, error) {
	next := current
	if in.RawEvent != nil {
		next = *in.RawEvent
	}
	if next && !current && !in.AllowClassRaise {
		return false, fmt.Errorf("%w: enabling raw event mode requires administer", shared.ErrForbidden)
	}
	if next && (channel.Type != domain.ChannelWebhook || channel.Class() != domain.DataClassDetail || channel.CustomBody) {
		return false, fmt.Errorf("%w: raw event mode requires a detail webhook without a custom body", shared.ErrValidation)
	}
	return next, nil
}

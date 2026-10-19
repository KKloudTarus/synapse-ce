package ticketing

import (
	"encoding/json"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func ticketGroupFactsDigest(facts []ports.TicketGroupFact) (string, error) {
	if len(facts) == 0 || len(facts) > 100 {
		return "", shared.ErrValidation
	}
	copyFacts := append([]ports.TicketGroupFact(nil), facts...)
	for index, fact := range copyFacts {
		class, allowed := notification.EffectiveDataClass(notification.DataClassDetail, fact.ExternalNotifications)
		if !allowed || class != notification.DataClassDetail {
			return "", shared.ErrForbidden
		}
		if fact.GroupRevision != facts[0].GroupRevision {
			return "", shared.ErrConflict
		}
		copyFacts[index].GroupRevision = 0
	}
	raw, err := json.Marshal(copyFacts)
	if err != nil {
		return "", shared.ErrValidation
	}
	return ticketDigest(raw), nil
}

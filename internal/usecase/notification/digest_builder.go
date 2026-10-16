package notification

import (
	"strconv"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
)

func digestEventBuilder() eventBuilder {
	return eventBuilder{vars: func(e domain.Event, data eventData, _ sourceFacts) map[string]string {
		values := map[string]string{"severity": string(e.Severity), "cadence": data.text("cadence"), "window_start": data.text("window_start"), "window_end": data.text("window_end"), "item_count": "0", "omitted_count": "0"}
		if ids, ok := data["event_ids"].([]any); ok {
			values["item_count"] = strconv.Itoa(len(ids))
		}
		return values
	}}
}

package notificationsender

import (
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// eventText supplies safe built-in content when the preferred title/summary
// fields are missing. It reads only the stored, catalog-filtered template context, never Event.Data,
// so an invalid template cannot revive raw summary data on a signal-class channel.
func eventText(w ports.NotificationWork) (string, string, bool) {
	title := "Synapse: " + string(w.Event.Type)
	summary := "A " + string(w.Event.Type) + " event occurred at " + w.Event.OccurredAt.UTC().Format(time.RFC3339)
	fallback := true
	class, deliver := notification.EffectiveDataClass(w.Channel.Class(), w.Engagement)
	if !deliver {
		return "Synapse notification", "Notification delivery is suppressed", true
	}
	if spec, ok := notification.LookupEvent(w.Event.Type); ok {
		if context, err := notification.DecodeTemplateContext(w.Event.Context); err == nil {
			vars := context.Filter(spec, class).Vars
			if value := strings.TrimSpace(vars["title"]); value != "" {
				title = value
			}
			if value := strings.TrimSpace(vars["summary"]); value != "" {
				summary = value
				fallback = false
			}
		}
	}
	return safeHeader(title), summary, fallback
}

func safeHeader(v string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(limit(v, 180)))
}

func limit(v string, n int) string {
	runes := []rune(v)
	if len(runes) > n {
		return string(runes[:n])
	}
	return v
}

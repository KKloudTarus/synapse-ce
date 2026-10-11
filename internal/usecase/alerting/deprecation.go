package alerting

import "log/slog"

// LegacyWebhookRemovalRelease is the release that removes the deployment-wide legacy incident alert
// webhook (SYNAPSE_ALERT_WEBHOOK_*) in favour of tenant notification rules for incident.created (#1347).
const LegacyWebhookRemovalRelease = "0.4.0"

// LegacyWebhookDeprecation is the operator-facing startup warning. It names the removal release and the
// replacement, and deliberately carries no configured value: the webhook URL may embed a credential.
const LegacyWebhookDeprecation = "SYNAPSE_ALERT_WEBHOOK_URL is deprecated and will be removed in " + LegacyWebhookRemovalRelease +
	"; incident.created notification rules now deliver independently of it, so create a rule under " +
	"Settings > Alerting and then unset SYNAPSE_ALERT_WEBHOOK_*"

// WarnLegacyWebhookDeprecated logs LegacyWebhookDeprecation once at startup when the legacy webhook is
// configured. It takes only whether the URL is set, never the URL itself, so a credential-bearing URL
// cannot reach the log.
func WarnLegacyWebhookDeprecated(log *slog.Logger, configured bool) {
	if log == nil || !configured {
		return
	}
	log.Warn(LegacyWebhookDeprecation, "removal_release", LegacyWebhookRemovalRelease, "replacement", "notification rule for incident.created")
}

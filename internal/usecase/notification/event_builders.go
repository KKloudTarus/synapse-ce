package notification

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// maxIncidentTitleRunes bounds an incident title in the event data, as the capture trigger did.
const maxIncidentTitleRunes = 500

// eventBuilders declares the builder of every catalog event type. Display names (engagement,
// project, finding, team, assignee, agent, asset) and the failed condition count arrive as source
// facts from the poller and pass through to the snapshot as declared variables.
func eventBuilders() map[domain.EventType]eventBuilder {
	return map[domain.EventType]eventBuilder{
		domain.EventVulnerabilityAction: {
			vars: func(e domain.Event, data eventData, _ sourceFacts) map[string]string {
				return map[string]string{"severity": string(e.Severity), "action_type": data.text("action_type")}
			},
		},
		domain.EventScanCompleted: {
			subjectKey: "scan_id",
			data:       scanCompletedData,
			vars: func(_ domain.Event, data eventData, facts sourceFacts) map[string]string {
				target := facts.get("scan_target")
				if target == "" {
					target = facts.get("target")
				}
				values := map[string]string{"scan_kind": data.text("scan_kind"), "target": displayTarget(target)}
				for _, name := range scanSummaryVariableNames {
					values[name] = facts.get(name)
					if values[name] == "" {
						values[name] = data.text(name)
					}
				}
				return values
			},
			lists: func(_ domain.Event, _ eventData, _ sourceFacts, lists map[string][]map[string]string) map[string][]map[string]string {
				return lists
			},
			relevant: scanStillSucceeded,
		},
		domain.EventQualityGateFailed: {subjectKey: "analysis_id", data: qualityGateFailedData},
		domain.EventSLAApproaching: {
			subjectKey: "finding_id",
			vars: func(_ domain.Event, data eventData, _ sourceFacts) map[string]string {
				deadline, _ := data.time("deadline")
				return map[string]string{"deadline": formatTime(deadline), "lead_time_hours": leadTimeHours(data)}
			},
			relevant: slaReminderStillDue,
		},
		domain.EventFleetAgentOffline: {
			subjectKey: "agent_id",
			vars: func(_ domain.Event, data eventData, _ sourceFacts) map[string]string {
				lastSeen, _ := data.time("last_seen_at")
				return map[string]string{"last_seen_at": formatTime(lastSeen)}
			},
			relevant: fleetAgentStillOffline,
		},
		domain.EventIncidentCreated: {
			subjectKey: "incident_id",
			data:       incidentCreatedData,
			vars: func(e domain.Event, _ eventData, _ sourceFacts) map[string]string {
				return map[string]string{"severity": string(e.Severity)}
			},
		},
		domain.EventOwnershipChanged: {
			subjectKey: "finding_id",
			vars: func(_ domain.Event, data eventData, _ sourceFacts) map[string]string {
				return map[string]string{"actor": data.text("actor"), "reason": data.text("reason")}
			},
		},
		domain.EventChannelPaused:      {subjectKey: "channel_id"},
		domain.EventDestinationChanged: {},
		domain.EventTest:               {},
	}
}

// The data of the captured events is the object the capture trigger of migration 0163 writes, key
// for key, so the webhook body does not change when a record carries only its identity. The trigger
// still writes the data; it moves to identity-only capture once every running worker composes.

func scanCompletedData(e domain.Event, facts sourceFacts) map[string]any {
	data := map[string]any{
		"title": "Scan completed", "summary": "A scan completed successfully.",
		"scan_id": factOr(facts, "scan_id", e.SourceID), "scan_kind": facts.get("scan_kind"),
	}
	if facts.get("total_count") == "" {
		return data // legacy source records retain the v1 payload exactly.
	}
	for _, name := range scanSummaryVariableNames {
		if name == "delta_available" {
			data[name] = facts.get(name) == "true"
			continue
		}
		data[name] = numericFact(facts.get(name))
	}
	return data
}

var scanSummaryVariableNames = []string{"total_count", "critical_count", "high_count", "medium_count", "low_count", "info_count", "new_count", "fixed_count", "unchanged_count", "delta_available"}

func numericFact(value string) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func qualityGateFailedData(e domain.Event, facts sourceFacts) map[string]any {
	return map[string]any{
		"title": "Quality gate failed", "summary": "A finalized project analysis failed its quality gate.",
		"analysis_id": factOr(facts, "analysis_id", e.SourceID), "project_id": facts.get("project_id"),
	}
}

// incidentCreatedData keeps the trigger's title rule: the incident's own title, bounded, or a
// generic one when the incident has none at all. An empty title stays empty.
func incidentCreatedData(e domain.Event, facts sourceFacts) map[string]any {
	title, ok := facts["incident_title"]
	if !ok {
		title = "Security incident created"
	}
	if runes := []rune(title); len(runes) > maxIncidentTitleRunes {
		title = string(runes[:maxIncidentTitleRunes])
	}
	return map[string]any{
		"title": title, "summary": "Fleet correlation created an incident.",
		"incident_id": factOr(facts, "incident_id", e.SourceID), "asset_id": facts.get("asset_id"),
	}
}

func factOr(facts sourceFacts, name, fallback string) string {
	if v := facts.get(name); v != "" {
		return v
	}
	return fallback
}

// displayTarget is a scan target fit for a message: a URL loses its userinfo, query and fragment,
// and any other form loses everything up to an "@" and from a "?" or "#", because a repository
// URL can carry a token.
func displayTarget(target string) string {
	if u, err := url.Parse(target); err == nil && u.Scheme != "" && u.Host != "" {
		u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
		return u.String()
	}
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if i := strings.LastIndex(target, "@"); i >= 0 {
		target = target[i+1:]
	}
	return target
}

// scanStillSucceeded holds back a scan.completed delivery whose job no longer reads as succeeded,
// for example a CI import rejected after capture. Only events captured from scan_jobs are checked.
func scanStillSucceeded(ctx context.Context, facts ports.NotificationRelevance, work ports.NotificationWork, _ eventData) (bool, error) {
	if work.Event.SourceKind != "scan_job" {
		return true, nil
	}
	return facts.ScanJobSucceeded(ctx, work.Event.TenantID, work.Event.SourceID)
}

// slaReminderStillDue holds back a reminder whose assessment was replaced, rescheduled, excepted
// or closed, or whose deadline already passed.
func slaReminderStillDue(ctx context.Context, facts ports.NotificationRelevance, work ports.NotificationWork, data eventData) (bool, error) {
	deadline, ok := data.time("deadline")
	if !ok {
		return false, fmt.Errorf("%w: decode SLA notification event", shared.ErrValidation)
	}
	return facts.SLAReminderDue(ctx, work.Event.TenantID, ports.SLAReminder{
		AssessmentID: data.text("assessment_id"), EngagementID: data.text("engagement_id"),
		FindingID: data.text("finding_id"), Deadline: deadline,
	})
}

// fleetAgentStillOffline holds back an offline notice once the agent has checked in again or left
// the fleet.
func fleetAgentStillOffline(ctx context.Context, facts ports.NotificationRelevance, work ports.NotificationWork, data eventData) (bool, error) {
	lastSeen, ok := data.time("last_seen_at")
	if !ok {
		return false, fmt.Errorf("%w: decode fleet notification event", shared.ErrValidation)
	}
	return facts.FleetAgentLastSeen(ctx, work.Event.TenantID, data.text("agent_id"), lastSeen)
}

func leadTimeHours(data eventData) string {
	seconds, err := strconv.ParseFloat(data.text("lead_time_seconds"), 64)
	if err != nil || seconds <= 0 {
		return ""
	}
	return strconv.FormatFloat(seconds/3600, 'f', -1, 64)
}

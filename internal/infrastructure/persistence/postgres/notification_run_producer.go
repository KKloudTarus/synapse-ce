package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// appendRunFinishedNotification captures the bounded terminal facts while the
// run row is still locked by its persistence transaction. It deliberately
// accepts only stable error codes; worker error text can contain targets,
// credentials, or tool output and never belongs in a notification source.
func appendRunFinishedNotification(ctx context.Context, tx pgx.Tx, tenantID, engagementID shared.ID, event notification.EventType, sourceKind, sourceID, scanKind, outcome string, providers []string, target, errorCode string, total int, occurredAt time.Time) error {
	var engagementName string
	if err := tx.QueryRow(ctx, `SELECT name FROM engagements WHERE id=$1 AND tenant_id=$2`, engagementID, tenantID).Scan(&engagementName); err != nil {
		return fmt.Errorf("read notification run engagement: %w", err)
	}
	dataFields := map[string]any{
		"title":         runNotificationTitle(event),
		"summary":       runNotificationSummary(event),
		"run_id":        sourceID,
		"scan_id":       sourceID,
		"engagement_id": engagementID.String(),
		"scan_kind":     scanKind,
		"outcome":       outcome,
		"provider":      runProviderToken(providers),
		"providers":     providers,
		"error_code":    errorCode,
		// These producers do not persist a severity breakdown. Omitting unknown
		// counts is safer than asserting zero findings of each severity.
		"severity_counts_available": false,
	}
	if total >= 0 {
		dataFields["total_count"] = total
		dataFields["counts_available"] = true
	} else {
		dataFields["counts_available"] = false
	}
	data, err := json.Marshal(dataFields)
	if err != nil {
		return fmt.Errorf("encode notification run facts: %w", err)
	}
	vars := map[string]string{
		"scan_kind": scanKind, "outcome": outcome, "provider": runProviderToken(providers), "error_code": errorCode,
		"engagement_name": engagementName, "target": notificationSafeTarget(target),
	}
	if total >= 0 {
		vars["total_count"] = fmt.Sprintf("%d", total)
	}
	return appendNotificationSnapshotTx(ctx, tx, notification.SourceRecord{
		TenantID: tenantID, SourceKind: sourceKind, SourceID: sourceID, EventType: event,
		EngagementID: engagementID, Severity: shared.SeverityInfo, OccurredAt: occurredAt,
		Data: data, SchemaVersion: 1, SubjectKind: notificationSubjectKind(event), SubjectID: sourceID,
	}, vars)
}

func runProviderToken(providers []string) string {
	if len(providers) == 1 {
		return providers[0]
	}
	if len(providers) == 0 {
		return "unknown"
	}
	return "multiple"
}

func runNotificationTitle(event notification.EventType) string {
	switch event {
	case notification.EventScanFailed:
		return "Scan failed"
	case notification.EventDASTRunFinished:
		return "DAST run finished"
	case notification.EventReconRunFinished:
		return "Reconnaissance run finished"
	case notification.EventCSPMRunFinished:
		return "Cloud posture run finished"
	default:
		return "Run finished"
	}
}

func runNotificationSummary(event notification.EventType) string {
	if event == notification.EventScanFailed {
		return "A scan did not finish."
	}
	return "A governed run reached a terminal outcome."
}

func notificationSubjectKind(event notification.EventType) string {
	spec, ok := notification.LookupEvent(event)
	if !ok {
		return ""
	}
	return spec.SubjectKind
}

// notificationSafeTarget removes URL credentials, query, fragment and path.
// Non-URL values are retained only when they contain no whitespace or '@'.
func notificationSafeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		return parsed.Hostname()
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	// Bare values cannot safely express credentials. URI values with userinfo
	// took the parsed-host path above; fail closed for any colon here.
	if strings.ContainsAny(raw, "@ \t\r\n:") {
		return ""
	}
	return raw
}

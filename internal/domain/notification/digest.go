package notification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DeliveryCadence controls external channel batching. Personal and mandatory notices stay immediate.
type DeliveryCadence string

const (
	CadenceImmediate DeliveryCadence = "immediate"
	CadenceHourly    DeliveryCadence = "hourly"
	CadenceDaily     DeliveryCadence = "daily"
	MaxDigestItems                   = 50
	MaxDigestMembers                 = 200
)

func (c DeliveryCadence) Valid() bool {
	return c == CadenceImmediate || c == CadenceHourly || c == CadenceDaily
}

// Window returns a half-open UTC publication window; daily means a UTC calendar day.
func (c DeliveryCadence) Window(at time.Time) (time.Time, time.Time) {
	duration := time.Hour
	if c == CadenceDaily {
		duration = 24 * time.Hour
	}
	start := at.UTC().Truncate(duration)
	return start, start.Add(duration)
}

func (r Rule) DigestEligible(e Event) bool {
	spec, _ := LookupEvent(e.Type)
	return (r.Cadence == CadenceHourly || r.Cadence == CadenceDaily) && e.Severity != shared.SeverityCritical && e.Type != EventEvidenceChainBroken && !spec.Mandatory && !InAppMandatory(e.Type)
}

// DigestData carries only references. Source snapshots remain authoritative for rendering.
type DigestData struct {
	Cadence     DeliveryCadence `json:"cadence"`
	WindowStart time.Time       `json:"window_start"`
	WindowEnd   time.Time       `json:"window_end"`
	EventIDs    []shared.ID     `json:"event_ids"`
	// TotalCount is the number of member events safe for the rendered class at
	// materialization. EventIDs remains capped; membership rows retain every item.
	TotalCount int `json:"total_count"`
}

type DigestItem struct {
	Event    Event
	Override EngagementNotifications
}

// DigestPolicy binds an admission to all member policies, including members currently suppressed.
// Callers read those policies under the same locks as engagement-setting writes before admission.
func DigestPolicy(items []DigestItem, class DataClass) string {
	rows := make([]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, item.Event.ID.String()+":"+item.Event.EngagementID.String()+":"+string(item.Override))
	}
	sort.Strings(rows)
	raw, _ := json.Marshal(struct {
		Class DataClass
		Items []string
	}{class, rows})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// BuildDigestContext filters each original snapshot before constructing fixed, bounded list rows.
// The returned count includes all allowed members; the rendered list contains at most fifty.
func BuildDigestContext(items []DigestItem, cadence DeliveryCadence, start, end time.Time, class DataClass) (TemplateContext, int, error) {
	if !class.Valid() || (cadence != CadenceHourly && cadence != CadenceDaily) || !end.After(start) {
		return TemplateContext{}, 0, fmt.Errorf("%w: invalid digest window or class", shared.ErrValidation)
	}
	ordered := append([]DigestItem(nil), items...)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i].Event, ordered[j].Event
		if a.OccurredAt.Equal(b.OccurredAt) {
			return a.ID < b.ID
		}
		return a.OccurredAt.Before(b.OccurredAt)
	})
	rows := make([]map[string]string, 0, min(len(items), MaxDigestItems))
	count := 0
	for _, item := range ordered {
		effective, deliver := EffectiveDataClass(class, item.Override)
		if !deliver {
			continue
		}
		spec, ok := LookupEvent(item.Event.Type)
		if !ok || item.Event.Type == EventDigest {
			continue
		}
		context, err := DecodeTemplateContext(item.Event.Context)
		if err != nil {
			return TemplateContext{}, 0, err
		}
		context = context.Filter(spec, effective)
		count++
		if len(rows) >= MaxDigestItems {
			continue
		}
		row := map[string]string{"event_type": string(item.Event.Type), "severity": string(item.Event.Severity), "occurred_at": item.Event.OccurredAt.UTC().Format(time.RFC3339Nano)}
		for _, name := range []string{"finding_title", "incident_title", "title", "summary"} {
			if value := context.Vars[name]; value != "" {
				row["title"] = boundRunes(value, 160)
				break
			}
		}
		// Targets are selected only after the original event's class filter.
		if value := context.Vars["target"]; value != "" {
			row["target"] = boundRunes(value, 160)
		}
		rows = append(rows, row)
	}
	spec, _ := LookupEvent(EventDigest)
	context := spec.SnapshotWithLists(map[string]string{"severity": string(DigestSeverity(items)), "event_type": string(EventDigest), "event_label": spec.Label, "occurred_at": end.UTC().Format(time.RFC3339Nano), "cadence": string(cadence), "window_start": start.UTC().Format(time.RFC3339Nano), "window_end": end.UTC().Format(time.RFC3339Nano), "item_count": strconv.Itoa(count), "omitted_count": strconv.Itoa(max(0, count-len(rows)))}, map[string][]map[string]string{"items": rows})
	context = context.withinByteLimit(16 * 1024)
	context.Vars["omitted_count"] = strconv.Itoa(max(0, count-len(context.Lists["items"])))
	return context, count, nil
}

// DigestSeverity is the highest visible member severity; suppressed members cannot raise it.
func DigestSeverity(items []DigestItem) shared.Severity {
	severity := shared.SeverityUnknown
	for _, item := range items {
		if item.Override == EngagementNotificationsNone {
			continue
		}
		if shared.SeverityRank(item.Event.Severity) > shared.SeverityRank(severity) {
			severity = item.Event.Severity
		}
	}
	return severity
}

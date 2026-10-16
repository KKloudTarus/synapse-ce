package notification

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDigestFiltersOriginalItemsAndDropsSuppressed(t *testing.T) {
	at := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	items := []DigestItem{}
	for i, override := range []EngagementNotifications{EngagementNotificationsInherit, EngagementNotificationsSignal, EngagementNotificationsNone} {
		c := TemplateContext{Vars: map[string]string{"title": "private-title", "finding_title": "private-finding", "target": "private-target", "severity": "high"}}
		raw, _ := c.Encode()
		items = append(items, DigestItem{Event: Event{ID: shared.ID(fmt.Sprintf("e%d", i)), Type: EventFindingCreated, OccurredAt: at, Context: raw, Severity: shared.SeverityHigh}, Override: override})
	}
	context, count, err := BuildDigestContext(items, CadenceHourly, at, at.Add(time.Hour), DataClassDetail)
	if err != nil || count != 2 || len(context.Lists["items"]) != 2 {
		t.Fatalf("context=%+v count=%d err=%v", context, count, err)
	}
	if context.Lists["items"][0]["title"] != "private-finding" || context.Lists["items"][1]["title"] != "" {
		t.Fatalf("per-item filter missing: %+v", context.Lists)
	}
	signal, _, _ := BuildDigestContext(items, CadenceHourly, at, at.Add(time.Hour), DataClassSignal)
	raw, _ := json.Marshal(signal)
	if strings.Contains(string(raw), "private-") {
		t.Fatalf("signal disclosed source values: %s", raw)
	}
	if DigestPolicy(items, DataClassDetail) == DigestPolicy(items, DataClassSignal) {
		t.Fatal("channel policy absent from witness")
	}
	changed := append([]DigestItem(nil), items...)
	changed[0].Override = EngagementNotificationsNone
	if DigestPolicy(items, DataClassDetail) == DigestPolicy(changed, DataClassDetail) {
		t.Fatal("member policy absent from witness")
	}
}

func TestDigestBoundsContextAndPreservesAllowedCount(t *testing.T) {
	at := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	items := make([]DigestItem, 100)
	for i := range items {
		raw, _ := (TemplateContext{Vars: map[string]string{"finding_title": strings.Repeat("界", 500)}}).Encode()
		items[i] = DigestItem{Event: Event{ID: shared.ID(fmt.Sprintf("e%03d", i)), Type: EventFindingCreated, OccurredAt: at, Context: raw}, Override: EngagementNotificationsInherit}
	}
	c, count, err := BuildDigestContext(items, CadenceDaily, at, at.Add(24*time.Hour), DataClassDetail)
	raw, _ := c.Encode()
	if err != nil || count != 100 || c.Vars["item_count"] != "100" || len(c.Lists["items"]) > 50 || len(raw) > 16*1024 {
		t.Fatalf("count=%d bytes=%d err=%v", count, len(raw), err)
	}
}

func TestDigestCadenceBypassesCriticalAndMandatory(t *testing.T) {
	for _, c := range []DeliveryCadence{CadenceHourly, CadenceDaily} {
		r := Rule{Cadence: c}
		if r.DigestEligible(Event{Type: EventFindingCreated, Severity: shared.SeverityCritical}) || r.DigestEligible(Event{Type: EventEvidenceChainBroken}) || r.DigestEligible(Event{Type: EventDestinationChanged}) {
			t.Fatal("mandatory or critical event delayed")
		}
		if !r.DigestEligible(Event{Type: EventFindingCreated, Severity: shared.SeverityHigh}) {
			t.Fatal("ordinary event not batched")
		}
		start, end := c.Window(time.Date(2026, 10, 16, 1, 30, 0, 0, time.FixedZone("test", 7*3600)))
		if !start.Before(end) || start.Location() != time.UTC {
			t.Fatal("window not UTC")
		}
	}
}

func TestEmailDestinationNoticeContainsOnlyCanonicalDomains(t *testing.T) {
	e, err := NewEmailDestinationEvent("tenant", "channel", []string{"alice@EXAMPLE.com", "bob@example.com", "carol@other.test"}, "domains_changed", "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(e.Data), "@") || strings.Contains(string(e.Data), "alice") || strings.Contains(string(e.Data), "carol") {
		t.Fatalf("address disclosed: %s", e.Data)
	}
	var notice DestinationNotice
	_ = json.Unmarshal(e.Data, &notice)
	if notice.Host != "example.com,other.test" || notice.Scheme != "mailto" {
		t.Fatalf("notice=%+v", notice)
	}
	subject, err := SubjectFromEvent(e)
	if err != nil || !subject.Admins || !InAppMandatory(e.Type) {
		t.Fatalf("mandatory admin notice missing: %+v %v", subject, err)
	}
}

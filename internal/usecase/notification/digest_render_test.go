package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	eventschemas "github.com/KKloudTarus/synapse-ce/docs/guide/schemas/events"
	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	"github.com/KKloudTarus/synapse-ce/internal/domain/consolelink"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestDigestRendersMixedMembersThroughEveryBuiltinFamily(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	at := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	var items []domain.DigestItem
	for i, kind := range []domain.EventType{domain.EventFindingCreated, domain.EventScanCompleted, domain.EventFindingCommented, domain.EventIncidentCreated, domain.EventScanFailed} {
		context := domain.TemplateContext{Vars: map[string]string{"title": "[Reset password](https://evil.example) @everyone <!channel> **bold** password=private-value", "finding_title": "Phát hiện kiểm thử", "severity": "high", "target": "https://target.example"}}
		raw, _ := context.Encode()
		e := domain.Event{ID: shared.ID(fmt.Sprintf("item-%d", i)), Type: kind, OccurredAt: at, Context: raw, Severity: shared.SeverityHigh}
		projected, err := NewEventBuilders().Project(h.ctx, e)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, domain.DigestItem{Event: projected, Override: domain.EngagementNotificationsInherit})
	}
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		for _, channelType := range []domain.ChannelType{domain.ChannelSlack, domain.ChannelTeams, domain.ChannelTelegram, domain.ChannelDiscord, domain.ChannelGoogleChat, domain.ChannelMattermost, domain.ChannelRocketChat, domain.ChannelSlackBot, domain.ChannelEmail, domain.ChannelWebhook, domain.ChannelPagerDuty, domain.ChannelJSM} {
			for _, class := range []domain.DataClass{domain.DataClassSignal, domain.DataClassDetail} {
				t.Run(string(locale)+"/"+string(channelType)+"/"+string(class), func(t *testing.T) {
					c, count, err := domain.BuildDigestContext(items, domain.CadenceHourly, at, at.Add(time.Hour), class)
					if err != nil || count != 5 {
						t.Fatalf("digest=%d %v", count, err)
					}
					raw, _ := c.Encode()
					channel := h.channel
					channel.Type = channelType
					channel.Locale = locale
					channel.DataClass = class
					descriptor, _ := json.Marshal(domain.DigestData{Cadence: domain.CadenceHourly, WindowStart: at, WindowEnd: at.Add(time.Hour)})
					e := domain.Event{Data: descriptor, TenantID: channel.TenantID, ID: "digest", Type: domain.EventDigest, SourceKind: "digest", SchemaVersion: 1, OccurredAt: at.Add(time.Hour), Context: raw, DigestItems: items}
					out, err := h.svc.RenderMessage(h.ctx, RenderInput{Channel: channel, Event: e})
					if err != nil || out.Fallback || out.Message.TemplateRef == "fallback" {
						t.Fatalf("render=%+v err=%v", out, err)
					}
					text := fmt.Sprint(out.Message.Fields)
					if channelType == domain.ChannelWebhook {
						text = string(out.WebhookBody)
					}
					if strings.Contains(text, "private-value") {
						t.Fatalf("secret exported: %s", text)
					}
					if !strings.Contains(text, "5") {
						t.Fatalf("count omitted: %s", text)
					}
					if channelType != domain.ChannelWebhook && locale == tenancy.LocaleVietnamese && !strings.Contains(text, "Tổng hợp") {
						t.Fatalf("locale not used: %s", text)
					}
				})
			}
		}
	}
}

func TestDigestLinksFollowVisibleChronologicalRows(t *testing.T) {
	h := newRenderHarness(t)
	builder, err := consolelink.NewBuilder("https://console.example")
	if err != nil {
		t.Fatal(err)
	}
	h.svc.SetConsoleLinkBuilder(builder)
	at := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	item := func(id string, when time.Time, override domain.EngagementNotifications) domain.DigestItem {
		return domain.DigestItem{Event: domain.Event{ID: shared.ID(id), Type: domain.EventFindingCreated, EngagementID: "assessment", SubjectID: id, OccurredAt: when}, Override: override}
	}
	links := h.svc.renderLinks(domain.Event{Type: domain.EventDigest, DigestItems: []domain.DigestItem{
		item("later", at.Add(time.Minute), domain.EngagementNotificationsInherit),
		item("suppressed", at.Add(-time.Minute), domain.EngagementNotificationsNone),
		item("earlier", at, domain.EngagementNotificationsInherit),
	}})
	if len(links) != 2 || links[0].Label != "1 · Open finding" || links[1].Label != "2 · Open finding" || !strings.HasSuffix(links[0].URL, "#finding-earlier") || !strings.HasSuffix(links[1].URL, "#finding-later") {
		t.Fatalf("links do not match the visible row order: %+v", links)
	}
}

type digestSourceState struct {
	ports.NotificationRepository
	reads int
	err   error
}

func (s *digestSourceState) FleetAgentLastSeen(context.Context, shared.ID, string, time.Time) (bool, error) {
	s.reads++
	return false, s.err
}
func (s *digestSourceState) SLAReminderDue(context.Context, shared.ID, ports.SLAReminder) (bool, error) {
	s.reads++
	return false, s.err
}

func TestDigestRechecksSourceStateBeforeEveryOutgoingField(t *testing.T) {
	for _, kind := range []domain.EventType{domain.EventFleetAgentOffline, domain.EventSLAApproaching} {
		t.Run(string(kind), func(t *testing.T) {
			h := newRenderHarness(t)
			h.svc.SetBuiltinTemplates(notificationbuiltin.New())
			state := &digestSourceState{NotificationRepository: h.repo}
			h.svc.repo = state
			h.svc.SetEventFixtures(eventschemas.Fixtures)
			stale, err := h.svc.fixtureEvent("tenant-r", kind)
			if err != nil {
				t.Fatal(err)
			}
			stale.ID, stale.Severity = "stale", shared.SeverityHigh
			kept, err := h.svc.fixtureEvent("tenant-r", domain.EventIncidentCreated)
			if err != nil {
				t.Fatal(err)
			}
			kept.ID, kept.Severity, kept.SubjectID = "kept", shared.SeverityLow, "kept-incident"
			at := h.clock.at
			descriptor, _ := json.Marshal(domain.DigestData{Cadence: domain.CadenceHourly, WindowStart: at, WindowEnd: at.Add(time.Hour), EventIDs: []shared.ID{stale.ID, kept.ID}, TotalCount: 2})
			event := domain.Event{TenantID: "tenant-r", ID: "aggregate", Type: domain.EventDigest, SourceKind: "digest", Data: descriptor, DigestItems: []domain.DigestItem{{Event: stale}, {Event: kept}}}
			out, err := h.svc.RenderMessage(h.ctx, RenderInput{Channel: h.channel, Event: event})
			if err != nil {
				t.Fatal(err)
			}
			if out.Suppressed || out.event == nil || len(out.event.DigestItems) != 1 || out.Message.Severity != shared.SeverityLow {
				t.Fatalf("render=%+v", out)
			}
			var data domain.DigestData
			if err := json.Unmarshal(out.event.Data, &data); err != nil {
				t.Fatal(err)
			}
			if data.TotalCount != 1 || len(data.EventIDs) != 1 || data.EventIDs[0] != kept.ID {
				t.Fatalf("raw descriptor=%+v", data)
			}
			if !strings.Contains(out.Message.Fields["body"], "1 events") || strings.Contains(out.Message.Fields["body"], string(kind)) {
				t.Fatalf("body=%q", out.Message.Fields["body"])
			}
			event.DigestItems = event.DigestItems[:1]
			out, err = h.svc.RenderMessage(h.ctx, RenderInput{Channel: h.channel, Event: event})
			if err != nil || !out.Suppressed || out.suppressionReason != "source_no_longer_relevant" {
				t.Fatalf("all expired=%+v %v", out, err)
			}
			state.err = errors.New("source read unavailable")
			if _, err = h.svc.RenderMessage(h.ctx, RenderInput{Channel: h.channel, Event: event}); !errors.Is(err, state.err) {
				t.Fatalf("source failure=%v", err)
			}
			event.DigestItems[0].Override = domain.EngagementNotificationsNone
			before := state.reads
			if _, err = h.svc.RenderMessage(h.ctx, RenderInput{Channel: h.channel, Event: event}); err != nil || state.reads != before {
				t.Fatalf("suppressed member read source: %d %v", state.reads-before, err)
			}
		})
	}
}

func TestDigestRelevanceWorkIsBounded(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetEventFixtures(eventschemas.Fixtures)
	state := &digestSourceState{NotificationRepository: h.repo}
	h.svc.repo = state
	source, err := h.svc.fixtureEvent("tenant-r", domain.EventFleetAgentOffline)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]domain.DigestItem, domain.MaxDigestMembers+1)
	for i := range items {
		items[i] = domain.DigestItem{Event: source}
	}
	at := h.clock.at
	data, _ := json.Marshal(domain.DigestData{Cadence: domain.CadenceHourly, WindowStart: at, WindowEnd: at.Add(time.Hour)})
	event := domain.Event{Type: domain.EventDigest, Data: data, DigestItems: items}
	if _, err := h.svc.RenderMessage(h.ctx, RenderInput{Channel: h.channel, Event: event}); !errors.Is(err, shared.ErrValidation) || state.reads != 0 {
		t.Fatalf("oversize digest read sources: %d %v", state.reads, err)
	}
	event.DigestItems = items[:domain.MaxDigestMembers]
	out, err := h.svc.RenderMessage(h.ctx, RenderInput{Channel: h.channel, Event: event})
	if err != nil || !out.Suppressed || state.reads != domain.MaxDigestMembers {
		t.Fatalf("bounded relevance reads=%d suppressed=%v err=%v", state.reads, out.Suppressed, err)
	}
}

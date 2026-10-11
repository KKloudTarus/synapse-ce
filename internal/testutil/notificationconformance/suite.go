// Package notificationconformance runs one behavioral contract against every adapter of the notification
// ports, so the in-memory twins cannot drift from PostgreSQL unnoticed (EPIC #1327 N04). It is test-only
// support code.
package notificationconformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Backend is one adapter family under test.
type Backend struct {
	Repository ports.NotificationRepository
	Outbox     ports.NotificationOutbox
	Source     ports.NotificationSource
	Runner     ports.TenantTransactionRunner
	// AddTenant makes a tenant exist, so Source.Poll visits it.
	AddTenant func(t *testing.T, tenant shared.ID)
	// AddEngagement creates an engagement a rule may be scoped to.
	AddEngagement func(t *testing.T, tenant, engagement shared.ID)
}

// Run executes the contract. newBackend is called once per case; every case works in tenants of its own,
// so a backend may share one database between cases.
func Run(t *testing.T, newBackend func(t *testing.T) Backend) {
	t.Helper()
	for _, c := range []struct {
		name string
		run  func(*testing.T, *fixture)
	}{
		{"a committed append is projected into one delivery", committedAppendIsProjectedOnce},
		{"an append in a rolled-back transaction leaves no record", rolledBackAppendLeavesNoRecord},
		{"an append outside a tenant transaction is refused", appendOutsideTransactionIsRefused},
		{"an append into another tenant's transaction is refused", appendIntoOtherTenantIsRefused},
		{"appending the same source twice records it once", repeatedSourceIsRecordedOnce},
		{"a record that predates activation is not captured", preActivationRecordIsNotCaptured},
		{"a record the schema would refuse is refused before it is written", malformedRecordIsRefused},
		{"a record never reaches another tenant's rules", recordStaysInItsTenant},
		{"channels are revised and deleted under optimistic concurrency", channelLifecycle},
		{"a rule names only channels and engagements that exist", ruleReferencesMustExist},
		{"a channel publication is listed, paged and loaded", channelPublicationIsListedPagedAndLoaded},
		{"an event keeps its subject and template context snapshot", eventKeepsSubjectAndContext},
		{"a channel keeps its data class, defaulting by type", channelKeepsDataClass},
		{"an engagement override is revision checked and reaches the work", engagementOverrideReachesWork},
		{"channel tests are rate limited per channel", channelTestsAreRateLimited},
		{"disabling or deleting a channel cancels its undelivered deliveries", closingChannelCancelsDeliveries},
		{"a new destination or secret cancels the deliveries meant for the old one", retargetingChannelCancelsDeliveries},
		{"repeated permanent failures pause a channel until an administrator resumes it", permanentFailuresPauseChannel},
		{"a record that cannot be projected is quarantined without blocking the next", invalidRecordIsQuarantined},
		{"a tenant's channel count is capped", channelCountIsCapped},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, newFixture(t, newBackend(t))) })
	}
}

var tenantSequence atomic.Int64

type fixture struct {
	Backend
	ctx    context.Context
	tenant shared.ID
	base   time.Time
}

func newFixture(t *testing.T, b Backend) *fixture {
	f := &fixture{Backend: b, base: time.Now().UTC().Truncate(time.Second)}
	f.tenant = f.newTenant(t)
	f.ctx = shared.WithTenant(context.Background(), f.tenant)
	return f
}

func (f *fixture) newTenant(t *testing.T) shared.ID {
	t.Helper()
	tenant := shared.ID(fmt.Sprintf("conformance-%d", tenantSequence.Add(1)))
	f.AddTenant(t, tenant)
	return tenant
}

func (f *fixture) at(offset time.Duration) time.Time { return f.base.Add(offset) }

// activate runs the tenant's first poll, which records the notification activation time.
func (f *fixture) activate(t *testing.T) { f.poll(t, 0) }

func (f *fixture) poll(t *testing.T, offset time.Duration) {
	t.Helper()
	if _, err := f.Source.Poll(f.ctx, f.at(offset), 100); err != nil {
		t.Fatalf("poll: %v", err)
	}
}

func (f *fixture) channel(t *testing.T, tenant, id shared.ID) notification.Channel {
	t.Helper()
	c := notification.Channel{TenantID: tenant, ID: id, Name: "hook " + id.String(), Type: notification.ChannelWebhook, Enabled: true,
		Destination: "https://hooks.example.test", Revision: 1, SecretVersion: 1, CreatedAt: f.base, UpdatedAt: f.base}
	created, err := f.Repository.CreateChannel(f.ctx, c, sealedConfig(id, 1))
	if err != nil {
		t.Fatalf("create channel %s: %v", id, err)
	}
	return created
}

func sealedConfig(channel shared.ID, version int) string {
	return fmt.Sprintf("sealed-%s-v%d", channel, version)
}

func (f *fixture) rule(t *testing.T, id shared.ID, channels ...shared.ID) notification.Rule {
	t.Helper()
	created, err := f.Repository.CreateRule(f.ctx, scanRule(f.tenant, id, f.base, channels...))
	if err != nil {
		t.Fatalf("create rule %s: %v", id, err)
	}
	return created
}

func scanRule(tenant, id shared.ID, at time.Time, channels ...shared.ID) notification.Rule {
	return notification.Rule{TenantID: tenant, ID: id, Name: "scans " + id.String(), Enabled: true, EventType: notification.EventScanCompleted,
		ChannelIDs: channels, Revision: 1, CreatedAt: at, UpdatedAt: at}
}

// routed gives the fixture tenant an activated notification framework with one rule for scan.completed.
func (f *fixture) routed(t *testing.T) (notification.Channel, notification.Rule) {
	t.Helper()
	f.activate(t)
	channel := f.channel(t, f.tenant, "hook")
	return channel, f.rule(t, "scans", channel.ID)
}

func scanRecord(tenant shared.ID, sourceID string, occurred time.Time, title string) notification.SourceRecord {
	return notification.SourceRecord{
		TenantID: tenant, SourceKind: "scan_job", SourceID: sourceID, EventType: notification.EventScanCompleted,
		SchemaVersion: 1, SubjectKind: "scan_job", SubjectID: sourceID, OccurredAt: occurred,
		Data: json.RawMessage(fmt.Sprintf(`{"title":%q,"scan_id":%q}`, title, sourceID)),
	}
}

// appendIn runs Append inside a tenant transaction of the given tenant and returns the transaction's result.
func (f *fixture) appendIn(tenant shared.ID, record notification.SourceRecord) error {
	return f.Runner.Run(f.ctx, tenant, func(ctx context.Context) error { return f.Outbox.Append(ctx, record) })
}

func (f *fixture) mustAppend(t *testing.T, record notification.SourceRecord) {
	t.Helper()
	if err := f.appendIn(record.TenantID, record); err != nil {
		t.Fatalf("append %s: %v", record.SourceID, err)
	}
}

func (f *fixture) deliveries(t *testing.T, tenant shared.ID) []notification.Delivery {
	t.Helper()
	page, err := f.Repository.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	return page.Items
}

func (f *fixture) work(t *testing.T, id shared.ID) ports.NotificationWork {
	t.Helper()
	w, err := f.Repository.LoadWork(f.ctx, f.tenant, id)
	if err != nil {
		t.Fatalf("load work %s: %v", id, err)
	}
	return w
}

func dataTitle(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var data struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode event data %s: %v", raw, err)
	}
	return data.Title
}

func committedAppendIsProjectedOnce(t *testing.T, f *fixture) {
	f.activate(t)
	channel := f.channel(t, f.tenant, "hook")
	// The rule also names a disabled channel, which publication must skip.
	muted := f.channel(t, f.tenant, "muted")
	muted.Enabled, muted.Revision, muted.UpdatedAt = false, 2, f.base
	if _, err := f.Repository.UpdateChannel(f.ctx, muted, "", false); err != nil {
		t.Fatalf("disable channel: %v", err)
	}
	rule := f.rule(t, "scans", channel.ID, muted.ID)
	record := scanRecord(f.tenant, "scan-1", f.at(time.Second), "Scan completed")
	record.EngagementID = "eng-1"
	f.mustAppend(t, record)
	f.poll(t, 2*time.Second)
	f.poll(t, 3*time.Second) // a second tick must not project the record again

	deliveries := f.deliveries(t, f.tenant)
	if len(deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(deliveries))
	}
	d := deliveries[0]
	if d.State != notification.DeliveryPending || d.ChannelID != channel.ID || !reflect.DeepEqual(d.MatchedRuleIDs, []shared.ID{rule.ID}) {
		t.Fatalf("delivery = %+v, want a pending delivery to %s matched by %s", d, channel.ID, rule.ID)
	}
	w := f.work(t, d.ID)
	e := w.Event
	if e.Type != notification.EventScanCompleted || e.SourceKind != "scan_job" || e.SourceID != "scan-1" || e.EngagementID != "eng-1" || !e.OccurredAt.Equal(record.OccurredAt) {
		t.Fatalf("projected event = %+v, want the appended record", e)
	}
	if got := dataTitle(t, e.Data); got != "Scan completed" {
		t.Fatalf("event data title = %q, want the appended data", got)
	}
	if w.Sealed != sealedConfig(channel.ID, 1) || w.Channel.ID != channel.ID {
		t.Fatalf("work channel = %s sealed %q, want %s with its version-1 configuration", w.Channel.ID, w.Sealed, channel.ID)
	}
}

func rolledBackAppendLeavesNoRecord(t *testing.T, f *fixture) {
	f.routed(t)
	rollback := errors.New("business write failed")
	err := f.Runner.Run(f.ctx, f.tenant, func(ctx context.Context) error {
		if err := f.Outbox.Append(ctx, scanRecord(f.tenant, "scan-rolled-back", f.at(time.Second), "rolled back")); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("transaction = %v, want the business failure", err)
	}
	f.poll(t, 2*time.Second)
	if deliveries := f.deliveries(t, f.tenant); len(deliveries) != 0 {
		t.Fatalf("a rolled-back append was projected: %+v", deliveries)
	}
	// Control: the same routing does project a committed record, so the empty result above is the rollback.
	f.mustAppend(t, scanRecord(f.tenant, "scan-committed", f.at(3*time.Second), "committed"))
	f.poll(t, 4*time.Second)
	deliveries := f.deliveries(t, f.tenant)
	if len(deliveries) != 1 || f.work(t, deliveries[0].ID).Event.SourceID != "scan-committed" {
		t.Fatalf("deliveries = %+v, want only the committed record", deliveries)
	}
}

func appendOutsideTransactionIsRefused(t *testing.T, f *fixture) {
	f.routed(t)
	if err := f.Outbox.Append(f.ctx, scanRecord(f.tenant, "scan-1", f.at(time.Second), "outside")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("append outside a transaction = %v, want ErrValidation", err)
	}
	f.poll(t, 2*time.Second)
	if deliveries := f.deliveries(t, f.tenant); len(deliveries) != 0 {
		t.Fatalf("a refused append was projected: %+v", deliveries)
	}
}

func appendIntoOtherTenantIsRefused(t *testing.T, f *fixture) {
	other := f.newTenant(t)
	f.activate(t)
	err := f.appendIn(f.tenant, scanRecord(other, "scan-1", f.at(time.Second), "foreign"))
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("append of tenant %s inside tenant %s's transaction = %v, want ErrValidation", other, f.tenant, err)
	}
}

func repeatedSourceIsRecordedOnce(t *testing.T, f *fixture) {
	f.routed(t)
	f.mustAppend(t, scanRecord(f.tenant, "scan-1", f.at(time.Second), "first"))
	f.mustAppend(t, scanRecord(f.tenant, "scan-1", f.at(2*time.Second), "second"))
	f.poll(t, 3*time.Second)
	deliveries := f.deliveries(t, f.tenant)
	if len(deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1 for one source", len(deliveries))
	}
	if got := dataTitle(t, f.work(t, deliveries[0].ID).Event.Data); got != "first" {
		t.Fatalf("event data title = %q, want the first append to win", got)
	}
}

func preActivationRecordIsNotCaptured(t *testing.T, f *fixture) {
	channel := f.channel(t, f.tenant, "hook")
	f.rule(t, "scans", channel.ID)
	// Not activated yet: the tenant has never been polled.
	f.mustAppend(t, scanRecord(f.tenant, "scan-before-first-poll", f.at(time.Second), "before first poll"))
	f.poll(t, 2*time.Second) // activates at +2s
	f.mustAppend(t, scanRecord(f.tenant, "scan-before-activation", f.at(time.Second), "before activation"))
	f.poll(t, 3*time.Second)
	if deliveries := f.deliveries(t, f.tenant); len(deliveries) != 0 {
		t.Fatalf("a record older than the activation was projected: %+v", deliveries)
	}
	// Control: a record at the activation instant is captured.
	f.mustAppend(t, scanRecord(f.tenant, "scan-at-activation", f.at(2*time.Second), "at activation"))
	f.poll(t, 4*time.Second)
	deliveries := f.deliveries(t, f.tenant)
	if len(deliveries) != 1 || f.work(t, deliveries[0].ID).Event.SourceID != "scan-at-activation" {
		t.Fatalf("deliveries = %+v, want only the record at the activation instant", deliveries)
	}
}

func malformedRecordIsRefused(t *testing.T, f *fixture) {
	f.routed(t)
	for name, mutate := range map[string]func(*notification.SourceRecord){
		"unknown event type":  func(r *notification.SourceRecord) { r.EventType = "finding.imagined" },
		"malformed subject":   func(r *notification.SourceRecord) { r.SubjectKind = "Scan Job" },
		"non-object context":  func(r *notification.SourceRecord) { r.Context = json.RawMessage(`[]`) },
		"non-object data":     func(r *notification.SourceRecord) { r.Data = json.RawMessage(`"text"`) },
		"no occurrence time":  func(r *notification.SourceRecord) { r.OccurredAt = time.Time{} },
		"negative schema":     func(r *notification.SourceRecord) { r.SchemaVersion = -1 },
		"subject id too long": func(r *notification.SourceRecord) { r.SubjectID = strings.Repeat("s", 513) },
	} {
		record := scanRecord(f.tenant, "scan-"+strings.ReplaceAll(name, " ", "-"), f.at(time.Second), name)
		mutate(&record)
		if err := f.appendIn(f.tenant, record); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: append = %v, want ErrValidation", name, err)
		}
	}
	f.poll(t, 2*time.Second)
	if deliveries := f.deliveries(t, f.tenant); len(deliveries) != 0 {
		t.Fatalf("a refused record was projected: %+v", deliveries)
	}
}

func recordStaysInItsTenant(t *testing.T, f *fixture) {
	f.routed(t)
	other := f.newTenant(t)
	f.mustAppend(t, scanRecord(other, "scan-1", f.at(time.Second), "other tenant"))
	f.poll(t, 2*time.Second) // activates the other tenant
	f.mustAppend(t, scanRecord(other, "scan-2", f.at(3*time.Second), "other tenant"))
	f.poll(t, 4*time.Second)
	if deliveries := f.deliveries(t, f.tenant); len(deliveries) != 0 {
		t.Fatalf("another tenant's record reached this tenant's rule: %+v", deliveries)
	}
}

func channelLifecycle(t *testing.T, f *fixture) {
	c := f.channel(t, f.tenant, "hook")
	got, err := f.Repository.GetChannel(f.ctx, f.tenant, c.ID)
	if err != nil || got.Name != c.Name || got.Revision != 1 || got.SecretVersion != 1 {
		t.Fatalf("get channel = %+v, %v", got, err)
	}
	if _, err := f.Repository.GetChannel(f.ctx, f.newTenant(t), c.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant read the channel: %v", err)
	}

	stale := c
	stale.Name, stale.UpdatedAt = "stale", f.at(time.Second)
	if _, err := f.Repository.UpdateChannel(f.ctx, stale, "", false); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("update at the current revision = %v, want ErrConflict", err)
	}
	next := c
	next.Name, next.Revision, next.UpdatedAt = "renamed", 2, f.at(time.Second)
	updated, err := f.Repository.UpdateChannel(f.ctx, next, sealedConfig(c.ID, 2), true)
	if err != nil || updated.SecretVersion != 2 {
		t.Fatalf("replace secret = %+v, %v, want secret version 2", updated, err)
	}
	next.Revision, next.UpdatedAt = 3, f.at(2*time.Second)
	if kept, err := f.Repository.UpdateChannel(f.ctx, next, "", false); err != nil || kept.SecretVersion != 2 {
		t.Fatalf("update without a secret = %+v, %v, want secret version kept at 2", kept, err)
	}

	if err := f.Repository.DeleteChannel(f.ctx, f.tenant, c.ID, 2, f.at(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("delete at a stale revision = %v, want ErrConflict", err)
	}
	if err := f.Repository.DeleteChannel(f.ctx, f.tenant, c.ID, 3, f.at(3*time.Second)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := f.Repository.GetChannel(f.ctx, f.tenant, c.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get deleted channel = %v, want ErrNotFound", err)
	}
	if channels, err := f.Repository.ListChannels(f.ctx, f.tenant); err != nil || len(channels) != 0 {
		t.Fatalf("list after delete = %+v, %v, want empty", channels, err)
	}
}

func ruleReferencesMustExist(t *testing.T, f *fixture) {
	channel := f.channel(t, f.tenant, "hook")
	if _, err := f.Repository.CreateRule(f.ctx, scanRule(f.tenant, "ghost-channel", f.base, "no-such-channel")); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rule on a missing channel = %v, want ErrNotFound", err)
	}
	// Engagement ids are unique across tenants, so each is named after the tenant that owns it.
	scoped := scanRule(f.tenant, "scoped", f.base, channel.ID)
	scoped.EngagementIDs = []shared.ID{f.tenant + "-eng-missing"}
	if _, err := f.Repository.CreateRule(f.ctx, scoped); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rule on a missing engagement = %v, want ErrNotFound", err)
	}
	other := f.newTenant(t)
	f.AddEngagement(t, other, other+"-eng")
	scoped.EngagementIDs = []shared.ID{other + "-eng"}
	if _, err := f.Repository.CreateRule(f.ctx, scoped); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rule on another tenant's engagement = %v, want ErrNotFound", err)
	}
	if _, err := f.Repository.GetRule(f.ctx, f.tenant, "scoped"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a refused rule was stored: %v", err)
	}

	own := f.tenant + "-eng"
	f.AddEngagement(t, f.tenant, own)
	scoped.EngagementIDs = []shared.ID{own}
	if _, err := f.Repository.CreateRule(f.ctx, scoped); err != nil {
		t.Fatalf("rule on an existing engagement: %v", err)
	}
	got, err := f.Repository.GetRule(f.ctx, f.tenant, "scoped")
	if err != nil || !reflect.DeepEqual(got.EngagementIDs, []shared.ID{own}) || !reflect.DeepEqual(got.ChannelIDs, []shared.ID{channel.ID}) {
		t.Fatalf("get rule = %+v, %v", got, err)
	}
	if _, err := f.Repository.UpdateRule(f.ctx, scoped); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("update at the current revision = %v, want ErrConflict", err)
	}
	if err := f.Repository.DeleteRule(f.ctx, f.tenant, "scoped", 2); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("delete at a stale revision = %v, want ErrConflict", err)
	}
	if err := f.Repository.DeleteRule(f.ctx, f.tenant, "scoped", 1); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	if rules, err := f.Repository.ListRules(f.ctx, f.tenant); err != nil || len(rules) != 0 {
		t.Fatalf("list after delete = %+v, %v, want empty", rules, err)
	}
}

func (f *fixture) publishTest(t *testing.T, channel shared.ID, n int) shared.ID {
	t.Helper()
	e := notification.Event{TenantID: f.tenant, ID: shared.ID(fmt.Sprintf("test-event-%d", n)), Type: notification.EventTest,
		SourceKind: "notification_test", SourceID: fmt.Sprintf("test-%d", n), SchemaVersion: 1, OccurredAt: f.base,
		Data: json.RawMessage(`{"title":"Test notification"}`)}
	id, err := f.Repository.PublishToChannel(f.ctx, e, channel)
	if err != nil {
		t.Fatalf("publish test %d: %v", n, err)
	}
	return id
}

func eventKeepsSubjectAndContext(t *testing.T, f *fixture) {
	channel := f.channel(t, f.tenant, "hook")
	snapshot := json.RawMessage(`{"vars":{"event_type":"notification.test","occurred_at":"2026-09-27T08:00:00Z"}}`)
	e := notification.Event{TenantID: f.tenant, ID: "test-event-context", Type: notification.EventTest, SourceKind: "notification_test",
		SourceID: "test-context", SchemaVersion: 1, OccurredAt: f.base, Data: json.RawMessage(`{"title":"Test notification"}`),
		SubjectKind: "channel", SubjectID: channel.ID.String(), Context: snapshot}
	id, err := f.Repository.PublishToChannel(f.ctx, e, channel.ID)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	w := f.work(t, id)
	if w.Event.SubjectKind != "channel" || w.Event.SubjectID != channel.ID.String() {
		t.Fatalf("subject = %q/%q", w.Event.SubjectKind, w.Event.SubjectID)
	}
	got, err := notification.DecodeTemplateContext(w.Event.Context)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Vars) != 2 || got.Vars["event_type"] != "notification.test" || got.Vars["occurred_at"] != "2026-09-27T08:00:00Z" {
		t.Fatalf("context = %+v", got)
	}

	// An event published without a snapshot loads with an empty one, as every event projected
	// before the builders existed does.
	plain := f.work(t, f.publishTest(t, channel.ID, 1))
	if empty, err := notification.DecodeTemplateContext(plain.Event.Context); err != nil || len(empty.Vars) != 0 || plain.Event.SubjectID != "" {
		t.Fatalf("event without a snapshot = %+v/%q, %v", empty, plain.Event.SubjectID, err)
	}
}

func channelKeepsDataClass(t *testing.T, f *fixture) {
	plain := f.channel(t, f.tenant, "plain")
	if plain.DataClass != notification.DataClassSummary {
		t.Fatalf("a webhook without a class = %q, want summary", plain.DataClass)
	}
	detailed := notification.Channel{TenantID: f.tenant, ID: "detailed", Name: "detailed", Type: notification.ChannelWebhook, Enabled: true,
		Destination: "https://hooks.example.test", Revision: 1, SecretVersion: 1, CreatedAt: f.base, UpdatedAt: f.base, DataClass: notification.DataClassDetail}
	if _, err := f.Repository.CreateChannel(f.ctx, detailed, sealedConfig("detailed", 1)); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Repository.GetChannel(f.ctx, f.tenant, "detailed"); err != nil || got.DataClass != notification.DataClassDetail {
		t.Fatalf("stored class = %+v, %v", got, err)
	}
	plain.DataClass, plain.Revision, plain.UpdatedAt = notification.DataClassSignal, 2, f.at(time.Second)
	if _, err := f.Repository.UpdateChannel(f.ctx, plain, "", false); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Repository.GetChannel(f.ctx, f.tenant, "plain"); err != nil || got.DataClass != notification.DataClassSignal {
		t.Fatalf("updated class = %+v, %v", got, err)
	}
	if w := f.work(t, f.publishTest(t, "detailed", 1)); w.Channel.DataClass != notification.DataClassDetail {
		t.Fatalf("work channel class = %q", w.Channel.DataClass)
	}
}

func engagementOverrideReachesWork(t *testing.T, f *fixture) {
	f.AddEngagement(t, f.tenant, "eng-1")
	if _, err := f.Repository.GetEngagementNotificationSetting(f.ctx, f.tenant, "eng-unknown"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown engagement = %v, want ErrNotFound", err)
	}
	current, err := f.Repository.GetEngagementNotificationSetting(f.ctx, f.tenant, "eng-1")
	if err != nil || current.ExternalNotifications != notification.EngagementNotificationsInherit || current.Revision != 0 {
		t.Fatalf("default = %+v, %v", current, err)
	}
	at := f.at(time.Second)
	setting := notification.EngagementNotificationSetting{TenantID: f.tenant, EngagementID: "eng-1", ExternalNotifications: notification.EngagementNotificationsNone,
		Revision: 1, UpdatedAt: &at, UpdatedBy: "admin"}
	if _, err := f.Repository.PutEngagementNotificationSetting(f.ctx, setting); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := f.Repository.PutEngagementNotificationSetting(f.ctx, setting); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second revision 1 = %v, want ErrConflict", err)
	}
	skipped := setting
	skipped.Revision = 3
	if _, err := f.Repository.PutEngagementNotificationSetting(f.ctx, skipped); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("skipped revision = %v, want ErrConflict", err)
	}
	stored, err := f.Repository.GetEngagementNotificationSetting(f.ctx, f.tenant, "eng-1")
	if err != nil || stored.ExternalNotifications != notification.EngagementNotificationsNone || stored.Revision != 1 || stored.UpdatedBy != "admin" {
		t.Fatalf("stored = %+v, %v", stored, err)
	}

	channel := f.channel(t, f.tenant, "hook")
	e := notification.Event{TenantID: f.tenant, ID: "test-event-engagement", Type: notification.EventTest, SourceKind: "notification_test",
		SourceID: "test-engagement", EngagementID: "eng-1", SchemaVersion: 1, OccurredAt: f.base, Data: json.RawMessage(`{"title":"Test notification"}`)}
	id, err := f.Repository.PublishToChannel(f.ctx, e, channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.work(t, id); w.Engagement != notification.EngagementNotificationsNone {
		t.Fatalf("work engagement override = %q, want none", w.Engagement)
	}
	if w := f.work(t, f.publishTest(t, channel.ID, 2)); w.Engagement != notification.EngagementNotificationsInherit {
		t.Fatalf("an event without an engagement = %q, want inherit", w.Engagement)
	}
}

func channelPublicationIsListedPagedAndLoaded(t *testing.T, f *fixture) {
	channel := f.channel(t, f.tenant, "hook")
	bystander := f.channel(t, f.tenant, "bystander")
	published := map[shared.ID]bool{}
	for n := range 3 {
		published[f.publishTest(t, channel.ID, n)] = true
	}
	if len(published) != 3 {
		t.Fatalf("three publications produced %d distinct deliveries", len(published))
	}
	if page, err := f.Repository.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant, ChannelID: bystander.ID}); err != nil || len(page.Items) != 0 {
		t.Fatalf("the other channel received %+v, %v", page.Items, err)
	}

	first, err := f.Repository.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant, Limit: 2})
	if err != nil || len(first.Items) != 2 || first.Next == "" {
		t.Fatalf("first page = %+v, %v, want two items and a cursor", first, err)
	}
	cursorAt, cursorID, _ := strings.Cut(first.Next, "|")
	before, err := time.Parse(time.RFC3339Nano, cursorAt)
	if err != nil {
		t.Fatalf("cursor %q: %v", first.Next, err)
	}
	second, err := f.Repository.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant, Limit: 2, Before: before, BeforeID: shared.ID(cursorID)})
	if err != nil || len(second.Items) != 1 || second.Next != "" {
		t.Fatalf("second page = %+v, %v, want the last item and no cursor", second, err)
	}
	seen := map[shared.ID]bool{}
	for _, d := range append(first.Items, second.Items...) {
		if !published[d.ID] || seen[d.ID] {
			t.Fatalf("paging returned %s twice or unpublished", d.ID)
		}
		seen[d.ID] = true
	}
	for name, filter := range map[string]ports.NotificationDeliveryFilter{
		"another event type": {EventType: notification.EventScanCompleted},
		"another state":      {State: notification.DeliveryCancelled},
		"created before":     {Until: f.base.Add(-time.Hour)},
		"created after":      {From: time.Now().Add(time.Hour)},
	} {
		filter.TenantID = f.tenant
		if page, err := f.Repository.ListDeliveries(f.ctx, filter); err != nil || len(page.Items) != 0 {
			t.Fatalf("filter on %s = %+v, %v, want nothing", name, page.Items, err)
		}
	}
	if page, err := f.Repository.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant, EventType: notification.EventTest,
		State: notification.DeliveryPending, From: f.base.Add(-time.Hour), Until: time.Now().Add(time.Hour)}); err != nil || len(page.Items) != 3 {
		t.Fatalf("filters matching every delivery = %d items, %v, want 3", len(page.Items), err)
	}

	for id := range published {
		d, err := f.Repository.GetDelivery(f.ctx, f.tenant, id)
		if err != nil || d.State != notification.DeliveryPending || d.ChannelID != channel.ID {
			t.Fatalf("get delivery %s = %+v, %v", id, d, err)
		}
		if attempts, err := f.Repository.ListAttempts(f.ctx, f.tenant, id); err != nil || len(attempts) != 0 {
			t.Fatalf("attempts of an unsent delivery = %+v, %v", attempts, err)
		}
		if w := f.work(t, id); w.Event.Type != notification.EventTest || w.Sealed != sealedConfig(channel.ID, 1) {
			t.Fatalf("work = %+v, want the test event with the channel's version-1 configuration", w)
		}
		if _, err := f.Repository.GetDelivery(f.ctx, f.newTenant(t), id); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("another tenant read delivery %s: %v", id, err)
		}
	}
	if _, err := f.Repository.GetDelivery(f.ctx, f.tenant, "no-such-delivery"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing delivery = %v, want ErrNotFound", err)
	}
	if _, err := f.Repository.ListAttempts(f.ctx, f.tenant, "no-such-delivery"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("attempts of a missing delivery = %v, want ErrNotFound", err)
	}
	if _, err := f.Repository.LoadWork(f.ctx, f.tenant, "no-such-delivery"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("work of a missing delivery = %v, want ErrNotFound", err)
	}

	// A delivery keeps the configuration version it was created with when the channel's secret is replaced.
	rotated := channel
	rotated.Revision, rotated.UpdatedAt = 2, f.at(time.Second)
	if _, err := f.Repository.UpdateChannel(f.ctx, rotated, sealedConfig(channel.ID, 2), true); err != nil {
		t.Fatalf("replace secret: %v", err)
	}
	for id := range published {
		if w := f.work(t, id); w.Sealed != sealedConfig(channel.ID, 1) || w.Channel.SecretVersion != 1 {
			t.Fatalf("work after rotation = version %d %q, want the version-1 configuration", w.Channel.SecretVersion, w.Sealed)
		}
	}
	if w := f.work(t, f.publishTest(t, channel.ID, 3)); w.Sealed != sealedConfig(channel.ID, 2) || w.Channel.SecretVersion != 2 {
		t.Fatalf("work after rotation = version %d %q, want new deliveries on version 2", w.Channel.SecretVersion, w.Sealed)
	}
}

func channelTestsAreRateLimited(t *testing.T, f *fixture) {
	channel := f.channel(t, f.tenant, "hook")
	other := f.channel(t, f.tenant, "other")
	for n := range 10 {
		f.publishTest(t, channel.ID, n)
	}
	e := notification.Event{TenantID: f.tenant, ID: "test-event-over", Type: notification.EventTest, SourceKind: "notification_test",
		SourceID: "test-over", SchemaVersion: 1, OccurredAt: f.base, Data: json.RawMessage(`{"title":"Test notification"}`)}
	if _, err := f.Repository.PublishToChannel(f.ctx, e, channel.ID); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("eleventh test within a minute = %v, want ErrSaturated", err)
	}
	// The limit is per channel.
	if _, err := f.Repository.PublishToChannel(f.ctx, e, other.ID); err != nil {
		t.Fatalf("test to another channel: %v", err)
	}
	disabled := other
	disabled.Enabled, disabled.Revision, disabled.UpdatedAt = false, 2, f.at(time.Second)
	if _, err := f.Repository.UpdateChannel(f.ctx, disabled, "", false); err != nil {
		t.Fatalf("disable channel: %v", err)
	}
	e.ID, e.SourceID = "test-event-disabled", "test-disabled"
	if _, err := f.Repository.PublishToChannel(f.ctx, e, other.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("test to a disabled channel = %v, want ErrNotFound", err)
	}
}

func closingChannelCancelsDeliveries(t *testing.T, f *fixture) {
	disabled := f.channel(t, f.tenant, "disabled")
	deleted := f.channel(t, f.tenant, "deleted")
	toDisable, toDelete := f.publishTest(t, disabled.ID, 1), f.publishTest(t, deleted.ID, 2)

	disabled.Enabled, disabled.Revision, disabled.UpdatedAt = false, 2, f.at(time.Second)
	if _, err := f.Repository.UpdateChannel(f.ctx, disabled, "", false); err != nil {
		t.Fatalf("disable channel: %v", err)
	}
	if err := f.Repository.DeleteChannel(f.ctx, f.tenant, deleted.ID, 1, f.at(time.Second)); err != nil {
		t.Fatalf("delete channel: %v", err)
	}
	for id, reason := range map[shared.ID]string{toDisable: "channel_disabled", toDelete: "channel_deleted"} {
		d, err := f.Repository.GetDelivery(f.ctx, f.tenant, id)
		if err != nil || d.State != notification.DeliveryCancelled || d.LastError != reason {
			t.Fatalf("delivery %s = %+v, %v, want cancelled with %s", id, d, err, reason)
		}
	}
}

func retargetingChannelCancelsDeliveries(t *testing.T, f *fixture) {
	moved := f.channel(t, f.tenant, "moved")
	rotated := f.channel(t, f.tenant, "rotated")
	both := f.channel(t, f.tenant, "both")
	renamed := f.channel(t, f.tenant, "renamed")
	toMoved, toRotated, toBoth := f.publishTest(t, moved.ID, 1), f.publishTest(t, rotated.ID, 2), f.publishTest(t, both.ID, 3)
	untouched := f.publishTest(t, renamed.ID, 4)

	moved.Destination, moved.Revision, moved.UpdatedAt = "https://hooks.example.test/moved", 2, f.at(time.Second)
	if _, err := f.Repository.UpdateChannel(f.ctx, moved, "", false); err != nil {
		t.Fatalf("move channel: %v", err)
	}
	rotated.Revision, rotated.UpdatedAt = 2, f.at(time.Second)
	if _, err := f.Repository.UpdateChannel(f.ctx, rotated, sealedConfig(rotated.ID, 2), true); err != nil {
		t.Fatalf("rotate channel secret: %v", err)
	}
	// Disabling wins over a secret rotation in the same call: the delivery is cancelled once.
	both.Enabled, both.Revision, both.UpdatedAt = false, 2, f.at(time.Second)
	if _, err := f.Repository.UpdateChannel(f.ctx, both, sealedConfig(both.ID, 2), true); err != nil {
		t.Fatalf("disable and rotate channel: %v", err)
	}
	renamed.Name, renamed.Revision, renamed.UpdatedAt = "renamed hook", 2, f.at(time.Second)
	if _, err := f.Repository.UpdateChannel(f.ctx, renamed, "", false); err != nil {
		t.Fatalf("rename channel: %v", err)
	}
	for id, reason := range map[shared.ID]string{toMoved: "destination_changed", toRotated: "destination_changed", toBoth: "channel_disabled"} {
		d, err := f.Repository.GetDelivery(f.ctx, f.tenant, id)
		if err != nil || d.State != notification.DeliveryCancelled || d.LastError != reason {
			t.Fatalf("delivery %s = %+v, %v, want cancelled with %s", id, d, err, reason)
		}
	}
	if d, err := f.Repository.GetDelivery(f.ctx, f.tenant, untouched); err != nil || d.State != notification.DeliveryPending {
		t.Fatalf("a rename cancelled delivery %s: %+v, %v", untouched, d, err)
	}
}

func permanentFailuresPauseChannel(t *testing.T, f *fixture) {
	channel := f.channel(t, f.tenant, "failing")
	queued := f.publishTest(t, channel.ID, 1)
	failure := func(n int) ports.NotificationChannelOutcome {
		return ports.NotificationChannelOutcome{ChannelID: channel.ID, DeliveryID: queued, AttemptID: shared.ID(fmt.Sprintf("attempt-%d", n)),
			Class: notification.AttemptPermanent, Code: "http_404", At: f.at(time.Duration(n) * time.Second), Threshold: 2}
	}
	first, err := f.Repository.RecordChannelOutcome(f.ctx, f.tenant, failure(1))
	if err != nil || first.Paused || first.Health.ConsecutiveFailures != 1 {
		t.Fatalf("first failure = %+v, %v, want counted without a pause", first, err)
	}
	second, err := f.Repository.RecordChannelOutcome(f.ctx, f.tenant, failure(2))
	if err != nil || !second.Paused || second.PauseID.IsZero() || !second.Health.Paused() {
		t.Fatalf("second failure = %+v, %v, want the pause", second, err)
	}
	paused, err := f.Repository.GetChannel(f.ctx, f.tenant, channel.ID)
	if err != nil || !paused.Health.Paused() || paused.Health.LastFailureCode != "http_404" || paused.Revision != channel.Revision {
		t.Fatalf("paused channel = %+v, %v, want paused health and an unchanged revision", paused, err)
	}
	if d, err := f.Repository.GetDelivery(f.ctx, f.tenant, queued); err != nil || d.State != notification.DeliveryCancelled || d.LastError != "channel_paused" {
		t.Fatalf("queued delivery = %+v, %v, want cancelled with channel_paused", d, err)
	}
	test := notification.Event{TenantID: f.tenant, ID: "test-event-paused", Type: notification.EventTest, SourceKind: "notification_test",
		SourceID: "test-paused", SchemaVersion: 1, OccurredAt: f.base, Data: json.RawMessage(`{"title":"Test notification"}`)}
	if _, err := f.Repository.PublishToChannel(f.ctx, test, channel.ID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("test to a paused channel = %v, want ErrConflict", err)
	}
	// Once paused, further outcomes change nothing until an administrator resumes.
	if later, err := f.Repository.RecordChannelOutcome(f.ctx, f.tenant, failure(3)); err != nil || later.Paused || later.Health.ConsecutiveFailures != 2 {
		t.Fatalf("failure while paused = %+v, %v", later, err)
	}

	if _, err := f.Repository.ResumeChannel(f.ctx, f.tenant, channel.ID, channel.Revision+1, "admin", f.at(10*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("resume with a stale revision = %v, want ErrConflict", err)
	}
	resumed, err := f.Repository.ResumeChannel(f.ctx, f.tenant, channel.ID, channel.Revision, "admin", f.at(10*time.Second))
	if err != nil || resumed.Health.Paused() || resumed.Health.ConsecutiveFailures != 0 || resumed.Revision != channel.Revision+1 {
		t.Fatalf("resume = %+v, %v, want an active channel at the next revision", resumed, err)
	}
	if _, err := f.Repository.ResumeChannel(f.ctx, f.tenant, channel.ID, resumed.Revision, "admin", f.at(11*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("resume of an active channel = %v, want ErrConflict", err)
	}
	history, err := f.Repository.ListChannelHealthEvents(f.ctx, f.tenant, channel.ID, 0)
	if err != nil || len(history) != 2 {
		t.Fatalf("history = %+v, %v, want a pause and a resume", history, err)
	}
	resume, pause := history[0], history[1]
	if resume.Action != notification.HealthActionResumed || resume.Actor != "admin" ||
		pause.Action != notification.HealthActionPaused || pause.ID != second.PauseID || pause.DeliveryID != queued ||
		pause.AttemptID != "attempt-2" || pause.Failures != 2 || pause.FailureCode != "http_404" {
		t.Fatalf("history = %+v, want the resume then the pause", history)
	}
}

func invalidRecordIsQuarantined(t *testing.T, f *fixture) {
	f.routed(t)
	f.mustAppend(t, scanRecord(f.tenant, "scan-oversized", f.at(time.Second), strings.Repeat("x", 17<<10)))
	f.mustAppend(t, scanRecord(f.tenant, "scan-valid", f.at(2*time.Second), "Scan completed"))
	f.poll(t, 3*time.Second)
	f.poll(t, 4*time.Second)

	deliveries := f.deliveries(t, f.tenant)
	if len(deliveries) != 1 {
		t.Fatalf("deliveries = %d, want only the valid record's", len(deliveries))
	}
	if w := f.work(t, deliveries[0].ID); w.Event.SourceID != "scan-valid" {
		t.Fatalf("delivered source = %s, want scan-valid", w.Event.SourceID)
	}
	page, err := f.Repository.ListSourceFailures(f.ctx, ports.NotificationSourceFailureFilter{TenantID: f.tenant, EventType: notification.EventScanCompleted})
	if err != nil || len(page.Items) != 1 || page.NextOffset != nil {
		t.Fatalf("source failures = %+v, %v, want one", page, err)
	}
	if got := page.Items[0]; got.SourceKind != "scan_job" || got.SourceID != "scan-oversized" || got.FailedReason != "event_data_too_large" || !got.ProcessedAt.Equal(f.at(3*time.Second)) {
		t.Fatalf("source failure = %+v", got)
	}
	if other, err := f.Repository.ListSourceFailures(f.ctx, ports.NotificationSourceFailureFilter{TenantID: f.tenant, EventType: notification.EventQualityGateFailed}); err != nil || len(other.Items) != 0 {
		t.Fatalf("event type filter = %+v, %v", other, err)
	}
}

func channelCountIsCapped(t *testing.T, f *fixture) {
	const capacity = 50
	for n := range capacity {
		f.channel(t, f.tenant, shared.ID(fmt.Sprintf("hook-%02d", n)))
	}
	over := notification.Channel{TenantID: f.tenant, ID: "one-too-many", Name: "one too many", Type: notification.ChannelWebhook, Enabled: true,
		Revision: 1, SecretVersion: 1, CreatedAt: f.base, UpdatedAt: f.base}
	if _, err := f.Repository.CreateChannel(f.ctx, over, "sealed"); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("channel %d = %v, want ErrSaturated", capacity+1, err)
	}
	// Deleting one frees its slot.
	if err := f.Repository.DeleteChannel(f.ctx, f.tenant, "hook-00", 1, f.at(time.Second)); err != nil {
		t.Fatalf("delete channel: %v", err)
	}
	if _, err := f.Repository.CreateChannel(f.ctx, over, "sealed"); err != nil {
		t.Fatalf("channel after freeing a slot: %v", err)
	}
}

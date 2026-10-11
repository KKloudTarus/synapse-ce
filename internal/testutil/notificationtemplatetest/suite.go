// Package notificationtemplatetest is the conformance suite for ports.NotificationTemplateStore
// (#1369). The memory and PostgreSQL stores both run it, so the in-memory store used by handler
// tests behaves like production.
package notificationtemplatetest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Tenants the suite writes to. A PostgreSQL factory must create both tenant rows.
const (
	TenantA shared.ID = "tenant-a"
	TenantB shared.ID = "tenant-b"
)

// Factory returns an empty store. Each subtest calls it once.
type Factory func(t *testing.T) ports.NotificationTemplateStore

var at = time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)

// Run runs every conformance case against stores made by newStore.
func Run(t *testing.T, newStore Factory) {
	cases := []struct {
		name string
		fn   func(*testing.T, ports.NotificationTemplateStore)
	}{
		{"CreateStoresDraftVersionOne", testCreate},
		{"CreateRejectsInvalidInput", testCreateRejects},
		{"AppendAddsVersionWithoutChangingWhatRenders", testAppend},
		{"ActivateAndRollBack", testActivateAndRollback},
		{"ActivatingArchivesTheKeysPreviousTemplate", testOneActivePerKey},
		{"ArchiveStopsResolution", testArchive},
		{"StaleRevisionIsConflict", testStaleRevision},
		{"CrossTenantAccessIsNotFound", testCrossTenant},
		{"ListFiltersAndPages", testList},
		{"VersionsPageNewestFirst", testVersionPages},
		{"ReturnedFieldsAreCopies", testFieldsAreCopies},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newStore(t)) })
	}
}

func chatKey(event notification.EventType) notification.TemplateKey {
	return notification.TemplateKey{EventType: event, Family: notification.FamilyChat, Locale: "en"}
}

func newTemplate(tenant, id shared.ID, key notification.TemplateKey) notification.Template {
	return notification.Template{TenantID: tenant, ID: id, Name: "Template " + id.String(), TemplateKey: key, CreatedAt: at, CreatedBy: "admin"}
}

func chatFields(title string) map[string]string {
	return map[string]string{"title": title, "body": "Scan {{.scan_id}} finished."}
}

func mustCreate(t *testing.T, s ports.NotificationTemplateStore, tenant, id shared.ID, key notification.TemplateKey) notification.Template {
	t.Helper()
	head, _, err := s.CreateNotificationTemplate(context.Background(), newTemplate(tenant, id, key), chatFields("v1"))
	if err != nil {
		t.Fatalf("create %s: %v", id, err)
	}
	return head
}

func change(tenant, id shared.ID, version, revision int) ports.NotificationTemplateChange {
	return ports.NotificationTemplateChange{TenantID: tenant, ID: id, Version: version, ExpectedRevision: revision, Actor: "admin", At: at.Add(time.Minute)}
}

func update(tenant, id shared.ID, title string, revision int) ports.NotificationTemplateUpdate {
	return ports.NotificationTemplateUpdate{TenantID: tenant, ID: id, Fields: chatFields(title), ExpectedRevision: revision, Actor: "editor", At: at.Add(time.Minute)}
}

func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: want %v, got %v", what, want, err)
	}
}

func testCreate(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	head, v, err := s.CreateNotificationTemplate(ctx, newTemplate(TenantA, "tpl-1", chatKey(notification.EventScanCompleted)), chatFields("Scan done"))
	if err != nil {
		t.Fatal(err)
	}
	if head.Status != notification.TemplateDraft || head.LatestVersion != 1 || head.ActiveVersion != 0 || head.Revision != 1 || head.UpdatedBy != "admin" {
		t.Fatalf("created head = %+v", head)
	}
	if v.Version != 1 || v.Fields["title"] != "Scan done" || v.Checksum != notification.TemplateChecksum(chatFields("Scan done")) || v.CreatedBy != "admin" {
		t.Fatalf("created version = %+v", v)
	}
	got, err := s.GetNotificationTemplate(ctx, TenantA, "tpl-1")
	if err != nil || got.TemplateKey != chatKey(notification.EventScanCompleted) || got.Name != "Template tpl-1" || !got.CreatedAt.Equal(at) {
		t.Fatalf("read back = %+v, %v", got, err)
	}
	stored, err := s.GetNotificationTemplateVersion(ctx, TenantA, "tpl-1", 1)
	if err != nil || stored.Checksum != v.Checksum || stored.Fields["body"] != v.Fields["body"] {
		t.Fatalf("version read back = %+v, %v", stored, err)
	}
	_, _, err = s.CreateNotificationTemplate(ctx, newTemplate(TenantA, "tpl-1", chatKey(notification.EventIncidentCreated)), chatFields("again"))
	wantErr(t, "duplicate id", err, shared.ErrConflict)
	// Wildcard keys are valid.
	wild := notification.TemplateKey{EventType: notification.AnyEventType, Family: notification.FamilyWebhook, Locale: notification.AnyLocale}
	if _, _, err := s.CreateNotificationTemplate(ctx, newTemplate(TenantA, "tpl-wild", wild), map[string]string{"body": `{"text":"{{.title}}"}`}); err != nil {
		t.Fatalf("wildcard template: %v", err)
	}
}

func testCreateRejects(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	key := chatKey(notification.EventScanCompleted)
	cases := []struct {
		name   string
		mutate func(*notification.Template)
		fields map[string]string
	}{
		{"unknown event type", func(tp *notification.Template) { tp.EventType = "made.up" }, nil},
		{"free-text family", func(tp *notification.Template) { tp.Family = "sms" }, nil},
		{"unsupported locale", func(tp *notification.Template) { tp.Locale = "fr" }, nil},
		{"blank name", func(tp *notification.Template) { tp.Name = " " }, nil},
		{"name with surrounding space", func(tp *notification.Template) { tp.Name = " padded" }, nil},
		{"missing id", func(tp *notification.Template) { tp.ID = "" }, nil},
		{"missing actor", func(tp *notification.Template) { tp.CreatedBy = "" }, nil},
		{"field of another family", nil, map[string]string{"subject": "x"}},
		{"no fields", nil, map[string]string{}},
		{"only blank fields", nil, map[string]string{"title": "  ", "body": ""}},
		{"oversized field", nil, map[string]string{"body": strings.Repeat("a", notification.MaxTemplateFieldBytes+1)}},
		{"NUL in field", nil, map[string]string{"body": "a\x00b"}},
	}
	for _, tc := range cases {
		tpl := newTemplate(TenantA, "tpl-bad", key)
		if tc.mutate != nil {
			tc.mutate(&tpl)
		}
		fields := tc.fields
		if fields == nil {
			fields = chatFields("ok")
		}
		_, _, err := s.CreateNotificationTemplate(ctx, tpl, fields)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", tc.name, err)
		}
		if err != nil && strings.Contains(err.Error(), strings.Repeat("a", 64)) {
			t.Errorf("%s: the error echoes template source", tc.name)
		}
	}
	if _, err := s.GetNotificationTemplate(ctx, TenantA, "tpl-bad"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a rejected template was stored: %v", err)
	}
}

func testAppend(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	mustCreate(t, s, TenantA, "tpl-1", chatKey(notification.EventScanCompleted))
	u := update(TenantA, "tpl-1", "v2", 1)
	u.Name = "Renamed"
	head, v, err := s.AppendNotificationTemplateVersion(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if head.LatestVersion != 2 || head.ActiveVersion != 0 || head.Status != notification.TemplateDraft || head.Revision != 2 || head.Name != "Renamed" || head.UpdatedBy != "editor" || head.CreatedBy != "admin" {
		t.Fatalf("head after append = %+v", head)
	}
	if v.Version != 2 || v.Fields["title"] != "v2" || v.CreatedBy != "editor" {
		t.Fatalf("appended version = %+v", v)
	}
	first, err := s.GetNotificationTemplateVersion(ctx, TenantA, "tpl-1", 1)
	if err != nil || first.Fields["title"] != "v1" {
		t.Fatalf("version 1 changed: %+v, %v", first, err)
	}
	// An empty name keeps the current one.
	head, _, err = s.AppendNotificationTemplateVersion(ctx, update(TenantA, "tpl-1", "v3", 2))
	if err != nil || head.Name != "Renamed" || head.LatestVersion != 3 {
		t.Fatalf("append without a name = %+v, %v", head, err)
	}
	bad := update(TenantA, "tpl-1", "x", 3)
	bad.Fields = map[string]string{"summary": "pager field on a chat template"}
	_, _, err = s.AppendNotificationTemplateVersion(ctx, bad)
	wantErr(t, "field of another family", err, shared.ErrValidation)
	_, _, err = s.AppendNotificationTemplateVersion(ctx, update(TenantA, "missing", "x", 1))
	wantErr(t, "append to a missing template", err, shared.ErrNotFound)
	if got, _ := s.GetNotificationTemplate(ctx, TenantA, "tpl-1"); got.LatestVersion != 3 || got.Revision != 3 {
		t.Fatalf("a refused append changed the head: %+v", got)
	}
}

func testActivateAndRollback(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	key := chatKey(notification.EventScanCompleted)
	mustCreate(t, s, TenantA, "tpl-1", key)
	if _, _, err := s.AppendNotificationTemplateVersion(ctx, update(TenantA, "tpl-1", "v2", 1)); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := s.ActiveNotificationTemplate(ctx, TenantA, key); err != nil || found {
		t.Fatalf("a draft resolved: found=%v err=%v", found, err)
	}
	head, archived, err := s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-1", 0, 2))
	if err != nil || archived != "" || head.Status != notification.TemplateActive || head.ActiveVersion != 2 || head.Revision != 3 {
		t.Fatalf("activate latest = %+v archived=%q err=%v", head, archived, err)
	}
	active, v, found, err := s.ActiveNotificationTemplate(ctx, TenantA, key)
	if err != nil || !found || active.ID != "tpl-1" || v.Version != 2 || v.Fields["title"] != "v2" {
		t.Fatalf("resolve = %+v %+v found=%v err=%v", active, v, found, err)
	}
	// A new version is a draft of the next revision: it does not render until activated.
	if _, _, err := s.AppendNotificationTemplateVersion(ctx, update(TenantA, "tpl-1", "v3", 3)); err != nil {
		t.Fatal(err)
	}
	if _, v, _, _ := s.ActiveNotificationTemplate(ctx, TenantA, key); v.Version != 2 {
		t.Fatalf("appending changed the rendered version to %d", v.Version)
	}
	// Rollback is activating an earlier version.
	head, _, err = s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-1", 1, 4))
	if err != nil || head.ActiveVersion != 1 || head.LatestVersion != 3 {
		t.Fatalf("rollback = %+v, %v", head, err)
	}
	if _, v, _, _ := s.ActiveNotificationTemplate(ctx, TenantA, key); v.Version != 1 || v.Fields["title"] != "v1" {
		t.Fatalf("rollback renders %+v", v)
	}
	_, _, err = s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-1", 9, 5))
	wantErr(t, "activate a missing version", err, shared.ErrNotFound)
	_, _, err = s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-1", -1, 5))
	wantErr(t, "negative version", err, shared.ErrValidation)
}

func testOneActivePerKey(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	key := chatKey(notification.EventScanCompleted)
	mustCreate(t, s, TenantA, "tpl-a", key)
	mustCreate(t, s, TenantA, "tpl-b", key)
	vi := key
	vi.Locale = "vi"
	mustCreate(t, s, TenantA, "tpl-vi", vi)
	wild := key
	wild.EventType = notification.AnyEventType
	mustCreate(t, s, TenantA, "tpl-any", wild)
	mustCreate(t, s, TenantB, "tpl-other-tenant", key)

	for _, id := range []shared.ID{"tpl-a", "tpl-vi", "tpl-any"} {
		if _, archived, err := s.ActivateNotificationTemplate(ctx, change(TenantA, id, 0, 1)); err != nil || archived != "" {
			t.Fatalf("activate %s: archived=%q err=%v", id, archived, err)
		}
	}
	if _, archived, err := s.ActivateNotificationTemplate(ctx, change(TenantB, "tpl-other-tenant", 0, 1)); err != nil || archived != "" {
		t.Fatalf("another tenant's key is independent: archived=%q err=%v", archived, err)
	}
	head, archived, err := s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-b", 0, 1))
	if err != nil || archived != "tpl-a" || head.Status != notification.TemplateActive {
		t.Fatalf("activate tpl-b = %+v archived=%q err=%v", head, archived, err)
	}
	previous, err := s.GetNotificationTemplate(ctx, TenantA, "tpl-a")
	if err != nil || previous.Status != notification.TemplateArchived || previous.Revision != 3 || previous.ActiveVersion != 1 {
		t.Fatalf("replaced template = %+v, %v", previous, err)
	}
	active, err := s.ListNotificationTemplates(ctx, TenantA, ports.NotificationTemplateQuery{Status: notification.TemplateActive})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(active))
	for _, head := range active {
		ids = append(ids, head.ID.String())
	}
	if strings.Join(ids, ",") != "tpl-any,tpl-b,tpl-vi" {
		t.Fatalf("active templates = %v, want one per key", ids)
	}
	if got, _, _, _ := s.ActiveNotificationTemplate(ctx, TenantA, key); got.ID != "tpl-b" {
		t.Fatalf("resolves to %q, want tpl-b", got.ID)
	}
	if got, _, _, _ := s.ActiveNotificationTemplate(ctx, TenantB, key); got.ID != "tpl-other-tenant" {
		t.Fatalf("tenant B resolves to %q", got.ID)
	}
}

func testArchive(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	key := chatKey(notification.EventIncidentCreated)
	mustCreate(t, s, TenantA, "tpl-1", key)
	if _, _, err := s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-1", 0, 1)); err != nil {
		t.Fatal(err)
	}
	head, err := s.ArchiveNotificationTemplate(ctx, change(TenantA, "tpl-1", 0, 2))
	if err != nil || head.Status != notification.TemplateArchived || head.ActiveVersion != 1 || head.Revision != 3 {
		t.Fatalf("archive = %+v, %v", head, err)
	}
	if _, _, found, err := s.ActiveNotificationTemplate(ctx, TenantA, key); err != nil || found {
		t.Fatalf("an archived template resolved: found=%v err=%v", found, err)
	}
	if head, _, err = s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-1", 1, 3)); err != nil || head.Status != notification.TemplateActive {
		t.Fatalf("reactivate = %+v, %v", head, err)
	}
	_, err = s.ArchiveNotificationTemplate(ctx, change(TenantA, "missing", 0, 1))
	wantErr(t, "archive a missing template", err, shared.ErrNotFound)
}

func testStaleRevision(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	mustCreate(t, s, TenantA, "tpl-1", chatKey(notification.EventScanCompleted))
	_, _, err := s.AppendNotificationTemplateVersion(ctx, update(TenantA, "tpl-1", "v2", 7))
	wantErr(t, "stale append", err, shared.ErrConflict)
	_, _, err = s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-1", 0, 7))
	wantErr(t, "stale activate", err, shared.ErrConflict)
	_, err = s.ArchiveNotificationTemplate(ctx, change(TenantA, "tpl-1", 0, 7))
	wantErr(t, "stale archive", err, shared.ErrConflict)
	_, _, err = s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-1", 0, 0))
	wantErr(t, "missing revision", err, shared.ErrValidation)
	if got, _ := s.GetNotificationTemplate(ctx, TenantA, "tpl-1"); got.Revision != 1 || got.Status != notification.TemplateDraft || got.LatestVersion != 1 {
		t.Fatalf("a refused change moved the head: %+v", got)
	}
}

func testCrossTenant(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	key := chatKey(notification.EventScanCompleted)
	mustCreate(t, s, TenantA, "tpl-1", key)
	if _, _, err := s.ActivateNotificationTemplate(ctx, change(TenantA, "tpl-1", 0, 1)); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetNotificationTemplate(ctx, TenantB, "tpl-1")
	wantErr(t, "cross-tenant get", err, shared.ErrNotFound)
	_, err = s.GetNotificationTemplateVersion(ctx, TenantB, "tpl-1", 1)
	wantErr(t, "cross-tenant version", err, shared.ErrNotFound)
	_, err = s.ListNotificationTemplateVersions(ctx, TenantB, "tpl-1", 0, 0)
	wantErr(t, "cross-tenant version list", err, shared.ErrNotFound)
	_, _, err = s.AppendNotificationTemplateVersion(ctx, update(TenantB, "tpl-1", "hijack", 2))
	wantErr(t, "cross-tenant append", err, shared.ErrNotFound)
	_, _, err = s.ActivateNotificationTemplate(ctx, change(TenantB, "tpl-1", 0, 2))
	wantErr(t, "cross-tenant activate", err, shared.ErrNotFound)
	_, err = s.ArchiveNotificationTemplate(ctx, change(TenantB, "tpl-1", 0, 2))
	wantErr(t, "cross-tenant archive", err, shared.ErrNotFound)
	if list, err := s.ListNotificationTemplates(ctx, TenantB, ports.NotificationTemplateQuery{}); err != nil || len(list) != 0 {
		t.Fatalf("tenant B lists %d templates, err=%v", len(list), err)
	}
	if _, _, found, err := s.ActiveNotificationTemplate(ctx, TenantB, key); err != nil || found {
		t.Fatalf("tenant B resolved tenant A's template: found=%v err=%v", found, err)
	}
	// Template IDs are scoped per tenant, so tenant B may reuse one.
	if _, _, err := s.CreateNotificationTemplate(ctx, newTemplate(TenantB, "tpl-1", key), chatFields("b")); err != nil {
		t.Fatalf("tenant B reusing an id: %v", err)
	}
	got, err := s.GetNotificationTemplate(ctx, TenantA, "tpl-1")
	if err != nil || got.Revision != 2 || got.Status != notification.TemplateActive || got.LatestVersion != 1 {
		t.Fatalf("tenant A's template changed: %+v, %v", got, err)
	}
}

func testList(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	mustCreate(t, s, TenantA, "tpl-1", chatKey(notification.EventScanCompleted))
	mustCreate(t, s, TenantA, "tpl-2", chatKey(notification.EventIncidentCreated))
	email := notification.TemplateKey{EventType: notification.EventScanCompleted, Family: notification.FamilyEmail, Locale: "vi"}
	if _, _, err := s.CreateNotificationTemplate(ctx, newTemplate(TenantA, "tpl-3", email), map[string]string{"subject": "s", "body": "b"}); err != nil {
		t.Fatal(err)
	}
	ids := func(q ports.NotificationTemplateQuery) string {
		t.Helper()
		list, err := s.ListNotificationTemplates(ctx, TenantA, q)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(list))
		for _, head := range list {
			out = append(out, head.ID.String())
		}
		return strings.Join(out, ",")
	}
	for _, tc := range []struct {
		q    ports.NotificationTemplateQuery
		want string
	}{
		{ports.NotificationTemplateQuery{}, "tpl-1,tpl-2,tpl-3"},
		{ports.NotificationTemplateQuery{EventType: notification.EventScanCompleted}, "tpl-1,tpl-3"},
		{ports.NotificationTemplateQuery{Family: notification.FamilyEmail}, "tpl-3"},
		{ports.NotificationTemplateQuery{Locale: "en"}, "tpl-1,tpl-2"},
		{ports.NotificationTemplateQuery{Status: notification.TemplateActive}, ""},
		{ports.NotificationTemplateQuery{Limit: 2}, "tpl-1,tpl-2"},
		{ports.NotificationTemplateQuery{AfterID: "tpl-2"}, "tpl-3"},
	} {
		if got := ids(tc.q); got != tc.want {
			t.Errorf("list %+v = %q, want %q", tc.q, got, tc.want)
		}
	}
}

func testVersionPages(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	mustCreate(t, s, TenantA, "tpl-1", chatKey(notification.EventScanCompleted))
	for rev := 1; rev <= 4; rev++ {
		if _, _, err := s.AppendNotificationTemplateVersion(ctx, update(TenantA, "tpl-1", "next", rev)); err != nil {
			t.Fatal(err)
		}
	}
	versions := func(before, limit int) []int {
		t.Helper()
		list, err := s.ListNotificationTemplateVersions(ctx, TenantA, "tpl-1", before, limit)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]int, 0, len(list))
		for _, v := range list {
			out = append(out, v.Version)
		}
		return out
	}
	if got := versions(0, 0); !equalInts(got, []int{5, 4, 3, 2, 1}) {
		t.Fatalf("all versions = %v", got)
	}
	if got := versions(0, 2); !equalInts(got, []int{5, 4}) {
		t.Fatalf("first page = %v", got)
	}
	if got := versions(4, 2); !equalInts(got, []int{3, 2}) {
		t.Fatalf("second page = %v", got)
	}
	if got := versions(1, 2); len(got) != 0 {
		t.Fatalf("past the end = %v", got)
	}
	_, err := s.GetNotificationTemplateVersion(ctx, TenantA, "tpl-1", 6)
	wantErr(t, "missing version", err, shared.ErrNotFound)
}

func testFieldsAreCopies(t *testing.T, s ports.NotificationTemplateStore) {
	ctx := context.Background()
	fields := chatFields("original")
	_, v, err := s.CreateNotificationTemplate(ctx, newTemplate(TenantA, "tpl-1", chatKey(notification.EventScanCompleted)), fields)
	if err != nil {
		t.Fatal(err)
	}
	fields["title"] = "changed by the caller"
	v.Fields["title"] = "changed through the result"
	stored, err := s.GetNotificationTemplateVersion(ctx, TenantA, "tpl-1", 1)
	if err != nil || stored.Fields["title"] != "original" || stored.Checksum != notification.TemplateChecksum(chatFields("original")) {
		t.Fatalf("stored version = %+v, %v", stored, err)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Every remaining source type must be matched inside its own tenant.  This is
// deliberately an adapter test: the positive control proves that the rule is
// routable, while the hostile event proves a same-shaped source in another
// tenant cannot be captured by that rule.
func TestRemainingNotificationRoutingKeepsAllScopedSourcesTenantLocal(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	at := time.Date(2026, time.October, 14, 1, 0, 0, 0, time.UTC)
	tenantA, tenantB := shared.ID("remaining-isolation-a"), shared.ID("remaining-isolation-b")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenantA, tenantB); err != nil {
		t.Fatal(err)
	}

	repo := NewNotificationRepository(pool)
	channel := notification.Channel{
		TenantID: tenantA, ID: "tenant-a-channel", Name: "Tenant A webhook", Type: notification.ChannelWebhook,
		Enabled: true, Destination: "https://tenant-a.example.test/hook", Revision: 1, SecretVersion: 1, CreatedAt: at, UpdatedAt: at,
	}
	if _, err := repo.CreateChannel(shared.WithTenant(ctx, tenantA), channel, "tenant-a-sealed"); err != nil {
		t.Fatal(err)
	}

	ordinary := []notification.EventType{
		notification.EventEngagementCreated,
		notification.EventEngagementStatusChanged,
		notification.EventEngagementWindowStarting,
		notification.EventEngagementWindowEnding,
		notification.EventFindingCommented,
		notification.EventApprovalRequested,
		notification.EventApprovalDecided,
		notification.EventApprovalTimedOut,
		notification.EventIncidentUpdated,
		notification.EventResponseFinished,
		notification.EventEvidenceChainBroken,
	}
	for _, eventType := range ordinary {
		eventType := eventType
		t.Run(string(eventType), func(t *testing.T) {
			rule := notification.Rule{
				TenantID: tenantA, ID: shared.ID("tenant-a-" + string(eventType)), Name: "Tenant A " + string(eventType), Enabled: true,
				EventType: eventType, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: at, UpdatedAt: at,
			}
			if _, err := repo.CreateRule(shared.WithTenant(ctx, tenantA), rule); err != nil {
				t.Fatal(err)
			}

			fromA := remainingIsolationEvent(t, tenantA, eventType, "a-"+string(eventType), at)
			deliveries, err := repo.Publish(shared.WithTenant(ctx, tenantA), fromA)
			if err != nil {
				t.Fatal(err)
			}
			if len(deliveries) != 1 {
				t.Fatalf("tenant A deliveries=%v, want one positive-control delivery", deliveries)
			}
			if got := personalCount(t, ctx, pool, tenantA, `SELECT count(*) FROM notification_deliveries WHERE tenant_id=$1 AND event_id=$2 AND channel_id=$3`, tenantA, fromA.ID, channel.ID); got != 1 {
				t.Fatalf("tenant A stored deliveries=%d, want 1", got)
			}

			fromB := remainingIsolationEvent(t, tenantB, eventType, "b-"+string(eventType), at)
			foreignDeliveries, err := repo.Publish(shared.WithTenant(ctx, tenantB), fromB)
			if err != nil {
				t.Fatal(err)
			}
			if len(foreignDeliveries) != 0 {
				t.Fatalf("tenant B event routed through tenant A rule: %v", foreignDeliveries)
			}
			if got := personalCount(t, ctx, pool, tenantB, `SELECT count(*) FROM notification_events WHERE tenant_id=$1 AND id=$2`, tenantB, fromB.ID); got != 1 {
				t.Fatalf("tenant B source records=%d, want 1", got)
			}
			if got := personalCount(t, ctx, pool, tenantA, `SELECT count(*) FROM notification_events WHERE tenant_id=$1 AND id=$2`, tenantA, fromB.ID); got != 0 {
				t.Fatalf("tenant A captured tenant B source=%d", got)
			}
			if got := personalCount(t, ctx, pool, tenantA, `SELECT count(*) FROM notification_deliveries WHERE tenant_id=$1 AND event_id=$2`, tenantA, fromB.ID); got != 0 {
				t.Fatalf("tenant A routed tenant B event deliveries=%d", got)
			}
		})
	}

	// Mentions intentionally have no conventional channel fanout.  A rule may
	// select canonical mentioned people only, and that relation remains tenant
	// scoped even when the tenant-A rule exists.
	personalExec(t, ctx, pool, tenantA, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('mentioned-a','Mentioned A','member','mention-a',$1,false)`, tenantA)
	personalExec(t, ctx, pool, tenantB, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('mentioned-b','Mentioned B','member','mention-b',$1,false)`, tenantB)
	mentionRule := notification.Rule{
		TenantID: tenantA, ID: "tenant-a-mentioned", Name: "Tenant A mentions", Enabled: true,
		EventType: notification.EventFindingMentioned, RecipientRoles: []string{notification.RoleMentionedUser}, Revision: 1, CreatedAt: at, UpdatedAt: at,
	}
	if _, err := repo.CreateRule(shared.WithTenant(ctx, tenantA), mentionRule); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant   shared.ID
		user     shared.ID
		eventID  shared.ID
		wantRows int
	}{
		{tenant: tenantA, user: "mentioned-a", eventID: "a-finding-mentioned", wantRows: 1},
		{tenant: tenantB, user: "mentioned-b", eventID: "b-finding-mentioned", wantRows: 1},
	} {
		t.Run("mention-"+tc.tenant.String(), func(t *testing.T) {
			event := remainingIsolationMentionEvent(t, tc.tenant, tc.user, tc.eventID, at)
			deliveries, err := repo.Publish(shared.WithTenant(ctx, tc.tenant), event)
			if err != nil {
				t.Fatal(err)
			}
			if len(deliveries) != 0 {
				t.Fatalf("mention conventional deliveries=%v, want none", deliveries)
			}
			if got := personalCount(t, ctx, pool, tc.tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND user_id=$2 AND event_id=$3`, tc.tenant, tc.user, event.ID); got != tc.wantRows {
				t.Fatalf("canonical mention inbox rows=%d, want %d", got, tc.wantRows)
			}
			if got := personalCount(t, ctx, pool, tc.tenant, `SELECT count(*) FROM notification_deliveries WHERE tenant_id=$1 AND event_id=$2`, tc.tenant, event.ID); got != 0 {
				t.Fatalf("mention channel fanout=%d, want 0", got)
			}
		})
	}
	if got := personalCount(t, ctx, pool, tenantA, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND user_id='mentioned-a' AND event_id='b-finding-mentioned'`, tenantA); got != 0 {
		t.Fatalf("tenant A mention rule captured tenant B recipient=%d", got)
	}
}

func remainingIsolationEvent(t *testing.T, tenant shared.ID, eventType notification.EventType, source string, at time.Time) notification.Event {
	t.Helper()
	engagement := shared.ID("eng-" + tenant.String())
	data := map[string]any{
		"engagement_id": engagement,
		"finding_id":    "finding-" + tenant.String(),
		"lead_user_id":  "lead-" + tenant.String(),
		"title":         "Scoped event",
		"summary":       "Tenant-local routing control.",
	}
	switch eventType {
	case notification.EventEngagementWindowStarting, notification.EventEngagementWindowEnding:
		data["lead_time_seconds"] = int64(24 * time.Hour / time.Second)
	case notification.EventApprovalRequested, notification.EventApprovalDecided, notification.EventApprovalTimedOut:
		data["approval_id"] = "approval-" + tenant.String()
		data["kind"] = "agent"
		data["status"] = "pending"
		data["approver_user_ids"] = []string{}
	case notification.EventIncidentUpdated:
		data["incident_id"] = "incident-" + tenant.String()
		data["update_kind"] = "note"
	case notification.EventResponseFinished:
		data["response_id"] = "response-" + tenant.String()
		data["outcome"] = "succeeded"
		data["action_kind"] = "contain"
	case notification.EventEvidenceChainBroken:
		data["evidence_chain_id"] = "chain-" + tenant.String()
		data["reason_code"] = "hash_mismatch"
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return notification.Event{
		TenantID: tenant, ID: shared.ID(source), Type: eventType, SourceKind: "remaining_isolation", SourceID: source,
		EngagementID: engagement, SchemaVersion: 1, OccurredAt: at, Data: raw,
	}
}

func remainingIsolationMentionEvent(t *testing.T, tenant, user, id shared.ID, at time.Time) notification.Event {
	t.Helper()
	engagement := shared.ID("eng-" + tenant.String())
	raw, err := json.Marshal(map[string]any{
		"engagement_id": engagement, "finding_id": "finding-" + tenant.String(), "comment_id": "comment-" + tenant.String(),
		"mentioned_user_id": user, "title": "Mention", "summary": "A canonical user was mentioned.",
	})
	if err != nil {
		t.Fatal(err)
	}
	return notification.Event{
		TenantID: tenant, ID: id, Type: notification.EventFindingMentioned, SourceKind: "remaining_mention", SourceID: fmt.Sprintf("%s:%s", tenant, id),
		EngagementID: engagement, SchemaVersion: 1, OccurredAt: at, Data: raw,
	}
}

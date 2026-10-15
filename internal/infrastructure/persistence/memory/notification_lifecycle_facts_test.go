package memory

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"testing"
)

func TestLifecycleFactsBindOnlyActiveCanonicalTenantUsers(t *testing.T) {
	ctx := context.Background()
	users, engagements := NewUserRepository(), NewEngagementRepository()
	e, err := engagement.New("eng", "tenant", "Captured name", "", notificationTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*user.User{
		{ID: "reviewer", TenantID: "tenant", Name: "Reviewer", Role: user.RoleReviewer},
		{ID: "viewer", TenantID: "tenant", Name: "Viewer", Role: user.RoleReadOnly},
		{ID: "disabled", TenantID: "tenant", Name: "Disabled", Role: user.RoleReviewer, Disabled: true},
		{ID: "foreign", TenantID: "other", Name: "Foreign", Role: user.RoleReviewer},
		{ID: "machine", TenantID: "tenant", Name: "Machine", Role: user.Role("agent")},
	} {
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	reader := NewNotificationLifecycleFactsReader(users, engagements, nil)
	for _, tc := range []struct {
		actor    string
		expected shared.ID
	}{{"reviewer", "reviewer"}, {"viewer", "viewer"}, {"disabled", ""}, {"foreign", ""}, {"machine", ""}, {"Reviewer", ""}} {
		facts, err := reader.SnapshotNotificationLifecycleFacts(ctx, "tenant", "eng", tc.actor)
		if err != nil || facts.ActorUserID != tc.expected || facts.EngagementName != "Captured name" {
			t.Fatalf("%s: facts=%+v err=%v", tc.actor, facts, err)
		}
	}
	ids, err := reader.SnapshotNotificationApprovers(ctx, "tenant")
	if err != nil || len(ids) != 1 || ids[0] != "reviewer" {
		t.Fatalf("roster=%v err=%v", ids, err)
	}
	if _, err := reader.SnapshotNotificationLifecycleFacts(ctx, "other", "eng", "foreign"); err == nil {
		t.Fatal("foreign engagement read succeeded")
	}
}

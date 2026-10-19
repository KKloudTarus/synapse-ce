package postgres

import (
	"context"
	"errors"
	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

func TestDocumentReleaseAuthorityAndSourcePolicyRuntimeRole(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "release-a", "release-b")
	f.enableProjection(t, "release-a", now)
	f.createUser(t, "release-a", "reviewer", user.RoleReviewer, now)
	reader, err := NewDocumentAuthorityReader(f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	actor := ports.DocumentActor{UserID: "reviewer"}
	check := func(tenant shared.ID, actor ports.DocumentActor, want bool) {
		t.Helper()
		got, err := reader.CanReleaseDocument(ctx, tenant, actor)
		if err != nil || got != want {
			t.Fatalf("current release authority=%v err=%v want=%v", got, err, want)
		}
	}
	check("release-a", actor, true)
	check("release-b", actor, false)
	if err := f.updateUser(t, "release-a", "reviewer", "user.disabled", func(u *user.User) { u.Disabled = true }); err != nil {
		t.Fatal(err)
	}
	check("release-a", actor, false)
	if err := f.updateUser(t, "release-a", "reviewer", "user.enabled", func(u *user.User) { u.Disabled = false }); err != nil {
		t.Fatal(err)
	}
	m := f.membershipOf(t, "release-a", "reviewer")
	f.declare(t, "release-a")
	check("release-a", actor, false) // a stale compatibility row cannot authorize canonical work
	actor.MembershipID = m.ID
	actor.PersonID = m.PersonID
	check("release-a", actor, true)
	forged := actor
	forged.UserID = "someone-else"
	check("release-a", forged, false)
	if _, err := f.platform.ApplyPersonCommand(ctx, m.PersonID, ports.IdentityPersonSuspended, "platform-admin", "suspension test"); err != nil {
		t.Fatal(err)
	}
	check("release-a", actor, false)
	if _, err := f.platform.ApplyPersonCommand(ctx, m.PersonID, ports.IdentityPersonReactivated, "platform-admin", "reactivation test"); err != nil {
		t.Fatal(err)
	}
	check("release-a", actor, true)
	// The definer returns only a tenant-bound boolean; an unbound or foreign
	// transaction cannot query a person's authority in another tenant.
	var unbound bool
	if err := f.runtime.QueryRow(ctx, `SELECT synapse_can_release_document('release-a','reviewer',$1,$2)`, m.ID.String(), m.PersonID.String()).Scan(&unbound); err != nil || unbound {
		t.Fatalf("unbound authority=%v err=%v", unbound, err)
	}
	err = WithTenant(ctx, f.runtime, "release-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name,status) VALUES('assessment','release-a','Stored report','completed')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := NewDocumentSourceReleaseReader(f.runtime)
	target := docpublish.Target{IntegrationID: "connection", SourceKind: docpublish.EngagementReport, Scope: docpublish.Engagement, ScopeID: "assessment", SourceRef: "engagement:assessment", Container: "LAB"}
	if err := policy.CheckDocumentSource(ctx, "release-a", target); err != nil {
		t.Fatal(err)
	}
	if err := policy.CheckDocumentSource(ctx, "release-b", target); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign source=%v", err)
	}
	err = WithTenant(ctx, f.runtime, "release-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO legal_holds(tenant_id,engagement_id,reason,placed_by,placed_at) VALUES('release-a','assessment','retain report','reviewer',now())`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.CheckDocumentSource(ctx, "release-a", target); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("held source=%v", err)
	}
	err = WithTenant(ctx, f.runtime, "release-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE legal_holds SET released_at=now(),released_by='reviewer' WHERE tenant_id='release-a'; INSERT INTO notification_engagement_settings(tenant_id,engagement_id,external_notifications,revision,updated_at,updated_by) VALUES('release-a','assessment','signal',1,now(),'reviewer')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.CheckDocumentSource(ctx, "release-a", target); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("lowered source class=%v", err)
	}
}

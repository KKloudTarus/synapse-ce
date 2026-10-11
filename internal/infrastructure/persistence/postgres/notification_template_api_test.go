package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// The template API (#1370) over the PostgreSQL store: each mutation and its audit entry commit in
// the caller's tenant transaction, activation archives the key's previous template, and another
// tenant reads nothing.
func TestNotificationTemplateAPIPostgres(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "tpl-a")
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES('tpl-a','A'),('tpl-b','B')"); err != nil {
		t.Fatal(err)
	}
	cipher, _ := vault.NewCipher([]byte(strings.Repeat("k", 32)))
	svc, err := notificationuc.NewService(NewNotificationRepository(pool), cipher, nil, NewAuditLog(pool), &notificationTestClock{time.Now().UTC().Truncate(time.Microsecond)}, &notificationTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(NewTenantTransactionRunner(pool))
	svc.SetTemplateStore(NewNotificationTemplateStore(pool))

	input := notificationuc.TemplateInput{Name: "Any chat", EventType: notification.AnyEventType, Family: notification.FamilyChat, Locale: "en",
		Fields: map[string]string{"title": "Synapse", "body": "Open Synapse for details."}}
	first, err := svc.CreateTemplate(ctx, "ada", input)
	if err != nil {
		t.Fatal(err)
	}
	first2, err := svc.UpdateTemplate(ctx, "ada", first.ID, notificationuc.TemplateUpdateInput{Fields: map[string]string{"title": "Synapse", "body": "Open Synapse.\nThanks."}, Revision: first.Revision})
	if err != nil {
		t.Fatal(err)
	}
	active, err := svc.ActivateTemplate(ctx, "ada", first.ID, notificationuc.TemplateChangeInput{Revision: first2.Revision})
	if err != nil || active.ActiveVersion != 2 {
		t.Fatalf("activate = %+v err=%v", active, err)
	}
	second, err := svc.CreateTemplate(ctx, "bob", input)
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := svc.ActivateTemplate(ctx, "bob", second.ID, notificationuc.TemplateChangeInput{Revision: second.Revision})
	if err != nil || replaced.ArchivedTemplateID != first.ID {
		t.Fatalf("replacement = %+v err=%v", replaced, err)
	}
	head, err := svc.GetTemplate(ctx, first.ID)
	if err != nil || head.Status != notification.TemplateArchived {
		t.Fatalf("first after replacement = %+v err=%v", head, err)
	}
	rolled, err := svc.RollbackTemplate(ctx, "ada", first.ID, notificationuc.TemplateChangeInput{Version: 1, Revision: head.Revision})
	if err != nil || rolled.ActiveVersion != 1 || rolled.ArchivedTemplateID != second.ID {
		t.Fatalf("rollback = %+v err=%v", rolled, err)
	}
	if _, err = svc.UpdateTemplate(ctx, "ada", first.ID, notificationuc.TemplateUpdateInput{Fields: map[string]string{"body": "x"}, Revision: head.Revision}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale update err = %v", err)
	}
	if _, err = svc.GetTemplate(shared.WithTenant(context.Background(), "tpl-b"), first.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read err = %v", err)
	}

	// audit_log is under forced RLS, so it is read as the tenant.
	var actions []string
	err = WithTenant(ctx, pool, "tpl-a", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT action, actor, metadata FROM audit_log WHERE action LIKE 'notification.template.%' ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var action, actor string
			var raw []byte
			if err := rows.Scan(&action, &actor, &raw); err != nil {
				return err
			}
			var meta map[string]string
			if err := json.Unmarshal(raw, &meta); err != nil {
				return err
			}
			if meta["diff"] == "" || strings.Contains(string(raw), "Open Synapse") {
				t.Errorf("%s metadata = %s", action, raw)
			}
			actions = append(actions, action+"/"+actor)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"notification.template.created/ada", "notification.template.updated/ada", "notification.template.activated/ada",
		"notification.template.created/bob", "notification.template.activated/bob", "notification.template.rolled_back/ada"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("audit actions = %v, want %v", actions, want)
	}
}

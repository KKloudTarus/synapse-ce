package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestJiraWebhookConfigurationReceiptsAndRLS(t *testing.T) {
	f := newRLS817Fixture(t)
	ctx := context.Background()
	integrationID := shared.ID("jira-hook-" + randHex(t))
	publicID := strings.Repeat("j", 32) + randHex(t)
	if _, err := f.owner.Exec(ctx, `INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,enabled,created_at,updated_at) VALUES($1,$2,'jira-cloud','Webhook test','https://unit.atlassian.net',true,now(),now())`, integrationID.String(), rls817TenantA); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.owner.Exec(context.Background(), `DELETE FROM inbound_webhook_events WHERE public_id=$1`, publicID)
		_, _ = f.owner.Exec(context.Background(), `DELETE FROM inbound_webhook_endpoints WHERE public_id=$1`, publicID)
		_, _ = f.owner.Exec(context.Background(), `DELETE FROM ticket_inbound_config WHERE integration_id=$1`, integrationID.String())
		_, _ = f.owner.Exec(context.Background(), `DELETE FROM integrations WHERE id=$1`, integrationID.String())
	})
	s, err := NewTicketStore(f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ports.TicketInboundConfiguration{TenantID: rls817TenantA, IntegrationID: integrationID, Enabled: true, IntegrationAuthor: "integration-user", ConnectionRevision: 1, CredentialRevision: 0, UpdatedAt: time.Now().UTC()}
	cfg, err = s.SaveTicketInboundConfiguration(ctx, rls817TenantA, cfg, 0)
	if err != nil || cfg.Version != 1 {
		t.Fatalf("save=%+v err=%v", cfg, err)
	}
	if _, err = s.GetTicketInboundConfiguration(ctx, rls817TenantB, integrationID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign config: %v", err)
	}
	if _, err = s.SaveTicketInboundConfiguration(ctx, rls817TenantA, cfg, 0); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("lost CAS: %v", err)
	}
	stale := cfg
	stale.ConnectionRevision++
	if _, err = s.SaveTicketInboundConfiguration(ctx, rls817TenantA, stale, cfg.Version); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale connection: %v", err)
	}
	var visible int
	if err = f.runtime.QueryRow(ctx, `SELECT count(*) FROM ticket_inbound_config WHERE integration_id=$1`, integrationID.String()).Scan(&visible); err != nil || visible != 0 {
		t.Fatalf("unbound config visibility=%d err=%v", visible, err)
	}
	var forced bool
	if err = f.owner.QueryRow(ctx, `SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='ticket_inbound_config'::regclass`).Scan(&forced); err != nil || !forced {
		t.Fatalf("config RLS=%v err=%v", forced, err)
	}
	hooks := NewInboundWebhookRepository(f.runtime)
	endpoint := ports.InboundWebhookEndpoint{PublicID: publicID, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: integrationID.String(), Provider: "jira-cloud", CurrentVersion: 1, CurrentSealed: "sealed-test-placeholder", Enabled: true, RatePerMinute: 60}
	forged := endpoint
	forged.TenantID = rls817TenantB
	if ok, err := hooks.ProvisionInboundWebhook(ctx, forged); err != nil || ok {
		t.Fatalf("foreign provision=%v err=%v", ok, err)
	}
	if ok, err := hooks.ProvisionInboundWebhook(ctx, endpoint); err != nil || !ok {
		t.Fatalf("provision=%v err=%v", ok, err)
	}
	identity := ports.InboundWebhookIdentity{PublicID: publicID, TenantID: rls817TenantA, OwnerKind: "integration", OwnerID: integrationID.String()}
	digest := sha256.Sum256([]byte("signed-body"))
	event := ports.InboundWebhookEvent{Provider: "jira-cloud", EventID: "delivery", PayloadSHA256: hex.EncodeToString(digest[:])}
	apply := func(txCtx context.Context) error {
		current, err := s.GetTicketInboundConfiguration(txCtx, rls817TenantA, integrationID)
		if err != nil {
			return err
		}
		_, err = s.SaveTicketInboundConfiguration(txCtx, rls817TenantA, current, current.Version)
		return err
	}
	if _, err = hooks.ProcessInboundWebhookEvent(ctx, identity, event, func(txCtx context.Context) error {
		if e := apply(txCtx); e != nil {
			return e
		}
		return errors.New("rollback test")
	}); err == nil {
		t.Fatal("accepted failed effect")
	}
	current, err := s.GetTicketInboundConfiguration(ctx, rls817TenantA, integrationID)
	if err != nil || current.Version != 1 {
		t.Fatal("effect survived rollback")
	}
	if ok, err := hooks.ProcessInboundWebhookEvent(ctx, identity, event, apply); err != nil || !ok {
		t.Fatalf("retry=%v err=%v", ok, err)
	}
	if ok, err := hooks.ProcessInboundWebhookEvent(ctx, identity, event, apply); err != nil || ok {
		t.Fatalf("replay=%v err=%v", ok, err)
	}
	changedID := event
	changedID.EventID = "forged-other-delivery"
	if ok, err := hooks.ProcessInboundWebhookEvent(ctx, identity, changedID, apply); err != nil || ok {
		t.Fatalf("body replay=%v err=%v", ok, err)
	}
	if _, err = f.owner.Exec(ctx, `UPDATE inbound_webhook_events SET received_at=now()-interval '2 hours 1 second' WHERE public_id=$1`, publicID); err != nil {
		t.Fatal(err)
	}
	if ok, err := hooks.ProcessInboundWebhookEvent(ctx, identity, event, apply); err != nil || !ok {
		t.Fatalf("expired receipt=%v err=%v", ok, err)
	}
	current, err = s.GetTicketInboundConfiguration(ctx, rls817TenantA, integrationID)
	if err != nil || current.Version != 3 {
		t.Fatalf("durable effects=%+v err=%v", current, err)
	}
}

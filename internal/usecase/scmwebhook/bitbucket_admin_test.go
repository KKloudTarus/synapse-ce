package scmwebhook

import (
	"context"
	"errors"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"strings"
	"testing"
	"time"
)

func TestConfigureBitbucketWebhookProvisionsThenRotatesCallerSuppliedSecret(t *testing.T) {
	svc, _, _ := webhookFixture()
	svc.integrations.(*fakeIntegrations).item.Provider = "bitbucket"
	admin := &fakeWebhookAdmin{}
	sealer := &fakeWebhookSealer{}
	audit := &fakeWebhookAudit{}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if err := svc.SetAdmin(admin, sealer, audit, fakeWebhookClock{now: now}, fakeWebhookTx{}); err != nil {
		t.Fatal(err)
	}

	firstSecret := "bitbucket-webhook-secret-000000000001"
	first, err := svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", firstSecret)
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 || first.Rotated || !strings.HasPrefix(first.Path, "/api/v1/hooks/") {
		t.Fatalf("first configuration=%+v", first)
	}
	if admin.endpoint == nil || admin.endpoint.PublicID != strings.TrimPrefix(first.Path, "/api/v1/hooks/") ||
		admin.endpoint.CurrentVersion != 1 || admin.endpoint.Provider != "bitbucket" {
		t.Fatalf("provisioned endpoint=%+v", admin.endpoint)
	}
	if string(sealer.plaintext) != firstSecret {
		t.Fatal("sealer did not receive the caller-supplied secret")
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "integration.bitbucket_webhook_provisioned" {
		t.Fatalf("provision audit=%+v", audit.entries)
	}
	for _, value := range audit.entries[0].Metadata {
		if strings.Contains(value, firstSecret) || strings.Contains(value, admin.endpoint.PublicID) {
			t.Fatal("audit metadata contains webhook credential material")
		}
	}

	secondSecret := "bitbucket-webhook-secret-000000000002"
	second, err := svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", secondSecret)
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != 2 || !second.Rotated || second.Path != first.Path ||
		second.PreviousSecretExpiresAt == nil || !second.PreviousSecretExpiresAt.After(now) {
		t.Fatalf("rotated configuration=%+v", second)
	}
	if string(sealer.plaintext) != secondSecret {
		t.Fatal("sealer did not receive the rotated caller-supplied secret")
	}
	if admin.endpoint.CurrentVersion != 2 || len(audit.entries) != 2 ||
		audit.entries[1].Action != "integration.bitbucket_webhook_rotated" {
		t.Fatalf("rotation endpoint=%+v audit=%+v", admin.endpoint, audit.entries)
	}
}

func TestConfigureBitbucketWebhookRejectsInvalidSecretWithoutPersisting(t *testing.T) {
	svc, _, _ := webhookFixture()
	svc.integrations.(*fakeIntegrations).item.Provider = "bitbucket"
	admin := &fakeWebhookAdmin{}
	if err := svc.SetAdmin(admin, &fakeWebhookSealer{}, &fakeWebhookAudit{}, fakeWebhookClock{now: time.Now()}, fakeWebhookTx{}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", "too-short")
	if !errors.Is(err, shared.ErrValidation) || admin.endpoint != nil {
		t.Fatalf("invalid secret err=%v endpoint=%+v", err, admin.endpoint)
	}
}

func TestConfigureBitbucketWebhookRequiresSingleBoundProject(t *testing.T) {
	svc, _, _ := webhookFixture()
	svc.integrations.(*fakeIntegrations).item.Provider = "bitbucket"
	fi := svc.integrations.(*fakeIntegrations)
	fi.bindings = nil
	admin := &fakeWebhookAdmin{}
	if err := svc.SetAdmin(admin, &fakeWebhookSealer{}, &fakeWebhookAudit{}, fakeWebhookClock{now: time.Now()}, fakeWebhookTx{}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", "bitbucket-webhook-secret-000000000001")
	if !errors.Is(err, shared.ErrConflict) || admin.endpoint != nil {
		t.Fatalf("unbound configure err=%v endpoint=%+v", err, admin.endpoint)
	}

	fi.bindings = []integration.Binding{{ProjectID: "project-1"}}
	fi.item.Provider = "jenkins"
	_, err = svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", "bitbucket-webhook-secret-000000000001")
	if !errors.Is(err, shared.ErrValidation) || admin.endpoint != nil {
		t.Fatalf("wrong-provider configure err=%v endpoint=%+v", err, admin.endpoint)
	}
}

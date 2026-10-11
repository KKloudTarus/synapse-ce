package notification

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// recordingAudit keeps every entry so a test can read the metadata an action wrote.
type recordingAudit struct{ entries []ports.AuditEntry }

func (a *recordingAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

func (a *recordingAudit) last(t *testing.T, action string) ports.AuditEntry {
	t.Helper()
	for i := len(a.entries) - 1; i >= 0; i-- {
		if a.entries[i].Action == action {
			return a.entries[i]
		}
	}
	t.Fatalf("no %s audit entry in %+v", action, a.entries)
	return ports.AuditEntry{}
}

// channelAdminRepo stores one channel and answers every channel call against it.
type channelAdminRepo struct {
	killSwitchRepo
	deleted bool
}

func (r *channelAdminRepo) UpdateChannel(_ context.Context, c domain.Channel, _ string, _ bool) (domain.Channel, error) {
	r.updated = true
	r.current = c
	return c, nil
}
func (r *channelAdminRepo) DeleteChannel(context.Context, shared.ID, shared.ID, int, time.Time) error {
	r.deleted = true
	return nil
}

func channelAdminService(t *testing.T, repo *channelAdminRepo, audit ports.AuditLogger) *Service {
	t.Helper()
	svc, err := NewService(repo, fakeProtector{}, nil, audit, fakeClock{time.Unix(1700000000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func webhookChannel() domain.Channel {
	return domain.Channel{TenantID: "tenant", ID: "channel", Name: "ops", Type: domain.ChannelWebhook, Enabled: true,
		Destination: "https://hooks.example.com/…", Revision: 3, SecretVersion: 1}
}

// An update from a caller without PermAdminister may rename, enable or disable a channel, but not
// point it somewhere else (#1358).
func TestUpdateChannelDestinationNeedsAdminister(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	email := domain.Channel{TenantID: "tenant", ID: "channel", Name: "mail", Type: domain.ChannelEmail, Enabled: true,
		Destination: "2 recipients", Recipients: []string{"a@example.com", "b@example.com"}, Revision: 3, SecretVersion: 1}
	for _, tc := range []struct {
		name    string
		current domain.Channel
		in      ChannelInput
		refused bool
	}{
		{"new URL", webhookChannel(), ChannelInput{Name: "ops", Enabled: true, URL: "https://evil.example.net/x", Secret: "0123456789abcdef-new", Revision: 3}, true},
		{"new secret only", webhookChannel(), ChannelInput{Name: "ops", Enabled: true, Secret: "0123456789abcdef-new", Revision: 3}, true},
		{"new recipients", email, ChannelInput{Name: "mail", Enabled: true, Recipients: []string{"a@example.com", "attacker@example.net"}, Revision: 3}, true},
		{"rename", webhookChannel(), ChannelInput{Name: "renamed", Enabled: true, Revision: 3}, false},
		{"disable", webhookChannel(), ChannelInput{Name: "ops", Enabled: false, Revision: 3}, false},
		{"same recipients reordered", email, ChannelInput{Name: "mail", Enabled: false, Recipients: []string{"B@example.com", "a@example.com"}, Revision: 3}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &channelAdminRepo{killSwitchRepo: killSwitchRepo{current: tc.current}}
			svc := channelAdminService(t, repo, &recordingAudit{})
			_, err := svc.UpdateChannel(ctx, "integrator", "channel", tc.in)
			if tc.refused {
				if !errors.Is(err, shared.ErrForbidden) || repo.updated {
					t.Fatalf("err=%v updated=%v, want ErrForbidden and nothing stored", err, repo.updated)
				}
				if strings.Contains(err.Error(), "evil") || strings.Contains(err.Error(), "attacker") || strings.Contains(err.Error(), "abcdef") {
					t.Fatalf("error echoes the request: %v", err)
				}
				if tc.name == "new secret only" {
					return // a secret without its URL is invalid even for an administrator
				}
				// An administrator may make the same change.
				tc.in.AllowDestinationChange = true
				if _, err = svc.UpdateChannel(ctx, "admin", "channel", tc.in); err != nil || !repo.updated {
					t.Fatalf("administrator refused: %v", err)
				}
				return
			}
			if err != nil || !repo.updated {
				t.Fatalf("update refused: %v", err)
			}
		})
	}
}

// Every channel audit entry records the actor and the masked destination, never a path or token.
func TestChannelAuditRecordsMaskedDestination(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	audit := &recordingAudit{}
	repo := &channelAdminRepo{killSwitchRepo: killSwitchRepo{current: webhookChannel()}}
	svc := channelAdminService(t, repo, audit)

	if _, err := svc.CreateChannel(ctx, "ada", ChannelInput{Name: "ops", Type: domain.ChannelWebhook, Enabled: true,
		URL: "https://Hooks.Example.com/secret/path?token=abc", Secret: "0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	created := audit.last(t, "notification.channel.created")
	if created.Actor != "ada" || created.Metadata["destination"] != "https://hooks.example.com" || created.Metadata["type"] != "webhook" {
		t.Fatalf("created entry = %+v", created)
	}

	if _, err := svc.UpdateChannel(ctx, "ada", "channel", ChannelInput{Name: "renamed", Enabled: true, Revision: 3}); err != nil {
		t.Fatal(err)
	}
	renamed := audit.last(t, "notification.channel.updated")
	if renamed.Metadata["destination"] != "https://hooks.example.com" || renamed.Metadata["destination_changed"] != "false" {
		t.Fatalf("rename entry = %+v", renamed)
	}

	repo.current.Revision = 4
	if _, err := svc.UpdateChannel(ctx, "root", "channel", ChannelInput{Name: "renamed", Enabled: true, Revision: 4,
		URL: "https://other.example.org:8443/p4th/token", Secret: "fedcba9876543210", AllowDestinationChange: true}); err != nil {
		t.Fatal(err)
	}
	moved := audit.last(t, "notification.channel.updated")
	if moved.Actor != "root" || moved.Metadata["destination"] != "https://other.example.org:8443" ||
		moved.Metadata["destination_changed"] != "true" || moved.Metadata["previous_destination"] != "https://hooks.example.com" {
		t.Fatalf("host change entry = %+v", moved)
	}

	if _, err := svc.TestChannel(ctx, "ada", "channel"); err != nil {
		t.Fatal(err)
	}
	if tested := audit.last(t, "notification.channel.test_queued"); tested.Metadata["destination"] != "https://other.example.org:8443" {
		t.Fatalf("test entry = %+v", tested)
	}
	if err := svc.DeleteChannel(ctx, "ada", "channel", 5); err != nil || !repo.deleted {
		t.Fatalf("delete: %v", err)
	}
	if deleted := audit.last(t, "notification.channel.deleted"); deleted.Metadata["destination"] != "https://other.example.org:8443" {
		t.Fatalf("delete entry = %+v", deleted)
	}
	for _, entry := range audit.entries {
		for key, value := range entry.Metadata {
			if strings.Contains(value, "token") || strings.Contains(value, "p4th") || strings.Contains(value, "secret") {
				t.Fatalf("%s metadata %s=%q leaks the destination path", entry.Action, key, value)
			}
		}
	}
}

func TestAuditDestinationForEmailRecordsDomainsOnly(t *testing.T) {
	c := domain.Channel{Type: domain.ChannelEmail, Recipients: []string{"b@Example.org", "a@example.com", "c@example.com"}}
	if got := auditDestination(c); got != "mailto://example.com,example.org" {
		t.Fatalf("auditDestination = %q", got)
	}
}

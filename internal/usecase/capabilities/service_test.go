package capabilities

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func find(t *testing.T, list []Capability, key string) Capability {
	t.Helper()
	for _, capability := range list {
		if capability.Key == key {
			return capability
		}
	}
	t.Fatalf("capability %q is missing from the catalog", key)
	return Capability{}
}

// TestCatalogReportsSwitchPerSubsystem pins the product contract: every optional subsystem answers
// with its own stable key, a human name, and the SYNAPSE_* variable an operator flips, so a client
// can distinguish "disabled" from "broken".
func TestCatalogReportsSwitchPerSubsystem(t *testing.T) {
	svc, err := NewService(Flags{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	list := svc.List()
	cases := []struct {
		key, envVar string
	}{
		{"fleet", "SYNAPSE_FLEET_ENABLED"},
		{"fleet_assets", "SYNAPSE_FLEET_ASSETS_ENABLED"},
		{"fleet_host_ingest", "SYNAPSE_FLEET_HOST_INGEST_ENABLED"},
		{"fleet_cluster_ingest", "SYNAPSE_FLEET_CLUSTER_INGEST_ENABLED"},
		{"fleet_telemetry_ingest", "SYNAPSE_FLEET_TELEMETRY_INGEST_ENABLED"},
		{"fleet_detection_ingest", "SYNAPSE_FLEET_DETECTION_INGEST_ENABLED"},
		{"cspm", "SYNAPSE_CSPM_ENABLED"},
		{"agent", "SYNAPSE_AGENT_ENABLED"},
		{"ai_triage", "SYNAPSE_FP_TRIAGE_ENABLED"},
		{"sla", "SYNAPSE_SLA_ENABLED"},
		{"judgments", "SYNAPSE_JUDGMENTS_ENABLED"},
		{"sandbox", "SYNAPSE_SANDBOX_ENABLED"},
		{"dast", "SYNAPSE_SANDBOX_ENABLED"},
		{"writeup_drafts", "SYNAPSE_WRITEUP_DRAFTS_ENABLED"},
		{"taint", "SYNAPSE_TAINT_ENABLED"},
		{"js_reachability", "SYNAPSE_JSREACH_ENABLED"},
		{"single_tenant", "SYNAPSE_SINGLE_TENANT"},
		{"oidc", "SYNAPSE_OIDC_ENABLED"},
		{"ownership", "SYNAPSE_OWNERSHIP_MODE"},
		{"inbound_webhooks", "SYNAPSE_INBOUND_WEBHOOKS_ENABLED"},
		{"notifications", "SYNAPSE_NOTIFICATIONS_ENABLED"},
		{"notifications.channel_types", "SYNAPSE_NOTIFICATIONS_ENABLED"},
		{"ticketing", ""},
		{"docpublish", ""},
		{"legacy_alert_webhook", "SYNAPSE_ALERT_WEBHOOK_URL"},
	}
	if len(list) != len(cases) {
		t.Fatalf("catalog has %d entries, want %d", len(list), len(cases))
	}
	for _, c := range cases {
		got := find(t, list, c.key)
		if got.Switch != c.envVar {
			t.Errorf("%s switch = %q, want %q", c.key, got.Switch, c.envVar)
		}
		if got.Name == "" {
			t.Errorf("%s has no human name", c.key)
		}
		if got.Enabled {
			t.Errorf("%s is enabled with every flag off", c.key)
		}
	}
}

func TestEnabledFlagsResolve(t *testing.T) {
	svc, err := NewService(Flags{
		Fleet: true, FleetAssets: true, FleetHostIngest: true, FleetClusterIngest: true,
		FleetTelemetryIngest: true, FleetDetectionIngest: true, CSPM: true, Agent: true,
		FPTriage: true, SLA: true, Judgments: true, Sandbox: true, WriteupDrafts: true,
		Taint: true, JSReachability: true, SingleTenant: true, OIDC: true,
		Ownership: true, InboundWebhooks: true, Notifications: true, LegacyAlertWebhook: true,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	for _, capability := range svc.List() {
		if capability.Planned {
			if capability.Enabled {
				t.Errorf("%s is planned but reported enabled", capability.Key)
			}
			continue
		}
		if !capability.Enabled {
			t.Errorf("%s is disabled with every flag on", capability.Key)
		}
	}
}

// TestDependentSubsystemsStayDisabled covers the case that made the endpoint necessary: an operator
// sets the ingest switch but leaves the transport off, so the routes are still absent. The catalog
// must report the subsystem as disabled and name what it depends on.
func TestDependentSubsystemsStayDisabled(t *testing.T) {
	cases := []struct {
		name  string
		flags Flags
		key   string
	}{
		{"host ingest without fleet transport", Flags{FleetHostIngest: true, FleetAssets: true}, "fleet_host_ingest"},
		{"cluster ingest without fleet assets", Flags{FleetClusterIngest: true, Fleet: true}, "fleet_cluster_ingest"},
		{"telemetry ingest without fleet transport", Flags{FleetTelemetryIngest: true}, "fleet_telemetry_ingest"},
		{"detection ingest without fleet transport", Flags{FleetDetectionIngest: true}, "fleet_detection_ingest"},
		{"cspm without fleet assets", Flags{CSPM: true}, "cspm"},
		{"dast without judgments", Flags{Sandbox: true}, "dast"},
		{"dast without sandbox", Flags{Judgments: true}, "dast"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, err := NewService(c.flags)
			if err != nil {
				t.Fatalf("new service: %v", err)
			}
			got := find(t, svc.List(), c.key)
			if got.Enabled {
				t.Errorf("%s reported enabled although a dependency is off", c.key)
			}
			if len(got.Requires) == 0 {
				t.Errorf("%s reports no dependency, so a client cannot explain why it is off", c.key)
			}
		})
	}
}

// TestNotificationCapabilities is #1350: the console reads whether notifications are on, and which
// channel types it can offer, from the catalog instead of probing a route for 404.
func TestNotificationCapabilities(t *testing.T) {
	off, err := NewService(Flags{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if got := find(t, off.List(), "notifications.channel_types"); got.Enabled || len(got.Requires) != 1 || got.Requires[0] != "notifications" {
		t.Errorf("channel types with notifications off = %+v, want disabled and requiring notifications", got)
	}
	on, err := NewService(Flags{Notifications: true, NotificationChannelTypes: []string{"webhook", "slack", "email"}})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if got := find(t, on.List(), "notifications"); !got.Enabled {
		t.Error("notifications reported disabled with SYNAPSE_NOTIFICATIONS_ENABLED on")
	}
	types := find(t, on.List(), "notifications.channel_types")
	if !types.Enabled {
		t.Error("channel types reported disabled with notifications on")
	}
	want := []string{"webhook", "slack", "email"}
	if len(types.Values) != len(want) {
		t.Fatalf("channel types = %v, want %v", types.Values, want)
	}
	for i := range want {
		if types.Values[i] != want[i] {
			t.Errorf("channel types = %v, want %v", types.Values, want)
			break
		}
	}
}

// TestNotificationChannelTypesFollowTheRegistryAndTheKillSwitch is #1362: the advertised channel
// types are the registry's, in its order, minus SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED.
func TestNotificationChannelTypesFollowTheRegistryAndTheKillSwitch(t *testing.T) {
	registry := []string{"webhook", "slack", "email", "pagerduty"}
	for _, tc := range []struct {
		name     string
		disabled []string
		want     string
	}{
		{"nothing disabled", nil, "webhook,slack,email,pagerduty"},
		{"a new driver is advertised without editing the catalog", []string{"email"}, "webhook,slack,pagerduty"},
		{"several disabled", []string{"slack", "webhook"}, "email,pagerduty"},
		{"every type disabled", registry, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := NewService(Flags{Notifications: true, NotificationChannelTypes: registry, NotificationProvidersDisabled: tc.disabled})
			if err != nil {
				t.Fatalf("new service: %v", err)
			}
			got := find(t, svc.List(), "notifications.channel_types")
			if !got.Enabled || strings.Join(got.Values, ",") != tc.want {
				t.Fatalf("channel types = %+v, want enabled with %q", got, tc.want)
			}
			// Switching types off never disables the framework itself.
			if !find(t, svc.List(), "notifications").Enabled {
				t.Fatal("notifications reported disabled")
			}
		})
	}
	// The catalog copies the registry list, so the caller cannot change the answer afterwards.
	flags := Flags{Notifications: true, NotificationChannelTypes: []string{"webhook"}}
	svc, err := NewService(flags)
	if err != nil {
		t.Fatal(err)
	}
	flags.NotificationChannelTypes[0] = "mutated"
	if got := find(t, svc.List(), "notifications.channel_types").Values; len(got) != 1 || got[0] != "webhook" {
		t.Fatalf("channel types = %v after the caller mutated its slice", got)
	}
}

// TestPlannedSubsystemsNameNoSwitch covers ticketing and documentation publishing, which this build
// does not ship: they stay disabled whatever the flags, and name no switch an operator could set.
func TestPlannedSubsystemsNameNoSwitch(t *testing.T) {
	svc, err := NewService(Flags{Notifications: true, Fleet: true, FleetAssets: true})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	for _, key := range []string{"ticketing", "docpublish"} {
		got := find(t, svc.List(), key)
		if !got.Planned || got.Enabled || got.Switch != "" {
			t.Errorf("%s = %+v, want planned, disabled and without a switch", key, got)
		}
	}
}

func TestListReturnsACopy(t *testing.T) {
	svc, err := NewService(Flags{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	first := svc.List()
	first[0].Enabled = true
	first[2].Requires[0] = "mutated"
	second := svc.List()
	if second[0].Enabled {
		t.Error("List returned a mutable view of the startup catalog")
	}
	if second[2].Requires[0] == "mutated" {
		t.Error("List shared the Requires slice with the caller")
	}
	first = svc.List()
	for i := range first {
		if len(first[i].Values) > 0 {
			first[i].Values[0] = "mutated"
		}
	}
	for _, capability := range svc.List() {
		if len(capability.Values) > 0 && capability.Values[0] == "mutated" {
			t.Errorf("List shared the Values slice of %s with the caller", capability.Key)
		}
	}
}

func TestNewServiceRejectsAnInvalidCatalog(t *testing.T) {
	// The production catalog is well-formed; the guard exists for a future edit. Drive it directly.
	if _, err := NewService(Flags{}); err != nil {
		t.Fatalf("production catalog must validate: %v", err)
	}
	if err := validate([]Capability{{Key: "a", Name: "A", Switch: "S"}, {Key: "a", Name: "A", Switch: "S"}}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("duplicate key: want ErrValidation, got %v", err)
	}
	if err := validate([]Capability{{Key: "a", Name: "A"}}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing switch: want ErrValidation, got %v", err)
	}
	if err := validate([]Capability{{Key: "a", Name: "A", Planned: true, Enabled: true}}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("enabled planned capability: want ErrValidation, got %v", err)
	}
	if err := validate([]Capability{{Key: "a", Name: "A", Planned: true, Switch: "S"}}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("planned capability with a switch: want ErrValidation, got %v", err)
	}
	if err := validate([]Capability{{Key: "a", Name: "A", Switch: "S", Requires: []string{"ghost"}}}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown dependency: want ErrValidation, got %v", err)
	}
}

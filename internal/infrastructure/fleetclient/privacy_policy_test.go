package fleetclient

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func testPrivacyAssignment(t *testing.T) privacy.Assignment {
	t.Helper()
	assignment, err := privacy.NewAssignment(
		"tenant-1",
		privacy.DefaultPolicy(),
		"operator",
		time.Date(2026, 8, 27, 12, 0, 0, 123_456_789, time.UTC),
	)
	if err != nil {
		t.Fatalf("NewAssignment() error = %v", err)
	}
	return assignment
}

func TestPrivacyPolicyCacheBindsNormalizedAgentAndControlPlane(t *testing.T) {
	for _, tc := range []struct {
		name      string
		persistAt string
		loadAt    string
	}{
		{
			name:      "host case default port trailing slash and encoded path",
			persistAt: "HTTPS://Example.COM:443/api/%7Eagent/",
			loadAt:    "https://example.com/api/%7Eagent",
		},
		{
			name:      "ipv6 default port",
			persistAt: "https://[2001:DB8::1]:443/control/",
			loadAt:    "https://[2001:db8::1]/control",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			want := testPrivacyAssignment(t)
			if err := PersistPrivacyPolicy(dir, " agent-1 ", tc.persistAt, want); err != nil {
				t.Fatalf("PersistPrivacyPolicy() error = %v", err)
			}
			got, ok := LoadPrivacyPolicy(dir, "agent-1", tc.loadAt)
			if !ok {
				t.Fatal("LoadPrivacyPolicy() rejected equivalent cache identity")
			}
			if !privacy.SameAssignment(got, want) || !got.CreatedAt.Equal(want.CreatedAt) {
				t.Fatalf("LoadPrivacyPolicy() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestPrivacyPolicyCacheRejectsMismatchedOrUnboundIdentity(t *testing.T) {
	dir := t.TempDir()
	assignment := testPrivacyAssignment(t)
	if err := PersistPrivacyPolicy(dir, "agent-1", "https://control.example/api", assignment); err != nil {
		t.Fatalf("PersistPrivacyPolicy() error = %v", err)
	}
	for _, tc := range []struct {
		name         string
		agentID      shared.ID
		controlPlane string
	}{
		{name: "agent", agentID: "agent-2", controlPlane: "https://control.example/api"},
		{name: "host", agentID: "agent-1", controlPlane: "https://other.example/api"},
		{name: "scheme", agentID: "agent-1", controlPlane: "http://control.example/api"},
		{name: "path", agentID: "agent-1", controlPlane: "https://control.example/other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := LoadPrivacyPolicy(dir, tc.agentID, tc.controlPlane); ok {
				t.Fatal("LoadPrivacyPolicy() accepted cache under a different identity")
			}
		})
	}

	path := privacyPolicyStatePath(dir)
	if err := os.WriteFile(path, []byte(`{"tenant_id":"tenant-1"}`), 0o600); err != nil {
		t.Fatalf("write legacy unbound cache: %v", err)
	}
	if _, ok := LoadPrivacyPolicy(dir, "agent-1", "https://control.example/api"); ok {
		t.Fatal("LoadPrivacyPolicy() accepted an old cache without agent and control-plane binding")
	}
	if err := os.WriteFile(path, []byte(`{"agent_id":`), 0o600); err != nil {
		t.Fatalf("write malformed cache: %v", err)
	}
	if _, ok := LoadPrivacyPolicy(dir, "agent-1", "https://control.example/api"); ok {
		t.Fatal("LoadPrivacyPolicy() accepted malformed cache JSON")
	}
}

func TestPersistPrivacyPolicyReplacesExistingAssignment(t *testing.T) {
	dir := t.TempDir()
	first := testPrivacyAssignment(t)
	if err := PersistPrivacyPolicy(dir, "agent-1", "https://control.example", first); err != nil {
		t.Fatalf("persist first policy: %v", err)
	}
	secondPolicy := privacy.DefaultPolicy()
	secondPolicy.MaxArgLen--
	secondPolicy.Version = "default:v2"
	second, err := privacy.NewAssignment("tenant-1", secondPolicy, "operator", first.CreatedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("create replacement policy: %v", err)
	}
	if err := PersistPrivacyPolicy(dir, "agent-1", "https://control.example", second); err != nil {
		t.Fatalf("persist replacement policy: %v", err)
	}
	got, ok := LoadPrivacyPolicy(dir, "agent-1", "https://control.example")
	if !ok || !privacy.SameAssignment(got, second) || !got.CreatedAt.Equal(second.CreatedAt) {
		t.Fatalf("replacement cache = %#v, %v; want %#v", got, ok, second)
	}
	if _, err := os.Stat(filepath.Join(dir, privacyPolicyStateFile+".tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary cache file remains after replacement: %v", err)
	}
}

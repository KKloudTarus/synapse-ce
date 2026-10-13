package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/prometheus/client_golang/prometheus"
)

func TestNotificationWorkerKindsAreExactAndNonEmpty(t *testing.T) {
	got := notificationWorkerKinds()
	want := map[string]bool{
		"notification.deliver":      true,
		"user_contact_verification": true,
		"personal.email":            true,
		"personal.slack":            true,
		"personal.teams":            true,
	}
	if len(got) != len(want) {
		t.Fatalf("notification worker kinds = %v, want exactly %d", got, len(want))
	}
	for _, kind := range got {
		if kind == "" || !want[kind] {
			t.Fatalf("notification worker kind %q is empty or not allowed", kind)
		}
		delete(want, kind)
	}
	if len(want) != 0 {
		t.Fatalf("notification worker is missing allowed kinds %v", want)
	}
}

func TestNotificationMaintenanceLeaseIsIsolated(t *testing.T) {
	base := config.Config{LeaderResource: "synapse"}
	if got, want := notificationMaintenanceResource(base), "synapse-worker-notification-maintenance"; got != want {
		t.Fatalf("notification maintenance resource = %q, want %q", got, want)
	}
	for _, profile := range []config.WorkerProfile{config.WorkerProfileAll, config.WorkerProfileIntegrations, config.WorkerProfileLifecycle} {
		cfg := base
		cfg.WorkerProfile = profile
		if got := cfg.LeaderResource + "-worker-maintenance"; got == notificationMaintenanceResource(base) {
			t.Fatalf("profile %q unexpectedly shares the notification maintenance lease", profile)
		}
	}
}

func TestNotificationWorkerVaultCipherRejectsMissingAndInvalidKeys(t *testing.T) {
	for _, masterKey := range []string{"", "not-a-vault-key"} {
		if _, err := notificationWorkerVaultCipher(config.Config{VaultMasterKey: masterKey}); err == nil {
			t.Fatalf("notification worker vault key %q must be refused", masterKey)
		}
	}
	if _, err := notificationWorkerVaultCipher(config.Config{VaultMasterKey: strings.Repeat("01", 32)}); err != nil {
		t.Fatalf("valid notification worker vault key = %v", err)
	}
}

func TestWorkerMetricsRemainAvailableUntilRootClosesThem(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := startWorkerMetrics(ctx, cancel, "127.0.0.1:0", prometheus.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	response, err := (&http.Client{Timeout: time.Second}).Get("http://" + server.address + "/metrics")
	if err != nil {
		server.close()
		t.Fatalf("metrics must stay available after start returns: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", response.StatusCode)
	}
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodPost, "/metrics", http.StatusMethodNotAllowed},
	} {
		request, err := http.NewRequest(test.method, "http://"+server.address+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		result, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = result.Body.Close()
		if result.StatusCode != test.status {
			t.Fatalf("%s %s status = %d, want %d", test.method, test.path, result.StatusCode, test.status)
		}
	}

	cancel()
	server.close()
	server.close()
	_, err = (&http.Client{Timeout: time.Second}).Get("http://" + server.address + "/metrics")
	if err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("closed metrics listener request error = %v, want connection failure", err)
	}
}

func TestWorkerMetricsRejectMissingRegistry(t *testing.T) {
	server, err := startWorkerMetrics(context.Background(), func() {}, "127.0.0.1:0", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || server.close != nil {
		t.Fatalf("missing metrics registry server=%+v err=%v, want startup error", server, err)
	}
}

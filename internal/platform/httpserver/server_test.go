package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// freePort asks the OS for an unused loopback port so tests never collide on a fixed
// address.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// TestRunPairServesBothListeners covers the coordinated dual-listener lifecycle: with a
// non-nil metrics handler, RunPair must actually serve BOTH the API and the metrics
// endpoint, and both must shut down cleanly when ctx is cancelled.
func TestRunPairServesBothListeners(t *testing.T) {
	apiAddr := freePort(t)
	metricsAddr := freePort(t)

	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# metrics\n"))
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- RunPair(ctx, apiAddr, apiHandler, metricsAddr, metricsHandler, discardLog()) }()

	waitForListener(t, apiAddr)
	waitForListener(t, metricsAddr)

	if resp, err := http.Get("http://" + apiAddr + "/"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("api listener not serving: err=%v resp=%v", err, resp)
	}
	resp, err := http.Get("http://" + metricsAddr + "/metrics")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics listener not serving: err=%v resp=%v", err, resp)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunPair returned an error on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunPair did not return after context cancellation")
	}
}

// TestRunPairMetricsFailureCancelsAPI covers coordinated failure: if the metrics
// listener cannot bind (e.g. address in use), RunPair must cancel the shared context so
// the API listener is also gracefully joined, rather than leaking a goroutine serving
// forever with no supervisor.
func TestRunListenersServesPrivateAuthority(t *testing.T) {
	apiAddr := freePort(t)
	authorityAddr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunListeners(ctx, []Listener{
			{Name: "http server", Addr: apiAddr, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })},
			{Name: "egress grant authority", Addr: authorityAddr, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })},
		}, discardLog())
	}()
	waitForListener(t, apiAddr)
	waitForListener(t, authorityAddr)
	if resp, err := http.Get("http://" + authorityAddr + "/internal/v1/egress-grants"); err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("authority listener not serving: err=%v resp=%v", err, resp)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("RunListeners returned an error on graceful shutdown: %v", err)
	}
}

func TestRunPairMetricsFailureCancelsAPI(t *testing.T) {
	apiAddr := freePort(t)
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve blocking port: %v", err)
	}
	defer blocked.Close()
	takenAddr := blocked.Addr().String()

	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunPair(context.Background(), apiAddr, apiHandler, takenAddr, metricsHandler, discardLog())
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("want a bind error from the metrics listener, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunPair did not return after the metrics listener failed to bind")
	}

	// The API listener must not still be reachable after the coordinated shutdown.
	time.Sleep(100 * time.Millisecond)
	if conn, err := net.DialTimeout("tcp", apiAddr, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Error("api listener should have been shut down when the metrics listener failed")
	}
}

// TestRunNoMetricsListener covers the metrics-disabled default: Run (metricsHandler
// nil via RunPair) must serve only the API listener and never attempt to bind a
// metrics address.
func TestRunNoMetricsListener(t *testing.T) {
	apiAddr := freePort(t)
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, apiAddr, apiHandler, discardLog()) }()

	waitForListener(t, apiAddr)
	if resp, err := http.Get("http://" + apiAddr + "/"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("api listener not serving: err=%v resp=%v", err, resp)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned an error on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener at %s did not come up in time", addr)
}

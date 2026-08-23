package egressbroker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type GrantAuthorityFunc func(context.Context, GrantRequest) (string, error)

func (f GrantAuthorityFunc) Authorize(ctx context.Context, req GrantRequest) (string, error) {
	return f(ctx, req)
}

func TestClientSetupAndCleanup(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	requests := make(chan request, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			req, decodeErr := decodeRequest(conn)
			if decodeErr != nil {
				conn.Close()
				return
			}
			requests <- req
			res := response{Version: protocolVersion, OK: true}
			if req.Action == "setup" {
				res.Rules = req.Rules
			}
			_ = encodeResponse(conn, res)
			conn.Close()
		}
	}()

	authority := GrantAuthorityFunc(func(_ context.Context, req GrantRequest) (string, error) {
		if req.TenantID != "tenant-test" || req.ExecutionKind != "recon" || req.ExecutionID != "job-1" || req.RunID != "syn3" || req.Slot != 3 || req.PID != 1234 || len(req.Rules) != 1 {
			t.Fatalf("grant request = %+v", req)
		}
		return "payload.signature", nil
	})
	client, err := NewClient(socket, time.Second, authority)
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	ns, err := client.Setup(ctx, "syn3", 3, 1234, "recon", "job-1", ports.EgressPolicy{Rules: []ports.EgressRule{{
		Allow: true,
		Net:   netip.MustParsePrefix("203.0.113.0/24"),
		Ports: []uint16{443},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if ns.NamespaceName() != "syn3" || ns.HostsPath() != "" || len(ns.Rules()) != 1 {
		t.Fatalf("namespace = name=%q hosts=%q rules=%d", ns.NamespaceName(), ns.HostsPath(), len(ns.Rules()))
	}
	if err := ns.Teardown(context.Background()); err != nil {
		t.Fatal(err)
	}

	setup := <-requests
	cleanup := <-requests
	if setup.Action != "setup" || setup.RunID != "syn3" || setup.Slot != 3 || setup.PID != 1234 || setup.TenantID != "tenant-test" || setup.ExecutionKind != "recon" || setup.ExecutionID != "job-1" || setup.Grant == "" || len(setup.Rules) != 1 {
		t.Fatalf("setup request = %+v", setup)
	}
	if cleanup.Action != "cleanup" || cleanup.RunID != "syn3" {
		t.Fatalf("cleanup request = %+v", cleanup)
	}
}

func TestClientFailsClosedWhenBrokerUnavailable(t *testing.T) {
	authority := GrantAuthorityFunc(func(context.Context, GrantRequest) (string, error) {
		return "payload.signature", nil
	})
	client, err := NewClient(filepath.Join(t.TempDir(), "missing.sock"), 100*time.Millisecond, authority)
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	_, err = client.Setup(ctx, "syn1", 1, 1234, "recon", "job-1", ports.EgressPolicy{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

func TestClientWaitReadyRetriesUntilBrokerListens(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "broker.sock")
	serverErr := make(chan error, 1)
	go func() {
		time.Sleep(25 * time.Millisecond)
		listener, err := net.Listen("unix", socket)
		if err != nil {
			serverErr <- err
			return
		}
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		req, err := decodeRequest(conn)
		if err != nil {
			serverErr <- err
			return
		}
		if req.Action != "probe" {
			serverErr <- errors.New("unexpected broker action")
			return
		}
		serverErr <- encodeResponse(conn, response{Version: protocolVersion, OK: true})
	}()

	client, err := NewClient(socket, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.WaitReady(ctx, 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestClientWaitReadyTimesOutWhenBrokerUnavailable(t *testing.T) {
	client, err := NewClient(filepath.Join(t.TempDir(), "missing.sock"), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err = client.WaitReady(ctx, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
	if !strings.Contains(err.Error(), ErrUnavailable.Error()) {
		t.Fatalf("error = %v, want last probe context", err)
	}
}

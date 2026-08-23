package egressbroker

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type testSandboxProcess struct {
	netnsFD int
}

func (p testSandboxProcess) Alive() error            { return nil }
func (p testSandboxProcess) NetworkNamespaceFD() int { return p.netnsFD }

func TestServerFailedSetupBurnsGrant(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	signer, err := NewGrantSigner(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewGrantVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	replays := newMemoryGrantReplayStore()
	server := &Server{
		setup: func(context.Context, string, int, ports.EgressPolicy, int) (*egress.Netns, error) {
			return nil, errors.New("injected namespace setup failure")
		},
		verifier: verifier,
		replays:  replays,
		log:      slog.Default(),
		now:      func() time.Time { return now },
		active:   make(map[string]*egress.Netns),
		pending:  make(map[string]struct{}),
	}
	req := request{
		Version:       protocolVersion,
		Action:        "setup",
		TenantID:      "tenant-test",
		ExecutionKind: "recon",
		ExecutionID:   "execution-1",
		RunID:         "syn1",
		Slot:          1,
		PID:           1234,
		Rules:         []CanonicalRule{{Allow: true, CIDR: "203.0.113.0/24", Ports: []uint16{443}}},
	}
	req.Grant, err = signer.Sign(GrantRequest{
		TenantID:      req.TenantID,
		ExecutionKind: req.ExecutionKind,
		ExecutionID:   req.ExecutionID,
		RunID:         req.RunID,
		Slot:          req.Slot,
		PID:           req.PID,
		Rules:         req.Rules,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	process := testSandboxProcess{netnsFD: 7}

	if _, err := server.execute(context.Background(), req, process); err == nil || err.Error() != "injected namespace setup failure" {
		t.Fatalf("first setup error = %v, want injected failure", err)
	}
	if _, err := server.execute(context.Background(), req, process); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("second setup error = %v, want %v", err, ErrGrantReplay)
	}
}

func TestServerReservesRunDuringSetup(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	signer, err := NewGrantSigner(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewGrantVerifier(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := &Server{
		setup: func(context.Context, string, int, ports.EgressPolicy, int) (*egress.Netns, error) {
			close(started)
			<-release
			return nil, errors.New("injected namespace setup failure")
		},
		verifier: verifier,
		replays:  newMemoryGrantReplayStore(),
		log:      slog.Default(),
		now:      func() time.Time { return now },
		active:   make(map[string]*egress.Netns),
		pending:  make(map[string]struct{}),
	}
	requestFor := func(executionID string) request {
		req := request{Version: protocolVersion, Action: "setup", TenantID: "tenant-test", ExecutionKind: "recon", ExecutionID: executionID, RunID: "syn1", Slot: 1, PID: 1234, Rules: []CanonicalRule{{Allow: true, CIDR: "203.0.113.0/24", Ports: []uint16{443}}}}
		req.Grant, err = signer.Sign(GrantRequest{TenantID: req.TenantID, ExecutionKind: req.ExecutionKind, ExecutionID: req.ExecutionID, RunID: req.RunID, Slot: req.Slot, PID: req.PID, Rules: req.Rules}, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := server.execute(context.Background(), requestFor("execution-1"), testSandboxProcess{netnsFD: 7})
		firstDone <- err
	}()
	<-started
	if _, err := server.execute(context.Background(), requestFor("execution-2"), testSandboxProcess{netnsFD: 7}); err == nil || err.Error() != "run namespace already exists" {
		t.Fatalf("concurrent setup error = %v, want run reservation rejection", err)
	}
	if _, err := server.execute(context.Background(), request{Action: "cleanup", RunID: "syn1"}, nil); err == nil || err.Error() != "run namespace setup is in progress" {
		t.Fatalf("cleanup during setup error = %v, want pending rejection", err)
	}
	close(release)
	if err := <-firstDone; err == nil || err.Error() != "injected namespace setup failure" {
		t.Fatalf("first setup error = %v, want injected failure", err)
	}
	server.mu.Lock()
	_, pending := server.pending["syn1"]
	server.mu.Unlock()
	if pending {
		t.Fatal("failed setup retained the run reservation")
	}
}

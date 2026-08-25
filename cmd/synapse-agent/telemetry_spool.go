package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/agentspool"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
)

const (
	agentSensorID      = "synapse-ebpf"
	agentSensorVersion = "1"
)

func (r *runner) telemetrySpoolDir() string {
	return filepath.Join(r.cfg.stateDir, "telemetry-spool")
}

// telemetrySpoolExists distinguishes a genuinely empty/off agent from one that
// has durable A2 state left by a previous run. Transport must resume that backlog
// even when detection is now disabled by configuration.
func (r *runner) telemetrySpoolExists() bool {
	info, err := os.Stat(r.telemetrySpoolDir())
	return err == nil && info.IsDir()
}

func (r *runner) openTelemetrySpool(ctx context.Context, cred fleetclient.Credential) (*spool.Spool, agentspool.SensorIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, agentspool.SensorIdentity{}, err
	}
	agentID := shared.ID(strings.TrimSpace(cred.AgentID))
	assetID := shared.ID(strings.TrimSpace(cred.AssetID))
	if agentID.IsZero() {
		return nil, agentspool.SensorIdentity{}, errors.New("enrolled credential has no canonical agent id")
	}
	if assetID.IsZero() {
		return nil, agentspool.SensorIdentity{}, errors.New("control plane has not established the canonical telemetry asset binding")
	}
	session := fleetagent.CanonicalSessionID(agentID)
	if session == "" {
		return nil, agentspool.SensorIdentity{}, errors.New("cannot derive canonical agent session")
	}
	bootID, err := currentBootID()
	if err != nil {
		return nil, agentspool.SensorIdentity{}, err
	}
	cfg := spool.DefaultConfig()
	cfg.Dir = r.telemetrySpoolDir()
	cfg.Session = session
	cfg.Boot = fleetagent.BootID(bootID)
	cfg.MaxBytes = r.cfg.spoolBytes
	if cfg.MaxBytes < 1<<20 {
		return nil, agentspool.SensorIdentity{}, fmt.Errorf("telemetry spool quota must be at least 1048576 bytes, got %d", cfg.MaxBytes)
	}
	// Reserve the same bounded share normalizeConfig will assign to loss
	// evidence, so WAL sizing cannot consume the gap journal's capacity.
	cfg.MaxGapBytes = spool.RecommendedGapBytes(cfg.MaxBytes)
	walBytes := cfg.MaxBytes - cfg.MaxGapBytes
	if cfg.SegmentBytes > walBytes {
		cfg.SegmentBytes = walBytes
	}
	if cfg.MaxRecordBytes > cfg.SegmentBytes-spool.FrameOverheadBudget {
		cfg.MaxRecordBytes = cfg.SegmentBytes - spool.FrameOverheadBudget
	}
	durable, err := spool.Open(cfg)
	if err != nil {
		return nil, agentspool.SensorIdentity{}, err
	}
	identity := agentspool.SensorIdentity{
		AgentID: agentID, AssetID: assetID, AgentSession: shared.ID(session),
		BootID: bootID, SensorID: agentSensorID, SensorVersion: agentSensorVersion,
	}
	return durable, identity, nil
}

// currentBootID uses the Linux kernel boot UUID. eBPF detection is Linux-only,
// so refusing to fabricate an incarnation on another platform is safer than a
// stable installation id which would misclassify post-reboot sequence resets.
func currentBootID() (shared.ID, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("kernel boot identity is unavailable on %s", runtime.GOOS)
	}
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("read kernel boot id: %w", err)
	}
	id := shared.ID(strings.TrimSpace(string(data)))
	if id.IsZero() {
		return "", errors.New("kernel boot id is empty")
	}
	return id, nil
}

// startSpoolMetrics returns a completion signal so the WAL owner can wait for
// the HTTP collector to stop before closing the spool it scrapes.
func (r *runner) startSpoolMetrics(ctx context.Context, durable *spool.Spool) (<-chan struct{}, error) {
	address := strings.TrimSpace(r.cfg.metricsAddr)
	if address == "" {
		return closedTelemetryWorker(), nil
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(spool.NewCollector(durable))
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveErr := make(chan error, 1)
		go func() { serveErr <- server.Serve(listener) }()
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics listener stopped: %v", err)
			}
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = server.Shutdown(shutdownCtx)
			cancel()
			if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics listener stopped: %v", err)
			}
		}
	}()
	return done, nil
}

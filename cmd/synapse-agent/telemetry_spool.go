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

func (r *runner) openTelemetrySpool(ctx context.Context, cred fleetclient.Credential) (*spool.Spool, agentspool.SensorIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, agentspool.SensorIdentity{}, err
	}
	agentID := shared.ID(strings.TrimSpace(cred.AgentID))
	if agentID.IsZero() {
		return nil, agentspool.SensorIdentity{}, errors.New("enrolled credential has no canonical agent id")
	}
	bootID, err := currentBootID()
	if err != nil {
		return nil, agentspool.SensorIdentity{}, err
	}
	cfg := spool.DefaultConfig()
	cfg.Dir = r.telemetrySpoolDir()
	cfg.Session = fleetagent.SessionID(agentID)
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
		AgentID: agentID, AssetID: agentID, AgentSession: agentID,
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

func (r *runner) startSpoolMetrics(ctx context.Context, durable *spool.Spool) error {
	address := strings.TrimSpace(r.cfg.metricsAddr)
	if address == "" {
		return nil
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(spool.NewCollector(durable))
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics listener stopped: %v", err)
		}
	}()
	return nil
}

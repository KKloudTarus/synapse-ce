package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/agentspool"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	detectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detect"
)

// detectionIdentity derives the canonical (host, agent) identity the detection engine tags its events
// and detections with, from the ENROLLED credential — never from the mutable display name (cfg.name).
//
// This is the D1 fix (#606): the server issues a canonical AgentID at enrolment and resolves the asset
// binding from it, so renaming an agent must not forge a new data-plane identity, two hosts sharing a
// display name must not collide, and signing-key lookup by enrolled AgentID must not miss. The agent
// runs one detection sensor for its own host, so that single canonical AgentID is the identity for both
// the host and agent tags here; the control plane remains authoritative and binds the asset on ingest.
// Returns ok=false when the credential carries no AgentID, so detection fails closed rather than
// starting under an empty or attacker-influenced identity.
func detectionIdentity(cred fleetclient.Credential) (host, agent shared.ID, ok bool) {
	id := shared.ID(strings.TrimSpace(cred.AgentID))
	if id == "" {
		return "", "", false
	}
	return id, id, true
}

// startDetection launches the agent-side detection engine (#422) in the background when configured. It
// is strictly best-effort and isolated from the inventory loop: on a host where the eBPF sensor cannot
// run (non-Linux, no root, missing kernel features) it logs the reason and returns, leaving the agent's
// normal work untouched. Detection is OFF unless -detect-classes / SYNAPSE_DETECT_CLASSES is set.
func (r *runner) startDetection(ctx context.Context, cred fleetclient.Credential) {
	classes, err := parseDetectClasses(r.cfg.detectClasses)
	if err != nil {
		log.Printf("detection: %v; detection engine disabled", err)
		return
	}
	if len(classes) == 0 {
		return // off by default
	}

	host, agent, ok := detectionIdentity(cred)
	if !ok {
		log.Print("detection: enrolled credential has no canonical agent id; detection engine disabled")
		return
	}
	durable, identity, err := r.openTelemetrySpool(ctx, cred)
	if err != nil {
		log.Printf("detection: open durable telemetry spool: %v; detection engine disabled", err)
		return
	}
	rawSensor := ebpf.NewSensor(host, agent, classes)
	sensor, err := agentspool.NewDurableSensor(rawSensor, durable, identity)
	if err != nil {
		log.Printf("detection: wire durable telemetry sensor: %v; detection engine disabled", err)
		_ = durable.Close()
		return
	}
	sink, err := agentspool.NewDetectionSink(durable)
	if err != nil {
		log.Printf("detection: wire durable detection sink: %v; detection engine disabled", err)
		_ = durable.Close()
		return
	}
	eng, err := detectuc.NewEngine(sensor, sink, host, agent, detectuc.Options{
		Classes:       classes,
		CPUCeilingPct: r.cfg.detectCeiling,
	})
	if err != nil {
		log.Printf("detection: %v; detection engine disabled", err)
		_ = durable.Close()
		return
	}
	if err := r.startSpoolMetrics(ctx, durable); err != nil {
		log.Printf("detection: agent metrics listener unavailable: %v", err)
	}

	log.Printf("detection engine starting: classes=%s ceiling=%.0f%% durable_spool=%s", r.cfg.detectClasses, r.cfg.detectCeiling, r.telemetrySpoolDir())
	// One-shot coverage report shortly after start, so the operator can see which classes actually came
	// up on this host and which are gaps — never silently assume a class is observing.
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			coverage := eng.Coverage()
			log.Printf("detection coverage: %s", formatCoverage(coverage))
			if err := agentspool.RecordCoverage(ctx, durable, coverage, time.Now().UTC()); err != nil {
				log.Printf("detection: persist coverage/sensor state: %v", err)
			}
		}
	}()
	go func() {
		err := eng.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("detection engine stopped: %v", err)
		}
		if closeErr := durable.Close(); closeErr != nil {
			log.Printf("detection: close durable spool: %v", closeErr)
		}
	}()
}

// parseDetectClasses turns the comma-separated config into validated classes. An unknown class is a
// configuration error (the whole engine stays off) rather than a silently-ignored typo.
func parseDetectClasses(s string) ([]detection.Class, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []detection.Class
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		c := detection.Class(p)
		if !c.Valid() {
			return nil, fmt.Errorf("unknown detection class %q (want any of process,network,file,privilege)", p)
		}
		out = append(out, c)
	}
	return out, nil
}

// parseCeiling reads the CPU-ceiling percent from the environment; a missing or invalid value disables
// load shedding (0), which is the safe default (shed only on a deliberate, valid setting).
func parseCeiling(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		// The raw value is operator-controlled (an environment variable), so it is deliberately kept
		// out of the log line to prevent log injection.
		log.Print("detection: ignoring invalid SYNAPSE_DETECT_CPU_CEIL_PCT (want a non-negative number)")
		return 0
	}
	return v
}

// formatCoverage renders a per-class coverage line: active classes and, explicitly, the gaps.
func formatCoverage(cov []detection.ClassCoverage) string {
	parts := make([]string, 0, len(cov))
	for _, c := range cov {
		state := string(c.State)
		if c.IsObservationGap() && c.Reason != "" {
			state = fmt.Sprintf("%s(%s)", c.State, c.Reason)
		}
		parts = append(parts, fmt.Sprintf("%s=%s", c.Class, state))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

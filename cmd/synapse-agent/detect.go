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

func detectionIdentity(cred fleetclient.Credential) (host, agent shared.ID, ok bool) {
	id := shared.ID(strings.TrimSpace(cred.AgentID))
	if id == "" {
		return "", "", false
	}
	return id, id, true
}

// startDetection owns the process-lifetime telemetry WAL/transport and optionally
// attaches the eBPF detection producer. Batch and durable-gap shippers are both
// process-owned users of the same spool and finish before Close.
func (r *runner) startDetection(ctx context.Context, cred fleetclient.Credential) {
	classes, err := parseDetectClasses(r.cfg.detectClasses)
	if err != nil {
		log.Printf("detection: %v; detection producer disabled", err)
		classes = nil
	}
	if len(classes) == 0 && !r.telemetrySpoolExists() {
		return
	}

	host, agent, ok := detectionIdentity(cred)
	if !ok {
		log.Print("telemetry: enrolled credential has no canonical agent id; transport disabled")
		return
	}
	durable, identity, err := r.openTelemetrySpool(ctx, cred)
	if err != nil {
		log.Printf("telemetry: open durable spool: %v; transport disabled", err)
		return
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	shipDone := r.startTelemetryShipper(runCtx, durable, cred)
	gapShipDone := r.startTelemetryGapShipper(runCtx, durable, cred)
	detectionShipDone := r.startDetectionDelivery(runCtx, durable, cred)
	metricsDone := closedTelemetryWorker()
	if done, metricsErr := r.startSpoolMetrics(runCtx, durable); metricsErr != nil {
		log.Printf("telemetry: agent metrics listener unavailable: %v", metricsErr)
	} else {
		metricsDone = done
	}
	workers := []<-chan struct{}{shipDone, gapShipDone, detectionShipDone, metricsDone}

	if len(classes) == 0 {
		log.Printf("telemetry transport resuming durable backlog with detection disabled: spool=%s", r.telemetrySpoolDir())
	} else {
		rawSensor := ebpf.NewSensor(host, agent, classes)
		sensor, sensorErr := agentspool.NewDurableSensor(rawSensor, durable, identity)
		if sensorErr != nil {
			log.Printf("detection: wire durable telemetry sensor: %v; detection producer disabled", sensorErr)
		} else {
			sink, sinkErr := agentspool.NewDetectionSink(durable)
			if sinkErr != nil {
				log.Printf("detection: wire durable detection sink: %v; detection producer disabled", sinkErr)
			} else {
				eng, engineErr := detectuc.NewEngine(sensor, sink, host, agent, detectuc.Options{
					Classes:       classes,
					CPUCeilingPct: r.cfg.detectCeiling,
				})
				if engineErr != nil {
					log.Printf("detection: %v; detection producer disabled", engineErr)
				} else {
					log.Printf("detection engine starting: classes=%s ceiling=%.0f%% durable_spool=%s", r.cfg.detectClasses, r.cfg.detectCeiling, r.telemetrySpoolDir())

					coverageDone := make(chan struct{})
					go func() {
						defer close(coverageDone)
						timer := time.NewTimer(3 * time.Second)
						defer timer.Stop()
						select {
						case <-runCtx.Done():
						case <-timer.C:
							coverage := eng.Coverage()
							log.Printf("detection coverage: %s", formatCoverage(coverage))
							if err := agentspool.RecordCoverage(runCtx, durable, coverage, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
								log.Printf("detection: persist coverage/sensor state: %v", err)
							}
						}
					}()
					workers = append(workers, coverageDone)

					engineDone := make(chan struct{})
					go func() {
						defer close(engineDone)
						if err := eng.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
							log.Printf("detection engine stopped; telemetry transport remains active: %v", err)
						}
					}()
					workers = append(workers, engineDone)
				}
			}
		}
	}

	go func(done []<-chan struct{}) {
		<-ctx.Done()
		cancelRun()
		for _, worker := range done {
			<-worker
		}
		if closeErr := durable.Close(); closeErr != nil {
			log.Printf("telemetry: close durable spool: %v", closeErr)
		}
	}(append([]<-chan struct{}(nil), workers...))
}

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

func parseCeiling(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		log.Print("detection: ignoring invalid SYNAPSE_DETECT_CPU_CEIL_PCT (want a non-negative number)")
		return 0
	}
	return v
}

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

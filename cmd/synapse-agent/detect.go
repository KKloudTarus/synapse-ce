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
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	detectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detect"
)

const (
	coverageReportInitialDelay = 3 * time.Second
	coverageReportInterval     = time.Minute
	coverageReportFinalTimeout = 5 * time.Second
)

func detectionIdentity(cred fleetclient.Credential) (host, agent shared.ID, ok bool) {
	id := shared.ID(strings.TrimSpace(cred.AgentID))
	if id == "" {
		return "", "", false
	}
	return id, id, true
}

// detectionTransport owns the process-lifetime telemetry WAL and durable
// shippers. Policy-bound producers share its spool and never open a second
// handle to the exclusively locked directory.
type detectionTransport struct {
	durable  *spool.Spool
	identity agentspool.SensorIdentity
	host     shared.ID
	agent    shared.ID
	classes  []detection.Class
	cancel   context.CancelFunc
	done     <-chan struct{}
}

func (t *detectionTransport) stop() {
	if t == nil || t.cancel == nil {
		return
	}
	t.cancel()
	<-t.done
	t.cancel = nil
	t.done = nil
}

// startDetectionTransport opens the telemetry spool once and starts every
// durable shipper independently from current source-observation authorization.
func (r *runner) startDetectionTransport(
	ctx context.Context,
	cred fleetclient.Credential,
) (*detectionTransport, error) {
	classes, err := parseDetectClasses(r.cfg.detectClasses)
	if err != nil {
		return nil, err
	}
	if len(classes) == 0 && !r.telemetrySpoolExists() {
		return nil, nil
	}
	host, agent, ok := detectionIdentity(cred)
	if !ok {
		return nil, errors.New("enrolled credential has no canonical agent id")
	}
	durable, identity, err := r.openTelemetrySpool(ctx, cred)
	if err != nil {
		return nil, fmt.Errorf("open durable spool: %w", err)
	}

	// The run loop owns shutdown ordering: source observation is stopped and
	// joined before these shippers and the shared spool. Detach only cancellation
	// while retaining authenticated context values.
	runCtx, cancelRun := context.WithCancel(context.WithoutCancel(ctx))
	workers := []<-chan struct{}{
		r.startTelemetryShipper(runCtx, durable, cred),
		r.startSensorStateShipper(runCtx, durable, cred),
		r.startTelemetryGapShipper(runCtx, durable, cred),
		r.startDetectionDelivery(runCtx, durable, cred),
	}
	metricsDone := closedTelemetryWorker()
	if done, metricsErr := r.startSpoolMetrics(runCtx, durable); metricsErr != nil {
		log.Printf("telemetry: agent metrics listener unavailable: %v", metricsErr)
	} else {
		metricsDone = done
	}
	workers = append(workers, metricsDone)

	done := make(chan struct{})
	go func() {
		defer close(done)
		<-runCtx.Done()
		for _, worker := range workers {
			<-worker
		}
		if closeErr := durable.Close(); closeErr != nil {
			log.Printf("telemetry: close durable spool: %v", closeErr)
		}
	}()
	if len(classes) == 0 {
		log.Printf("telemetry transport resuming durable backlog with detection disabled: spool=%s", r.telemetrySpoolDir())
	}
	return &detectionTransport{
		durable: durable, identity: identity, host: host, agent: agent,
		classes: classes, cancel: cancelRun, done: done,
	}, nil
}

// startDetectionProducer attaches one policy-bound source producer to the
// process-owned transport. Both observation boundaries receive the exact same
// validated policy before the engine can start.
func (r *runner) startDetectionProducer(
	ctx context.Context,
	transport *detectionTransport,
	assignment privacy.Assignment,
) (<-chan struct{}, error) {
	if transport == nil || transport.durable == nil || len(transport.classes) == 0 {
		return nil, fmt.Errorf("%w: detection producer needs an active transport and configured classes", shared.ErrValidation)
	}
	if err := assignment.Validate(); err != nil {
		return nil, fmt.Errorf("validate source-privacy policy: %w", err)
	}
	rawSensor := ebpf.NewSensor(transport.host, transport.agent, transport.classes)
	sensor, err := agentspool.NewDurableSensor(rawSensor, transport.durable, transport.identity)
	if err != nil {
		return nil, fmt.Errorf("wire durable telemetry sensor: %w", err)
	}
	if err := sensor.SetRedactionPolicy(assignment.Policy); err != nil {
		return nil, fmt.Errorf("apply telemetry source-privacy policy: %w", err)
	}
	sink, err := agentspool.NewDetectionSink(transport.durable)
	if err != nil {
		return nil, fmt.Errorf("wire durable detection sink: %w", err)
	}
	if err := sink.SetRedactionPolicy(assignment.Policy); err != nil {
		return nil, fmt.Errorf("apply detection source-privacy policy: %w", err)
	}
	eng, err := detectuc.NewEngine(sensor, sink, transport.host, transport.agent, detectuc.Options{
		Classes: transport.classes, CPUCeilingPct: r.cfg.detectCeiling,
	})
	if err != nil {
		return nil, err
	}
	log.Printf("detection engine starting: classes=%s ceiling=%.0f%% durable_spool=%s", r.cfg.detectClasses, r.cfg.detectCeiling, r.telemetrySpoolDir())

	coverageDone := make(chan struct{})
	go func() {
		defer close(coverageDone)
		timer := time.NewTimer(coverageReportInitialDelay)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				coverage := eng.Coverage()
				log.Printf("detection coverage: %s", formatCoverage(coverage))
				if recordErr := agentspool.RecordCoverage(ctx, transport.durable, coverage, time.Now().UTC()); recordErr != nil && !errors.Is(recordErr, context.Canceled) {
					log.Printf("detection: persist coverage/sensor state: %v", recordErr)
				}
				timer.Reset(coverageReportInterval)
			}
		}
	}()
	engineDone := make(chan struct{})
	go func() {
		defer close(engineDone)
		if runErr := eng.Run(ctx); runErr != nil && !errors.Is(runErr, context.Canceled) {
			log.Printf("detection engine stopped; telemetry transport remains active: %v", runErr)
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), coverageReportFinalTimeout)
		if recordErr := agentspool.RecordCoverage(shutdownCtx, transport.durable, eng.Coverage(), time.Now().UTC()); recordErr != nil {
			log.Printf("detection: persist final coverage/sensor state: %v", recordErr)
		}
		cancel()
		<-coverageDone
		<-engineDone
	}()
	return done, nil
}

func parseDetectClasses(s string) ([]detection.Class, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []detection.Class
	for part := range strings.SplitSeq(s, ",") {
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

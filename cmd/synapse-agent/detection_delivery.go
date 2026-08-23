package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/agentstate"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detectionship"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var (
	detectionEngagement   = strings.TrimSpace(os.Getenv("SYNAPSE_DETECTION_ENGAGEMENT_ID"))
	detectionShipInterval = parsePositiveDuration(os.Getenv("SYNAPSE_DETECTION_SHIP_INTERVAL"), time.Second)
)

func init() {
	flag.StringVar(&detectionEngagement, "detection-engagement", detectionEngagement, "engagement id receiving signed detection batches; empty keeps detections local")
	flag.DurationVar(&detectionShipInterval, "detection-ship-interval", detectionShipInterval, "idle interval for the independent detection delivery loop")
}

func parsePositiveDuration(value string, def time.Duration) time.Duration {
	if value == "" {
		return def
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		log.Printf("ignoring invalid detection ship interval (want a positive duration)")
		return def
	}
	return parsed
}

func (r *runner) startDetectionDelivery(ctx context.Context, durable *spool.Spool, cred fleetclient.Credential) <-chan struct{} {
	engagement := shared.ID(strings.TrimSpace(detectionEngagement))
	if engagement.IsZero() {
		return closedTelemetryWorker()
	}
	transport, ok := r.api.(ports.DetectionTransport)
	if !ok {
		log.Print("detection delivery disabled: fleet API does not implement detection transport")
		return closedTelemetryWorker()
	}
	agentID := shared.ID(strings.TrimSpace(cred.AgentID))
	shipper, err := detectionship.NewService(durable, transport, agentstate.NewDetectionStore(r.cfg.stateDir), detectionship.Config{
		AgentID:      agentID,
		EngagementID: engagement,
		Token:        cred.Token,
		IdleInterval: detectionShipInterval,
		Retry:        detectionRetry(spool.DefaultRetryPolicy()),
	})
	if err != nil {
		log.Printf("detection: wire signed delivery: %v; remote detection delivery disabled", err)
		return closedTelemetryWorker()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := shipper.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("detection delivery stopped with P1 WAL retained: %v", err)
		}
	}()
	return done
}

func detectionRetry(policy spool.RetryPolicy) detectionship.RetryDecider {
	return func(err error, attempt uint) (bool, time.Duration) {
		if status, retryAfter, ok := fleetclient.HTTPStatus(err); ok {
			decision, classifyErr := policy.ClassifyHTTP(status, retryAfter, time.Now().UTC(), attempt)
			if classifyErr != nil {
				return false, 0
			}
			return decision.Retry, decision.Delay
		}
		if fleetclient.IsNetworkError(err) {
			decision, classifyErr := policy.NetworkFailure(attempt)
			if classifyErr == nil {
				return decision.Retry, decision.Delay
			}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			decision, classifyErr := policy.ClassifyHTTP(http.StatusRequestTimeout, "", time.Now().UTC(), attempt)
			if classifyErr == nil {
				return decision.Retry, decision.Delay
			}
		}
		return false, 0
	}
}

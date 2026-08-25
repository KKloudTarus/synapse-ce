package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type telemetryGapTransport interface {
	RegisterTelemetrySigningKey(context.Context, string, fleetagent.AgentSigningKey, string) error
	ShipTelemetryGap(context.Context, string, fleetagent.TelemetryGapReport) (fleetclient.TelemetryGapShipResponse, error)
}

func (r *runner) startTelemetryGapShipper(ctx context.Context, durable *spool.Spool, cred fleetclient.Credential) <-chan struct{} {
	api, ok := r.api.(telemetryGapTransport)
	if !ok {
		return closedTelemetryWorker()
	}
	if cred.AgentID == "" || cred.AssetID == "" {
		log.Printf("telemetry gap transport disabled: canonical agent/asset binding is incomplete")
		return closedTelemetryWorker()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.telemetryGapShipLoop(ctx, durable, api, cred)
	}()
	return done
}

func (r *runner) telemetryGapShipLoop(ctx context.Context, durable *spool.Spool, api telemetryGapTransport, cred fleetclient.Credential) {
	var signer fleetclient.TelemetrySigner
	for {
		registered, err := r.ensureTelemetryGapSignerRegistered(ctx, api, cred, signer)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			retry, wait := telemetryRegistrationRetry(err)
			if !retry {
				log.Printf("telemetry gap signing-key registration rejected; gap journal retained: %v", err)
				return
			}
			log.Printf("telemetry gap signing-key registration failed (will retry): %v", err)
			if !sleepContext(ctx, wait) {
				return
			}
			continue
		}
		signer = registered

		gaps, err := durable.Gaps(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("telemetry gap journal read failed (will retry): %v", err)
			if !sleepContext(ctx, telemetryShipBackoff) {
				return
			}
			continue
		}
		if len(gaps) == 0 {
			if !sleepContext(ctx, telemetryShipIdle) {
				return
			}
			continue
		}

		reload := false
		for _, gap := range gaps {
			report, err := buildTelemetryGapReport(cred, signer, gap)
			if err != nil {
				log.Printf("telemetry gap transport stopped with gap journal retained: %v", err)
				return
			}
			resp, err := api.ShipTelemetryGap(ctx, cred.Token, report)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				retry, wait := telemetryDeliveryRetry(err, retryAfterFromTelemetryError(err))
				if !retry {
					log.Printf("telemetry gap transport stopped with gap journal retained: %v", err)
					return
				}
				log.Printf("telemetry gap ship failed (will retry): %v", err)
				if !sleepContext(ctx, wait) {
					return
				}
				reload = true
				break
			}
			if !resp.Acknowledged || resp.GapID != report.GapID {
				log.Printf("telemetry gap transport stopped with gap journal retained: server ACK %q does not match gap %q", resp.GapID, report.GapID)
				return
			}
			acked, err := durable.AckGap(ctx, gap)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				log.Printf("telemetry gap local ACK failed (will retry without deleting evidence): %v", err)
				if !sleepContext(ctx, telemetryShipBackoff) {
					return
				}
				reload = true
				break
			}
			if !acked {
				// The stable GapID grew while its older snapshot was in flight. The server
				// has the acknowledged prefix, while the local journal keeps the larger
				// snapshot. Reload immediately and send the monotonic extension.
				reload = true
				break
			}
		}
		if reload {
			continue
		}
	}
}

func (r *runner) ensureTelemetryGapSignerRegistered(ctx context.Context, api telemetryGapTransport, cred fleetclient.Credential, current fleetclient.TelemetrySigner) (fleetclient.TelemetrySigner, error) {
	now := time.Now().UTC()
	if !current.NeedsRotation(now) {
		return current, nil
	}
	signer, err := r.store.EnsureTelemetrySigner(cred.AgentID, now)
	if err != nil {
		return fleetclient.TelemetrySigner{}, err
	}
	proof := fleetagent.ProveKeyPossession(signer.PrivateKey, signer.Key)
	if err := api.RegisterTelemetrySigningKey(ctx, cred.Token, signer.Key, proof); err != nil {
		return fleetclient.TelemetrySigner{}, err
	}
	return signer, nil
}

func retryAfterFromTelemetryError(err error) time.Duration {
	var status *fleetclient.HTTPStatusError
	if errors.As(err, &status) {
		return status.RetryAfter
	}
	return 0
}

func buildTelemetryGapReport(cred fleetclient.Credential, signer fleetclient.TelemetrySigner, gap ports.SpoolGap) (fleetagent.TelemetryGapReport, error) {
	if err := gap.Validate(); err != nil {
		return fleetagent.TelemetryGapReport{}, err
	}
	agentID := shared.ID(cred.AgentID)
	assetID := shared.ID(cred.AssetID)
	if agentID.IsZero() || assetID.IsZero() {
		return fleetagent.TelemetryGapReport{}, fmt.Errorf("telemetry gap requires canonical agent and asset identity")
	}
	session := fleetagent.CanonicalSessionID(agentID)
	if session == "" {
		return fleetagent.TelemetryGapReport{}, fmt.Errorf("telemetry gap cannot derive canonical agent session")
	}
	streamID, err := fleetagent.TelemetryDeliveryStreamID(agentID, session, gap.Priority)
	if err != nil {
		return fleetagent.TelemetryGapReport{}, err
	}
	fromAt, toAt := gap.TimeBounds()
	report := fleetagent.TelemetryGapReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		GapID:           gap.ID,
		AgentID:         agentID,
		HostID:          agentID,
		AgentSessionID:  session,
		AssetID:         assetID,
		StreamID:        streamID,
		Priority:        gap.Priority,
		Epoch:           gap.Epoch,
		KnownSequence:   gap.KnownSequence,
		FromSequence:    gap.FromSequence,
		ToSequence:      gap.ToSequence,
		Count:           gap.Count,
		Reason:          fleetagent.TelemetryGapReason(gap.Reason),
		FromAt:          fromAt,
		ToAt:            toAt,
		KeyID:           signer.Key.KeyID,
	}
	if !report.Reason.Valid() {
		return fleetagent.TelemetryGapReport{}, fmt.Errorf("telemetry gap reason %q has no wire mapping", gap.Reason)
	}
	report.Signature = fleetagent.SignTelemetryGap(signer.PrivateKey, report)
	if err := report.Validate(); err != nil {
		return fleetagent.TelemetryGapReport{}, err
	}
	return report, nil
}

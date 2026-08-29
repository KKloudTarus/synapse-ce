package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sensorstatejournal"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/sensorstateship"
)

type sensorStateTransport interface {
	RegisterTelemetrySigningKey(context.Context, string, fleetagent.AgentSigningKey, string) error
	ShipSensorState(context.Context, string, fleetagent.SensorStateReport) (fleetclient.SensorStateShipResponse, error)
}

type sensorStateTransportAdapter struct {
	api sensorStateTransport
}

func (a sensorStateTransportAdapter) ShipSensorState(ctx context.Context, token string, report fleetagent.SensorStateReport) (sensorstateship.ACK, error) {
	response, err := a.api.ShipSensorState(ctx, token, report)
	return sensorstateship.ACK{Acknowledged: response.Acknowledged, ReportID: response.ReportID}, err
}

func (r *runner) startSensorStateShipper(ctx context.Context, durable *spool.Spool, cred fleetclient.Credential) <-chan struct{} {
	api, ok := r.api.(sensorStateTransport)
	if !ok {
		return closedTelemetryWorker()
	}
	if cred.AgentID == "" || cred.AssetID == "" {
		log.Printf("sensor-state transport disabled: canonical agent/asset binding is incomplete")
		return closedTelemetryWorker()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.sensorStateShipLoop(ctx, durable, api, cred)
	}()
	return done
}

func (r *runner) sensorStateShipLoop(ctx context.Context, durable *spool.Spool, api sensorStateTransport, cred fleetclient.Credential) {
	journal, err := sensorstatejournal.New(r.cfg.stateDir)
	if err != nil {
		log.Printf("sensor-state journal unavailable; P0 WAL retained: %v", err)
		return
	}
	var signer fleetclient.TelemetrySigner
	for {
		registered, err := r.ensureSensorStateSignerRegistered(ctx, api, cred, signer)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			retry, wait := telemetryRegistrationRetry(err)
			if !retry {
				log.Printf("sensor-state signing-key registration rejected; P0 WAL retained: %v", err)
				return
			}
			log.Printf("sensor-state signing-key registration failed (will retry): %v", err)
			if !sleepContext(ctx, wait) {
				return
			}
			continue
		}
		signer = registered
		service, err := sensorstateship.NewService(
			durable,
			sensorStateTransportAdapter{api: api},
			journal,
			sensorstateship.Config{
				AgentID: shared.ID(cred.AgentID), AssetID: shared.ID(cred.AssetID), Token: cred.Token,
				Signer: sensorstateship.Signer{PrivateKey: signer.PrivateKey, KeyID: signer.Key.KeyID},
			},
		)
		if err != nil {
			log.Printf("sensor-state service unavailable; P0 WAL retained: %v", err)
			return
		}
		shipped, err := service.DeliverOnce(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			if errors.Is(err, sensorstateship.ErrProtocol) {
				log.Printf("sensor-state transport stopped with P0 WAL retained: %v", err)
				return
			}
			retryAfter := retryAfterFromTelemetryError(err)
			retry, wait := telemetryDeliveryRetry(err, retryAfter)
			if !retry {
				log.Printf("sensor-state transport stopped with P0 WAL retained: %v", err)
				return
			}
			log.Printf("sensor-state ship failed (will retry): %v", err)
			if !sleepContext(ctx, wait) {
				return
			}
			continue
		}
		if !shipped && !sleepContext(ctx, telemetryShipIdle) {
			return
		}
	}
}

func (r *runner) ensureSensorStateSignerRegistered(ctx context.Context, api sensorStateTransport, cred fleetclient.Credential, current fleetclient.TelemetrySigner) (fleetclient.TelemetrySigner, error) {
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

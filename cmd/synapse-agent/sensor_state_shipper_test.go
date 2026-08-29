package main

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/sensorstateship"
)

type fakeSensorStateTransport struct {
	response fleetclient.SensorStateShipResponse
	err      error
	calls    int
}

func (f *fakeSensorStateTransport) RegisterTelemetrySigningKey(context.Context, string, fleetagent.AgentSigningKey, string) error {
	return nil
}

func (f *fakeSensorStateTransport) ShipSensorState(_ context.Context, _ string, _ fleetagent.SensorStateReport) (fleetclient.SensorStateShipResponse, error) {
	f.calls++
	return f.response, f.err
}

func TestSensorStateTransportAdapterMapsACK(t *testing.T) {
	api := &fakeSensorStateTransport{response: fleetclient.SensorStateShipResponse{Acknowledged: true, ReportID: "report-1"}}
	ack, err := (sensorStateTransportAdapter{api: api}).ShipSensorState(context.Background(), "token", fleetagent.SensorStateReport{ReportID: "report-1"})
	if err != nil {
		t.Fatal(err)
	}
	if api.calls != 1 || ack != (sensorstateship.ACK{Acknowledged: true, ReportID: "report-1"}) {
		t.Fatalf("mapped ACK=%+v calls=%d", ack, api.calls)
	}
}

func TestSensorStateTransportAdapterPreservesRetryError(t *testing.T) {
	want := &fleetclient.HTTPStatusError{StatusCode: 429, RetryAfter: 3 * time.Second}
	api := &fakeSensorStateTransport{err: want}
	_, err := (sensorStateTransportAdapter{api: api}).ShipSensorState(context.Background(), "token", fleetagent.SensorStateReport{ReportID: "report-1"})
	if err != want {
		t.Fatalf("adapter error=%v, want original transport error", err)
	}
}

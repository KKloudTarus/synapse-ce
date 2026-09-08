package main

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

type responseObservationStub struct{ called bool }

func (s *responseObservationStub) Observe(context.Context, fleetclient.Credential, fleetclient.Order) error {
	s.called = true
	return nil
}

func TestHandleResponseObservationInvokesConfiguredRuntime(t *testing.T) {
	stub := &responseObservationStub{}
	r := &runner{responseObserver: stub}
	r.handleResponseObservation(context.Background(), fleetclient.Credential{}, fleetclient.Order{})
	if !stub.called {
		t.Fatal("configured response-observation runtime was not invoked")
	}
}

var _ responseObservationRunner = (*responseObservationStub)(nil)

package main

import (
	"context"
	"log"

	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

func (r *runner) handleResponseObservation(ctx context.Context, credential fleetclient.Credential, order fleetclient.Order) {
	if r.responseObserver == nil {
		_ = r.api.SubmitResult(ctx, credential.Token, order.ID, order.LeaseID, string(workorder.StateFailed), "response observation capability is not configured")
		return
	}
	if err := r.responseObserver.Observe(ctx, credential, order); err != nil {
		log.Printf("order %s: response observation: %v", order.ID, err)
	}
}

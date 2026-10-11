package main

import (
	"context"
	"testing"
	"time"
)

func TestIdentityHeartbeatSchedulingContinuesDuringBlockedMaintenance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocked := make(chan struct{}, 1)
	finished := make(chan struct{}, 1)
	startIdentityPeriodic(ctx, time.Millisecond, func() {
		select {
		case blocked <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case finished <- struct{}{}:
		default:
		}
	})
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("maintenance did not start")
	}
	// This loop models a tenant heartbeat; the other loop remains blocked in delivery.
	heartbeats := make(chan struct{}, 2)
	startIdentityPeriodic(ctx, time.Millisecond, func() {
		select {
		case heartbeats <- struct{}{}:
		default:
		}
	})
	for i := 0; i < 2; i++ {
		select {
		case <-heartbeats:
		case <-time.After(time.Second):
			t.Fatal("heartbeat delayed by maintenance")
		}
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("maintenance ignored cancellation")
	}
}

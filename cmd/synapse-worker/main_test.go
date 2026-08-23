package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

type readinessWaiterFunc func(context.Context, time.Duration) error

func (f readinessWaiterFunc) WaitReady(ctx context.Context, interval time.Duration) error {
	return f(ctx, interval)
}

func TestWaitForEgressBrokerPreservesParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()

	err := waitForEgressBroker(parent, readinessWaiterFunc(func(ctx context.Context, interval time.Duration) error {
		if interval != 100*time.Millisecond {
			t.Fatalf("interval = %s, want 100ms", interval)
		}
		<-ctx.Done()
		return ctx.Err()
	}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want context canceled", err)
	}
}

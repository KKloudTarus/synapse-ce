package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	cycle "github.com/KKloudTarus/synapse-ce/internal/infrastructure/reachbench"
)

func TestExecuteCLIRejectsAllArguments(t *testing.T) {
	called := false
	code := executeCLI(context.Background(), []string{"--run-key", "caller-controlled"}, &bytes.Buffer{}, &bytes.Buffer{}, func(context.Context, []string) (cycle.Result, error) {
		called = true
		return cycle.Result{}, nil
	})
	if code != 1 || called {
		t.Fatalf("CLI code = %d, called = %t; arguments must be rejected before execution", code, called)
	}
}

func TestExecuteCLIPassesNoArgumentsToLifecycle(t *testing.T) {
	var received []string
	code := executeCLI(context.Background(), nil, &bytes.Buffer{}, &bytes.Buffer{}, func(_ context.Context, args []string) (cycle.Result, error) {
		received = args
		return cycle.Result{}, nil
	})
	if code != 0 || received != nil {
		t.Fatalf("CLI code = %d, lifecycle args = %#v", code, received)
	}
}

func TestExecuteCLIPassesCancellationToLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var lifecycleContext context.Context
	code := executeCLI(ctx, nil, &bytes.Buffer{}, &bytes.Buffer{}, func(received context.Context, _ []string) (cycle.Result, error) {
		lifecycleContext = received
		return cycle.Result{}, nil
	})
	if code != 0 || lifecycleContext == nil || !errors.Is(lifecycleContext.Err(), context.Canceled) {
		t.Fatalf("CLI code = %d, lifecycle context error = %v; want propagated cancellation", code, lifecycleContext.Err())
	}
}

func TestExecuteCLIReportsLifecycleFailure(t *testing.T) {
	stderr := &bytes.Buffer{}
	code := executeCLI(context.Background(), nil, &bytes.Buffer{}, stderr, func(context.Context, []string) (cycle.Result, error) {
		return cycle.Result{}, errors.New("capture unavailable")
	})
	if code != 1 || !bytes.Contains(stderr.Bytes(), []byte("capture unavailable")) {
		t.Fatalf("CLI code = %d, stderr = %q", code, stderr.String())
	}
}

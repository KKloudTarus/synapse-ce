// Package dastengine runs authenticated DAST plans through a dedicated helper.
package dastengine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.DASTEngine = (*Engine)(nil)

// Engine uses a ToolRunner; it never creates an HTTP client in the API process.
type Engine struct {
	runner  ports.ToolRunner
	helper  string
	timeout time.Duration
	maxOut  int
}

func New(runner ports.ToolRunner, helper string, timeout time.Duration, maxOut int) (*Engine, error) {
	if runner == nil {
		return nil, fmt.Errorf("%w: DAST engine requires a tool runner", shared.ErrValidation)
	}
	if strings.TrimSpace(helper) == "" {
		helper = "synapse-dast-helper"
	}
	if timeout <= 0 {
		timeout = ports.DefaultDASTTimeout
	}
	if maxOut <= 0 {
		maxOut = 128 << 10
	}
	return &Engine{runner: runner, helper: helper, timeout: timeout, maxOut: maxOut}, nil
}

func (e *Engine) Run(ctx context.Context, plan ports.DASTPlan, secretEnv []string, authorize func(context.Context, ports.DASTRequest) error) (ports.DASTOutcome, error) {
	if authorize == nil {
		return ports.DASTOutcome{}, fmt.Errorf("%w: DAST request authorization is required", shared.ErrValidation)
	}
	if err := plan.Session.Validate(); err != nil {
		return ports.DASTOutcome{}, fmt.Errorf("validate DAST session: %w", err)
	}
	if strings.TrimSpace(plan.Target) == "" {
		return ports.DASTOutcome{}, fmt.Errorf("%w: DAST target is required", shared.ErrValidation)
	}
	if plan.EgressPolicy == nil || strings.TrimSpace(plan.EgressExecutionKind) == "" || strings.TrimSpace(plan.EgressExecutionID) == "" {
		return ports.DASTOutcome{}, fmt.Errorf("%w: DAST execution requires authoritative signed execution grants", shared.ErrValidation)
	}
	if plan.HelperBin != "" && plan.HelperBin != e.helper {
		return ports.DASTOutcome{}, fmt.Errorf("%w: approved DAST helper does not match configured helper", shared.ErrValidation)
	}
	if len(plan.ConfigDigest) != 64 {
		return ports.DASTOutcome{}, fmt.Errorf("%w: approved DAST configuration digest is required", shared.ErrValidation)
	}
	if plan.RatePerSec <= 0 {
		plan.RatePerSec = ports.DefaultDASTRatePerSec
	}
	if plan.Concurrency <= 0 {
		plan.Concurrency = ports.DefaultDASTConcurrency
	}
	if plan.RatePerSec > ports.DefaultDASTRatePerSec || plan.Concurrency > ports.DefaultDASTConcurrency {
		return ports.DASTOutcome{}, fmt.Errorf("%w: DAST rate and concurrency cannot exceed conservative defaults", shared.ErrValidation)
	}
	stdin, err := json.Marshal(plan)
	if err != nil {
		return ports.DASTOutcome{}, fmt.Errorf("encode DAST plan: %w", err)
	}
	requestR, requestW, err := os.Pipe()
	if err != nil {
		return ports.DASTOutcome{}, fmt.Errorf("open DAST authorization request pipe: %w", err)
	}
	defer func() { _ = requestR.Close() }()
	decisionR, decisionW, err := os.Pipe()
	if err != nil {
		return ports.DASTOutcome{}, fmt.Errorf("open DAST authorization decision pipe: %w", err)
	}
	defer func() { _ = decisionR.Close() }()

	var authErr error
	var authOnce sync.Once
	authDone := make(chan struct{})
	go func() {
		defer close(authDone)
		decoder := json.NewDecoder(bufio.NewReader(requestR))
		encoder := json.NewEncoder(decisionW)
		for {
			var request ports.DASTRequest
			if err := decoder.Decode(&request); err != nil {
				if err != io.EOF {
					authOnce.Do(func() { authErr = fmt.Errorf("read DAST authorization request: %w", err) })
				}
				return
			}
			if err := authorize(ctx, request); err != nil {
				if err := encoder.Encode(ports.DASTAuthorization{}); err != nil {
					authOnce.Do(func() { authErr = fmt.Errorf("write DAST authorization decision: %w", err) })
				}
				continue
			}
			if err := encoder.Encode(ports.DASTAuthorization{Allowed: true}); err != nil {
				authOnce.Do(func() { authErr = fmt.Errorf("write DAST authorization decision: %w", err) })
				return
			}
		}
	}()

	res, runErr := e.runner.Run(ctx, ports.ToolSpec{
		Name:           e.helper,
		Args:           []string{"run", "--config-sha256=" + plan.ConfigDigest},
		Stdin:          stdin,
		Timeout:        e.timeout,
		MaxOutputBytes: e.maxOut,
		// The sandbox places caller files after its seccomp fd: request=4, decision=5.
		Env:                 append([]string{"SYNAPSE_DAST_AUTH_REQUEST_FD=4", "SYNAPSE_DAST_AUTH_DECISION_FD=5"}, secretEnv...),
		ExtraFiles:          []*os.File{requestW, decisionR},
		EngagementID:        plan.EngagementID,
		EgressPolicy:        plan.EgressPolicy,
		EgressExecutionKind: plan.EgressExecutionKind,
		EgressExecutionID:   plan.EgressExecutionID,
	})
	_ = requestW.Close()
	_ = decisionR.Close()
	<-authDone
	_ = decisionW.Close()
	if authErr != nil {
		return ports.DASTOutcome{}, authErr
	}
	if runErr != nil {
		return ports.DASTOutcome{}, fmt.Errorf("run DAST helper: %w", runErr)
	}
	if res.ExitCode != 0 || res.TimedOut || res.Truncated {
		return ports.DASTOutcome{}, fmt.Errorf("DAST helper failed: exit=%d timeout=%t truncated=%t", res.ExitCode, res.TimedOut, res.Truncated)
	}
	var outcome ports.DASTOutcome
	if err := json.NewDecoder(bytes.NewReader(res.Stdout)).Decode(&outcome); err != nil {
		return ports.DASTOutcome{}, fmt.Errorf("decode DAST helper result: %w", err)
	}
	return outcome, nil
}

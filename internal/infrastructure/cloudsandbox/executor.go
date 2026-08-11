// Package cloudsandbox executes credentialed cloud SDK helpers inside the hardened sandbox.
package cloudsandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const credentialFD = 4

type Executor struct {
	runner     ports.ToolRunner
	vault      ports.CredentialVault
	binary     string
	rate       int
	maxOutput  int
	timeout    time.Duration
	egressHost map[cloudposture.Provider][]string
}

var _ ports.CloudSandboxExecutor = (*Executor)(nil)

func New(runner ports.ToolRunner, vault ports.CredentialVault, binary string, rate int, timeout time.Duration, maxOutput int, egressHosts map[cloudposture.Provider][]string) (*Executor, error) {
	if runner == nil || vault == nil || strings.TrimSpace(binary) == "" || timeout <= 0 || maxOutput < 1 {
		return nil, fmt.Errorf("%w: invalid cloud sandbox executor", shared.ErrValidation)
	}
	return &Executor{runner: runner, vault: vault, binary: binary, rate: rate, timeout: timeout, maxOutput: maxOutput, egressHost: egressHosts}, nil
}

func (e *Executor) EnumerateCloud(ctx context.Context, scope ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	if scope.Authorize == nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("%w: cloud operation authorizer is required", shared.ErrForbidden)
	}
	input, err := json.Marshal(struct {
		Scope ports.CloudScope `json:"scope"`
		Rate  int              `json:"rate"`
	}{scope, e.rate})
	if err != nil {
		return cloudposture.Inventory{}, nil, err
	}
	hosts := e.egressHost[scope.Provider]
	if len(hosts) == 0 {
		return cloudposture.Inventory{}, nil, fmt.Errorf("%w: no CSPM egress hosts configured for %s", shared.ErrValidation, scope.Provider)
	}
	policy := &ports.EgressPolicy{}
	for _, host := range hosts {
		policy.AllowDomainRules = append(policy.AllowDomainRules, ports.DomainRule{Host: host, Ports: []uint16{443}})
	}
	secret, err := e.vault.Resolve(ctx, scope.EngagementID, scope.CredentialRef)
	if err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("resolve CSPM credential: %w", err)
	}
	defer clear(secret)
	credentialR, credentialW, err := os.Pipe()
	if err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("create CSPM credential pipe: %w", err)
	}
	defer credentialR.Close()
	go func() {
		_, _ = credentialW.Write(secret)
		_ = credentialW.Close()
	}()
	requestR, requestW, err := os.Pipe()
	if err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("create CSPM authorization request pipe: %w", err)
	}
	defer requestR.Close()
	decisionR, decisionW, err := os.Pipe()
	if err != nil {
		_ = requestW.Close()
		return cloudposture.Inventory{}, nil, fmt.Errorf("create CSPM authorization decision pipe: %w", err)
	}
	defer decisionR.Close()
	var authErr error
	var authOnce sync.Once
	authDone := make(chan struct{})
	go func() {
		defer close(authDone)
		decoder := json.NewDecoder(bufio.NewReader(requestR))
		encoder := json.NewEncoder(decisionW)
		for {
			var operation ports.CloudOperation
			if err := decoder.Decode(&operation); err != nil {
				if err != io.EOF {
					authOnce.Do(func() { authErr = fmt.Errorf("read CSPM authorization request: %w", err) })
				}
				return
			}
			if operation.Provider != scope.Provider || operation.ScopeKey != scope.ScopeKey {
				authOnce.Do(func() { authErr = fmt.Errorf("CSPM authorization scope mismatch") })
				_ = encoder.Encode(struct {
					Allowed bool `json:"allowed"`
				}{})
				return
			}
			allowed := scope.Authorize(ctx, operation) == nil
			if err := encoder.Encode(struct {
				Allowed bool `json:"allowed"`
			}{allowed}); err != nil {
				authOnce.Do(func() { authErr = fmt.Errorf("write CSPM authorization decision: %w", err) })
				return
			}
		}
	}()
	result, runErr := e.runner.Run(ctx, ports.ToolSpec{
		Name: e.binary, Stdin: input, Timeout: e.timeout, MaxOutputBytes: e.maxOutput,
		EngagementID: scope.EngagementID, EgressPolicy: policy, ExtraFiles: []*os.File{credentialR, requestW, decisionR},
		Env: []string{
			fmt.Sprintf("SYNAPSE_CSPM_CREDENTIAL_FD=%d", credentialFD),
			"SYNAPSE_CSPM_AUTH_REQUEST_FD=5",
			"SYNAPSE_CSPM_AUTH_DECISION_FD=6",
		},
	})
	_ = requestW.Close()
	_ = decisionR.Close()
	<-authDone
	_ = decisionW.Close()
	if authErr != nil {
		return cloudposture.Inventory{}, nil, authErr
	}
	if runErr != nil || result.ExitCode != 0 || result.TimedOut || result.Truncated {
		return cloudposture.Inventory{}, nil, fmt.Errorf("sandboxed CSPM helper failed")
	}
	result.Stdout = redact.Bytes(result.Stdout, [][]byte{secret})
	if strings.Contains(string(result.Stdout), redact.Placeholder) {
		return cloudposture.Inventory{}, nil, fmt.Errorf("sandboxed CSPM output contained credential material")
	}
	var output struct {
		Inventory cloudposture.Inventory       `json:"inventory"`
		Coverage  []cloudposture.CoverageIssue `json:"coverage"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(result.Stdout)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return cloudposture.Inventory{}, nil, fmt.Errorf("decode sandboxed CSPM output: %w", err)
	}
	return output.Inventory, output.Coverage, nil
}

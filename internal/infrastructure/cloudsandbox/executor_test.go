package cloudsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type runnerStub struct {
	spec      ports.ToolSpec
	result    ports.ToolResult
	err       error
	operation ports.CloudOperation
}

func (r *runnerStub) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	r.spec = spec
	if len(spec.ExtraFiles) == 3 {
		operation := r.operation
		if operation.Provider == "" {
			operation = ports.CloudOperation{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-test", Name: "ListAccounts"}
		}
		_ = json.NewEncoder(spec.ExtraFiles[1]).Encode(operation)
		_ = spec.ExtraFiles[1].Close()
		var decision struct {
			Allowed bool `json:"allowed"`
		}
		if err := json.NewDecoder(spec.ExtraFiles[2]).Decode(&decision); err != nil || !decision.Allowed {
			return ports.ToolResult{}, fmt.Errorf("authorization denied: %v", err)
		}
	}
	out, _ := json.Marshal(struct {
		Inventory cloudposture.Inventory       `json:"inventory"`
		Coverage  []cloudposture.CoverageIssue `json:"coverage"`
	}{Inventory: cloudposture.Inventory{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-test", Complete: true}})
	if r.err != nil {
		return ports.ToolResult{}, r.err
	}
	if r.result.ExitCode != 0 || r.result.TimedOut || r.result.Truncated {
		return r.result, nil
	}
	return ports.ToolResult{Stdout: out}, nil
}

func TestExecutorUsesSecretPlaceholderAndDefaultDenyEgress(t *testing.T) {
	runner := &runnerStub{}
	executor, err := New(runner, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", Authorize: func(_ context.Context, operation ports.CloudOperation) error {
		if operation.Provider != cloudposture.ProviderAWS || operation.ScopeKey != "aws:organizations/o-test" || operation.Name != "ListAccounts" {
			t.Fatalf("operation = %#v", operation)
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if runner.spec.EgressPolicy == nil || len(runner.spec.EgressPolicy.AllowDomainRules) != 1 || runner.spec.HostNetwork {
		t.Fatalf("egress policy = %#v", runner.spec.EgressPolicy)
	}
	if len(runner.spec.Env) != 3 || runner.spec.Env[0] != "SYNAPSE_CSPM_CREDENTIAL_FD=4" || runner.spec.Env[1] != "SYNAPSE_CSPM_AUTH_REQUEST_FD=5" || runner.spec.Env[2] != "SYNAPSE_CSPM_AUTH_DECISION_FD=6" || len(runner.spec.ExtraFiles) != 3 {
		t.Fatalf("env=%#v files=%d", runner.spec.Env, len(runner.spec.ExtraFiles))
	}
}

func TestExecutorPreservesRunnerFailure(t *testing.T) {
	runErr := errors.New("sandbox unavailable")
	executor, err := New(&runnerStub{err: runErr}, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if !errors.Is(err, runErr) {
		t.Fatalf("error = %v", err)
	}
}

func TestExecutorReportsHelperExitState(t *testing.T) {
	executor, err := New(&runnerStub{result: ports.ToolResult{ExitCode: 3, TimedOut: true}}, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "exit_code=3 timed_out=true truncated=false") {
		t.Fatalf("error = %v", err)
	}
}

func TestExecutorPreservesAuthorizationDenial(t *testing.T) {
	executor, err := New(&runnerStub{}, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", Authorize: func(context.Context, ports.CloudOperation) error { return shared.ErrForbidden }})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("error = %v", err)
	}
}

func TestExecutorClassifiesAuthorizationScopeMismatchAsForbidden(t *testing.T) {
	runner := &runnerStub{}
	runner.operation = ports.CloudOperation{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-other", Name: "ListAccounts"}
	executor, err := New(runner, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("error = %v", err)
	}
}

type nilVault struct{}

func (nilVault) Resolve(context.Context, shared.ID, string) ([]byte, error)      { return nil, nil }
func (nilVault) Put(context.Context, shared.ID, string, []byte) error            { return nil }
func (nilVault) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) { return nil, nil }
func (nilVault) Delete(context.Context, shared.ID, string) error                 { return nil }

// secretVault hands out real credential material so the redaction path is exercised for real
// rather than against nilVault's empty secret.
type secretVault struct{ secret []byte }

func (v secretVault) Resolve(context.Context, shared.ID, string) ([]byte, error) {
	return append([]byte(nil), v.secret...), nil
}
func (secretVault) Put(context.Context, shared.ID, string, []byte) error            { return nil }
func (secretVault) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) { return nil, nil }
func (secretVault) Delete(context.Context, shared.ID, string) error                 { return nil }

// TestExecutorSurfacesHelperStderr pins the helper's failure REASON onto the error. The executor
// used to report only "exit_code=1", so an operator-fixable misconfiguration (unassumable role,
// denied API, blocked egress) was indistinguishable from a crash: the durable run dead-lettered
// after three attempts with no recorded cause anywhere in the worker log or the run row.
func TestExecutorSurfacesHelperStderr(t *testing.T) {
	runner := &runnerStub{result: ports.ToolResult{ExitCode: 1, Stderr: []byte("enumerate accounts: AccessDenied\n")}}
	executor, err := New(runner, nilVault{}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if err == nil {
		t.Fatal("expected a helper failure")
	}
	if !strings.Contains(err.Error(), "exit_code=1") {
		t.Errorf("error = %v, want the exit code preserved", err)
	}
	if !strings.Contains(err.Error(), "reason=enumerate accounts: AccessDenied") {
		t.Errorf("error = %v, want the helper's stderr reason", err)
	}
}

// TestExecutorNeverLeaksCredentialsThroughStderr is the other half of the contract: stderr is
// attacker-influenced, untrusted output on a credentialed path, so a helper that echoes its own
// credential must not turn an error message into a secret sink.
func TestExecutorNeverLeaksCredentialsThroughStderr(t *testing.T) {
	const secret = "AKIAEXAMPLECANARY"
	runner := &runnerStub{result: ports.ToolResult{ExitCode: 1, Stderr: []byte("failed for key " + secret)}}
	executor, err := New(runner, secretVault{secret: []byte(secret)}, "synapse-cspm", 5, time.Minute, 1<<20, map[cloudposture.Provider][]string{cloudposture.ProviderAWS: {"organizations.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executor.EnumerateCloud(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAWS, Root: "o-test", ScopeKey: "aws:organizations/o-test", CredentialRef: "aws-prod", Authorize: func(context.Context, ports.CloudOperation) error { return nil }})
	if err == nil {
		t.Fatal("expected a helper failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("credential material leaked into the error message")
	}
	if !strings.Contains(err.Error(), "reason=<redacted>") {
		t.Errorf("error = %v, want the reason dropped once a placeholder survives", err)
	}
}

// TestDiagnosticBoundsAndNormalizesReason keeps the suffix log-safe: empty stderr adds nothing, and
// a malfunctioning helper cannot emit an unbounded multi-line blob into a structured log field.
func TestDiagnosticBoundsAndNormalizesReason(t *testing.T) {
	if got := diagnostic(nil, nil); got != "" {
		t.Errorf("diagnostic(nil) = %q, want empty", got)
	}
	if got := diagnostic([]byte("  \n\t "), nil); got != "" {
		t.Errorf("diagnostic(whitespace) = %q, want empty", got)
	}
	if got := diagnostic([]byte("first line\nsecond line"), nil); got != " reason=first line second line" {
		t.Errorf("diagnostic(multiline) = %q, want a single line", got)
	}
	long := diagnostic([]byte(strings.Repeat("x", diagnosticCap*3)), nil)
	if len(long) > diagnosticCap+len(" reason=")+len("…") {
		t.Errorf("diagnostic(long) length = %d, want bounded by diagnosticCap", len(long))
	}
}

package cloudsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type runnerStub struct{ spec ports.ToolSpec }

func (r *runnerStub) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	r.spec = spec
	if len(spec.ExtraFiles) == 3 {
		_ = json.NewEncoder(spec.ExtraFiles[1]).Encode(ports.CloudOperation{Provider: cloudposture.ProviderAWS, ScopeKey: "aws:organizations/o-test", Name: "ListAccounts"})
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

type nilVault struct{}

func (nilVault) Resolve(context.Context, shared.ID, string) ([]byte, error)      { return nil, nil }
func (nilVault) Put(context.Context, shared.ID, string, []byte) error            { return nil }
func (nilVault) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) { return nil, nil }
func (nilVault) Delete(context.Context, shared.ID, string) error                 { return nil }

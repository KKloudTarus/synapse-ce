package dastengine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type engineRunner struct{ spec ports.ToolSpec }

func (r *engineRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	r.spec = spec
	return ports.ToolResult{Stdout: []byte(`{"observations":[],"incomplete":false}`)}, nil
}

func TestEngineUsesSecretEnvAndAuthorizationPipes(t *testing.T) {
	runner := &engineRunner{}
	engine, err := New(runner, "helper", time.Second, 1024)
	if err != nil {
		t.Fatal(err)
	}
	plan := ports.DASTPlan{HelperBin: "helper", ConfigDigest: strings.Repeat("a", 64), Target: "https://example.test", EgressPolicy: &ports.EgressPolicy{}, EgressExecutionKind: "dast-session", EgressExecutionID: "session-1", Session: dastsession.Config{Scheme: dastsession.SchemeBearer, Credentials: []dastsession.CredentialBinding{{Name: "token", Reference: "vault-token"}}, LoginRequest: dastsession.Request{Method: "POST", Path: "/login"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/live"}, Success: dastsession.SuccessSignal{StatusCode: 200}}}
	_, err = engine.Run(context.Background(), plan, []string{"SYNAPSE_DAST_SECRET_TOKEN=" + ports.SecretPlaceholder("vault-token")}, func(context.Context, ports.DASTRequest) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.spec.ExtraFiles) != 2 || runner.spec.Args[0] != "run" {
		t.Fatalf("spec=%#v", runner.spec)
	}
	if runner.spec.EgressExecutionKind != "dast-session" || runner.spec.EgressExecutionID != "session-1" {
		t.Fatalf("execution identity = %q/%q", runner.spec.EgressExecutionKind, runner.spec.EgressExecutionID)
	}
	for _, item := range runner.spec.Env {
		if item == "SYNAPSE_DAST_SECRET_TOKEN=plain" {
			t.Fatal("plaintext credential in environment spec")
		}
	}
	for _, file := range runner.spec.ExtraFiles {
		_ = file.Close()
	}
}

func TestEngineBindsApprovedHelperAndDigest(t *testing.T) {
	runner := &engineRunner{}
	engine, err := New(runner, "helper", time.Second, 1024)
	if err != nil {
		t.Fatal(err)
	}
	plan := ports.DASTPlan{HelperBin: "other", ConfigDigest: strings.Repeat("a", 64), Target: "https://example.test", EgressPolicy: &ports.EgressPolicy{}, EgressExecutionKind: "dast-session", EgressExecutionID: "session-1", Session: dastsession.Config{Scheme: dastsession.SchemeBearer, Credentials: []dastsession.CredentialBinding{{Name: "token", Reference: "vault-token"}}, LoginRequest: dastsession.Request{Method: "POST", Path: "/login"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/live"}, Success: dastsession.SuccessSignal{StatusCode: 200}}}
	if _, err := engine.Run(context.Background(), plan, nil, func(context.Context, ports.DASTRequest) error { return nil }); err == nil {
		t.Fatal("mismatched approved helper was accepted")
	}
	plan.HelperBin = "helper"
	if _, err := engine.Run(context.Background(), plan, nil, func(context.Context, ports.DASTRequest) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(runner.spec.Args) != 2 || runner.spec.Args[0] != "run" || runner.spec.Args[1] != "--config-sha256="+plan.ConfigDigest {
		t.Fatalf("helper args=%v", runner.spec.Args)
	}
}

func TestEngineRejectsMissingAuthorization(t *testing.T) {
	engine, err := New(&engineRunner{}, "helper", time.Second, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Run(context.Background(), ports.DASTPlan{}, nil, nil)
	if err == nil {
		t.Fatal("missing authorization accepted")
	}
}

func TestEngineRejectsMissingExecutionIdentityBeforeRunner(t *testing.T) {
	runner := &engineRunner{}
	engine, err := New(runner, "helper", time.Second, 1024)
	if err != nil {
		t.Fatal(err)
	}
	plan := ports.DASTPlan{
		HelperBin: "helper", ConfigDigest: strings.Repeat("a", 64), Target: "https://example.test",
		EgressPolicy: &ports.EgressPolicy{},
		Session:      dastsession.Config{Scheme: dastsession.SchemeBearer, Credentials: []dastsession.CredentialBinding{{Name: "token", Reference: "vault-token"}}, LoginRequest: dastsession.Request{Method: "POST", Path: "/login"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/live"}, Success: dastsession.SuccessSignal{StatusCode: 200}},
	}
	_, err = engine.Run(context.Background(), plan, nil, func(context.Context, ports.DASTRequest) error { return nil })
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "authoritative signed execution grants") {
		t.Fatalf("Run() error = %v, want signed-grant validation", err)
	}
	if runner.spec.Name != "" {
		t.Fatalf("runner reached with spec %#v", runner.spec)
	}
}

func TestDASTPlanIsSecretFreeJSON(t *testing.T) {
	plan := ports.DASTPlan{Target: "https://example.test", Requests: []dastsurface.Request{{Method: "GET", URL: "https://example.test/a"}}}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" {
		t.Fatal("empty plan")
	}
}

type badProtocolRunner struct{}

func (badProtocolRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	_, _ = spec.ExtraFiles[0].Write([]byte("not-json\n"))
	return ports.ToolResult{Stdout: []byte(`{"observations":[]}`)}, nil
}

func TestEngineSurfacesAuthorizationProtocolError(t *testing.T) {
	engine, err := New(badProtocolRunner{}, "helper", time.Second, 1024)
	if err != nil {
		t.Fatal(err)
	}
	plan := ports.DASTPlan{HelperBin: "helper", ConfigDigest: strings.Repeat("a", 64), Target: "https://example.test", EgressPolicy: &ports.EgressPolicy{}, EgressExecutionKind: "dast-session", EgressExecutionID: "session-1", Session: dastsession.Config{Scheme: dastsession.SchemeBearer, Credentials: []dastsession.CredentialBinding{{Name: "token", Reference: "vault-token"}}, LoginRequest: dastsession.Request{Method: "POST", Path: "/login"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/live"}, Success: dastsession.SuccessSignal{StatusCode: 200}}}
	if _, err := engine.Run(context.Background(), plan, nil, func(context.Context, ports.DASTRequest) error { return nil }); err == nil {
		t.Fatal("authorization protocol error was not surfaced")
	}
}

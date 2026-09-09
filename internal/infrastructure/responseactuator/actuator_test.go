package responseactuator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeProcesses struct {
	stopped   shared.ID
	restarted shared.ID
	already   bool
	err       error
}

func (f *fakeProcesses) StopProcess(_ context.Context, target shared.ID) (bool, error) {
	f.stopped = target
	return f.already, f.err
}

func (f *fakeProcesses) RestartProcess(_ context.Context, target shared.ID) (bool, error) {
	f.restarted = target
	return f.already, f.err
}

func actuatorCommand(t *testing.T) fleetagent.ResponseCommand {
	t.Helper()
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rdom.CanonicalDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	return fleetagent.ResponseCommand{
		ProtocolVersion: fleetagent.ResponseCommandProtocolVersion, CommandID: "command-1", TenantID: "tenant-1",
		AgentID: "agent-1", AssetID: "asset-1", EngagementID: "engagement-1", Action: action,
		ActionDigest: digest, AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("a", 64),
		AuthorizationTarget: engagement.Target{Kind: engagement.TargetDomain, Value: "process-1"},
		Target: responsesaga.TargetFingerprint{
			Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1",
		},
		IssuedAt: now, NotAfter: now.Add(time.Minute), SigningKeyID: "key-1", Signature: "signed-upstream",
	}
}

func TestActuatorUsesTypedProcessBoundary(t *testing.T) {
	processes := &fakeProcesses{}
	actuator, err := New(processes)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := actuator.ExecuteResponse(context.Background(), actuatorCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	if processes.stopped != "process-1" || outcome.ObservedRadius != offensivepolicy.RadiusStateChanging || outcome.AffectedCount != 1 {
		t.Fatalf("stop outcome=%+v processes=%+v", outcome, processes)
	}

	processes.already = true
	outcome, err = actuator.ExecuteResponse(context.Background(), actuatorCommand(t))
	if err != nil || !outcome.AlreadyApplied || outcome.AffectedCount != 0 {
		t.Fatalf("idempotent stop outcome=%+v err=%v", outcome, err)
	}
}

func TestActuatorKeepsReversalSeparate(t *testing.T) {
	processes := &fakeProcesses{}
	actuator, err := New(processes)
	if err != nil {
		t.Fatal(err)
	}
	command := actuatorCommand(t)
	command.Reversal = true
	if _, err := actuator.ExecuteResponse(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if processes.restarted != "process-1" || processes.stopped != "" {
		t.Fatalf("reversal crossed wrong boundary: %+v", processes)
	}
	processes.already = true
	outcome, err := actuator.ExecuteResponse(context.Background(), command)
	if err != nil || !outcome.AlreadyApplied || outcome.AffectedCount != 0 {
		t.Fatalf("idempotent restart outcome=%+v err=%v", outcome, err)
	}
}

func TestActuatorFailsClosedBeforeProcessBoundary(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil process controller error=%v", err)
	}
	processes := &fakeProcesses{}
	actuator, _ := New(processes)
	command := actuatorCommand(t)
	command.Target.ProcessEntityID = "different-process"
	if _, err := actuator.ExecuteResponse(context.Background(), command); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unbound command error=%v", err)
	}
	if processes.stopped != "" || processes.restarted != "" {
		t.Fatal("invalid command reached the process boundary")
	}
}

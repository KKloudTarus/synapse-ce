package fleetagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func responseCommandFixture(t *testing.T) (ResponseCommand, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "pe_11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rdom.CanonicalDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(3_000_000, 0).UTC()
	command := ResponseCommand{
		ProtocolVersion: ResponseCommandProtocolVersion, CommandID: "command-1", TenantID: "tenant-1",
		AgentID: "executor-1", AssetID: "asset-1", EngagementID: "eng-1", Action: action,
		ActionDigest: digest, AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("a", 64),
		AuthorizationTarget: engagement.Target{Kind: engagement.TargetProcess, Value: "pe_11111111111111111111111111111111"},
		Target:              responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "pe_11111111111111111111111111111111"},
		HaltGeneration:      4, IssuedAt: now, NotAfter: now.Add(time.Minute), SigningKeyID: evidence.KeyFingerprint(public),
	}
	command.Signature = SignResponseCommand(private, command)
	return command, public, private
}

func TestResponseCommandSignatureBindsExecutionFields(t *testing.T) {
	command, public, _ := responseCommandFixture(t)
	if err := VerifyResponseCommand(public, command); err != nil {
		t.Fatalf("verify command: %v", err)
	}

	tampered := command
	tampered.HaltGeneration++
	if err := VerifyResponseCommand(public, tampered); !errors.Is(err, ErrBadResponseCommandSignature) {
		t.Fatalf("tampered halt fence must fail signature verification, got %v", err)
	}
	tampered = command
	tampered.AgentID = "executor-2"
	if err := VerifyResponseCommand(public, tampered); !errors.Is(err, ErrBadResponseCommandSignature) {
		t.Fatalf("tampered executor identity must fail signature verification, got %v", err)
	}
	tampered = command
	tampered.AuthorizationTarget.Value = "pe_22222222222222222222222222222222"
	if err := VerifyResponseCommand(public, tampered); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("tampered authorization target must fail validation, got %v", err)
	}
}

func TestResponseCommandRejectsCrossAssetAndUnsupportedAction(t *testing.T) {
	command, _, private := responseCommandFixture(t)
	command.AssetID = "asset-2"
	command.Signature = SignResponseCommand(private, command)
	if err := command.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-asset process target must fail, got %v", err)
	}

	action, err := rdom.NewAction("action-2", rdom.KindQuarantineFile, "file-1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rdom.CanonicalDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	command.Action = action
	command.ActionDigest = digest
	command.Signature = SignResponseCommand(private, command)
	if err := command.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported response kind must fail closed, got %v", err)
	}
}

func TestResponseCommandRejectsWrongAuthorizationKind(t *testing.T) {
	for _, kind := range []engagement.TargetKind{engagement.TargetCloudAccount, engagement.TargetRepo} {
		t.Run(string(kind), func(t *testing.T) {
			command, _, private := responseCommandFixture(t)
			command.AuthorizationTarget.Kind = kind
			command.Signature = SignResponseCommand(private, command)
			if err := command.Validate(); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("same process identity under %s must be rejected, got %v", kind, err)
			}
		})
	}
}

func TestResponseExecutionOutcomeUnknownCannotClaimEffect(t *testing.T) {
	result := ResponseExecutionResult{
		AttemptKey: "attempt-1", CommandDigest: strings.Repeat("a", 64), LeaseID: "lease-1",
		State: ResponseExecutionOutcomeUnknown, CompletedAt: time.Now().UTC(),
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("minimal ambiguous result must validate: %v", err)
	}
	result.AffectedCount = 1
	if err := result.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("ambiguous result claiming an effect must fail, got %v", err)
	}
}

func TestResponseExecutionJournalBindsReplacementToReversal(t *testing.T) {
	command, _, private := responseCommandFixture(t)
	command.Reversal = true
	command.Signature = SignResponseCommand(private, command)
	result := ResponseExecutionResult{AttemptKey: command.AttemptKey, CommandDigest: ResponseCommandDigest(command), LeaseID: "lease", State: ResponseExecutionApplied, ObservedRadius: offensivepolicy.RadiusStateChanging, AffectedCount: 1, CompletedAt: command.IssuedAt.Add(time.Second)}
	entry := ResponseExecutionJournalEntry{Version: ResponseExecutionJournalVersion, Command: command, CommandDigest: result.CommandDigest, LeaseID: result.LeaseID, LeaseUntil: command.NotAfter, State: result.State, Result: &result}
	if err := entry.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing replacement err=%v", err)
	}
	result.ReplacementProcessEntityID = "pe_22222222222222222222222222222222"
	if err := entry.Validate(); err != nil {
		t.Fatalf("valid reversal: %v", err)
	}
	changed := result
	changed.ReplacementProcessEntityID = "pe_33333333333333333333333333333333"
	if SameResponseExecutionResult(result, changed) {
		t.Fatal("result replay ignored replacement identity")
	}
	result.ReplacementProcessEntityID = command.Target.ProcessEntityID
	if err := entry.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("original as replacement err=%v", err)
	}
	result.ReplacementProcessEntityID = "bad"
	if err := entry.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("malformed replacement err=%v", err)
	}
}

package fleetagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
)

func TestResponseHaltCommandSignatureBindsGenerationAndAgent(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	command := ResponseHaltCommand{
		ProtocolVersion: ResponseHaltCommandProtocolVersion, CommandID: "halt-1", TenantID: "tenant-1",
		AgentID: "agent-1", AssetID: "asset-1", Generation: 2, AttemptKey: "halt-attempt-1", IssuedAt: now, NotAfter: now.Add(time.Minute),
		SigningKeyID: evidence.KeyFingerprint(public),
	}
	command.Signature = SignResponseHaltCommand(private, command)
	if err := VerifyResponseHaltCommand(public, command); err != nil {
		t.Fatalf("verify halt command: %v", err)
	}
	tampered := command
	tampered.Generation++
	if err := VerifyResponseHaltCommand(public, tampered); !errors.Is(err, ErrBadResponseCommandSignature) {
		t.Fatalf("tampered generation error=%v", err)
	}
	tampered = command
	tampered.AgentID = "agent-2"
	if err := VerifyResponseHaltCommand(public, tampered); !errors.Is(err, ErrBadResponseCommandSignature) {
		t.Fatalf("tampered agent error=%v", err)
	}
}

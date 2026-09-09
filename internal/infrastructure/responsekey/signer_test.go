package responsekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func signingCommand(t *testing.T, at time.Time) fleetagent.ResponseCommand {
	t.Helper()
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rdom.CanonicalDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	return fleetagent.ResponseCommand{
		ProtocolVersion: fleetagent.ResponseCommandProtocolVersion, CommandID: "command-1", TenantID: "tenant-1",
		AgentID: "agent-1", AssetID: "asset-1", EngagementID: "engagement-1", Action: action, ActionDigest: digest,
		AttemptKey: "attempt-1", VerificationChallenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AuthorizationTarget: engagement.Target{Kind: engagement.TargetDomain, Value: "process-1"},
		Target:              responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		IssuedAt:            at, NotAfter: at.Add(time.Minute),
	}
}

func TestSignerSignsWithBoundedFingerprintKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1000, 0).UTC()
	signer, err := NewSigner(private, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	command, err := signer.Sign(signingCommand(t, at))
	if err != nil {
		t.Fatal(err)
	}
	if command.SigningKeyID != signer.PublicKey().KeyID {
		t.Fatalf("signing key id=%q", command.SigningKeyID)
	}
	if err := fleetagent.VerifyResponseCommand(public, command); err != nil {
		t.Fatalf("verify signed command: %v", err)
	}
	if _, err := signer.Sign(command); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("re-signing must conflict, got %v", err)
	}
}

func TestLoadSignerFileRequiresOwnerOnlyStrictDocument(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(signingKeyDocument{
		Version: bundleVersion, PrivateKey: base64.StdEncoding.EncodeToString(private.Seed()),
		NotBefore: time.Unix(100, 0).UTC(), NotAfter: time.Unix(300, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "response-signing-key.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignerFile(path); err != nil {
		t.Fatalf("load protected signer: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignerFile(path); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("group-readable signer error=%v", err)
	}
}

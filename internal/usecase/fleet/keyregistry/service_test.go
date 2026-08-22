package keyregistry

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeAudit struct{ actions []string }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.actions = append(a.actions, e.Action)
	return nil
}
func (a *fakeAudit) has(action string) bool {
	for _, x := range a.actions {
		if x == action {
			return true
		}
	}
	return false
}

func newHarness(t *testing.T) (*Service, *fakeAudit, context.Context) {
	t.Helper()
	audit := &fakeAudit{}
	svc, err := NewService(memory.NewAgentSigningKeyStore(), audit, fakeClock{t: time.Unix(1_000_000, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return svc, audit, shared.WithTenant(context.Background(), "t1")
}

// proofFor builds a valid registration request for agentID: it generates a keypair, produces the
// proof-of-possession the same way an agent would, and returns the request plus the private key so a test
// can also craft a mismatched proof.
func proofFor(t *testing.T, agentID shared.ID, purpose fleetagent.SigningPurpose) (RegisterRequest, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	nb, na := time.Unix(0, 0).UTC(), time.Unix(3600, 0).UTC() // 1h window, within MaxSigningKeyValidity
	key, err := fleetagent.NewSigningKey(agentID, purpose, pub, nb, na)
	if err != nil {
		t.Fatal(err)
	}
	return RegisterRequest{
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub),
		Purpose:      string(purpose),
		NotBefore:    nb,
		NotAfter:     na,
		Proof:        fleetagent.ProveKeyPossession(priv, key),
	}, priv, pub
}

func TestRegisterWithProofSucceedsAndIsResolvable(t *testing.T) {
	svc, audit, ctx := newHarness(t)
	req, _, _ := proofFor(t, "agent:1", fleetagent.PurposeDetectionBatch)
	key, err := svc.Register(ctx, "agent:1", req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if key.AgentID != "agent:1" || key.Purpose != fleetagent.PurposeDetectionBatch {
		t.Fatalf("unexpected key: %+v", key)
	}
	if !audit.has("fleet.key.registered") {
		t.Error("a registration must be audited")
	}
	keys, err := svc.List(ctx, "agent:1")
	if err != nil || len(keys) != 1 || keys[0].KeyID != key.KeyID {
		t.Fatalf("registered key must be listable, got %+v err=%v", keys, err)
	}
}

func TestRegisterFailsClosedWithoutValidProof(t *testing.T) {
	svc, audit, ctx := newHarness(t)
	req, _, _ := proofFor(t, "agent:1", fleetagent.PurposeDetectionBatch)
	// A proof made with a DIFFERENT private key than the posted public key must not verify.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	bad := req
	key, _ := fleetagent.NewSigningKey("agent:1", fleetagent.PurposeDetectionBatch, mustDecode(t, req.PublicKeyB64), req.NotBefore, req.NotAfter)
	bad.Proof = fleetagent.ProveKeyPossession(otherPriv, key)
	if _, err := svc.Register(ctx, "agent:1", bad); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a bad possession proof must be forbidden, got %v", err)
	}
	if !audit.has("fleet.key.rejected") {
		t.Error("a rejected registration must be audited")
	}
	if keys, _ := svc.List(ctx, "agent:1"); len(keys) != 0 {
		t.Fatalf("nothing must be registered on a bad proof, got %d", len(keys))
	}
}

func TestRegisterBindsToAuthenticatedAgent(t *testing.T) {
	svc, _, ctx := newHarness(t)
	// The agent proved possession for agent:1, but registration is attempted under authenticated agent:2.
	// The server rebuilds the key against the AUTHENTICATED id, so the binding message (and PoP) no longer
	// matches — a key can only ever be registered for the agent that authenticated. Fail closed.
	req, _, _ := proofFor(t, "agent:1", fleetagent.PurposeDetectionBatch)
	if _, err := svc.Register(ctx, "agent:2", req); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a proof bound to another agent must be forbidden, got %v", err)
	}
}

func TestRegisterValidatesInput(t *testing.T) {
	svc, _, ctx := newHarness(t)
	good, _, _ := proofFor(t, "agent:1", fleetagent.PurposeDetectionBatch)
	if _, err := svc.Register(ctx, "agent:1", RegisterRequest{PublicKeyB64: "!!not base64", Purpose: good.Purpose, NotBefore: good.NotBefore, NotAfter: good.NotAfter, Proof: good.Proof}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad public key must be ErrValidation, got %v", err)
	}
	bad := good
	bad.Purpose = "not-a-purpose"
	if _, err := svc.Register(ctx, "agent:1", bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown purpose must be ErrValidation, got %v", err)
	}
	if _, err := svc.Register(ctx, "", good); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("empty authenticated agent must be forbidden, got %v", err)
	}
}

func TestRegisterRejectsOverLongValidity(t *testing.T) {
	svc, _, ctx := newHarness(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// A window longer than MaxSigningKeyValidity must be refused (rotation hygiene), fail-closed.
	nb := time.Unix(0, 0).UTC()
	na := nb.Add(MaxSigningKeyValidity + 24*time.Hour)
	key, err := fleetagent.NewSigningKey("agent:1", fleetagent.PurposeDetectionBatch, pub, nb, na)
	if err != nil {
		t.Fatal(err)
	}
	req := RegisterRequest{
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub),
		Purpose:      string(fleetagent.PurposeDetectionBatch),
		NotBefore:    nb, NotAfter: na,
		Proof: fleetagent.ProveKeyPossession(priv, key),
	}
	if _, err := svc.Register(ctx, "agent:1", req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an over-long validity window must be ErrValidation, got %v", err)
	}
	if keys, _ := svc.List(ctx, "agent:1"); len(keys) != 0 {
		t.Fatalf("nothing must be registered on an over-long window, got %d", len(keys))
	}
}

func TestRevokeRequiresActorAndMarksRevoked(t *testing.T) {
	svc, audit, ctx := newHarness(t)
	req, _, _ := proofFor(t, "agent:1", fleetagent.PurposeDetectionBatch)
	key, err := svc.Register(ctx, "agent:1", req)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, "agent:1", key.KeyID, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("revoke without an actor must be ErrValidation, got %v", err)
	}
	if err := svc.Revoke(ctx, "agent:1", key.KeyID, "operator@x"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !audit.has("fleet.key.revoked") {
		t.Error("a revoke must be audited")
	}
	keys, _ := svc.List(ctx, "agent:1")
	if len(keys) != 1 || keys[0].RevokedAt.IsZero() {
		t.Fatalf("the key must be marked revoked, got %+v", keys)
	}
}

func mustDecode(t *testing.T, b64 string) ed25519.PublicKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PublicKey(raw)
}

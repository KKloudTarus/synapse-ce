package rulepack

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type testGateEvidenceSigner struct{ priv ed25519.PrivateKey }

func (s testGateEvidenceSigner) Sign(_ context.Context, head string) (evidence.Attestation, error) {
	pub := s.priv.Public().(ed25519.PublicKey)
	return evidence.Attestation{
		Algorithm: "ed25519",
		KeyID: evidence.KeyFingerprint(pub),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Context: GateEvidenceAttestationContext,
		Head: head,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, evidence.AttestationMessage(GateEvidenceAttestationContext, head))),
	}, nil
}

func TestEvidenceCollectorAttestsAuthoritativeRetroAndPurpleEvidence(t *testing.T) {
	p := gatePack(t)
	now := time.Unix(10, 0).UTC()
	event := detection.Event{Class: detection.ClassProcess, At: now, Host: "h1", Process: &detection.ProcessEvent{Comm: "tool", Args: []string{"run", "--danger"}}}
	hunter := &fakeHunter{result: ports.HuntResult{Events: []detection.Event{event}, Complete: true}}
	purpleRow := purplecoverage.Coverage{
		TenantID: "t1", EngagementID: "e1", RunID: "run1", AssetID: "asset1", TechniqueID: "emu.test",
		TaxonomyRef: "T1059", Expected: "det.test", Actual: []string{"det.test"}, Verdict: purplecoverage.VerdictCovered, ComputedAt: now,
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewEvidenceCollector(hunter, fakePurpleReader{rows: []purplecoverage.Coverage{purpleRow}}, testGateEvidenceSigner{priv: priv})
	if err != nil {
		t.Fatal(err)
	}
	req := GateEvidenceRequest{
		Deployment: gateDeployment(p, DeploymentCandidateForTest()),
		Policy: gatePolicy(),
		Costs: []RuleCostObservation{{RuleID: "det.test", LatencyMicros: 50, CPUMicrosPerHostDay: 500}},
		RetroCases: []RetroCase{{RuleID: "det.test", Query: ports.HuntQuery{HostID: "h1", Class: detection.ClassProcess, Since: now.Add(-time.Minute), Until: now.Add(time.Minute), Limit: 100}}},
		Purple: PurpleRequest{EngagementID: "e1", RunID: "run1"},
		Evaluation: goodSample(),
	}
	signed, err := collector.Collect(context.Background(), p, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed.Input.Retro) != 1 || signed.Input.Retro[0].MatchedEvents != 1 || len(signed.Input.Purple) != 1 {
		t.Fatalf("collected evidence = %+v", signed.Input)
	}
	input, err := VerifyGateEvidence(signed, p, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Retro) != 1 || len(input.Purple) != 1 {
		t.Fatalf("verified evidence = %+v", input)
	}
}

// DeploymentCandidateForTest keeps this test independent of literal state spelling while reusing the
// same deployment helper as the gate tests in this package.
func DeploymentCandidateForTest() string {
	return "candidate"
}

func TestVerifyGateEvidenceRejectsTamperAndWrongTrustedKey(t *testing.T) {
	p := gatePack(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	input := goodGateInput(p)
	head, err := gateEvidenceHead(p.ID, p.Version, p.Digest, input)
	if err != nil {
		t.Fatal(err)
	}
	signer := testGateEvidenceSigner{priv: priv}
	att, err := signer.Sign(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	signed := SignedGateEvidence{PackID: p.ID, PackVersion: p.Version, PackDigest: p.Digest, Input: input, Attestation: att}
	if _, err := VerifyGateEvidence(signed, p, pub); err != nil {
		t.Fatalf("valid signed evidence: %v", err)
	}

	tampered := signed
	tampered.Input.Retro = append([]RetroEvidence(nil), signed.Input.Retro...)
	tampered.Input.Retro[0].MatchedEvents++
	if _, err := VerifyGateEvidence(tampered, p, pub); err == nil {
		t.Fatal("tampered release evidence must fail attestation verification")
	}
	wrongPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGateEvidence(signed, p, wrongPub); err == nil {
		t.Fatal("release evidence must not trust a different externally pinned key")
	}
}

func TestGateEvidenceHeadCanonicalizesSetLikeOrdering(t *testing.T) {
	p := gatePack(t)
	a := goodGateInput(p)
	b := cloneGateInput(a)
	b.Deployment.AvailableFields[0], b.Deployment.AvailableFields[1] = b.Deployment.AvailableFields[1], b.Deployment.AvailableFields[0]
	b.Evaluation.AvailableFields[0], b.Evaluation.AvailableFields[1] = b.Evaluation.AvailableFields[1], b.Evaluation.AvailableFields[0]
	b.Purple[0].Actual = []string{"zzz", "det.test"}
	a.Purple[0].Actual = []string{"det.test", "zzz"}
	ha, err := gateEvidenceHead(p.ID, p.Version, p.Digest, a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := gateEvidenceHead(p.ID, p.Version, p.Digest, b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("set-like ordering changed gate evidence identity: %s != %s", ha, hb)
	}
}

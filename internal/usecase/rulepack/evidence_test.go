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
	rulepackdomain "github.com/KKloudTarus/synapse-ce/internal/domain/rulepack"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type testGateEvidenceSigner struct{ priv ed25519.PrivateKey }

func (s testGateEvidenceSigner) Sign(_ context.Context, head string) (evidence.Attestation, error) {
	pub := s.priv.Public().(ed25519.PublicKey)
	return evidence.Attestation{
		Algorithm: "ed25519",
		KeyID:     evidence.KeyFingerprint(pub),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Context:   GateEvidenceAttestationContext,
		Head:      head,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, evidence.AttestationMessage(GateEvidenceAttestationContext, head))),
	}, nil
}

func gateRetroQueryProvenance() []RetroQueryProvenance {
	now := time.Unix(10, 0).UTC()
	return []RetroQueryProvenance{{
		RuleID: "det.test", HostID: "h1", Class: detection.ClassProcess,
		Since: now.Add(-time.Minute), Until: now.Add(time.Minute), Limit: 100,
	}}
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
		Deployment: gateDeployment(p, rulepackdomain.DeploymentCandidate),
		Policy:     gatePolicy(),
		Costs:      []RuleCostObservation{{RuleID: "det.test", LatencyMicros: 50, CPUMicrosPerHostDay: 500}},
		RetroCases: []RetroCase{{RuleID: "det.test", Query: ports.HuntQuery{HostID: "h1", Class: detection.ClassProcess, Since: now.Add(-time.Minute), Until: now.Add(time.Minute), Limit: 100}}},
		Purple:     PurpleRequest{EngagementID: "e1", RunID: "run1"},
		Evaluation: goodSample(),
	}
	signed, err := collector.Collect(context.Background(), p, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed.Input.Retro) != 1 || signed.Input.Retro[0].MatchedEvents != 1 || len(signed.Input.Purple) != 1 {
		t.Fatalf("collected evidence = %+v", signed.Input)
	}
	if len(signed.RetroQueries) != 1 || signed.RetroQueries[0].RuleID != "det.test" || signed.RetroQueries[0].HostID != "h1" || signed.RetroQueries[0].Limit != 100 {
		t.Fatalf("retro query provenance = %+v", signed.RetroQueries)
	}
	input, err := VerifyGateEvidence(signed, p, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Retro) != 1 || len(input.Purple) != 1 {
		t.Fatalf("verified evidence = %+v", input)
	}
}

func TestVerifyGateEvidenceRejectsTamperAndWrongTrustedKey(t *testing.T) {
	p := gatePack(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	input := goodGateInput(p)
	queries := gateRetroQueryProvenance()
	head, err := gateEvidenceHead(p.ID, p.Version, p.Digest, input, queries)
	if err != nil {
		t.Fatal(err)
	}
	signer := testGateEvidenceSigner{priv: priv}
	att, err := signer.Sign(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	signed := SignedGateEvidence{PackID: p.ID, PackVersion: p.Version, PackDigest: p.Digest, RetroQueries: queries, Input: input, Attestation: att}
	if _, err := VerifyGateEvidence(signed, p, pub); err != nil {
		t.Fatalf("valid signed evidence: %v", err)
	}

	tampered := signed
	tampered.Input.Retro = append([]RetroEvidence(nil), signed.Input.Retro...)
	tampered.Input.Retro[0].MatchedEvents++
	if _, err := VerifyGateEvidence(tampered, p, pub); err == nil {
		t.Fatal("tampered release evidence must fail attestation verification")
	}

	tamperedQuery := signed
	tamperedQuery.RetroQueries = append([]RetroQueryProvenance(nil), signed.RetroQueries...)
	tamperedQuery.RetroQueries[0].Limit++
	if _, err := VerifyGateEvidence(tamperedQuery, p, pub); err == nil {
		t.Fatal("tampered retro query provenance must fail attestation verification")
	}

	missingQuery := signed
	missingQuery.RetroQueries = nil
	if _, err := VerifyGateEvidence(missingQuery, p, pub); err == nil {
		t.Fatal("retro aggregate without its bounded query provenance must fail")
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
	queries := gateRetroQueryProvenance()
	ha, err := gateEvidenceHead(p.ID, p.Version, p.Digest, a, queries)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := gateEvidenceHead(p.ID, p.Version, p.Digest, b, queries)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("set-like ordering changed gate evidence identity: %s != %s", ha, hb)
	}
}

func TestGateEvidenceHeadBindsRetroQueryWindow(t *testing.T) {
	p := gatePack(t)
	input := goodGateInput(p)
	a := gateRetroQueryProvenance()
	b := append([]RetroQueryProvenance(nil), a...)
	b[0].Since = b[0].Since.Add(time.Second)
	ha, err := gateEvidenceHead(p.ID, p.Version, p.Digest, input, a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := gateEvidenceHead(p.ID, p.Version, p.Digest, input, b)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Fatal("changing the retro-hunt window must change the attested evidence head")
	}
}

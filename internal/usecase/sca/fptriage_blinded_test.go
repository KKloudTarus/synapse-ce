package sca

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type blindFixtureTriager struct{ run AIEvaluationRun }

func (t blindFixtureTriager) Triage(_ context.Context, candidates []finding.Finding, _ string) []ports.AICritique {
	out := make([]ports.AICritique, 0, len(candidates))
	for _, c := range candidates {
		verdict := "refuted"
		if strings.Contains(c.DedupKey, "tp") {
			verdict = "sound"
		}
		out = append(out, ports.AICritique{DedupKey: c.DedupKey, Verdict: verdict, Driver: "fixture", Confidence: 90,
			ProposerProvider: t.run.ProposerProvider, ProposerModel: t.run.ProposerModel, ProposerModelFamily: t.run.ProposerModel,
			VerifierProvider: t.run.VerifierProvider, VerifierModel: t.run.VerifierModel, VerifierModelFamily: t.run.VerifierModel,
			VerifierVerdict: verdict, VerifierDriver: "fixture", VerifierConfidence: 90, IndependencePolicy: t.run.IndependencePolicy,
			PromptVersion: t.run.PromptVersion})
	}
	return out
}

func blindFixture(t *testing.T) (AIEvaluationDataset, AIEvaluationReport) {
	t.Helper()
	dataset := loadGoldenEvaluationDataset(t)
	run := AIEvaluationRun{ProposerProvider: "provider-a", ProposerModel: "proposer", VerifierProvider: "provider-b", VerifierModel: "verifier", IndependencePolicy: ports.AIIndependenceProvider, PromptVersion: "blind-fixture", PolicyVersion: EvaluationPolicyVersion()}
	report, err := EvaluateFPTriage(context.Background(), dataset, run, blindFixtureTriager{run: run})
	if err != nil {
		t.Fatalf("evaluate fixture: %v", err)
	}
	return dataset, report
}

func blindAuthenticator(t *testing.T) BlindFPTriageAuthenticator {
	t.Helper()
	authenticator, err := NewBlindFPTriageAuthenticator([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

func TestBlindPacketWorkflowLocksAndMeasures(t *testing.T) {
	dataset, report := blindFixture(t)
	authenticator := blindAuthenticator(t)
	packet, err := ExportBlindFPTriagePacket(dataset, report, "private-seed", authenticator)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ExportBlindFPTriagePacket(dataset, report, "private-seed", authenticator)
	if err != nil {
		t.Fatal(err)
	}
	if packet.PacketID != again.PacketID || len(packet.Cases) != len(again.Cases) || packet.Cases[0].BlindID != again.Cases[0].BlindID {
		t.Fatal("same seed must produce the same packet")
	}
	if !packet.Shadow || packet.GateExempt || packet.DatasetSHA256 != report.DatasetSHA256 || packet.RunSHA256 != report.RunID {
		t.Fatalf("packet locking/invariants missing: %+v", packet)
	}
	encoded, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\"label\"", "\"verdict\"", "\"confidence\"", "\"rationale\"", "\"model\"", "\"arm\"", "\"would_gate_exempt\""} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("packet leaked field %s: %s", forbidden, encoded)
		}
	}

	submission := BlindFPTriageSubmission{SchemaVersion: BlindFPTriageSubmissionSchema, PacketID: packet.PacketID, DatasetSHA256: packet.DatasetSHA256, RunSHA256: packet.RunSHA256, Shadow: true}
	for i, c := range packet.Cases {
		decision := BlindFPTriageTruePositive
		if i == 0 {
			decision = BlindFPTriageAbstain
		}
		submission.Decisions = append(submission.Decisions, BlindFPTriageReviewDecision{BlindID: c.BlindID, Decision: decision})
	}
	imported, err := ImportBlindFPTriageSubmission(packet, submission, "human-reviewer", []string{"human-reviewer"}, report.Run.ProposerModel, report.Run.VerifierModel, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := JoinBlindFPTriageSubmission(dataset, report, packet, imported, []string{"human-reviewer"}, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	if !joined.Shadow || joined.GateExempt || joined.Metrics.Total != len(packet.Cases) || joined.Metrics.Abstentions != 1 || joined.Metrics.AbstentionRate == 0 || joined.Metrics.DisagreementComparisons == 0 {
		t.Fatalf("joined metrics/invariants missing: %+v", joined)
	}
}

func TestBlindSubmissionRejectsModelReviewerAndBrokenLocks(t *testing.T) {
	dataset, report := blindFixture(t)
	authenticator := blindAuthenticator(t)
	packet, err := ExportBlindFPTriagePacket(dataset, report, "private-seed", authenticator)
	if err != nil {
		t.Fatal(err)
	}
	submission := BlindFPTriageSubmission{SchemaVersion: BlindFPTriageSubmissionSchema, PacketID: packet.PacketID, DatasetSHA256: packet.DatasetSHA256, RunSHA256: packet.RunSHA256, Shadow: true}
	for _, c := range packet.Cases {
		submission.Decisions = append(submission.Decisions, BlindFPTriageReviewDecision{BlindID: c.BlindID, Decision: BlindFPTriageAbstain})
	}
	if _, err := ImportBlindFPTriageSubmission(packet, submission, report.Run.ProposerModel, []string{report.Run.ProposerModel}, report.Run.ProposerModel, report.Run.VerifierModel, authenticator); err == nil {
		t.Fatal("proposer identity was accepted as reviewer")
	}
	submission.GateExempt = true
	if _, err := ImportBlindFPTriageSubmission(packet, submission, "human-reviewer", []string{"human-reviewer"}, report.Run.ProposerModel, report.Run.VerifierModel, authenticator); err == nil {
		t.Fatal("gate-exempt submission was accepted")
	}
	packet.Shadow = false
	if _, err := ImportBlindFPTriageSubmission(packet, submission, "human-reviewer", []string{"human-reviewer"}, report.Run.ProposerModel, report.Run.VerifierModel, authenticator); err == nil {
		t.Fatal("non-shadow packet was accepted")
	}
}

func TestBlindPacketRejectsTamperingAndEmbeddedLeakage(t *testing.T) {
	dataset, report := blindFixture(t)
	authenticator := blindAuthenticator(t)
	packet, err := ExportBlindFPTriagePacket(dataset, report, "private-seed", authenticator)
	if err != nil {
		t.Fatal(err)
	}
	packet.Cases[0].Title = "model verdict"
	if _, err := ImportBlindFPTriageSubmission(packet, BlindFPTriageSubmission{}, "human-reviewer", []string{"human-reviewer"}, report.Run.ProposerModel, report.Run.VerifierModel, authenticator); err == nil {
		t.Fatal("tampered packet was accepted")
	}
	dataset.Cases[0].Source += " // verifier confidence 99"
	if _, err := ExportBlindFPTriagePacket(dataset, report, "private-seed", authenticator); err == nil {
		t.Fatal("embedded blind leakage was accepted")
	}
}

func TestBlindSubmissionReceiptBindsReviewerAndDecisions(t *testing.T) {
	dataset, report := blindFixture(t)
	authenticator := blindAuthenticator(t)
	packet, err := ExportBlindFPTriagePacket(dataset, report, "private-seed", authenticator)
	if err != nil {
		t.Fatal(err)
	}
	submission := BlindFPTriageSubmission{SchemaVersion: BlindFPTriageSubmissionSchema, PacketID: packet.PacketID, DatasetSHA256: packet.DatasetSHA256, RunSHA256: packet.RunSHA256, Shadow: true}
	for _, c := range packet.Cases {
		submission.Decisions = append(submission.Decisions, BlindFPTriageReviewDecision{BlindID: c.BlindID, Decision: BlindFPTriageAbstain})
	}
	imported, err := ImportBlindFPTriageSubmission(packet, submission, "human-reviewer", []string{"human-reviewer"}, report.Run.ProposerModel, report.Run.VerifierModel, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	imported.Reviewer = "other-human"
	if _, err := JoinBlindFPTriageSubmission(dataset, report, packet, imported, []string{"human-reviewer", "other-human"}, authenticator); err == nil {
		t.Fatal("reviewer-mutated receipt was accepted")
	}
}

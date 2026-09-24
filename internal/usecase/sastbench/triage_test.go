package sastbench

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestReplayVerdictsAcceptsCompleteIndependentReview(t *testing.T) {
	batch := testProposalBatch(t)
	digest, err := ProposalDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	artifact := testArtifact(digest)
	artifact.Verdicts = []Verdict{{ProposalID: batch.Proposals[0].ID, Decision: "confirmed"}, {ProposalID: batch.Proposals[1].ID, Decision: "rejected"}}
	confirmed, err := ReplayVerdicts(batch, artifact, sealTestResponse(t, &artifact), "corpus")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(confirmed) != 1 || confirmed[0] != batch.Proposals[0].Finding {
		t.Fatalf("confirmed = %#v", confirmed)
	}
}

func TestReplayVerdictsRejectsMissingDuplicateAndForeignVerdicts(t *testing.T) {
	batch := testProposalBatch(t)
	digest, err := ProposalDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	base := testArtifact(digest)
	cases := []struct {
		name     string
		verdicts []Verdict
		want     string
	}{
		{"missing", []Verdict{{ProposalID: batch.Proposals[0].ID, Decision: "confirmed"}}, "coverage incomplete"},
		{"duplicate", []Verdict{{ProposalID: batch.Proposals[0].ID, Decision: "confirmed"}, {ProposalID: batch.Proposals[0].ID, Decision: "rejected"}}, "verdicts do not match"},
		{"foreign", []Verdict{{ProposalID: batch.Proposals[0].ID, Decision: "confirmed"}, {ProposalID: "foreign", Decision: "rejected"}}, "foreign proposal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			artifact := base
			artifact.Verdicts = tc.verdicts
			if _, err := ReplayVerdicts(batch, artifact, sealTestResponse(t, &artifact), "corpus"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestReplayVerdictsRejectsChangedProposalAndSelfReview(t *testing.T) {
	batch := testProposalBatch(t)
	digest, err := ProposalDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	artifact := testArtifact(digest)
	artifact.Verifier = "proposer"
	artifact.Verdicts = completeVerdicts(batch)
	if _, err := ReplayVerdicts(batch, artifact, sealTestResponse(t, &artifact), "corpus"); err == nil || !strings.Contains(err.Error(), "differ from proposer") {
		t.Fatalf("self review err = %v", err)
	}
	artifact.Verifier = "capsast:model-v1"
	artifact.ProposalDigest = "changed"
	if _, err := ReplayVerdicts(batch, artifact, sealTestResponse(t, &artifact), "corpus"); err == nil || !strings.Contains(err.Error(), "fresh proposal batch") {
		t.Fatalf("changed proposal err = %v", err)
	}
	artifact.ProposalDigest = digest
	if _, err := ReplayVerdicts(batch, artifact, sealTestResponse(t, &artifact), "other-corpus"); err == nil || !strings.Contains(err.Error(), "current corpus") {
		t.Fatalf("changed corpus err = %v", err)
	}
}

func TestReplayVerdictsRejectsChangedSourceContextAndUnknownDecision(t *testing.T) {
	batch, err := NewProposalBatchWithContext("corpus", "owned-engine", []ProposalInput{{
		Finding: Finding{File: "a.java", Line: 10, CWE: "CWE-89"}, SourceContext: "executeQuery(sql)",
	}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ProposalDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	artifact := testArtifact(digest)
	artifact.Verdicts = []Verdict{{ProposalID: batch.Proposals[0].ID, Decision: "unknown"}}
	if _, err := ReplayVerdicts(batch, artifact, sealTestResponse(t, &artifact), "corpus"); err == nil || !strings.Contains(err.Error(), "invalid decision") {
		t.Fatalf("unknown decision err = %v", err)
	}
	batch.Proposals[0].SourceContext = "preparedStatement(sql)"
	changedArtifact := testArtifact(digest)
	if _, err := ReplayVerdicts(batch, changedArtifact, sealTestResponse(t, &changedArtifact), "corpus"); err == nil || !strings.Contains(err.Error(), "fresh proposal batch") {
		t.Fatalf("changed context err = %v", err)
	}
}

func TestReplayVerdictsRejectedRealFindingRemainsFalseNegative(t *testing.T) {
	cases := []LabeledCase{{Name: "real", File: "a.java", Line: 10, CWE: "CWE-89", Real: true}}
	batch, err := NewProposalBatch(CorpusDigest(cases), "owned-engine", []Finding{{File: "a.java", Line: 10, CWE: "CWE-89"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ProposalDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	artifact := testArtifact(digest)
	artifact.CorpusDigest = batch.CorpusDigest
	artifact.Verdicts = []Verdict{{ProposalID: batch.Proposals[0].ID, Decision: "rejected"}}
	confirmed, err := ReplayVerdicts(batch, artifact, sealTestResponse(t, &artifact), batch.CorpusDigest)
	if err != nil {
		t.Fatal(err)
	}
	score := ScoreByCWE(confirmed, cases, []string{"CWE-89"}, 0)[0]
	if score.FN != 1 || score.TP != 0 {
		t.Fatalf("rejecting a true proposal must score FN, got %+v", score)
	}
}

func TestScorePostTriageProducesBoundPostTriageReport(t *testing.T) {
	cases := []LabeledCase{{Name: "real", File: "a.java", Line: 10, CWE: "CWE-89", Real: true}}
	batch, err := NewProposalBatch(CorpusDigest(cases), "owned-engine", []Finding{{File: "a.java", Line: 10, CWE: "CWE-89"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ProposalDigest(batch)
	if err != nil {
		t.Fatal(err)
	}
	artifact := testArtifact(digest)
	artifact.CorpusDigest = batch.CorpusDigest
	artifact.Verdicts = completeVerdicts(batch)
	report, err := ScorePostTriage(batch, artifact, sealTestResponse(t, &artifact), cases, []string{"CWE-89"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stage != "post-triage" || report.CorpusDigest != batch.CorpusDigest || report.CWEs[0].TP != 1 {
		t.Fatalf("post-triage report = %+v", report)
	}
}

func TestNewlyLostTrueCasesRejectsSuppressionHiddenByAggregateRecall(t *testing.T) {
	cases := []LabeledCase{
		{Name: "true-a", File: "a.java", Line: 10, CWE: "CWE-89", Real: true},
		{Name: "true-b", File: "b.java", Line: 10, CWE: "CWE-89", Real: true},
	}
	proposed := []Finding{{File: "a.java", Line: 10, CWE: "CWE-89"}}
	postTriage := []Finding{{File: "b.java", Line: 10, CWE: "CWE-89"}}
	lost := NewlyLostTrueCases(proposed, postTriage, cases, []string{"CWE-89"}, 0)
	if len(lost) != 1 || lost[0] != "true-a" {
		t.Fatalf("lost true cases = %v", lost)
	}
}

func TestVerifyRecordedResponseRejectsChangedBytes(t *testing.T) {
	artifact := testArtifact("proposal-digest")
	artifact.Verdicts = []Verdict{{ProposalID: "proposal", Decision: "confirmed"}}
	response, err := json.Marshal(RecordedVerdictResponse{Schema: RecordedVerdictResponseSchemaVersion, ProposalDigest: artifact.ProposalDigest, Verdicts: artifact.Verdicts})
	if err != nil {
		t.Fatal(err)
	}
	artifact.ResponseDigest = testDigest(string(response))
	if err := VerifyRecordedResponse(artifact, strings.NewReader(string(response))); err != nil {
		t.Fatalf("verify recorded response: %v", err)
	}
	if err := VerifyRecordedResponse(artifact, strings.NewReader(`{"schema":"synapse-sast-verdict-response-v1","proposal_digest":"proposal-digest","verdicts":[]}`)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("changed response err = %v", err)
	}
}

func TestVerifyRecordedResponseRejectsTrailingDocument(t *testing.T) {
	artifact := testArtifact("proposal-digest")
	artifact.Verdicts = []Verdict{{ProposalID: "proposal", Decision: "confirmed"}}
	response, err := json.Marshal(RecordedVerdictResponse{Schema: RecordedVerdictResponseSchemaVersion, ProposalDigest: artifact.ProposalDigest, Verdicts: artifact.Verdicts})
	if err != nil {
		t.Fatal(err)
	}
	sealed := string(response) + ` {"extra":true}`
	artifact.ResponseDigest = testDigest(sealed)
	if err := VerifyRecordedResponse(artifact, strings.NewReader(sealed)); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("trailing recorded response err = %v", err)
	}
}

func TestTriageArtifactsRoundTripAndRejectUnknownFields(t *testing.T) {
	batch := testProposalBatch(t)
	var encoded bytes.Buffer
	if err := EncodeProposalBatch(&encoded, batch); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProposalBatch(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ProposalDigest(loaded); err != nil || got == "" {
		t.Fatalf("loaded digest = %q, %v", got, err)
	}
	if _, err := LoadVerdictArtifact(strings.NewReader(`{"schema":"synapse-sast-verdicts-v1","unknown":true}`)); err == nil {
		t.Fatal("unknown verdict field must fail")
	}
}

func TestImprovedOverBaselineRejectsRecallRegression(t *testing.T) {
	base := Report{Schema: ReportSchemaVersion, CorpusDigest: "d", CWEs: []CWEScore{{CWE: "CWE-78", Precision: .5, Recall: .8}, {CWE: "CWE-89", Precision: .6, Recall: .7}}}
	owned := Report{Schema: ReportSchemaVersion, CorpusDigest: "d", CWEs: []CWEScore{{CWE: "CWE-78", Precision: .8, Recall: .7}, {CWE: "CWE-89", Precision: .6, Recall: .7}}}
	improved, detail, err := ImprovedOverBaseline(owned, base, 1e-9)
	if err != nil || improved || !strings.Contains(strings.Join(detail, "\n"), "recall regressed") {
		t.Fatalf("recall regression must fail: improved=%v detail=%v err=%v", improved, detail, err)
	}
}

func testProposalBatch(t *testing.T) ProposalBatch {
	t.Helper()
	batch, err := NewProposalBatch("corpus", "proposer", []Finding{{File: "a.java", Line: 10, CWE: "CWE-89"}, {File: "b.java", Line: 12, CWE: "CWE-78"}})
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func completeVerdicts(batch ProposalBatch) []Verdict {
	verdicts := make([]Verdict, 0, len(batch.Proposals))
	for _, proposal := range batch.Proposals {
		verdicts = append(verdicts, Verdict{ProposalID: proposal.ID, Decision: "confirmed"})
	}
	return verdicts
}

func testArtifact(proposalDigest string) VerdictArtifact {
	return VerdictArtifact{
		Schema: VerdictSchemaVersion, CorpusDigest: "corpus", ProposalDigest: proposalDigest,
		Verifier: "advisory-agent", Model: "gpt-6-astra", Role: "independent-verifier",
		ConfigDigest: testDigest("config"), PromptDigest: testDigest("prompt"), PacketDigest: proposalDigest,
		ResponseDigest: testDigest("response"), ResponseRef: "recorded-response.json",
	}
}

func sealTestResponse(t *testing.T, artifact *VerdictArtifact) *strings.Reader {
	t.Helper()
	response, err := json.Marshal(RecordedVerdictResponse{Schema: RecordedVerdictResponseSchemaVersion, ProposalDigest: artifact.ProposalDigest, Verdicts: artifact.Verdicts})
	if err != nil {
		t.Fatal(err)
	}
	artifact.ResponseDigest = testDigest(string(response))
	return strings.NewReader(string(response))
}

func testDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

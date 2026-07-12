package fptriage_test

// Live-AI demonstration for #165 (AI false-positive triage in the scan pipeline, with the #156 distinct-
// verifier consensus). It drives the REAL Coordinator against a live OpenAI-compatible gateway (9router):
// a clearly PARAMETERIZED query (not injectable) is critiqued as a false positive by the proposer AND
// confirmed by a DISTINCT verifier → suspected-FP (retain-and-mark, exempt from the gate); a clearly
// INJECTABLE string-concatenation stays gating (not refuted). This proves the pipeline's FP gate + the
// two-model consensus are effective end-to-end, and — critically — that a real weakness is NOT dismissed.
//
// Gated behind SYNAPSE_LIVE_AI=1 so the normal suite stays hermetic. Run:
//   SYNAPSE_LIVE_AI=1 SYNAPSE_LLM_BASE_URL=http://localhost:20128/v1 \
//     SYNAPSE_LLM_MODEL=cx/gpt-5.4-mini SYNAPSE_VERIFIER_MODEL=cx/gpt-5.4 \
//     go test ./internal/usecase/fptriage/ -run TestLiveAIFPTriageConsensus -v

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fptriage"
)

type liveSrc struct{ byFile map[string]string }

func (l liveSrc) Snippet(_ context.Context, file string, _, _ int) (string, error) {
	if s, ok := l.byFile[file]; ok {
		return s, nil
	}
	return "", fmt.Errorf("no snippet for %q", file)
}

func TestLiveAIFPTriageConsensus(t *testing.T) {
	if os.Getenv("SYNAPSE_LIVE_AI") != "1" {
		t.Skip("set SYNAPSE_LIVE_AI=1 to run the live 9router demonstration")
	}
	base := os.Getenv("SYNAPSE_LLM_BASE_URL")
	if base == "" {
		base = "http://localhost:20128/v1"
	}
	proposerModel := os.Getenv("SYNAPSE_LLM_MODEL")
	if proposerModel == "" {
		proposerModel = "cx/gpt-5.4-mini"
	}
	verifierModel := os.Getenv("SYNAPSE_VERIFIER_MODEL")
	if verifierModel == "" {
		verifierModel = "cx/gpt-5.4"
	}
	key := os.Getenv("SYNAPSE_LLM_API_KEY")
	proposer, err := openai.New(base, key, proposerModel, 90*time.Second)
	if err != nil {
		t.Fatalf("proposer client: %v", err)
	}
	verifier, err := openai.New(base, key, verifierModel, 90*time.Second)
	if err != nil {
		t.Fatalf("verifier client: %v", err)
	}
	c := fptriage.New(proposer, proposerModel).WithVerifier(verifier, verifierModel)
	if c.VerifierModel() == "" {
		t.Fatalf("distinct verifier not attached (proposer=%q verifier=%q must differ)", proposerModel, verifierModel)
	}

	// A clear FALSE POSITIVE (parameterized query — not injectable) and a clear TRUE POSITIVE (user input
	// concatenated into SQL). The location is parsed from the title "... (file:line)".
	fp := finding.Finding{
		ID: "fp-1", Kind: finding.KindSAST, Severity: shared.SeverityHigh, CWE: "CWE-89",
		Title:       "Possible SQL injection (app/dao_safe.py:2)",
		Description: "Pattern rule flagged a SQL execute call.",
	}
	tp := finding.Finding{
		ID: "tp-1", Kind: finding.KindSAST, Severity: shared.SeverityHigh, CWE: "CWE-89",
		Title:       "Possible SQL injection (app/dao_vuln.py:2)",
		Description: "Pattern rule flagged a SQL execute call.",
	}
	src := liveSrc{byFile: map[string]string{
		"app/dao_safe.py": "def get_user(db, user_id):\n    return db.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
		"app/dao_vuln.py": "def get_user(db, user_id):\n    return db.execute(\"SELECT * FROM users WHERE id = \" + user_id)",
	}}

	crits := c.Assess(context.Background(), []finding.Finding{fp, tp}, src)
	if len(crits) != 2 {
		t.Fatalf("want 2 critiques, got %d", len(crits))
	}
	by := map[string]fptriage.Critique{}
	for _, cr := range crits {
		if cr.Err != nil {
			t.Fatalf("critique %s errored (real AI unreachable?): %v", cr.FindingID, cr.Err)
		}
		by[cr.FindingID] = cr
	}
	minConf := c.MinConfidence()

	fpCrit := by["fp-1"]
	t.Logf("FP (parameterized): proposer verdict=%s conf=%d; verifyAttempted=%v verifier=%+v",
		fpCrit.Claim.Verdict, fpCrit.Claim.Confidence, fpCrit.VerifyAttempted, fpCrit.Verifier)
	if !fpCrit.SuspectedFP(minConf) {
		t.Errorf("a parameterized query must be a consensus suspected-FP (proposer+verifier refute >= %d)", minConf)
	}
	if !fpCrit.VerifyAttempted || fpCrit.Verifier == nil {
		t.Errorf("the distinct verifier must have been consulted for the proposer's refutation")
	}

	tpCrit := by["tp-1"]
	t.Logf("TP (concatenation): proposer verdict=%s conf=%d; verifyAttempted=%v verifier=%+v",
		tpCrit.Claim.Verdict, tpCrit.Claim.Confidence, tpCrit.VerifyAttempted, tpCrit.Verifier)
	if tpCrit.SuspectedFP(minConf) {
		t.Errorf("a clearly injectable concatenation must NOT be dismissed as a false positive — it must stay gating")
	}

	t.Logf("PASS: real two-model consensus held back the parameterized-query false positive and kept the injectable finding gating (retain-and-mark + distinct-verifier consensus effective)")
}

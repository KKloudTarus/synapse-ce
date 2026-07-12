package fptriage

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeLLM returns a scripted reply per call, or an error, keyed by the finding title carried in the
// user message so a table test can route a distinct verdict to each candidate.
type fakeLLM struct {
	byTitleSubstr map[string]string // substring of the user prompt -> raw JSON content
	err           error
}

func (f fakeLLM) Chat(_ context.Context, req ports.ChatRequest) (ports.ChatResponse, error) {
	if f.err != nil {
		return ports.ChatResponse{}, f.err
	}
	user := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			user = m.Content
		}
	}
	for sub, content := range f.byTitleSubstr {
		if strings.Contains(user, sub) {
			return ports.ChatResponse{Content: content, FinishReason: "stop"}, nil
		}
	}
	return ports.ChatResponse{Content: `{"verdict":"uncertain","driver":"insufficient_context","confidence":10}`}, nil
}

func mkFinding(id, title string) finding.Finding {
	return finding.Finding{ID: shared.ID("id-" + id), DedupKey: "dk-" + id, Title: title, Kind: finding.KindSAST}
}

func TestAssessAppliesVerdicts(t *testing.T) {
	llm := fakeLLM{byTitleSubstr: map[string]string{
		"real-sqli.go": `{"verdict":"sound","driver":"attacker_controlled","confidence":80}`,
		"fixture.go":   `{"verdict":"refuted","driver":"test_or_example_code","confidence":92}`,
		"lowconf.go":   `{"verdict":"refuted","driver":"input_sanitized","confidence":40}`, // below the 75 bar
		"constant.go":  `{"verdict":"refuted","driver":"constant_or_literal","confidence":88}`,
	}}
	cands := []finding.Finding{
		mkFinding("1", "SQL query uses dynamic string (internal/db/real-sqli.go:20)"),
		mkFinding("2", "Command execution receives dynamic input (internal/x/fixture.go:5)"),
		mkFinding("3", "Weak randomness (internal/y/lowconf.go:9)"),
		mkFinding("4", "Response writes request data (internal/z/constant.go:12)"),
	}
	got := New(llm, "test-model").Assess(context.Background(), cands, nil)
	if len(got) != 4 {
		t.Fatalf("want 4 critiques, got %d", len(got))
	}
	// sound → not FP
	if got[0].Claim.Verdict != judgment.CritiqueSound || got[0].SuspectedFP(75) {
		t.Errorf("real finding must be sound / not suspected-FP: %+v", got[0])
	}
	// refuted high-confidence → suspected FP
	if !got[1].SuspectedFP(75) || got[1].Claim.Driver != "test_or_example_code" {
		t.Errorf("fixture finding must be a suspected FP: %+v", got[1])
	}
	// refuted but below the confidence bar → NOT actionable
	if got[2].SuspectedFP(75) {
		t.Errorf("low-confidence refutation must not clear the 75 bar: %+v", got[2])
	}
	if !got[3].SuspectedFP(75) {
		t.Errorf("constant-input refutation must be a suspected FP: %+v", got[3])
	}
}

// roleLLM answers differently for the proposer vs the verifier pass (the verifier user prompt carries
// the "first reviewer's verdict" preamble), and can fail the verifier call.
type roleLLM struct {
	proposer  string
	verifier  string
	verifyErr error
}

func (f roleLLM) Chat(_ context.Context, req ports.ChatRequest) (ports.ChatResponse, error) {
	user := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			user = m.Content
		}
	}
	if strings.Contains(user, "first reviewer's verdict") { // the verifier pass
		if f.verifyErr != nil {
			return ports.ChatResponse{}, f.verifyErr
		}
		return ports.ChatResponse{Content: f.verifier}, nil
	}
	return ports.ChatResponse{Content: f.proposer}, nil
}

func TestVerifierConsensus(t *testing.T) {
	cand := []finding.Finding{mkFinding("1", "X (a/b.go:1)")}
	refuted := `{"verdict":"refuted","driver":"not_reachable","confidence":92}`
	run := func(llm roleLLM) Critique {
		c := New(llm, "proposer-model").WithVerifier(llm, "verifier-model")
		return c.Assess(context.Background(), cand, nil)[0]
	}
	// Both agree → suspected FP, verified.
	if got := run(roleLLM{proposer: refuted, verifier: `{"verdict":"refuted","driver":"not_reachable","confidence":85}`}); !got.SuspectedFP(75) || !got.VerifyAttempted || got.Verifier == nil {
		t.Errorf("consensus refuted must be suspected-FP + verified: %+v", got)
	}
	// Verifier disagrees (sound) → NOT suspected FP (finding gates).
	if got := run(roleLLM{proposer: refuted, verifier: `{"verdict":"sound","driver":"attacker_controlled","confidence":80}`}); got.SuspectedFP(75) {
		t.Errorf("a verifier that disagrees must keep the finding gating: %+v", got)
	}
	// Verifier below the bar → NOT suspected FP.
	if got := run(roleLLM{proposer: refuted, verifier: `{"verdict":"refuted","driver":"not_reachable","confidence":40}`}); got.SuspectedFP(75) {
		t.Errorf("a low-confidence verifier must keep the finding gating: %+v", got)
	}
	// Verifier call fails → fail-safe, NOT suspected FP.
	if got := run(roleLLM{proposer: refuted, verifyErr: errors.New("gateway 503")}); got.SuspectedFP(75) || got.Verifier != nil {
		t.Errorf("a failed verify must keep the finding gating (fail-safe): %+v", got)
	}
	// Proposer says sound → no verify attempted, not FP.
	if got := run(roleLLM{proposer: `{"verdict":"sound","driver":"attacker_controlled","confidence":88}`, verifier: refuted}); got.SuspectedFP(75) || got.VerifyAttempted {
		t.Errorf("a sound proposer must not trigger verification or FP: %+v", got)
	}
}

func TestAssessBestEffortOnLLMError(t *testing.T) {
	cands := []finding.Finding{mkFinding("1", "X (a/b.go:1)")}
	got := New(fakeLLM{err: errors.New("gateway 503")}, "m").Assess(context.Background(), cands, nil)
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("an LLM error must surface as Critique.Err, got %+v", got)
	}
	if got[0].SuspectedFP(75) {
		t.Error("a failed critique must never mark a finding as FP")
	}
}

func TestParseCritiqueFailClosed(t *testing.T) {
	// The VERDICT stays strict; an unknown/absent verdict or no JSON at all must fail closed.
	bad := []string{
		``,
		`{"verdict":"maybe","driver":"x","confidence":10}`, // unknown verdict
		`{"driver":"x","confidence":10}`,                   // missing verdict
		`no json at all`,
	}
	for _, s := range bad {
		if _, err := parseCritique(s); err == nil {
			t.Errorf("parseCritique(%q) must fail closed", s)
		}
	}
	// The driver is normalized/defaulted and confidence clamped, so a valid verdict is never discarded
	// over a cosmetic field — including the shapes the gateway actually returns (fences, prose, extra
	// keys, empty/spaced drivers).
	if c, err := parseCritique(`{"verdict":"refuted","driver":"not_reachable","confidence":85}`); err != nil || c.Driver != "not_reachable" || c.Confidence != 85 {
		t.Errorf("plain refuted: %+v err=%v", c, err)
	}
	if c, err := parseCritique(`{"verdict":"refuted","driver":"not a real sink","confidence":90}`); err != nil || c.Driver != "not_a_real_sink" {
		t.Errorf("spaced driver must normalize to a token: %+v err=%v", c, err)
	}
	if c, err := parseCritique(`{"verdict":"sound","driver":"","confidence":80}`); err != nil || c.Verdict != judgment.CritiqueSound || c.Driver == "" {
		t.Errorf("empty driver must default, not drop the verdict: %+v err=%v", c, err)
	}
	if c, err := parseCritique(`{"verdict":"refuted","driver":"the input here is a compile time constant and never attacker controlled at all","confidence":95}`); err != nil || strings.Contains(c.Driver, " ") || len(c.Driver) > 48 {
		t.Errorf("a sentence driver must fall back to a clean token (no prose): %+v err=%v", c, err)
	}
	if c, err := parseCritique(`{"verdict":"refuted","driver":"not_reachable","confidence":900}`); err != nil || c.Confidence != 100 {
		t.Errorf("confidence must clamp to 100: %+v err=%v", c, err)
	}
	if c, err := parseCritique("```json\n{\"verdict\":\"refuted\",\"driver\":\"not_reachable\",\"confidence\":85,\"why\":\"x\"}\n```"); err != nil || c.Verdict != judgment.CritiqueRefuted || c.Driver != "not_reachable" {
		t.Errorf("fenced JSON with an extra key must parse: %+v err=%v", c, err)
	}
}

func TestLocationOf(t *testing.T) {
	cases := []struct {
		title    string
		wantFile string
		wantLine int
		wantOK   bool
	}{
		{"SQL uses dynamic string (internal/db/repo.go:42)", "internal/db/repo.go", 42, true},
		{"no location here", "", 0, false},
		{"bad (no colon)", "", 0, false},
		{"bad line (a/b.go:zero)", "", 0, false},
	}
	for _, c := range cases {
		f, l, ok := locationOf(finding.Finding{Title: c.title})
		if ok != c.wantOK || f != c.wantFile || l != c.wantLine {
			t.Errorf("locationOf(%q) = (%q,%d,%v), want (%q,%d,%v)", c.title, f, l, ok, c.wantFile, c.wantLine, c.wantOK)
		}
	}
}

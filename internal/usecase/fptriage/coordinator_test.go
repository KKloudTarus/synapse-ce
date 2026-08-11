package fptriage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

type boundedLLM struct {
	mu      sync.Mutex
	active  int
	maxSeen int
	calls   int
	started chan struct{}
	release chan struct{}
}

func (b *boundedLLM) Chat(ctx context.Context, _ ports.ChatRequest) (ports.ChatResponse, error) {
	b.mu.Lock()
	b.active++
	b.calls++
	if b.active > b.maxSeen {
		b.maxSeen = b.active
	}
	b.mu.Unlock()
	b.started <- struct{}{}

	select {
	case <-b.release:
	case <-ctx.Done():
		b.mu.Lock()
		b.active--
		b.mu.Unlock()
		return ports.ChatResponse{}, ctx.Err()
	}

	b.mu.Lock()
	b.active--
	b.mu.Unlock()
	return ports.ChatResponse{Content: `{"verdict":"sound","driver":"attacker_controlled","confidence":80}`, FinishReason: "stop"}, nil
}

func (b *boundedLLM) snapshot() (calls, maxSeen int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, b.maxSeen
}

func TestAssessBoundsConcurrencyAndVerifierCalls(t *testing.T) {
	llm := &boundedLLM{started: make(chan struct{}, 8), release: make(chan struct{})}
	candidates := make([]finding.Finding, 4)
	for i := range candidates {
		candidates[i] = mkFinding(strconv.Itoa(i), "finding")
	}
	done := make(chan []Critique, 1)
	go func() {
		done <- New(llm, "proposer-model").WithVerifier(llm, "verifier-model").WithConcurrency(2).Assess(context.Background(), candidates, nil)
	}()

	for range 2 {
		select {
		case <-llm.started:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for the initial bounded calls")
		}
	}
	select {
	case <-llm.started:
		t.Fatal("a third provider call started while the concurrency budget was full")
	case <-time.After(50 * time.Millisecond):
	}
	close(llm.release)

	select {
	case got := <-done:
		if len(got) != len(candidates) {
			t.Fatalf("critiques = %d, want %d", len(got), len(candidates))
		}
	case <-time.After(time.Second):
		t.Fatal("assessment did not finish")
	}
	calls, maxSeen := llm.snapshot()
	if calls != 2*len(candidates) {
		t.Fatalf("provider calls = %d, want at most two per attempted finding (%d)", calls, 2*len(candidates))
	}
	if maxSeen > 2 {
		t.Fatalf("peak provider concurrency = %d, want <= 2", maxSeen)
	}
}

func TestAssessCancellationDoesNotScheduleQueuedCandidates(t *testing.T) {
	llm := &boundedLLM{started: make(chan struct{}, 10), release: make(chan struct{})}
	candidates := make([]finding.Finding, 10)
	for i := range candidates {
		candidates[i] = mkFinding(strconv.Itoa(i), "finding")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []Critique, 1)
	go func() {
		done <- New(llm, "proposer-model").WithConcurrency(1).Assess(ctx, candidates, nil)
	}()
	select {
	case <-llm.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the first provider call")
	}
	cancel()

	var got []Critique
	select {
	case got = <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled assessment did not finish")
	}
	calls, _ := llm.snapshot()
	if calls != 1 {
		t.Fatalf("provider calls after cancellation = %d, want only the active call", calls)
	}
	for i := 1; i < len(got); i++ {
		if !errors.Is(got[i].Err, context.Canceled) {
			t.Errorf("queued critique %d error = %v, want context.Canceled", i, got[i].Err)
		}
	}
}

func TestWithConcurrencyRejectsUnboundedValues(t *testing.T) {
	c := New(fakeLLM{}, "model")
	for _, value := range []int{0, -1, maxConcurrency + 1} {
		c.WithConcurrency(value)
		if got := c.Concurrency(); got != defaultConcurrency {
			t.Errorf("WithConcurrency(%d) = %d, want finite default %d", value, got, defaultConcurrency)
		}
	}
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
	if got[1].VerifiedConsensus(75) || got[3].VerifiedConsensus(75) {
		t.Error("single-model suspected FPs must remain advisory, never verified consensus")
	}
}

// roleLLM answers by configured model identity and can fail the verifier call. Routing by model keeps
// the test independent of prompt text, which is important because the verifier prompt must stay blind.
type roleLLM struct {
	proposer  string
	verifier  string
	verifyErr error
}

func (f roleLLM) Chat(_ context.Context, req ports.ChatRequest) (ports.ChatResponse, error) {
	if req.Model == "verifier-model" {
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
	if got := run(roleLLM{proposer: refuted, verifier: `{"verdict":"refuted","driver":"not_reachable","confidence":85}`}); !got.SuspectedFP(75) || !got.VerifiedConsensus(75) || !got.VerifyAttempted || got.Verifier == nil {
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
	// The verifier runs blind for every candidate, but a sound proposer can never produce consensus.
	if got := run(roleLLM{proposer: `{"verdict":"sound","driver":"attacker_controlled","confidence":88}`, verifier: refuted}); got.SuspectedFP(75) || !got.VerifyAttempted || got.Verifier == nil {
		t.Errorf("a sound proposer must remain non-FP after an independent verifier pass: %+v", got)
	}
}

func TestVerifierMustBeCanonicallyDistinct(t *testing.T) {
	llm := roleLLM{}
	for _, tc := range []struct {
		proposer string
		verifier string
	}{
		{"proposer-model", "PROPOSER-MODEL"},
		{"proposer-model", "openai/proposer-model"},
		{"proposer-model", "router/openai/PROPOSER-MODEL"},
		{"anthropic.claude-opus-5-v1:0", "us.anthropic.claude-opus-5-v1:0"},
		{"anthropic/claude-opus-5", "global.anthropic.claude-opus-5-v1:0"},
		{"", "verifier-model"},
	} {
		c := New(llm, tc.proposer).WithVerifier(llm, tc.verifier)
		if c.VerifierModel() != "" {
			t.Errorf("verifier %q self-confirmed proposer %q through an alias", tc.verifier, tc.proposer)
		}
	}
}

func TestVerifierProviderPolicyFailsClosed(t *testing.T) {
	llm := roleLLM{}
	for _, tc := range []struct {
		name, proposerProvider, verifierProvider, verifierModel string
		policy                                                  ports.AIIndependencePolicy
		wantAttached                                            bool
	}{
		{"different provider and family", "openai", "anthropic", "claude-sonnet-4", ports.AIIndependenceProvider, true},
		{"same provider", "openai", "OPENAI", "gpt-4.1", ports.AIIndependenceProvider, false},
		{"missing provider", "openai", "", "claude-sonnet-4", ports.AIIndependenceProvider, false},
		{"same family across providers", "bedrock", "anthropic", "anthropic/claude-opus-5", ports.AIIndependenceProvider, false},
		{"unknown policy", "openai", "anthropic", "claude-sonnet-4", "typo", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proposerModel := "gpt-4o"
			if tc.name == "same family across providers" {
				proposerModel = "us.anthropic.claude-opus-5-v1:0"
			}
			c := NewWithIdentity(llm, tc.proposerProvider, proposerModel).
				WithIndependentVerifier(llm, tc.verifierProvider, tc.verifierModel, tc.policy)
			if got := c.VerifierModel() != ""; got != tc.wantAttached {
				t.Fatalf("verifier attached = %v, want %v", got, tc.wantAttached)
			}
		})
	}
}

// anchoringLLM simulates a verifier that rubber-stamps only when the first reviewer's exact output is
// leaked into its transcript. The safe blind prompt makes it disagree, so restoring the old preamble
// changes the gate outcome and fails this test.
type anchoringLLM struct {
	reqs []ports.ChatRequest
}

func (a *anchoringLLM) Chat(_ context.Context, req ports.ChatRequest) (ports.ChatResponse, error) {
	a.reqs = append(a.reqs, req)
	if req.Model == "proposer-model" {
		return ports.ChatResponse{Content: `{"verdict":"refuted","driver":"not_reachable","confidence":92}`}, nil
	}
	var transcript strings.Builder
	for _, message := range req.Messages {
		transcript.WriteString(message.Content)
		transcript.WriteByte('\n')
	}
	leaked := strings.Contains(transcript.String(), "first reviewer's verdict") ||
		strings.Contains(transcript.String(), "verdict=refuted") ||
		strings.Contains(transcript.String(), "driver=not_reachable") ||
		strings.Contains(transcript.String(), "confidence=92")
	if leaked {
		return ports.ChatResponse{Content: `{"verdict":"refuted","driver":"not_reachable","confidence":92}`}, nil
	}
	return ports.ChatResponse{Content: `{"verdict":"sound","driver":"attacker_controlled","confidence":88}`}, nil
}

func TestVerifierAssessmentIsBlindAndRunsBeforeComparison(t *testing.T) {
	llm := &anchoringLLM{}
	got := New(llm, "proposer-model").WithVerifier(llm, "verifier-model").Assess(
		context.Background(), []finding.Finding{mkFinding("1", "X (a/b.go:1)")}, nil,
	)[0]

	if len(llm.reqs) != 2 || llm.reqs[0].Model != "verifier-model" || llm.reqs[1].Model != "proposer-model" {
		t.Fatalf("blind verifier must run before the proposer result exists, requests=%+v", llm.reqs)
	}
	if got.Verifier == nil || got.Verifier.Verdict != judgment.CritiqueSound {
		t.Fatalf("verifier was anchored by proposer output: %+v", got)
	}
	if got.SuspectedFP(75) || got.VerifiedConsensus(75) {
		t.Fatalf("an independent disagreement must keep the finding gating: %+v", got)
	}
}

// TestVerifierPromptContractIsPinned addresses the review follow-up that ordering alone prevents the
// proposer's dynamic result from leaking, but would not catch a future static anchoring sentence such as
// "findings like this are usually false positives". Any verifier-system-prompt change now requires an
// explicit security-review update to this fingerprint instead of silently changing the neutral contract.
func TestVerifierPromptContractIsPinned(t *testing.T) {
	const approvedSHA256 = "aba2cc4a917ac633bc8fd5d5c9facb2d3ad90f0100b537116e3a82cd114f1778"
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(verifierSystemPrompt)))
	if got != approvedSHA256 {
		t.Fatalf("verifier system prompt changed: sha256=%s; review it for static anchoring before updating the approved fingerprint", got)
	}
}

// recordingLLM answers like roleLLM but keeps every request, so a test can assert what the coordinator
// actually asked the provider for.
type recordingLLM struct {
	reply string
	reqs  []ports.ChatRequest
}

func (r *recordingLLM) Chat(_ context.Context, req ports.ChatRequest) (ports.ChatResponse, error) {
	r.reqs = append(r.reqs, req)
	return ports.ChatResponse{Content: r.reply, FinishReason: "stop"}, nil
}

// TestCritiqueRequestsAreGreedy guards the determinism the gate exemption rests on: both the proposer
// and the distinct verifier must ask for temperature 0 explicitly. A nil temperature would leave the
// adjudication to the provider's default sampling, so the same finding could land on either side of the
// confidence bar across two runs.
func TestCritiqueRequestsAreGreedy(t *testing.T) {
	llm := &recordingLLM{reply: `{"verdict":"refuted","driver":"not_reachable","confidence":92}`}
	c := New(llm, "proposer-model").WithVerifier(llm, "verifier-model")
	c.Assess(context.Background(), []finding.Finding{mkFinding("1", "X (a/b.go:1)")}, nil)

	if len(llm.reqs) != 2 {
		t.Fatalf("want a proposer and a verifier call, got %d", len(llm.reqs))
	}
	for i, req := range llm.reqs {
		if req.Temperature == nil {
			t.Errorf("request %d (%s) left temperature unset – the provider default applies", i, req.Model)
			continue
		}
		if *req.Temperature != 0 {
			t.Errorf("request %d (%s) temperature = %v, want 0", i, req.Model, *req.Temperature)
		}
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
	// Verdict and confidence participate in the gate decision, so malformed values must fail closed.
	bad := []string{
		``,
		`{"verdict":"maybe","driver":"x","confidence":10}`, // unknown verdict
		`{"driver":"x","confidence":10}`,                   // missing verdict
		`{"verdict":"refuted","driver":"x"}`,               // missing confidence
		`{"verdict":"refuted","driver":"x","confidence":-1}`,
		`{"verdict":"refuted","driver":"x","confidence":101}`,
		`{"verdict":"refuted","driver":"x","confidence":900}`,
		`no json at all`,
	}
	for _, s := range bad {
		if _, err := parseCritique(s); err == nil {
			t.Errorf("parseCritique(%q) must fail closed", s)
		}
	}
	// The driver is normalized/defaulted because it is a cosmetic audit label. Fences, prose, extra keys,
	// and empty/spaced drivers remain tolerated without relaxing verdict or confidence validation.
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

func TestLocationOfPrefersValidatedStructuredLocation(t *testing.T) {
	structured := finding.Finding{
		Title:          "conflicting display location (wrong.go:99)",
		SourceLocation: &finding.SourceLocation{File: "internal/right.go", StartLine: 42, EndLine: 42},
	}
	file, line, ok := locationOf(structured)
	if !ok || file != "internal/right.go" || line != 42 {
		t.Fatalf("structured location = (%q,%d,%v), want internal/right.go:42", file, line, ok)
	}

	structured.SourceLocation = &finding.SourceLocation{File: "../outside.go", StartLine: 1, EndLine: 1}
	if file, line, ok := locationOf(structured); ok || file != "" || line != 0 {
		t.Fatalf("invalid structured location fell back to title: (%q,%d,%v)", file, line, ok)
	}
}

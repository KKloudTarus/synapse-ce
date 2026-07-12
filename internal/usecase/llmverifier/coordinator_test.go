package llmverifier

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeLLM struct {
	content string
	err     error
}

func (f fakeLLM) Chat(_ context.Context, _ ports.ChatRequest) (ports.ChatResponse, error) {
	if f.err != nil {
		return ports.ChatResponse{}, f.err
	}
	return ports.ChatResponse{Content: f.content}, nil
}

// fakeVerifier records Verify calls and confirms iff score >= 75 (mirrors the real gate bar), enforcing
// self-confirm rejection like analysis.Service.
type fakeVerifier struct {
	calls []struct {
		verifier string
		id       shared.ID
		score    int
	}
}

func (v *fakeVerifier) Verify(_ context.Context, verifier string, _, id shared.ID, score int, _ string, _ int) (judgment.Judgment, error) {
	v.calls = append(v.calls, struct {
		verifier string
		id       shared.ID
		score    int
	}{verifier, id, score})
	st := judgment.StateRefuted
	if score >= 75 {
		st = judgment.StateConfirmed
	}
	return judgment.Judgment{ID: id, State: st}, nil
}

type fakeLister struct{ js []judgment.Judgment }

func (l fakeLister) ListByEngagement(_ context.Context, _ shared.ID) ([]judgment.Judgment, error) {
	return l.js, nil
}

func critique(id, proposer string, state judgment.State) judgment.Judgment {
	return judgment.Judgment{
		ID: shared.ID(id), Capability: judgment.CapCritique, SubjectKind: judgment.SubjectFinding,
		SubjectID: shared.ID("f-" + id), Claim: judgment.CritiqueClaim{Verdict: judgment.CritiqueRefuted, Driver: "not_reachable", Confidence: 80},
		State: state, ProposedBy: proposer, Version: 1,
	}
}

func TestAutoVerifyConfirmsAndRefutes(t *testing.T) {
	lister := fakeLister{js: []judgment.Judgment{
		critique("1", "agent:x", judgment.StateProposed),                                                       // high-score → confirmed
		critique("2", "agent:x", judgment.StateProposed),                                                       // low-score → refuted (separate run below)
		critique("3", "agent:x", judgment.StateConfirmed),                                                      // already confirmed → skip
		{ID: "4", Capability: judgment.CapRiskNarrative, State: judgment.StateProposed, ProposedBy: "agent:x"}, // ungated → skip
	}}
	ver := &fakeVerifier{}
	c := New(fakeLLM{content: `{"score":90,"rationale":"clearly a false positive"}`}, "cx/verifier", ver, lister)
	res, err := c.AutoVerify(context.Background(), "eng")
	if err != nil {
		t.Fatalf("AutoVerify: %v", err)
	}
	// Only the two PROPOSED gated (critique) judgments are attempted.
	if res.Attempted != 2 || res.Confirmed != 2 || res.Errors != 0 {
		t.Fatalf("want attempted=2 confirmed=2, got %+v", res)
	}
	if len(ver.calls) != 2 || ver.calls[0].verifier != "llm:cx/verifier" {
		t.Fatalf("verify calls wrong: %+v", ver.calls)
	}
}

func TestAutoVerifyLowScoreRefutes(t *testing.T) {
	c := New(fakeLLM{content: `{"score":40,"rationale":"finding looks real"}`}, "cx/verifier", &fakeVerifier{},
		fakeLister{js: []judgment.Judgment{critique("1", "agent:x", judgment.StateProposed)}})
	res, _ := c.AutoVerify(context.Background(), "eng")
	if res.Confirmed != 0 || res.Refuted != 1 {
		t.Errorf("low score must refute, got %+v", res)
	}
}

func TestAutoVerifySkipsSelfConfirm(t *testing.T) {
	// A judgment proposed BY this verifier identity must be skipped (never self-confirm).
	c := New(fakeLLM{content: `{"score":99,"rationale":"x"}`}, "cx/verifier", &fakeVerifier{},
		fakeLister{js: []judgment.Judgment{critique("1", "llm:cx/verifier", judgment.StateProposed)}})
	res, _ := c.AutoVerify(context.Background(), "eng")
	if res.Attempted != 0 || res.Skipped != 1 {
		t.Errorf("self-proposed judgment must be skipped, got %+v", res)
	}
}

func TestAutoVerifyBestEffortOnLLMError(t *testing.T) {
	ver := &fakeVerifier{}
	c := New(fakeLLM{err: errors.New("gateway 503")}, "cx/verifier", ver,
		fakeLister{js: []judgment.Judgment{critique("1", "agent:x", judgment.StateProposed)}})
	res, err := c.AutoVerify(context.Background(), "eng")
	if err != nil {
		t.Fatalf("batch must not error on a per-judgment LLM failure: %v", err)
	}
	if res.Errors != 1 || len(ver.calls) != 0 {
		t.Errorf("LLM error must skip Verify and count an error, got %+v calls=%v", res, ver.calls)
	}
}

func TestParseVerdict(t *testing.T) {
	for _, bad := range []string{"", "no json", `{"rationale":"x"}` /* no score */} {
		if _, _, ok := parseVerdict(bad); ok {
			t.Errorf("parseVerdict(%q) must fail", bad)
		}
	}
	// clamp + fence + prose tolerance
	if s, _, ok := parseVerdict("```json\n{\"score\":150,\"rationale\":\"y\"}\n```"); !ok || s != 100 {
		t.Errorf("fenced/over-100 score: got %d ok=%v, want 100", s, ok)
	}
	if s, r, ok := parseVerdict(`here: {"score":80,"rationale":"ok"} done`); !ok || s != 80 || r != "ok" {
		t.Errorf("prose-wrapped: %d %q %v", s, r, ok)
	}
	if _, r, _ := parseVerdict(`{"score":75,"rationale":""}`); !strings.Contains(r, "no rationale") {
		t.Errorf("empty rationale must default, got %q", r)
	}
}

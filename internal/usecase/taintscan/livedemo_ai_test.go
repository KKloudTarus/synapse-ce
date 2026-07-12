package taintscan

// Live-AI demonstration for #163 (source→sink file:line on taint findings): the REAL taint coordinator
// proposes a gated CapSAST judgment whose Location is now a "relpath:line" (from the SSA Positions side
// table) instead of only a symbol, and a REAL 9router model (the llmverifier — exactly how a taint judgment
// is confirmed in production) adversarially assesses that precise-location claim. When it confirms, the
// emitted Kind=sast finding carries the file:line; when it refutes, no finding is emitted (a valid
// adversarial outcome). Either way this proves the def-use precision reaches the AI verifier + the finding.
//
// Gated behind SYNAPSE_LIVE_AI=1. Run:
//   SYNAPSE_LIVE_AI=1 SYNAPSE_LLM_BASE_URL=http://localhost:20128/v1 SYNAPSE_LLM_MODEL=cx/gpt-5.4 \
//     go test ./internal/usecase/taintscan/ -run TestLiveAITaintFileLine -v

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/llmverifier"
)

type liveSealer struct{}

func (liveSealer) Seal(context.Context, shared.ID, string, []byte, string) (evidence.Evidence, error) {
	return evidence.Evidence{}, nil
}

type liveIDs struct{ n int }

func (i *liveIDs) NewID() shared.ID { i.n++; return shared.ID(fmt.Sprintf("id-%d", i.n)) }

func TestLiveAITaintFileLine(t *testing.T) {
	if os.Getenv("SYNAPSE_LIVE_AI") != "1" {
		t.Skip("set SYNAPSE_LIVE_AI=1 to run the live 9router demonstration")
	}
	base := os.Getenv("SYNAPSE_LLM_BASE_URL")
	if base == "" {
		base = "http://localhost:20128/v1"
	}
	model := os.Getenv("SYNAPSE_LLM_MODEL")
	if model == "" {
		model = "cx/gpt-5.4"
	}
	llm, err := openai.New(base, os.Getenv("SYNAPSE_LLM_API_KEY"), model, 90*time.Second)
	if err != nil {
		t.Fatalf("openai client: %v", err)
	}

	// Real analysis.Service + a real findings.Service as the SAST recorder, over memory stores.
	store := memory.NewJudgmentStore()
	findingRepo := memory.NewFindingRepository()
	analysisSvc, err := analysis.NewService(store, liveSealer{}, &fakeAudit{}, fixedClock{}, &liveIDs{})
	if err != nil {
		t.Fatalf("analysis service: %v", err)
	}
	analysisSvc.SetSASTRecorder(findings.NewService(findingRepo, nil, nil, &fakeAudit{}, fixedClock{}, &liveIDs{}))

	// The REAL taint coordinator proposes over a graph that carries a def-use position for the sink-using
	// function (as the SSA builder now emits). os.Getenv (source) + os/exec.Command (sink) → CWE-78.
	coord, err := NewCoordinator(
		&fakeBuilder{g: &callgraph.Graph{
			Edges:     []callgraph.Edge{{Caller: "app.handler", Callees: []string{"os.Getenv", "os/exec.Command"}}},
			Positions: map[string]string{"app.handler": "internal/app/handler.go:42"},
		}},
		analysisSvc, taint.DefaultCatalog(), &fakeAudit{}, fixedClock{},
	)
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	eng := shared.ID("eng-live")
	n, err := coord.Scan(context.Background(), eng, "/work/target")
	if err != nil || n == 0 {
		t.Fatalf("taint scan proposed nothing: n=%d err=%v", n, err)
	}

	// #163: the PROPOSED claim the verifier will read carries the file:line, not just the symbol.
	js, _ := store.ListByEngagement(context.Background(), eng)
	var claimLoc string
	for _, j := range js {
		if sc, ok := j.Claim.(judgment.SASTClaim); ok {
			claimLoc = sc.Location
		}
	}
	if claimLoc != "internal/app/handler.go:42" {
		t.Fatalf("the taint claim must carry the sink file:line, got %q", claimLoc)
	}
	t.Logf("taint CapSAST proposed with def-use Location=%q", claimLoc)

	// A REAL model adversarially verifies the precise-location taint judgment (the production confirm path).
	verifier := llmverifier.New(llm, model, analysisSvc, store)
	res, err := verifier.AutoVerify(context.Background(), eng, "human:pentester")
	if err != nil {
		t.Fatalf("auto-verify: %v", err)
	}
	t.Logf("llm verifier (%s): attempted=%d confirmed=%d refuted=%d errors=%d", model, res.Attempted, res.Confirmed, res.Refuted, res.Errors)
	if res.Attempted == 0 {
		t.Fatalf("the real model must have assessed the taint judgment, got attempted=0")
	}

	fs, _ := findingRepo.ListByEngagement(context.Background(), eng)
	switch {
	case res.Confirmed >= 1:
		if len(fs) == 0 {
			t.Fatalf("a confirmed taint judgment must emit a Kind=sast finding")
		}
		f := fs[0]
		if f.Kind != finding.KindSAST {
			t.Fatalf("want Kind=sast from the static/LLM verify path, got %s", f.Kind)
		}
		if !strings.Contains(f.Title, "internal/app/handler.go:42") {
			t.Fatalf("the confirmed finding must show the file:line (def-use precision), got title %q", f.Title)
		}
		t.Logf("PASS: real model CONFIRMED → Kind=sast finding shows file:line: %q", f.Title)
	default:
		if len(fs) != 0 {
			t.Fatalf("a non-confirmed judgment must NOT emit a finding, got %+v", fs)
		}
		t.Logf("PASS: real model did not confirm (adversarial refutation is a valid outcome); the file:line claim reached the verifier and no finding was emitted")
	}
}

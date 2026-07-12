package llmverifier

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type noopSealer struct{}

func (noopSealer) Seal(_ context.Context, _ shared.ID, kind string, _ []byte, _ string) (evidence.Evidence, error) {
	return evidence.Evidence{Kind: kind}.Seal(), nil
}

type noopAudit struct{}

func (noopAudit) Record(_ context.Context, _ ports.AuditEntry) error { return nil }

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Unix(0, 0).UTC() }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID { s.n++; return shared.ID(fmt.Sprintf("j%d", s.n)) }

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// TestLiveAutoVerifyAgainstGateway exercises the full propose → LLM-verify → seal path against a REAL
// OpenAI-compatible endpoint. Skipped unless SYNAPSE_LIVE_LLM_TEST is set (network + a live model), so the
// default suite stays deterministic. Run with:
//
//	SYNAPSE_LIVE_LLM_TEST=1 SYNAPSE_VERIFIER_MODEL=cx/gpt-5.4 go test ./internal/usecase/llmverifier -run Live -v
func TestLiveAutoVerifyAgainstGateway(t *testing.T) {
	if os.Getenv("SYNAPSE_LIVE_LLM_TEST") == "" {
		t.Skip("set SYNAPSE_LIVE_LLM_TEST=1 (with an OpenAI-compatible endpoint) to run the live verifier test")
	}
	base := envOr("SYNAPSE_LLM_BASE_URL", "http://localhost:20128/v1")
	model := envOr("SYNAPSE_VERIFIER_MODEL", "cx/gpt-5.4")
	llm, err := openai.New(base, os.Getenv("SYNAPSE_LLM_API_KEY"), model, 60*time.Second)
	if err != nil {
		t.Fatalf("openai client: %v", err)
	}

	store := memory.NewJudgmentStore()
	svc, err := analysis.NewService(store, noopSealer{}, noopAudit{}, sysClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("analysis service: %v", err)
	}

	ctx := context.Background()
	eng := shared.ID("eng-live")
	// Propose a gated critique AS the agent (a distinct identity from the "llm:<model>" verifier).
	claim := judgment.CritiqueClaim{Verdict: judgment.CritiqueRefuted, Driver: "not_reachable", Confidence: 85}
	proposed, err := svc.Propose(ctx, "agent:test", eng, judgment.CapCritique, judgment.SubjectFinding, shared.ID("finding-1"), claim)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if proposed.State != judgment.StateProposed || proposed.EvidenceScore != 0 {
		t.Fatalf("a proposed judgment must be inert (proposed, score 0): %+v", proposed)
	}

	res, err := New(llm, model, svc, store).AutoVerify(ctx, eng, "human:tester")
	if err != nil {
		t.Fatalf("AutoVerify: %v", err)
	}
	t.Logf("live AutoVerify result: %+v", res)
	if res.Attempted != 1 {
		t.Fatalf("want 1 attempted, got %+v", res)
	}
	if res.Errors != 0 {
		t.Fatalf("the live model call/parse failed (Errors>0): %+v", res)
	}
	got, err := store.ListByEngagement(ctx, eng)
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %v (%d judgments)", err, len(got))
	}
	if got[0].State == judgment.StateProposed {
		t.Fatalf("judgment must be verified (confirmed or refuted), still proposed: %+v", got[0])
	}
	t.Logf("judgment after live verify: state=%s score=%d", got[0].State, got[0].EvidenceScore)
}

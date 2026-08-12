package fptriage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type testTriageCache struct {
	mu   sync.Mutex
	data map[ports.FPTriageCacheKey]ports.FPTriageCachedDecision
}

func (c *testTriageCache) Load(_ context.Context, key ports.FPTriageCacheKey) (ports.FPTriageCachedDecision, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	decision, ok := c.data[key]
	return decision, ok, nil
}

func (c *testTriageCache) Store(_ context.Context, key ports.FPTriageCacheKey, decision ports.FPTriageCachedDecision) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil {
		c.data = map[ports.FPTriageCacheKey]ports.FPTriageCachedDecision{}
	}
	c.data[key] = decision
	return nil
}

type countingTriageLLM struct {
	mu      sync.Mutex
	calls   int
	content string
	err     error
}

func (l *countingTriageLLM) Chat(_ context.Context, _ ports.ChatRequest) (ports.ChatResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.err != nil {
		return ports.ChatResponse{}, l.err
	}
	return ports.ChatResponse{Content: l.content, FinishReason: "stop"}, nil
}

func (l *countingTriageLLM) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

type cacheSourceReader struct {
	snippet string
	hash    string
}

func (r *cacheSourceReader) Snippet(_ context.Context, _ string, _, _ int) (string, error) {
	return r.snippet, nil
}

func (r *cacheSourceReader) SnippetContext(_ context.Context, _ string, _, _ int) (string, string, error) {
	return r.snippet, r.hash, nil
}

func TestTriagerMapsToPortsDTO(t *testing.T) {
	llm := fakeLLM{byTitleSubstr: map[string]string{
		"fp.go":   `{"verdict":"refuted","driver":"test_or_example_code","confidence":90}`,
		"real.go": `{"verdict":"sound","driver":"attacker_controlled","confidence":80}`,
	}}
	tr := NewTriager(New(llm, "m"), nil) // nil reader → metadata-only critique
	var _ ports.FPTriager = tr           // implements the port
	cands := []finding.Finding{
		mkFinding("1", "X (a/fp.go:1)"),
		mkFinding("2", "Y (a/real.go:2)"),
	}
	out := tr.Triage(context.Background(), cands, "/root")
	if len(out) != 2 {
		t.Fatalf("want 2 critiques, got %d", len(out))
	}
	byKey := map[string]ports.AICritique{}
	for _, c := range out {
		byKey[c.DedupKey] = c
	}
	if c := byKey["dk-1"]; !c.SuspectedFP || c.Verdict != "refuted" || c.Driver != "test_or_example_code" {
		t.Errorf("fp finding mapping wrong: %+v", c)
	}
	if c := byKey["dk-2"]; c.SuspectedFP || c.Verdict != "sound" {
		t.Errorf("sound finding must not be suspected-FP: %+v", c)
	}
	// Verified is false in single-model mode.
	if byKey["dk-1"].Verified {
		t.Error("single-model refutation must not be marked verified")
	}
	if c := byKey["dk-1"]; c.GateExempt || c.ProposerModel != "m" || c.ProposerProvider != defaultProviderID ||
		c.ProposerModelFamily != "m" || c.VerifierModel != "" || c.IndependencePolicy != ports.AIIndependenceModelFamily || c.PromptVersion != promptVersion {
		t.Errorf("single-model DTO must be advisory with audit metadata, got %+v", c)
	}
}

func TestTriagerNilSafe(t *testing.T) {
	var tr *Triager
	if got := tr.Triage(context.Background(), []finding.Finding{mkFinding("1", "X (a.go:1)")}, "/r"); got != nil {
		t.Errorf("nil triager must return nil, got %v", got)
	}
	if got := NewTriager(nil, nil).Triage(context.Background(), nil, "/r"); got != nil {
		t.Errorf("nil coordinator / no candidates must return nil, got %v", got)
	}
}

func TestTriagerCacheHitsAndInvalidatesBySafeContext(t *testing.T) {
	proposer := &countingTriageLLM{content: `{"verdict":"refuted","driver":"input_sanitized","confidence":91}`}
	verifier := &countingTriageLLM{content: `{"verdict":"refuted","driver":"input_sanitized","confidence":88}`}
	cache := &testTriageCache{}
	reader := &cacheSourceReader{snippet: "1: safe(query)\n", hash: strings.Repeat("a", 64)}
	coord := New(proposer, "provider/model-a").WithVerifier(verifier, "provider/model-b")
	triager := NewTriager(coord, func(string) ports.SourceSnippetReader { return reader }).WithCache(cache, "policy-v1")
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	f := mkFinding("1", "SQL query (app.go:1)")
	f.EngagementID = "project-a"

	first := triager.Triage(ctx, []finding.Finding{f}, "/workspace")
	if len(first) != 1 || !first[0].Verified {
		t.Fatalf("first critique = %+v", first)
	}
	if proposer.callCount() != 1 || verifier.callCount() != 1 {
		t.Fatalf("first scan calls proposer=%d verifier=%d", proposer.callCount(), verifier.callCount())
	}

	// A scan-local finding ID may change across scans. The cached model claims must bind to the current
	// finding instead of replaying the old row identity.
	f.ID = "id-current-scan"
	second := triager.Triage(ctx, []finding.Finding{f}, "/workspace")
	if len(second) != 1 || second[0].FindingID != "id-current-scan" || second[0].Verdict != first[0].Verdict {
		t.Fatalf("cache hit was not rebound identically: first=%+v second=%+v", first, second)
	}
	if proposer.callCount() != 1 || verifier.callCount() != 1 {
		t.Fatal("an identical second scan must not call either model")
	}

	reader.hash = strings.Repeat("b", 64) // full file changed outside the identical snippet window
	triager.Triage(ctx, []finding.Finding{f}, "/workspace")
	if proposer.callCount() != 2 || verifier.callCount() != 2 {
		t.Fatal("a complete-source hash change must invalidate both model claims")
	}

	f.Title = "SQL query with changed metadata (app.go:1)"
	triager.Triage(ctx, []finding.Finding{f}, "/workspace")
	if proposer.callCount() != 3 || verifier.callCount() != 3 {
		t.Fatal("a prompt-context change must invalidate both model claims")
	}

	triager.Triage(shared.WithTenant(context.Background(), "tenant-b"), []finding.Finding{f}, "/workspace")
	if proposer.callCount() != 4 || verifier.callCount() != 4 {
		t.Fatal("a different tenant must never reuse the cached claims")
	}

	f.EngagementID = "project-b"
	triager.Triage(ctx, []finding.Finding{f}, "/workspace")
	if proposer.callCount() != 5 || verifier.callCount() != 5 {
		t.Fatal("an incompatible project/engagement scope must never reuse the cached claims")
	}

	NewTriager(coord, func(string) ports.SourceSnippetReader { return reader }).
		WithCache(cache, "policy-v2").Triage(ctx, []finding.Finding{f}, "/workspace")
	if proposer.callCount() != 6 || verifier.callCount() != 6 {
		t.Fatal("a policy-version change must invalidate both model claims")
	}

	providerScoped := NewWithIdentity(proposer, "provider-a", "provider/model-a").
		WithIndependentVerifier(verifier, "provider-b", "provider/model-b", ports.AIIndependenceProvider)
	got := NewTriager(providerScoped, func(string) ports.SourceSnippetReader { return reader }).
		WithCache(cache, "policy-v1").Triage(ctx, []finding.Finding{f}, "/workspace")
	if proposer.callCount() != 7 || verifier.callCount() != 7 {
		t.Fatal("different provider identities must invalidate both model claims")
	}
	if len(got) != 1 || got[0].ProposerProvider != "provider-a" || got[0].VerifierProvider != "provider-b" {
		t.Fatalf("provider-scoped critique metadata = %+v", got)
	}
}

func TestTriagerDoesNotCacheVerifierOutage(t *testing.T) {
	proposer := &countingTriageLLM{content: `{"verdict":"refuted","driver":"input_sanitized","confidence":91}`}
	verifier := &countingTriageLLM{err: errors.New("provider unavailable")}
	reader := &cacheSourceReader{snippet: "1: safe(query)\n", hash: strings.Repeat("a", 64)}
	triager := NewTriager(
		New(proposer, "provider/model-a").WithVerifier(verifier, "provider/model-b"),
		func(string) ports.SourceSnippetReader { return reader },
	).WithCache(&testTriageCache{}, "policy-v1")
	f := mkFinding("1", "SQL query (app.go:1)")
	f.EngagementID = "project-a"
	ctx := shared.WithTenant(context.Background(), "tenant-a")

	for range 2 {
		got := triager.Triage(ctx, []finding.Finding{f}, "/workspace")
		if len(got) != 1 || got[0].Verified {
			t.Fatalf("verifier outage must stay advisory: %+v", got)
		}
	}
	if proposer.callCount() != 2 || verifier.callCount() != 2 {
		t.Fatalf("outage must be retried, calls proposer=%d verifier=%d", proposer.callCount(), verifier.callCount())
	}
}

func TestTriagerWithoutTenantContextNeverCaches(t *testing.T) {
	proposer := &countingTriageLLM{content: `{"verdict":"sound","driver":"attacker_controlled","confidence":85}`}
	reader := &cacheSourceReader{snippet: "1: query(input)\n", hash: strings.Repeat("a", 64)}
	triager := NewTriager(
		New(proposer, "provider/model-a"), func(string) ports.SourceSnippetReader { return reader },
	).WithCache(&testTriageCache{}, "policy-v1")
	f := mkFinding("1", "SQL query (app.go:1)")
	f.EngagementID = "project-a"

	for range 2 {
		if got := triager.Triage(context.Background(), []finding.Finding{f}, "/workspace"); len(got) != 1 {
			t.Fatalf("live triage must still run without cache scope: %+v", got)
		}
	}
	if proposer.callCount() != 2 {
		t.Fatalf("missing tenant identity must disable cache, calls=%d", proposer.callCount())
	}
}

func TestEvidenceAwareCacheHitRevalidatesCitationsAgainstCurrentContext(t *testing.T) {
	proposer := &countingTriageLLM{content: `{"verdict":"refuted","driver":"input_sanitized","confidence":91,"evidence_tokens":["ev:sanitizer"]}`}
	cache := &testTriageCache{}
	reader := &cacheSourceReader{snippet: "1: safe(query)\n", hash: strings.Repeat("a", 64)}
	triager := NewTriager(New(proposer, "provider/model-a"), func(string) ports.SourceSnippetReader { return reader }).WithCache(cache, "policy-v1")
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	f := mkFinding("1", "SQL query (app.go:1)")
	f.EngagementID = "project-a"
	evidence := map[string][]ports.AITriageEvidenceToken{f.DedupKey: {
		{ID: "ev:cwe", Kind: "cwe", Value: "CWE-89"},
		{ID: "ev:sanitizer", Kind: "sanitizer", Value: "sanitized before sink"},
	}}

	first := triager.TriageWithEvidence(ctx, []finding.Finding{f}, "/workspace", evidence)
	if len(first) != 1 || proposer.callCount() != 1 {
		t.Fatalf("first evidence-aware critique=%+v calls=%d", first, proposer.callCount())
	}

	cache.mu.Lock()
	if len(cache.data) != 1 {
		cache.mu.Unlock()
		t.Fatalf("cache entries=%d, want 1", len(cache.data))
	}
	for key, decision := range cache.data {
		// Keep the exact cache key/current dictionary but corrupt the claim's citation so it no
		// longer supports input_sanitized. The use case must fail closed to a live miss.
		decision.EvidenceTokens = []string{"ev:cwe"}
		cache.data[key] = decision
	}
	cache.mu.Unlock()

	second := triager.TriageWithEvidence(ctx, []finding.Finding{f}, "/workspace", evidence)
	if len(second) != 1 || proposer.callCount() != 2 {
		t.Fatalf("stale citation was reused instead of re-triaged: second=%+v calls=%d", second, proposer.callCount())
	}
}

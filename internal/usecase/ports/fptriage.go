package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SourceSnippetReader returns a small source excerpt around file:line (1-based, radius lines each side)
// from a workspace. The concrete implementation reads the Synapse-controlled scanned tree (a bounded,
// read-only helper), so this is not a path handed to a tool. An error (missing/binary file) is
// non-fatal — the caller critiques on finding metadata alone.
type SourceSnippetReader interface {
	Snippet(ctx context.Context, file string, line, radius int) (string, error)
}

// AIIndependencePolicy identifies the deterministic separation-of-duties rule applied to an
// AI-triage proposer/verifier pair. Model-family is the backwards-compatible minimum; provider
// additionally requires two explicitly identified, different providers. Unknown values are never
// authoritative and therefore keep the finding gating.
type AIIndependencePolicy string

const (
	AIIndependenceModelFamily AIIndependencePolicy = "model_family"
	AIIndependenceProvider    AIIndependencePolicy = "provider"
)

// AICritique is one finding's LLM false-positive verdict (propose-only, advisory). Verdict and Driver use
// the closed judgment.CritiqueClaim vocabulary (no free prose). SuspectedFP records the model's opinion;
// it NEVER grants a gate exemption by itself. GateExempt is a separate, server-owned policy decision that
// requires distinct-model consensus and must also clear the human-review floor. The complete decision and
// model metadata are retained in the scan result and its tamper-evident evidence link.
type AICritique struct {
	FindingID     string `json:"finding_id"`
	DedupKey      string `json:"dedup_key"`
	Verdict       string `json:"verdict"`
	Driver        string `json:"driver"`
	Confidence    int    `json:"confidence"`
	SuspectedFP   bool   `json:"suspected_fp"`
	ProposerModel string `json:"proposer_model"`
	VerifierModel string `json:"verifier_model,omitempty"`
	// Provider and canonical model-family metadata make the separation-of-duties decision
	// replayable. The server re-derives both family values from the raw model IDs before granting
	// authority; these fields are audit metadata, not trusted shortcuts.
	ProposerProvider    string               `json:"proposer_provider"`
	ProposerModelFamily string               `json:"proposer_model_family"`
	VerifierProvider    string               `json:"verifier_provider,omitempty"`
	VerifierModelFamily string               `json:"verifier_model_family,omitempty"`
	IndependencePolicy  AIIndependencePolicy `json:"independence_policy"`
	PromptVersion       string               `json:"prompt_version"`
	PolicyVersion       string               `json:"policy_version,omitempty"`
	PolicyReason        string               `json:"policy_reason,omitempty"`
	// Shadow is server-owned rollout metadata. When true, WouldGateExempt records the decision the
	// enforced policy would have made, but GateExempt must remain false and the finding keeps gating.
	Shadow          bool `json:"shadow,omitempty"`
	WouldGateExempt bool `json:"would_gate_exempt,omitempty"`
	GateExempt      bool `json:"gate_exempt"`
	ReviewRequired  bool `json:"review_required"`
	// Verified is true when a DISTINCT canonical model family independently confirmed the refutation
	// without seeing the proposer result. Single-model triage can set SuspectedFP but can never set
	// Verified or GateExempt.
	Verified           bool   `json:"verified"`
	VerifierVerdict    string `json:"verifier_verdict,omitempty"`
	VerifierDriver     string `json:"verifier_driver,omitempty"`
	VerifierConfidence int    `json:"verifier_confidence,omitempty"`
}

// AIGateExemption is the minimal, policy-owned projection an output adapter may use to explain why
// a retained finding did not affect the CI gate. It deliberately excludes model prose and scores:
// exports describe the deterministic policy decision, not an untrusted model response.
type AIGateExemption struct {
	DedupKey      string
	PolicyVersion string
	PolicyReason  string
}

// AIGateExemptionReader returns only exemptions revalidated against the exact finding view being
// exported. An exporter must not infer gate authority directly from the advisory AICritique fields.
type AIGateExemptionReader interface {
	AIGateExemptions(ctx context.Context, engagementID shared.ID, findings []finding.Finding) ([]AIGateExemption, error)
}

// FPTriager runs an LLM false-positive critique over candidate findings from a workspace and returns a
// per-candidate advisory verdict. It is best-effort and PROPOSE-ONLY: it never mutates or deletes a
// finding. The caller applies the deterministic gate policy; only a verified critique that clears the
// human-review floor can be retain-and-mark gate-exempt.
//
// FPTriager is a trusted in-process boundary. The caller defensively revalidates its DTOs to contain a
// buggy implementation or forged decision fields; it does not sandbox a malicious implementation that
// already has the process's memory/filesystem authority. Injected optionally into the scan pipeline;
// nil = no triage.
type FPTriager interface {
	Triage(ctx context.Context, candidates []finding.Finding, workspaceDir string) []AICritique
}

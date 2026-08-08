package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
)

// SourceSnippetReader returns a small source excerpt around file:line (1-based, radius lines each side)
// from a workspace. The concrete implementation reads the Synapse-controlled scanned tree (a bounded,
// read-only helper), so this is not a path handed to a tool. An error (missing/binary file) is
// non-fatal — the caller critiques on finding metadata alone.
type SourceSnippetReader interface {
	Snippet(ctx context.Context, file string, line, radius int) (string, error)
}

// AICritique is one finding's LLM false-positive verdict (propose-only, advisory). Verdict and Driver use
// the closed judgment.CritiqueClaim vocabulary (no free prose). SuspectedFP records the model's opinion;
// it NEVER grants a gate exemption by itself. GateExempt is a separate, server-owned policy decision that
// requires distinct-model consensus and must also clear the human-review floor. The complete decision and
// model metadata are retained in the scan result and its tamper-evident evidence link.
type AICritique struct {
	FindingID      string `json:"finding_id"`
	DedupKey       string `json:"dedup_key"`
	Verdict        string `json:"verdict"`
	Driver         string `json:"driver"`
	Confidence     int    `json:"confidence"`
	SuspectedFP    bool   `json:"suspected_fp"`
	ProposerModel  string `json:"proposer_model"`
	VerifierModel  string `json:"verifier_model,omitempty"`
	PromptVersion  string `json:"prompt_version"`
	PolicyVersion  string `json:"policy_version,omitempty"`
	PolicyReason   string `json:"policy_reason,omitempty"`
	GateExempt     bool   `json:"gate_exempt"`
	ReviewRequired bool   `json:"review_required"`
	// Verified is true when a DISTINCT verifier model independently confirmed the refutation (two-model
	// consensus). Single-model triage can set SuspectedFP but can never set Verified or GateExempt.
	Verified           bool   `json:"verified"`
	VerifierVerdict    string `json:"verifier_verdict,omitempty"`
	VerifierDriver     string `json:"verifier_driver,omitempty"`
	VerifierConfidence int    `json:"verifier_confidence,omitempty"`
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

// Package agenttools is the agent's tool catalog: the bounded set of
// capabilities the LLM is allowed to invoke. It embodies two non-negotiable constraints in
// its very shape:
//
// Anti-self-escalation. The catalog exposes ONLY read tools – scoped to the
// agent's own engagement – plus a single propose-only execute tool. There is NO tool to
// mutate scope, the authorization window, RoE, live-recon, credentials, or the approval
// mode; those are operator-only. The catalog literally holds no writer for any of them,
// so a hostile or confused model cannot widen its own authority by calling a tool.
// Data minimization. Scope data, tokens, and AUP records are NEVER returned
// to the LLM. The agent does not need the scope inventory to be useful – the safety gate
// enforces scope server-side regardless of what the model proposes – so it is never
// disclosed to the (third-party, untrusted) LLM provider. Read tools are locked to the
// session's engagement id; an engagement id is not even accepted as a tool argument.
//
// Read tools return DATA (fed back to the model as a tool message). The execute tool
// (start_recon) returns a *ProposedAction ENVELOPE and runs nothing – the orchestrator MUST
// pass it through safety.Gate before any execution. Every dispatch is recorded in the
// append-only audit log as the agent (actor = "agent:<sessionID>").
package agenttools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Catalog tool names. These are the EXACT set advertised to the LLM; the anti-self-escalation
// test pins that no scope/credential/mode-mutating tool is ever added here.
const (
	ToolListFindings            = "list_findings"
	ToolGetFindingDetail        = "get_finding_detail"
	ToolListSASTValidation      = "list_sast_validation"
	ToolPlanRuntimeVerification = "plan_runtime_verification"
	ToolListEvidence            = "list_evidence"
	ToolVerifyCustody           = "verify_custody"
	ToolListReconTools          = "list_recon_tools"
	ToolStartRecon              = "start_recon"
	ToolProposePlan             = "propose_plan"              // propose a multi-step recon plan (DAG); runs nothing
	ToolProposeFinding          = "propose_finding"           // record an UNPROVEN exploitation claim at score 0
	ToolReachabilityContext     = "reachability_context"      // read dep-graph reachability facts (T0/T1)
	ToolProposeReachability     = "propose_reachability"      // propose a reachability Judgment (score 0; verify is human-only)
	ToolProposeSASTValidation   = "propose_sast_validation"   // propose a gated CapSAST judgment for verifier review; score 0, no execution
	ToolProposeCritique         = "propose_critique"          // propose an adversarial critique Judgment against a finding (score 0)
	ToolEvidenceSufficiency     = "evidence_sufficiency"      // read-only advisory – what's missing for a finding to reach the bar
	ToolProposeRiskNarrative    = "propose_risk_narrative"    // propose a risk-narrative Judgment (ungated; a human accepts)
	ToolProposeThreat           = "propose_threat"            // propose a STRIDE threat Judgment over the architecture model (score 0; a human ratifies)
	ToolProposeWriteupDraft     = "propose_writeup_draft"     // propose a finding write-up DRAFT (prose) awaiting human sign-off (NOT a judgment)
	ToolProposeAttackChain      = "propose_attack_chain"      // propose an attack-chain HYPOTHESIS finding (score 0; gated until a human verifies)
	ToolProposeVexJustification = "propose_vex_justification" // propose an OpenVEX not_affected justification Judgment (score 0; a human ratifies)
)

// MaxPlanNodes bounds how many nodes a single propose_plan may carry (mirrors the domain cap);
// a larger proposal is rejected, never truncated.
const MaxPlanNodes = agent.MaxPlanNodes

// maxRows caps how many rows a read tool returns, so a large engagement cannot blow the
// agent's token budget in one call; the payload reports the true total + a truncated flag.
const maxRows = 50

// findingReader / evidenceReader are the narrow read slices of the finding/evidence ports the
// catalog needs (consumer-defined interfaces: the concrete repositories satisfy them and
// tests fake them trivially). The catalog deliberately depends on no write method.
type findingReader interface {
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error)
}

type evidenceReader interface {
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]evidence.Evidence, error)
}

// findingProposer is the narrow slice of the exploitation use-case the catalog needs to record
// an UNPROVEN finding. It creates the finding at EvidenceScore 0 attributed to the
// proposer; it confers NO power to raise the score or confirm – a DISTINCT verifier must do that
// out of band (the catalog deliberately exposes no score/verify/confirm writer). *exploitation.Service
// satisfies it.
type findingProposer interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, in finding.ExploitationInput) (finding.Finding, error)
}

// hypothesisProposer is the narrow slice of the exploitation use-case the catalog needs to record an
// attack-chain HYPOTHESIS: a Kind=hypothesis finding at EvidenceScore 0, gated until a distinct human
// verifies it. Like findingProposer it exposes only the propose path – no score/verify writer. The created
// finding NEVER auto-merges its constituents (it only names them). *exploitation.Service satisfies it.
type hypothesisProposer interface {
	ProposeHypothesis(ctx context.Context, proposer string, engagementID shared.ID, in finding.HypothesisInput) (finding.Finding, error)
}

// scanResultReader is the narrow read slice of the SCA scan-result store the reachability-context
// tool needs: the latest persisted scan result for an engagement, as JSON. The catalog decodes only
// the dep-graph fields it needs (SBOM components + edges) – it does NOT import the sca use case.
type scanResultReader interface {
	LatestResult(ctx context.Context, engagementID shared.ID) ([]byte, error)
}

// judgmentProposer is the narrow slice of the analysis use-case the propose_reachability/critique/risk_narrative/threat tools need:
// record a PROPOSED judgment (score 0). It exposes ONLY Propose – NOT Verify/Accept – so the agent
// can never confirm its own judgment (R11); the arch_test tripwire forbidding usecase/analysis makes
// that structural. *analysis.Service satisfies it.
type judgmentProposer interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error)
}

// writeupdraftProposer is the narrow slice of the writeupdraft use-case the propose_writeup_draft tool
// needs: record a PROPOSED draft awaiting human sign-off. It exposes ONLY Propose – NOT Edit/Accept/Reject
// – so the agent can never sign off its own draft (the human-gate + SoD live behind the HTTP routes); the
// arch_test tripwire forbidding usecase/writeupdraftuc makes that structural. *writeupdraftuc.Service satisfies it.
type writeupdraftProposer interface {
	Propose(ctx context.Context, proposer string, engagementID, findingID shared.ID, description, remediation string) (writeupdraft.Draft, error)
}

// Catalog dispatches the agent's tool calls: read tools against the engagement's own data,
// and start_recon into a gated proposal. It never executes a tool or mutates anything.
type Catalog struct {
	findings    findingReader
	evidences   evidenceReader
	recon       map[string]ports.ReconTool // by name, for start_recon lookup
	reconList   []ports.ReconTool          // stable (sorted) order for list_recon_tools
	audit       ports.AuditLogger
	clock       ports.Clock
	ids         ports.IDGenerator
	planning    bool                 // advertise + dispatch propose_plan (only when the orchestrator has a PlanStore)
	proposer    findingProposer      // advertise + dispatch propose_finding (nil ⇒ tool absent)
	hypProposer hypothesisProposer   // advertise + dispatch propose_attack_chain (nil ⇒ tool absent)
	reach       scanResultReader     // advertise + dispatch reachability_context (nil ⇒ tool absent)
	jproposer   judgmentProposer     // advertise + dispatch propose_reachability/critique/risk_narrative/threat (nil ⇒ absent)
	drafter     writeupdraftProposer // advertise + dispatch propose_writeup_draft (nil ⇒ absent)
}

// EnableFindingProposals turns on the propose_finding tool. The agent can then
// RECORD an unproven exploitation claim (score 0); it still cannot raise its own score or
// confirm – that needs a distinct verifier out of band. The composition root supplies the
// exploitation service.
func (c *Catalog) EnableFindingProposals(p findingProposer) { c.proposer = p }

// EnableHypotheses turns on the propose_attack_chain tool. The agent can then record an attack-chain
// HYPOTHESIS (a Kind=hypothesis finding at score 0, linking constituent findings); it still cannot raise the
// score or confirm – a distinct human verifies it out of band (the same gate as an exploitation finding).
func (c *Catalog) EnableHypotheses(p hypothesisProposer) { c.hypProposer = p }

// EnableReachability turns on the reachability_context read tool: the agent can read the
// engagement's dependency-graph FACTS for a vulnerable package (dep path, direct flag, scope,
// manifest location) to reason about T0/T1 reachability. Read-only – it forms NO verdict (the agent
// proposes a ReachabilityClaim out of band). The composition root supplies the scan-result store.
func (c *Catalog) EnableReachability(r scanResultReader) { c.reach = r }

// EnableJudgments turns on the propose_reachability + propose_sast_validation + propose_critique + propose_risk_narrative + propose_threat tools: the agent can
// RECORD a judgment (score 0); it still cannot raise the score or confirm – a distinct human reviewer verifies
// it via PermReview, out of band. The composition root supplies the analysis service.
func (c *Catalog) EnableJudgments(p judgmentProposer) { c.jproposer = p }

// EnableWriteupDrafts turns on the propose_writeup_draft tool: the agent can DRAFT a finding's
// description + remediation PROSE as a proposal (awaiting human sign-off). It still cannot edit, accept, or
// reject a draft – those are human actions behind PermReview + SoD (the proposer cannot sign off its own
// draft). The composition root supplies the writeupdraft service (which satisfies the narrow proposer).
func (c *Catalog) EnableWriteupDrafts(p writeupdraftProposer) { c.drafter = p }

// EnablePlanning turns on the propose_plan tool. The composition root calls this for the
// orchestrator's catalog when (and only when) it also wires a PlanStore + SetPlanStore, so the
// catalog never advertises a capability the orchestrator cannot drive. Left off for the
// MCP/read-only catalog, which has no planner.
func (c *Catalog) EnablePlanning() { c.planning = true }

// New validates its dependencies. reconTools is the SAME set wired into the recon use-case
// (passed by the composition root); duplicates are rejected.
func New(findings findingReader, evidences evidenceReader, reconTools []ports.ReconTool, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Catalog, error) {
	if findings == nil || evidences == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: agenttools catalog is missing a dependency", shared.ErrValidation)
	}
	m := make(map[string]ports.ReconTool, len(reconTools))
	list := make([]ports.ReconTool, 0, len(reconTools))
	for _, t := range reconTools {
		if t == nil {
			continue
		}
		if _, dup := m[t.Name()]; dup {
			return nil, fmt.Errorf("%w: duplicate recon tool %q", shared.ErrValidation, t.Name())
		}
		m[t.Name()] = t
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name() < list[j].Name() })
	return &Catalog{findings: findings, evidences: evidences, recon: m, reconList: list, audit: audit, clock: clock, ids: ids}, nil
}

// Result is a tool dispatch outcome. Exactly one field is set: Data for a read tool (JSON to
// feed back to the model as a tool message), or Proposal for an execute tool (an
// approval-required envelope the orchestrator must run through safety.Gate). A non-nil
// Proposal has executed NOTHING.
type Result struct {
	Data     json.RawMessage
	Proposal *agent.ProposedAction
	// Plan is set by propose_plan: a validated, NOT-yet-persisted execution DAG (Go minted the
	// node ids, classified risk, and validated acyclicity). It has executed nothing – the
	// orchestrator persists it and drives each node through safety.Gate.Admit.
	Plan *agent.Plan
}

// Tools returns the JSON-schema tool definitions advertised to the LLM. The read tools take
// no arguments – they operate on the session's engagement, which is never an LLM-supplied id.
func (c *Catalog) Tools() []agent.ToolSchema {
	empty := json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)
	schemas := []agent.ToolSchema{
		{Name: ToolListFindings, Description: "List the security findings recorded for the current engagement (id, title, severity, kind, status, priority, KEV). Read-only.", Parameters: empty},
		{Name: ToolGetFindingDetail, Description: "Get one finding's bounded detail for AppSec review: metadata, redacted description, confidence, class/scope, reachability, evidence score/count, and SAST validation-envelope text when present. Read-only; does not expose raw source or evidence content.", Parameters: json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","description":"the finding id from list_findings"}},"required":["finding_id"],"additionalProperties":false}`)},
		{Name: ToolListSASTValidation, Description: "List SAST candidates as a bounded validation closure table: finding id, CWE/OWASP, source/control/sink, disposition, closure status, blockers, and counterevidence. Read-only; does not expose raw source or evidence content.", Parameters: empty},
		{Name: ToolPlanRuntimeVerification, Description: "Build a SAFE, read-only runtime-verification plan for a SAST finding that needs exploitability proof. This does NOT execute a probe and accepts only an existing finding id; scope, authorization window, HITL approval, and evidence sealing remain server-side requirements before any DAST/verifier run.", Parameters: json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","description":"the SAST finding id from list_sast_validation"}},"required":["finding_id"],"additionalProperties":false}`)},
		{Name: ToolListEvidence, Description: "List evidence-chain metadata for the current engagement (id, kind, hash, previous_hash, created_by, created_at). Evidence content is never returned. Read-only.", Parameters: empty},
		{Name: ToolVerifyCustody, Description: "Verify the integrity of the engagement's hash-chained evidence custody. Returns {ok, count, head_hash}. Read-only.", Parameters: empty},
		{Name: ToolListReconTools, Description: "List the reconnaissance tools you may propose via start_recon, with the target kinds each accepts and the risk class a proposal would carry. Read-only.", Parameters: empty},
		{Name: ToolStartRecon, Description: "Propose a reconnaissance run against a target. This does NOT run the tool: it creates an approval-required proposal that the scope/authorization gate and a human approver must clear before anything executes. Always include a one-line rationale.", Parameters: json.RawMessage(`{"type":"object","properties":{"tool":{"type":"string","description":"recon tool name, e.g. subfinder"},"target":{"type":"string","description":"the target to run against, e.g. app.example.com"},"rationale":{"type":"string","description":"one-line justification shown to the approver"}},"required":["tool","target"],"additionalProperties":false}`)},
		{Name: ToolEvidenceSufficiency, Description: "Assess whether a finding has enough evidence to be PUBLISHABLE. Returns its evidence score vs the bar, whether it is gated (exploitation/AI claims need a distinct verifier's sealed verdict; SCA/recon/manual do not), how many evidence items it has, and structured ADVICE on what is missing. Read-only and ADVISORY – it sets no score; only a distinct human verifier's sealed verdict moves a finding's score.", Parameters: json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","description":"the finding id to assess (from list_findings)"}},"required":["finding_id"],"additionalProperties":false}`)},
	}
	if c.proposer != nil {
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposeFinding,
			Description: "Record a SUSPECTED exploitation finding for the current engagement. This is an UNPROVEN claim: it is stored at evidence score 0 and is NOT reportable. You CANNOT confirm it or raise its score – a separate human/verifier must adversarially verify it out of band. Use only for a concrete, observed exploitation hypothesis.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"title":{"type":"string"},"description":{"type":"string"},"severity":{"type":"string","description":"critical|high|medium|low|info"},"cvss_vector":{"type":"string"},"cwe":{"type":"string"}},"required":["title","description","severity"],"additionalProperties":false}`),
		})
	}
	if c.hypProposer != nil {
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposeAttackChain,
			Description: "Record an attack-chain HYPOTHESIS: a claim that two or more EXISTING findings chain into an attack path (e.g. SSRF → cloud-metadata creds → admin API). This is an UNPROVEN claim, stored at evidence score 0 and NOT reportable; you CANNOT confirm it or raise its score – a distinct human verifies it out of band. It NEVER modifies or merges the constituent findings, only names them. Give the constituent finding ids (>= 2, from list_findings).",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"title":{"type":"string","description":"short name of the attack chain"},"description":{"type":"string","description":"how the findings chain into an attack path"},"constituent_ids":{"type":"array","items":{"type":"string"},"minItems":2,"description":"the finding ids this chain links (>= 2, from list_findings)"},"severity":{"type":"string","description":"optional: critical|high|medium|low|info; defaults to unknown for human triage"}},"required":["title","description","constituent_ids"],"additionalProperties":false}`),
		})
	}
	if c.planning {
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposePlan,
			Description: "Propose a MULTI-STEP reconnaissance plan as a dependency graph, instead of one step at a time. Each node names a recon tool + target + a short label ('key') + the labels it depends_on (run only after those complete). This RUNS NOTHING: Go validates the graph (acyclic, bounded) and then executes each node through the same scope/authorization gate + human approval as start_recon. Use when several recon steps are needed and some depend on others (e.g. probe hosts only after enumerating subdomains).",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"nodes":{"type":"array","items":{"type":"object","properties":{"key":{"type":"string","description":"a short unique label for this node, e.g. 'enum'"},"tool":{"type":"string","description":"recon tool name, e.g. subfinder"},"target":{"type":"string","description":"the target, e.g. app.example.com"},"depends_on":{"type":"array","items":{"type":"string"},"description":"keys of nodes that must complete first"},"rationale":{"type":"string","description":"one-line justification"}},"required":["key","tool","target"],"additionalProperties":false}}},"required":["nodes"],"additionalProperties":false}`),
		})
	}
	if c.reach != nil {
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolReachabilityContext,
			Description: "Get dependency-graph reachability FACTS for a vulnerable package in the current engagement: whether it is present in the SBOM, its dependency path from the project root, whether it is a DIRECT dependency, its scope (production/test/example/…), and its manifest location. Read-only – it returns facts, not a verdict; use it to reason about whether a vulnerability is actually reachable (a transitive, dev-only, deep dependency is far less likely to be reachable than a direct production one). Source call-path analysis is NOT included. Pass the exact version to disambiguate a package present at multiple versions; omitting it matches the first found.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"component":{"type":"string","description":"the vulnerable package name, e.g. lodash"},"version":{"type":"string","description":"the package version, e.g. 4.17.21 (optional)"}},"required":["component"],"additionalProperties":false}`),
		})
	}
	if c.jproposer != nil {
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposeReachability,
			Description: "Propose a REACHABILITY judgment for a finding – whether the vulnerable code is actually reachable – based on the facts from reachability_context. This is a PROPOSAL recorded at score 0: you CANNOT confirm it or raise its score; a distinct human reviewer must verify it out of band. Use tier-0 (dependency-graph presence) or tier-1 (direct import) – do NOT claim a deeper tier without source-call-path proof.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"subject_id":{"type":"string","description":"the finding id this judgment is about (from list_findings)"},"reachable":{"type":"string","description":"reachable | not_reachable | unknown"},"tier":{"type":"string","description":"tier-0 | tier-1 (the strongest your evidence supports)"},"path":{"type":"array","items":{"type":"string"},"description":"the dependency/call path supporting the verdict"},"confidence":{"type":"integer","description":"0-100"}},"required":["subject_id","reachable","tier"],"additionalProperties":false}`),
		})
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposeSASTValidation,
			Description: "Propose a gated SAST/runtime-validation judgment for an existing SAST finding. This records a typed CapSAST claim at score 0 for a distinct verifier/human to confirm or refute; it does NOT run DAST, does NOT execute payloads, and cannot raise evidence score. Use after plan_runtime_verification for needs-runtime-proof candidates.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","description":"the SAST finding id from list_sast_validation"},"cwe":{"type":"string","description":"CWE id, e.g. CWE-89"},"location":{"type":"string","description":"bounded location token such as path:line or finding:<id>; no prose"},"rule":{"type":"string","description":"structured rule/proof token, e.g. runtime-verification-needed, static-source-to-sink, verifier-refutation-needed"}},"required":["finding_id","cwe","location","rule"],"additionalProperties":false}`),
		})
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposeCritique,
			Description: "Adversarially CRITIQUE a finding – try to REFUTE it (is it a false positive? wrong version match? unreachable? a duplicate?). This is a PROPOSAL recorded at score 0: you CANNOT suppress or confirm a finding. A confirmed 'refuted' critique only FLAGS the finding as suspected-FP for a human reviewer; it never auto-hides it. Give a structured driver TOKEN for the refutation category, not prose.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"subject_id":{"type":"string","description":"the finding id you are critiquing (from list_findings)"},"verdict":{"type":"string","description":"refuted | sound | uncertain"},"driver":{"type":"string","description":"a short token for the refutation category, e.g. not_reachable, version_mismatch, false_match, duplicate (lowercase, no spaces, no prose)"},"confidence":{"type":"integer","description":"0-100"}},"required":["subject_id","verdict","driver"],"additionalProperties":false}`),
		})
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposeRiskNarrative,
			Description: "Explain WHY a finding has its computed risk priority, as STRUCTURED driver TOKENS (never prose). Recorded as a descriptive, UNGATED Judgment that a human ACCEPTS – it proves nothing, so there is no score or verifier verdict; it just explains. The renderer composes the sentence from the tokens.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"subject_id":{"type":"string","description":"the finding id this narrative explains (from list_findings)"},"drivers":{"type":"array","items":{"type":"string"},"description":"the risk-factor TOKENS that drive the priority, e.g. kev, epss>0.5, cvss>=9, reachable, direct, production (lowercase tokens, no spaces, no prose)"},"priority":{"type":"integer","description":"1 (highest) .. 5, mirroring the finding's computed priority"}},"required":["subject_id","drivers","priority"],"additionalProperties":false}`),
		})
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposeThreat,
			Description: "Propose a STRIDE THREAT over the architecture model: pick the category (spoofing/tampering/repudiation/info_disclosure/denial_of_service/elevation_of_privilege) and the model ELEMENT it applies to – a component or a data flow (prefer the flows that CROSS a trust boundary, the attack surface). This is a PROPOSAL recorded at score 0: you CANNOT confirm or rate it; a distinct human ratifies it. Give a structured category + element id, never prose.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"element_kind":{"type":"string","description":"component | data_flow (what the threatened element is)"},"element_id":{"type":"string","description":"the threatened model element's id (a component id or data flow id)"},"category":{"type":"string","description":"spoofing | tampering | repudiation | info_disclosure | denial_of_service | elevation_of_privilege"},"asset":{"type":"string","description":"optional id of the asset at risk (e.g. the classified data an info_disclosure exposes); omit if none"}},"required":["element_kind","element_id","category"],"additionalProperties":false}`),
		})
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposeVexJustification,
			Description: "Propose an OpenVEX JUSTIFICATION for why a finding is NOT AFFECTED – pick ONE of the closed OpenVEX justifications. This is a PROPOSAL recorded at score 0: you CANNOT confirm it; a distinct human ratifies it before any export trusts it (a false 'not affected' suppresses a real vuln). Pick the most specific justification you can support.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","description":"the finding this justification is about (from list_findings)"},"justification":{"type":"string","description":"one of: component_not_present | vulnerable_code_not_present | vulnerable_code_not_in_execute_path | vulnerable_code_cannot_be_controlled_by_adversary | inline_mitigations_already_exist"}},"required":["finding_id","justification"],"additionalProperties":false}`),
		})
	}
	if c.drafter != nil {
		schemas = append(schemas, agent.ToolSchema{
			Name:        ToolProposeWriteupDraft,
			Description: "DRAFT a finding's write-up – its description (what the issue is) and/or remediation (how to fix it) – as PROSE for a human to review. This is a PROPOSAL awaiting explicit human sign-off: it is NEVER auto-applied to the finding or rendered into a report, and you CANNOT accept your own draft. Provide at least a description or a remediation.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","description":"the finding whose write-up you are drafting (from list_findings)"},"description":{"type":"string","description":"the drafted finding-description prose; optional if you provide a remediation"},"remediation":{"type":"string","description":"the drafted remediation prose; optional if you provide a description"}},"required":["finding_id"],"additionalProperties":false}`),
		})
	}
	return schemas
}

// Dispatch routes a single LLM tool call. The engagement is ALWAYS the session's; an
// engagement id is never read from the call arguments (anti cross-engagement self-escalation).
func (c *Catalog) Dispatch(ctx context.Context, sess agent.Session, call agent.ToolCall) (Result, error) {
	switch call.Name {
	case ToolListFindings:
		return c.listFindings(ctx, sess)
	case ToolGetFindingDetail:
		return c.getFindingDetail(ctx, sess, call.Arguments)
	case ToolListSASTValidation:
		return c.listSASTValidation(ctx, sess)
	case ToolPlanRuntimeVerification:
		return c.planRuntimeVerification(ctx, sess, call.Arguments)
	case ToolListEvidence:
		return c.listEvidence(ctx, sess)
	case ToolVerifyCustody:
		return c.verifyCustody(ctx, sess)
	case ToolListReconTools:
		return c.listReconTools(ctx, sess)
	case ToolStartRecon:
		return c.startRecon(ctx, sess, call.Arguments)
	case ToolEvidenceSufficiency:
		return c.evidenceSufficiency(ctx, sess, call.Arguments)
	case ToolProposePlan:
		if !c.planning {
			return Result{}, fmt.Errorf("%w: planning is not enabled", shared.ErrValidation)
		}
		return c.proposePlan(ctx, sess, call.Arguments)
	case ToolProposeFinding:
		if c.proposer == nil {
			return Result{}, fmt.Errorf("%w: finding proposals are not enabled", shared.ErrValidation)
		}
		return c.proposeFinding(ctx, sess, call.Arguments)
	case ToolProposeAttackChain:
		if c.hypProposer == nil {
			return Result{}, fmt.Errorf("%w: attack-chain hypotheses are not enabled", shared.ErrValidation)
		}
		return c.proposeAttackChain(ctx, sess, call.Arguments)
	case ToolReachabilityContext:
		if c.reach == nil {
			return Result{}, fmt.Errorf("%w: reachability context is not enabled", shared.ErrValidation)
		}
		return c.reachabilityContext(ctx, sess, call.Arguments)
	case ToolProposeReachability:
		if c.jproposer == nil {
			return Result{}, fmt.Errorf("%w: reachability proposals are not enabled", shared.ErrValidation)
		}
		return c.proposeReachability(ctx, sess, call.Arguments)
	case ToolProposeSASTValidation:
		if c.jproposer == nil {
			return Result{}, fmt.Errorf("%w: SAST validation proposals are not enabled", shared.ErrValidation)
		}
		return c.proposeSASTValidation(ctx, sess, call.Arguments)
	case ToolProposeCritique:
		if c.jproposer == nil {
			return Result{}, fmt.Errorf("%w: critique proposals are not enabled", shared.ErrValidation)
		}
		return c.proposeCritique(ctx, sess, call.Arguments)
	case ToolProposeRiskNarrative:
		if c.jproposer == nil {
			return Result{}, fmt.Errorf("%w: risk-narrative proposals are not enabled", shared.ErrValidation)
		}
		return c.proposeRiskNarrative(ctx, sess, call.Arguments)
	case ToolProposeThreat:
		if c.jproposer == nil {
			return Result{}, fmt.Errorf("%w: threat proposals are not enabled", shared.ErrValidation)
		}
		return c.proposeThreat(ctx, sess, call.Arguments)
	case ToolProposeVexJustification:
		if c.jproposer == nil {
			return Result{}, fmt.Errorf("%w: VEX justification proposals are not enabled", shared.ErrValidation)
		}
		return c.proposeVexJustification(ctx, sess, call.Arguments)
	case ToolProposeWriteupDraft:
		if c.drafter == nil {
			return Result{}, fmt.Errorf("%w: writeup draft proposals are not enabled", shared.ErrValidation)
		}
		return c.proposeWriteupDraft(ctx, sess, call.Arguments)
	default:
		return Result{}, fmt.Errorf("%w: unknown tool %q", shared.ErrValidation, call.Name)
	}
}

// --- read tools ---

type findingView struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Severity  string  `json:"severity"`
	Kind      string  `json:"kind"`
	Status    string  `json:"status"`
	Priority  int     `json:"priority"`
	KEV       bool    `json:"kev"`
	RiskScore float64 `json:"risk_score"`
}

type findingDetailView struct {
	ID              string                `json:"id"`
	Title           string                `json:"title"`
	Description     string                `json:"description"`
	Severity        string                `json:"severity"`
	CWE             string                `json:"cwe,omitempty"`
	Kind            string                `json:"kind"`
	Class           string                `json:"class"`
	Scope           string                `json:"scope"`
	Status          string                `json:"status"`
	Priority        int                   `json:"priority"`
	KEV             bool                  `json:"kev"`
	RiskScore       float64               `json:"risk_score"`
	Sources         []string              `json:"sources,omitempty"`
	Confidence      string                `json:"confidence,omitempty"`
	Reachability    string                `json:"reachability,omitempty"`
	Impact          string                `json:"impact,omitempty"`
	EvidenceScore   int                   `json:"evidence_score"`
	EvidenceCount   int                   `json:"evidence_count"`
	Publishable     bool                  `json:"publishable"`
	RequiresGate    bool                  `json:"requires_evidence_gate"`
	DedupKey        string                `json:"dedup_key,omitempty"`
	HasSASTEnvelope bool                  `json:"has_sast_validation_envelope"`
	SASTValidation  *sastValidationDetail `json:"sast_validation,omitempty"`
	Note            string                `json:"note"`
}

type sastValidationDetail struct {
	OWASPCWE                   string   `json:"owasp_cwe,omitempty"`
	EntryPoint                 string   `json:"entrypoint,omitempty"`
	Source                     string   `json:"source,omitempty"`
	SourceEvidence             string   `json:"source_evidence,omitempty"`
	Sink                       string   `json:"sink,omitempty"`
	SinkEvidence               string   `json:"sink_evidence,omitempty"`
	ControlEvidence            string   `json:"control_evidence,omitempty"`
	RouteMiddleware            string   `json:"route_middleware,omitempty"`
	AuthEvidence               string   `json:"auth_evidence,omitempty"`
	Exposure                   string   `json:"exposure,omitempty"`
	TrustBoundary              string   `json:"trust_boundary,omitempty"`
	ImpactHypothesis           string   `json:"impact_hypothesis,omitempty"`
	RouteReachability          string   `json:"route_reachability,omitempty"`
	AuthRoleContext            string   `json:"auth_role_context,omitempty"`
	Dataflow                   string   `json:"dataflow,omitempty"`
	DataflowEvidence           string   `json:"dataflow_evidence,omitempty"`
	DataflowConfidence         string   `json:"dataflow_confidence,omitempty"`
	ValidationMethod           string   `json:"validation_method,omitempty"`
	ValidationDisposition      string   `json:"validation_disposition,omitempty"`
	ValidationReceipt          string   `json:"validation_receipt,omitempty"`
	PreconditionsProofGaps     string   `json:"preconditions_proof_gaps,omitempty"`
	Counterevidence            string   `json:"counterevidence,omitempty"`
	ValidationRubric           string   `json:"validation_rubric,omitempty"`
	ExploitabilityValidation   string   `json:"exploitability_validation,omitempty"`
	AttackPathCalibration      string   `json:"attack_path_calibration,omitempty"`
	SeverityRationale          string   `json:"severity_rationale,omitempty"`
	ClosureStatus              string   `json:"closure_status,omitempty"`
	PromotionBlockers          []string `json:"promotion_blockers,omitempty"`
	StaticEvidenceOnlyReminder string   `json:"static_evidence_only_reminder"`
}

type sastValidationRow struct {
	FindingID             string                `json:"finding_id"`
	Title                 string                `json:"title"`
	Severity              string                `json:"severity"`
	CWE                   string                `json:"cwe,omitempty"`
	Confidence            string                `json:"confidence,omitempty"`
	Priority              int                   `json:"priority"`
	Status                string                `json:"status"`
	ValidationDisposition string                `json:"validation_disposition,omitempty"`
	ClosureStatus         string                `json:"closure_status,omitempty"`
	PromotionBlockers     []string              `json:"promotion_blockers,omitempty"`
	OWASPCWE              string                `json:"owasp_cwe,omitempty"`
	Source                string                `json:"source,omitempty"`
	Sink                  string                `json:"sink,omitempty"`
	ControlEvidence       string                `json:"control_evidence,omitempty"`
	Exposure              string                `json:"exposure,omitempty"`
	AuthEvidence          string                `json:"auth_evidence,omitempty"`
	Counterevidence       string                `json:"counterevidence,omitempty"`
	ValidationRubric      string                `json:"validation_rubric,omitempty"`
	DataflowConfidence    string                `json:"dataflow_confidence,omitempty"`
	HasValidationEnvelope bool                  `json:"has_validation_envelope"`
	Validation            *sastValidationDetail `json:"validation,omitempty"`
}

type runtimeVerificationPlan struct {
	FindingID             string   `json:"finding_id"`
	Title                 string   `json:"title"`
	CWE                   string   `json:"cwe,omitempty"`
	OWASP                 string   `json:"owasp,omitempty"`
	ValidationDisposition string   `json:"validation_disposition,omitempty"`
	ExecutionAllowed      bool     `json:"execution_allowed"`
	VerifierKind          string   `json:"verifier_kind"`
	RiskClass             string   `json:"risk_class"`
	TargetHint            string   `json:"target_hint,omitempty"`
	Source                string   `json:"source,omitempty"`
	Sink                  string   `json:"sink,omitempty"`
	DataflowConfidence    string   `json:"dataflow_confidence,omitempty"`
	Prerequisites         []string `json:"prerequisites"`
	SafeProbeStrategy     []string `json:"safe_probe_strategy"`
	EvidenceRequired      []string `json:"evidence_required"`
	StopConditions        []string `json:"stop_conditions"`
	PromotionGate         string   `json:"promotion_gate"`
	ArchitectureGuard     string   `json:"architecture_guard"`
	Note                  string   `json:"note"`
}

func (c *Catalog) listFindings(ctx context.Context, sess agent.Session) (Result, error) {
	fs, err := c.findings.ListByEngagement(ctx, sess.EngagementID)
	if err != nil {
		return Result{}, fmt.Errorf("list findings: %w", err)
	}
	views := make([]findingView, 0, min(len(fs), maxRows))
	for i, f := range fs {
		if i >= maxRows {
			break
		}
		views = append(views, findingView{
			ID: f.ID.String(), Title: f.Title, Severity: string(f.Severity), Kind: string(f.Kind),
			Status: string(f.Status), Priority: f.Priority, KEV: f.KEV, RiskScore: f.RiskScore,
		})
	}
	payload, err := json.Marshal(map[string]any{"findings": views, "total": len(fs), "truncated": len(fs) > maxRows})
	if err != nil {
		return Result{}, fmt.Errorf("marshal findings: %w", err)
	}
	if err := c.auditRead(ctx, sess, "agent.read.findings", sess.EngagementID.String(), len(views)); err != nil {
		return Result{}, err
	}
	return Result{Data: payload}, nil
}

// reachabilityView is the dependency-graph FACTS the reachability_context tool returns –
// context for the model to reason about T0/T1 reachability, NOT a verdict. The agent forms a
// ReachabilityClaim and proposes it; a human verifies. Source call-path is out of
// scope here – the scanned source is not retained after a scan.
func (c *Catalog) listSASTValidation(ctx context.Context, sess agent.Session) (Result, error) {
	fs, err := c.findings.ListByEngagement(ctx, sess.EngagementID)
	if err != nil {
		return Result{}, fmt.Errorf("list findings: %w", err)
	}
	rows := make([]sastValidationRow, 0)
	totalSAST := 0
	for _, f := range fs {
		desc := redact.String(strings.TrimSpace(f.Description), nil)
		validation := parseSASTValidationEnvelope(desc)
		if f.Kind != finding.KindSAST && validation == nil {
			continue
		}
		totalSAST++
		if len(rows) >= maxRows {
			continue
		}
		row := sastValidationRow{
			FindingID:             f.ID.String(),
			Title:                 f.Title,
			Severity:              string(f.Severity),
			CWE:                   f.CWE,
			Confidence:            f.Confidence,
			Priority:              f.Priority,
			Status:                string(f.Status),
			HasValidationEnvelope: validation != nil,
			Validation:            validation,
		}
		if validation != nil {
			row.ValidationDisposition = validation.ValidationDisposition
			row.ClosureStatus = validation.ClosureStatus
			row.PromotionBlockers = validation.PromotionBlockers
			row.OWASPCWE = validation.OWASPCWE
			row.Source = validation.Source
			row.Sink = validation.Sink
			row.ControlEvidence = validation.ControlEvidence
			row.Exposure = validation.Exposure
			row.AuthEvidence = validation.AuthEvidence
			row.Counterevidence = validation.Counterevidence
			row.ValidationRubric = validation.ValidationRubric
			row.DataflowConfidence = validation.DataflowConfidence
		}
		rows = append(rows, row)
	}
	payload, err := json.Marshal(map[string]any{
		"sast_validation": rows,
		"total":           totalSAST,
		"truncated":       totalSAST > len(rows),
		"note":            "read-only SAST validation closure table; static evidence only, not runtime exploit proof",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal sast validation: %w", err)
	}
	if err := c.auditRead(ctx, sess, "agent.read.sast_validation", sess.EngagementID.String(), len(rows)); err != nil {
		return Result{}, err
	}
	return Result{Data: payload}, nil
}

func (c *Catalog) planRuntimeVerification(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var args struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("%w: invalid plan_runtime_verification arguments", shared.ErrValidation)
	}
	fid := strings.TrimSpace(args.FindingID)
	if fid == "" {
		return Result{}, fmt.Errorf("%w: finding_id is required", shared.ErrValidation)
	}
	fs, err := c.findings.ListByEngagement(ctx, sess.EngagementID)
	if err != nil {
		return Result{}, fmt.Errorf("list findings: %w", err)
	}
	var f *finding.Finding
	for i := range fs {
		if fs[i].ID.String() == fid {
			f = &fs[i]
			break
		}
	}
	if f == nil {
		payload, err := json.Marshal(map[string]any{
			"found": false,
			"note":  "finding not found in the current engagement; no target or scope data was disclosed",
		})
		if err != nil {
			return Result{}, fmt.Errorf("marshal runtime verification plan: %w", err)
		}
		if err := c.auditRead(ctx, sess, "agent.read.runtime_verification_plan", fid, 0); err != nil {
			return Result{}, err
		}
		return Result{Data: payload}, nil
	}
	desc := redact.String(strings.TrimSpace(f.Description), nil)
	validation := parseSASTValidationEnvelope(desc)
	if f.Kind != finding.KindSAST && validation == nil {
		return Result{}, fmt.Errorf("%w: runtime verification plans require a SAST validation envelope", shared.ErrValidation)
	}
	plan := buildRuntimeVerificationPlan(f, validation)
	payload, err := json.Marshal(map[string]any{
		"found":                     true,
		"runtime_verification_plan": plan,
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal runtime verification plan: %w", err)
	}
	if err := c.auditRead(ctx, sess, "agent.read.runtime_verification_plan", fid, 1); err != nil {
		return Result{}, err
	}
	return Result{Data: payload}, nil
}

func buildRuntimeVerificationPlan(f *finding.Finding, validation *sastValidationDetail) runtimeVerificationPlan {
	cwe := strings.TrimSpace(f.CWE)
	if cwe == "" && validation != nil {
		cwe = cweFromOWASPCWE(validation.OWASPCWE)
	}
	owasp := ""
	if validation != nil {
		owasp, _, _ = strings.Cut(validation.OWASPCWE, "/")
		owasp = strings.TrimSpace(owasp)
	}
	plan := runtimeVerificationPlan{
		FindingID:         f.ID.String(),
		Title:             f.Title,
		CWE:               cwe,
		OWASP:             owasp,
		ExecutionAllowed:  false,
		VerifierKind:      "manual-or-server-side-verifier-plan",
		RiskClass:         "active",
		PromotionGate:     "Any runtime claim must be produced by a scoped verifier run or distinct human verifier, sealed as evidence, then pass the existing evidence/judgment gate; the agent cannot execute or confirm it.",
		ArchitectureGuard: "Read-only planning only: no network request, payload execution, scope expansion, credential use, or evidence-score mutation is performed by this tool.",
		Note:              "Use this as a DAST/verifier checklist, not as permission to run it.",
		Prerequisites: []string{
			"engagement target must already be in scope",
			"authorization window must be open at execution time",
			"operator approval is required before any active or intrusive probe",
			"verifier output must be treated as untrusted data and sealed into the evidence chain",
		},
		StopConditions: []string{
			"target is out of scope or scope cannot be resolved server-side",
			"authorization window is closed or approval is absent",
			"probe would mutate production data, access third-party systems, or use credentials not explicitly authorized",
			"unexpected sensitive data appears in output; stop and seal minimal metadata only",
		},
	}
	if validation != nil {
		plan.ValidationDisposition = validation.ValidationDisposition
		plan.TargetHint = validation.EntryPoint
		plan.Source = validation.Source
		plan.Sink = validation.Sink
		plan.DataflowConfidence = validation.DataflowConfidence
	}
	plan.SafeProbeStrategy, plan.EvidenceRequired, plan.RiskClass = verifierRecipeForCWE(cwe, plan.RiskClass)
	if plan.ValidationDisposition == "false-positive-static" {
		plan.SafeProbeStrategy = []string{"do not run runtime verification unless a human reopens the candidate with new evidence"}
		plan.EvidenceRequired = []string{"static false-positive rationale and reviewer acknowledgement if reopened"}
		plan.RiskClass = "read-only-review"
	}
	return plan
}

func cweFromOWASPCWE(s string) string {
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == ',' || r == ';' || r == ' ' }) {
		if strings.HasPrefix(strings.ToUpper(part), "CWE-") {
			return strings.ToUpper(part)
		}
	}
	return ""
}

func verifierRecipeForCWE(cwe, fallbackRisk string) (strategy, evidence []string, risk string) {
	risk = fallbackRisk
	switch cwe {
	case "CWE-89":
		return []string{
				"reconstruct only the affected route and parameter from the SAST envelope; do not infer new targets",
				"use non-destructive SQLi probes against a disposable/staging dataset or an operator-approved canary record",
				"compare baseline vs probe response shape, status, timing, and server-side error evidence without dumping table data",
				"prefer a parameterization/blocked-control proof over extracting data",
			}, []string{
				"baseline request/response metadata",
				"probe request/response metadata with sensitive values redacted",
				"database/error/timing signal sufficient to distinguish parameterized vs injectable behavior",
				"verifier verdict explaining why the proof is or is not exploitable",
			}, "active"
	case "CWE-79":
		return []string{
				"probe with a harmless unique marker first; only test script execution in an isolated browser profile",
				"capture rendered DOM and execution/no-execution signal; do not steal cookies, tokens, or user data",
				"check framework escaping and CSP as counterevidence before promotion",
			}, []string{
				"baseline rendered response or DOM snapshot metadata",
				"marker reflection/rendering evidence",
				"isolated-browser execution signal or clear counterevidence",
				"CSP/escaping observations and verifier verdict",
			}, "active"
	case "CWE-918":
		return []string{
				"use only an operator-controlled callback/canary endpoint; do not probe cloud metadata or private networks by default",
				"verify whether the server performs the outbound request and whether redirects/private-IP blocking exists",
				"stop at canary reachability; do not pivot to internal service enumeration",
			}, []string{
				"baseline application request metadata",
				"operator-controlled callback hit metadata",
				"redirect/private-network guard observations",
				"verifier verdict on impact and reachable boundary",
			}, "active"
	case "CWE-22":
		return []string{
				"use an approved canary file inside a verifier fixture or disposable staging filesystem",
				"attempt traversal only toward the canary path; do not read OS secrets such as /etc/passwd or production config",
				"record normalization/base-directory controls as counterevidence",
			}, []string{
				"baseline file request metadata",
				"canary-file read/no-read result with content hash only",
				"path normalization/base-directory evidence",
				"verifier verdict on file boundary impact",
			}, "active"
	case "CWE-78":
		return []string{
				"default to staging/sandbox only; production command-injection proof is intrusive",
				"use a harmless canary command or argument-boundary probe approved by the operator",
				"prove argument injection vs shell execution without destructive commands, persistence, or outbound callbacks unless explicitly authorized",
			}, []string{
				"baseline request/response metadata",
				"approved canary command signal or safe argument-boundary evidence",
				"execution context and sandbox/staging confirmation",
				"verifier verdict on command execution impact",
			}, "intrusive"
	default:
		return []string{
				"derive the minimal proof from the SAST source/sink/control envelope",
				"use a non-destructive canary and capture only metadata needed to accept or refute exploitability",
				"prefer counterevidence and safe negative proof over impact escalation",
			}, []string{
				"baseline observation",
				"safe canary probe observation",
				"counterevidence review",
				"distinct verifier verdict",
			}, risk
	}
}

func (c *Catalog) getFindingDetail(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var args struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("%w: invalid get_finding_detail arguments", shared.ErrValidation)
	}
	fid := strings.TrimSpace(args.FindingID)
	if fid == "" {
		return Result{}, fmt.Errorf("%w: finding_id is required", shared.ErrValidation)
	}
	fs, err := c.findings.ListByEngagement(ctx, sess.EngagementID)
	if err != nil {
		return Result{}, fmt.Errorf("list findings: %w", err)
	}
	for i := range fs {
		f := fs[i]
		if f.ID.String() != fid {
			continue
		}
		desc := redact.String(strings.TrimSpace(f.Description), nil)
		sastValidation := parseSASTValidationEnvelope(desc)
		view := findingDetailView{
			ID:              f.ID.String(),
			Title:           f.Title,
			Description:     desc,
			Severity:        string(f.Severity),
			CWE:             f.CWE,
			Kind:            string(f.Kind),
			Class:           string(f.Class),
			Scope:           string(f.Scope),
			Status:          string(f.Status),
			Priority:        f.Priority,
			KEV:             f.KEV,
			RiskScore:       f.RiskScore,
			Sources:         f.Sources,
			Confidence:      f.Confidence,
			Reachability:    string(f.Reachability),
			Impact:          string(f.Impact),
			EvidenceScore:   f.EvidenceScore,
			EvidenceCount:   c.countEvidence(ctx, sess.EngagementID, f.ID),
			Publishable:     f.CanPromote(),
			RequiresGate:    f.RequiresEvidenceGate(),
			DedupKey:        f.DedupKey,
			HasSASTEnvelope: sastValidation != nil,
			SASTValidation:  sastValidation,
			Note:            "read-only bounded finding detail; raw source and evidence content are not returned",
		}
		payload, err := json.Marshal(view)
		if err != nil {
			return Result{}, fmt.Errorf("marshal finding detail: %w", err)
		}
		if err := c.auditRead(ctx, sess, "agent.read.finding_detail", fid, 1); err != nil {
			return Result{}, err
		}
		return Result{Data: payload}, nil
	}
	payload, err := json.Marshal(map[string]any{
		"finding_id": fid,
		"found":      false,
		"note":       "finding not found in this agent session engagement",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal finding detail miss: %w", err)
	}
	if err := c.auditRead(ctx, sess, "agent.read.finding_detail", fid, 0); err != nil {
		return Result{}, err
	}
	return Result{Data: payload}, nil
}

func parseSASTValidationEnvelope(desc string) *sastValidationDetail {
	const marker = "AppSec validation envelope:"
	idx := strings.Index(desc, marker)
	if idx < 0 {
		return nil
	}
	fields := map[string]string{}
	for _, line := range strings.Split(desc[idx+len(marker):], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- ") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(line, "- "))
		k, v, ok := strings.Cut(body, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		fields[key] = strings.TrimSpace(v)
	}
	if len(fields) == 0 {
		return &sastValidationDetail{StaticEvidenceOnlyReminder: staticSASTReminder()}
	}
	d := &sastValidationDetail{
		OWASPCWE:                   fields["owasp/cwe mapping"],
		EntryPoint:                 fields["entrypoint/control"],
		Source:                     fields["source"],
		SourceEvidence:             fields["source evidence"],
		Sink:                       fields["sink/control"],
		SinkEvidence:               fields["sink evidence"],
		ControlEvidence:            fields["control evidence"],
		RouteMiddleware:            fields["route middleware"],
		AuthEvidence:               fields["auth evidence"],
		Exposure:                   fields["exposure"],
		TrustBoundary:              fields["trust boundary"],
		ImpactHypothesis:           fields["impact hypothesis"],
		RouteReachability:          fields["route reachability"],
		AuthRoleContext:            fields["auth/role context"],
		Dataflow:                   fields["dataflow"],
		DataflowEvidence:           fields["dataflow evidence"],
		DataflowConfidence:         fields["dataflow confidence"],
		ValidationReceipt:          fields["validation receipt"],
		PreconditionsProofGaps:     fields["preconditions/proof gaps"],
		Counterevidence:            fields["counterevidence"],
		ValidationRubric:           fields["validation rubric"],
		ExploitabilityValidation:   fields["exploitability validation"],
		AttackPathCalibration:      fields["attack-path calibration"],
		SeverityRationale:          fields["severity rationale"],
		StaticEvidenceOnlyReminder: staticSASTReminder(),
	}
	d.ValidationMethod, d.ValidationDisposition = splitValidationReceipt(d.ValidationReceipt)
	d.ClosureStatus = closureStatus(d.ValidationDisposition)
	d.PromotionBlockers = promotionBlockers(d)
	return d
}

func splitValidationReceipt(receipt string) (method, disposition string) {
	left, right, ok := strings.Cut(receipt, "/")
	if !ok {
		return strings.TrimSpace(receipt), ""
	}
	return strings.TrimSpace(left), strings.TrimSpace(right)
}

func closureStatus(disposition string) string {
	switch strings.TrimSpace(disposition) {
	case "reportable-static-candidate":
		return "static_candidate_survives_code_understanding"
	case "deferred-proof-gap":
		return "deferred_until_proof_gap_closed"
	case "needs-review-counterevidence":
		return "deferred_until_counterevidence_reviewed"
	case "needs-runtime-proof":
		return "deferred_until_runtime_verifier_evidence"
	case "false-positive-static":
		return "closed_false_positive_static"
	case "":
		return "unknown"
	default:
		return "needs_human_review"
	}
}

func promotionBlockers(d *sastValidationDetail) []string {
	var out []string
	switch d.ValidationDisposition {
	case "deferred-proof-gap":
		if d.DataflowConfidence == "context-only" || d.DataflowConfidence == "missing" {
			out = append(out, "source-to-sink value flow is not proven beyond bounded-context proximity")
		}
		if d.PreconditionsProofGaps != "" {
			out = append(out, d.PreconditionsProofGaps)
		}
		if len(out) == 0 {
			out = append(out, "static proof gap remains")
		}
	case "needs-review-counterevidence":
		if d.DataflowConfidence == "sanitized" {
			out = append(out, "sanitizer/validator cue appears on the source-to-sink path and needs verifier review")
		}
		if d.DataflowConfidence == "guarded" {
			out = append(out, "guard/allowlist cue appears before the sink and needs verifier review")
		}
		if d.Counterevidence != "" && d.Counterevidence != "none observed in bounded local context" {
			out = append(out, d.Counterevidence)
		}
		if len(out) == 0 {
			out = append(out, "counterevidence review required")
		}
	case "needs-runtime-proof":
		out = append(out, "static source-to-sink evidence exists, but exploitability needs a safe runtime verifier or sealed distinct-verifier acceptance")
	case "false-positive-static":
		if d.Counterevidence != "" && d.Counterevidence != "none observed in bounded local context" {
			out = append(out, "static false positive: "+d.Counterevidence)
		} else {
			out = append(out, "static analyzer observed enough counter-pattern evidence to close this as a false positive")
		}
	}
	if d.ValidationDisposition != "false-positive-static" {
		out = append(out, "runtime exploitability still requires separate sealed evidence or distinct verifier acceptance")
	}
	return out
}

func staticSASTReminder() string {
	return "SAST validation is bounded static evidence only; do not treat it as runtime DAST proof."
}

type reachabilityView struct {
	Component         string   `json:"component"`
	Version           string   `json:"version,omitempty"`
	PresentInSBOM     bool     `json:"present_in_sbom"`
	InDependencyGraph bool     `json:"in_dependency_graph"`
	Direct            bool     `json:"direct"`
	Depth             int      `json:"depth"`
	Path              []string `json:"path,omitempty"`
	Scope             string   `json:"scope,omitempty"`
	BackgroundScope   bool     `json:"background_scope"`
	Location          string   `json:"location,omitempty"`
	FirstParty        bool     `json:"first_party"`
	AffectedSymbols   []string `json:"affected_symbols,omitempty"`
	SuggestedTier     string   `json:"suggested_tier"`
	Note              string   `json:"note"`
}

// scanResultView is the minimal projection of the persisted sca scan result the reachability tool
// decodes – only the SBOM, so the catalog depends on the domain types, not the sca use case.
type scanResultView struct {
	SBOM            *sbom.SBOM                    `json:"sbom"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulnerabilities"`
}

// reachabilityContext returns dependency-graph FACTS for a vulnerable package so the model
// can reason about whether the vulnerability is actually reachable. Read-only + session-locked (the
// engagement is the session's, never an argument) + audited. It forms NO verdict; the vulnerability/
// score is moved only by the propose→verify lifecycle.
func (c *Catalog) reachabilityContext(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var args struct {
		Component string `json:"component"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("%w: invalid reachability_context arguments", shared.ErrValidation)
	}
	component, version := strings.TrimSpace(args.Component), strings.TrimSpace(args.Version)
	if component == "" {
		return Result{}, fmt.Errorf("%w: component is required", shared.ErrValidation)
	}
	view := reachabilityView{
		Component:     component,
		Version:       version,
		SuggestedTier: string(judgment.Tier0),
		Note:          "Dependency-graph facts only (T0/T1); source call-path is not available post-scan. Reason about reachability, then propose a ReachabilityClaim for a human to verify.",
	}
	if blob, err := c.reach.LatestResult(ctx, sess.EngagementID); err == nil && len(blob) > 0 {
		var sr scanResultView
		if json.Unmarshal(blob, &sr) == nil {
			if sr.SBOM != nil {
				fillReachability(&view, sr.SBOM, component, version)
			}
			view.AffectedSymbols = affectedSymbolsFor(sr.Vulnerabilities, component, version)
		}
	}
	payload, err := json.Marshal(view)
	if err != nil {
		return Result{}, fmt.Errorf("marshal reachability context: %w", err)
	}
	if err := c.auditRead(ctx, sess, "agent.read.reachability", component, 1); err != nil {
		return Result{}, err
	}
	return Result{Data: payload}, nil
}

// maxReachStr bounds any single SBOM-sourced string reflected into the (untrusted) LLM transcript,
// and maxReachPathElems bounds the reflected dep-path depth – the scanned artifact is
// attacker-influenceable, so a hostile component name/location/PURL cannot bloat or smuggle into the
// transcript (defense-in-depth; read-tool data is fed back un-capped by the orchestrator).
const (
	maxReachStr       = 200
	maxReachPathElems = 64
)

func clampStr(s string) string {
	if len(s) > maxReachStr {
		return s[:maxReachStr] + "…"
	}
	return s
}

// fillReachability populates the dep-graph facts for component[@version] from the SBOM. Absence from
// the SBOM is itself a strong not-reachable signal. When version is empty the FIRST
// name-match wins (a multi-version graph should pass the exact version to disambiguate).
func fillReachability(v *reachabilityView, doc *sbom.SBOM, component, version string) {
	var comp *sbom.Component
	for i := range doc.Components {
		if doc.Components[i].Name == component && (version == "" || doc.Components[i].Version == version) {
			comp = &doc.Components[i]
			break
		}
	}
	if comp == nil {
		v.Note = "Package not found in the engagement's SBOM – it is not in the resolved dependency graph (a strong signal it is not reachable). " + v.Note
		return
	}
	v.PresentInSBOM = true
	v.Version = clampStr(comp.Version)
	v.Scope = comp.Scope // closed vocab from sbom.ClassifyScope – bounded, no clamp needed
	v.BackgroundScope = sbom.IsBackgroundScope(comp.Scope)
	if comp.Location != "" {
		v.Location = clampStr(filepath.Base(comp.Location)) // basename only (data-minimization) + bounded
	}
	v.FirstParty = comp.FirstParty
	path := sbom.PathToRoot(doc.Dependencies, sbom.ComponentID(comp.Name, comp.Version, comp.PURL))
	v.Depth = len(path) // true depth, even if the reflected Path below is capped
	v.InDependencyGraph = len(path) > 0
	v.Direct = len(path) > 0 && len(path) <= 2
	for i, p := range path { // reflect a BOUNDED copy (each element clamped, depth capped)
		if i >= maxReachPathElems {
			v.Path = append(v.Path, "…")
			break
		}
		v.Path = append(v.Path, clampStr(p))
	}
	if v.Direct {
		v.SuggestedTier = string(judgment.Tier1)
	}
}

// affectedSymbolsFor unions the advisory-provided affected symbols of the matching
// component's vulnerabilities, bounded for the transcript. Helps the agent reason about whether the
// vulnerable symbols are actually called.
func affectedSymbolsFor(vulns []vulnerability.Vulnerability, component, version string) []string {
	seen := map[string]bool{}
	var all []string
	for _, vu := range vulns {
		if vu.Component != component || (version != "" && vu.Version != version) {
			continue
		}
		for _, s := range vu.AffectedSymbols {
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			all = append(all, s)
		}
	}
	sort.Strings(all) // sort BEFORE capping so the surviving subset is deterministic (reproducible LLM input)
	out := make([]string, 0, min(len(all), maxReachPathElems))
	for _, s := range all {
		if len(out) >= maxReachPathElems {
			break
		}
		out = append(out, clampStr(s))
	}
	return out
}

// --- propose tool: the agent records a reachability Judgment at score 0 ---

type proposeReachabilityArgs struct {
	SubjectID  string   `json:"subject_id"`
	Reachable  string   `json:"reachable"`
	Tier       string   `json:"tier"`
	Path       []string `json:"path"`
	Confidence int      `json:"confidence"`
}

// proposeReachability records a PROPOSED reachability judgment (score 0) for a finding. The agent
// forms the verdict from reachability_context facts; the domain validates the typed claim (fail-closed
// vocab) and the analysis service persists at score 0 + audits. The agent CANNOT confirm it – a
// distinct human verifies via PermReview (R11); the propose-only interface + the arch tripwire make
// that structural.
func (c *Catalog) proposeReachability(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposeReachabilityArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_reachability args: %w", shared.ErrValidation, err)
	}
	subjectID := strings.TrimSpace(a.SubjectID)
	if subjectID == "" {
		return Result{}, fmt.Errorf("%w: subject_id is required", shared.ErrValidation)
	}
	claim := judgment.ReachabilityClaim{
		Reachable:  judgment.ReachabilityState(strings.TrimSpace(a.Reachable)),
		Tier:       judgment.ReachabilityTier(strings.TrimSpace(a.Tier)),
		Path:       a.Path,
		Confidence: a.Confidence,
	}
	j, err := c.jproposer.Propose(ctx, sess.AgentActor(), sess.EngagementID, judgment.CapReachability, judgment.SubjectFinding, shared.ID(subjectID), claim)
	if err != nil {
		return Result{}, err // domain validates the claim; the service persists at score 0 + audits
	}
	payload, err := json.Marshal(map[string]any{
		"judgment_id": j.ID.String(), "state": string(j.State), "evidence_score": j.EvidenceScore,
		"proposed_by": j.ProposedBy, "publishable": j.Publishable(),
		"note": "recorded as a PROPOSED reachability judgment (score 0); a distinct human reviewer must verify it – you cannot confirm your own.",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal judgment: %w", err)
	}
	return Result{Data: payload}, nil
}

type proposeThreatArgs struct {
	ElementKind string `json:"element_kind"`
	ElementID   string `json:"element_id"`
	Category    string `json:"category"`
	Asset       string `json:"asset"`
}

// proposeThreat records a PROPOSED STRIDE threat (score 0) over the architecture model. The agent
// picks a STRIDE category + the threatened model element (a component or a boundary-crossing data flow); the
// domain validates the typed claim (closed STRIDE vocab) and the analysis service persists at score 0 +
// audits. The threat is GATED + human-ratified – the agent CANNOT confirm it (the propose-only interface +
// the arch tripwire make that structural).
func (c *Catalog) proposeThreat(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposeThreatArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_threat args: %w", shared.ErrValidation, err)
	}
	elementID := strings.TrimSpace(a.ElementID)
	if elementID == "" {
		return Result{}, fmt.Errorf("%w: element_id is required", shared.ErrValidation)
	}
	var subjectKind judgment.SubjectKind
	switch strings.TrimSpace(a.ElementKind) {
	case "component":
		subjectKind = judgment.SubjectComponent
	case "data_flow":
		subjectKind = judgment.SubjectDataFlow
	default:
		return Result{}, fmt.Errorf("%w: element_kind must be component|data_flow, got %q", shared.ErrValidation, a.ElementKind)
	}
	claim := judgment.ThreatClaim{
		Category: judgment.StrideCategory(strings.TrimSpace(a.Category)),
		Asset:    strings.TrimSpace(a.Asset),
	}
	j, err := c.jproposer.Propose(ctx, sess.AgentActor(), sess.EngagementID, judgment.CapThreat, subjectKind, shared.ID(elementID), claim)
	if err != nil {
		return Result{}, err // domain validates the claim; the service persists at score 0 + audits
	}
	payload, err := json.Marshal(map[string]any{
		"judgment_id": j.ID.String(), "state": string(j.State), "evidence_score": j.EvidenceScore,
		"proposed_by": j.ProposedBy, "publishable": j.Publishable(),
		"note": "recorded as a PROPOSED STRIDE threat (score 0); a distinct human reviewer must ratify it – you cannot confirm your own.",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal judgment: %w", err)
	}
	return Result{Data: payload}, nil
}

type proposeVexJustificationArgs struct {
	FindingID     string `json:"finding_id"`
	Justification string `json:"justification"`
}

// proposeVexJustification records a PROPOSED OpenVEX justification for why a finding is not_affected:
// the agent picks ONE of the closed OpenVEX justifications and the analysis service persists it at score 0 +
// audits. GATED + human-ratified – the agent CANNOT confirm it (the propose-only interface + the arch tripwire
// make that structural); a confirmed claim later refines the OpenVEX export. The justification is a closed
// enum (the domain VexJustificationClaim.Validate rejects anything else) – never free prose. The finding is
// ALWAYS the session's engagement scope; the engagement id is never read from the call.
func (c *Catalog) proposeVexJustification(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposeVexJustificationArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_vex_justification args: %w", shared.ErrValidation, err)
	}
	findingID := strings.TrimSpace(a.FindingID)
	if findingID == "" {
		return Result{}, fmt.Errorf("%w: finding_id is required", shared.ErrValidation)
	}
	claim := judgment.VexJustificationClaim{Justification: vex.OpenVexJustification(strings.TrimSpace(a.Justification))}
	j, err := c.jproposer.Propose(ctx, sess.AgentActor(), sess.EngagementID, judgment.CapVexJustification, judgment.SubjectFinding, shared.ID(findingID), claim)
	if err != nil {
		return Result{}, err // domain validates the closed-enum claim; the service persists at score 0 + audits
	}
	payload, err := json.Marshal(map[string]any{
		"judgment_id": j.ID.String(), "state": string(j.State), "evidence_score": j.EvidenceScore,
		"proposed_by": j.ProposedBy, "publishable": j.Publishable(),
		"note": "recorded as a PROPOSED OpenVEX justification (score 0); a distinct human reviewer must ratify it before any export trusts it – you cannot confirm your own.",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal judgment: %w", err)
	}
	return Result{Data: payload}, nil
}

type proposeWriteupDraftArgs struct {
	FindingID   string `json:"finding_id"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// proposeWriteupDraft records a PROPOSED finding write-up draft: the agent drafts the finding's
// description + remediation PROSE, scrubbed of URL credentials (mirroring propose_finding) and bounded
// by the domain. The draft is inert – a distinct human must edit/accept it (the proposer cannot sign off its
// own draft) and it never auto-renders. The finding is ALWAYS the agent's session engagement
// scope; only the finding id comes from the call, never a cross-engagement reference.
func (c *Catalog) proposeWriteupDraft(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposeWriteupDraftArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_writeup_draft args: %w", shared.ErrValidation, err)
	}
	findingID := strings.TrimSpace(a.FindingID)
	if findingID == "" {
		return Result{}, fmt.Errorf("%w: finding_id is required", shared.ErrValidation)
	}
	description := redact.String(strings.TrimSpace(a.Description), nil)
	remediation := redact.String(strings.TrimSpace(a.Remediation), nil)
	d, err := c.drafter.Propose(ctx, sess.AgentActor(), sess.EngagementID, shared.ID(findingID), description, remediation)
	if err != nil {
		return Result{}, err // domain validates (>=1 non-empty + bounds); the service persists + audits
	}
	payload, err := json.Marshal(map[string]any{
		"draft_id": d.ID.String(), "state": string(d.State), "finding_id": d.FindingID.String(),
		"proposed_by": d.ProposedBy,
		"note":        "recorded as a PROPOSED writeup draft awaiting human sign-off – it is not applied to the finding or rendered, and you cannot accept your own draft.",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal writeup draft: %w", err)
	}
	return Result{Data: payload}, nil
}

type proposeSASTValidationArgs struct {
	FindingID string `json:"finding_id"`
	CWE       string `json:"cwe"`
	Location  string `json:"location"`
	Rule      string `json:"rule"`
}

// proposeSASTValidation records a gated CapSAST judgment at score 0 for an existing SAST
// finding. It is the custody-friendly handoff between static triage / verifier planning and a
// later distinct verifier verdict. It does NOT execute DAST or mutate the finding's score.
func (c *Catalog) proposeSASTValidation(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposeSASTValidationArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_sast_validation args: %w", shared.ErrValidation, err)
	}
	fid := strings.TrimSpace(a.FindingID)
	if fid == "" {
		return Result{}, fmt.Errorf("%w: finding_id is required", shared.ErrValidation)
	}
	if !c.findingExists(ctx, sess.EngagementID, shared.ID(fid), finding.KindSAST) {
		return Result{}, fmt.Errorf("%w: finding_id must reference an existing SAST finding in this engagement", shared.ErrValidation)
	}
	claim := judgment.SASTClaim{
		CWE:      strings.TrimSpace(a.CWE),
		Location: strings.TrimSpace(a.Location),
		Rule:     strings.TrimSpace(a.Rule),
	}
	j, err := c.jproposer.Propose(ctx, sess.AgentActor(), sess.EngagementID, judgment.CapSAST, judgment.SubjectFinding, shared.ID(fid), claim)
	if err != nil {
		return Result{}, err
	}
	payload, err := json.Marshal(map[string]any{
		"judgment_id": j.ID.String(), "state": string(j.State), "evidence_score": j.EvidenceScore,
		"proposed_by": j.ProposedBy, "publishable": j.Publishable(),
		"note": "recorded as a PROPOSED gated SAST validation judgment (score 0); a distinct verifier/human must verify it. This tool executed no DAST probe and cannot raise the evidence score.",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal judgment: %w", err)
	}
	return Result{Data: payload}, nil
}

func (c *Catalog) findingExists(ctx context.Context, engagementID, findingID shared.ID, kind finding.Kind) bool {
	fs, err := c.findings.ListByEngagement(ctx, engagementID)
	if err != nil {
		return false
	}
	for _, f := range fs {
		if f.ID == findingID && (kind == "" || f.Kind == kind) {
			return true
		}
	}
	return false
}

type proposeCritiqueArgs struct {
	SubjectID  string `json:"subject_id"`
	Verdict    string `json:"verdict"`
	Driver     string `json:"driver"`
	Confidence int    `json:"confidence"`
}

// proposeCritique records a PROPOSED adversarial critique (score 0) against a finding. The
// agent tries to REFUTE the finding; the domain validates the typed claim and the analysis service
// persists at score 0 + audits. The agent CANNOT suppress/confirm – a confirmed "refuted" critique
// only flags suspected-FP for a human (the propose-only interface + the arch tripwire are structural).
func (c *Catalog) proposeCritique(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposeCritiqueArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_critique args: %w", shared.ErrValidation, err)
	}
	subjectID := strings.TrimSpace(a.SubjectID)
	if subjectID == "" {
		return Result{}, fmt.Errorf("%w: subject_id is required", shared.ErrValidation)
	}
	claim := judgment.CritiqueClaim{
		Verdict:    judgment.CritiqueVerdict(strings.TrimSpace(a.Verdict)),
		Driver:     strings.TrimSpace(a.Driver),
		Confidence: a.Confidence,
	}
	j, err := c.jproposer.Propose(ctx, sess.AgentActor(), sess.EngagementID, judgment.CapCritique, judgment.SubjectFinding, shared.ID(subjectID), claim)
	if err != nil {
		return Result{}, err // domain validates the claim; the service persists at score 0 + audits
	}
	payload, err := json.Marshal(map[string]any{
		"judgment_id": j.ID.String(), "state": string(j.State), "evidence_score": j.EvidenceScore,
		"proposed_by": j.ProposedBy, "publishable": j.Publishable(),
		"note": "recorded as a PROPOSED critique (score 0); a distinct human reviewer verifies it. A confirmed refutation only FLAGS the finding as suspected-FP – it never suppresses it.",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal judgment: %w", err)
	}
	return Result{Data: payload}, nil
}

type proposeRiskNarrativeArgs struct {
	SubjectID string   `json:"subject_id"`
	Drivers   []string `json:"drivers"`
	Priority  int      `json:"priority"`
}

// proposeRiskNarrative records a PROPOSED risk-narrative judgment: the agent explains a
// finding's computed priority via STRUCTURED driver tokens (never prose, R8). It is DESCRIPTIVE +
// UNGATED – a human ACCEPTS it (there is nothing to "refute at 75"); the agent sets no score, and
// the domain rejects any free-text driver.
func (c *Catalog) proposeRiskNarrative(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposeRiskNarrativeArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_risk_narrative args: %w", shared.ErrValidation, err)
	}
	subjectID := strings.TrimSpace(a.SubjectID)
	if subjectID == "" {
		return Result{}, fmt.Errorf("%w: subject_id is required", shared.ErrValidation)
	}
	claim := judgment.RiskNarrativeClaim{Drivers: a.Drivers, Priority: a.Priority}
	j, err := c.jproposer.Propose(ctx, sess.AgentActor(), sess.EngagementID, judgment.CapRiskNarrative, judgment.SubjectFinding, shared.ID(subjectID), claim)
	if err != nil {
		return Result{}, err // domain validates the driver tokens + priority; the service persists at score 0 + audits
	}
	payload, err := json.Marshal(map[string]any{
		"judgment_id": j.ID.String(), "state": string(j.State), "evidence_score": j.EvidenceScore,
		"proposed_by": j.ProposedBy, "publishable": j.Publishable(),
		"note": "recorded as a PROPOSED risk narrative (descriptive, ungated); a human ACCEPTS it – there is no score or verifier verdict. Drivers are tokens, never prose.",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal judgment: %w", err)
	}
	return Result{Data: payload}, nil
}

// --- evidence-sufficiency advisor: read-only; proposes what's missing to reach the bar ---

type sufficiencyView struct {
	FindingID     string `json:"finding_id"`
	Found         bool   `json:"found"`
	Kind          string `json:"kind,omitempty"`
	EvidenceScore int    `json:"evidence_score"`
	Bar           int    `json:"bar"`
	Gap           int    `json:"gap"`
	Gated         bool   `json:"gated"`
	Publishable   bool   `json:"publishable"`
	EvidenceCount int    `json:"evidence_count"`
	Advice        string `json:"advice"`
	Note          string `json:"note"`
}

// evidenceSufficiency is a read-only ADVISORY: for a finding, it reports the evidence score vs
// the publishability bar, whether it is gated, its evidence-item count, and a structured advice token
// for what is missing. It sets NO score – only a distinct verifier's sealed verdict moves the score
// . Session-locked + audited.
func (c *Catalog) evidenceSufficiency(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var args struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("%w: invalid evidence_sufficiency arguments", shared.ErrValidation)
	}
	fid := strings.TrimSpace(args.FindingID)
	if fid == "" {
		return Result{}, fmt.Errorf("%w: finding_id is required", shared.ErrValidation)
	}
	fs, err := c.findings.ListByEngagement(ctx, sess.EngagementID)
	if err != nil {
		return Result{}, fmt.Errorf("list findings: %w", err)
	}
	view := sufficiencyView{
		FindingID: fid, Bar: finding.EvidenceThreshold,
		Note: "advisory only – a DISTINCT verifier's sealed verdict moves the score; this tool sets nothing.",
	}
	var f *finding.Finding
	for i := range fs {
		if fs[i].ID.String() == fid {
			f = &fs[i]
			break
		}
	}
	if f == nil {
		view.Advice = "finding_not_found"
	} else {
		view.Found = true
		view.Kind = string(f.Kind)
		view.EvidenceScore = f.EvidenceScore
		view.Gated = f.RequiresEvidenceGate()
		view.Publishable = f.CanPromote()
		view.EvidenceCount = c.countEvidence(ctx, sess.EngagementID, f.ID)
		switch {
		case !view.Gated:
			view.Advice = "ungated_already_publishable" // recon/SCA/manual: no verifier verdict needed
		case view.Publishable:
			view.Advice = "gated_already_meets_bar"
		default:
			if view.Gap = finding.EvidenceThreshold - f.EvidenceScore; view.Gap < 0 {
				view.Gap = 0
			}
			if view.EvidenceCount == 0 {
				view.Advice = "needs_evidence_then_distinct_verifier_verdict"
			} else {
				view.Advice = "needs_distinct_verifier_verdict_at_or_above_bar"
			}
		}
	}
	payload, err := json.Marshal(view)
	if err != nil {
		return Result{}, fmt.Errorf("marshal sufficiency: %w", err)
	}
	if err := c.auditRead(ctx, sess, "agent.read.sufficiency", fid, 1); err != nil {
		return Result{}, err
	}
	return Result{Data: payload}, nil
}

// countEvidence counts evidence items linked to a finding (best-effort; a read error ⇒ 0).
func (c *Catalog) countEvidence(ctx context.Context, engagementID, findingID shared.ID) int {
	evs, err := c.evidences.ListByEngagement(ctx, engagementID)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range evs {
		if e.FindingID == findingID {
			n++
		}
	}
	return n
}

type evidenceView struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	FindingID    string `json:"finding_id,omitempty"`
	Hash         string `json:"hash"`
	PreviousHash string `json:"previous_hash,omitempty"`
	CreatedBy    string `json:"created_by"`
	CreatedAt    string `json:"created_at"`
}

func (c *Catalog) listEvidence(ctx context.Context, sess agent.Session) (Result, error) {
	items, err := c.evidences.ListByEngagement(ctx, sess.EngagementID)
	if err != nil {
		return Result{}, fmt.Errorf("list evidence: %w", err)
	}
	// Metadata only – evidence Content/StorageRef are never surfaced to the model (content
	// may carry secrets or scope-derived data; the storage ref is an internal blob key).
	views := make([]evidenceView, 0, min(len(items), maxRows))
	for i, e := range items {
		if i >= maxRows {
			break
		}
		views = append(views, evidenceView{
			ID: e.ID.String(), Kind: e.Kind, FindingID: e.FindingID.String(), Hash: e.Hash,
			PreviousHash: e.PreviousHash, CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	payload, err := json.Marshal(map[string]any{"evidence": views, "total": len(items), "truncated": len(items) > maxRows})
	if err != nil {
		return Result{}, fmt.Errorf("marshal evidence: %w", err)
	}
	if err := c.auditRead(ctx, sess, "agent.read.evidence", sess.EngagementID.String(), len(views)); err != nil {
		return Result{}, err
	}
	return Result{Data: payload}, nil
}

func (c *Catalog) verifyCustody(ctx context.Context, sess agent.Session) (Result, error) {
	items, err := c.evidences.ListByEngagement(ctx, sess.EngagementID)
	if err != nil {
		return Result{}, fmt.Errorf("list evidence: %w", err)
	}
	verifyErr := evidence.VerifyChain(items)
	out := map[string]any{"ok": verifyErr == nil, "count": len(items)}
	if len(items) > 0 {
		out["head_hash"] = items[len(items)-1].Hash
	}
	if verifyErr != nil {
		out["error"] = verifyErr.Error()
	}
	payload, err := json.Marshal(out)
	if err != nil {
		return Result{}, fmt.Errorf("marshal custody: %w", err)
	}
	if err := c.auditRead(ctx, sess, "agent.read.custody", sess.EngagementID.String(), len(items)); err != nil {
		return Result{}, err
	}
	return Result{Data: payload}, nil
}

type reconToolView struct {
	Name                string   `json:"name"`
	Action              string   `json:"action"`
	AcceptedKinds       []string `json:"accepted_kinds"`
	CapabilitySensitive bool     `json:"capability_sensitive"`
	Risk                string   `json:"risk"`
}

// targetKinds is the full set of target kinds, used to report which kinds each recon tool
// accepts (mirrors the recon use-case's launcher metadata).
var targetKinds = []engagement.TargetKind{
	engagement.TargetDomain, engagement.TargetIP, engagement.TargetCIDR,
	engagement.TargetURL, engagement.TargetRepo, engagement.TargetImage,
}

func (c *Catalog) listReconTools(ctx context.Context, sess agent.Session) (Result, error) {
	views := make([]reconToolView, 0, len(c.reconList))
	for _, t := range c.reconList {
		kinds := make([]string, 0, len(targetKinds))
		for _, k := range targetKinds {
			if t.Accepts(k) {
				kinds = append(kinds, string(k))
			}
		}
		views = append(views, reconToolView{
			Name: t.Name(), Action: t.Action(), AcceptedKinds: kinds,
			CapabilitySensitive: t.CapabilitySensitive(), Risk: string(riskFor(t)),
		})
	}
	payload, err := json.Marshal(map[string]any{"tools": views})
	if err != nil {
		return Result{}, fmt.Errorf("marshal recon tools: %w", err)
	}
	if err := c.auditRead(ctx, sess, "agent.read.recon_tools", sess.EngagementID.String(), len(views)); err != nil {
		return Result{}, err
	}
	return Result{Data: payload}, nil
}

// --- execute tool: propose-only ---

type startReconArgs struct {
	Tool      string `json:"tool"`
	Target    string `json:"target"`
	Rationale string `json:"rationale"`
}

// startRecon builds an approval-required ProposedAction for a recon run. It runs NOTHING: the
// orchestrator must clear the proposal through safety.Gate (scope + authorization window + RoE,
// then HITL) before anything executes. The argv preview is the exact command the gated run
// will use (tool.BuildArgs), so the human approves precisely what runs.
func (c *Catalog) startRecon(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a startReconArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: start_recon args: %w", shared.ErrValidation, err)
	}
	prop, err := c.buildReconProposal(sess, a.Tool, a.Target, a.Rationale, c.ids.NewID())
	if err != nil {
		return Result{}, err
	}
	// Record the proposal (distinct from the guard's later authorize audit at admission).
	if err := c.audit.Record(ctx, ports.AuditEntry{
		Actor:  sess.AgentActor(),
		Action: "agent.propose",
		Target: prop.Target.Value,
		Metadata: map[string]string{
			"tool": a.Tool, "action": prop.Action, "risk": string(prop.Risk),
			"proposed_action_id": prop.ID.String(), "session": sess.ID.String(),
		},
		At: c.clock.Now(),
	}); err != nil {
		return Result{}, fmt.Errorf("audit proposal: %w", err)
	}
	return Result{Proposal: &prop}, nil
}

// buildReconProposal turns (tool, target) into an approval-required ProposedAction with the
// EXACT argv the gated run would use. It runs nothing and audits nothing – the caller owns the
// audit (start_recon audits a single propose; a plan audits once at the plan level). actionID
// is supplied by the caller so a plan node keeps a STABLE id across re-admissions (idempotency).
// This is the single source of truth for target validation + argv building.
func (c *Catalog) buildReconProposal(sess agent.Session, toolName, targetStr, rationale string, actionID shared.ID) (agent.ProposedAction, error) {
	toolName = strings.TrimSpace(toolName)
	targetStr = strings.TrimSpace(targetStr)
	if toolName == "" {
		return agent.ProposedAction{}, fmt.Errorf("%w: a recon step requires a 'tool'", shared.ErrValidation)
	}
	// Own the target-string guard at this layer: reject flag-injection and
	// whitespace BEFORE building any argv, rather than trusting each tool's BuildArgs to.
	if err := engagement.ValidateTargetValue(targetStr); err != nil {
		return agent.ProposedAction{}, err
	}
	tool, ok := c.recon[toolName]
	if !ok {
		return agent.ProposedAction{}, fmt.Errorf("%w: unknown recon tool %q", shared.ErrValidation, toolName)
	}
	target := engagement.Target{Kind: engagement.InferTargetKind(targetStr), Value: targetStr}
	if !tool.Accepts(target.Kind) {
		return agent.ProposedAction{}, fmt.Errorf("%w: %s does not accept %s targets", shared.ErrValidation, toolName, target.Kind)
	}
	spec, err := tool.BuildArgs(target)
	if err != nil {
		return agent.ProposedAction{}, fmt.Errorf("%w: build args for %s: %w", shared.ErrValidation, toolName, err)
	}
	argv := append([]string{spec.Name}, spec.Args...)
	// Defense in depth: a credential placeholder must never ride in the argv preview the
	// orchestrator may surface to the transcript. Recon tools keep secrets in ToolSpec.Env,
	// never Args, so this only trips on a malformed/hostile BuildArgs.
	for _, arg := range argv {
		if strings.Contains(arg, "{{") {
			return agent.ProposedAction{}, fmt.Errorf("%w: argv may not contain a credential placeholder", shared.ErrValidation)
		}
	}
	return agent.ProposedAction{
		ID:            actionID,
		SessionID:     sess.ID,
		EngagementID:  sess.EngagementID, // session-locked; never an LLM-supplied id
		Tool:          ToolStartRecon,
		Action:        tool.Action(),
		Target:        target,
		Argv:          argv,
		EgressPreview: []string{target.Value},
		Risk:          riskFor(tool),
		Rationale:     redact.String(strings.TrimSpace(rationale), nil), // scrub URL creds from LLM prose
		ProposedAt:    c.clock.Now(),
	}, nil
}

// --- finding tool: record an unproven exploitation claim ---

type proposeFindingArgs struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVSSVector  string `json:"cvss_vector"`
	CWE         string `json:"cwe"`
}

// proposeFinding records a SUSPECTED exploitation finding at EvidenceScore 0, attributed to the
// agent. It is NOT a gated tool execution (it touches no target) and confers no power to raise
// the score or confirm – the finding is inert (unreportable, CanPromote=false) until a DISTINCT
// verifier acts out of band. Redaction: title/description are LLM prose → scrubbed before persist.
func (c *Catalog) proposeFinding(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposeFindingArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_finding args: %w", shared.ErrValidation, err)
	}
	sev := shared.Severity(strings.ToLower(strings.TrimSpace(a.Severity)))
	if !sev.Valid() {
		return Result{}, fmt.Errorf("%w: invalid severity %q", shared.ErrValidation, a.Severity)
	}
	in := finding.ExploitationInput{
		Title:       redact.String(strings.TrimSpace(a.Title), nil),
		Description: redact.String(strings.TrimSpace(a.Description), nil),
		Severity:    sev,
		CVSSVector:  strings.TrimSpace(a.CVSSVector),
		CWE:         strings.TrimSpace(a.CWE),
	}
	f, err := c.proposer.Propose(ctx, sess.AgentActor(), sess.EngagementID, in)
	if err != nil {
		return Result{}, err // the service validates + persists at score 0 + audits the proposal
	}
	payload, err := json.Marshal(map[string]any{
		"finding_id": f.ID.String(), "kind": string(f.Kind), "status": string(f.Status),
		"evidence_score": f.EvidenceScore, "proposed_by": f.ProposedBy, "can_promote": f.CanPromote(),
		"note": "recorded as an UNPROVEN claim (score 0); a distinct verifier must verify it before it is reportable",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal finding: %w", err)
	}
	return Result{Data: payload}, nil
}

type proposeAttackChainArgs struct {
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	ConstituentIDs []string `json:"constituent_ids"`
	Severity       string   `json:"severity"`
}

// proposeAttackChain records an attack-chain HYPOTHESIS finding (Kind=hypothesis) at EvidenceScore 0,
// attributed to the agent. The chain narrative (title/description) is LLM prose → scrubbed before persist
// (GR3, like propose_finding). It confers NO power to verify – the finding is gated/unreportable until a
// DISTINCT human raises its score out of band – and the constituent findings are only NAMED, never merged.
// The domain (NewHypothesis) validates >= 2 constituents + title/description. Engagement is ALWAYS the
// session's; only the finding ids come from the call, never a cross-engagement reference.
func (c *Catalog) proposeAttackChain(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposeAttackChainArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_attack_chain args: %w", shared.ErrValidation, err)
	}
	var sev shared.Severity
	if s := strings.ToLower(strings.TrimSpace(a.Severity)); s != "" {
		sev = shared.Severity(s)
		if !sev.Valid() {
			return Result{}, fmt.Errorf("%w: invalid severity %q", shared.ErrValidation, a.Severity)
		}
	}
	in := finding.HypothesisInput{
		Title:          redact.String(strings.TrimSpace(a.Title), nil),
		Description:    redact.String(strings.TrimSpace(a.Description), nil),
		ConstituentIDs: a.ConstituentIDs,
		Severity:       sev,
	}
	f, err := c.hypProposer.ProposeHypothesis(ctx, sess.AgentActor(), sess.EngagementID, in)
	if err != nil {
		return Result{}, err // domain validates (>= 2 constituents, title/description); service persists at 0 + audits
	}
	payload, err := json.Marshal(map[string]any{
		"finding_id": f.ID.String(), "kind": string(f.Kind), "status": string(f.Status),
		"evidence_score": f.EvidenceScore, "proposed_by": f.ProposedBy, "can_promote": f.CanPromote(),
		"note": "recorded as an UNPROVEN attack-chain hypothesis (score 0); a distinct human must verify it before it is reportable, and it did NOT modify the constituent findings",
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal hypothesis: %w", err)
	}
	return Result{Data: payload}, nil
}

// --- plan tool: propose-only multi-step DAG ---

type proposePlanArgs struct {
	Nodes []proposePlanNode `json:"nodes"`
}

type proposePlanNode struct {
	Key       string   `json:"key"`
	Tool      string   `json:"tool"`
	Target    string   `json:"target"`
	DependsOn []string `json:"depends_on"`
	Rationale string   `json:"rationale"`
}

// proposePlan turns an LLM-proposed step graph into a validated agent.Plan and RUNS NOTHING.
// Go owns every authority-bearing field: it mints each node's id + a stable ActionID, classifies
// risk via riskFor (never trusting an LLM-supplied risk), validates each tool/target exactly as
// start_recon does, translates the LLM's dependency LABELS (keys) to minted ids, and validates
// the DAG (acyclic, bounded) via agent.NewPlan. The orchestrator persists the returned plan and
// admits every node through safety.Gate – a node carries no authority of its own.
func (c *Catalog) proposePlan(ctx context.Context, sess agent.Session, raw json.RawMessage) (Result, error) {
	var a proposePlanArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return Result{}, fmt.Errorf("%w: propose_plan args: %w", shared.ErrValidation, err)
	}
	if len(a.Nodes) == 0 {
		return Result{}, fmt.Errorf("%w: propose_plan requires at least one node", shared.ErrValidation)
	}
	if len(a.Nodes) > MaxPlanNodes {
		return Result{}, fmt.Errorf("%w: plan has %d nodes (max %d)", shared.ErrValidation, len(a.Nodes), MaxPlanNodes)
	}
	// First pass: mint a real node id per unique key (the LLM's labels are never used as ids).
	keyToID := make(map[string]string, len(a.Nodes))
	for _, n := range a.Nodes {
		key := strings.TrimSpace(n.Key)
		if key == "" {
			return Result{}, fmt.Errorf("%w: every plan node needs a 'key'", shared.ErrValidation)
		}
		if _, dup := keyToID[key]; dup {
			return Result{}, fmt.Errorf("%w: duplicate plan node key %q", shared.ErrValidation, key)
		}
		keyToID[key] = c.ids.NewID().String()
	}
	// Second pass: validate each node's tool/target (reusing the start_recon guards) + classify
	// risk in Go, translate depends_on keys to minted ids, and build the typed PlanNode set.
	nodes := make([]agent.PlanNode, 0, len(a.Nodes))
	for _, n := range a.Nodes {
		toolName := strings.TrimSpace(n.Tool)
		targetStr := strings.TrimSpace(n.Target)
		if toolName == "" || targetStr == "" {
			return Result{}, fmt.Errorf("%w: plan node %q needs tool + target", shared.ErrValidation, n.Key)
		}
		if err := engagement.ValidateTargetValue(targetStr); err != nil {
			return Result{}, err
		}
		tool, ok := c.recon[toolName]
		if !ok {
			return Result{}, fmt.Errorf("%w: unknown recon tool %q", shared.ErrValidation, toolName)
		}
		kind := engagement.InferTargetKind(targetStr)
		if !tool.Accepts(kind) {
			return Result{}, fmt.Errorf("%w: %s does not accept %s targets", shared.ErrValidation, toolName, kind)
		}
		deps := make([]string, 0, len(n.DependsOn))
		for _, depKey := range n.DependsOn {
			depKey = strings.TrimSpace(depKey)
			id, ok := keyToID[depKey]
			if !ok {
				return Result{}, fmt.Errorf("%w: plan node %q depends on unknown key %q", shared.ErrValidation, n.Key, depKey)
			}
			deps = append(deps, id)
		}
		nodes = append(nodes, agent.PlanNode{
			ID:        keyToID[strings.TrimSpace(n.Key)],
			Tool:      toolName,
			Target:    targetStr,
			DependsOn: deps,
			ActionID:  c.ids.NewID(), // minted ONCE; reused on every re-admission (stable idempotency key)
			Risk:      riskFor(tool), // classified in Go; never an LLM-supplied risk
			// Scrub URL-embedded creds from the LLM-authored rationale before it is persisted to
			// the plan row: it is the one node string written to the DB.
			Rationale: redact.String(strings.TrimSpace(n.Rationale), nil),
		})
	}
	plan, err := agent.NewPlan(c.ids.NewID(), sess.ID, sess.EngagementID, sess.Goal, nodes, c.clock.Now())
	if err != nil {
		return Result{}, err // cycle / oversize / bad dep – rejected, never truncated
	}
	if err := c.audit.Record(ctx, ports.AuditEntry{
		Actor:  sess.AgentActor(),
		Action: "agent.propose_plan",
		Target: sess.EngagementID.String(),
		Metadata: map[string]string{
			"plan_id": plan.ID.String(), "nodes": strconv.Itoa(len(nodes)), "session": sess.ID.String(),
		},
		At: c.clock.Now(),
	}); err != nil {
		return Result{}, fmt.Errorf("audit plan proposal: %w", err)
	}
	return Result{Plan: &plan}, nil
}

// ProposeForNode rebuilds the approval-required ProposedAction for a plan node at execution
// time, reusing the node's STABLE ActionID so the evidence-chain idempotency holds across
// redeliveries. It runs + audits nothing (the plan was audited at proposal); the orchestrator
// admits the result through safety.Gate. Same argv/target guards as start_recon (one source).
func (c *Catalog) ProposeForNode(sess agent.Session, node agent.PlanNode) (agent.ProposedAction, error) {
	if node.ActionID == "" {
		return agent.ProposedAction{}, fmt.Errorf("%w: plan node %q has no action id", shared.ErrValidation, node.ID)
	}
	return c.buildReconProposal(sess, node.Tool, node.Target, node.Rationale, node.ActionID)
}

// --- helpers ---

// auditRead records a read-tool access in the append-only log as the agent. A failure
// to audit fails the call closed – an unrecorded data access is not allowed.
func (c *Catalog) auditRead(ctx context.Context, sess agent.Session, action, target string, count int) error {
	if err := c.audit.Record(ctx, ports.AuditEntry{
		Actor:    sess.AgentActor(),
		Action:   action,
		Target:   target,
		Metadata: map[string]string{"count": strconv.Itoa(count), "session": sess.ID.String()},
		At:       c.clock.Now(),
	}); err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}

// riskFor classifies a recon proposal's risk. Capability-sensitive tools (raw sockets, e.g.
// naabu SYN scans) are Intrusive (always manual approval); all other live recon is Active. No
// recon launch is ever Read – reconnaissance touches third-party/target infrastructure, so it
// is never silently auto-approved in filter mode (only in full auto mode). Conservative by
// design: the gate can always be made stricter, never weaker, by this mapping.
func riskFor(t ports.ReconTool) agent.RiskClass {
	if t.CapabilitySensitive() {
		return agent.RiskIntrusive
	}
	return agent.RiskActive
}

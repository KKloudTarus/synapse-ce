// Package httpapi is the HTTP driving adapter: it maps routes to use case services.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"path"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
	audituc "github.com/KKloudTarus/synapse-ce/internal/usecase/audit"
	aupuc "github.com/KKloudTarus/synapse-ce/internal/usecase/aup"
	credentialsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/credentials"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	dastverifieruc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
	dastworkflowuc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastworkflow"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	exportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/export"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
	reportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/report"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
	transferuc "github.com/KKloudTarus/synapse-ce/internal/usecase/transfer"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
	vexuc "github.com/KKloudTarus/synapse-ce/internal/usecase/vex"
)

// Router wires HTTP routes to use case services.
type Router struct {
	log          *slog.Logger
	auth         *Authenticator
	eng          *enguc.Service
	sca          *scauc.Service
	aup          *aupuc.Service
	findings     *findingsuc.Service
	export       *exportuc.Service
	report       *reportuc.Service
	evidence     *evidenceuc.Service
	recon        *reconuc.Service
	logs         ports.LogStream
	transfer     *transferuc.Service
	audit        *audituc.Service
	vex          *vexuc.Service
	users        *usersuc.Service
	credentials  *credentialsuc.Service
	dastVerifier runtimeVerifierService
	dastWorkflow dastWorkflowService
	agent        *agentDeps          // optional; nil ⇒ agent routes are not registered
	exploitation findingVerifier     // optional; nil ⇒ the verify route is not registered
	judgments    judgmentService     // optional; nil ⇒ judgment routes are not registered
	autoVerifier autoVerifierService // optional; nil ⇒ the LLM auto-verify route is not registered
	threatModels threatModelService  // optional; nil ⇒ threat-model routes are not registered
	drafts       writeupDraftService // optional; nil ⇒ writeup-draft sign-off routes are not registered
	codeQuality  codeQualityService  // optional; nil ⇒ the code-quality route is not registered
	projects     projectService      // optional; nil ⇒ project routes are not registered
	qualityGates qualityGateService  // optional; nil ⇒ quality-gate routes are not registered
	rules        rulesService        // optional; nil ⇒ rule catalog routes are not registered
}

// findingVerifier is the narrow slice of the exploitation use-case the verify endpoint needs:
// apply a distinct-verifier verdict that seals evidence + (if it passes) raises the score.
// *exploitation.Service satisfies it.
type findingVerifier interface {
	Confirm(ctx context.Context, verifier string, engagementID, findingID shared.ID, score int, rationale string, expectedVersion int) (finding.Finding, error)
}

// SetExploitation wires the evidence-gated finding-verify endpoint.
func (rt *Router) SetExploitation(v findingVerifier) { rt.exploitation = v }

// judgmentService is the narrow slice of the analysis use-case the HTTP layer needs: list
// the engagement's AI judgments (read) and apply a distinct-verifier verdict / human acceptance.
// Verify + Accept are gated by PermReview (separation of duties; never a machine role). Propose is
// NOT exposed here – judgments are proposed by the agent via the tool catalog, and the
// score-mover is off the broad read port. *analysis.Service satisfies this.
type judgmentService interface {
	List(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
	Verify(ctx context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error)
	Accept(ctx context.Context, by string, engagementID, judgmentID shared.ID, expectedVersion int) (judgment.Judgment, error)
}

// writeupDraftService is the human sign-off slice of the writeupdraft use case: list the
// engagement's drafts, and the human-only edit/accept/reject. (Propose is NOT here – the agent reaches
// it via a separate narrow interface in the agent catalog; a human cannot propose via HTTP.)
type writeupDraftService interface {
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]writeupdraft.Draft, error)
	Edit(ctx context.Context, principal string, engagementID, id shared.ID, description, remediation string) (writeupdraft.Draft, error)
	Accept(ctx context.Context, principal string, engagementID, id shared.ID) (writeupdraft.Draft, error)
	Reject(ctx context.Context, principal string, engagementID, id shared.ID) (writeupdraft.Draft, error)
}

// SetJudgments wires the AI judgment lifecycle endpoints. nil ⇒ routes are not registered.
func (rt *Router) SetJudgments(s judgmentService) { rt.judgments = s }

// SetAutoVerifier wires the optional automated LLM judgment-verifier (nil ⇒ the auto-verify route is
// not registered). It seals a distinct-verifier verdict on each proposed gated judgment.
func (rt *Router) SetAutoVerifier(s autoVerifierService) { rt.autoVerifier = s }

// runtimeVerifierService is the narrow HTTP slice for applying approved DAST/runtime verifier
// results. It validates the typed proof class and delegates to analysis.Verify; it is deliberately
// separate from the agent and does not run probes.
type runtimeVerifierService interface {
	Apply(ctx context.Context, engagementID shared.ID, r dastverifieruc.Result) (judgment.Judgment, error)
}

// SetRuntimeVerifier wires typed runtime-verifier result ingestion. nil means the route is absent.
func (rt *Router) SetRuntimeVerifier(s runtimeVerifierService) { rt.dastVerifier = s }

type dastWorkflowService interface {
	Propose(ctx context.Context, actor string, engagementID shared.ID, probe dastrunner.Probe) (dastworkflowuc.Proposal, error)
	Decide(ctx context.Context, human string, engagementID, actionID shared.ID, approve bool, reason string) (agent.ApprovalDecision, error)
	Run(ctx context.Context, actor string, engagementID, actionID shared.ID, probe dastrunner.Probe) (dastrunner.Result, error)
}

// SetDASTWorkflow wires the governed safe-DAST proposal/approval/run endpoints.
func (rt *Router) SetDASTWorkflow(s dastWorkflowService) { rt.dastWorkflow = s }

// SetThreatModel wires the architecture threat-model ingest/read endpoints. nil ⇒ not registered.
func (rt *Router) SetThreatModel(s threatModelService) { rt.threatModels = s }

// SetWriteupDrafts wires the human sign-off endpoints for AI-proposed write-up drafts. nil ⇒ not registered.
func (rt *Router) SetWriteupDrafts(s writeupDraftService) { rt.drafts = s }

// qualityGateService is the HTTP slice for tenant-scoped gate management.
type qualityGateService interface {
	List(context.Context, shared.ID) ([]qualitygate.Gate, error)
	Get(context.Context, shared.ID, string) (qualitygate.Gate, error)
	Create(context.Context, string, shared.ID, qualitygate.Gate) (qualitygate.Gate, error)
	Update(context.Context, string, shared.ID, string, qualitygate.Gate) (qualitygate.Gate, error)
	Delete(context.Context, string, shared.ID, string) error
}

// SetQualityGates wires quality gate management endpoints.
func (rt *Router) SetQualityGates(s qualityGateService) { rt.qualityGates = s }

// SetRules wires the rule catalog endpoints. nil ⇒ not registered.
func (rt *Router) SetRules(s rulesService) { rt.rules = s }

// NewRouter builds the HTTP router.
func NewRouter(log *slog.Logger, auth *Authenticator, eng *enguc.Service, sca *scauc.Service, aup *aupuc.Service, findings *findingsuc.Service, export *exportuc.Service, report *reportuc.Service, evidence *evidenceuc.Service, recon *reconuc.Service, logs ports.LogStream, transfer *transferuc.Service, audit *audituc.Service, vex *vexuc.Service, users *usersuc.Service, credentials *credentialsuc.Service) *Router {
	return &Router{log: log, auth: auth, eng: eng, sca: sca, aup: aup, findings: findings, export: export, report: report, evidence: evidence, recon: recon, logs: logs, transfer: transfer, audit: audit, vex: vex, users: users, credentials: credentials}
}

// authz wraps a handler with an RBAC check: the request principal's role must be granted
// perm, else 403. It is the single role chokepoint – every non-public route is registered through
// it, so no handler decides its own authorization. Composed OUTSIDE withEngTenant for engagement
// child routes (role 403 is decided first and cheaply, without revealing whether a cross-tenant
// engagement exists; a role-allowed caller then hits the tenant 404). Machine (mcp/agent) and
// unknown roles are granted nothing here (user.Role.Can), so the human REST API is closed to them.
func (rt *Router) authz(perm userdom.Permission, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalObj(r.Context())
		if !ok || !userdom.Role(p.Role).Can(perm) {
			writeJSON(w, http.StatusForbidden, errorBody{Error: "insufficient permissions: this action requires the " + string(perm) + " capability"})
			return
		}
		h(w, r)
	}
}

// withEngTenant wraps an engagement-scoped CHILD-resource handler with a tenant-isolation
// precondition. The {id} path segment is the engagement id; the wrapped
// handler runs only if that engagement exists AND belongs to the caller's tenant. A missing
// OR cross-tenant engagement yields 404 (existence is never revealed) BEFORE the child resource
// (findings, evidence, credentials, scans, recon runs, agent sessions, reports, …) is touched.
//
// This is the SINGLE chokepoint that makes every "/engagements/{id}/…" child route tenant-
// isolated, so no individual handler can forget the check. The engagement-row routes (Get + the
// five mutations) are scoped at the service layer instead, and the two body-keyed routes
// (POST /sca/scans, POST /engagements/import) check tenancy in their handlers. The decorator runs
// as the matched handler, so r.PathValue("id") is populated.
func (rt *Router) withEngTenant(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id"))); err != nil {
			writeError(w, rt.log, err)
			return
		}
		h(w, r)
	}
}

// routes registers every route on a fresh ServeMux and returns it. Split out from Handler so the
// hostile validation harness can drive the real route → authz → withEngTenant → handler
// chain directly with a context-injected principal – exercising the production authorization wiring
// without the auth/AUP middleware (which are validated separately).
func (rt *Router) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "synapse-api"})
	})
	// Identity/consent routes carry NO role gate (a brand-new principal must reach them): /aup,
	// /aup/accept, /me, and public /healthz. EVERY other route below is registered through
	// authz(perm, …) – the single RBAC chokepoint, so no handler decides its own role
	// check. Engagement child routes compose authz OUTSIDE withEngTenant: the role 403 is decided
	// first and cheaply (without revealing whether a cross-tenant engagement exists); a role-allowed
	// caller then hits the tenant 404. Machine (mcp/agent) roles are granted nothing here.
	mux.HandleFunc("GET /api/v1/aup", rt.getAUP)
	mux.HandleFunc("POST /api/v1/aup/accept", rt.acceptAUP)
	if rt.qualityGates != nil {
		mux.HandleFunc("GET /api/v1/quality-gates", rt.authz(userdom.PermView, rt.listQualityGates))
		mux.HandleFunc("GET /api/v1/quality-gates/{key}", rt.authz(userdom.PermView, rt.getQualityGate))
		mux.HandleFunc("POST /api/v1/quality-gates", rt.authz(userdom.PermOperate, rt.createQualityGate))
		mux.HandleFunc("PUT /api/v1/quality-gates/{key}", rt.authz(userdom.PermOperate, rt.updateQualityGate))
		mux.HandleFunc("DELETE /api/v1/quality-gates/{key}", rt.authz(userdom.PermOperate, rt.deleteQualityGate))
	}
	if rt.projects != nil {
		mux.HandleFunc("POST /api/v1/projects", rt.authz(userdom.PermOperate, rt.createProject))
		mux.HandleFunc("GET /api/v1/projects", rt.authz(userdom.PermView, rt.listProjects))
		mux.HandleFunc("GET /api/v1/projects/{key}", rt.authz(userdom.PermView, rt.getProject))
		mux.HandleFunc("GET /api/v1/projects/{key}/overview", rt.authz(userdom.PermView, rt.projectOverview))
		mux.HandleFunc("GET /api/v1/projects/{key}/hotspots", rt.authz(userdom.PermView, rt.listProjectHotspots))
		mux.HandleFunc("GET /api/v1/projects/{key}/hotspots/{id}", rt.authz(userdom.PermView, rt.getProjectHotspot))
		mux.HandleFunc("PUT /api/v1/projects/{key}/gate", rt.authz(userdom.PermOperate, rt.assignProjectGate))
		mux.HandleFunc("POST /api/v1/projects/{key}/analyses", rt.authz(userdom.PermOperate, rt.startProjectAnalysis))
		mux.HandleFunc("GET /api/v1/projects/{key}/analyses", rt.authz(userdom.PermView, rt.listProjectAnalyses))
		mux.HandleFunc("GET /api/v1/projects/{key}/analyses/{id}", rt.authz(userdom.PermView, rt.getProjectAnalysis))
		mux.HandleFunc("GET /api/v1/projects/{key}/analysis-status", rt.authz(userdom.PermView, rt.projectAnalysisStatus))
		mux.HandleFunc("GET /api/v1/projects/{key}/analysis", rt.authz(userdom.PermView, rt.latestProjectAnalysis))
	}
	mux.HandleFunc("POST /api/v1/engagements", rt.authz(userdom.PermOperate, rt.createEngagement))
	mux.HandleFunc("GET /api/v1/engagements", rt.authz(userdom.PermView, rt.listEngagements))
	mux.HandleFunc("GET /api/v1/engagements/{id}", rt.authz(userdom.PermView, rt.getEngagement))
	mux.HandleFunc("PATCH /api/v1/engagements/{id}", rt.authz(userdom.PermOperate, rt.transitionEngagement))
	mux.HandleFunc("PUT /api/v1/engagements/{id}/scope", rt.authz(userdom.PermOperate, rt.updateScope))
	mux.HandleFunc("PUT /api/v1/engagements/{id}/authorization-window", rt.authz(userdom.PermOperate, rt.setAuthorizationWindow))
	mux.HandleFunc("PUT /api/v1/engagements/{id}/roe", rt.authz(userdom.PermOperate, rt.setRoE))
	mux.HandleFunc("PUT /api/v1/engagements/{id}/live-recon", rt.authz(userdom.PermOperate, rt.setLiveRecon))
	mux.HandleFunc("GET /api/v1/engagements/{id}/findings", rt.authz(userdom.PermView, rt.withEngTenant(rt.listFindings)))
	mux.HandleFunc("POST /api/v1/engagements/{id}/findings", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.createFinding)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/scan", rt.authz(userdom.PermView, rt.withEngTenant(rt.latestScan)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/scan-status", rt.authz(userdom.PermView, rt.withEngTenant(rt.scanStatus)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/scan-runs", rt.authz(userdom.PermView, rt.withEngTenant(rt.scanRuns)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/scan-runs/compare", rt.authz(userdom.PermView, rt.withEngTenant(rt.compareScanRuns)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/credentials", rt.authz(userdom.PermView, rt.withEngTenant(rt.listCredentials)))
	mux.HandleFunc("POST /api/v1/engagements/{id}/credentials", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.setCredential)))
	mux.HandleFunc("DELETE /api/v1/engagements/{id}/credentials/{name}", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.deleteCredential)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/evidence", rt.authz(userdom.PermView, rt.withEngTenant(rt.evidenceLedger)))
	mux.HandleFunc("POST /api/v1/engagements/{id}/evidence", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.captureEvidence)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/evidence/{sha}", rt.authz(userdom.PermView, rt.withEngTenant(rt.downloadArtifact)))
	mux.HandleFunc("PATCH /api/v1/engagements/{id}/findings/{fid}", rt.authz(userdom.PermTriage, rt.withEngTenant(rt.updateFindingStatus)))
	if rt.exploitation != nil { // distinct-verifier verdict that gates promotion (sign-off → PermReview)
		mux.HandleFunc("POST /api/v1/engagements/{id}/findings/{fid}/verify", rt.authz(userdom.PermReview, rt.withEngTenant(rt.verifyFinding)))
	}
	if rt.judgments != nil { // AI judgment lifecycle – read (PermView) + sign-off verify/accept (PermReview, SoD)
		mux.HandleFunc("GET /api/v1/engagements/{id}/judgments", rt.authz(userdom.PermView, rt.withEngTenant(rt.listJudgments)))
		mux.HandleFunc("POST /api/v1/engagements/{id}/judgments/{jid}/verify", rt.authz(userdom.PermReview, rt.withEngTenant(rt.verifyJudgment)))
		mux.HandleFunc("POST /api/v1/engagements/{id}/judgments/{jid}/accept", rt.authz(userdom.PermReview, rt.withEngTenant(rt.acceptJudgment)))
	}
	if rt.autoVerifier != nil { // automated LLM verifier: a distinct verifier model seals verdicts (PermReview, SoD)
		mux.HandleFunc("POST /api/v1/engagements/{id}/judgments/auto-verify", rt.authz(userdom.PermReview, rt.withEngTenant(rt.autoVerifyJudgments)))
	}
	if rt.dastVerifier != nil {
		mux.HandleFunc("POST /api/v1/engagements/{id}/judgments/{jid}/runtime-verification", rt.authz(userdom.PermReview, rt.withEngTenant(rt.applyRuntimeVerification)))
	}
	if rt.dastWorkflow != nil {
		mux.HandleFunc("POST /api/v1/engagements/{id}/judgments/{jid}/runtime-verification/proposals", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.proposeRuntimeVerification)))
		mux.HandleFunc("POST /api/v1/engagements/{id}/dast/approvals/{aid}/decide", rt.authz(userdom.PermReview, rt.withEngTenant(rt.decideRuntimeVerification)))
		mux.HandleFunc("POST /api/v1/engagements/{id}/judgments/{jid}/runtime-verification/proposals/{aid}/run", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.runRuntimeVerification)))
	}
	if rt.threatModels != nil { // architecture threat-model ingest (PermOperate) + read (PermView)
		mux.HandleFunc("PUT /api/v1/engagements/{id}/threat-model", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.putThreatModel)))
		mux.HandleFunc("GET /api/v1/engagements/{id}/threat-model", rt.authz(userdom.PermView, rt.withEngTenant(rt.getThreatModel)))
	}
	if rt.codeQuality != nil { // read-only code-quality dashboard (PermView)
		mux.HandleFunc("GET /api/v1/engagements/{id}/code-quality", rt.authz(userdom.PermView, rt.withEngTenant(rt.codeQualityReport)))
	}
	if rt.drafts != nil { // AI-proposed write-up drafts – read (PermView) + human sign-off edit/accept/reject (PermReview, SoD)
		mux.HandleFunc("GET /api/v1/engagements/{id}/writeup-drafts", rt.authz(userdom.PermView, rt.withEngTenant(rt.listWriteupDrafts)))
		mux.HandleFunc("POST /api/v1/engagements/{id}/writeup-drafts/{did}/edit", rt.authz(userdom.PermReview, rt.withEngTenant(rt.editWriteupDraft)))
		mux.HandleFunc("POST /api/v1/engagements/{id}/writeup-drafts/{did}/accept", rt.authz(userdom.PermReview, rt.withEngTenant(rt.acceptWriteupDraft)))
		mux.HandleFunc("POST /api/v1/engagements/{id}/writeup-drafts/{did}/reject", rt.authz(userdom.PermReview, rt.withEngTenant(rt.rejectWriteupDraft)))
	}
	mux.HandleFunc("PUT /api/v1/engagements/{id}/findings/{fid}/assignee", rt.authz(userdom.PermTriage, rt.withEngTenant(rt.setFindingAssignee)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/findings/{fid}/comments", rt.authz(userdom.PermView, rt.withEngTenant(rt.listFindingComments)))
	mux.HandleFunc("POST /api/v1/engagements/{id}/findings/{fid}/comments", rt.authz(userdom.PermTriage, rt.withEngTenant(rt.addFindingComment)))
	mux.HandleFunc("GET /api/v1/cvss", rt.authz(userdom.PermView, rt.cvssScore))
	mux.HandleFunc("GET /api/v1/writeups", rt.authz(userdom.PermView, rt.listWriteups))
	mux.HandleFunc("GET /api/v1/engagements/{id}/export/sarif", rt.authz(userdom.PermView, rt.withEngTenant(rt.exportSARIF)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/export/openvex", rt.authz(userdom.PermView, rt.withEngTenant(rt.exportOpenVEX)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/export/spdx", rt.authz(userdom.PermView, rt.withEngTenant(rt.exportSPDX)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/export/cyclonedx", rt.authz(userdom.PermView, rt.withEngTenant(rt.exportCycloneDX)))
	mux.HandleFunc("POST /api/v1/engagements/{id}/vex", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.applyVEX)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/sbom", rt.authz(userdom.PermView, rt.withEngTenant(rt.importedSBOM)))
	mux.HandleFunc("POST /api/v1/engagements/{id}/sbom", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.importSBOM)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/report.pdf", rt.authz(userdom.PermView, rt.withEngTenant(rt.exportReport)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/report.html", rt.authz(userdom.PermView, rt.withEngTenant(rt.exportReportHTML)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/report.docx", rt.authz(userdom.PermView, rt.withEngTenant(rt.exportReportDOCX)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/bundle", rt.authz(userdom.PermView, rt.withEngTenant(rt.exportBundle)))
	mux.HandleFunc("POST /api/v1/engagements/import", rt.authz(userdom.PermOperate, rt.importBundle))
	mux.HandleFunc("GET /api/v1/engagements/{id}/findings/{fid}/retests", rt.authz(userdom.PermView, rt.withEngTenant(rt.listRetests)))
	mux.HandleFunc("POST /api/v1/engagements/{id}/findings/{fid}/retests", rt.authz(userdom.PermTriage, rt.withEngTenant(rt.recordRetest)))
	// Audit is oversight data and is NOT yet tenant-scoped (global), so it is gated to the
	// sign-off capability (reviewer/admin) rather than the view floor.
	mux.HandleFunc("GET /api/v1/audit", rt.authz(userdom.PermReview, rt.listAudit))
	mux.HandleFunc("GET /api/v1/audit/verify", rt.authz(userdom.PermReview, rt.verifyAudit))
	mux.HandleFunc("GET /api/v1/me", rt.currentUser)
	mux.HandleFunc("GET /api/v1/users", rt.authz(userdom.PermAdminister, rt.listUsers))
	mux.HandleFunc("POST /api/v1/users", rt.authz(userdom.PermAdminister, rt.createUser))
	mux.HandleFunc("POST /api/v1/sca/scans", rt.authz(userdom.PermOperate, rt.runSCAScan))
	mux.HandleFunc("GET /api/v1/recon/tools", rt.authz(userdom.PermView, rt.listReconTools))
	mux.HandleFunc("POST /api/v1/engagements/{id}/recon/runs", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.startReconRun)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/recon/runs", rt.authz(userdom.PermView, rt.withEngTenant(rt.listReconRuns)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/recon/runs/{rid}", rt.authz(userdom.PermView, rt.withEngTenant(rt.getReconRun)))
	mux.HandleFunc("GET /api/v1/engagements/{id}/recon/runs/{rid}/logs", rt.authz(userdom.PermView, rt.withEngTenant(rt.streamReconLogs)))

	// AI agent orchestration (only when wired via EnableAgent). decide = sign-off →
	// PermReview (a machine role is granted nothing, so it cannot approve its own actions).
	if rt.agent != nil {
		mux.HandleFunc("GET /api/v1/engagements/{id}/agent/readiness", rt.authz(userdom.PermView, rt.withEngTenant(rt.agentReadiness)))
		mux.HandleFunc("POST /api/v1/engagements/{id}/agent/sessions", rt.authz(userdom.PermOperate, rt.withEngTenant(rt.startAgentSession)))
		mux.HandleFunc("GET /api/v1/engagements/{id}/agent/sessions", rt.authz(userdom.PermView, rt.withEngTenant(rt.listAgentSessions)))
		mux.HandleFunc("GET /api/v1/engagements/{id}/agent/sessions/{sid}", rt.authz(userdom.PermView, rt.withEngTenant(rt.getAgentSession)))
		mux.HandleFunc("GET /api/v1/engagements/{id}/agent/sessions/{sid}/decisions", rt.authz(userdom.PermView, rt.withEngTenant(rt.listAgentDecisions)))
		mux.HandleFunc("GET /api/v1/engagements/{id}/agent/sessions/{sid}/plan", rt.authz(userdom.PermView, rt.withEngTenant(rt.getAgentPlan)))
		mux.HandleFunc("GET /api/v1/engagements/{id}/agent/sessions/{sid}/stream", rt.authz(userdom.PermView, rt.withEngTenant(rt.streamAgentSession)))
		mux.HandleFunc("GET /api/v1/engagements/{id}/agent/approvals", rt.authz(userdom.PermView, rt.withEngTenant(rt.listAgentApprovals)))
		mux.HandleFunc("POST /api/v1/engagements/{id}/agent/approvals/{aid}/decide", rt.authz(userdom.PermReview, rt.withEngTenant(rt.decideAgentApproval)))
	}

	if rt.rules != nil { // read-only rule catalog (PermView)
		mux.HandleFunc("GET /api/v1/rules", rt.authz(userdom.PermView, rt.listRules))
		mux.HandleFunc("GET /api/v1/rules/{key}", rt.authz(userdom.PermView, rt.getRule))
	}

	return mux
}

// Handler returns the root http.Handler. Middleware chain (outermost first):
// normalize-path → auth → AUP gate → routes. Per-route RBAC is applied at registration via
// authz(perm, …) – not a path-set. Normalizing first ensures the public/AUP-exempt path-sets
// (matched on the request path) see exactly the path the ServeMux will route on (closes the
// raw-vs-cleaned path mismatch).
func (rt *Router) Handler() http.Handler {
	// Public: no auth and no AUP gate.
	public := map[string]bool{"/healthz": true}
	// Authenticated but exempt from the AUP gate (so the operator can read + accept).
	aupExempt := map[string]bool{
		"/healthz":           true,
		"/api/v1/aup":        true,
		"/api/v1/aup/accept": true,
		"/api/v1/me":         true,
	}
	return normalizePath(rt.auth.Middleware(public, rt.requireAUP(aupExempt, rt.routes())))
}

// normalizePath rejects non-canonical request paths (e.g. `/a//b`, `/a/../b`,
// trailing slashes) with 400 before any auth/AUP check runs, so authorization
// decisions are made on the same path the router uses.
func normalizePath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || r.URL.Path != path.Clean(r.URL.Path) {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "non-canonical request path"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

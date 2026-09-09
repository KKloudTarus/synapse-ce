// Package response applies governed defensive response actions (issue #425): isolate a host, quarantine
// a file, stop a process. It adds no new trust model — every action goes through the SAME admission gate
// (internal/usecase/safety) as a DAST probe and an exploitation step, is approved by a human (never a
// model) with the approval sealed as evidence, is argv-only, is reversible, and is halted by the #418
// kill switch. Apply is reachable only after admission plus a recorded human approval.
package response

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// admitter is the admission gate every action is routed through — the SAME gate the DAST probe and the
// exploitation step use (*safety.Gate satisfies it). A response action is not a privileged side path: it
// cannot execute without an AdmittedAction, which only the gate can mint (its fields are unexported).
type admitter interface {
	Admit(ctx context.Context, p agent.ProposedAction, actor string) (admission, error)
	Reauthorize(ctx context.Context, admitted admission) error
}

type approvalDecider interface {
	Get(context.Context, shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error)
	Decide(context.Context, string, shared.ID, bool, string) (agent.ApprovalDecision, error)
}

type admission struct {
	action     agent.ProposedAction
	decidedBy  string
	evidenceID shared.ID
	token      safety.AdmittedAction
}

type gateAdmitter struct{ gate *safety.Gate }

func (g gateAdmitter) Admit(ctx context.Context, p agent.ProposedAction, actor string) (admission, error) {
	token, err := g.gate.Admit(ctx, p, actor)
	if err != nil {
		return admission{}, err
	}
	admitted := token.Action()
	if !sameProposedAction(admitted, p) || token.EvidenceID().IsZero() || token.AuthorizedAt().IsZero() ||
		strings.TrimSpace(token.DecidedBy()) == "" || shared.IsMachineActor(token.DecidedBy()) {
		return admission{}, fmt.Errorf("%w: safety gate returned an invalid or unbound admission", shared.ErrForbidden)
	}
	return admission{action: admitted, decidedBy: token.DecidedBy(), evidenceID: token.EvidenceID(), token: token}, nil
}

func (g gateAdmitter) Reauthorize(ctx context.Context, admitted admission) error {
	return g.gate.Reauthorize(ctx, admitted.token)
}

// Executor and its DTOs remain aliases for compatibility; the executable boundary lives in ports.
type Executor = ports.ResponseExecutor
type ExecRequest = ports.ResponseExecRequest
type ExecOutcome = ports.ResponseExecOutcome

// EffectVerifier confirms, against telemetry, whether an applied action's intended EFFECT actually took
// hold on the target (#638). It is READ-ONLY — it observes, it never executes anything on the host — so
// wiring it crosses no execution boundary. `CommandApplied ≠ VerifiedSucceeded`: a kill whose syscall
// returned but whose process is still observed alive verifies as Failed; a target with no covering
// telemetry verifies as Unknown, never silently a success. Optional (nil ⇒ verification is not run).
type EffectVerifier interface {
	Identity() string
	Verify(ctx context.Context, req VerificationRequest) (VerificationReceipt, error)
}

// VerificationRequest remains an alias for compatibility; the observer-dispatch DTO lives in ports.
type VerificationRequest = ports.ResponseVerificationRequest

// VerificationReceipt binds a telemetry verdict to durable evidence produced by an independent verifier.
type VerificationReceipt struct {
	Outcome    rdom.Verification
	EvidenceID shared.ID
	Source     *VerificationSource
}

// VerificationSource embeds the exact purpose-signed observer report sealed into verification evidence.
// RecordedAt is server-owned; SignedContentDigest commits to the report's canonical signed message.
type VerificationSource struct {
	Report              fleetagent.ResponseVerificationReport    `json:"report"`
	RecordedAt          time.Time                                `json:"recorded_at"`
	SignedContentDigest string                                   `json:"signed_content_digest"`
	Receipt             fleetagent.ResponseTargetEvidenceReceipt `json:"target_evidence_receipt"`
	Timeline            []endpoint.TimelineEntry                 `json:"timeline,omitempty"`
	Coverage            []sensorstate.CoverageWindow             `json:"coverage,omitempty"`
}

func (s VerificationSource) validateBinding(req VerificationRequest) error {
	if err := s.Report.Validate(); err != nil {
		return err
	}
	if req.DeadlineAt.IsZero() || !req.DeadlineAt.After(req.AttemptedAt) ||
		s.RecordedAt.IsZero() || s.RecordedAt.Before(s.Report.ObservedAt) || !s.RecordedAt.Before(req.DeadlineAt) {
		return fmt.Errorf("%w: response verification source has invalid server receipt time", shared.ErrValidation)
	}
	digest := sha256.Sum256(fleetagent.ResponseVerificationMessage(s.Report))
	if s.SignedContentDigest != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("%w: response verification source digest does not match its signed report", shared.ErrForbidden)
	}
	if s.Report.EngagementID != req.EngagementID || s.Report.ActionID != req.Action.ID ||
		s.Report.ActionDigest != responseActionDigest(req.Action) || s.Report.AttemptKey != req.AttemptKey ||
		s.Report.VerificationChallenge != req.VerificationChallenge ||
		s.Report.Target != req.Target || s.Report.Reversal != req.Reversal ||
		!s.Report.ObservedAt.After(req.AttemptedAt) || !s.Report.ObservedAt.Before(req.DeadlineAt) {
		return fmt.Errorf("%w: response verification source is not bound to the execution attempt", shared.ErrForbidden)
	}
	if strings.EqualFold(s.Report.ObserverIdentity(), strings.TrimSpace(req.ExecutorID)) {
		return fmt.Errorf("%w: response executor cannot produce its own verification observation", shared.ErrForbidden)
	}
	if s.Report.AgentID == req.ExecutorAgentID {
		return fmt.Errorf("%w: response executor agent cannot produce its own verification observation", shared.ErrForbidden)
	}
	return nil
}

func (s VerificationSource) validate(req VerificationRequest, outcome rdom.Verification) error {
	if err := s.validateBinding(req); err != nil {
		return err
	}
	if !sameReceiptEvidence(s.Timeline, s.Coverage, s.Receipt.Timeline, s.Receipt.Coverage) {
		return fmt.Errorf("%w: response verification source evidence differs from immutable target receipt", shared.ErrForbidden)
	}
	derived, err := deriveTelemetryVerification(req, s.Receipt)
	if err != nil {
		return err
	}
	if derived != outcome {
		return fmt.Errorf("%w: response verification outcome does not match authoritative telemetry", shared.ErrForbidden)
	}
	return nil
}

// VerificationProvenance is the durable successful attempt identity an incident may reference. It is
// reconstructed from the response store and its evidence receipt, never from a verifier's live label.
type VerificationProvenance struct {
	ActionID     shared.ID
	EngagementID shared.ID
	ActionDigest string
	Target       responsesaga.TargetFingerprint
	AttemptKey   string
	ExecutorID   string
	VerifierID   string
	EvidenceID   shared.ID
}

// VerificationEvidenceKind identifies canonical response-verification claims in the evidence chain.
const VerificationEvidenceKind = "response_verification"

// ErrVerificationPending means no signed post-condition has arrived yet. It is not insufficient coverage:
// callers must leave the attempt in Verifying until an explicit unknown report or a governed timeout.
var ErrVerificationPending = errors.New("response verification observation pending")

// ErrAttemptDeadlineExceeded means a durable response attempt exhausted its authorization and evidence window.
var ErrAttemptDeadlineExceeded = errors.New("response attempt deadline exceeded")

type verificationEvidencePayload struct {
	Version               int                            `json:"version"`
	TenantID              shared.ID                      `json:"tenant_id"`
	EngagementID          shared.ID                      `json:"engagement_id"`
	ActionID              shared.ID                      `json:"action_id"`
	ActionDigest          string                         `json:"action_digest"`
	Target                responsesaga.TargetFingerprint `json:"target"`
	Reversal              bool                           `json:"reversal"`
	Outcome               rdom.Verification              `json:"outcome"`
	ExecutorID            string                         `json:"executor_id"`
	ExecutorAgentID       shared.ID                      `json:"executor_agent_id"`
	VerifierID            string                         `json:"verifier_id"`
	AttemptKey            string                         `json:"attempt_key"`
	VerificationChallenge string                         `json:"verification_challenge"`
	AttemptedAt           time.Time                      `json:"attempted_at"`
	DeadlineAt            time.Time                      `json:"deadline_at"`
	Source                *VerificationSource            `json:"source,omitempty"`
}

// MarshalVerificationEvidence returns the one canonical payload accepted for a verification receipt.
// Verifier adapters seal these exact bytes before returning the resulting evidence ID.
func MarshalVerificationEvidence(req VerificationRequest, outcome rdom.Verification, verifierID string, source *VerificationSource) ([]byte, error) {
	verifierID = strings.TrimSpace(verifierID)
	executorID := strings.TrimSpace(req.ExecutorID)
	if req.TenantID.IsZero() || req.EngagementID.IsZero() || req.ExecutorAgentID.IsZero() || verifierID == "" || executorID == "" ||
		strings.TrimSpace(req.AttemptKey) == "" || !validVerificationChallenge(req.VerificationChallenge) || req.AttemptedAt.IsZero() ||
		req.DeadlineAt.IsZero() || !req.DeadlineAt.After(req.AttemptedAt) {
		return nil, fmt.Errorf("%w: verification evidence is missing an identity", shared.ErrValidation)
	}
	if strings.EqualFold(verifierID, executorID) {
		return nil, fmt.Errorf("%w: response executor cannot verify its own effect", shared.ErrForbidden)
	}
	if err := req.Action.Validate(); err != nil {
		return nil, err
	}
	if err := req.Target.Validate(); err != nil {
		return nil, err
	}
	if !outcome.Valid() || outcome == VerificationPending {
		return nil, fmt.Errorf("%w: verification evidence has invalid outcome %q", shared.ErrValidation, outcome)
	}
	if source == nil {
		return nil, fmt.Errorf("%w: terminal verification evidence requires a signed source observation", shared.ErrValidation)
	}
	if err := source.validate(req, outcome); err != nil {
		return nil, err
	}
	actionBytes, err := json.Marshal(req.Action)
	if err != nil {
		return nil, fmt.Errorf("marshal response action: %w", err)
	}
	actionDigest := sha256.Sum256(actionBytes)
	return json.Marshal(verificationEvidencePayload{
		Version:               4,
		TenantID:              req.TenantID,
		EngagementID:          req.EngagementID,
		ActionID:              req.Action.ID,
		ActionDigest:          fmt.Sprintf("%x", actionDigest),
		Target:                req.Target,
		Reversal:              req.Reversal,
		Outcome:               outcome,
		ExecutorID:            executorID,
		ExecutorAgentID:       req.ExecutorAgentID,
		VerifierID:            verifierID,
		AttemptKey:            strings.TrimSpace(req.AttemptKey),
		VerificationChallenge: strings.TrimSpace(req.VerificationChallenge),
		AttemptedAt:           req.AttemptedAt.UTC(),
		DeadlineAt:            req.DeadlineAt.UTC(),
		Source:                source,
	})
}

type verificationEvidenceVault interface {
	LookupAttestedByID(ctx context.Context, engagementID, evidenceID shared.ID) (evdom.Evidence, *evdom.Attestation, bool, error)
}

type verificationSigningKeyResolver interface {
	ResolveSigningKey(ctx context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error)
}

type receiptValidator interface {
	Validate(ctx context.Context, req VerificationRequest, receipt VerificationReceipt, verifierID string) error
}

type evidenceReceiptValidator struct {
	vault            verificationEvidenceVault
	trustedPublicKey string
	observations     ports.ResponseVerificationStore
	receipts         ports.ResponseTargetEvidenceReceiptStore
	keys             verificationSigningKeyResolver
}

func (v evidenceReceiptValidator) Validate(ctx context.Context, req VerificationRequest, receipt VerificationReceipt, verifierID string) error {
	item, att, found, err := v.vault.LookupAttestedByID(ctx, req.EngagementID, receipt.EvidenceID)
	if err != nil {
		return fmt.Errorf("verify response evidence chain: %w", err)
	}
	if !found || att == nil {
		return fmt.Errorf("%w: response verification evidence is missing or unattested", shared.ErrForbidden)
	}
	var payload verificationEvidencePayload
	if err := json.Unmarshal(item.Content, &payload); err != nil {
		return fmt.Errorf("%w: response verification evidence payload is malformed", shared.ErrForbidden)
	}
	source := payload.Source
	accepted, acceptedFound, err := v.observations.GetResponseVerification(ctx, req.AttemptKey)
	if err != nil {
		return fmt.Errorf("read accepted response verification for receipt: %w", err)
	}
	if !acceptedFound {
		return fmt.Errorf("%w: response verification evidence has no accepted source observation", shared.ErrForbidden)
	}
	if err := accepted.Validate(); err != nil {
		return fmt.Errorf("%w: accepted response-verification provenance is invalid: %v", shared.ErrForbidden, err)
	}
	if v.receipts == nil {
		return fmt.Errorf("%w: response verification receipt store is unavailable", shared.ErrForbidden)
	}
	targetReceipt, receiptFound, err := v.receipts.GetResponseTargetEvidenceReceipt(ctx, req.AttemptKey)
	if err != nil || !receiptFound || targetReceipt.Validate() != nil || targetReceipt.ReceiptID != accepted.Report.ReceiptID || targetReceipt.Digest != accepted.Report.ReceiptDigest {
		return fmt.Errorf("%w: accepted report has no matching target evidence receipt", shared.ErrForbidden)
	}
	acceptedSource := VerificationSource{
		Report: accepted.Report, RecordedAt: accepted.RecordedAt, SignedContentDigest: accepted.SignedContentDigest, Receipt: targetReceipt, Timeline: targetReceipt.Timeline, Coverage: targetReceipt.Coverage,
	}
	if source == nil || !sameAcceptedVerificationSource(*source, acceptedSource) {
		return fmt.Errorf("%w: response verification evidence does not reference the accepted signed observation", shared.ErrForbidden)
	}
	key, err := v.keys.ResolveSigningKey(ctx, accepted.Report.AgentID, accepted.Report.KeyID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return fmt.Errorf("%w: accepted response-verification signing key is missing", shared.ErrForbidden)
		}
		return fmt.Errorf("resolve accepted response-verification signing key: %w", err)
	}
	// A later revocation must not erase a receipt accepted while its key was still
	// trusted. Validate the signature at its signed event time, then enforce the
	// server-owned acceptance time as the durable trust cutoff.
	if err := fleetagent.VerifyResponseVerificationWithKey(key, accepted.Report.ObservedAt, accepted.Report); err != nil {
		return fmt.Errorf("%w: accepted response-verification signature is no longer valid: %v", shared.ErrForbidden, err)
	}
	if err := key.UsableAt(accepted.RecordedAt); err != nil {
		return fmt.Errorf("%w: accepted response-verification key was not usable at receipt: %v", shared.ErrForbidden, err)
	}
	if receipt.Source != nil && (source == nil || !sameVerificationSource(*source, *receipt.Source)) {
		return fmt.Errorf("%w: response verification receipt source does not match its evidence", shared.ErrForbidden)
	}
	want, err := MarshalVerificationEvidence(req, receipt.Outcome, verifierID, source)
	if err != nil {
		return err
	}
	if item.EngagementID != req.EngagementID || item.Kind != VerificationEvidenceKind ||
		!strings.EqualFold(strings.TrimSpace(item.CreatedBy), strings.TrimSpace(verifierID)) || !bytes.Equal(item.Content, want) {
		return fmt.Errorf("%w: response verification evidence is not bound to the claim", shared.ErrForbidden)
	}
	if att.Context != evdom.AttestationContextEvidence || att.PublicKey != v.trustedPublicKey || att.Head == "" {
		return fmt.Errorf("%w: response verification evidence has an untrusted attestation", shared.ErrForbidden)
	}
	if err := evdom.VerifyAttestation(*att); err != nil {
		return fmt.Errorf("verify response evidence attestation: %w", err)
	}
	return nil
}

func sameReceiptEvidence(leftTimeline []endpoint.TimelineEntry, leftCoverage []sensorstate.CoverageWindow, rightTimeline []endpoint.TimelineEntry, rightCoverage []sensorstate.CoverageWindow) bool {
	leftBytes, leftErr := json.Marshal(struct {
		Timeline []endpoint.TimelineEntry     `json:"timeline"`
		Coverage []sensorstate.CoverageWindow `json:"coverage"`
	}{leftTimeline, leftCoverage})
	rightBytes, rightErr := json.Marshal(struct {
		Timeline []endpoint.TimelineEntry     `json:"timeline"`
		Coverage []sensorstate.CoverageWindow `json:"coverage"`
	}{rightTimeline, rightCoverage})
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func sameVerificationSource(left, right VerificationSource) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func sameAcceptedVerificationSource(left, right VerificationSource) bool {
	return sameVerificationSource(left, right)
}

// Record and State are the domain types (domain/response); re-exported as aliases so callers of this
// usecase package need not import both.
type (
	Record       = rdom.Record
	State        = rdom.State
	Verification = rdom.Verification
)

const (
	StatePending   = rdom.StatePending
	StateApplied   = rdom.StateApplied
	StateReverted  = rdom.StateReverted
	StateCancelled = rdom.StateCancelled
	StateViolation = rdom.StateViolation

	VerificationPending   = rdom.VerificationPending
	VerificationSucceeded = rdom.VerificationSucceeded
	VerificationFailed    = rdom.VerificationFailed
	VerificationUnknown   = rdom.VerificationUnknown
)

// Service applies response actions under the shared governance.
type Service struct {
	admit               admitter
	exec                Executor
	store               ports.ResponseAuditStore
	haltWriter          ports.ResponseHaltWriter
	audit               ports.IdempotentAuditLogger
	clock               ports.Clock
	verify              EffectVerifier // optional (#638): confirms an applied effect via telemetry; nil ⇒ not run
	receipts            receiptValidator
	approvals           approvalDecider
	verificationTimeout time.Duration
	// effectMu and inFlight close the local Apply/Halt race. Distributed production execution remains
	// disabled until the agent-side claim protocol carries the same durable fence.
	effectMu sync.Mutex
	inFlight map[string]*responseFlight
}

const (
	DefaultVerificationTimeout = 2 * time.Minute
	verificationCallTimeout    = 5 * time.Second
)

// SetHaltWriter replaces the halt-fence capability. PostgreSQL composition provides a
// dedicated narrow pool; in-memory operation retains the single transactional store.
func (s *Service) SetHaltWriter(haltWriter ports.ResponseHaltWriter) error {
	if haltWriter == nil {
		return fmt.Errorf("%w: response halt writer is required", shared.ErrValidation)
	}
	s.haltWriter = haltWriter
	return nil
}

// SetApprovalDecider installs the existing HITL service used to decide and resume response actions.
func (s *Service) SetApprovalDecider(approvals approvalDecider) {
	s.approvals = approvals
}

// SetVerificationTimeout bounds command-outcome and telemetry-verification obligations.
func (s *Service) SetVerificationTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("%w: response verification timeout must be positive", shared.ErrValidation)
	}
	s.verificationTimeout = timeout
	return nil
}

// responseStoreHaltWriter preserves the memory-mode default until the composition root
// explicitly installs the separate PostgreSQL halt writer.
type responseStoreHaltWriter struct{ ports.ResponseAuditStore }

func (w responseStoreHaltWriter) CurrentHaltGeneration(ctx context.Context) (int64, error) {
	return w.ResponseAuditStore.CurrentHaltGeneration(ctx)
}

func (w responseStoreHaltWriter) AdvanceHaltGenerationWithAudit(ctx context.Context, expected int64, intent ports.ResponseAuditIntent) (int64, ports.ResponseAuditIntent, ports.ResponseHaltDispatch, error) {
	return w.ResponseAuditStore.AdvanceHaltGenerationWithAudit(ctx, expected, intent)
}

type verificationPendingFailure struct {
	actionID shared.ID
	detail   string
	cause    error
}

func (e *verificationPendingFailure) Error() string {
	return fmt.Sprintf("response %s %s: %v", e.actionID, e.detail, e.cause)
}

func (e *verificationPendingFailure) Unwrap() []error {
	return []error{ErrVerificationPending, e.cause}
}

// NewService validates dependencies.
func NewService(gate *safety.Gate, exec Executor, store ports.ResponseAuditStore, audit ports.IdempotentAuditLogger, clock ports.Clock, verifier EffectVerifier, evidenceVault verificationEvidenceVault, trustedEvidencePublicKey string, observations ports.ResponseVerificationStore, targetReceipts ports.ResponseTargetEvidenceReceiptStore, keys verificationSigningKeyResolver) (*Service, error) {
	if gate == nil || verifier == nil || evidenceVault == nil || observations == nil || targetReceipts == nil || keys == nil || strings.TrimSpace(trustedEvidencePublicKey) == "" {
		return nil, fmt.Errorf("%w: response service requires the safety gate, telemetry verifier, and trusted evidence verifier", shared.ErrValidation)
	}
	trustedEvidencePublicKey = strings.TrimSpace(trustedEvidencePublicKey)
	publicKey, err := base64.StdEncoding.DecodeString(trustedEvidencePublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: response service trusted evidence public key is malformed", shared.ErrValidation)
	}
	service, err := newService(gateAdmitter{gate: gate}, exec, store, audit, clock)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(verifier.Identity()) == "" || strings.EqualFold(strings.TrimSpace(verifier.Identity()), strings.TrimSpace(service.exec.Identity())) {
		return nil, fmt.Errorf("%w: response executor and verifier require distinct non-empty identities", shared.ErrValidation)
	}
	service.verify = verifier
	service.receipts = evidenceReceiptValidator{
		vault: evidenceVault, trustedPublicKey: trustedEvidencePublicKey, observations: observations, receipts: targetReceipts, keys: keys,
	}
	return service, nil
}

func newService(admit admitter, exec Executor, store ports.ResponseAuditStore, audit ports.IdempotentAuditLogger, clock ports.Clock) (*Service, error) {
	if admit == nil || exec == nil || store == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: response service is missing a dependency", shared.ErrValidation)
	}
	if strings.TrimSpace(exec.Identity()) == "" {
		return nil, fmt.Errorf("%w: response executor has no identity", shared.ErrValidation)
	}
	return &Service{
		admit: admit, exec: exec, store: store, haltWriter: responseStoreHaltWriter{store}, audit: audit, clock: clock,
		verificationTimeout: DefaultVerificationTimeout, inFlight: map[string]*responseFlight{},
	}, nil
}

func (s *Service) verifyEffect(ctx context.Context, engagementID shared.ID, action rdom.Action, attempt responsesaga.ResponseAttempt) (Verification, string, shared.ID, error) {
	if s.verify == nil {
		return VerificationUnknown, "", "", nil
	}
	verifierID := strings.TrimSpace(s.verify.Identity())
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return VerificationUnknown, verifierID, "", nil
	}
	req := VerificationRequest{
		TenantID: tenantID, EngagementID: engagementID, Action: cloneAction(action), Target: attempt.Target,
		ExecutorID: strings.TrimSpace(attempt.ExecutorID), Reversal: attempt.IsReversal,
		ExecutorAgentID: attempt.ExecutorAgentID,
		AttemptKey:      strings.TrimSpace(attempt.IdempotencyKey), VerificationChallenge: attempt.VerificationChallenge,
		AttemptedAt: attempt.At.UTC(), DeadlineAt: attempt.DeadlineAt.UTC(),
	}
	receipt, err := s.verify.Verify(ctx, req)
	if err != nil {
		return VerificationPending, verifierID, "", err
	}
	if !receipt.Outcome.Valid() || receipt.Outcome == VerificationPending ||
		verifierID == "" || receipt.EvidenceID.IsZero() || strings.EqualFold(verifierID, strings.TrimSpace(attempt.ExecutorID)) {
		return VerificationUnknown, verifierID, receipt.EvidenceID, nil
	}
	if s.receipts == nil {
		return VerificationUnknown, verifierID, receipt.EvidenceID, nil
	}
	if err := s.receipts.Validate(ctx, req, receipt, verifierID); err != nil {
		if !errors.Is(err, shared.ErrForbidden) && !errors.Is(err, shared.ErrValidation) {
			return VerificationPending, verifierID, "", err
		}
		return VerificationUnknown, verifierID, receipt.EvidenceID, nil
	}
	return receipt.Outcome, verifierID, receipt.EvidenceID, nil
}

// PlanStep is one line of a dry run: the action or reversal that WOULD run, and its argv.
type PlanStep struct {
	Label       string
	Argv        []string
	BlastRadius offensivepolicy.Radius
}

// DryRun enumerates exactly what an action would do — the action and its reversal — and executes NOTHING.
// Same contract as the offensive-policy dry run.
func (s *Service) DryRun(action rdom.Action) ([]PlanStep, error) {
	action = cloneAction(action)
	if err := action.Validate(); err != nil {
		return nil, err
	}
	return []PlanStep{
		{Label: "apply " + string(action.Kind), Argv: action.Argv, BlastRadius: action.BlastRadius},
		{Label: "reverse via " + string(action.Reversal.Kind), Argv: action.Reversal.Argv, BlastRadius: action.BlastRadius},
	}, nil
}

// Decide records a second-human decision and resumes the exact durable response action on approval.
func (s *Service) Decide(ctx context.Context, actionID shared.ID, reviewer string, approve bool, reason string) (Record, error) {
	if actionID.IsZero() || strings.TrimSpace(reviewer) == "" {
		return Record{}, fmt.Errorf("%w: response decision requires an action and reviewer", shared.ErrValidation)
	}
	if isMachine(reviewer) {
		return Record{}, fmt.Errorf("%w: a response decision requires an authenticated human", shared.ErrForbidden)
	}
	if _, ok := shared.TenantFrom(ctx); !ok {
		return Record{}, fmt.Errorf("%w: response decision requires a tenant in context", shared.ErrValidation)
	}
	rec, found, err := s.store.Get(ctx, actionID)
	if err != nil {
		return Record{}, err
	}
	if !found {
		return Record{}, shared.ErrNotFound
	}
	if s.approvals == nil {
		return Record{}, fmt.Errorf("%w: response approval service is unavailable", shared.ErrForbidden)
	}
	if err := rec.AuthorizationTarget.Validate(); err != nil {
		return Record{}, fmt.Errorf("%w: response %s has no durable authorization target", shared.ErrConflict, actionID)
	}
	if rec.AuthorizationTarget.Value != rec.Action.Target.String() {
		return Record{}, fmt.Errorf("%w: response %s authorization target is not action-bound", shared.ErrConflict, actionID)
	}
	if err := bindFingerprint(rec.Action, rec.TargetFingerprint); err != nil {
		return Record{}, fmt.Errorf("%w: response %s has no durable target fingerprint", shared.ErrConflict, actionID)
	}
	reversal := rec.ReversalRequestedBy != ""
	approvalID := actionID
	submitter := rec.SubmittedBy
	if reversal {
		approvalID = shared.ID("revert:" + actionID.String())
		submitter = rec.ReversalRequestedBy
	}
	if strings.TrimSpace(submitter) == "" {
		return Record{}, fmt.Errorf("%w: response approval %s has no durable submitter binding", shared.ErrConflict, approvalID)
	}
	proposal, decision, err := s.approvals.Get(ctx, approvalID)
	if err != nil {
		return Record{}, fmt.Errorf("read response approval %s: %w", approvalID, err)
	}
	if !responseApprovalMatchesRecord(proposal, rec, reversal) {
		return Record{}, fmt.Errorf("%w: response approval %s is not bound to the durable action", shared.ErrForbidden, approvalID)
	}
	approvedRetry := approve && decision.State == agent.ApprovalApproved && !isMachine(decision.DecidedBy) &&
		((!reversal && rec.State == StateApplied && strings.EqualFold(strings.TrimSpace(rec.ApprovedBy), strings.TrimSpace(decision.DecidedBy))) ||
			(reversal && rec.State == StateReverted))
	deniedRetry := !reversal && !approve && rec.State == StateCancelled &&
		(decision.State == agent.ApprovalDenied || decision.State == agent.ApprovalTimeout)
	if approvedRetry || deniedRetry {
		return rec, nil
	}
	if (!reversal && rec.State != StatePending) || (reversal && rec.State != StateApplied) {
		return Record{}, fmt.Errorf("%w: response %s cannot be decided from state %s", shared.ErrConflict, actionID, rec.State)
	}
	if decision.State == agent.ApprovalPending {
		if approve && strings.EqualFold(strings.TrimSpace(submitter), strings.TrimSpace(reviewer)) {
			return Record{}, fmt.Errorf("%w: response submitter cannot approve the same action", shared.ErrForbidden)
		}
		decision, err = s.approvals.Decide(ctx, reviewer, approvalID, approve, reason)
		if err != nil {
			return Record{}, fmt.Errorf("decide response approval %s: %w", approvalID, err)
		}
	}
	if approve && decision.State != agent.ApprovalApproved {
		return Record{}, fmt.Errorf("%w: response %s already has a non-approval decision", shared.ErrConflict, actionID)
	}
	if !approve && decision.State == agent.ApprovalApproved {
		return Record{}, fmt.Errorf("%w: response %s is already approved", shared.ErrConflict, actionID)
	}
	if decision.State == agent.ApprovalApproved {
		if isMachine(decision.DecidedBy) || strings.EqualFold(strings.TrimSpace(submitter), strings.TrimSpace(decision.DecidedBy)) {
			return Record{}, fmt.Errorf("%w: response approval must come from a distinct human", shared.ErrForbidden)
		}
		if reversal {
			return s.Revert(ctx, rec.ID, rec.AuthorizationTarget, rec.TargetFingerprint, decision.DecidedBy)
		}
		return s.Apply(ctx, rec.EngagementID, rec.Action, rec.AuthorizationTarget, rec.TargetFingerprint, decision.DecidedBy)
	}
	if decision.State != agent.ApprovalDenied && decision.State != agent.ApprovalTimeout {
		return Record{}, fmt.Errorf("%w: response %s approval remains pending", shared.ErrConflict, actionID)
	}
	from := rec.State
	if !reversal {
		rec.State = StateCancelled
		rec.ApprovedBy = strings.TrimSpace(decision.DecidedBy)
		if rec.ApprovedBy == "" {
			rec.ApprovedBy = "system"
		}
	}
	auditActor := strings.TrimSpace(decision.DecidedBy)
	if auditActor == "" {
		auditActor = "system"
	}
	rec.UpdatedAt = s.clock.Now().UTC()
	operation := "apply"
	if reversal {
		operation = "revert"
	}
	intent := responseAuditIntent(
		"response-approval-denied:v1:"+rec.TenantID.String()+":"+approvalID.String(),
		auditActor, "response.approval_denied", rec.ID.String(), rec.UpdatedAt,
		map[string]string{"reason": decision.Reason, "operation": operation, "kind": string(rec.Action.Kind), "target": rec.Action.Target.String()},
	)
	transitioned, committed, err := s.store.TransitionWithAudit(ctx, rec, from, intent)
	if err != nil {
		return Record{}, fmt.Errorf("cancel denied response %s: %w", actionID, err)
	}
	if !transitioned {
		return Record{}, fmt.Errorf("%w: response %s changed while recording its decision", shared.ErrConflict, actionID)
	}
	if err := s.deliverResponseAudit(ctx, committed); err != nil {
		return rec, fmt.Errorf("deliver response %s denial audit: %w", actionID, err)
	}
	return rec, nil
}

// PrepareIncidentResponse persists the exact pending action identity required by the incident projection's
// live-action foreign key. It performs no admission, approval, attempt creation, or side effect. Apply reloads
// and validates this immutable record before the governed execution path can continue.
func (s *Service) PrepareIncidentResponse(ctx context.Context, engagementID shared.ID, action rdom.Action, target engagement.Target, fingerprint responsesaga.TargetFingerprint, submitter string) (Record, error) {
	action = cloneAction(action)
	if err := action.Validate(); err != nil {
		return Record{}, err
	}
	if err := bindFingerprint(action, fingerprint); err != nil {
		return Record{}, err
	}
	if !s.exec.Supports(action.Kind) {
		return Record{}, fmt.Errorf("%w: response executor %s does not support action kind %s", shared.ErrValidation, s.exec.Identity(), action.Kind)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	submitter = strings.TrimSpace(submitter)
	if !ok || tenantID.IsZero() || engagementID.IsZero() || submitter == "" {
		return Record{}, fmt.Errorf("%w: incident response preparation requires tenant, engagement, and submitter", shared.ErrValidation)
	}
	if shared.IsMachineActor(submitter) {
		return Record{}, fmt.Errorf("%w: incident response submission requires a human identity", shared.ErrForbidden)
	}
	if target.Value != action.Target.String() {
		return Record{}, fmt.Errorf("%w: admitted target %q does not match the action target %q", shared.ErrForbidden, target.Value, action.Target)
	}
	existing, found, err := s.store.Get(ctx, action.ID)
	if err != nil {
		return Record{}, fmt.Errorf("read incident response action: %w", err)
	}
	if found {
		if !sameAction(existing.Action, action) || existing.EngagementID != engagementID ||
			existing.AuthorizationTarget != target || existing.TargetFingerprint != fingerprint ||
			strings.TrimSpace(existing.SubmittedBy) != submitter {
			return Record{}, fmt.Errorf("%w: incident response action id %s is already bound to different immutable input", shared.ErrConflict, action.ID)
		}
		// Coordinator retries must be able to recover the request or verification projection after the
		// governed response has advanced. Apply remains responsible for validating the lifecycle state.
		return existing, nil
	}
	pending := s.record(tenantID, engagementID, action, target, fingerprint, submitter, StatePending, "", "")
	if err := s.put(ctx, pending); err != nil {
		return Record{}, fmt.Errorf("persist incident response action %s: %w", action.ID, err)
	}
	return pending, nil
}

// Apply executes a response action after: (1) it validates (fail-closed on missing reversal/argv/
// radius/scope), (2) the approver is a HUMAN (a machine identity is refused — no model verdict can
// approve), (3) the admission gate admits it (scope guard + recorded human approval, sealed as evidence),
// and (4) the executed effect stays within the declared blast radius. Re-issuing an applied action is a
// no-op reporting the already-applied state.
func (s *Service) Apply(ctx context.Context, engagementID shared.ID, action rdom.Action, target engagement.Target, fingerprint responsesaga.TargetFingerprint, approver string) (Record, error) {
	action = cloneAction(action)
	if err := action.Validate(); err != nil {
		return Record{}, err
	}
	if err := bindFingerprint(action, fingerprint); err != nil {
		return Record{}, err
	}
	if !s.exec.Supports(action.Kind) {
		return Record{}, fmt.Errorf("%w: response executor %s does not support action kind %s", shared.ErrValidation, s.exec.Identity(), action.Kind)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return Record{}, fmt.Errorf("%w: response apply requires a tenant in context", shared.ErrValidation)
	}
	if err := s.ReconcileHaltDispatches(ctx); err != nil {
		return Record{}, fmt.Errorf("reconcile response halt fence before apply: %w", err)
	}
	haltGeneration, err := s.store.CurrentHaltGeneration(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("read response halt generation: %w", err)
	}
	if isMachine(approver) {
		return Record{}, fmt.Errorf("%w: a response action requires a human approver; %q is a machine identity", shared.ErrForbidden, approver)
	}

	// Bind the ADMITTED target to the EXECUTED target: admission scope-checks the engagement.Target, but
	// execution acts on action.Target — decoupling them would let a caller get an in-scope admission for
	// one asset while hitting another. They must be the same asset.
	if target.Value != action.Target.String() {
		return Record{}, fmt.Errorf("%w: admitted target %q does not match the action target %q", shared.ErrForbidden, target.Value, action.Target)
	}

	existing, found, err := s.store.Get(ctx, action.ID)
	if err != nil {
		return Record{}, err
	}
	if found {
		if !sameAction(existing.Action, action) || existing.EngagementID != engagementID ||
			existing.AuthorizationTarget != target || existing.TargetFingerprint != fingerprint {
			return Record{}, fmt.Errorf("%w: response action id %s is already bound to different immutable input", shared.ErrConflict, action.ID)
		}
		switch existing.State {
		case StateApplied:
			candidate := newAttempt(action, fingerprint, false, responsesaga.StateIssued, haltGeneration, "", s.clock.Now().UTC())
			attempt, attemptFound, attemptErr := s.store.GetAttempt(ctx, candidate.IdempotencyKey)
			if attemptErr != nil {
				return Record{}, attemptErr
			}
			if attemptFound {
				if attempt.Target != fingerprint {
					return Record{}, fmt.Errorf("%w: response %s fingerprint is immutable", shared.ErrConflict, action.ID)
				}
				return s.finishApplied(ctx, ctx, existing, attempt, existing.ApprovedBy)
			}
			return Record{}, fmt.Errorf("%w: response %s is marked applied without a durable execution attempt", shared.ErrConflict, action.ID)
		case StatePending:
			// Resume the admitted operation below. Its execution journal deduplicates a prior delivery.
		default:
			return Record{}, fmt.Errorf("%w: response %s cannot be applied from state %s", shared.ErrConflict, action.ID, existing.State)
		}
	}
	submissionActor := strings.TrimSpace(approver)
	if found {
		if strings.TrimSpace(existing.SubmittedBy) == "" {
			return Record{}, fmt.Errorf("%w: response %s has no durable submitter binding", shared.ErrConflict, action.ID)
		}
		submissionActor = existing.SubmittedBy
	}

	// Admission: the SAME gate as exploitation. Fail-closed — out-of-scope → ErrForbidden, no approval →
	// ErrPendingApproval; nothing executes in either case.
	p := agent.ProposedAction{
		ID: action.ID, SessionID: shared.ID("response:" + action.ID.String()), EngagementID: engagementID,
		Tool: "response." + string(action.Kind), Action: "response." + string(action.Kind),
		Target: target, Argv: action.Argv, Risk: agent.RiskIntrusive, ProposedAt: s.clock.Now().UTC(),
		Rationale: "defensive response: " + string(action.Kind),
	}
	adm, err := s.admit.Admit(ctx, p, approver)
	if err != nil {
		// Record the pending state durably so the kill switch and the list route see the in-flight
		// action. If that write fails the 202 would be a lie (nothing to cancel, nothing to resume), so
		// the persistence error is returned instead of the pending signal.
		if isPending(err) {
			if found {
				return existing, err
			}
			pending := Record{
				ID: action.ID, TenantID: tenantID, EngagementID: engagementID, Action: action,
				AuthorizationTarget: target, TargetFingerprint: fingerprint,
				SubmittedBy: submissionActor, State: StatePending, ApprovedBy: approver, UpdatedAt: s.clock.Now().UTC(),
			}
			if putErr := s.put(ctx, pending); putErr != nil {
				return Record{}, fmt.Errorf("persist pending response %s: %w", action.ID, putErr)
			}
			// Hand the pending record back so the caller learns the server-minted id it can reference.
			return pending, err
		}
		return Record{}, err
	}
	if strings.EqualFold(strings.TrimSpace(submissionActor), strings.TrimSpace(adm.decidedBy)) {
		return Record{}, fmt.Errorf("%w: response submitter cannot approve the same action", shared.ErrForbidden)
	}

	// The parent action and the attempt journal must both exist before a side effect. The journal insert is
	// atomic and idempotent, so a retry either resumes this exact fingerprint/key or fails on a collision.
	pending := s.record(tenantID, engagementID, action, target, fingerprint, submissionActor, StatePending, adm.decidedBy, adm.evidenceID)
	if err := s.put(ctx, pending); err != nil {
		return Record{}, fmt.Errorf("persist approved response %s before execution: %w", action.ID, err)
	}
	attempt := s.newAttempt(action, fingerprint, false, responsesaga.StateIssued, haltGeneration, adm.decidedBy, s.clock.Now().UTC())
	attempt.ExecutorID = strings.TrimSpace(s.exec.Identity())
	attempt.ExecutorAgentID, err = s.exec.ResolveAgent(ctx, tenantID, fingerprint)
	if err != nil {
		return Record{}, fmt.Errorf("resolve response %s executor agent: %w", action.ID, err)
	}
	if attempt.ExecutorAgentID.IsZero() {
		return Record{}, fmt.Errorf("%w: response %s executor resolved no enrolled agent identity", shared.ErrForbidden, action.ID)
	}
	if err := setVerificationChallenge(&attempt); err != nil {
		return Record{}, fmt.Errorf("generate response %s verification challenge before dispatch: %w", action.ID, err)
	}
	attempt, _, err = s.store.StartAttempt(ctx, attempt)
	if err != nil {
		if errors.Is(err, responsesaga.ErrStaleHaltGeneration) || errors.Is(err, responsesaga.ErrHaltLatched) {
			cancelled := pending
			cancelled.State = StateCancelled
			cancelled.UpdatedAt = s.clock.Now().UTC()
			_, _ = s.store.Transition(ctx, cancelled, StatePending)
		}
		return Record{}, fmt.Errorf("journal response %s before execution: %w", action.ID, err)
	}
	switch attempt.State {
	case responsesaga.StateCommandApplied, responsesaga.StateVerifying,
		responsesaga.StateVerifiedSucceeded, responsesaga.StateVerificationFailed,
		responsesaga.StateVerificationUnknown, responsesaga.StateTimedOut:
		if !attemptOutcomeInRadius(action.BlastRadius, attempt) {
			return Record{}, fmt.Errorf("%w: response %s has no durable in-radius command outcome", shared.ErrConflict, action.ID)
		}
		return s.finishApplied(ctx, ctx, pending, attempt, approver)
	case responsesaga.StateOutcomeUnknown:
		return s.reconcileUnknownApply(ctx, pending, attempt)
	case responsesaga.StateCommandFailed:
		return Record{}, fmt.Errorf("%w: response %s has a durable failed execution attempt", shared.ErrConflict, action.ID)
	case responsesaga.StateExecuting:
		return Record{}, fmt.Errorf("%w: response %s execution outcome is ambiguous and requires telemetry reconciliation", shared.ErrConflict, action.ID)
	case responsesaga.StateIssued:
		if s.attemptExpired(attempt) {
			return s.expireAttempt(ctx, pending, attempt, responsesaga.StateCommandFailed, "dispatch_deadline_exceeded")
		}
		// This delivery may claim the issued attempt after its audit intent is durable.
	default:
		return Record{}, fmt.Errorf("%w: response %s has unexpected attempt state %s", shared.ErrConflict, action.ID, attempt.State)
	}
	if err := s.recordExecutionIntent(ctx, attempt.DecidedBy, action, attempt, adm.decidedBy); err != nil {
		return Record{}, fmt.Errorf("persist response %s execution audit intent: %w", action.ID, err)
	}
	claimAt := s.clock.Now().UTC()
	attempt, claimed, err := s.store.ClaimAttempt(ctx, attempt.IdempotencyKey, responsesaga.StateIssued, responsesaga.StateExecuting, claimAt)
	if err != nil {
		return Record{}, fmt.Errorf("claim response %s execution: %w", action.ID, err)
	}
	if !claimed {
		if attempt.State == responsesaga.StateIssued && !claimAt.Before(attempt.DeadlineAt) {
			return s.expireAttempt(ctx, pending, attempt, responsesaga.StateCommandFailed, "dispatch_deadline_exceeded")
		}
		if attempt.State == responsesaga.StateCommandApplied || attempt.State == responsesaga.StateVerifying ||
			attempt.State == responsesaga.StateVerifiedSucceeded || attempt.State == responsesaga.StateVerificationFailed ||
			attempt.State == responsesaga.StateVerificationUnknown || attempt.State == responsesaga.StateTimedOut {
			if !attemptOutcomeInRadius(action.BlastRadius, attempt) {
				return Record{}, fmt.Errorf("%w: response %s has no durable in-radius command outcome", shared.ErrConflict, action.ID)
			}
			return s.finishApplied(ctx, ctx, pending, attempt, approver)
		}
		if attempt.State == responsesaga.StateOutcomeUnknown {
			return s.reconcileUnknownApply(ctx, pending, attempt)
		}
		return Record{}, fmt.Errorf("%w: response %s execution is already claimed and requires reconciliation", shared.ErrConflict, action.ID)
	}
	// Atomically recheck the halt-visible action state and register a cancellable in-flight operation. The
	// attempt CAS above provides cross-process single-claim behavior; an ambiguous claimed attempt is never
	// automatically executed again after a crash.
	s.effectMu.Lock()
	current, found, err := s.store.Get(ctx, action.ID)
	if err != nil {
		s.effectMu.Unlock()
		return Record{}, fmt.Errorf("recheck response %s before execution: %w", action.ID, err)
	}
	if !found || current.State != StatePending {
		s.effectMu.Unlock()
		attempt.CommandOutcome = "cancelled_before_execution"
		_, _ = s.transitionAttempt(ctx, attempt, responsesaga.StateExecuting, responsesaga.StateCommandFailed)
		return Record{}, fmt.Errorf("%w: response %s was halted before execution", shared.ErrForbidden, action.ID)
	}
	execCtx, finishFlight, err := s.registerFlightLocked(ctx, tenantID, action.ID, false)
	s.effectMu.Unlock()
	if err != nil {
		return Record{}, err
	}
	defer finishFlight()
	execCtx, cancelDeadline := s.attemptContext(execCtx, attempt)
	defer cancelDeadline()
	if err := s.admit.Reauthorize(execCtx, adm); err != nil {
		attempt.CommandOutcome = "dispatch_reauthorization_refused"
		_, _ = s.transitionAttempt(ctx, attempt, responsesaga.StateExecuting, responsesaga.StateCommandFailed)
		return Record{}, fmt.Errorf("reauthorize response %s at dispatch: %w", action.ID, err)
	}
	if err := execCtx.Err(); err != nil {
		attempt.CommandOutcome = "cancelled_before_execution"
		_, _ = s.transitionAttempt(ctx, attempt, responsesaga.StateExecuting, responsesaga.StateCommandFailed)
		return Record{}, errors.Join(fmt.Errorf("%w: response %s was halted before execution", shared.ErrForbidden, action.ID), err)
	}
	currentAt := s.clock.Now().UTC()
	currentAttempt, err := s.store.AttemptStillCurrent(ctx, attempt.IdempotencyKey, responsesaga.StateExecuting, currentAt)
	if err != nil {
		return Record{}, fmt.Errorf("recheck response %s execution fence: %w", action.ID, err)
	}
	if !currentAttempt {
		if !currentAt.Before(attempt.DeadlineAt) {
			return s.expireAttempt(ctx, pending, attempt, responsesaga.StateCommandFailed, "dispatch_deadline_exceeded_after_claim")
		}
		return Record{}, fmt.Errorf("%w: response %s was halted before execution", shared.ErrForbidden, action.ID)
	}

	// Execute argv-only. The admitted payload and executed argv are identical. The durable key and stable
	// fingerprint travel to the executor so an at-least-once redelivery cannot double-apply or hit a
	// recycled target.
	out, err := s.exec.Execute(execCtx, ExecRequest{
		TenantID: tenantID, EngagementID: engagementID, ActionID: action.ID, AgentID: attempt.ExecutorAgentID, Action: cloneAction(action),
		Argv: slices.Clone(action.Argv), Target: action.Target, Fingerprint: fingerprint,
		AuthorizationTarget: target,
		IdempotencyKey:      attempt.IdempotencyKey, Declared: action.BlastRadius,
		HaltGeneration: attempt.HaltGeneration, VerificationChallenge: attempt.VerificationChallenge,
		IssuedAt: attempt.At, DeadlineAt: attempt.DeadlineAt,
	})
	journalCtx, cancelJournal := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelJournal()
	ctx = journalCtx
	if err == nil && out.EnforcedHaltGeneration != attempt.HaltGeneration {
		err = fmt.Errorf("%w: response executor did not enforce halt generation %d", shared.ErrForbidden, attempt.HaltGeneration)
	}
	if err != nil {
		attempt.CommandOutcome = "executor_error_outcome_unknown"
		attempt, journalErr := s.transitionAttempt(ctx, attempt, responsesaga.StateExecuting, responsesaga.StateOutcomeUnknown)
		if journalErr != nil {
			return Record{}, errors.Join(fmt.Errorf("execute response %s: %w", action.ID, err), fmt.Errorf("persist failed response attempt: %w", journalErr))
		}
		execErr := fmt.Errorf("execute response %s: %w", action.ID, err)
		if auditErr := s.recordOutcome(ctx, "response.execution_outcome_unknown", attempt.DecidedBy, action, attempt, nil); auditErr != nil {
			return Record{}, errors.Join(execErr, fmt.Errorf("persist failed response audit: %w", auditErr))
		}
		return Record{}, execErr
	}
	if execCtx.Err() != nil || s.attemptExpired(attempt) {
		attempt.CommandOutcome = "completed_after_halt"
		if s.attemptExpired(attempt) || errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			attempt.CommandOutcome = "completed_after_deadline"
		}
		attempt.ObservedRadius = out.ObservedRadius
		attempt.AffectedCount = out.AffectedCount
		attempt.AlreadyApplied = out.AlreadyApplied
		attempt, journalErr := s.transitionAttempt(ctx, attempt, responsesaga.StateExecuting, responsesaga.StateOutcomeUnknown)
		if journalErr != nil {
			return Record{}, fmt.Errorf("persist response %s ambiguous post-halt outcome: %w", action.ID, journalErr)
		}
		rec := s.record(tenantID, engagementID, action, target, fingerprint, submissionActor, StateViolation, adm.decidedBy, adm.evidenceID)
		if transitioned, transitionErr := s.store.Transition(ctx, rec, StatePending); transitionErr != nil {
			return Record{}, fmt.Errorf("persist response %s post-halt state: %w", action.ID, transitionErr)
		} else if !transitioned {
			if current, currentFound, getErr := s.store.Get(ctx, action.ID); getErr == nil && currentFound {
				rec = current
			}
		}
		haltErr := fmt.Errorf("%w: response %s completed after its kill-switch cancellation", shared.ErrForbidden, action.ID)
		if auditErr := s.recordOutcome(ctx, "response.completed_after_halt", attempt.DecidedBy, action, attempt, nil); auditErr != nil {
			return rec, errors.Join(haltErr, fmt.Errorf("persist post-halt response audit: %w", auditErr))
		}
		return rec, haltErr
	}
	attempt.ObservedRadius = out.ObservedRadius
	attempt.AffectedCount = out.AffectedCount
	attempt.AlreadyApplied = out.AlreadyApplied
	// Validate the complete observed effect before entering a journal state eligible to repair the parent
	// projection after a crash. An unsafe outcome is durable but can never be promoted to Applied.
	if !attemptOutcomeInRadius(action.BlastRadius, attempt) {
		attempt.CommandOutcome = "blast_radius_violation"
		attempt, err = s.transitionAttempt(ctx, attempt, responsesaga.StateExecuting, responsesaga.StateOutcomeUnknown)
		if err != nil {
			return Record{}, fmt.Errorf("persist response %s blast-radius outcome: %w", action.ID, err)
		}
		rec := s.record(tenantID, engagementID, action, target, fingerprint, submissionActor, StateViolation, adm.decidedBy, adm.evidenceID)
		if err := s.transition(ctx, rec, StatePending); err != nil {
			return rec, fmt.Errorf("persist response %s blast-radius violation: %w", action.ID, err)
		}
		meta := map[string]string{
			"declared": string(action.BlastRadius), "observed": string(out.ObservedRadius), "affected": fmt.Sprint(out.AffectedCount),
		}
		violationErr := fmt.Errorf("%w: response %s effect exceeded its declared single-target radius (observed=%s affected=%d)", shared.ErrForbidden, action.ID, out.ObservedRadius, out.AffectedCount)
		if auditErr := s.recordOutcome(ctx, "response.blast_radius_violation", attempt.DecidedBy, action, attempt, meta); auditErr != nil {
			return rec, errors.Join(violationErr, fmt.Errorf("persist blast-radius audit: %w", auditErr))
		}
		return rec, violationErr
	}
	if out.AlreadyApplied {
		attempt.CommandOutcome = "already_applied"
	} else {
		attempt.CommandOutcome = "applied"
	}
	attempt, err = s.transitionAttempt(ctx, attempt, responsesaga.StateExecuting, responsesaga.StateCommandApplied)
	if err != nil {
		return Record{}, fmt.Errorf("persist response %s command outcome after execution: %w", action.ID, err)
	}
	if out.AlreadyApplied {
		rec := s.record(tenantID, engagementID, action, target, fingerprint, submissionActor, StatePending, adm.decidedBy, adm.evidenceID)
		return s.finishApplied(ctx, execCtx, rec, attempt, approver)
	}
	rec := s.record(tenantID, engagementID, action, target, fingerprint, submissionActor, StatePending, adm.decidedBy, adm.evidenceID)
	return s.finishApplied(ctx, execCtx, rec, attempt, approver)
}

// finishApplied repairs the action projection from the durable command journal after a crash and advances
// telemetry verification without ever reissuing an already-recorded command.
func (s *Service) finishApplied(ctx, verifyCtx context.Context, rec Record, attempt responsesaga.ResponseAttempt, approver string) (Record, error) {
	if (attempt.State == responsesaga.StateCommandApplied || attempt.State == responsesaga.StateVerifying) && s.attemptExpired(attempt) {
		return s.expireAttempt(ctx, rec, attempt, responsesaga.StateTimedOut, "verification_deadline_exceeded")
	}
	if attempt.State == responsesaga.StateVerifiedSucceeded {
		if err := s.revalidatePersistedReceipt(ctx, rec, attempt); err != nil {
			return Record{}, fmt.Errorf("revalidate response %s verification receipt: %w", rec.ID, err)
		}
	}
	from := rec.State
	rec.State = StateApplied
	if rec.AppliedAt.IsZero() {
		rec.AppliedAt = s.clock.Now().UTC()
	}
	rec.UpdatedAt = s.clock.Now().UTC()
	switch attempt.State {
	case responsesaga.StateVerifiedSucceeded:
		rec.Verification = VerificationSucceeded
	case responsesaga.StateVerificationFailed:
		rec.Verification = VerificationFailed
	case responsesaga.StateVerificationUnknown, responsesaga.StateTimedOut:
		rec.Verification = VerificationUnknown
	}
	actor := rec.ApprovedBy
	if actor == "" {
		actor = approver
	}
	appliedIntent := responseOutcomeAuditIntent("response.applied", actor, rec.Action, attempt, map[string]string{"command_outcome": attempt.CommandOutcome})
	transitioned, committedApplied, err := s.store.TransitionWithAudit(ctx, rec, from, appliedIntent)
	if err != nil {
		return Record{}, fmt.Errorf("persist applied response %s with audit intent: %w", rec.ID, err)
	}
	if !transitioned {
		return Record{}, fmt.Errorf("%w: response %s state changed while applying its command outcome", shared.ErrConflict, rec.ID)
	}
	if err := s.deliverResponseAudit(ctx, committedApplied); err != nil {
		return rec, fmt.Errorf("deliver response %s applied audit: %w", rec.ID, err)
	}
	if attempt.State != responsesaga.StateCommandApplied && attempt.State != responsesaga.StateVerifying {
		if event := verificationAuditEvent(rec.Verification); event != "" {
			if err := s.recordOutcome(ctx, event, actor, rec.Action, attempt, map[string]string{"verification": string(rec.Verification)}); err != nil {
				return Record{}, fmt.Errorf("persist response %s verification audit: %w", rec.ID, err)
			}
		}
		if rec.Verification != VerificationPending && rec.Verification != VerificationSucceeded {
			return rec, fmt.Errorf("%w: response %s effect was not verified (outcome=%s)", shared.ErrConflict, rec.ID, rec.Verification)
		}
		return rec, nil
	}
	if s.verify == nil {
		return rec, nil
	}
	if attempt.State == responsesaga.StateCommandApplied {
		var err error
		attempt, err = s.transitionAttempt(ctx, attempt, responsesaga.StateCommandApplied, responsesaga.StateVerifying)
		if err != nil {
			return Record{}, fmt.Errorf("persist response %s verification start: %w", rec.ID, err)
		}
	}

	var verificationErr error
	rec.Verification, attempt.VerifierID, attempt.VerificationEvidenceID, verificationErr = s.verifyEffect(verifyCtx, rec.EngagementID, rec.Action, attempt)
	if rec.Verification == VerificationPending {
		if s.attemptExpired(attempt) {
			return s.expireAttempt(ctx, rec, attempt, responsesaga.StateTimedOut, "verification_deadline_exceeded")
		}
		return rec, verificationPendingError(rec.ID, "has no signed post-condition yet", verificationErr)
	}
	to := responsesaga.StateVerificationUnknown
	if verifyErr := verifyCtx.Err(); verifyErr != nil {
		rec.Verification = VerificationUnknown
		attempt.VerificationOutcome = responsesaga.VerificationUnknown
		_, committed, err := s.commitAttemptOutcome(ctx, attempt, responsesaga.StateVerifying, to,
			"response.verification_unknown", actor, rec.Action, map[string]string{"verification": string(rec.Verification)})
		if err != nil {
			return Record{}, fmt.Errorf("persist response %s interrupted verification: %w", rec.ID, err)
		}
		if err := s.transition(ctx, rec, StateApplied); err != nil {
			return Record{}, fmt.Errorf("persist response %s interrupted verification projection: %w", rec.ID, err)
		}
		if err := s.deliverResponseAudit(ctx, committed); err != nil {
			return Record{}, errors.Join(fmt.Errorf("persist response %s interrupted verification audit: %w", rec.ID, err), verifyErr)
		}
		return rec, errors.Join(fmt.Errorf("%w: response %s verification was interrupted", shared.ErrSaturated, rec.ID), verifyErr)
	}
	switch rec.Verification {
	case VerificationSucceeded:
		to = responsesaga.StateVerifiedSucceeded
		attempt.VerificationOutcome = responsesaga.VerificationSucceeded
	case VerificationFailed:
		to = responsesaga.StateVerificationFailed
		attempt.VerificationOutcome = responsesaga.VerificationFailed
	default:
		attempt.VerificationOutcome = responsesaga.VerificationUnknown
	}
	event := verificationAuditEvent(rec.Verification)
	attempt, committed, err := s.commitAttemptOutcome(ctx, attempt, responsesaga.StateVerifying, to,
		event, actor, rec.Action, map[string]string{"verification": string(rec.Verification)})
	if err != nil {
		return Record{}, fmt.Errorf("persist response %s verification outcome: %w", rec.ID, err)
	}
	if err := s.transition(ctx, rec, StateApplied); err != nil {
		return Record{}, fmt.Errorf("persist response %s verified projection: %w", rec.ID, err)
	}
	if err := s.deliverResponseAudit(ctx, committed); err != nil {
		return Record{}, fmt.Errorf("deliver response %s verification audit: %w", rec.ID, err)
	}
	if rec.Verification != VerificationSucceeded {
		return rec, fmt.Errorf("%w: response %s effect was not verified (outcome=%s)", shared.ErrConflict, rec.ID, rec.Verification)
	}
	return rec, nil
}

func (s *Service) revalidatePersistedReceipt(ctx context.Context, rec Record, attempt responsesaga.ResponseAttempt) error {
	if s.receipts == nil {
		return fmt.Errorf("%w: persisted response success has no receipt validator", shared.ErrForbidden)
	}
	outcome := rdom.Verification(attempt.VerificationOutcome)
	if outcome != VerificationSucceeded || attempt.VerificationEvidenceID.IsZero() || strings.TrimSpace(attempt.VerifierID) == "" {
		return fmt.Errorf("%w: persisted response success has incomplete verification provenance", shared.ErrForbidden)
	}
	req := VerificationRequest{
		TenantID:              rec.TenantID,
		EngagementID:          rec.EngagementID,
		Action:                cloneAction(rec.Action),
		Target:                attempt.Target,
		ExecutorID:            strings.TrimSpace(attempt.ExecutorID),
		ExecutorAgentID:       attempt.ExecutorAgentID,
		Reversal:              attempt.IsReversal,
		AttemptKey:            attempt.IdempotencyKey,
		VerificationChallenge: attempt.VerificationChallenge,
		AttemptedAt:           attempt.At,
		DeadlineAt:            attempt.DeadlineAt,
	}
	receipt := VerificationReceipt{Outcome: outcome, EvidenceID: attempt.VerificationEvidenceID}
	if err := s.receipts.Validate(ctx, req, receipt, attempt.VerifierID); err != nil {
		return fmt.Errorf("%w: persisted response verification evidence is no longer trusted", shared.ErrForbidden)
	}
	return nil
}

// VerifiedProvenance returns a successful apply attempt only after revalidating its persisted evidence.
// This is the read seam used by the incident event bridge; callers cannot supply verifier provenance.
func (s *Service) VerifiedProvenance(ctx context.Context, actionID shared.ID) (VerificationProvenance, error) {
	if actionID.IsZero() {
		return VerificationProvenance{}, fmt.Errorf("%w: response provenance requires an action id", shared.ErrValidation)
	}
	rec, found, err := s.store.Get(ctx, actionID)
	if err != nil {
		return VerificationProvenance{}, err
	}
	if !found {
		return VerificationProvenance{}, fmt.Errorf("%w: response action %s", shared.ErrNotFound, actionID)
	}
	attempt, found, err := s.store.GetAttempt(ctx, responseAttemptKey(rec.Action, false))
	if err != nil {
		return VerificationProvenance{}, err
	}
	if !found || attempt.ActionID != actionID || attempt.IsReversal || attempt.State != responsesaga.StateVerifiedSucceeded ||
		rec.Verification != VerificationSucceeded {
		return VerificationProvenance{}, fmt.Errorf("%w: response action %s has no verified apply attempt", shared.ErrConflict, actionID)
	}
	if err := s.revalidatePersistedReceipt(ctx, rec, attempt); err != nil {
		return VerificationProvenance{}, err
	}
	return VerificationProvenance{
		ActionID: actionID, EngagementID: rec.EngagementID, ActionDigest: responseActionDigest(rec.Action),
		Target: attempt.Target, AttemptKey: attempt.IdempotencyKey, ExecutorID: strings.TrimSpace(attempt.ExecutorID),
		VerifierID: strings.TrimSpace(attempt.VerifierID), EvidenceID: attempt.VerificationEvidenceID,
	}, nil
}

func verificationAuditEvent(v Verification) string {
	switch v {
	case VerificationSucceeded:
		return "response.verified"
	case VerificationFailed:
		return "response.verification_failed"
	case VerificationUnknown:
		return "response.verification_unknown"
	default:
		return ""
	}
}

func responseVerificationOutcome(v Verification) responsesaga.VerificationOutcome {
	switch v {
	case VerificationSucceeded:
		return responsesaga.VerificationSucceeded
	case VerificationFailed:
		return responsesaga.VerificationFailed
	default:
		return responsesaga.VerificationUnknown
	}
}

// ListByState returns the tenant's response actions in a state (from ctx tenant), for the operator's
// view of what is admitted-but-not-applied — the same set the kill switch cancels.
func (s *Service) ListByState(ctx context.Context, state State) ([]Record, error) {
	return s.store.ListByState(ctx, state)
}

package response

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/responsejournal"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/signing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/incidentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseexecute"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// fakeEngRepo returns one in-scope, authorized engagement for every id — enough to drive the REAL
// admission gate (guard + approval + evidence) in this end-to-end test.
type fakeEngRepo struct{ eng *engagement.Engagement }

func (f *fakeEngRepo) Create(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Update(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Delete(context.Context, shared.ID) error              { return nil }
func (f *fakeEngRepo) GetByID(context.Context, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (f *fakeEngRepo) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (*fakeEngRepo) GetByHostAssetID(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return nil, shared.ErrNotFound
}
func (*fakeEngRepo) GetByProjectID(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return nil, shared.ErrNotFound
}
func (*fakeEngRepo) ProjectContexts(context.Context, shared.ID, []shared.ID) (map[shared.ID]*engagement.Engagement, error) {
	return map[shared.ID]*engagement.Engagement{}, nil
}
func (*fakeEngRepo) List(context.Context, shared.ID) ([]*engagement.Engagement, error) {
	return nil, nil
}

type e2eIDs struct{ n int }

func (g *e2eIDs) NewID() shared.ID { g.n++; return shared.ID("ev-" + string(rune('0'+g.n))) }

type e2eObservationDispatcher struct {
	observations interface {
		ports.ResponseVerificationAuditStore
		ports.ResponseTargetEvidenceReceiptStore
	}
	keys     ports.AgentSigningKeyStore
	timeline ports.EndpointTimelineStore
	coverage ports.CoverageWindowStore
}

type e2eAgentActuator struct {
	commands []fleetagent.ResponseCommand
}

func (a *e2eAgentActuator) ExecuteResponse(_ context.Context, command fleetagent.ResponseCommand) (responseexecute.ActuatorOutcome, error) {
	a.commands = append(a.commands, command)
	return responseexecute.ActuatorOutcome{ObservedRadius: offensivepolicy.RadiusStateChanging, AffectedCount: 1}, nil
}

type e2eAgentExecutor struct {
	service  *responseexecute.Service
	private  ed25519.PrivateKey
	now      time.Time
	actuator *e2eAgentActuator
}

type e2eCommandKeys struct{ public ed25519.PublicKey }

func (k e2eCommandKeys) ResolveResponseCommandKey(context.Context, string) (fleetagent.ResponseCommandSigningKey, error) {
	return fleetagent.ResponseCommandSigningKey{
		KeyID: evdom.KeyFingerprint(k.public), PublicKey: k.public,
		NotBefore: time.Unix(0, 0).UTC(), NotAfter: time.Unix(1<<31, 0).UTC(),
	}, nil
}

func newE2EAgentExecutor(t *testing.T, clock fixedClock) *e2eAgentExecutor {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := responsejournal.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	actuator := &e2eAgentActuator{}
	service, err := responseexecute.NewService("response-executor", "asset-1", e2eCommandKeys{public: public}, journal, actuator, clock)
	if err != nil {
		t.Fatal(err)
	}
	return &e2eAgentExecutor{service: service, private: private, now: clock.Now(), actuator: actuator}
}

func (*e2eAgentExecutor) Identity() string        { return "agent:response-executor" }
func (*e2eAgentExecutor) Supports(rdom.Kind) bool { return true }
func (*e2eAgentExecutor) ResolveAgent(context.Context, shared.ID, responsesaga.TargetFingerprint) (shared.ID, error) {
	return "response-executor", nil
}
func (e *e2eAgentExecutor) count() int          { return len(e.actuator.commands) }
func (e *e2eAgentExecutor) reversal(i int) bool { return e.actuator.commands[i].Reversal }
func (e *e2eAgentExecutor) Halt(ctx context.Context, _ shared.ID, generation int64) error {
	return e.service.Halt(ctx, generation)
}

func (e *e2eAgentExecutor) Execute(ctx context.Context, req ExecRequest) (ExecOutcome, error) {
	digest, err := rdom.CanonicalDigest(req.Action)
	if err != nil {
		return ExecOutcome{}, err
	}
	command := fleetagent.ResponseCommand{
		ProtocolVersion:       fleetagent.ResponseCommandProtocolVersion,
		CommandID:             shared.ID("command:" + req.IdempotencyKey),
		TenantID:              req.TenantID,
		AgentID:               req.AgentID,
		AssetID:               req.Fingerprint.ProcessAssetID,
		EngagementID:          req.EngagementID,
		Action:                req.Action,
		ActionDigest:          digest,
		AttemptKey:            req.IdempotencyKey,
		VerificationChallenge: req.VerificationChallenge,
		AuthorizationTarget:   req.AuthorizationTarget,
		Target:                req.Fingerprint,
		Reversal:              req.IsReversal,
		HaltGeneration:        req.HaltGeneration,
		IssuedAt:              e.now.Add(-time.Second),
		NotAfter:              e.now.Add(time.Minute),
		SigningKeyID:          evdom.KeyFingerprint(e.private.Public().(ed25519.PublicKey)),
	}
	command.Signature = fleetagent.SignResponseCommand(e.private, command)
	result, err := e.service.Execute(ctx, command, "e2e-lease", command.NotAfter)
	if err != nil {
		return ExecOutcome{}, err
	}
	return ExecOutcome{
		ObservedRadius: result.ObservedRadius, AffectedCount: result.AffectedCount,
		AlreadyApplied: result.AlreadyApplied, EnforcedHaltGeneration: req.HaltGeneration,
	}, nil
}

func (d *e2eObservationDispatcher) EnsureObservation(ctx context.Context, req VerificationRequest) error {
	source, key, err := newE2EVerificationSource(req, VerificationSucceeded)
	if err != nil {
		return err
	}
	if err := d.keys.Register(ctx, key); err != nil {
		return err
	}
	if _, err := d.observations.AppendResponseTargetEvidenceReceipt(ctx, source.Receipt); err != nil {
		return err
	}
	if err := d.timeline.AppendTimeline(ctx, source.Timeline); err != nil {
		return err
	}
	for _, window := range source.Coverage {
		if _, err := d.coverage.AppendCoverageWindow(ctx, window); err != nil {
			return err
		}
	}
	observation := ports.AcceptedResponseVerification{
		Report: source.Report, ObserverID: source.Report.ObserverIdentity(),
		SignedContentDigest: source.SignedContentDigest, RecordedAt: source.RecordedAt,
	}
	auditID := "audit:" + req.AttemptKey
	if _, err := d.observations.AppendResponseVerificationWithAudit(ctx, observation, ports.FleetAuditIntent{
		ID: auditID, Entry: ports.AuditEntry{
			Actor: observation.ObserverID, Action: "fleet.response_verification.ingest", Target: source.Report.ReportID.String(),
			At: source.RecordedAt, Metadata: map[string]string{"idempotency_key": auditID},
		},
	}); err != nil {
		return err
	}
	return nil
}

func newE2EVerificationSource(req VerificationRequest, outcome Verification) (VerificationSource, fleetagent.AgentSigningKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return VerificationSource{}, fleetagent.AgentSigningKey{}, err
	}
	observedAt := req.AttemptedAt.Add(time.Second).UTC()
	key, err := fleetagent.NewSigningKey("observer-1", fleetagent.PurposeResponseResult, public, observedAt.Add(-time.Hour), observedAt.Add(time.Hour))
	if err != nil {
		return VerificationSource{}, fleetagent.AgentSigningKey{}, err
	}
	replacementID := shared.ID("")
	if req.Reversal {
		replacementID = req.Target.ProcessEntityID + "-replacement"
	}
	receipt := fleetagent.ResponseTargetEvidenceReceipt{
		Version: fleetagent.ResponseTargetEvidenceReceiptVersion, ReceiptID: shared.ID("receipt:" + req.AttemptKey), TenantID: req.TenantID,
		EngagementID: req.EngagementID, ActionID: req.Action.ID, ActionDigest: responseActionDigest(req.Action), AttemptKey: req.AttemptKey,
		VerificationChallenge: req.VerificationChallenge, Target: req.Target, Reversal: req.Reversal, AttemptedAt: req.AttemptedAt.UTC().Truncate(time.Microsecond),
		WindowUntil: observedAt.Add(time.Microsecond), RecordedAt: observedAt.Add(time.Second), SourceAgentID: "observer-1",
		SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("observer-1")), SourceHostID: "observer-1", TimelineComplete: outcome != VerificationUnknown,
		CoverageComplete: outcome != VerificationUnknown, Reasons: []string{"complete"},
	}
	if outcome == VerificationUnknown {
		receipt.TimelineComplete, receipt.CoverageComplete, receipt.Reasons = false, false, []string{"coverage_incomplete"}
	}
	report := fleetagent.ResponseVerificationReport{
		ProtocolVersion:            fleetagent.TelemetryProtocolVersion,
		ReportID:                   shared.ID("report:" + req.AttemptKey),
		AgentID:                    "observer-1",
		HostID:                     "observer-1",
		AgentSessionID:             fleetagent.CanonicalSessionID("observer-1"),
		AssetID:                    req.Target.ProcessAssetID,
		EngagementID:               req.EngagementID,
		ActionID:                   req.Action.ID,
		ActionDigest:               responseActionDigest(req.Action),
		AttemptKey:                 req.AttemptKey,
		ReceiptID:                  receipt.ReceiptID,
		ReceiptDigest:              "",
		VerificationChallenge:      req.VerificationChallenge,
		Target:                     req.Target,
		Reversal:                   req.Reversal,
		ObservedAt:                 observedAt,
		ReplacementProcessEntityID: replacementID,
		KeyID:                      key.KeyID,
	}
	report.Signature = fleetagent.SignResponseVerification(private, report)
	digest := sha256.Sum256(fleetagent.ResponseVerificationMessage(report))
	source := VerificationSource{Report: report, RecordedAt: observedAt, SignedContentDigest: hex.EncodeToString(digest[:])}
	if outcome != VerificationUnknown {
		window := sensorstate.CoverageWindow{
			AssetID: req.Target.ProcessAssetID, AgentID: report.AgentID, HostID: report.HostID,
			Since: req.AttemptedAt.UTC().Truncate(time.Microsecond), Until: observedAt.Add(time.Microsecond),
			InputDigest: strings.Repeat("a", 64), CreatedAt: observedAt.Add(time.Second), BatchCount: 1,
			States: []detection.ClassCoverage{{
				Class: detection.ClassProcess, HostID: report.HostID, AgentID: report.AgentID,
				State: detection.StateActive, Since: req.AttemptedAt.UTC().Truncate(time.Microsecond),
			}},
		}
		window.Vector = sensorstate.BuildCoverageVector(window)
		window.Revision = sensorstate.RevisionFor(window)
		if err := window.Validate(); err != nil {
			return VerificationSource{}, fleetagent.AgentSigningKey{}, err
		}
		source.Coverage = []sensorstate.CoverageWindow{window}
		entityID, kind := req.Target.ProcessEntityID, endpoint.TimelineProcessExit
		if req.Reversal && outcome == VerificationSucceeded {
			entityID, kind = replacementID, endpoint.TimelineProcessStart
		} else if outcome == VerificationFailed {
			kind = endpoint.TimelineProcessExec
		}
		source.Timeline = []endpoint.TimelineEntry{{
			OccurredAt: observedAt, TenantID: req.TenantID, AssetID: req.Target.ProcessAssetID,
			SourceAgentID: report.AgentID, SourceAgentSessionID: shared.ID(report.AgentSessionID),
			EntityKind: endpoint.EntityProcess, EntityID: entityID, Kind: kind, EventID: shared.ID("event:" + req.AttemptKey),
		}}
		if req.Reversal && outcome == VerificationSucceeded {
			source.Timeline = append([]endpoint.TimelineEntry{{
				OccurredAt: observedAt.Add(-time.Nanosecond), TenantID: req.TenantID, AssetID: req.Target.ProcessAssetID,
				SourceAgentID: report.AgentID, SourceAgentSessionID: shared.ID(report.AgentSessionID),
				EntityKind: endpoint.EntityProcess, EntityID: req.Target.ProcessEntityID, Kind: endpoint.TimelineProcessExit, EventID: shared.ID("exit:" + req.AttemptKey),
			}}, source.Timeline...)
		}
	}
	receipt.Timeline = append([]endpoint.TimelineEntry(nil), source.Timeline...)
	receipt.Coverage = append([]sensorstate.CoverageWindow(nil), source.Coverage...)
	receipt.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(receipt)
	report.ReceiptDigest = receipt.Digest
	report.Signature = fleetagent.SignResponseVerification(private, report)
	digest = sha256.Sum256(fleetagent.ResponseVerificationMessage(report))
	source.Report, source.SignedContentDigest, source.Receipt = report, hex.EncodeToString(digest[:]), receipt
	return source, key, nil
}

func e2eEngagement(now time.Time) *engagement.Engagement {
	e, _ := engagement.New(shared.ID("eng-1"), shared.ID("t1"), "Acme", "Acme", now)
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	_ = e.SetAuthorizationWindow(&from, &to, "UTC", now)
	e.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.acme.io"}}}
	return e
}

// TestGovernedResponseEndToEnd drives the full governed-response loop through the real admission gate,
// durable control-plane and agent journals, a signed command, production telemetry verifier, and incident
// event log. The actuator and observer transport are test doubles; no host is touched, and the verifier
// derives both post-conditions from the fixture's independently accepted timeline and coverage records.
func TestGovernedResponseEndToEnd(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	clock := fixedClock{t: now}
	audit := &fakeAudit{}
	ctx := tctx()

	guard, err := execution.NewGuard(&fakeEngRepo{eng: e2eEngagement(now)}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	appr, err := approval.NewService(memory.NewApprovalStore(), audit, clock, agent.ModeAuto, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clock, &e2eIDs{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.NewEd25519Signer(nil)
	if err != nil {
		t.Fatal(err)
	}
	ev.SetSigner(signer.WithContext(evdom.AttestationContextEvidence))
	gate, err := safety.NewGate(guard, appr, ev)
	if err != nil {
		t.Fatal(err)
	}
	exec := newE2EAgentExecutor(t, clock)
	observations := memory.NewResponseVerificationStore()
	keys := memory.NewAgentSigningKeyStore()
	timeline := memory.NewEndpointTimelineStore()
	coverage := memory.NewCoverageWindowStore()
	verifier, err := NewTelemetryEffectVerifier("control-plane:response-verifier", observations, observations, timeline, coverage, ev)
	if err != nil {
		t.Fatal(err)
	}
	verifier.SetObservationDispatcher(&e2eObservationDispatcher{
		observations: observations, keys: keys, timeline: timeline, coverage: coverage,
	})
	responseStore := memory.NewResponseStore()
	svc, err := NewService(gate, exec, responseStore, audit, clock, verifier, ev, signer.PublicKey(), observations, observations, keys)
	if err != nil {
		t.Fatal(err)
	}
	incidentStore := memory.NewIncidentEventStore()
	incidentSvc, err := incidentuc.NewService(incidentStore)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incidentSvc.Append(ctx, "inc-1", 0, []incident.IncidentEvent{{
		IncidentID: "inc-1", Kind: incident.EventCreated, At: now, Actor: "correlator",
		AssetID: "host-1", Title: "malicious process", Severity: shared.SeverityHigh,
	}}); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	coordinator, err := NewIncidentCoordinator(svc, incidentSvc, clock)
	if err != nil {
		t.Fatal(err)
	}

	action, err := rdom.NewAction("resp-1", rdom.KindStopProcess, "app.acme.io")
	if err != nil {
		t.Fatalf("build action: %v", err)
	}
	target := engagement.Target{Kind: engagement.TargetDomain, Value: "app.acme.io"}
	fingerprint := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "app.acme.io"}

	// 1) Even ModeAuto suspends an intrusive response action until a human decides it.
	if _, err := coordinator.Apply(ctx, "inc-1", "eng-1", action, target, fingerprint, "alice"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("unapproved apply must suspend with ErrPendingApproval, got %v", err)
	}
	if exec.count() != 0 {
		t.Fatal("ModeAuto must not execute an unapproved response action")
	}

	// 2) A HUMAN approves (a machine never could — enforced elsewhere; here bob is the human approver).
	if _, err := appr.Decide(ctx, "bob", action.ID, true, "confirmed malicious process"); err != nil {
		t.Fatalf("human approve: %v", err)
	}

	// 3) Re-apply: admitted → journaled → simulated execute → observer dispatch → pending.
	rec, err := coordinator.Apply(ctx, "inc-1", "eng-1", action, target, fingerprint, "alice")
	if !errors.Is(err, ErrVerificationPending) {
		t.Fatalf("approved response must await the dispatched observation, got %v", err)
	}
	if rec.State != StateApplied || rec.Verification != VerificationPending {
		t.Fatalf("the command must remain applied and pending verification, got state=%s verification=%s", rec.State, rec.Verification)
	}
	if exec.count() != 1 {
		t.Fatalf("the approved response action must execute exactly once, got %d", exec.count())
	}

	// 4) Retry: the production verifier derives success from the accepted timeline and coverage without
	// reissuing the side effect.
	rec, err = coordinator.Apply(ctx, "inc-1", "eng-1", action, target, fingerprint, "alice")
	if err != nil {
		t.Fatalf("approved response must verify from telemetry: %v", err)
	}
	if rec.State != StateApplied || rec.Verification != VerificationSucceeded || exec.count() != 1 {
		t.Fatalf("telemetry verification must not re-execute: state=%s verification=%s executions=%d", rec.State, rec.Verification, exec.count())
	}
	if !audit.has("response.applied") || !audit.has("response.verified") {
		t.Error("the applied action and its verification must both be audited")
	}
	linked, err := incidentSvc.Get(ctx, "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(linked.Responses) != 1 || linked.Responses[0].ActionID != action.ID || !linked.Responses[0].Verified ||
		linked.Responses[0].VerifierID != verifier.Identity() || linked.Revision != 3 {
		t.Fatalf("incident response events were not linked exactly once: %+v", linked)
	}

	// 5) Reversal is a distinct intrusive action and requires its own human approval in ModeAuto.
	if _, err := svc.Revert(ctx, action.ID, target, fingerprint, "alice"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("unapproved reversal must suspend with ErrPendingApproval, got %v", err)
	}
	if exec.count() != 1 {
		t.Fatalf("ModeAuto must not execute an unapproved reversal, got %d total executions", exec.count())
	}
	reversalID := shared.ID("revert:" + action.ID.String())
	if _, err := appr.Decide(ctx, "carol", reversalID, true, "restore the process state"); err != nil {
		t.Fatalf("human approve reversal: %v", err)
	}
	rec, err = svc.Revert(ctx, action.ID, target, fingerprint, "alice")
	if !errors.Is(err, ErrVerificationPending) {
		t.Fatalf("approved reversal must await the dispatched observation, got %v", err)
	}
	if rec.State != StateApplied || exec.count() != 2 || !exec.reversal(1) {
		t.Fatalf("approved reversal did not execute exactly once: state=%s executions=%d", rec.State, exec.count())
	}
	rec, err = svc.Revert(ctx, action.ID, target, fingerprint, "alice")
	if err != nil {
		t.Fatalf("approved reversal must verify from telemetry: %v", err)
	}
	if rec.State != StateReverted || exec.count() != 2 || !exec.reversal(1) {
		t.Fatalf("verified reversal must not re-execute: state=%s executions=%d", rec.State, exec.count())
	}
	if rec.Verification != VerificationSucceeded {
		t.Fatalf("reversal must retain the independently verified apply result, got %q", rec.Verification)
	}
	rollbackAttempt, found, err := responseStore.GetAttempt(ctx, responseAttemptKey(action, true))
	if err != nil || !found {
		t.Fatalf("load verified rollback attempt: found=%t err=%v", found, err)
	}
	if rollbackAttempt.State != responsesaga.StateRolledBack ||
		rollbackAttempt.VerificationOutcome != responsesaga.VerificationSucceeded ||
		rollbackAttempt.VerifierID != verifier.Identity() || rollbackAttempt.VerificationEvidenceID.IsZero() {
		t.Fatalf("rollback post-condition was not independently verified: %+v", rollbackAttempt)
	}

	// 6) Out-of-scope target is refused by the gate FIRST — no approval can widen scope.
	oos, _ := rdom.NewAction("resp-2", rdom.KindStopProcess, "evil.example.com")
	oosFingerprint := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "evil.example.com"}
	if _, err := svc.Apply(ctx, "eng-1", oos, engagement.Target{Kind: engagement.TargetDomain, Value: "evil.example.com"}, oosFingerprint, "alice"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("out-of-scope response must be forbidden, got %v", err)
	}
}

type staticVerificationVault struct {
	item evdom.Evidence
	att  *evdom.Attestation
}

type staticVerificationSigningKeys struct{ key fleetagent.AgentSigningKey }

func (s staticVerificationSigningKeys) ResolveSigningKey(context.Context, shared.ID, string) (fleetagent.AgentSigningKey, error) {
	return s.key, nil
}

func (v staticVerificationVault) LookupAttestedByID(_ context.Context, engagementID, evidenceID shared.ID) (evdom.Evidence, *evdom.Attestation, bool, error) {
	if v.item.EngagementID != engagementID || v.item.ID != evidenceID {
		return evdom.Evidence{}, v.att, false, nil
	}
	return v.item, v.att, true, nil
}

func TestEvidenceReceiptValidatorRejectsUnboundAndUntrustedClaims(t *testing.T) {
	action, err := rdom.NewAction("a1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	req := VerificationRequest{
		TenantID: "t1", EngagementID: "eng-1", Action: action,
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		ExecutorID: "agent:response-executor", ExecutorAgentID: "response-executor", AttemptKey: "attempt-1",
		VerificationChallenge: strings.Repeat("c", 64), AttemptedAt: time.Unix(999, 0).UTC(), DeadlineAt: time.Unix(1099, 0).UTC(),
	}
	verifierID := "agent:response-verifier"
	source, key, err := newE2EVerificationSource(req, VerificationSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	content, err := MarshalVerificationEvidence(req, VerificationSucceeded, verifierID, &source)
	if err != nil {
		t.Fatal(err)
	}
	item := evdom.Evidence{
		ID: "verification-evidence-1", EngagementID: req.EngagementID, Kind: VerificationEvidenceKind,
		Content: content, CreatedBy: verifierID, CreatedAt: time.Unix(1000, 0).UTC(),
	}.Seal()
	signer, err := signing.NewEd25519Signer(nil)
	if err != nil {
		t.Fatal(err)
	}
	att, err := signer.WithContext(evdom.AttestationContextEvidence).Sign(context.Background(), item.Hash)
	if err != nil {
		t.Fatal(err)
	}
	receipt := VerificationReceipt{Outcome: VerificationSucceeded, EvidenceID: item.ID, Source: &source}
	observations := memory.NewResponseVerificationStore()
	keys := memory.NewAgentSigningKeyStore()
	ctx := tctx()
	if err := keys.Register(ctx, key); err != nil {
		t.Fatal(err)
	}
	observation := ports.AcceptedResponseVerification{
		Report: source.Report, ObserverID: source.Report.ObserverIdentity(),
		SignedContentDigest: source.SignedContentDigest, RecordedAt: source.RecordedAt,
	}
	if _, err := observations.AppendResponseVerificationWithAudit(ctx, observation, ports.FleetAuditIntent{
		ID: "audit-1", Entry: ports.AuditEntry{
			Actor: observation.ObserverID, Action: "fleet.response_verification.ingest", Target: source.Report.ReportID.String(),
			At: source.RecordedAt, Metadata: map[string]string{"idempotency_key": "audit-1"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := observations.AppendResponseTargetEvidenceReceipt(ctx, source.Receipt); err != nil {
		t.Fatal(err)
	}
	validator := evidenceReceiptValidator{
		vault: staticVerificationVault{item: item, att: &att}, trustedPublicKey: signer.PublicKey(), observations: observations, receipts: observations, keys: keys,
	}
	if err := validator.Validate(ctx, req, receipt, verifierID); err != nil {
		t.Fatalf("validate bound signed claim: %v", err)
	}
	if err := keys.Revoke(ctx, key.AgentID, key.KeyID, source.RecordedAt.Add(time.Second)); err != nil {
		t.Fatalf("revoke after receipt: %v", err)
	}
	if err := validator.Validate(ctx, req, receipt, verifierID); err != nil {
		t.Fatalf("later revocation must preserve accepted receipt: %v", err)
	}

	validator.observations = memory.NewResponseVerificationStore()
	if err := validator.Validate(ctx, req, receipt, verifierID); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("signed evidence without an accepted source observation must be forbidden, got %v", err)
	}
	validator.observations = observations

	key.RevokedAt = source.RecordedAt
	validator.keys = staticVerificationSigningKeys{key: key}
	if err := validator.Validate(ctx, req, receipt, verifierID); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("revocation at receipt must reject persisted verification, got %v", err)
	}
	key.RevokedAt = source.RecordedAt.Add(time.Second)
	validator.keys = staticVerificationSigningKeys{key: key}
	if err := validator.Validate(ctx, req, receipt, verifierID); err != nil {
		t.Fatalf("revocation after receipt must preserve persisted verification, got %v", err)
	}
	validator.keys = keys

	tampered := item
	tampered.Content = []byte(`{"outcome":"verified_succeeded"}`)
	validator.vault = staticVerificationVault{item: tampered, att: &att}
	if err := validator.Validate(ctx, req, receipt, verifierID); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unbound claim must be forbidden, got %v", err)
	}

	otherSigner, err := signing.NewEd25519Signer(nil)
	if err != nil {
		t.Fatal(err)
	}
	validator.vault = staticVerificationVault{item: item, att: &att}
	validator.trustedPublicKey = otherSigner.PublicKey()
	if err := validator.Validate(ctx, req, receipt, verifierID); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("attestation from an unpinned key must be forbidden, got %v", err)
	}
}

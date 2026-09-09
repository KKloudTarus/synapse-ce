package postgres

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func postgresResponseVerificationFixture(t *testing.T, f responseAuditFixture) ports.AcceptedResponseVerification {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey("observer-1", fleetagent.PurposeResponseResult, public, f.at.Add(-time.Hour), f.at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	report := fleetagent.ResponseVerificationReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, ReportID: "report-1", AgentID: "observer-1", HostID: "observer-1",
		AgentSessionID: fleetagent.CanonicalSessionID("observer-1"), AssetID: "asset-1", EngagementID: f.engage, ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("b", 64),
		ReceiptID: "receipt-1", ReceiptDigest: strings.Repeat("c", 64),
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		ObservedAt: f.at, KeyID: key.KeyID,
	}
	report.Signature = fleetagent.SignResponseVerification(private, report)
	digest := sha256.Sum256(fleetagent.ResponseVerificationMessage(report))
	return ports.AcceptedResponseVerification{
		Report: report, ObserverID: report.ObserverIdentity(), SignedContentDigest: hex.EncodeToString(digest[:]), RecordedAt: f.at.Add(time.Second),
	}
}

func postgresTargetReceiptFixture(t *testing.T, f responseAuditFixture) fleetagent.ResponseTargetEvidenceReceipt {
	t.Helper()
	receipt := fleetagent.ResponseTargetEvidenceReceipt{Version: fleetagent.ResponseTargetEvidenceReceiptVersion, ReceiptID: shared.ID("receipt-" + randHex(t)), TenantID: f.tenant, EngagementID: f.engage, ActionID: "action-1", ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-" + randHex(t), VerificationChallenge: strings.Repeat("b", 64), Target: responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"}, AttemptedAt: f.at, WindowUntil: f.at.Add(time.Second), RecordedAt: f.at.Add(2 * time.Second), SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), SourceHostID: "asset-1", TimelineComplete: true, CoverageComplete: true, Reasons: []string{"complete"}}
	receipt.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(receipt)
	return receipt
}

func TestResponseVerificationRepositoryTargetReceiptLifecycleAndIsolation(t *testing.T) {
	f := newResponseAuditFixture(t)
	repo, err := NewResponseVerificationRepository(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	receipt := postgresTargetReceiptFixture(t, f)
	if _, err := repo.AppendResponseTargetEvidenceReceipt(f.ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if retry, err := repo.AppendResponseTargetEvidenceReceipt(f.ctx, receipt); err != nil || !fleetagent.SameResponseTargetEvidenceReceipt(receipt, retry) {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	loaded, found, err := repo.GetResponseTargetEvidenceReceipt(f.ctx, receipt.AttemptKey)
	if err != nil || !found || !fleetagent.SameResponseTargetEvidenceReceipt(receipt, loaded) {
		t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
	}
	conflict := fleetagent.CloneResponseTargetEvidenceReceipt(receipt)
	conflict.Reasons, conflict.TimelineComplete, conflict.CoverageComplete = []string{"coverage_incomplete"}, false, false
	conflict.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(conflict)
	if _, err := repo.AppendResponseTargetEvidenceReceipt(f.ctx, conflict); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("attempt equivocation=%v", err)
	}
	otherTenant := shared.WithTenant(f.ctx, "other-tenant")
	if _, found, err := repo.GetResponseTargetEvidenceReceipt(otherTenant, receipt.AttemptKey); err != nil || found {
		t.Fatalf("tenant isolation found=%t err=%v", found, err)
	}
}

func TestResponseVerificationRepositoryCommitsObservationAndAuditAtomically(t *testing.T) {
	f := newResponseAuditFixture(t)
	repo, err := NewResponseVerificationRepository(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	observation := postgresResponseVerificationFixture(t, f)
	if _, err := repo.AppendResponseVerificationWithAudit(f.ctx, observation, ports.FleetAuditIntent{ID: "bad"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid audit intent must fail: %v", err)
	}
	if _, found, err := repo.GetResponseVerification(f.ctx, observation.Report.AttemptKey); err != nil || found {
		t.Fatalf("invalid audit intent committed observation: found=%t err=%v", found, err)
	}

	intent := ports.FleetAuditIntent{ID: "audit-1", Entry: ports.AuditEntry{
		Actor: observation.ObserverID, Action: "fleet.response_verification.ingest", Target: observation.Report.ReportID.String(),
		At: observation.RecordedAt, Metadata: map[string]string{"idempotency_key": "audit-1"},
	}}
	if _, err := repo.AppendResponseVerificationWithAudit(f.ctx, observation, intent); err != nil {
		t.Fatalf("append observation: %v", err)
	}
	stored, found, err := repo.GetResponseVerification(f.ctx, observation.Report.AttemptKey)
	if err != nil || !found || !ports.SameAcceptedResponseVerification(stored, observation) {
		t.Fatalf("stored observation=%+v found=%t err=%v", stored, found, err)
	}
	if _, err := repo.AppendResponseVerificationWithAudit(f.ctx, observation, intent); err != nil {
		t.Fatalf("exact retry must be idempotent: %v", err)
	}

	equivocation := observation
	equivocation.Report.ReportID = "report-2"
	equivocation.Report.VerificationChallenge = strings.Repeat("c", 64)
	digest := sha256.Sum256(fleetagent.ResponseVerificationMessage(equivocation.Report))
	equivocation.SignedContentDigest = hex.EncodeToString(digest[:])
	if _, err := repo.AppendResponseVerificationWithAudit(f.ctx, equivocation, intent); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second report for one attempt must conflict: %v", err)
	}
}

func TestMigration0148ResponseVerificationGuards(t *testing.T) {
	f := newResponseAuditFixture(t)
	repo, err := NewResponseVerificationRepository(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	observation := postgresResponseVerificationFixture(t, f)
	intent := ports.FleetAuditIntent{ID: "guard-audit", Entry: ports.AuditEntry{
		Actor: observation.ObserverID, Action: "fleet.response_verification.ingest", Target: observation.Report.ReportID.String(),
		At: observation.RecordedAt, Metadata: map[string]string{"idempotency_key": "guard-audit"},
	}}
	if _, err := repo.AppendResponseVerificationWithAudit(f.ctx, observation, intent); err != nil {
		t.Fatal(err)
	}
	var rls, forced bool
	if err := f.pool.QueryRow(f.ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class
		WHERE oid='response_verification_observations'::regclass`).Scan(&rls, &forced); err != nil {
		t.Fatal(err)
	}
	if !rls || !forced {
		t.Fatalf("response-verification RLS/forced=%t/%t, want true/true", rls, forced)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE response_verification_observations SET observer_id='tampered'
		WHERE tenant_id=$1 AND report_id=$2`, f.tenant.String(), observation.Report.ReportID.String()); err == nil {
		t.Fatal("database allowed mutation of accepted response verification")
	}
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM response_verification_observations
		WHERE tenant_id=$1 AND report_id=$2`, f.tenant.String(), observation.Report.ReportID.String()); err == nil {
		t.Fatal("database allowed deletion of accepted response verification")
	}
}

package fleetagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func responseReportFixture(t *testing.T) (ResponseVerificationReport, AgentSigningKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000, 0).UTC()
	key, err := NewSigningKey("observer-1", PurposeResponseResult, public, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	report := ResponseVerificationReport{
		ProtocolVersion: TelemetryProtocolVersion, ReportID: "report-1", AgentID: "observer-1", HostID: "observer-1",
		AgentSessionID: CanonicalSessionID("observer-1"), AssetID: "asset-1", EngagementID: "eng-1", ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1",
		ReceiptID: "receipt", ReceiptDigest: "0000000000000000000000000000000000000000000000000000000000000000", VerificationChallenge: strings.Repeat("b", 64),
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		ObservedAt: now, KeyID: key.KeyID,
	}
	report.Signature = SignResponseVerification(private, report)
	return report, key, private
}

func TestResponseVerificationReportSignatureAndPurpose(t *testing.T) {
	report, key, _ := responseReportFixture(t)
	if err := report.Validate(); err != nil {
		t.Fatalf("validate report: %v", err)
	}
	if err := VerifyResponseVerificationWithKey(key, report.ObservedAt, report); err != nil {
		t.Fatalf("verify signed report: %v", err)
	}

	tampered := report
	tampered.AttemptKey = "other-attempt"
	if err := VerifyResponseVerificationWithKey(key, report.ObservedAt, tampered); !errors.Is(err, ErrBadResponseVerificationSignature) {
		t.Fatalf("tampered causal binding must fail signature verification, got %v", err)
	}
	tampered = report
	tampered.VerificationChallenge = strings.Repeat("c", 64)
	if err := VerifyResponseVerificationWithKey(key, report.ObservedAt, tampered); !errors.Is(err, ErrBadResponseVerificationSignature) {
		t.Fatalf("tampered post-command challenge must fail signature verification, got %v", err)
	}
	wrongPurpose := key
	wrongPurpose.Purpose = PurposeTelemetryBatch
	if err := VerifyResponseVerificationWithKey(wrongPurpose, report.ObservedAt, report); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-purpose key must fail, got %v", err)
	}
}

func TestResponseVerificationReportCannotClaimVerdictAndBindsReversalCandidate(t *testing.T) {
	report, _, private := responseReportFixture(t)

	reversal := report
	reversal.Reversal = true
	reversal.ReplacementProcessEntityID = "process-2"
	reversal.Signature = SignResponseVerification(private, reversal)
	if err := reversal.Validate(); err != nil {
		t.Fatalf("replacement candidate must be valid: %v", err)
	}

	revived := reversal
	revived.ReplacementProcessEntityID = "process-1"
	revived.Signature = SignResponseVerification(private, revived)
	if err := revived.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("reversal must not nominate the exited entity, got %v", err)
	}
}

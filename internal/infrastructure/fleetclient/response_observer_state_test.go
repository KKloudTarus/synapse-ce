package fleetclient

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/fssecurity"
)

func TestResponseVerificationSignerPersistsAndRotatesByPurpose(t *testing.T) {
	store := NewCredentialStore(t.TempDir())
	now := time.Unix(2_000_000, 0).UTC()
	first, err := store.EnsureResponseVerificationSigner("observer-1", now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.EnsureResponseVerificationSigner("observer-1", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.Key.KeyID != second.Key.KeyID || first.Key.Purpose != fleetagent.PurposeResponseResult {
		t.Fatalf("first=%+v second=%+v", first.Key, second.Key)
	}
	info, err := os.Stat(store.responseVerificationSignerPath())
	if err != nil {
		t.Fatal(err)
	}
	if fssecurity.UnixModeEnforced() && info.Mode().Perm() != 0o600 {
		t.Fatalf("signer mode=%o", info.Mode().Perm())
	}
}

func TestResponseVerificationOutboxIsDurableAndRejectsEquivocation(t *testing.T) {
	store := NewCredentialStore(t.TempDir())
	now := time.Unix(2_000_000, 0).UTC()
	signer, err := store.EnsureResponseVerificationSigner("observer-1", now)
	if err != nil {
		t.Fatal(err)
	}
	report := fleetagent.ResponseVerificationReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, ReportID: "report-1", AgentID: "observer-1", HostID: "observer-1",
		AgentSessionID: fleetagent.CanonicalSessionID("observer-1"), AssetID: "asset-1", EngagementID: "eng-1", ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("b", 64),
		ReceiptID: "receipt-1", ReceiptDigest: strings.Repeat("c", 64),
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		ObservedAt: now, KeyID: signer.Key.KeyID,
	}
	report.Signature = fleetagent.SignResponseVerification(signer.PrivateKey, report)
	if err := store.SaveResponseVerificationReport(report); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.LoadResponseVerificationReport(report.AttemptKey)
	if err != nil || !found || loaded.Signature != report.Signature {
		t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
	}
	info, err := os.Stat(store.responseVerificationReportPath(report.AttemptKey))
	if err != nil {
		t.Fatal(err)
	}
	if fssecurity.UnixModeEnforced() && info.Mode().Perm() != 0o600 {
		t.Fatalf("outbox mode=%o", info.Mode().Perm())
	}
	equivocation := report
	equivocation.ReportID = "report-2"
	equivocation.Signature = fleetagent.SignResponseVerification(signer.PrivateKey, equivocation)
	if err := store.SaveResponseVerificationReport(equivocation); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("equivocation error=%v", err)
	}
	if err := store.AcknowledgeResponseVerificationReport(report.AttemptKey); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.LoadResponseVerificationReport(report.AttemptKey); err != nil || found {
		t.Fatalf("acknowledged outbox found=%t err=%v", found, err)
	}
}

package transfer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/signing"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (g *seqIDs) NewID() shared.ID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return shared.ID(fmt.Sprintf("gen-%d", g.n))
}

type nopAudit struct{}

func (nopAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func setup(t *testing.T) (*Service, *memory.EngagementRepository, *memory.FindingRepository, *evidenceuc.Service) {
	t.Helper()
	clock := fixedClock{t: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}
	engRepo := memory.NewEngagementRepository()
	findRepo := memory.NewFindingRepository()
	commentRepo := memory.NewCommentRepository()
	ev, err := evidenceuc.NewService(memory.NewEvidenceStore(), blob.NewMemory(), nopAudit{}, clock, &seqIDs{})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	svc, err := NewService(engRepo, findRepo, commentRepo, ev, nopAudit{}, clock, &seqIDs{})
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	return svc, engRepo, findRepo, ev
}

func seedEngagement(t *testing.T, engRepo *memory.EngagementRepository, findRepo *memory.FindingRepository, ev *evidenceuc.Service) {
	t.Helper()
	ctx := context.Background()
	eng := &engagement.Engagement{
		ID: "e1", Name: "acme", Client: "Acme", Status: engagement.StatusActive,
		Scope: engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "example.com"}}},
	}
	if err := engRepo.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	if err := findRepo.Upsert(ctx, []finding.Finding{
		{ID: "manual:1", EngagementID: "e1", Title: "XSS", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: "manual:1"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Seal(ctx, "e1", "scan", []byte("first link"), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Seal(ctx, "e1", "report", []byte("second link"), "alice"); err != nil {
		t.Fatal(err)
	}
}

// TestExportTenantIsolation proves the service-layer defense-in-depth: even reached
// DIRECTLY (bypassing the HTTP withEngTenant wrapper), Export refuses a cross-tenant engagement
// with ErrNotFound – so the bundle, which leaves the instance, can never be pulled across tenants
// even if a future caller forgets the route wrapper. The matching tenant still exports normally.
func TestExportTenantIsolation(t *testing.T) {
	svc, engRepo, findRepo, ev := setup(t)
	seedEngagement(t, engRepo, findRepo, ev) // "e1", default tenant ""
	ctx := context.Background()
	if _, err := svc.Export(ctx, "mallory", "tenant-B", "e1"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant Export must be ErrNotFound at the service layer, got %v", err)
	}
	if _, err := svc.Export(ctx, "alice", "", "e1"); err != nil {
		t.Errorf("matching-tenant Export must still succeed, got %v", err)
	}
}

// TestExportBundleAppliesPublishabilityGate proves the engagement bundle (a customer-
// facing artifact that leaves the instance) reads through the evidence gate: an unproven
// agent-proposed exploitation finding (score 0) never travels in it via the
// publishability filter (ListPublishableByEngagement, not ListByEngagement).
func TestExportBundleAppliesPublishabilityGate(t *testing.T) {
	svc, engRepo, findRepo, ev := setup(t)
	seedEngagement(t, engRepo, findRepo, ev) // seeds 1 publishable finding (manual:1)
	ctx := context.Background()
	if err := findRepo.Upsert(ctx, []finding.Finding{
		{ID: "exp-unproven", EngagementID: "e1", Title: "Unproven RCE", Kind: finding.KindExploitation, EvidenceScore: 0, Severity: shared.SeverityCritical, Status: finding.StatusOpen, DedupKey: "exploitation:exp-unproven"},
	}); err != nil {
		t.Fatal(err)
	}
	bundle, err := svc.Export(ctx, "alice", "", "e1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	for _, f := range bundle.Findings {
		if f.ID == "exp-unproven" {
			t.Fatal("bundle leaked an unproven exploitation finding")
		}
	}
	if len(bundle.Findings) != 1 {
		t.Fatalf("bundle must carry only the 1 publishable finding, got %d", len(bundle.Findings))
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	svc, engRepo, findRepo, ev := setup(t)
	seedEngagement(t, engRepo, findRepo, ev)
	ctx := context.Background()

	bundle, err := svc.Export(ctx, "alice", "", "e1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if bundle.Version != BundleVersion || bundle.Engagement == nil {
		t.Fatalf("bad bundle: %+v", bundle)
	}
	if len(bundle.Findings) != 1 || len(bundle.Evidence) != 2 {
		t.Fatalf("bundle findings=%d evidence=%d", len(bundle.Findings), len(bundle.Evidence))
	}

	imported, err := svc.Import(ctx, "alice", "", bundle)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imported.ID == "e1" {
		t.Error("import must create a NEW engagement id, not clobber the source")
	}
	if len(imported.Scope.InScope) != 1 || imported.Scope.InScope[0].Value != "example.com" {
		t.Errorf("scope not carried over: %+v", imported.Scope)
	}
	// Findings + evidence re-materialized under the new engagement.
	fs, _ := findRepo.ListByEngagement(ctx, imported.ID)
	if len(fs) != 1 {
		t.Errorf("imported findings = %d, want 1", len(fs))
	}
	rep, err := ev.Verify(ctx, imported.ID)
	if err != nil {
		t.Fatalf("verify imported: %v", err)
	}
	if !rep.Intact || rep.Verified != 2 {
		t.Errorf("imported chain: intact=%v verified=%d", rep.Intact, rep.Verified)
	}
}

func TestImportRejectsTamperedChain(t *testing.T) {
	svc, engRepo, findRepo, ev := setup(t)
	seedEngagement(t, engRepo, findRepo, ev)
	ctx := context.Background()

	bundle, err := svc.Export(ctx, "alice", "", "e1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Tamper with a sealed link's content; its stored Hash no longer matches.
	bundle.Evidence[1].Content = []byte("tampered payload")

	if _, err := svc.Import(ctx, "alice", "", bundle); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a tampered chain must be rejected with ErrValidation, got %v", err)
	}
	// And nothing was materialized (reject-before-write).
	engs, _ := engRepo.List(ctx, "")
	if len(engs) != 1 {
		t.Errorf("a rejected import must not create an engagement (have %d)", len(engs))
	}
}

func TestExportAttestsAndImportVerifiesOrigin(t *testing.T) {
	svc, engRepo, findRepo, ev := setup(t)
	base, err := signing.NewEd25519Signer(nil) // ephemeral key is fine for the round trip
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	// Production wiring: the evidence vault signs under the evidence-head context.
	ev.SetSigner(base.WithContext(evdom.AttestationContextEvidence))
	seedEngagement(t, engRepo, findRepo, ev)
	ctx := context.Background()

	bundle, err := svc.Export(ctx, "alice", "", "e1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if bundle.Attestation == nil {
		t.Fatal("a signed instance must attach a chain-head attestation to the bundle")
	}
	if bundle.Attestation.Head != bundle.EvidenceHead {
		t.Fatalf("attestation must sign the bundle's evidence head: %s vs %s", bundle.Attestation.Head, bundle.EvidenceHead)
	}
	if bundle.Attestation.Context != evdom.AttestationContextEvidence {
		t.Fatalf("bundle attestation must carry the evidence context, got %q", bundle.Attestation.Context)
	}
	// A clean bundle imports (origin attestation verifies).
	if _, err := svc.Import(ctx, "alice", "", bundle); err != nil {
		t.Fatalf("a validly attested bundle must import: %v", err)
	}

	// A forged attestation (head it never signed) is rejected before any write.
	forged, err := svc.Export(ctx, "alice", "", "e1")
	if err != nil {
		t.Fatalf("export 2: %v", err)
	}
	forged.Attestation.Head = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := svc.Import(ctx, "alice", "", forged); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a bundle whose attestation does not verify must be rejected, got %v", err)
	}

	// Domain separation: an AUDIT-head attestation carried in an evidence bundle is
	// rejected even though it is a cryptographically valid signature by the same key.
	mislabeled, err := svc.Export(ctx, "alice", "", "e1")
	if err != nil {
		t.Fatalf("export 3: %v", err)
	}
	auditAtt, err := base.WithContext(evdom.AttestationContextAudit).Sign(ctx, mislabeled.EvidenceHead)
	if err != nil {
		t.Fatalf("audit sign: %v", err)
	}
	mislabeled.Attestation = &auditAtt
	if _, err := svc.Import(ctx, "alice", "", mislabeled); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an audit-context attestation in an evidence bundle must be rejected, got %v", err)
	}
}

func TestImportCanonicalizesAndValidatesScope(t *testing.T) {
	svc, engRepo, findRepo, ev := setup(t)
	seedEngagement(t, engRepo, findRepo, ev)
	ctx := context.Background()
	bundle, err := svc.Export(ctx, "alice", "", "e1")
	if err != nil {
		t.Fatal(err)
	}
	bundle.Engagement.Scope.InScope[0].Value = "Example.COM."
	imported, err := svc.Import(ctx, "alice", "", bundle)
	if err != nil {
		t.Fatalf("import canonical scope: %v", err)
	}
	if got := imported.Scope.InScope[0].Value; got != "example.com" {
		t.Errorf("imported scope = %q, want canonical example.com", got)
	}

	invalid, err := svc.Export(ctx, "alice", "", "e1")
	if err != nil {
		t.Fatal(err)
	}
	invalid.Engagement.Scope.OutOfScope = []engagement.Target{{Kind: engagement.TargetDomain, Value: "not a host"}}
	before, _ := engRepo.List(ctx, "")
	if _, err := svc.Import(ctx, "alice", "", invalid); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid imported scope error = %v, want ErrValidation", err)
	}
	after, _ := engRepo.List(ctx, "")
	if len(after) != len(before) {
		t.Errorf("invalid scope import wrote an engagement: before=%d after=%d", len(before), len(after))
	}
}

func TestImportRejectsUnknownVersion(t *testing.T) {
	svc, engRepo, findRepo, ev := setup(t)
	seedEngagement(t, engRepo, findRepo, ev)
	ctx := context.Background()
	bundle, _ := svc.Export(ctx, "alice", "", "e1")
	bundle.Version = "synapse.engagement-bundle/v999"
	if _, err := svc.Import(ctx, "alice", "", bundle); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown bundle version must be rejected, got %v", err)
	}
}

func TestImportRejectsDanglingCommentRef(t *testing.T) {
	svc, engRepo, findRepo, ev := setup(t)
	seedEngagement(t, engRepo, findRepo, ev)
	ctx := context.Background()
	bundle, _ := svc.Export(ctx, "alice", "", "e1")
	// A comment referencing a finding not present in the bundle is rejected up front.
	bundle.Comments = append(bundle.Comments, finding.Comment{ID: "c1", EngagementID: "e1", FindingID: "ghost", Author: "a", Body: "b"})
	if _, err := svc.Import(ctx, "alice", "", bundle); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a dangling comment finding-ref must be rejected, got %v", err)
	}
	engs, _ := engRepo.List(ctx, "")
	if len(engs) != 1 {
		t.Errorf("a rejected import must not create an engagement (have %d)", len(engs))
	}
}

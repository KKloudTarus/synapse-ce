package httpapi

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	credentialsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/credentials"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	transferuc "github.com/KKloudTarus/synapse-ce/internal/usecase/transfer"
)

// The "core" seed plants one tenantA engagement's finding workflow records (the finding, a comment
// on it and a retest of it), its evidence ledger and one vault credential, so the generated sweep
// can show that these six reads answer tenantA its own data and never answer tenantB:
//
//	GET /api/v1/engagements/{id}/findings
//	GET /api/v1/engagements/{id}/findings/{fid}/comments
//	GET /api/v1/engagements/{id}/findings/{fid}/retests
//	GET /api/v1/engagements/{id}/evidence
//	GET /api/v1/engagements/{id}/bundle
//	GET /api/v1/engagements/{id}/credentials
//
// Every record goes through the real use case over the real in-memory store. None of those stores
// filters by the caller's tenant for these reads (they are keyed by engagement), so the tenant guard
// in front of the handler is the only thing standing between tenantB and these records. That is the
// property the sweep is meant to prove, and a stand-in that filtered by tenant itself would hide it.
func init() {
	registerHarnessSeed(harnessSeed{
		Name: "core",
		Routes: []string{
			"GET /api/v1/engagements/{id}/bundle",
			"GET /api/v1/engagements/{id}/credentials",
			"GET /api/v1/engagements/{id}/evidence",
			"GET /api/v1/engagements/{id}/findings",
			"GET /api/v1/engagements/{id}/findings/{fid}/comments",
			"GET /api/v1/engagements/{id}/findings/{fid}/retests",
		},
		Run: seedCore,
	})
}

// The markers are plain strings inside fields the handlers serialize verbatim (a title, a comment
// body, a retest note, an evidence kind and author, a credential name). Evidence content is base64
// in JSON, so the evidence marker lives in the kind instead.
const (
	coreFindingMarker    = "tenantA-core-finding-marker"
	coreCommentMarker    = "tenantA-core-comment-marker"
	coreRetestMarker     = "tenantA-core-retest-marker"
	coreEvidenceMarker   = "tenantA-core-evidence-marker"
	coreCredentialMarker = "tenantA-core-credential-marker"

	// coreFindingID is the id the sweep substitutes for {fid} (harnessPathValues), so the finding
	// planted here is the one the comments and retests routes are asked about.
	coreFindingID = shared.ID("f1")
	coreEngID     = shared.ID("engA")
)

// harnessEvidenceVaultKey is where this seed leaves its evidence vault in harnessWorld.state. The
// scan service takes its stores only through its constructor, so it is built once, by the "reports"
// seed, and receives this vault there; two seeds each building one would let the later replace the
// earlier and silently empty its routes. Seeds run in name order, so "core" runs before "reports".
const harnessEvidenceVaultKey = "evidence-vault"

// harnessEvidenceVault returns the vault the core seed sealed its ledger entry into, or nil when that
// seed is absent.
func harnessEvidenceVault(w *harnessWorld) *evidenceuc.Service {
	svc, _ := w.state[harnessEvidenceVaultKey].(*evidenceuc.Service)
	return svc
}

// harnessCoreIDs hands out a fixed list of ids first and then derives unique ones, so a record the
// sweep addresses by path (the finding "f1") gets that id while later records never collide.
type harnessCoreIDs struct {
	mu     sync.Mutex
	prefix string
	fixed  []shared.ID
	n      int
}

func (g *harnessCoreIDs) NewID() shared.ID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	if g.n <= len(g.fixed) {
		return g.fixed[g.n-1]
	}
	return shared.ID(fmt.Sprintf("%s-%d", g.prefix, g.n))
}

func seedCore(w *harnessWorld) []string {
	t := w.t
	t.Helper()
	// Planted without a tenant on the context on purpose: the request context in the harness
	// carries none either, and the retest store keys its rows by the context's tenant. Writing and
	// reading in the same (unscoped) way keeps every store a plain per-engagement table.
	ctx := context.Background()
	clock := fixedClock{t: time.Unix(1, 0).UTC()}

	// Findings, comments and retests: the findings service over three real in-memory stores.
	// The fourth id is the one the "projects" seed's source finding takes from this shared service.
	// The sweep asks for {fid}=f1 on the project routes too, and the repository keys findings by
	// engagement, so that finding does not collide with the one planted here.
	findingIDs := &harnessCoreIDs{prefix: "core-finding", fixed: []shared.ID{coreFindingID, "c1", "r1", coreFindingID}}
	findingRepo := memory.NewFindingRepository()
	commentRepo := memory.NewCommentRepository()
	retestRepo := memory.NewRetestRepository()
	findings := findingsuc.NewService(findingRepo, commentRepo, retestRepo, w.audit, clock, findingIDs)
	created, err := findings.Create(ctx, "core-seed", coreEngID, finding.ManualInput{
		Title: coreFindingMarker, Description: "planted for the core cross-tenant sweep", Severity: shared.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("seed core finding: %v", err)
	}
	if created.ID != coreFindingID {
		t.Fatalf("seed core finding id = %q, want %q: the sweep addresses it by that id", created.ID, coreFindingID)
	}
	if _, err := findings.AddComment(ctx, coreEngID, created.ID, coreCommentMarker, "core-seed"); err != nil {
		t.Fatalf("seed core comment: %v", err)
	}
	if _, _, err := findings.RecordRetest(ctx, coreEngID, created.ID, finding.RetestStillVulnerable, coreRetestMarker, "core-seed", created.Version); err != nil {
		t.Fatalf("seed core retest: %v", err)
	}
	w.rt.findings = findings

	// Evidence ledger: sealed through the real evidence vault, then served by the SCA service's
	// verify-and-list read, which is the one the route calls. The scan service is built once, by the
	// "reports" seed, which needs the most stores; it receives this vault through w.evidence. Without
	// that seed the ledger route has no scan service and stays unwired.
	evidenceSvc, err := evidenceuc.NewService(memory.NewEvidenceStore(), nil, w.audit, clock, &harnessCoreIDs{prefix: "core-evidence"})
	if err != nil {
		t.Fatalf("core evidence service: %v", err)
	}
	if _, err := evidenceSvc.Seal(ctx, coreEngID, coreEvidenceMarker, []byte(`{"planted":"core"}`), coreEvidenceMarker); err != nil {
		t.Fatalf("seed core evidence: %v", err)
	}
	w.state[harnessEvidenceVaultKey] = evidenceSvc

	// Bundle export: the transfer service over the same engagement repository, findings, comments
	// and evidence vault, so the bundle carries all of the records above.
	transfer, err := transferuc.NewService(w.engagements, findingRepo, commentRepo, evidenceSvc, w.audit, clock, &harnessCoreIDs{prefix: "core-transfer"})
	if err != nil {
		t.Fatalf("core transfer service: %v", err)
	}
	w.rt.transfer = transfer

	// Credential vault listing: names and timestamps only, never values. The vault encrypts at rest
	// like the production one; the key is a fixed test value.
	cipher, err := vault.NewCipher([]byte("core-seed-vault-key-0123456789ab"))
	if err != nil {
		t.Fatalf("core vault cipher: %v", err)
	}
	credentials, err := credentialsuc.NewService(vault.NewMemoryVault(cipher, clock.Now), w.audit, clock)
	if err != nil {
		t.Fatalf("core credentials service: %v", err)
	}
	if err := credentials.Set(ctx, "core-seed", coreEngID, coreCredentialMarker, []byte("not-a-real-secret")); err != nil {
		t.Fatalf("seed core credential: %v", err)
	}
	w.rt.credentials = credentials

	return []string{coreFindingMarker, coreCommentMarker, coreRetestMarker, coreEvidenceMarker, coreCredentialMarker}
}

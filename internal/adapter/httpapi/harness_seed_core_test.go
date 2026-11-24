package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	credentialsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/credentials"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	transferuc "github.com/KKloudTarus/synapse-ce/internal/usecase/transfer"
)

// The "core" seed plants one tenantA engagement's finding workflow records (the finding, a comment
// on it and a retest of it), one source finding of the project's analysis context, its evidence
// ledger with one captured artifact, and one vault credential, so the generated sweep can show that
// these reads answer tenantA its own data and never answer tenantB:
//
//	GET /api/v1/engagements/{id}/findings
//	GET /api/v1/engagements/{id}/findings/{fid}/comments
//	GET /api/v1/engagements/{id}/findings/{fid}/retests
//	GET /api/v1/projects/{key}/source-findings
//	GET /api/v1/projects/{key}/source-findings/{fid}
//	GET /api/v1/engagements/{id}/evidence
//	GET /api/v1/engagements/{id}/evidence/{sha}
//	GET /api/v1/engagements/{id}/bundle
//	GET /api/v1/engagements/{id}/credentials
//
// Every record goes through the real use case over the real in-memory store. None of those stores
// filters by the caller's tenant for these reads (they are keyed by engagement), so the tenant guard
// in front of the handler is the only thing standing between tenantB and these records. That is the
// property the sweep is meant to prove, and a stand-in that filtered by tenant itself would hide it.
//
// The seed wires the router's findings service, so it plants every finding that service serves,
// the project's source finding included: no other seed assigns rt.findings or creates a finding
// through it.
func init() {
	registerHarnessSeed(harnessSeed{
		Name: "core",
		Routes: []string{
			"GET /api/v1/engagements/{id}/bundle",
			"GET /api/v1/engagements/{id}/credentials",
			"GET /api/v1/engagements/{id}/evidence",
			"GET /api/v1/engagements/{id}/evidence/{sha}",
			"GET /api/v1/engagements/{id}/findings",
			"GET /api/v1/engagements/{id}/findings/{fid}/comments",
			"GET /api/v1/engagements/{id}/findings/{fid}/retests",
			"GET /api/v1/projects/{key}/source-findings",
			"GET /api/v1/projects/{key}/source-findings/{fid}",
		},
		// The route downloads an artifact by the sha256 of its bytes, so the id is derived from the
		// content the seed captures instead of being written down twice.
		PathValues: map[string]string{"{sha}": coreArtifactSHA},
		Run:        seedCore,
	})
}

// The markers are plain strings inside fields the handlers serialize verbatim (a title, a comment
// body, a retest note, an evidence kind and author, a credential name). Evidence content is base64
// in JSON, so the evidence marker lives in the kind instead.
const (
	coreFindingMarker       = "tenantA-core-finding-marker"
	coreCommentMarker       = "tenantA-core-comment-marker"
	coreRetestMarker        = "tenantA-core-retest-marker"
	coreSourceFindingMarker = "tenantA-core-source-finding-marker"
	coreEvidenceMarker      = "tenantA-core-evidence-marker"
	coreArtifactMarker      = "tenantA-core-artifact-marker"
	coreCredentialMarker    = "tenantA-core-credential-marker"

	// coreFindingID is the id the sweep substitutes for {fid} (harnessPathValues), so the finding
	// planted here is the one the comments and retests routes are asked about, and the project's
	// source finding takes the same id under its own engagement.
	coreFindingID = shared.ID("f1")
	coreEngID     = shared.ID("engA")

	// coreArtifactContent is what the artifact download route returns. The marker sits in the bytes
	// themselves, so it appears in a response only when the sealed artifact was served.
	coreArtifactContent = coreArtifactMarker + " captured artifact bytes"
)

// coreArtifactSHA is the sha256 digest the download route addresses the captured artifact by.
var coreArtifactSHA = func() string {
	sum := sha256.Sum256([]byte(coreArtifactContent))
	return hex.EncodeToString(sum[:])
}()

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

	// Findings, comments and retests: the findings service over three real in-memory stores. The
	// service hands out its ids in the order the records are created below, so the list says which
	// record takes which id:
	//
	//	1st  f1  the engagement's finding   ({fid} on the findings, comments and retests routes)
	//	2nd  c1  the comment on that finding
	//	3rd  r1  the retest of that finding
	//	4th  f1  the project's source finding ({fid} on the source-findings route)
	//
	// The repository keys findings by engagement, so the second f1 lives under the project's context
	// engagement and does not collide with the first.
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

	// The project's source finding: the source-finding routes resolve the project's hidden analysis
	// engagement through the project service and read this same findings service under that id.
	// Resolving it here, instead of assuming the fixture's constant, keeps the finding where the
	// routes will look whatever id the project service hands out.
	source, err := w.projects.SourceContext(shared.WithTenant(ctx, "tenantA"), "tenantA", harnessPathValues["{key}"])
	if err != nil {
		t.Fatalf("seed core source finding: resolve the project's analysis context: %v", err)
	}
	sourceFinding, err := findings.Create(ctx, "core-seed", source.Context.ID, finding.ManualInput{
		Title: coreSourceFindingMarker, Description: "planted for the core cross-tenant sweep", Severity: shared.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("seed core source finding: %v", err)
	}
	if sourceFinding.ID.String() != harnessPathValues["{fid}"] {
		t.Fatalf("seed core source finding id = %q, want %q: the sweep addresses it by that id", sourceFinding.ID, harnessPathValues["{fid}"])
	}
	w.rt.findings = findings

	// Evidence ledger: sealed through the real evidence vault, then served by the SCA service's
	// verify-and-list read, which is the one the route calls. The scan service is built once, by the
	// "reports" seed, which needs the most stores; it receives this vault through the shared state.
	// Without that seed the ledger route has no scan service and stays unwired.
	//
	// The vault keeps artifact bytes in an in-memory blob store, and one artifact is captured through
	// it: the download route returns those bytes for the digest the seed declared in PathValues, but
	// only for an engagement whose chain references the blob.
	evidenceSvc, err := evidenceuc.NewService(memory.NewEvidenceStore(), blob.NewMemory(), w.audit, clock, &harnessCoreIDs{prefix: "core-evidence"})
	if err != nil {
		t.Fatalf("core evidence service: %v", err)
	}
	if _, err := evidenceSvc.Seal(ctx, coreEngID, coreEvidenceMarker, []byte(`{"planted":"core"}`), coreEvidenceMarker); err != nil {
		t.Fatalf("seed core evidence: %v", err)
	}
	if _, err := evidenceSvc.CaptureArtifact(ctx, coreEngID, "core-seed", "artifact", "core-artifact.txt", []byte(coreArtifactContent), "planted for the core cross-tenant sweep"); err != nil {
		t.Fatalf("seed core artifact: %v", err)
	}
	w.state[harnessEvidenceVaultKey] = evidenceSvc
	w.rt.evidence = evidenceSvc

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

	return []string{coreFindingMarker, coreCommentMarker, coreRetestMarker, coreSourceFindingMarker, coreEvidenceMarker, coreArtifactMarker, coreCredentialMarker}
}

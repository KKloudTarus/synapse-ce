package reachproof

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

const jvmTier2TestPURL = "pkg:maven/com.acme/vuln@1.0.0"

func TestJVMTier2CoordinatorRaiseOnlyAndNonSuppressingActors(t *testing.T) {
	rec := &fakeRecorder{}
	c, err := NewJVMTier2Coordinator(fakeAnalyzer{res: []reachability.Result{
		{Symbol: jvmTier2TestPURL + jvmTier2SubjectSeparator + "com.acme.Vuln.hit", Reachable: true, Path: []string{"app.Main.main", "com.acme.Vuln.hit"}},
		{Symbol: jvmTier2TestPURL + jvmTier2SubjectSeparator + "com.acme.Vuln.miss", Reachable: false},
	}}, rec, &fakeAudit{}, fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{
		{FindingID: "f-hit", Symbols: []string{"com.acme.Vuln.hit"}, PackagePURL: jvmTier2TestPURL},
		{FindingID: "f-miss", Symbols: []string{"com.acme.Vuln.miss"}, PackagePURL: jvmTier2TestPURL},
	})
	if err != nil || n != 1 {
		t.Fatalf("minted=%d err=%v, want only reachable", n, err)
	}
	if len(rec.proposes) != 1 || rec.proposes[0].subjectID != "f-hit" {
		t.Fatalf("proposes=%+v", rec.proposes)
	}
	if rec.proposes[0].proposer != jvmTier2Proposer || len(rec.verifies) != 1 || rec.verifies[0].verifier != jvmTier2Verifier {
		t.Fatalf("wrong JVM actors: proposes=%+v verifies=%+v", rec.proposes, rec.verifies)
	}
	if judgment.IsDeterministicReachabilityProof(judgment.Tier2, jvmTier2Proposer, jvmTier2Verifier) {
		t.Fatal("JVM Tier-2 actors must remain outside the suppression proof allowlist")
	}
}

func TestJVMTier2CoordinatorSkipsUnattributedSubject(t *testing.T) {
	rec := &fakeRecorder{}
	c, err := NewJVMTier2Coordinator(fakeAnalyzer{res: []reachability.Result{{
		Symbol: "com.acme.Vuln.hit", Reachable: true, Path: []string{"app.Main.main", "com.acme.Vuln.hit"},
	}}}, rec, &fakeAudit{}, fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{{
		FindingID: "f-hit", Symbols: []string{"com.acme.Vuln.hit"},
	}})
	if err != nil || n != 0 || len(rec.proposes) != 0 {
		t.Fatalf("unattributed JVM subject must mint nothing: n=%d err=%v proposes=%+v", n, err, rec.proposes)
	}
}

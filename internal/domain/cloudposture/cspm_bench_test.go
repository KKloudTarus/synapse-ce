package cloudposture

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
)

// cspm_bench_test.go is the owned CSPM accuracy gate (#1040). Evaluate is a pure function over explicit
// provider facts (an Inventory of normalized resources), so the corpus is a fixture inventory with a known
// expected finding per resource — no cloud account is contacted and nothing is mutated. Each misconfigured
// resource is shaped to trip exactly one posture rule; compliant resources trip none; and an
// unknown-state resource is NotAssessed (produces no finding), so inaccessible evidence is never reported as
// either a violation or a clean pass.

// cspmCase is one labeled resource: expectRule is the rule key that must fire, or "" for a resource that must
// produce no finding (compliant or not-assessed).
type cspmCase struct {
	res        Resource
	expectRule string
}

func awsRes(id string, kind asset.Kind) Resource {
	return Resource{Provider: ProviderAWS, ID: id, Kind: kind}
}

// cspmCorpus labels one resource per posture rule (each shaped to trip only that rule), a compliant resource,
// and a not-assessed (unknown-state) resource.
var cspmCorpus = []cspmCase{
	func() cspmCase {
		r := awsRes("bucket-public", asset.KindStorage)
		r.Public = StateEnabled
		r.Encrypted = StateEnabled
		return cspmCase{r, RuleStoragePublic}
	}(),
	func() cspmCase {
		r := awsRes("vm-public", asset.KindHost)
		r.Public, r.PublicNetwork, r.Encrypted = StateEnabled, StateEnabled, StateEnabled
		return cspmCase{r, RuleComputePublic}
	}(),
	func() cspmCase {
		r := awsRes("role-wildcard", asset.KindIdentity)
		r.PolicyKnown, r.WildcardAction, r.Encrypted = true, true, StateEnabled
		return cspmCase{r, RuleIdentityWildcard}
	}(),
	func() cspmCase {
		r := awsRes("role-unused", asset.KindIdentity)
		r.HighPrivilege, r.LastUseKnown, r.UnusedDays, r.Encrypted = true, true, 91, StateEnabled
		return cspmCase{r, RuleIdentityUnusedAdmin}
	}(),
	func() cspmCase {
		r := awsRes("db-unencrypted", asset.KindStorage)
		r.Encrypted = StateDisabled
		return cspmCase{r, RuleEncryptionDisabled}
	}(),
	func() cspmCase {
		r := awsRes("secret-store", asset.KindStorage)
		r.Sensitive, r.PublicNetwork, r.Encrypted = true, StateEnabled, StateEnabled
		return cspmCase{r, RuleSensitivePublicPath}
	}(),
	// Cover the KindWorkload branch of compute-public (not just KindHost).
	func() cspmCase {
		r := awsRes("workload-public", asset.KindWorkload)
		r.Public, r.PublicNetwork, r.Encrypted = StateEnabled, StateEnabled, StateEnabled
		return cspmCase{r, RuleComputePublic}
	}(),
	// Cover the WildcardTarget branch of identity-wildcard (not just WildcardAction).
	func() cspmCase {
		r := awsRes("role-wildcard-target", asset.KindIdentity)
		r.PolicyKnown, r.WildcardTarget, r.Encrypted = true, true, StateEnabled
		return cspmCase{r, RuleIdentityWildcard}
	}(),
	// Compliant: everything explicitly safe.
	func() cspmCase {
		r := awsRes("bucket-locked", asset.KindStorage)
		r.Public, r.Encrypted, r.PublicNetwork = StateDisabled, StateEnabled, StateDisabled
		return cspmCase{r, ""}
	}(),
	// Not assessed: the provider did not report these facts, so nothing is evaluated.
	func() cspmCase {
		r := awsRes("bucket-opaque", asset.KindStorage)
		r.Public, r.Encrypted, r.PublicNetwork = StateUnknown, StateUnknown, StateUnknown
		return cspmCase{r, ""}
	}(),
}

const (
	cspmRecallFloor    = 1.0
	cspmPrecisionFloor = 1.0
)

// TestCSPMOwnedAccuracy runs the owned posture evaluator over the fixture inventory and gates recall (each
// misconfigured resource trips its expected rule) and precision (no compliant or not-assessed resource is
// flagged, and no resource trips a rule other than its expected one).
func TestCSPMOwnedAccuracy(t *testing.T) {
	inv := Inventory{Provider: ProviderAWS, Complete: true}
	for _, c := range cspmCorpus {
		inv.Resources = append(inv.Resources, c.res)
	}
	findings, err := Evaluate(inv)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	fired := map[string]map[string]bool{}
	for _, f := range findings {
		if fired[f.ResourceID] == nil {
			fired[f.ResourceID] = map[string]bool{}
		}
		fired[f.ResourceID][f.RuleKey] = true
	}

	tp, fp, fn := 0, 0, 0
	for _, c := range cspmCorpus {
		got := fired[c.res.ID]
		if c.expectRule != "" {
			if got[c.expectRule] {
				tp++
			} else {
				fn++
				t.Errorf("%s: expected rule %q to fire, but it did not (fired: %v)", c.res.ID, c.expectRule, cspmKeys(got))
			}
		}
		for rule := range got {
			if rule != c.expectRule {
				fp++
				t.Errorf("%s: unexpected rule %q fired", c.res.ID, rule)
			}
		}
	}
	recall, precision := cspmRate(tp, fn), cspmRate(tp, fp)
	t.Logf("cspm owned: resources=%d tp=%d fp=%d fn=%d recall=%.3f precision=%.3f", len(cspmCorpus), tp, fp, fn, recall, precision)
	if recall < cspmRecallFloor {
		t.Errorf("cspm recall %.3f below floor %.3f", recall, cspmRecallFloor)
	}
	if precision < cspmPrecisionFloor {
		t.Errorf("cspm precision %.3f below floor %.3f", precision, cspmPrecisionFloor)
	}
}

// TestCSPMNotAssessedIsNotCompliant: an unknown-state resource produces no finding, so inaccessible evidence
// is not silently treated as a violation OR as compliant. This is the NotAssessed / permission-denied
// distinction the dimension requires.
func TestCSPMNotAssessedIsNotCompliant(t *testing.T) {
	r := awsRes("opaque", asset.KindStorage)
	r.Public, r.Encrypted, r.PublicNetwork = StateUnknown, StateUnknown, StateUnknown
	findings, err := Evaluate(Inventory{Provider: ProviderAWS, Complete: false, Resources: []Resource{r}})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("an unknown-state (not-assessed) resource must produce no posture finding; got %v", findings)
	}
	// The same resource with an EXPLICIT unsafe fact must be flagged, proving the difference is the evidence
	// state, not the resource being ignored.
	r.Encrypted = StateDisabled
	flagged, err := Evaluate(Inventory{Provider: ProviderAWS, Resources: []Resource{r}})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(flagged) == 0 {
		t.Errorf("the same resource with encryption explicitly disabled must be flagged")
	}
}

func cspmRate(tp, other int) float64 {
	if tp+other == 0 {
		return 0
	}
	return float64(tp) / float64(tp+other)
}

func cspmKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

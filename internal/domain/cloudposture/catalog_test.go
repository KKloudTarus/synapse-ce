package cloudposture

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
)

func TestCatalogAndHighConfidenceChecks(t *testing.T) {
	rules, err := Catalog()
	if err != nil || len(rules) != 7 {
		t.Fatalf("Catalog() = %d, %v", len(rules), err)
	}
	inv := Inventory{Provider: ProviderAWS, Complete: true, Resources: []Resource{
		{Provider: ProviderAWS, ID: "bucket", Kind: asset.KindStorage, Public: StateEnabled, Encrypted: StateDisabled},
		{Provider: ProviderAWS, ID: "vm", Kind: asset.KindHost, Public: StateEnabled, PublicNetwork: StateEnabled, Sensitive: true},
		{Provider: ProviderAWS, ID: "role", Kind: asset.KindIdentity, WildcardAction: true, PolicyKnown: true, HighPrivilege: true, UnusedDays: 91, LastUseKnown: true},
		{Provider: ProviderAWS, ID: "unknown", Kind: asset.KindStorage, Public: StateUnknown, Encrypted: StateUnknown},
	}}
	got, err := Evaluate(inv)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{RuleStoragePublic: true, RuleComputePublic: true, RuleIdentityWildcard: true, RuleIdentityUnusedAdmin: true, RuleEncryptionDisabled: true, RuleSensitivePublicPath: true}
	for _, f := range got {
		delete(want, f.RuleKey)
		if f.ResourceID == "unknown" {
			t.Fatal("unknown state produced a finding")
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing checks: %v", want)
	}
}

func TestDetectDrift(t *testing.T) {
	inv := Inventory{Provider: ProviderAWS, Resources: []Resource{{Provider: ProviderAWS, ID: "bucket", Kind: asset.KindStorage, Encrypted: StateDisabled}}}
	findings, gaps := DetectDrift(inv, []Expectation{
		{Provider: ProviderAWS, ResourceID: "bucket", Control: "encrypted", State: StateEnabled, Source: "main.tf:10"},
		{Provider: ProviderAWS, ResourceID: "dynamic", Control: "public", State: StateDisabled, Source: "main.tf:20"},
	})
	if len(findings) != 1 || findings[0].RuleKey != RuleIaCLiveDrift || findings[0].Class != ClassIaCLiveDrift {
		t.Fatalf("findings = %#v", findings)
	}
	if len(gaps) != 1 || gaps[0].Code != "iac_identity_unresolved" {
		t.Fatalf("gaps = %#v", gaps)
	}
}

func TestDetectDriftSeparatesControlsAndScopes(t *testing.T) {
	inv := Inventory{Provider: ProviderAWS, ScopeKey: "aws:organizations/o-a", Resources: []Resource{{Provider: ProviderAWS, ScopeKey: "aws:organizations/o-a", ID: "bucket", Kind: asset.KindStorage, Public: StateEnabled, Encrypted: StateDisabled}}}
	findings, gaps := DetectDrift(inv, []Expectation{
		{Provider: ProviderAWS, ScopeKey: "aws:organizations/o-a", ResourceID: "bucket", Control: "public", State: StateDisabled, Source: "a.tf"},
		{Provider: ProviderAWS, ScopeKey: "aws:organizations/o-a", ResourceID: "bucket", Control: "encrypted", State: StateEnabled, Source: "a.tf"},
		{Provider: ProviderAWS, ScopeKey: "aws:organizations/o-b", ResourceID: "missing", Control: "public", State: StateDisabled, Source: "b.tf"},
	})
	if len(gaps) != 0 || len(findings) != 2 {
		t.Fatalf("findings=%#v gaps=%#v", findings, gaps)
	}
	if findings[0].Control == findings[1].Control {
		t.Fatalf("drift controls collided: %#v", findings)
	}
}

func TestScopeKeyCanonicalizesProviderRoots(t *testing.T) {
	for _, tc := range []struct {
		provider Provider
		root     string
		want     string
	}{
		{ProviderAWS, "organization/o-example", "aws:organizations/o-example"},
		{ProviderAzure, "sub-1", "azure:subscriptions/sub-1"},
		{ProviderGCP, "folders/123", "gcp:folders/123"},
	} {
		got, err := ScopeKey(tc.provider, tc.root)
		if err != nil || got != tc.want {
			t.Fatalf("ScopeKey(%q, %q) = %q, %v", tc.provider, tc.root, got, err)
		}
	}
}

package misconfig

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestBicepInsecureResources checks that raw .bicep source runs the Azure ARM ruleset: an insecure storage
// account, network security group, Key Vault, and AKS cluster produce the same rule ids scanARM emits for
// the compiled template.
func TestBicepInsecureResources(t *testing.T) {
	src := `
resource stg 'Microsoft.Storage/storageAccounts@2018-01-01' = {
  name: 'companyprodstore'
  location: 'eastus'
  properties: {
    allowBlobPublicAccess: true
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_0'
    publicNetworkAccess: 'Enabled'
    encryption: {
      requireInfrastructureEncryption: false
    }
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-01-01' = {
  name: 'open-nsg'
  properties: {
    securityRules: [
      {
        name: 'in'
        properties: {
          direction: 'Inbound'
          access: 'Allow'
          sourceAddressPrefix: '0.0.0.0/0'
        }
      }
      {
        name: 'out'
        properties: {
          direction: 'Outbound'
          access: 'Allow'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'companyvault'
  location: 'eastus'
  properties: {
    publicNetworkAccess: 'Enabled'
    enableRbacAuthorization: false
    enablePurgeProtection: false
  }
}

resource aks 'Microsoft.ContainerService/managedClusters@2023-01-01' = {
  name: 'prodcluster'
  location: 'eastus'
  properties: {
    enableRBAC: false
  }
}
`
	got := ruleIDs(scan(t, map[string]string{"main.bicep": src}))
	for _, want := range []string{
		"arm-storage-public-blob",
		"arm-storage-https-only-off",
		"arm-storage-min-tls-below-12",
		"arm-storage-public-network",
		"arm-storage-infrastructure-encryption-disabled",
		"arm-nsg-open-inbound",
		"arm-nsg-open-egress",
		"arm-keyvault-public-network",
		"arm-keyvault-rbac-disabled",
		"arm-keyvault-purge-protection-disabled",
		"arm-aks-rbac-disabled",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %s on insecure bicep, got %v", want, keys(got))
		}
	}
}

// TestBicepFindingLine confirms a finding points at the offending property's line, not the file top.
func TestBicepFindingLine(t *testing.T) {
	src := `resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'store'
  location: 'eastus'
  properties: {
    supportsHttpsTrafficOnly: false
  }
}
`
	got := ruleIDs(scan(t, map[string]string{"main.bicep": src}))
	f, ok := got["arm-storage-https-only-off"]
	if !ok {
		t.Fatalf("expected arm-storage-https-only-off, got %v", keys(got))
	}
	if f.Line != 5 {
		t.Errorf("finding line = %d, want 5 (the supportsHttpsTrafficOnly line)", f.Line)
	}
}

// TestBicepDynamicExpressionsFailClosed is the no-false-positive guard: a value that is a parameter/variable
// reference, a function call, a ternary, or an interpolated string is dynamic and must never yield an
// insecure-literal finding, exactly as scanARM suppresses ARM expressions.
func TestBicepDynamicExpressionsFailClosed(t *testing.T) {
	src := `
param enablePublic bool
param useRbac bool
param purge bool

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  tags: {
    owner: 'security'
  }
  properties: {
    publicNetworkAccess: enablePublic ? 'Enabled' : 'Disabled'
    enableRbacAuthorization: useRbac
    enablePurgeProtection: purge
  }
}
`
	got := ruleIDs(scan(t, map[string]string{"main.bicep": src}))
	for _, unwanted := range []string{
		"arm-keyvault-public-network",
		"arm-keyvault-rbac-disabled",
		"arm-keyvault-purge-protection-disabled",
		"arm-location-hardcoded",
		"arm-resource-name-hardcoded",
	} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("dynamic bicep expression must suppress %s; got %v", unwanted, keys(got))
		}
	}
}

// TestBicepSecretNeverCopied confirms a hardcoded secret is flagged but its plaintext never enters the
// finding, so the finding text, evidence seal, and report cannot leak the secret.
func TestBicepSecretNeverCopied(t *testing.T) {
	const secret = "do-not-copy-this-bicep-secret"
	src := `resource site 'Microsoft.Web/sites@2023-01-01' = {
  name: 'app'
  location: 'eastus'
  properties: {
    siteConfig: {
      connectionStrings: [
        {
          name: 'db'
          connectionString: '` + secret + `'
        }
      ]
    }
  }
}
`
	findings := scan(t, map[string]string{"main.bicep": src})
	got := ruleIDs(findings)
	if _, ok := got["arm-hardcoded-secret"]; !ok {
		t.Fatalf("expected arm-hardcoded-secret, got %v", keys(got))
	}
	for _, f := range findings {
		if strings.Contains(f.Description, secret) || strings.Contains(f.Resource, secret) || strings.Contains(f.Title, secret) {
			t.Fatalf("secret value leaked into finding %+v", f)
		}
	}
}

// TestBicepExistingAndLoopSkipped confirms the parser skips an `existing` reference and a resource loop
// (unmodeled forms) without inventing findings, while still scanning a normal insecure resource in the same
// file. Skipping an unmodeled form loses coverage but never produces a false finding.
func TestBicepExistingAndLoopSkipped(t *testing.T) {
	src := `
resource existingStore 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: 'preexisting'
}

resource loopStores 'Microsoft.Storage/storageAccounts@2023-01-01' = [for i in range(0, 3): {
  name: 'store${i}'
  properties: {
    supportsHttpsTrafficOnly: false
  }
}]

resource realStore 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'realstore'
  location: 'eastus'
  properties: {
    supportsHttpsTrafficOnly: false
  }
}
`
	findings := scan(t, map[string]string{"main.bicep": src})
	got := ruleIDs(findings)
	if _, ok := got["arm-storage-https-only-off"]; !ok {
		t.Fatalf("expected the real resource to be scanned (arm-storage-https-only-off), got %v", keys(got))
	}
	// The loop body also sets supportsHttpsTrafficOnly:false, so if it were parsed we would see two such
	// findings. Exactly one confirms the loop and the existing reference were skipped.
	count := 0
	for _, f := range findings {
		if f.RuleID == "arm-storage-https-only-off" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 https-only finding (only the real resource), got %d: %v", count, keys(got))
	}
}

// TestBicepNotConfusedWithARM confirms a .bicep file is not mistaken for anything else and an empty or
// resource-free file yields nothing.
func TestBicepNotConfusedWithARM(t *testing.T) {
	if f := scanBicep("empty.bicep", []byte("")); f != nil {
		t.Errorf("empty bicep should yield no findings, got %v", f)
	}
	noResource := "param location string = 'eastus'\nvar name = 'x'\noutput id string = name\n"
	if f := scanBicep("vars.bicep", []byte(noResource)); f != nil {
		t.Errorf("resource-free bicep should yield no findings, got %v", f)
	}
}

// TestBicepMalformedNoPanic feeds malformed and adversarial Bicep to the parser: it must never panic and
// must terminate (scanBicep is called directly, without a recover, like the other misconfig scanners).
func TestBicepMalformedNoPanic(t *testing.T) {
	cases := []string{
		"resource",
		"resource x",
		"resource x '",
		"resource x 'T@1' = {",
		"resource x 'T@1' = { name: 'a'",
		"resource x 'T@1' = { properties: { a: { b: { c:",
		"resource x 'T@1' = { a: ] } ) , }",
		"resource x 'T@1' = { a: 'unterminated",
		"resource x 'T@1' = { a: '${nested '} b }",
		"resource x 'T@1' = [for i in range(0,3): { properties: { supportsHttpsTrafficOnly: false }",
		"resource x 'T@1' existing = ",
		"{{{{{{{{{{{{{{{{",
		"resource resource resource resource",
		"resource x 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n" + strings.Repeat("  nest: {\n", 200),
		strings.Repeat("resource x 'T@1' = {}\n", 100),
	}
	for i, src := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v\nsrc=%q", i, r, src)
				}
			}()
			_ = scanBicep("m.bicep", []byte(src))
		}()
	}
}

// TestBicepStringHeadedExpressionFailClosed guards the string-led dynamic-expression class (review finding):
// a value whose text begins with a string literal but continues into an expression (concat, comparison,
// ternary, member access) is dynamic and must not yield an insecure-literal finding.
func TestBicepStringHeadedExpressionFailClosed(t *testing.T) {
	cases := map[string]string{
		"concat":       "publicNetworkAccess: 'Enabled' + suffix",
		"yoda-ternary": "minimumTlsVersion: 'TLS1_0' == chosen ? 'TLS1_2' : 'TLS1_0'",
		"yoda-compare": "publicNetworkAccess: 'Enabled' == want ? 'Enabled' : 'Disabled'",
	}
	unwanted := []string{"arm-storage-public-network", "arm-storage-min-tls-below-12"}
	for name, prop := range cases {
		src := "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n" +
			"  name: 'store'\n  location: 'eastus'\n  properties: {\n    " + prop + "\n  }\n}\n"
		got := ruleIDs(scan(t, map[string]string{"main.bicep": src}))
		for _, u := range unwanted {
			if _, ok := got[u]; ok {
				t.Errorf("%s: string-headed expression must suppress %s; got %v", name, u, keys(got))
			}
		}
	}
}

// TestBicepDynamicObjectParentFailClosed guards the dynamic-object-parent class (review finding): a nested
// object property set to a dynamic value is unknown, so an "absent hardening" rule that descends into it
// must not fire.
func TestBicepDynamicObjectParentFailClosed(t *testing.T) {
	storage := `resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'store'
  location: 'eastus'
  properties: {
    encryption: encParam
  }
}
`
	if got := ruleIDs(scan(t, map[string]string{"main.bicep": storage})); hasRule(got, "arm-storage-infrastructure-encryption-disabled") {
		t.Errorf("dynamic encryption object must suppress arm-storage-infrastructure-encryption-disabled; got %v", keys(got))
	}
	aks := `resource aks 'Microsoft.ContainerService/managedClusters@2023-01-01' = {
  name: 'cluster'
  location: 'eastus'
  identity: idParam
  properties: {
    enableRBAC: true
    apiServerAccessProfile: apiParam
  }
}
`
	got := ruleIDs(scan(t, map[string]string{"main.bicep": aks}))
	for _, u := range []string{"arm-managed-identity-missing", "arm-aks-private-cluster-disabled"} {
		if hasRule(got, u) {
			t.Errorf("dynamic object/identity must suppress %s; got %v", u, keys(got))
		}
	}
}

// TestBicepUnterminatedStringFailClosed guards review finding 3: an unterminated string is not a plain
// literal and must not produce an insecure-literal finding.
func TestBicepUnterminatedStringFailClosed(t *testing.T) {
	src := "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n" +
		"  name: 'store'\n  location: 'eastus'\n  properties: {\n    publicNetworkAccess: 'Enabled\n  }\n}\n"
	if got := ruleIDs(scan(t, map[string]string{"main.bicep": src})); hasRule(got, "arm-storage-public-network") {
		t.Errorf("unterminated string must not be treated as a literal; got %v", keys(got))
	}
}

// TestBicepNestedResourceNoDesync guards review finding 4: a nested child resource inside a parent body is
// skipped as a whole declaration, so the parent's own later properties are still scanned (no parse desync).
func TestBicepNestedResourceNoDesync(t *testing.T) {
	src := `resource nsg 'Microsoft.Network/networkSecurityGroups@2023-01-01' = {
  name: 'nsg'
  location: 'eastus'
  resource child 'securityRules' = {
    name: 'AllowRdp'
    properties: {
      access: 'Allow'
      direction: 'Inbound'
      sourceAddressPrefix: '10.0.0.0/8'
    }
  }
  properties: {
    securityRules: [
      {
        name: 'open'
        properties: {
          direction: 'Inbound'
          access: 'Allow'
          sourceAddressPrefix: '0.0.0.0/0'
        }
      }
    ]
  }
}
`
	got := ruleIDs(scan(t, map[string]string{"main.bicep": src}))
	if !hasRule(got, "arm-nsg-open-inbound") {
		t.Errorf("parent's open securityRule must still be scanned after a nested child resource; got %v", keys(got))
	}
}

func hasRule(m map[string]ports.MisconfigRawFinding, rule string) bool {
	_, ok := m[rule]
	return ok
}

// TestBicepInlineObjectInExpressionNoDesync guards the security review's FN variant: a string-headed
// expression containing an inline object ('x' ? {a:1} : y) must be consumed whole (consumeExpr tracks
// braces), so a genuinely insecure literal on the NEXT line is still scanned rather than dropped by the
// inline object's closing brace being mistaken for the resource body's.
func TestBicepInlineObjectInExpressionNoDesync(t *testing.T) {
	src := `resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'store'
  location: 'eastus'
  properties: {
    metadata: pick ? {a: 1} : {b: 2}
    supportsHttpsTrafficOnly: false
  }
}
`
	got := ruleIDs(scan(t, map[string]string{"main.bicep": src}))
	if !hasRule(got, "arm-storage-https-only-off") {
		t.Errorf("insecure literal after an inline-object expression must still fire; got %v", keys(got))
	}
}

// TestBicepNestedResourceComplexNoDesync guards the re-review's finding-4 edge cases: a nested child
// resource whose declaration carries a pre-body condition with a bracket index (`if (flags[0])`) or a
// comment containing a brace must still be skipped as a whole, so the parent's own later insecure property
// is scanned. Only a top-level `{`/`[` is the child body.
func TestBicepNestedResourceComplexNoDesync(t *testing.T) {
	cases := map[string]string{
		"condition-bracket": `resource nsg 'Microsoft.Network/networkSecurityGroups@2023-01-01' = {
  name: 'nsg'
  resource child 'securityRules' = if (flags[0]) {
    name: 'c'
    properties: { access: 'Allow' }
  }
  properties: {
    securityRules: [
      { name: 'open', properties: { direction: 'Inbound', access: 'Allow', sourceAddressPrefix: '0.0.0.0/0' } }
    ]
  }
}
`,
		"comment-brace": `resource nsg 'Microsoft.Network/networkSecurityGroups@2023-01-01' = {
  name: 'nsg'
  resource child 'securityRules' = /* body { follows */ {
    name: 'c'
    properties: { access: 'Allow' }
  }
  properties: {
    securityRules: [
      { name: 'open', properties: { direction: 'Inbound', access: 'Allow', sourceAddressPrefix: '0.0.0.0/0' } }
    ]
  }
}
`,
	}
	for name, src := range cases {
		got := ruleIDs(scan(t, map[string]string{"main.bicep": src}))
		if !hasRule(got, "arm-nsg-open-inbound") {
			t.Errorf("%s: parent open securityRule must still be scanned; got %v", name, keys(got))
		}
	}
}

// TestBicepNestedResourceBodyCommentNoOverskip guards the re-review's deeper finding: a comment INSIDE a
// nested child's body containing an unbalanced brace (or an apostrophe) must not miscount the balanced skip
// and consume the parent's own later property. The parent's insecure literal after the child must fire.
func TestBicepNestedResourceBodyCommentNoOverskip(t *testing.T) {
	cases := map[string]string{
		"brace-in-comment": `resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'p'
  resource child 'blobServices' = {
    // stray brace { in a comment
    name: 'c'
  }
  properties: {
    supportsHttpsTrafficOnly: false
  }
}
`,
		"apostrophe-in-comment": `resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'p'
  resource child 'blobServices' = {
    // don't miscount this
    name: 'c'
  }
  properties: {
    supportsHttpsTrafficOnly: false
  }
}
`,
	}
	for name, src := range cases {
		got := ruleIDs(scan(t, map[string]string{"main.bicep": src}))
		if !hasRule(got, "arm-storage-https-only-off") {
			t.Errorf("%s: parent property after a child with a comment must still be scanned; got %v", name, keys(got))
		}
	}
}

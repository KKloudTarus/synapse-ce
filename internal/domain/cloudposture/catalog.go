package cloudposture

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	RuleStoragePublic       = "cloud-storage-public"
	RuleComputePublic       = "cloud-compute-public"
	RuleIdentityWildcard    = "cloud-identity-wildcard"
	RuleIdentityUnusedAdmin = "cloud-identity-unused-privileged"
	RuleEncryptionDisabled  = "cloud-resource-encryption-disabled"
	RuleSensitivePublicPath = "cloud-network-sensitive-public-path"
	RuleIaCLiveDrift        = "cloud-iac-live-drift"
	ClassIaCLiveDrift       = "iac_live_drift"
)

// Rule is a stable clean-room live posture check.
type Rule struct {
	Key      string
	Title    string
	Category string
	Severity shared.Severity
}

func (r Rule) Validate() error {
	if strings.TrimSpace(r.Key) == "" || strings.TrimSpace(r.Title) == "" || strings.TrimSpace(r.Category) == "" {
		return fmt.Errorf("%w: incomplete cloud posture rule", shared.ErrValidation)
	}
	if !r.Severity.Valid() || r.Severity == shared.SeverityUnknown {
		return fmt.Errorf("%w: invalid severity for cloud posture rule %q", shared.ErrValidation, r.Key)
	}
	return nil
}

var catalog = []Rule{
	{RuleStoragePublic, "Cloud storage is public", "public-exposure", shared.SeverityHigh},
	{RuleComputePublic, "Cloud compute is publicly reachable", "public-exposure", shared.SeverityHigh},
	{RuleIdentityWildcard, "Cloud identity grant uses wildcards", "identity", shared.SeverityHigh},
	{RuleIdentityUnusedAdmin, "High-privilege cloud identity is unused", "identity", shared.SeverityMedium},
	{RuleEncryptionDisabled, "Cloud resource encryption is disabled", "encryption", shared.SeverityHigh},
	{RuleSensitivePublicPath, "Public network path reaches a sensitive resource", "network", shared.SeverityCritical},
	{RuleIaCLiveDrift, "Live cloud state differs from infrastructure as code", "drift", shared.SeverityHigh},
}

// Catalog returns a validated, deterministic copy of the built-in rules.
func Catalog() ([]Rule, error) {
	seen := make(map[string]struct{}, len(catalog))
	out := append([]Rule(nil), catalog...)
	for _, r := range out {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if _, ok := seen[r.Key]; ok {
			return nil, fmt.Errorf("%w: duplicate cloud posture rule %q", shared.ErrValidation, r.Key)
		}
		seen[r.Key] = struct{}{}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Evaluate applies the high-confidence checks only to explicit provider facts.
func Evaluate(inv Inventory) ([]PostureFinding, error) {
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	rules, err := Catalog()
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byKey[r.Key] = r
	}
	var out []PostureFinding
	add := func(key string, r Resource, description string) {
		rule := byKey[key]
		out = append(out, PostureFinding{RuleKey: key, ScopeKey: inv.ScopeKey, ResourceID: r.ID, Control: key, Title: rule.Title, Description: description, Severity: rule.Severity, Class: finding.ClassFirstParty})
	}
	for _, r := range inv.Resources {
		switch {
		case r.Kind == asset.KindStorage && r.Public == StateEnabled:
			add(RuleStoragePublic, r, "The provider reports that this storage resource is publicly accessible.")
		case (r.Kind == asset.KindHost || r.Kind == asset.KindWorkload) && r.Public == StateEnabled && r.PublicNetwork == StateEnabled:
			add(RuleComputePublic, r, "The provider reports a public address with an effective public network path.")
		}
		if r.Kind == asset.KindIdentity && r.PolicyKnown && (r.WildcardAction || r.WildcardTarget) {
			add(RuleIdentityWildcard, r, "The provider reports an allow grant with a wildcard action or target.")
		}
		if r.Kind == asset.KindIdentity && r.HighPrivilege && r.LastUseKnown && r.UnusedDays > 90 {
			add(RuleIdentityUnusedAdmin, r, "Provider last-use evidence shows this high-privilege identity has been unused for more than 90 days.")
		}
		if r.Encrypted == StateDisabled {
			add(RuleEncryptionDisabled, r, "The provider explicitly reports encryption disabled.")
		}
		if r.Sensitive && r.PublicNetwork == StateEnabled {
			add(RuleSensitivePublicPath, r, "An effective public network path reaches this sensitive resource.")
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleKey != out[j].RuleKey {
			return out[i].RuleKey < out[j].RuleKey
		}
		return out[i].ResourceID < out[j].ResourceID
	})
	return out, nil
}

// DetectDrift compares only explicit, matched control states.
func DetectDrift(inv Inventory, expectations []Expectation) ([]PostureFinding, []CoverageIssue) {
	live := make(map[string]State, len(inv.Resources)*2)
	for _, r := range inv.Resources {
		live[r.ID+"\x00public"] = r.Public
		live[r.ID+"\x00encrypted"] = r.Encrypted
	}
	var findings []PostureFinding
	var gaps []CoverageIssue
	for _, exp := range expectations {
		if exp.Provider != inv.Provider || exp.ScopeKey != "" && exp.ScopeKey != inv.ScopeKey {
			continue
		}
		state, ok := live[exp.ResourceID+"\x00"+exp.Control]
		if !ok || state == StateUnknown || exp.State == StateUnknown {
			gaps = append(gaps, CoverageIssue{Provider: inv.Provider, Scope: exp.ResourceID, Category: "drift", Code: "iac_identity_unresolved", Detail: exp.Source})
			continue
		}
		if state != exp.State {
			findings = append(findings, PostureFinding{RuleKey: RuleIaCLiveDrift, ScopeKey: inv.ScopeKey, ResourceID: exp.ResourceID, Control: exp.Control, Title: "Live cloud state differs from infrastructure as code", Description: fmt.Sprintf("%s expects %s=%s; live state is %s", exp.Source, exp.Control, exp.State, state), Severity: shared.SeverityHigh, Class: ClassIaCLiveDrift})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ResourceID != findings[j].ResourceID {
			return findings[i].ResourceID < findings[j].ResourceID
		}
		return findings[i].Control < findings[j].Control
	})
	return findings, gaps
}

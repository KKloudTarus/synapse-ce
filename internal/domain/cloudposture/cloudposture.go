// Package cloudposture models vendor-neutral live cloud inventory and posture.
package cloudposture

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Provider identifies a supported cloud control plane.
type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"
)

func (p Provider) Valid() bool {
	switch p {
	case ProviderAWS, ProviderAzure, ProviderGCP:
		return true
	}
	return false
}

// State is a three-valued observed control state. Unknown is never treated as secure.
// NormalizeRoot returns the provider-native root and its stable provider-qualified identity.
func NormalizeRoot(provider Provider, root string) (string, string, error) {
	root = strings.Trim(strings.TrimSpace(root), "/")
	if !provider.Valid() || root == "" || strings.ContainsAny(root, " \t\r\n") {
		return "", "", fmt.Errorf("%w: invalid cloud scope", shared.ErrValidation)
	}
	switch provider {
	case ProviderAWS:
		root = strings.TrimPrefix(root, "organization/")
		root = strings.TrimPrefix(root, "organizations/")
		if !strings.HasPrefix(root, "o-") {
			return "", "", fmt.Errorf("%w: AWS root must be an organization id", shared.ErrValidation)
		}
		return root, "aws:organizations/" + root, nil
	case ProviderAzure:
		if !strings.HasPrefix(root, "subscriptions/") && !strings.HasPrefix(root, "managementGroups/") {
			root = "subscriptions/" + root
		}
		return root, "azure:" + root, nil
	case ProviderGCP:
		if !strings.HasPrefix(root, "projects/") && !strings.HasPrefix(root, "folders/") && !strings.HasPrefix(root, "organizations/") {
			return "", "", fmt.Errorf("%w: GCP root must identify a project, folder, or organization", shared.ErrValidation)
		}
		return root, "gcp:" + root, nil
	default:
		return "", "", fmt.Errorf("%w: invalid cloud provider %q", shared.ErrValidation, provider)
	}
}

// ScopeKey returns the stable provider-qualified identity for one approved root.
func ScopeKey(provider Provider, root string) (string, error) {
	_, key, err := NormalizeRoot(provider, root)
	return key, err
}

type State string

const (
	StateUnknown  State = "unknown"
	StateEnabled  State = "enabled"
	StateDisabled State = "disabled"
)

// Resource is the SDK-free representation of one live cloud resource.
type Resource struct {
	Provider       Provider
	ScopeKey       string
	AccountID      string
	ID             string
	Name           string
	Kind           asset.Kind
	ResourceType   string
	Region         string
	Public         State
	Encrypted      State
	Sensitive      bool
	PublicNetwork  State
	HighPrivilege  bool
	PolicyKnown    bool
	UnusedDays     int
	LastUseKnown   bool
	WildcardAction bool
	WildcardTarget bool
}

// Relationship is an observed relationship between normalized resources.
type Relationship struct {
	ScopeKey string
	FromID   string
	ToID     string
	Kind     asset.EdgeKind
}

// Inventory is a bounded, normalized snapshot returned by a connector.
type Inventory struct {
	Provider      Provider
	ScopeKey      string
	Resources     []Resource
	Relationships []Relationship
	Complete      bool
}

// CoverageIssue records why a scope or category could not be assessed completely.
type CoverageIssue struct {
	Provider Provider `json:"provider"`
	Scope    string   `json:"scope"`
	Category string   `json:"category"`
	Code     string   `json:"code"`
	Detail   string   `json:"detail,omitempty"`
}

// Expectation is one file-derived control expectation that can be joined to live state.
type Expectation struct {
	Provider       Provider
	ScopeKey       string
	ResourceID     string
	Control        string
	State          State
	Source         string
	AnalysisID     shared.ID
	ArtifactDigest string
}

// PostureFinding is a provider-neutral rule match, converted to the standard Finding path by the use case.
type PostureFinding struct {
	RuleKey     string
	ScopeKey    string
	ResourceID  string
	Control     string
	Title       string
	Description string
	Severity    shared.Severity
	Class       string
}

// Validate checks inventory identity and bounded-domain invariants.
func (i Inventory) Validate() error {
	if !i.Provider.Valid() {
		return fmt.Errorf("%w: invalid cloud provider %q", shared.ErrValidation, i.Provider)
	}
	seen := make(map[string]struct{}, len(i.Resources))
	for _, r := range i.Resources {
		if r.Provider != i.Provider || strings.TrimSpace(r.ID) == "" || !r.Kind.Valid() {
			return fmt.Errorf("%w: invalid cloud resource %q", shared.ErrValidation, r.ID)
		}
		if i.ScopeKey != "" && r.ScopeKey != "" && r.ScopeKey != i.ScopeKey {
			return fmt.Errorf("%w: cloud resource %q belongs to another scope", shared.ErrValidation, r.ID)
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("%w: duplicate cloud resource %q", shared.ErrValidation, r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	for _, relationship := range i.Relationships {
		if i.ScopeKey != "" && relationship.ScopeKey != "" && relationship.ScopeKey != i.ScopeKey {
			return fmt.Errorf("%w: cloud relationship belongs to another scope", shared.ErrValidation)
		}
		if _, ok := seen[relationship.FromID]; !ok {
			return fmt.Errorf("%w: cloud relationship source %q is missing", shared.ErrValidation, relationship.FromID)
		}
		if _, ok := seen[relationship.ToID]; !ok {
			return fmt.Errorf("%w: cloud relationship target %q is missing", shared.ErrValidation, relationship.ToID)
		}
	}
	return nil
}

// Sort makes connector output deterministic.
func (i *Inventory) Sort() {
	sort.Slice(i.Resources, func(a, b int) bool { return i.Resources[a].ID < i.Resources[b].ID })
	sort.Slice(i.Relationships, func(a, b int) bool {
		x, y := i.Relationships[a], i.Relationships[b]
		if x.FromID != y.FromID {
			return x.FromID < y.FromID
		}
		if x.ToID != y.ToID {
			return x.ToID < y.ToID
		}
		return x.Kind < y.Kind
	})
}

// Package jsresolution models deterministic JavaScript and TypeScript package
// identity resolution without embedding filesystem or parser implementation details.
package jsresolution

import "github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"

// Status is the explicit package-identity resolution state for an observed import.
type Status string

const (
	StatusBuiltin Status = "builtin"
	// StatusLocal closes an external-looking alias back onto source inside the
	// same non-workspace package. Keeping it explicit prevents supported local
	// aliases from being mistaken for third-party npm dependencies.
	StatusLocal       Status = "local"
	StatusWorkspace   Status = "workspace"
	StatusComponent   Status = "component"
	StatusUnresolved  Status = "unresolved"
	StatusAmbiguous   Status = "ambiguous"
	StatusUnsupported Status = "unsupported"
)

// Valid reports whether s is a supported resolution status.
func (s Status) Valid() bool {
	switch s {
	case StatusBuiltin, StatusLocal, StatusWorkspace, StatusComponent, StatusUnresolved, StatusAmbiguous, StatusUnsupported:
		return true
	default:
		return false
	}
}

// PackageIdentity is a deterministic package identity selected or proposed by
// the resolver. Workspace identities remain distinguishable from SBOM components.
type PackageIdentity struct {
	Name      string
	Version   string
	PURL      string
	Workspace bool
	Path      string
}

// ImportResolution preserves source-edge semantics while recording package identity.
type ImportResolution struct {
	From            string
	Specifier       string
	Position        modulegraph.Position
	Kind            modulegraph.ImportKind
	TypeOnly        bool
	DeclarationOnly bool
	Status          Status
	Package         PackageIdentity
	Candidates      []PackageIdentity
	Reason          string
}

// CoverageIssueKind identifies a condition that makes package identity
// resolution incomplete or unsafe for a later negative reachability conclusion.
type CoverageIssueKind string

const (
	CoverageUnreadableMetadata        CoverageIssueKind = "unreadable-metadata"
	CoverageMalformedMetadata         CoverageIssueKind = "malformed-metadata"
	CoverageUnsupportedMetadata       CoverageIssueKind = "unsupported-metadata"
	CoverageMetadataBudgetExceeded    CoverageIssueKind = "metadata-budget-exceeded"
	CoverageWorkspaceRootEscape       CoverageIssueKind = "workspace-root-escape"
	CoverageSymlinkWorkspace          CoverageIssueKind = "symlink-workspace"
	CoverageWorkspaceNameConflict     CoverageIssueKind = "workspace-name-conflict"
	CoverageUnresolvedSpecifier       CoverageIssueKind = "unresolved-specifier"
	CoverageUnsupportedSpecifier      CoverageIssueKind = "unsupported-specifier"
	CoverageUnresolvedAlias           CoverageIssueKind = "unresolved-alias"
	CoverageUnsupportedAlias          CoverageIssueKind = "unsupported-alias"
	CoverageMissingSBOMComponent      CoverageIssueKind = "missing-sbom-component"
	CoverageAmbiguousSBOMComponent    CoverageIssueKind = "ambiguous-sbom-component"
	CoverageUnsupportedPackageManager CoverageIssueKind = "unsupported-package-manager"
)

// Valid reports whether k is a supported coverage issue kind.
func (k CoverageIssueKind) Valid() bool {
	switch k {
	case CoverageUnreadableMetadata,
		CoverageMalformedMetadata,
		CoverageUnsupportedMetadata,
		CoverageMetadataBudgetExceeded,
		CoverageWorkspaceRootEscape,
		CoverageSymlinkWorkspace,
		CoverageWorkspaceNameConflict,
		CoverageUnresolvedSpecifier,
		CoverageUnsupportedSpecifier,
		CoverageUnresolvedAlias,
		CoverageUnsupportedAlias,
		CoverageMissingSBOMComponent,
		CoverageAmbiguousSBOMComponent,
		CoverageUnsupportedPackageManager:
		return true
	default:
		return false
	}
}

// CoverageIssue records deterministic, attributable incomplete package-resolution coverage.
type CoverageIssue struct {
	Kind   CoverageIssueKind
	Path   string
	Detail string
}

// MetadataDeclaration records where a workspace relationship was declared.
type MetadataDeclaration struct {
	Source  string
	Pattern string
}

// PackageMetadata is package.json-derived first-party package metadata.
// DependencySpec is one declared dependency of a package: the name a source file imports, and the raw
// specification the manifest declares for it.
//
// The spec matters for identity because npm lets a dependency be ALIASED
// ("lodash": "npm:lodash-es@^4") or fetched from somewhere other than the registry (file:, link:,
// workspace:, git+ssh:, github:, patch:). In both cases the imported name is NOT the package name, so
// correlating a specifier to a same-named component would attach the wrong identity.
type DependencySpec struct {
	Name string
	Spec string
}

type PackageMetadata struct {
	Name       string
	Version    string
	Path       string
	Private    bool
	Workspace  bool
	DeclaredBy []MetadataDeclaration
	// Dependencies are the package's declared dependencies, sorted by name and deduplicated.
	Dependencies []DependencySpec
}

// Inventory is the deterministic offline package/workspace metadata inventory
// consumed by later module-specifier and SBOM-correlation stages.
type Inventory struct {
	Packages       []PackageMetadata
	Coverage       []CoverageIssue
	Complete       bool
	EntriesScanned int
	FilesScanned   int
}

// Result is the package-resolution output consumed by a later Tier-1 analyzer.
// Complete is false whenever package-resolution coverage is incomplete; source
// graph coverage is preserved separately and must also be considered by callers.
type Result struct {
	Imports       []ImportResolution
	Coverage      []CoverageIssue
	GraphCoverage []modulegraph.CoverageIssue
	Complete      bool
}

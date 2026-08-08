package jsresolve

import (
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	defaultMaxAliasEntries       = 100000
	defaultMaxAliasFiles         = 10000
	defaultMaxAliasFileBytes     = int64(2 << 20)
	defaultMaxAliasTotalBytes    = int64(32 << 20)
	defaultMaxAliasMappings      = 8192
	defaultMaxAliasTargets       = 64
	defaultMaxAliasPatternBytes  = 4096
	defaultMaxAliasCoverageIssue = 4096
)

type aliasLimits struct {
	maxEntries        int
	maxFiles          int
	maxFileBytes      int64
	maxTotalBytes     int64
	maxMappings       int
	maxTargets        int
	maxPatternBytes   int
	maxCoverageIssues int
}

func defaultAliasLimits() aliasLimits {
	return aliasLimits{
		maxEntries:        defaultMaxAliasEntries,
		maxFiles:          defaultMaxAliasFiles,
		maxFileBytes:      defaultMaxAliasFileBytes,
		maxTotalBytes:     defaultMaxAliasTotalBytes,
		maxMappings:       defaultMaxAliasMappings,
		maxTargets:        defaultMaxAliasTargets,
		maxPatternBytes:   defaultMaxAliasPatternBytes,
		maxCoverageIssues: defaultMaxAliasCoverageIssue,
	}
}

func (l aliasLimits) validate() error {
	if l.maxEntries <= 0 || l.maxFiles <= 0 || l.maxFileBytes <= 0 || l.maxTotalBytes <= 0 ||
		l.maxMappings <= 0 || l.maxTargets <= 0 || l.maxPatternBytes <= 0 || l.maxCoverageIssues <= 0 {
		return fmt.Errorf("%w: alias limits must be positive", shared.ErrValidation)
	}
	return nil
}

type aliasKind uint8

const (
	aliasPackageImports aliasKind = iota + 1
	aliasTSConfigPaths
)

type aliasModuleResolution uint8

const (
	aliasModuleResolutionUnknown aliasModuleResolution = iota
	aliasModuleResolutionExtensionless
	aliasModuleResolutionStrictNode
)

type aliasMapping struct {
	kind             aliasKind
	source           string
	scopeDir         string
	baseDir          string
	pattern          string
	targets          []string
	moduleResolution aliasModuleResolution
}

type aliasConfigContext struct {
	source     string
	scopeDir   string
	hasBaseURL bool
	uncertain  bool
}

type aliasPackageContext struct {
	source         string
	scopeDir       string
	importsPresent bool
	uncertain      bool
}

type aliasInventory struct {
	mappings               []aliasMapping
	configs                []aliasConfigContext
	packageScopes          []aliasPackageContext
	coverage               []jsresolution.CoverageIssue
	scopeDiscoveryComplete bool
}

type aliasInventoryBuilder struct {
	limits aliasLimits
}

func newAliasInventoryBuilder() *aliasInventoryBuilder {
	return &aliasInventoryBuilder{limits: defaultAliasLimits()}
}

func newAliasInventoryBuilderWithLimits(limits aliasLimits) *aliasInventoryBuilder {
	return &aliasInventoryBuilder{limits: limits}
}

type aliasCoverageSink struct {
	issues []jsresolution.CoverageIssue
	limit  int
	capped bool
}

func (s *aliasCoverageSink) add(issue jsresolution.CoverageIssue) {
	if s.capped {
		return
	}
	if len(s.issues) < s.limit-1 {
		s.issues = append(s.issues, issue)
		return
	}
	budget := jsresolution.CoverageIssue{
		Kind:   jsresolution.CoverageMetadataBudgetExceeded,
		Path:   ".",
		Detail: fmt.Sprintf("alias coverage issue budget exceeded (%d)", s.limit),
	}
	if len(s.issues) < s.limit {
		s.issues = append(s.issues, budget)
	} else {
		s.issues[s.limit-1] = budget
	}
	s.capped = true
}

func (s *aliasCoverageSink) addAll(issues []jsresolution.CoverageIssue) {
	for _, issue := range issues {
		s.add(issue)
		if s.capped {
			return
		}
	}
}

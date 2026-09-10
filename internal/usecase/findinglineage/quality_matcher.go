package findinglineage

import (
	"fmt"
	"strconv"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	QualityMatcherVersionV1            = 1
	QualityFingerprintSchemaVersionV1  = 1
	QualityTargetIdentitySchemaVersion = 1
)

type QualityAnchorKind string

const (
	QualityAnchorSymbol QualityAnchorKind = "symbol"
	QualityAnchorAST    QualityAnchorKind = "ast"
	QualityAnchorFile   QualityAnchorKind = "file"
)

func (kind QualityAnchorKind) Valid() bool {
	return kind == QualityAnchorSymbol || kind == QualityAnchorAST || kind == QualityAnchorFile
}

type QualityAnchorV1 struct {
	Kind               QualityAnchorKind
	SchemaVersion      int
	LanguageID         string
	QualifiedSymbol    string
	NodeKind           string
	AncestorNameDigest string
	RawOffsets         map[string]int
}

type QualityRuleProfileV1 struct {
	Primary           string
	Aliases           []string
	OneFindingPerFile bool
}

type QualityMatcherV1 struct {
	rules           SASTMatcherV1
	fileScopedRules map[string]struct{}
}

func NewQualityMatcherV1(profiles []QualityRuleProfileV1) (QualityMatcherV1, error) {
	aliasSets := make([]SASTRuleAliasSetV1, len(profiles))
	fileScoped := map[string]struct{}{}
	for index, profile := range profiles {
		primary, err := normalizeSourceRuleKey("code quality", profile.Primary)
		if err != nil {
			return QualityMatcherV1{}, err
		}
		aliasSets[index] = SASTRuleAliasSetV1{Primary: primary, Aliases: append([]string(nil), profile.Aliases...)}
		if profile.OneFindingPerFile {
			fileScoped[primary] = struct{}{}
		}
	}
	rules, err := NewSASTMatcherV1(aliasSets)
	if err != nil {
		return QualityMatcherV1{}, err
	}
	return QualityMatcherV1{rules: rules, fileScopedRules: fileScoped}, nil
}

type QualityFingerprintInputV1 struct {
	TargetIdentityCanonical string
	FindingClass            string
	RepoPath                string
	RuleKey                 string
	RuleAliases             []string
	Anchor                  QualityAnchorV1
	LegacyDedupKey          string
	LegacySourceValidated   bool
}

type QualityMatchPlanV1 struct {
	FingerprintInput    domain.FingerprintCanonicalInputV1
	Method              domain.MatchMethod
	MatcherVersion      int
	ReasonCode          string
	ReviewReason        domain.CandidateReason
	Ambiguous           bool
	ProvisionalIdentity bool
	SkipInput           bool
}

func (matcher QualityMatcherV1) Build(input QualityFingerprintInputV1) (QualityMatchPlanV1, error) {
	target, err := normalizeSourceText("code quality", "target identity", input.TargetIdentityCanonical, 2048, false)
	if err != nil {
		return QualityMatchPlanV1{}, err
	}
	legacy := parseQualityLegacyKey(input.LegacyDedupKey)
	class := strings.ToLower(strings.TrimSpace(input.FindingClass))
	repoPath := input.RepoPath
	ruleKey := input.RuleKey
	legacyClassMismatch := false
	if legacy.kind == qualityLegacyValid {
		if class == "" {
			class = legacy.class
		} else if class != legacy.class {
			legacyClassMismatch = true
		}
		if strings.TrimSpace(repoPath) == "" {
			repoPath = legacy.repoPath
		}
		if strings.TrimSpace(ruleKey) == "" {
			ruleKey = legacy.ruleKey
		}
	}
	if class != "quality" && class != "reliability" {
		return QualityMatchPlanV1{}, fmt.Errorf("%w: finding class must be quality or reliability", shared.ErrValidation)
	}
	normalizedPath, pathErr := normalizeSourceRepoPath("code quality", repoPath)
	if pathErr != nil && strings.TrimSpace(repoPath) != "" {
		return QualityMatchPlanV1{}, pathErr
	}
	primaryRule, normalizedRules, ruleConflict, ruleErr := matcher.rules.normalizeRule("code quality", ruleKey, input.RuleAliases)
	if ruleErr != nil && strings.TrimSpace(ruleKey) != "" {
		return QualityMatchPlanV1{}, ruleErr
	}
	anchorValue, anchorErr := matcher.normalizeAnchor(primaryRule, input.Anchor)
	if input.Anchor.Kind != "" && !input.Anchor.Kind.Valid() {
		return QualityMatchPlanV1{}, fmt.Errorf("%w: code quality anchor kind is invalid", shared.ErrValidation)
	}
	if len(input.Anchor.RawOffsets) > 0 {
		return QualityMatchPlanV1{}, fmt.Errorf("%w: code quality anchors cannot contain raw offsets", shared.ErrValidation)
	}
	if anchorErr != nil && input.Anchor.Kind.Valid() && input.Anchor.Kind != QualityAnchorFile {
		return QualityMatchPlanV1{}, anchorErr
	}

	fields := map[string]domain.CanonicalValue{
		"finding_class":            domain.Text(class),
		"producer_matcher_version": domain.Integer(QualityMatcherVersionV1),
		"rule_alias_graph_version": domain.Integer(SASTRuleAliasSchemaVersionV1),
	}
	if normalizedPath != "" {
		fields["repo_path"] = domain.Text(normalizedPath)
	}
	if primaryRule != "" {
		fields["rule_key"] = domain.Text(primaryRule)
	}
	if anchorErr == nil && input.Anchor.Kind.Valid() {
		fields["anchor_kind"] = domain.Text(string(input.Anchor.Kind))
		fields["anchor_schema_version"] = domain.Integer(int64(input.Anchor.SchemaVersion))
		fields["anchor_value"] = anchorValue
	}
	if ruleConflict {
		fields["rule_candidates"] = domain.StringSet(normalizedRules...)
		delete(fields, "rule_key")
	}
	plan := QualityMatchPlanV1{
		FingerprintInput: domain.FingerprintCanonicalInputV1{
			CanonicalizationVersion: domain.CanonicalizationVersionV1, ProducerKind: class,
			TargetIdentitySchemaVersion: QualityTargetIdentitySchemaVersion, TargetIdentityCanonical: target, IdentityFields: fields,
		},
		Method: domain.MethodMatcher, MatcherVersion: QualityMatcherVersionV1, ReasonCode: "quality_identity_complete",
	}
	switch {
	case input.LegacyDedupKey != "" && !input.LegacySourceValidated:
		plan.SkipInput, plan.ReasonCode = true, "legacy_source_not_validated"
	case ruleConflict:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous = domain.ReasonMerge, "rule_alias_conflict", true
	case legacyClassMismatch:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonLegacyAmbiguous, "legacy_class_mismatch", true, true
	case legacy.kind == qualityLegacyMalformed:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonLegacyAmbiguous, "legacy_key_malformed", true, true
	case normalizedPath == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_repo_path", true, true
	case primaryRule == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_rule_key", true, true
	case input.Anchor.Kind == QualityAnchorFile && anchorErr != nil:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "file_anchor_not_declared", true, true
	case !input.Anchor.Kind.Valid():
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_semantic_anchor", true, true
	case legacy.kind == qualityLegacyValid:
		plan.ReasonCode = "legacy_quality_structured"
	}
	return plan, nil
}

func (plan QualityMatchPlanV1) Apply(input CorrelateInput) CorrelateInput {
	producer := plan.FingerprintInput.ProducerKind
	input.ProducerKind = producer
	input.FindingKind = producer
	input.FingerprintSchemaVersion = QualityFingerprintSchemaVersionV1
	input.FingerprintInput = plan.FingerprintInput
	input.ReviewReason = plan.ReviewReason
	input.ReviewDetailCode = plan.ReasonCode
	input.ProvisionalIdentity = plan.ProvisionalIdentity
	if plan.SkipInput {
		input.InputTrusted = false
	}
	return input
}

func (matcher QualityMatcherV1) normalizeAnchor(primaryRule string, anchor QualityAnchorV1) (domain.CanonicalValue, error) {
	if !anchor.Kind.Valid() || anchor.SchemaVersion <= 0 {
		return domain.CanonicalValue{}, fmt.Errorf("%w: code quality semantic anchor is required", shared.ErrValidation)
	}
	value := map[string]domain.CanonicalValue{}
	switch anchor.Kind {
	case QualityAnchorSymbol:
		language, err := normalizeSourceToken("code quality", "language id", anchor.LanguageID)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		symbol, err := normalizeSourceText("code quality", "qualified symbol", anchor.QualifiedSymbol, 1024, false)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		if anchor.NodeKind != "" || anchor.AncestorNameDigest != "" {
			return domain.CanonicalValue{}, fmt.Errorf("%w: symbol anchor contains AST fields", shared.ErrValidation)
		}
		value["language_id"] = domain.Text(language)
		value["qualified_symbol"] = domain.Text(symbol)
	case QualityAnchorAST:
		nodeKind, err := normalizeSourceToken("code quality", "AST node kind", anchor.NodeKind)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		digest, err := normalizeSourceDigest("code quality", "AST ancestor/name digest", anchor.AncestorNameDigest)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		if anchor.LanguageID != "" || anchor.QualifiedSymbol != "" {
			return domain.CanonicalValue{}, fmt.Errorf("%w: AST anchor contains symbol fields", shared.ErrValidation)
		}
		value["ancestor_name_digest"] = domain.Text(digest)
		value["node_kind"] = domain.Text(nodeKind)
	case QualityAnchorFile:
		if _, allowed := matcher.fileScopedRules[primaryRule]; !allowed {
			return domain.CanonicalValue{}, fmt.Errorf("%w: rule does not declare one Finding per file", shared.ErrValidation)
		}
		if anchor.LanguageID != "" || anchor.QualifiedSymbol != "" || anchor.NodeKind != "" || anchor.AncestorNameDigest != "" {
			return domain.CanonicalValue{}, fmt.Errorf("%w: file anchor cannot carry symbol or AST fields", shared.ErrValidation)
		}
		value["scope"] = domain.Text("file")
	}
	return domain.Object(value), nil
}

type qualityLegacyKind uint8

const (
	qualityLegacyNone qualityLegacyKind = iota
	qualityLegacyValid
	qualityLegacyMalformed
)

type qualityLegacyKey struct {
	kind     qualityLegacyKind
	class    string
	ruleKey  string
	repoPath string
}

func parseQualityLegacyKey(value string) qualityLegacyKey {
	value = strings.TrimSpace(value)
	if value == "" {
		return qualityLegacyKey{}
	}
	if !strings.HasPrefix(value, "cq:") {
		return qualityLegacyKey{kind: qualityLegacyMalformed}
	}
	rest := strings.TrimPrefix(value, "cq:")
	classEnd := strings.IndexByte(rest, ':')
	if classEnd <= 0 {
		return qualityLegacyKey{kind: qualityLegacyMalformed}
	}
	class := rest[:classEnd]
	if class != "quality" && class != "reliability" {
		return qualityLegacyKey{kind: qualityLegacyMalformed}
	}
	rest = rest[classEnd+1:]
	lineSeparator := strings.LastIndexByte(rest, ':')
	if lineSeparator <= 0 {
		return qualityLegacyKey{kind: qualityLegacyMalformed}
	}
	line, err := strconv.Atoi(rest[lineSeparator+1:])
	pathSeparator := strings.LastIndexByte(rest[:lineSeparator], ':')
	if err != nil || line < 1 || pathSeparator <= 0 || pathSeparator == lineSeparator-1 {
		return qualityLegacyKey{kind: qualityLegacyMalformed}
	}
	return qualityLegacyKey{kind: qualityLegacyValid, class: class, ruleKey: rest[:pathSeparator], repoPath: rest[pathSeparator+1 : lineSeparator]}
}

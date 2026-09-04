package findinglineage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"golang.org/x/text/unicode/norm"
)

const (
	SASTMatcherVersionV1             = 1
	SASTFingerprintSchemaVersionV1   = 1
	SASTTargetIdentitySchemaVersion  = 1
	SASTRuleAliasSchemaVersionV1     = 1
	SASTIdentityAliasSchemaVersionV1 = 1
)

type SASTAnchorKind string

const (
	SASTAnchorSymbol   SASTAnchorKind = "symbol"
	SASTAnchorAST      SASTAnchorKind = "ast"
	SASTAnchorDataflow SASTAnchorKind = "dataflow"
	SASTAnchorJudgment SASTAnchorKind = "judgment"
)

func (kind SASTAnchorKind) Valid() bool {
	switch kind {
	case SASTAnchorSymbol, SASTAnchorAST, SASTAnchorDataflow, SASTAnchorJudgment:
		return true
	}
	return false
}

type SASTAnchorV1 struct {
	Kind                   SASTAnchorKind
	SchemaVersion          int
	LanguageID             string
	QualifiedSymbol        string
	NodeKind               string
	AncestorNameDigest     string
	SourceRuleClass        string
	SinkRuleClass          string
	GraphAnchorDigest      string
	JudgmentID             shared.ID
	JudgmentSemanticDigest string
	RawOffsets             map[string]int
}

type SASTRuleAliasSetV1 struct {
	Primary string
	Aliases []string
}

type SASTMatcherV1 struct {
	rulePrimaries map[string]map[string]struct{}
}

func NewSASTMatcherV1(aliasSets []SASTRuleAliasSetV1) (SASTMatcherV1, error) {
	matcher := SASTMatcherV1{rulePrimaries: map[string]map[string]struct{}{}}
	for _, aliasSet := range aliasSets {
		primary, err := normalizeSourceRuleKey("SAST", aliasSet.Primary)
		if err != nil {
			return SASTMatcherV1{}, err
		}
		for _, raw := range append([]string{primary}, aliasSet.Aliases...) {
			alias, err := normalizeSourceRuleKey("SAST", raw)
			if err != nil {
				return SASTMatcherV1{}, err
			}
			if matcher.rulePrimaries[alias] == nil {
				matcher.rulePrimaries[alias] = map[string]struct{}{}
			}
			matcher.rulePrimaries[alias][primary] = struct{}{}
		}
	}
	return matcher, nil
}

func (SASTMatcherV1) Descriptor() domain.MatcherDescriptor {
	return domain.MatcherDescriptor{
		ProducerKind: "sast", FindingKind: "sast", Method: domain.MethodMatcher,
		MethodVersion: SASTMatcherVersionV1, CanonicalizationVersion: domain.CanonicalizationVersionV1,
		FingerprintSchemaVersion: SASTFingerprintSchemaVersionV1, TargetIdentitySchemaVersion: SASTTargetIdentitySchemaVersion,
	}
}

type SASTFingerprintInputV1 struct {
	TargetIdentityCanonical string
	RepoPath                string
	PriorRepoPath           string
	RuleKey                 string
	RuleAliases             []string
	Anchor                  SASTAnchorV1
	LegacyDedupKey          string
	LegacySourceValidated   bool
	LegacyOwnershipValid    bool
	JudgmentAnchor          *SASTAnchorV1
	TrustedProducerIdentity bool
	ApprovedIdentityAliases []string
}

type SASTMatchPlanV1 struct {
	FingerprintInput    domain.FingerprintCanonicalInputV1
	Aliases             []AliasInput
	Method              domain.MatchMethod
	MatcherVersion      int
	ReasonCode          string
	ReviewReason        domain.CandidateReason
	Ambiguous           bool
	ProvisionalIdentity bool
	TrustedProducerID   bool
	PathChanged         bool
	SkipInput           bool
	SkipOwnership       bool
}

func (matcher SASTMatcherV1) Build(input SASTFingerprintInputV1) (SASTMatchPlanV1, error) {
	target, err := normalizeSourceText("SAST", "target identity", input.TargetIdentityCanonical, 2048, false)
	if err != nil {
		return SASTMatchPlanV1{}, err
	}

	legacy := parseSASTLegacyKey(input.LegacyDedupKey)
	repoPath := input.RepoPath
	ruleKey := input.RuleKey
	anchor := input.Anchor
	if legacy.kind == sastLegacyCodeQuality {
		if strings.TrimSpace(repoPath) == "" {
			repoPath = legacy.repoPath
		}
		if strings.TrimSpace(ruleKey) == "" {
			ruleKey = legacy.ruleKey
		}
	}
	if legacy.kind == sastLegacyJudgment {
		switch {
		case input.JudgmentAnchor == nil:
			anchor = SASTAnchorV1{}
		case input.JudgmentAnchor.Kind != SASTAnchorJudgment || input.JudgmentAnchor.JudgmentID.String() != legacy.judgmentID:
			anchor = SASTAnchorV1{}
		default:
			anchor = *input.JudgmentAnchor
		}
	}

	normalizedPath, pathErr := normalizeSourceRepoPath("SAST", repoPath)
	primaryRule, normalizedRules, ruleConflict, ruleErr := matcher.normalizeRule("SAST", ruleKey, input.RuleAliases)
	if anchor.Kind != "" && !anchor.Kind.Valid() {
		return SASTMatchPlanV1{}, fmt.Errorf("%w: SAST semantic anchor kind is invalid", shared.ErrValidation)
	}
	if len(anchor.RawOffsets) > 0 && !anchor.Kind.Valid() {
		return SASTMatchPlanV1{}, fmt.Errorf("%w: SAST semantic anchors cannot contain raw offsets", shared.ErrValidation)
	}
	anchorValue, anchorErr := normalizeSASTAnchor(anchor)
	if pathErr != nil && strings.TrimSpace(repoPath) != "" {
		return SASTMatchPlanV1{}, pathErr
	}
	if ruleErr != nil && strings.TrimSpace(ruleKey) != "" {
		return SASTMatchPlanV1{}, ruleErr
	}
	if anchorErr != nil && anchor.Kind.Valid() {
		return SASTMatchPlanV1{}, anchorErr
	}

	fields := map[string]domain.CanonicalValue{
		"producer_matcher_version": domain.Integer(SASTMatcherVersionV1),
		"rule_alias_graph_version": domain.Integer(SASTRuleAliasSchemaVersionV1),
	}
	if normalizedPath != "" {
		fields["repo_path"] = domain.Text(normalizedPath)
	}
	if primaryRule != "" {
		fields["rule_key"] = domain.Text(primaryRule)
	}
	if anchorErr == nil && anchor.Kind.Valid() {
		fields["anchor_kind"] = domain.Text(string(anchor.Kind))
		fields["anchor_schema_version"] = domain.Integer(int64(anchor.SchemaVersion))
		fields["anchor_value"] = anchorValue
	}
	if ruleConflict {
		fields["rule_candidates"] = domain.StringSet(normalizedRules...)
		delete(fields, "rule_key")
	}

	plan := SASTMatchPlanV1{
		FingerprintInput: domain.FingerprintCanonicalInputV1{
			CanonicalizationVersion: domain.CanonicalizationVersionV1,
			ProducerKind:            "sast", TargetIdentitySchemaVersion: SASTTargetIdentitySchemaVersion,
			TargetIdentityCanonical: target, IdentityFields: fields,
		},
		Method: domain.MethodMatcher, MatcherVersion: SASTMatcherVersionV1, ReasonCode: "sast_identity_complete",
		TrustedProducerID: input.TrustedProducerIdentity,
	}
	approvedAliases := append([]string(nil), input.ApprovedIdentityAliases...)
	sort.Strings(approvedAliases)
	lastAlias := ""
	for _, alias := range approvedAliases {
		normalized, normalizeErr := normalizeSourceText("SAST", "approved identity alias", alias, 2048, false)
		if normalizeErr != nil {
			return SASTMatchPlanV1{}, normalizeErr
		}
		if normalized == lastAlias {
			continue
		}
		lastAlias = normalized
		plan.Aliases = append(plan.Aliases, AliasInput{SchemaVersion: SASTIdentityAliasSchemaVersionV1, Value: normalized})
	}

	if strings.TrimSpace(input.PriorRepoPath) != "" {
		prior, priorErr := normalizeSourceRepoPath("SAST", input.PriorRepoPath)
		if priorErr != nil {
			return SASTMatchPlanV1{}, priorErr
		}
		plan.PathChanged = normalizedPath != "" && prior != normalizedPath
	}

	switch {
	case input.LegacyDedupKey != "" && !input.LegacySourceValidated:
		plan.SkipInput, plan.ReasonCode = true, "legacy_source_not_validated"
	case input.LegacyDedupKey != "" && !input.LegacyOwnershipValid:
		plan.SkipOwnership, plan.ReasonCode = true, "legacy_ownership_not_validated"
	case ruleConflict:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous = domain.ReasonMerge, "rule_alias_conflict", true
	case legacy.kind == sastLegacyJudgment && input.JudgmentAnchor == nil:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonLegacyAmbiguous, "legacy_judgment_missing", true, true
	case legacy.kind == sastLegacyJudgment && (input.JudgmentAnchor.Kind != SASTAnchorJudgment || input.JudgmentAnchor.JudgmentID.String() != legacy.judgmentID):
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonLegacyAmbiguous, "legacy_judgment_mismatch", true, true
	case legacy.kind == sastLegacyMalformed:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonLegacyAmbiguous, "legacy_key_malformed", true, true
	case pathErr != nil || normalizedPath == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_repo_path", true, true
	case ruleErr != nil || primaryRule == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_rule_key", true, true
	case anchorErr != nil || !anchor.Kind.Valid():
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_semantic_anchor", true, true
	case legacy.kind == sastLegacyCodeQuality:
		plan.ReasonCode = "legacy_code_quality_structured"
	case legacy.kind == sastLegacyJudgment:
		plan.ReasonCode = "legacy_judgment_resolved"
	}
	return plan, nil
}

func (plan SASTMatchPlanV1) Apply(input CorrelateInput) CorrelateInput {
	input.ProducerKind = "sast"
	input.FindingKind = "sast"
	input.FingerprintSchemaVersion = SASTFingerprintSchemaVersionV1
	input.FingerprintInput = plan.FingerprintInput
	input.Aliases = append([]AliasInput(nil), plan.Aliases...)
	input.TrustedProducerID = input.TrustedProducerID || plan.TrustedProducerID
	input.ReviewReason = plan.ReviewReason
	input.ReviewDetailCode = plan.ReasonCode
	input.ProvisionalIdentity = plan.ProvisionalIdentity
	if plan.PathChanged && input.OverrideSourceObservationID.IsZero() && !input.TrustedProducerID && len(input.Aliases) == 0 {
		input.ReviewReason = domain.ReasonLegacyAmbiguous
		input.ReviewDetailCode = "unapproved_path_change"
	}
	if plan.SkipInput {
		input.InputTrusted = false
	}
	if plan.SkipOwnership {
		input.OwnershipValidated = false
	}
	return input
}

func SASTJudgmentAnchorV1(expectedEngagementID shared.ID, current judgment.Judgment) (SASTAnchorV1, error) {
	if expectedEngagementID.IsZero() || current.ID.IsZero() || current.EngagementID != expectedEngagementID {
		return SASTAnchorV1{}, fmt.Errorf("%w: SAST judgment ownership does not match the Assessment", shared.ErrForbidden)
	}
	if current.Capability != judgment.CapSAST || !current.Publishable() {
		return SASTAnchorV1{}, fmt.Errorf("%w: SAST judgment must be confirmed and publishable", shared.ErrValidation)
	}
	if !current.SubjectKind.Valid() || current.SubjectID.IsZero() {
		return SASTAnchorV1{}, fmt.Errorf("%w: SAST judgment subject is invalid", shared.ErrValidation)
	}
	claim, ok := current.Claim.(judgment.SASTClaim)
	if !ok {
		return SASTAnchorV1{}, fmt.Errorf("%w: SAST judgment claim type is invalid", shared.ErrValidation)
	}
	if err := claim.Validate(); err != nil {
		return SASTAnchorV1{}, err
	}
	canonical, err := json.Marshal(struct {
		Capability  judgment.Capability  `json:"capability"`
		SubjectKind judgment.SubjectKind `json:"subject_kind"`
		SubjectID   shared.ID            `json:"subject_id"`
		CWE         string               `json:"cwe"`
		Rule        string               `json:"rule"`
		AssetID     shared.ID            `json:"asset_id"`
	}{current.Capability, current.SubjectKind, current.SubjectID, claim.CWE, claim.Rule, claim.AssetID})
	if err != nil {
		return SASTAnchorV1{}, fmt.Errorf("marshal SAST judgment semantic anchor: %w", err)
	}
	digest := sha256.Sum256(append([]byte("synapse:sast-judgment-anchor:v1\x00"), canonical...))
	return SASTAnchorV1{
		Kind: SASTAnchorJudgment, SchemaVersion: 1, JudgmentID: current.ID,
		JudgmentSemanticDigest: hex.EncodeToString(digest[:]),
	}, nil
}

func (matcher SASTMatcherV1) normalizeRule(producer, rule string, aliases []string) (string, []string, bool, error) {
	observed := make([]string, 0, len(aliases)+1)
	for _, raw := range append([]string{rule}, aliases...) {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		normalized, err := normalizeSourceRuleKey(producer, raw)
		if err != nil {
			return "", nil, false, err
		}
		observed = append(observed, normalized)
	}
	if len(observed) == 0 {
		return "", nil, false, fmt.Errorf("%w: SAST rule key is required", shared.ErrValidation)
	}
	primaries := map[string]struct{}{}
	for _, observedRule := range observed {
		mapped := matcher.rulePrimaries[observedRule]
		if len(mapped) == 0 {
			primaries[observedRule] = struct{}{}
			continue
		}
		for primary := range mapped {
			primaries[primary] = struct{}{}
		}
	}
	values := make([]string, 0, len(primaries))
	for primary := range primaries {
		values = append(values, primary)
	}
	sort.Strings(values)
	if len(values) != 1 {
		return "", values, true, nil
	}
	return values[0], values, false, nil
}

func normalizeSASTAnchor(anchor SASTAnchorV1) (domain.CanonicalValue, error) {
	if !anchor.Kind.Valid() || anchor.SchemaVersion <= 0 {
		return domain.CanonicalValue{}, fmt.Errorf("%w: SAST semantic anchor is required", shared.ErrValidation)
	}
	if len(anchor.RawOffsets) > 0 {
		return domain.CanonicalValue{}, fmt.Errorf("%w: SAST semantic anchors cannot contain raw offsets", shared.ErrValidation)
	}
	value := map[string]domain.CanonicalValue{}
	switch anchor.Kind {
	case SASTAnchorSymbol:
		language, err := normalizeSourceToken("SAST", "language id", anchor.LanguageID)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		symbol, err := normalizeSourceText("SAST", "qualified symbol", anchor.QualifiedSymbol, 1024, false)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		if anchor.NodeKind != "" || anchor.AncestorNameDigest != "" || anchor.SourceRuleClass != "" || anchor.SinkRuleClass != "" || anchor.GraphAnchorDigest != "" || !anchor.JudgmentID.IsZero() || anchor.JudgmentSemanticDigest != "" {
			return domain.CanonicalValue{}, fmt.Errorf("%w: symbol anchor contains fields from another anchor kind", shared.ErrValidation)
		}
		value["language_id"] = domain.Text(language)
		value["qualified_symbol"] = domain.Text(symbol)
	case SASTAnchorAST:
		nodeKind, err := normalizeSourceToken("SAST", "AST node kind", anchor.NodeKind)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		digest, err := normalizeSourceDigest("SAST", "AST ancestor/name digest", anchor.AncestorNameDigest)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		if anchor.LanguageID != "" || anchor.QualifiedSymbol != "" || anchor.SourceRuleClass != "" || anchor.SinkRuleClass != "" || anchor.GraphAnchorDigest != "" || !anchor.JudgmentID.IsZero() || anchor.JudgmentSemanticDigest != "" {
			return domain.CanonicalValue{}, fmt.Errorf("%w: AST anchor contains fields from another anchor kind", shared.ErrValidation)
		}
		value["ancestor_name_digest"] = domain.Text(digest)
		value["node_kind"] = domain.Text(nodeKind)
	case SASTAnchorDataflow:
		sourceClass, err := normalizeSourceToken("SAST", "dataflow source rule class", anchor.SourceRuleClass)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		sinkClass, err := normalizeSourceToken("SAST", "dataflow sink rule class", anchor.SinkRuleClass)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		graphDigest, err := normalizeSourceDigest("SAST", "dataflow graph anchor", anchor.GraphAnchorDigest)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		if anchor.LanguageID != "" || anchor.QualifiedSymbol != "" || anchor.NodeKind != "" || anchor.AncestorNameDigest != "" || !anchor.JudgmentID.IsZero() || anchor.JudgmentSemanticDigest != "" {
			return domain.CanonicalValue{}, fmt.Errorf("%w: dataflow anchor contains fields from another anchor kind", shared.ErrValidation)
		}
		value["graph_anchor_digest"] = domain.Text(graphDigest)
		value["sink_rule_class"] = domain.Text(sinkClass)
		value["source_rule_class"] = domain.Text(sourceClass)
	case SASTAnchorJudgment:
		judgmentID, err := normalizeSourceText("SAST", "judgment id", anchor.JudgmentID.String(), 512, false)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		digest, err := normalizeSourceDigest("SAST", "judgment semantic digest", anchor.JudgmentSemanticDigest)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		if anchor.LanguageID != "" || anchor.QualifiedSymbol != "" || anchor.NodeKind != "" || anchor.AncestorNameDigest != "" || anchor.SourceRuleClass != "" || anchor.SinkRuleClass != "" || anchor.GraphAnchorDigest != "" {
			return domain.CanonicalValue{}, fmt.Errorf("%w: judgment anchor contains fields from another anchor kind", shared.ErrValidation)
		}
		value["judgment_id"] = domain.Text(judgmentID)
		value["semantic_digest"] = domain.Text(digest)
	}
	return domain.Object(value), nil
}

func normalizeSourceRepoPath(producer, value string) (string, error) {
	value = norm.NFC.String(strings.TrimSpace(value))
	if value == "" {
		return "", fmt.Errorf("%w: %s repository path is required", shared.ErrValidation, producer)
	}
	if !utf8.ValidString(value) || len(value) > 2048 || strings.Contains(value, "\\") || path.IsAbs(value) || len(value) >= 2 && value[1] == ':' {
		return "", fmt.Errorf("%w: %s repository path must be a bounded relative slash path", shared.ErrValidation, producer)
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: %s repository path traversal is forbidden", shared.ErrValidation, producer)
		}
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%w: %s repository path is invalid", shared.ErrValidation, producer)
	}
	for _, char := range cleaned {
		if unicode.IsControl(char) {
			return "", fmt.Errorf("%w: %s repository path contains control characters", shared.ErrValidation, producer)
		}
	}
	if containsSourceSensitiveMarker(cleaned) {
		return "", fmt.Errorf("%w: %s repository path contains sensitive input", domain.ErrSensitiveInput, producer)
	}
	return cleaned, nil
}

func normalizeSourceRuleKey(producer, value string) (string, error) {
	return normalizeSourceText(producer, "rule key", value, 256, true)
}

func normalizeSourceToken(producer, name, value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 128 {
		return "", fmt.Errorf("%w: %s %s is required", shared.ErrValidation, producer, name)
	}
	for index, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9' && index > 0) || index > 0 && strings.ContainsRune("+._-/", char) {
			continue
		}
		return "", fmt.Errorf("%w: %s %s is not a stable token", shared.ErrValidation, producer, name)
	}
	return value, nil
}

func normalizeSourceDigest(producer, name, value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != sha256.Size*2 {
		return "", fmt.Errorf("%w: %s %s must be a SHA-256 digest", shared.ErrValidation, producer, name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("%w: %s %s must be a SHA-256 digest", shared.ErrValidation, producer, name)
	}
	return value, nil
}

func normalizeSourceText(producer, name, value string, maximum int, rejectWhitespace bool) (string, error) {
	value = norm.NFC.String(strings.TrimSpace(value))
	if value == "" || !utf8.ValidString(value) || len(value) > maximum {
		return "", fmt.Errorf("%w: %s %s is required and must not exceed %d bytes", shared.ErrValidation, producer, name, maximum)
	}
	for _, char := range value {
		if unicode.IsControl(char) || rejectWhitespace && unicode.IsSpace(char) {
			return "", fmt.Errorf("%w: %s %s contains invalid characters", shared.ErrValidation, producer, name)
		}
	}
	if containsSourceSensitiveMarker(value) {
		return "", fmt.Errorf("%w: %s %s contains sensitive input", domain.ErrSensitiveInput, producer, name)
	}
	return value, nil
}

func containsSourceSensitiveMarker(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password=", "passwd=", "token=", "api_key=", "apikey=", "secret=", "authorization:", "bearer "} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

type sastLegacyKind uint8

const (
	sastLegacyNone sastLegacyKind = iota
	sastLegacyJudgment
	sastLegacyCodeQuality
	sastLegacyMalformed
)

type sastLegacyKey struct {
	kind       sastLegacyKind
	judgmentID string
	ruleKey    string
	repoPath   string
}

func parseSASTLegacyKey(value string) sastLegacyKey {
	value = strings.TrimSpace(value)
	if value == "" {
		return sastLegacyKey{}
	}
	if strings.HasPrefix(value, "sast:ai:") {
		judgmentID := strings.TrimSpace(strings.TrimPrefix(value, "sast:ai:"))
		if judgmentID == "" || strings.ContainsAny(judgmentID, "\x00\r\n") {
			return sastLegacyKey{kind: sastLegacyMalformed}
		}
		return sastLegacyKey{kind: sastLegacyJudgment, judgmentID: judgmentID}
	}
	if strings.HasPrefix(value, "cq:sast:") {
		rest := strings.TrimPrefix(value, "cq:sast:")
		lineSeparator := strings.LastIndexByte(rest, ':')
		if lineSeparator <= 0 {
			return sastLegacyKey{kind: sastLegacyMalformed}
		}
		line, err := strconv.Atoi(rest[lineSeparator+1:])
		pathSeparator := strings.LastIndexByte(rest[:lineSeparator], ':')
		if err != nil || line < 1 || pathSeparator <= 0 || pathSeparator == lineSeparator-1 {
			return sastLegacyKey{kind: sastLegacyMalformed}
		}
		return sastLegacyKey{
			kind: sastLegacyCodeQuality, ruleKey: rest[:pathSeparator], repoPath: rest[pathSeparator+1 : lineSeparator],
		}
	}
	return sastLegacyKey{kind: sastLegacyMalformed}
}

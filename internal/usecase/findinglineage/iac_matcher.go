package findinglineage

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	IaCMatcherVersionV1            = 1
	IaCFingerprintSchemaVersionV1  = 1
	IaCTargetIdentitySchemaVersion = 1
)

type IaCConfigKind string

const (
	IaCTerraform      IaCConfigKind = "terraform"
	IaCCloudFormation IaCConfigKind = "cloudformation"
	IaCKubernetes     IaCConfigKind = "kubernetes"
)

func (kind IaCConfigKind) Valid() bool {
	return kind == IaCTerraform || kind == IaCCloudFormation || kind == IaCKubernetes
}

type IaCRuleAliasSetV1 struct {
	Primary string
	Aliases []string
}

type IaCMatcherV1 struct {
	rules SASTMatcherV1
}

func NewIaCMatcherV1(aliasSets []IaCRuleAliasSetV1) (IaCMatcherV1, error) {
	sharedSets := make([]SASTRuleAliasSetV1, len(aliasSets))
	for index, aliasSet := range aliasSets {
		sharedSets[index] = SASTRuleAliasSetV1{Primary: aliasSet.Primary, Aliases: append([]string(nil), aliasSet.Aliases...)}
	}
	rules, err := NewSASTMatcherV1(sharedSets)
	if err != nil {
		return IaCMatcherV1{}, err
	}
	return IaCMatcherV1{rules: rules}, nil
}

type IaCFingerprintInputV1 struct {
	TargetIdentityCanonical    string
	ConfigKind                 IaCConfigKind
	RuleKey                    string
	RuleAliases                []string
	RepoPath                   string
	SemanticConfigAnchorDigest string
	TerraformAddress           string
	CloudFormationStackPath    []string
	CloudFormationLogicalID    string
	KubernetesAPIVersion       string
	KubernetesKind             string
	KubernetesNamespace        string
	KubernetesName             string
	KubernetesIdentityApproved bool
	LegacyDedupKey             string
	LegacySourceValidated      bool
	RuntimeResourceID          string
	RenderedValue              string
	RawOffsets                 map[string]int
}

type IaCMatchPlanV1 struct {
	FingerprintInput    domain.FingerprintCanonicalInputV1
	Method              domain.MatchMethod
	MatcherVersion      int
	ReasonCode          string
	ReviewReason        domain.CandidateReason
	Ambiguous           bool
	ProvisionalIdentity bool
	SkipInput           bool
}

func (matcher IaCMatcherV1) Build(input IaCFingerprintInputV1) (IaCMatchPlanV1, error) {
	if strings.TrimSpace(input.RuntimeResourceID) != "" || strings.TrimSpace(input.RenderedValue) != "" {
		return IaCMatchPlanV1{}, fmt.Errorf("%w: IaC runtime identifiers and rendered values are observation-only", shared.ErrValidation)
	}
	if len(input.RawOffsets) > 0 {
		return IaCMatchPlanV1{}, fmt.Errorf("%w: IaC identity cannot contain raw offsets", shared.ErrValidation)
	}
	target, err := normalizeSourceText("IaC", "target identity", input.TargetIdentityCanonical, 2048, false)
	if err != nil {
		return IaCMatchPlanV1{}, err
	}
	legacy := parseIaCLegacyKey(input.LegacyDedupKey)
	ruleKey := input.RuleKey
	repoPath := input.RepoPath
	if legacy.kind == iacLegacyValid {
		if strings.TrimSpace(ruleKey) == "" {
			ruleKey = legacy.ruleKey
		}
		if strings.TrimSpace(repoPath) == "" {
			repoPath = legacy.repoPath
		}
	}
	configKind := input.ConfigKind
	if !configKind.Valid() {
		configKind = inferIaCConfigKind(ruleKey)
	}
	if !configKind.Valid() {
		return IaCMatchPlanV1{}, fmt.Errorf("%w: IaC config kind is unsupported", shared.ErrValidation)
	}
	normalizedPath, pathErr := normalizeSourceRepoPath("IaC", repoPath)
	if pathErr != nil && strings.TrimSpace(repoPath) != "" {
		return IaCMatchPlanV1{}, pathErr
	}
	primaryRule, normalizedRules, ruleConflict, ruleErr := matcher.rules.normalizeRule("IaC", ruleKey, input.RuleAliases)
	if ruleErr != nil && strings.TrimSpace(ruleKey) != "" {
		return IaCMatchPlanV1{}, ruleErr
	}
	semanticAnchor, semanticErr := normalizeSourceDigest("IaC", "semantic config anchor", input.SemanticConfigAnchorDigest)
	if semanticErr != nil && strings.TrimSpace(input.SemanticConfigAnchorDigest) != "" {
		return IaCMatchPlanV1{}, semanticErr
	}
	resourceAnchor, resourceReason, resourceErr := normalizeIaCResourceAnchor(configKind, input)
	if resourceErr != nil {
		return IaCMatchPlanV1{}, resourceErr
	}

	fields := map[string]domain.CanonicalValue{
		"config_kind":               domain.Text(string(configKind)),
		"producer_matcher_version":  domain.Integer(IaCMatcherVersionV1),
		"rule_alias_graph_version":  domain.Integer(SASTRuleAliasSchemaVersionV1),
		"resource_adapter_version":  domain.Integer(1),
		"resource_identity_grammar": domain.Text(string(configKind) + "_v1"),
	}
	if normalizedPath != "" {
		fields["repo_path"] = domain.Text(normalizedPath)
	}
	if primaryRule != "" {
		fields["rule_key"] = domain.Text(primaryRule)
	}
	if semanticAnchor != "" {
		fields["semantic_config_anchor"] = domain.Text(semanticAnchor)
	}
	if resourceReason == "" {
		fields["resource_anchor"] = resourceAnchor
	}
	if ruleConflict {
		fields["rule_candidates"] = domain.StringSet(normalizedRules...)
		delete(fields, "rule_key")
	}
	plan := IaCMatchPlanV1{
		FingerprintInput: domain.FingerprintCanonicalInputV1{
			CanonicalizationVersion: domain.CanonicalizationVersionV1, ProducerKind: "iac",
			TargetIdentitySchemaVersion: IaCTargetIdentitySchemaVersion, TargetIdentityCanonical: target, IdentityFields: fields,
		},
		Method: domain.MethodMatcher, MatcherVersion: IaCMatcherVersionV1, ReasonCode: "iac_identity_complete",
	}
	switch {
	case input.LegacyDedupKey != "" && !input.LegacySourceValidated:
		plan.SkipInput, plan.ReasonCode = true, "legacy_source_not_validated"
	case ruleConflict:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous = domain.ReasonMerge, "rule_alias_conflict", true
	case legacy.kind == iacLegacyMalformed:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonLegacyAmbiguous, "legacy_key_malformed", true, true
	case normalizedPath == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_repo_path", true, true
	case primaryRule == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_rule_key", true, true
	case semanticAnchor == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_semantic_config_anchor", true, true
	case resourceReason != "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, resourceReason, true, true
	case legacy.kind == iacLegacyValid:
		plan.ReasonCode = "legacy_iac_structured"
	}
	return plan, nil
}

func (plan IaCMatchPlanV1) Apply(input CorrelateInput) CorrelateInput {
	input.ProducerKind = "iac"
	input.FindingKind = "misconfig"
	input.FingerprintSchemaVersion = IaCFingerprintSchemaVersionV1
	input.FingerprintInput = plan.FingerprintInput
	input.ReviewReason = plan.ReviewReason
	input.ReviewDetailCode = plan.ReasonCode
	input.ProvisionalIdentity = plan.ProvisionalIdentity
	if plan.SkipInput {
		input.InputTrusted = false
	}
	return input
}

func normalizeIaCResourceAnchor(kind IaCConfigKind, input IaCFingerprintInputV1) (domain.CanonicalValue, string, error) {
	switch kind {
	case IaCTerraform:
		if strings.TrimSpace(input.TerraformAddress) == "" {
			return domain.CanonicalValue{}, "missing_terraform_address", nil
		}
		modulePath, resourceAddress, err := normalizeTerraformAddress(input.TerraformAddress)
		if err != nil {
			return domain.CanonicalValue{}, "", err
		}
		if modulePath == "" {
			modulePath = "root"
		}
		return domain.Object(map[string]domain.CanonicalValue{
			"module_path":      domain.Text(modulePath),
			"resource_address": domain.Text(resourceAddress),
		}), "", nil
	case IaCCloudFormation:
		if strings.TrimSpace(input.CloudFormationLogicalID) == "" {
			return domain.CanonicalValue{}, "missing_cloudformation_logical_id", nil
		}
		logicalID, err := normalizeCloudFormationLogicalID(input.CloudFormationLogicalID)
		if err != nil {
			return domain.CanonicalValue{}, "", err
		}
		if len(input.CloudFormationStackPath) > 32 {
			return domain.CanonicalValue{}, "", fmt.Errorf("%w: CloudFormation nested stack path is too deep", shared.ErrValidation)
		}
		stackPath := make([]domain.CanonicalValue, len(input.CloudFormationStackPath))
		for index, segment := range input.CloudFormationStackPath {
			normalized, normalizeErr := normalizeCloudFormationLogicalID(segment)
			if normalizeErr != nil {
				return domain.CanonicalValue{}, "", normalizeErr
			}
			stackPath[index] = domain.Text(normalized)
		}
		return domain.Object(map[string]domain.CanonicalValue{
			"logical_resource_id": domain.Text(logicalID),
			"nested_stack_path":   domain.OrderedArray(stackPath...),
		}), "", nil
	case IaCKubernetes:
		if !input.KubernetesIdentityApproved {
			return domain.CanonicalValue{}, "kubernetes_source_identity_not_approved", nil
		}
		apiVersion, err := normalizeKubernetesIdentityPart("apiVersion", input.KubernetesAPIVersion, 253, true)
		if err != nil {
			return domain.CanonicalValue{}, "", err
		}
		objectKind, err := normalizeKubernetesIdentityPart("kind", input.KubernetesKind, 128, false)
		if err != nil {
			return domain.CanonicalValue{}, "", err
		}
		name, err := normalizeKubernetesIdentityPart("name", input.KubernetesName, 253, true)
		if err != nil {
			return domain.CanonicalValue{}, "", err
		}
		namespace := strings.TrimSpace(input.KubernetesNamespace)
		if namespace == "" {
			namespace = "default"
		}
		namespace, err = normalizeKubernetesIdentityPart("namespace", namespace, 253, true)
		if err != nil {
			return domain.CanonicalValue{}, "", err
		}
		return domain.Object(map[string]domain.CanonicalValue{
			"api_version": domain.Text(apiVersion),
			"kind":        domain.Text(objectKind),
			"name":        domain.Text(name),
			"namespace":   domain.Text(namespace),
		}), "", nil
	}
	return domain.CanonicalValue{}, "", fmt.Errorf("%w: IaC config kind is unsupported", shared.ErrValidation)
}

func normalizeTerraformAddress(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || containsSourceSensitiveMarker(value) {
		return "", "", fmt.Errorf("%w: Terraform address is invalid", shared.ErrValidation)
	}
	position := 0
	modules := make([]string, 0, 8)
	for strings.HasPrefix(value[position:], "module.") {
		position += len("module.")
		name, next, err := parseTerraformIdentifier(value, position)
		if err != nil {
			return "", "", err
		}
		position = next
		index, next, err := parseTerraformIndex(value, position)
		if err != nil {
			return "", "", err
		}
		position = next
		modules = append(modules, "module."+name+index)
		if position >= len(value) || value[position] != '.' {
			return "", "", fmt.Errorf("%w: Terraform module address must be followed by a resource", shared.ErrValidation)
		}
		position++
	}
	resourceType, next, err := parseTerraformIdentifier(value, position)
	if err != nil {
		return "", "", err
	}
	position = next
	if position >= len(value) || value[position] != '.' {
		return "", "", fmt.Errorf("%w: Terraform resource address needs type.name", shared.ErrValidation)
	}
	position++
	resourceName, next, err := parseTerraformIdentifier(value, position)
	if err != nil {
		return "", "", err
	}
	position = next
	index, next, err := parseTerraformIndex(value, position)
	if err != nil {
		return "", "", err
	}
	if next != len(value) {
		return "", "", fmt.Errorf("%w: Terraform resource address has trailing content", shared.ErrValidation)
	}
	return strings.Join(modules, "."), resourceType + "." + resourceName + index, nil
}

func parseTerraformIdentifier(value string, start int) (string, int, error) {
	if start >= len(value) || !isTerraformIdentifierStart(value[start]) {
		return "", start, fmt.Errorf("%w: Terraform address identifier is invalid", shared.ErrValidation)
	}
	position := start + 1
	for position < len(value) && isTerraformIdentifierContinue(value[position]) {
		position++
	}
	return value[start:position], position, nil
}

func isTerraformIdentifierStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isTerraformIdentifierContinue(value byte) bool {
	return isTerraformIdentifierStart(value) || value == '-' || value >= '0' && value <= '9'
}

func parseTerraformIndex(value string, start int) (string, int, error) {
	if start >= len(value) || value[start] != '[' {
		return "", start, nil
	}
	contentStart := start + 1
	if contentStart >= len(value) {
		return "", start, fmt.Errorf("%w: Terraform instance index is unterminated", shared.ErrValidation)
	}
	end := -1
	if value[contentStart] == '"' {
		escaped := false
		for position := contentStart + 1; position < len(value); position++ {
			switch {
			case escaped:
				escaped = false
			case value[position] == '\\':
				escaped = true
			case value[position] == '"':
				if position+1 < len(value) && value[position+1] == ']' {
					end = position + 1
				}
				position = len(value)
			}
		}
	} else if relativeEnd := strings.IndexByte(value[contentStart:], ']'); relativeEnd >= 0 {
		end = contentStart + relativeEnd
	}
	if end < 0 {
		return "", start, fmt.Errorf("%w: Terraform instance index is unterminated", shared.ErrValidation)
	}
	raw := value[contentStart:end]
	if raw == "" {
		return "", start, fmt.Errorf("%w: Terraform instance index is empty", shared.ErrValidation)
	}
	if raw[0] == '"' {
		key, err := strconv.Unquote(raw)
		if err != nil {
			return "", start, fmt.Errorf("%w: Terraform for_each key is invalid", shared.ErrValidation)
		}
		key, err = normalizeSourceText("IaC", "Terraform for_each key", key, 512, false)
		if err != nil {
			return "", start, err
		}
		return "[" + strconv.Quote(key) + "]", end + 1, nil
	}
	for _, char := range raw {
		if char < '0' || char > '9' {
			return "", start, fmt.Errorf("%w: Terraform count index is invalid", shared.ErrValidation)
		}
	}
	numeric, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return "", start, fmt.Errorf("%w: Terraform count index is invalid", shared.ErrValidation)
	}
	return "[" + strconv.FormatUint(numeric, 10) + "]", end + 1, nil
}

func normalizeCloudFormationLogicalID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 255 || !isASCIILetter(value[0]) {
		return "", fmt.Errorf("%w: CloudFormation logical ID is invalid", shared.ErrValidation)
	}
	for index := 1; index < len(value); index++ {
		if !isASCIILetter(value[index]) && (value[index] < '0' || value[index] > '9') {
			return "", fmt.Errorf("%w: CloudFormation logical ID is invalid", shared.ErrValidation)
		}
	}
	return value, nil
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func normalizeKubernetesIdentityPart(name, value string, maximum int, lower bool) (string, error) {
	value = strings.TrimSpace(value)
	if lower {
		value = strings.ToLower(value)
	}
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || containsSourceSensitiveMarker(value) {
		return "", fmt.Errorf("%w: Kubernetes %s is invalid", shared.ErrValidation, name)
	}
	for _, char := range value {
		if unicode.IsControl(char) || unicode.IsSpace(char) || char == '/' && name != "apiVersion" {
			return "", fmt.Errorf("%w: Kubernetes %s is invalid", shared.ErrValidation, name)
		}
	}
	return value, nil
}

func inferIaCConfigKind(rule string) IaCConfigKind {
	rule = strings.ToLower(strings.TrimSpace(rule))
	switch {
	case strings.HasPrefix(rule, "terraform-"):
		return IaCTerraform
	case strings.HasPrefix(rule, "cloudformation-"):
		return IaCCloudFormation
	case strings.HasPrefix(rule, "kubernetes-"):
		return IaCKubernetes
	}
	return ""
}

type iacLegacyKind uint8

const (
	iacLegacyNone iacLegacyKind = iota
	iacLegacyValid
	iacLegacyMalformed
)

type iacLegacyKey struct {
	kind     iacLegacyKind
	ruleKey  string
	repoPath string
}

func parseIaCLegacyKey(value string) iacLegacyKey {
	value = strings.TrimSpace(value)
	if value == "" {
		return iacLegacyKey{}
	}
	if !strings.HasPrefix(value, "misconfig:") {
		return iacLegacyKey{kind: iacLegacyMalformed}
	}
	rest := strings.TrimPrefix(value, "misconfig:")
	lineSeparator := strings.LastIndexByte(rest, ':')
	if lineSeparator <= 0 {
		return iacLegacyKey{kind: iacLegacyMalformed}
	}
	line, err := strconv.Atoi(rest[lineSeparator+1:])
	pathSeparator := strings.LastIndexByte(rest[:lineSeparator], ':')
	if err != nil || line < 1 || pathSeparator <= 0 || pathSeparator == lineSeparator-1 {
		return iacLegacyKey{kind: iacLegacyMalformed}
	}
	return iacLegacyKey{kind: iacLegacyValid, ruleKey: rest[:pathSeparator], repoPath: rest[pathSeparator+1 : lineSeparator]}
}

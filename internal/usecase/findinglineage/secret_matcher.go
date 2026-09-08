package findinglineage

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	SecretMatcherVersionV1            = 1
	SecretFingerprintSchemaVersionV1  = 1
	SecretTargetIdentitySchemaVersion = 1
)

var ErrSecretMaterialRejected = errors.New("secret material rejected before lineage matching")

type SecretAnchorKind string

const (
	SecretAnchorSymbol         SecretAnchorKind = "symbol"
	SecretAnchorConfigKey      SecretAnchorKind = "config_key"
	SecretAnchorEnvName        SecretAnchorKind = "env_name"
	SecretAnchorStructuredSlot SecretAnchorKind = "structured_slot"
)

func (kind SecretAnchorKind) Valid() bool {
	switch kind {
	case SecretAnchorSymbol, SecretAnchorConfigKey, SecretAnchorEnvName, SecretAnchorStructuredSlot:
		return true
	}
	return false
}

type SecretAnchorV1 struct {
	Kind              SecretAnchorKind
	SchemaVersion     int
	LanguageID        string
	QualifiedSymbol   string
	ContainerName     string
	ContainerApproved bool
	RawOffsets        map[string]int
}

type SecretDetectorAliasSetV1 struct {
	Primary string
	Aliases []string
}

type SecretMatcherV1 struct {
	detectors SASTMatcherV1
}

func NewSecretMatcherV1(aliasSets []SecretDetectorAliasSetV1) (SecretMatcherV1, error) {
	sharedSets := make([]SASTRuleAliasSetV1, len(aliasSets))
	for index, aliasSet := range aliasSets {
		sharedSets[index] = SASTRuleAliasSetV1{Primary: aliasSet.Primary, Aliases: append([]string(nil), aliasSet.Aliases...)}
	}
	detectors, err := NewSASTMatcherV1(sharedSets)
	if err != nil {
		return SecretMatcherV1{}, err
	}
	return SecretMatcherV1{detectors: detectors}, nil
}

type SecretProducerInputV1 struct {
	TargetIdentityCanonical string
	DetectorKey             string
	DetectorAliases         []string
	SecretClass             string
	RepoPath                string
	Anchor                  SecretAnchorV1
	LegacyDedupKey          string
	LegacySourceValidated   bool
	TrustedProducerIdentity bool
	RawSecret               string
	ReversibleDigest        string
	EntropySample           string
	MatchedSubstring        string
	RequestValue            string
	ResponseValue           string
	Evidence                string
}

type SecretFingerprintInputV1 struct {
	TargetIdentityCanonical string
	DetectorKey             string
	DetectorAliases         []string
	SecretClass             string
	RepoPath                string
	Anchor                  SecretAnchorV1
	LegacyDedupKey          string
	LegacySourceValidated   bool
	TrustedProducerIdentity bool
	RedactionComplete       bool
}

func RedactSecretProducerInputV1(raw SecretProducerInputV1) (SecretFingerprintInputV1, error) {
	anchor := raw.Anchor
	if !anchor.ContainerApproved {
		anchor.ContainerName = ""
	}
	sanitized := SecretFingerprintInputV1{
		TargetIdentityCanonical: raw.TargetIdentityCanonical,
		DetectorKey:             raw.DetectorKey,
		DetectorAliases:         append([]string(nil), raw.DetectorAliases...),
		SecretClass:             raw.SecretClass,
		RepoPath:                raw.RepoPath,
		Anchor:                  anchor,
		LegacyDedupKey:          raw.LegacyDedupKey,
		LegacySourceValidated:   raw.LegacySourceValidated,
		TrustedProducerIdentity: raw.TrustedProducerIdentity,
		RedactionComplete:       true,
	}
	forbidden := make([]string, 0, 7)
	for _, field := range []struct {
		name  string
		value string
	}{
		{"raw_secret", raw.RawSecret},
		{"reversible_digest", raw.ReversibleDigest},
		{"entropy_sample", raw.EntropySample},
		{"matched_substring", raw.MatchedSubstring},
		{"request_value", raw.RequestValue},
		{"response_value", raw.ResponseValue},
		{"evidence", raw.Evidence},
	} {
		if field.value != "" {
			forbidden = append(forbidden, field.name)
		}
	}
	if len(forbidden) > 0 {
		sort.Strings(forbidden)
		return sanitized, fmt.Errorf("%w: forbidden fields: %s", ErrSecretMaterialRejected, strings.Join(forbidden, ","))
	}
	return sanitized, nil
}

type SecretMatchPlanV1 struct {
	FingerprintInput    domain.FingerprintCanonicalInputV1
	Method              domain.MatchMethod
	MatcherVersion      int
	ReasonCode          string
	ReviewReason        domain.CandidateReason
	Ambiguous           bool
	ProvisionalIdentity bool
	TrustedProducerID   bool
	SkipInput           bool
	SkipRedaction       bool
}

func (matcher SecretMatcherV1) Build(input SecretFingerprintInputV1) (SecretMatchPlanV1, error) {
	target, err := normalizeSourceText("secret", "target identity", input.TargetIdentityCanonical, 2048, false)
	if err != nil {
		return SecretMatchPlanV1{}, err
	}
	legacy := parseSecretLegacyKey(input.LegacyDedupKey)
	detectorKey := input.DetectorKey
	repoPath := input.RepoPath
	if legacy.kind == secretLegacyValid {
		if strings.TrimSpace(detectorKey) == "" {
			detectorKey = legacy.detectorKey
		}
		if strings.TrimSpace(repoPath) == "" {
			repoPath = legacy.repoPath
		}
	}
	normalizedPath, pathErr := normalizeSourceRepoPath("secret", repoPath)
	if pathErr != nil && strings.TrimSpace(repoPath) != "" {
		return SecretMatchPlanV1{}, pathErr
	}
	primaryDetector, normalizedDetectors, detectorConflict, detectorErr := matcher.detectors.normalizeRule("secret", detectorKey, input.DetectorAliases)
	if detectorErr != nil && strings.TrimSpace(detectorKey) != "" {
		return SecretMatchPlanV1{}, detectorErr
	}
	secretClass, classErr := normalizeSourceToken("secret", "class", input.SecretClass)
	if classErr != nil && strings.TrimSpace(input.SecretClass) != "" {
		return SecretMatchPlanV1{}, classErr
	}
	anchorValue, anchorErr := normalizeSecretAnchor(input.Anchor)
	if input.Anchor.Kind != "" && !input.Anchor.Kind.Valid() {
		return SecretMatchPlanV1{}, fmt.Errorf("%w: secret container anchor kind is invalid", shared.ErrValidation)
	}
	if len(input.Anchor.RawOffsets) > 0 {
		return SecretMatchPlanV1{}, fmt.Errorf("%w: secret container anchors cannot contain raw offsets", shared.ErrValidation)
	}
	if anchorErr != nil && input.Anchor.Kind.Valid() {
		return SecretMatchPlanV1{}, anchorErr
	}

	fields := map[string]domain.CanonicalValue{
		"detector_alias_graph_version": domain.Integer(SASTRuleAliasSchemaVersionV1),
		"producer_matcher_version":     domain.Integer(SecretMatcherVersionV1),
	}
	if primaryDetector != "" {
		fields["detector_id"] = domain.Text(primaryDetector)
	}
	if secretClass != "" {
		fields["secret_class"] = domain.Text(secretClass)
	}
	if normalizedPath != "" {
		fields["repo_path"] = domain.Text(normalizedPath)
	}
	if anchorErr == nil && input.Anchor.Kind.Valid() {
		fields["anchor_kind"] = domain.Text(string(input.Anchor.Kind))
		fields["anchor_schema_version"] = domain.Integer(int64(input.Anchor.SchemaVersion))
		fields["anchor_value"] = anchorValue
	}
	if detectorConflict {
		fields["detector_candidates"] = domain.StringSet(normalizedDetectors...)
		delete(fields, "detector_id")
	}
	plan := SecretMatchPlanV1{
		FingerprintInput: domain.FingerprintCanonicalInputV1{
			CanonicalizationVersion: domain.CanonicalizationVersionV1, ProducerKind: "secret",
			TargetIdentitySchemaVersion: SecretTargetIdentitySchemaVersion, TargetIdentityCanonical: target, IdentityFields: fields,
		},
		Method: domain.MethodMatcher, MatcherVersion: SecretMatcherVersionV1, ReasonCode: "secret_identity_complete",
		TrustedProducerID: input.TrustedProducerIdentity,
	}
	switch {
	case !input.RedactionComplete:
		plan.SkipRedaction, plan.ReasonCode = true, "redaction_not_complete"
	case input.LegacyDedupKey != "" && !input.LegacySourceValidated:
		plan.SkipInput, plan.ReasonCode = true, "legacy_source_not_validated"
	case detectorConflict:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous = domain.ReasonMerge, "detector_alias_conflict", true
	case legacy.kind == secretLegacyMalformed:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonLegacyAmbiguous, "legacy_key_malformed", true, true
	case normalizedPath == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_repo_path", true, true
	case primaryDetector == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_detector_id", true, true
	case secretClass == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_secret_class", true, true
	case !input.Anchor.Kind.Valid():
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "missing_container_anchor", true, true
	case legacy.kind == secretLegacyValid:
		plan.ReasonCode = "legacy_secret_structured"
	}
	return plan, nil
}

func (plan SecretMatchPlanV1) Apply(input CorrelateInput) CorrelateInput {
	input.ProducerKind = "secret"
	input.FindingKind = "secret"
	input.FingerprintSchemaVersion = SecretFingerprintSchemaVersionV1
	input.FingerprintInput = plan.FingerprintInput
	input.TrustedProducerID = input.TrustedProducerID || plan.TrustedProducerID
	input.ReviewReason = plan.ReviewReason
	input.ReviewDetailCode = plan.ReasonCode
	input.ProvisionalIdentity = plan.ProvisionalIdentity
	if plan.SkipInput {
		input.InputTrusted = false
	}
	if plan.SkipRedaction {
		input.RedactionComplete = false
	}
	return input
}

func normalizeSecretAnchor(anchor SecretAnchorV1) (domain.CanonicalValue, error) {
	if !anchor.Kind.Valid() || anchor.SchemaVersion <= 0 {
		return domain.CanonicalValue{}, fmt.Errorf("%w: secret container anchor is required", shared.ErrValidation)
	}
	value := map[string]domain.CanonicalValue{}
	switch anchor.Kind {
	case SecretAnchorSymbol:
		language, err := normalizeSourceToken("secret", "language id", anchor.LanguageID)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		symbol, err := normalizeSourceText("secret", "qualified symbol", anchor.QualifiedSymbol, 1024, false)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		if anchor.ContainerName != "" {
			return domain.CanonicalValue{}, fmt.Errorf("%w: symbol anchor cannot carry a container name", shared.ErrValidation)
		}
		value["language_id"] = domain.Text(language)
		value["qualified_symbol"] = domain.Text(symbol)
	default:
		if !anchor.ContainerApproved {
			return domain.CanonicalValue{}, fmt.Errorf("%w: secret container name is not approved for identity", shared.ErrValidation)
		}
		container, err := normalizeSourceText("secret", "container name", anchor.ContainerName, 1024, false)
		if err != nil {
			return domain.CanonicalValue{}, err
		}
		if anchor.LanguageID != "" || anchor.QualifiedSymbol != "" {
			return domain.CanonicalValue{}, fmt.Errorf("%w: container anchor cannot carry symbol fields", shared.ErrValidation)
		}
		value["container_name"] = domain.Text(container)
	}
	return domain.Object(value), nil
}

type secretLegacyKind uint8

const (
	secretLegacyNone secretLegacyKind = iota
	secretLegacyValid
	secretLegacyMalformed
)

type secretLegacyKey struct {
	kind        secretLegacyKind
	detectorKey string
	repoPath    string
}

func parseSecretLegacyKey(value string) secretLegacyKey {
	value = strings.TrimSpace(value)
	if value == "" {
		return secretLegacyKey{}
	}
	if !strings.HasPrefix(value, "secret:") {
		return secretLegacyKey{kind: secretLegacyMalformed}
	}
	rest := strings.TrimPrefix(value, "secret:")
	lineSeparator := strings.LastIndexByte(rest, ':')
	if lineSeparator <= 0 {
		return secretLegacyKey{kind: secretLegacyMalformed}
	}
	line, err := strconv.Atoi(rest[lineSeparator+1:])
	pathSeparator := strings.LastIndexByte(rest[:lineSeparator], ':')
	if err != nil || line < 1 || pathSeparator <= 0 || pathSeparator == lineSeparator-1 {
		return secretLegacyKey{kind: secretLegacyMalformed}
	}
	return secretLegacyKey{kind: secretLegacyValid, detectorKey: rest[:pathSeparator], repoPath: rest[pathSeparator+1 : lineSeparator]}
}

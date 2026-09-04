package findinglineage

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

const (
	SCAMatcherVersionV1            = 1
	SCAFingerprintSchemaVersionV1  = 1
	SCATargetIdentitySchemaVersion = 1
	SCAAdvisoryAliasSchemaVersion  = 1
)

var pypiNameSeparators = regexp.MustCompile(`[-_.]+`)

type SCAAdvisoryAliasSetV1 struct {
	Primary string
	Aliases []string
}

type SCAMatcherV1 struct {
	advisoryPrimaries map[string]string
}

func NewSCAMatcherV1(aliasSets []SCAAdvisoryAliasSetV1) (SCAMatcherV1, error) {
	matcher := SCAMatcherV1{advisoryPrimaries: map[string]string{}}
	for _, aliasSet := range aliasSets {
		primary, err := normalizeSCAAdvisoryID(aliasSet.Primary)
		if err != nil {
			return SCAMatcherV1{}, err
		}
		for _, raw := range append([]string{primary}, aliasSet.Aliases...) {
			alias, err := normalizeSCAAdvisoryID(raw)
			if err != nil {
				return SCAMatcherV1{}, err
			}
			if existing := matcher.advisoryPrimaries[alias]; existing != "" && existing != primary {
				return SCAMatcherV1{}, fmt.Errorf("%w: advisory alias %q maps to multiple primaries", shared.ErrValidation, alias)
			}
			matcher.advisoryPrimaries[alias] = primary
		}
	}
	return matcher, nil
}

func (SCAMatcherV1) Descriptor() domain.MatcherDescriptor {
	return domain.MatcherDescriptor{
		ProducerKind: "sca", FindingKind: "vulnerability", Method: domain.MethodMatcher,
		MethodVersion: SCAMatcherVersionV1, CanonicalizationVersion: domain.CanonicalizationVersionV1,
		FingerprintSchemaVersion: SCAFingerprintSchemaVersionV1, TargetIdentitySchemaVersion: SCATargetIdentitySchemaVersion,
	}
}

type SCAFingerprintInputV1 struct {
	TargetIdentityCanonical string
	AdvisoryID              string
	AdvisoryAliases         []string
	PackagePURL             string
	PackageEcosystem        string
	PackageName             string
	DependencyInstanceID    string
	DependencyPath          []string
	LegacyDedupKey          string
}

func SCAFingerprintInputFromVulnerabilityV1(target string, current vulnerability.Vulnerability, aliases []string, legacyDedupKey, dependencyInstanceID string) SCAFingerprintInputV1 {
	return SCAFingerprintInputV1{
		TargetIdentityCanonical: target,
		AdvisoryID:              current.ID,
		AdvisoryAliases:         append([]string(nil), aliases...),
		PackagePURL:             current.PackagePURL,
		PackageEcosystem:        current.Ecosystem,
		PackageName:             current.Component,
		DependencyInstanceID:    dependencyInstanceID,
		DependencyPath:          append([]string(nil), current.Path...),
		LegacyDedupKey:          legacyDedupKey,
	}
}

type SCAMatchPlanV1 struct {
	FingerprintInput    domain.FingerprintCanonicalInputV1
	Aliases             []AliasInput
	Method              domain.MatchMethod
	MatcherVersion      int
	ReasonCode          string
	ReviewReason        domain.CandidateReason
	Ambiguous           bool
	ProvisionalIdentity bool
}

func (matcher SCAMatcherV1) Build(input SCAFingerprintInputV1) (SCAMatchPlanV1, error) {
	target := strings.TrimSpace(input.TargetIdentityCanonical)
	if target == "" || len(target) > 2048 {
		return SCAMatchPlanV1{}, fmt.Errorf("%w: SCA target identity is required", shared.ErrValidation)
	}
	if err := validateSCASafeText(target); err != nil {
		return SCAMatchPlanV1{}, err
	}

	advisoryID := input.AdvisoryID
	packageName := input.PackageName
	legacyAdvisory, legacyPackage, _, legacyOK := vulnerability.ParseDedupKey(input.LegacyDedupKey)
	legacyMalformed := input.LegacyDedupKey != "" && (!legacyOK || strings.TrimSpace(legacyAdvisory) == "" || strings.TrimSpace(legacyPackage) == "")
	if strings.TrimSpace(advisoryID) == "" && legacyOK {
		advisoryID = legacyAdvisory
	}
	if strings.TrimSpace(input.PackagePURL) == "" && strings.TrimSpace(packageName) == "" && legacyOK {
		packageName = legacyPackage
	}

	primary, normalizedIDs, conflict, advisoryErr := matcher.normalizeAdvisory(advisoryID, input.AdvisoryAliases)
	packageCoordinate, packageErr := normalizeSCAPackageCoordinate(input.PackagePURL, input.PackageEcosystem, packageName)
	dependencyPath, pathErr := normalizeSCADependencyPath(input.DependencyPath)
	instanceID := strings.TrimSpace(input.DependencyInstanceID)
	if instanceID != "" {
		if err := validateSCASafeText(instanceID); err != nil {
			return SCAMatchPlanV1{}, err
		}
	}
	if errors.Is(packageErr, domain.ErrSensitiveInput) {
		return SCAMatchPlanV1{}, packageErr
	}
	if errors.Is(pathErr, domain.ErrSensitiveInput) {
		return SCAMatchPlanV1{}, pathErr
	}

	fields := map[string]domain.CanonicalValue{
		"advisory_alias_graph_version": domain.Integer(SCAAdvisoryAliasSchemaVersion),
		"producer_matcher_version":     domain.Integer(SCAMatcherVersionV1),
	}
	if primary != "" {
		fields["advisory_id"] = domain.Text(primary)
	}
	if packageErr == nil {
		fields["package_coordinate"] = domain.Text(packageCoordinate)
	}
	if pathErr == nil && len(dependencyPath) > 0 {
		values := make([]domain.CanonicalValue, len(dependencyPath))
		for index, coordinate := range dependencyPath {
			values[index] = domain.Text(coordinate)
		}
		fields["dependency_path"] = domain.OrderedArray(values...)
	} else if instanceID != "" {
		fields["dependency_instance_id"] = domain.Text(instanceID)
	}
	if conflict {
		fields["advisory_candidates"] = domain.StringSet(normalizedIDs...)
		delete(fields, "advisory_id")
	}

	plan := SCAMatchPlanV1{
		FingerprintInput: domain.FingerprintCanonicalInputV1{
			CanonicalizationVersion: domain.CanonicalizationVersionV1,
			ProducerKind:            "sca", TargetIdentitySchemaVersion: SCATargetIdentitySchemaVersion,
			TargetIdentityCanonical: target, IdentityFields: fields,
		},
		Method: domain.MethodMatcher, MatcherVersion: SCAMatcherVersionV1, ReasonCode: "sca_identity_complete",
	}
	switch {
	case conflict:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous = domain.ReasonMerge, "advisory_alias_conflict", true
	case advisoryErr != nil:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonLegacyAmbiguous, "missing_advisory_identity", true, true
	case packageErr != nil:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "invalid_package_coordinate", true, true
	case pathErr != nil:
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "invalid_dependency_path", true, true
	case len(dependencyPath) == 0 && instanceID == "":
		plan.ReviewReason, plan.ReasonCode, plan.Ambiguous, plan.ProvisionalIdentity = domain.ReasonInsufficientAnchor, "insufficient_dependency_instance", true, true
	case legacyMalformed:
		plan.ReasonCode = "structured_fields_preferred"
	}
	if !plan.Ambiguous {
		plan.Aliases = make([]AliasInput, len(normalizedIDs))
		for index, alias := range normalizedIDs {
			plan.Aliases[index] = AliasInput{SchemaVersion: SCAAdvisoryAliasSchemaVersion, Value: alias}
		}
	}
	return plan, nil
}

func (plan SCAMatchPlanV1) Apply(input CorrelateInput) CorrelateInput {
	input.ProducerKind = "sca"
	input.FindingKind = "vulnerability"
	input.FingerprintSchemaVersion = SCAFingerprintSchemaVersionV1
	input.FingerprintInput = plan.FingerprintInput
	input.Aliases = append([]AliasInput(nil), plan.Aliases...)
	input.ReviewReason = plan.ReviewReason
	input.ReviewDetailCode = plan.ReasonCode
	input.ProvisionalIdentity = plan.ProvisionalIdentity
	return input
}

func (matcher SCAMatcherV1) normalizeAdvisory(primary string, aliases []string) (string, []string, bool, error) {
	seen := map[string]struct{}{}
	for _, raw := range append([]string{primary}, aliases...) {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		id, err := normalizeSCAAdvisoryID(raw)
		if err != nil {
			return "", nil, false, err
		}
		seen[id] = struct{}{}
	}
	if len(seen) == 0 {
		return "", nil, false, fmt.Errorf("%w: SCA advisory identity is required", shared.ErrValidation)
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	knownPrimaries := map[string]struct{}{}
	for _, id := range ids {
		if resolved := matcher.advisoryPrimaries[id]; resolved != "" {
			knownPrimaries[resolved] = struct{}{}
		}
	}
	if len(knownPrimaries) > 1 {
		return "", ids, true, nil
	}
	if len(knownPrimaries) == 1 {
		var resolved string
		for resolved = range knownPrimaries {
		}
		if strings.HasPrefix(resolved, "CVE-") {
			for _, id := range ids {
				if strings.HasPrefix(id, "CVE-") && id != resolved {
					return "", ids, true, nil
				}
			}
		}
		return resolved, ids, false, nil
	}

	cves := 0
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			cves++
		}
	}
	if cves > 1 {
		return "", ids, true, nil
	}
	return preferredSCAAdvisoryID(ids), ids, false, nil
}

func normalizeSCAAdvisoryID(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || len(value) > 256 {
		return "", fmt.Errorf("%w: SCA advisory id is required", shared.ErrValidation)
	}
	for _, char := range value {
		if char != '-' && char != '_' && char != '.' && char != ':' && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return "", fmt.Errorf("%w: SCA advisory id contains invalid characters", shared.ErrValidation)
		}
	}
	return value, nil
}

func preferredSCAAdvisoryID(ids []string) string {
	best, bestRank := "", 0
	for _, id := range ids {
		rank := 1
		if strings.HasPrefix(id, "GHSA-") {
			rank = 2
		}
		if strings.HasPrefix(id, "CVE-") {
			rank = 3
		}
		if rank > bestRank || rank == bestRank && (best == "" || id < best) {
			best, bestRank = id, rank
		}
	}
	return best
}

func normalizeSCADependencyPath(values []string) ([]string, error) {
	if len(values) > 256 {
		return nil, fmt.Errorf("%w: SCA dependency path is too long", shared.ErrValidation)
	}
	path := make([]string, len(values))
	for index, value := range values {
		coordinate, err := normalizeSCAPackageCoordinate(value, "", "")
		if err != nil {
			return nil, err
		}
		path[index] = coordinate
	}
	return path, nil
}

func normalizeSCAPackageCoordinate(purl, ecosystem, packageName string) (string, error) {
	purl = strings.TrimSpace(purl)
	if purl == "" {
		var err error
		purl, err = scaPURLFromPackage(ecosystem, packageName)
		if err != nil {
			return "", err
		}
	}
	if len(purl) > 2048 || len(purl) < 5 || !strings.EqualFold(purl[:4], "pkg:") {
		return "", fmt.Errorf("%w: SCA package purl is malformed", shared.ErrValidation)
	}
	rest := purl[4:]
	if fragment := strings.IndexByte(rest, '#'); fragment >= 0 {
		rest = rest[:fragment]
	}
	qualifiers := ""
	if query := strings.IndexByte(rest, '?'); query >= 0 {
		qualifiers, rest = rest[query+1:], rest[:query]
	}
	typeEnd := strings.IndexByte(rest, '/')
	if typeEnd <= 0 || typeEnd == len(rest)-1 {
		return "", fmt.Errorf("%w: SCA package purl is incomplete", shared.ErrValidation)
	}
	typ := strings.ToLower(rest[:typeEnd])
	if typ[0] < 'a' || typ[0] > 'z' {
		return "", fmt.Errorf("%w: SCA package purl type is invalid", shared.ErrValidation)
	}
	for _, char := range typ {
		if char != '.' && char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return "", fmt.Errorf("%w: SCA package purl type is invalid", shared.ErrValidation)
		}
	}
	rawPath := strings.Trim(rest[typeEnd+1:], "/")
	if slash := strings.LastIndexByte(rawPath, '/'); slash >= 0 {
		if version := strings.LastIndexByte(rawPath, '@'); version > slash {
			rawPath = rawPath[:version]
		}
	} else if version := strings.LastIndexByte(rawPath, '@'); version > 0 {
		rawPath = rawPath[:version]
	}
	path, err := normalizeSCAPackagePath(typ, rawPath)
	if err != nil {
		return "", err
	}
	coordinate := "pkg:" + typ + "/" + path
	if qualifiers != "" {
		normalized, err := normalizeSCAPURLQualifiers(qualifiers)
		if err != nil {
			return "", err
		}
		if normalized != "" {
			coordinate += "?" + normalized
		}
	}
	return coordinate, nil
}

func scaPURLFromPackage(ecosystem, packageName string) (string, error) {
	name := strings.TrimSpace(packageName)
	if name == "" {
		return "", fmt.Errorf("%w: SCA package identity is required", shared.ErrValidation)
	}
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "go", "golang":
		return "pkg:golang/" + name, nil
	case "npm":
		return "pkg:npm/" + name, nil
	case "pypi":
		return "pkg:pypi/" + name, nil
	case "maven":
		group, artifact, ok := strings.Cut(name, ":")
		if !ok || group == "" || artifact == "" {
			return "", fmt.Errorf("%w: Maven package must use group:artifact", shared.ErrValidation)
		}
		return "pkg:maven/" + group + "/" + artifact, nil
	case "crates.io", "cargo":
		return "pkg:cargo/" + name, nil
	case "rubygems", "gem":
		return "pkg:gem/" + name, nil
	case "nuget":
		return "pkg:nuget/" + name, nil
	default:
		return "", fmt.Errorf("%w: SCA package ecosystem is unsupported", shared.ErrValidation)
	}
}

func normalizeSCAPackagePath(typ, rawPath string) (string, error) {
	parts := strings.Split(rawPath, "/")
	if len(parts) == 0 || len(parts) > 64 {
		return "", fmt.Errorf("%w: SCA package path is invalid", shared.ErrValidation)
	}
	for index, raw := range parts {
		part, err := url.PathUnescape(raw)
		if err != nil || strings.TrimSpace(part) == "" || part == "." || part == ".." || strings.ContainsAny(part, "\x00\r\n") {
			return "", fmt.Errorf("%w: SCA package path is invalid", shared.ErrValidation)
		}
		switch typ {
		case "pypi", "cargo", "gem", "nuget", "deb", "apk", "rpm":
			part = strings.ToLower(part)
		}
		if typ == "pypi" {
			part = pypiNameSeparators.ReplaceAllString(part, "-")
		}
		parts[index] = escapePURLComponent(part)
	}
	if typ == "maven" && len(parts) < 2 {
		return "", fmt.Errorf("%w: Maven package path is incomplete", shared.ErrValidation)
	}
	return strings.Join(parts, "/"), nil
}

func normalizeSCAPURLQualifiers(raw string) (string, error) {
	values := map[string]string{}
	for _, entry := range strings.Split(raw, "&") {
		rawKey, rawValue, ok := strings.Cut(entry, "=")
		if !ok || strings.Contains(rawKey, "%") {
			return "", fmt.Errorf("%w: SCA package qualifiers are invalid", shared.ErrValidation)
		}
		key := strings.ToLower(strings.TrimSpace(rawKey))
		value, err := url.PathUnescape(rawValue)
		if err != nil || key == "" || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("%w: SCA package qualifiers are invalid", shared.ErrValidation)
		}
		for _, char := range key {
			if char != '.' && char != '_' && char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return "", fmt.Errorf("%w: SCA package qualifier key is invalid", shared.ErrValidation)
			}
		}
		if sensitiveSCAQualifierKey(key) {
			return "", fmt.Errorf("%w: SCA package qualifier %q is not allowed", domain.ErrSensitiveInput, key)
		}
		if err := validateSCASafeText(value); err != nil {
			return "", err
		}
		if _, duplicate := values[key]; duplicate {
			return "", fmt.Errorf("%w: SCA package qualifier keys must be unique", shared.ErrValidation)
		}
		values[key] = strings.TrimSpace(value)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	qualifiers := make([]string, len(keys))
	for index, key := range keys {
		qualifiers[index] = key + "=" + escapePURLComponent(values[key])
	}
	return strings.Join(qualifiers, "&"), nil
}

func escapePURLComponent(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var output strings.Builder
	for _, current := range []byte(value) {
		if current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z' || current >= '0' && current <= '9' || strings.ContainsRune(".-_~:", rune(current)) {
			output.WriteByte(current)
			continue
		}
		output.WriteByte('%')
		output.WriteByte(hexDigits[current>>4])
		output.WriteByte(hexDigits[current&0x0f])
	}
	return output.String()
}

func sensitiveSCAQualifierKey(value string) bool {
	normalized := strings.Map(func(char rune) rune {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			return char
		}
		return -1
	}, strings.ToLower(value))
	for _, marker := range []string{"accesstoken", "apikey", "apitoken", "auth", "credential", "password", "privatekey", "secret", "sessionkey", "token"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func validateSCASafeText(value string) error {
	if len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%w: SCA identity text is invalid", shared.ErrValidation)
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.User != nil {
		return fmt.Errorf("%w: credentials are not allowed in SCA identity text", domain.ErrSensitiveInput)
	}
	if err == nil {
		for key := range parsed.Query() {
			if sensitiveSCAQualifierKey(key) {
				return fmt.Errorf("%w: credentials are not allowed in SCA identity text", domain.ErrSensitiveInput)
			}
		}
	}
	return nil
}

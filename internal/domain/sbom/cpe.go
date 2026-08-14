package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type CPE23 struct {
	Part      string
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SWEdition string
	TargetSW  string
	TargetHW  string
	Other     string
}

type CPEIdentity struct {
	CPE         CPE23
	Canonical   string
	Fingerprint string
	Status      string
	Reason      string
}

func IdentityFromCPE(raw, componentVersion string) CPEIdentity {
	parsed, err := ParseCPE23(raw)
	if err != nil {
		return CPEIdentity{Status: IdentityUnsupported, Reason: "missing_or_malformed_cpe"}
	}
	if parsed.Part != "a" && parsed.Part != "o" && parsed.Part != "h" {
		return CPEIdentity{CPE: parsed, Status: IdentityUnsupported, Reason: "unsupported_cpe_part"}
	}
	if !concreteCPEValue(parsed.Vendor) || !concreteCPEValue(parsed.Product) {
		return CPEIdentity{CPE: parsed, Status: IdentityAmbiguous, Reason: "cpe_vendor_or_product_unresolved"}
	}
	componentVersion = strings.TrimSpace(componentVersion)
	if concreteCPEValue(parsed.Version) && componentVersion != "" && !strings.EqualFold(parsed.Version, componentVersion) {
		return CPEIdentity{CPE: parsed, Status: IdentityAmbiguous, Reason: "component_and_cpe_versions_differ"}
	}
	if !concreteCPEValue(parsed.Version) {
		if !IsResolvedVersion(componentVersion) {
			return CPEIdentity{CPE: parsed, Status: IdentityAmbiguous, Reason: "cpe_version_unresolved"}
		}
		parsed.Version = componentVersion
	}
	canonical := parsed.String()
	digest := sha256.Sum256([]byte(canonical))
	return CPEIdentity{CPE: parsed, Canonical: canonical, Fingerprint: hex.EncodeToString(digest[:]), Status: IdentityResolved}
}

func ParseCPE23(raw string) (CPE23, error) {
	parts, err := splitCPE23(strings.TrimSpace(raw))
	if err != nil || len(parts) != 13 || parts[0] != "cpe" || parts[1] != "2.3" {
		return CPE23{}, fmt.Errorf("invalid CPE 2.3")
	}
	values := make([]string, 11)
	for i := range values {
		value, err := unescapeCPE23(parts[i+2])
		if err != nil || value == "" {
			return CPE23{}, fmt.Errorf("invalid CPE 2.3 component")
		}
		values[i] = strings.ToLower(value)
	}
	return CPE23{Part: values[0], Vendor: values[1], Product: values[2], Version: values[3], Update: values[4], Edition: values[5], Language: values[6], SWEdition: values[7], TargetSW: values[8], TargetHW: values[9], Other: values[10]}, nil
}

func (c CPE23) String() string {
	values := []string{c.Part, c.Vendor, c.Product, c.Version, c.Update, c.Edition, c.Language, c.SWEdition, c.TargetSW, c.TargetHW, c.Other}
	for i := range values {
		values[i] = escapeCPE23(strings.ToLower(values[i]))
	}
	return "cpe:2.3:" + strings.Join(values, ":")
}

func (c CPE23) MatchAttributes(candidate CPE23) bool {
	left := []string{c.Part, c.Vendor, c.Product, c.Update, c.Edition, c.Language, c.SWEdition, c.TargetSW, c.TargetHW, c.Other}
	right := []string{candidate.Part, candidate.Vendor, candidate.Product, candidate.Update, candidate.Edition, candidate.Language, candidate.SWEdition, candidate.TargetSW, candidate.TargetHW, candidate.Other}
	for i := range left {
		if left[i] != "*" && !strings.EqualFold(left[i], right[i]) {
			return false
		}
	}
	return true
}

func concreteCPEValue(value string) bool { return value != "" && value != "*" && value != "-" }

func splitCPE23(value string) ([]string, error) {
	parts := make([]string, 0, 13)
	var current strings.Builder
	escaped := false
	for _, char := range value {
		if escaped {
			current.WriteRune('\\')
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == ':' {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(char)
	}
	if escaped {
		return nil, fmt.Errorf("trailing CPE escape")
	}
	parts = append(parts, current.String())
	return parts, nil
}

func unescapeCPE23(value string) (string, error) {
	var result strings.Builder
	escaped := false
	for _, char := range value {
		if escaped {
			result.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		result.WriteRune(char)
	}
	if escaped {
		return "", fmt.Errorf("trailing CPE escape")
	}
	return result.String(), nil
}

func escapeCPE23(value string) string {
	var result strings.Builder
	for _, char := range value {
		if char == '\\' || char == ':' {
			result.WriteRune('\\')
		}
		result.WriteRune(char)
	}
	return result.String()
}

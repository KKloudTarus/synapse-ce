package rule

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Key string

type Type string

const (
	TypeBug             Type = "bug"
	TypeVulnerability   Type = "vulnerability"
	TypeCodeSmell       Type = "code_smell"
	TypeSecurityHotspot Type = "security_hotspot"
)

func (t Type) Valid() bool {
	switch t {
	case TypeBug, TypeVulnerability, TypeCodeSmell, TypeSecurityHotspot:
		return true
	default:
		return false
	}
}

type Quality string

const (
	QualitySecurity        Quality = "security"
	QualityReliability     Quality = "reliability"
	QualityMaintainability Quality = "maintainability"
)

func (q Quality) Valid() bool {
	switch q {
	case QualitySecurity, QualityReliability, QualityMaintainability:
		return true
	default:
		return false
	}
}

type Detection string

const (
	DetectionAST     Detection = "ast"
	DetectionPattern Detection = "pattern"
	DetectionParse   Detection = "parse"
	DetectionMetric  Detection = "metric"
)

func (d Detection) Valid() bool {
	switch d {
	case DetectionAST, DetectionPattern, DetectionParse, DetectionMetric:
		return true
	default:
		return false
	}
}

type Rule struct {
	Key                 Key
	Name                string
	Language            string
	Type                Type
	Qualities           []Quality
	DefaultSeverity     shared.Severity
	Tags                []string
	CWE                 []string
	OWASP               []string
	Description         string
	Rationale           string
	Remediation         string
	CompliantExample    string
	NoncompliantExample string
	RemediationEffort   int
	Detection           Detection
}

func validateMetadataValue(
	kind string,
	value string,
	seen map[string]struct{},
) error {
	trimmed := strings.TrimSpace(value)

	if trimmed == "" {
		return fmt.Errorf("%s value is empty or whitespace-only", kind)
	}

	if trimmed != value {
		return fmt.Errorf("%s value has surrounding whitespace", kind)
	}

	key := strings.ToLower(trimmed)
	if _, exists := seen[key]; exists {
		return fmt.Errorf("duplicate %s value %q", kind, value)
	}

	seen[key] = struct{}{}
	return nil
}

func (r Rule) Validate() error {
	kStr := string(r.Key)
	if strings.TrimSpace(kStr) == "" ||
		strings.ContainsAny(kStr, "/?#") ||
		strings.IndexFunc(kStr, unicode.IsSpace) >= 0 ||
		strings.IndexFunc(kStr, unicode.IsControl) >= 0 {
		return errors.New(
			"key is empty or contains whitespace, control characters, or route delimiters",
		)
	}

	if strings.TrimSpace(r.Name) == "" {
		return errors.New("name is empty or whitespace-only")
	}

	if strings.TrimSpace(r.Language) == "" {
		return errors.New("language is empty or whitespace-only")
	}

	if !r.Type.Valid() {
		return errors.New("invalid type")
	}

	if len(r.Qualities) == 0 {
		return errors.New("qualities must contain at least one value")
	}

	seenQualities := make(map[Quality]bool)
	hasSecurity := false
	hasReliability := false
	hasMaintainability := false

	for _, q := range r.Qualities {
		if !q.Valid() {
			return errors.New("invalid quality")
		}
		if seenQualities[q] {
			return errors.New("duplicate quality")
		}
		seenQualities[q] = true
		switch q {
		case QualitySecurity:
			hasSecurity = true
		case QualityReliability:
			hasReliability = true
		case QualityMaintainability:
			hasMaintainability = true
		}
	}

	switch r.Type {
	case TypeBug:
		if !hasReliability {
			return errors.New("bug type requires reliability quality")
		}
	case TypeVulnerability, TypeSecurityHotspot:
		if !hasSecurity {
			return fmt.Errorf("%s type requires security quality", r.Type)
		}
	case TypeCodeSmell:
		if !hasMaintainability {
			return errors.New("code_smell type requires maintainability quality")
		}
	}

	if !r.DefaultSeverity.Valid() || r.DefaultSeverity == shared.SeverityUnknown {
		return errors.New("invalid or unknown default severity")
	}

	seenTags := make(map[string]struct{})
	for _, t := range r.Tags {
		if err := validateMetadataValue("tag", t, seenTags); err != nil {
			return err
		}
	}

	seenCWE := make(map[string]struct{})
	for _, c := range r.CWE {
		if err := validateMetadataValue("cwe", c, seenCWE); err != nil {
			return err
		}
	}

	seenOWASP := make(map[string]struct{})
	for _, o := range r.OWASP {
		if err := validateMetadataValue("owasp", o, seenOWASP); err != nil {
			return err
		}
	}

	if strings.TrimSpace(r.Description) == "" {
		return errors.New("description is empty or whitespace-only")
	}

	if strings.TrimSpace(r.Rationale) == "" {
		return errors.New("rationale is empty or whitespace-only")
	}

	if strings.TrimSpace(r.Remediation) == "" {
		return errors.New("remediation is empty or whitespace-only")
	}

	if strings.TrimSpace(r.CompliantExample) == "" {
		return errors.New("compliant example is empty or whitespace-only")
	}

	if strings.TrimSpace(r.NoncompliantExample) == "" {
		return errors.New("non-compliant example is empty or whitespace-only")
	}

	if strings.TrimSpace(r.CompliantExample) == strings.TrimSpace(r.NoncompliantExample) {
		return errors.New("compliant and non-compliant examples are identical after trimming")
	}

	if r.RemediationEffort <= 0 {
		return errors.New("remediation effort must be greater than zero")
	}

	if !r.Detection.Valid() {
		return errors.New("invalid detection")
	}

	return nil
}

func (r Rule) Clone() Rule {
	res := r
	if r.Qualities != nil {
		res.Qualities = make([]Quality, len(r.Qualities))
		copy(res.Qualities, r.Qualities)
	}
	if r.Tags != nil {
		res.Tags = make([]string, len(r.Tags))
		copy(res.Tags, r.Tags)
	}
	if r.CWE != nil {
		res.CWE = make([]string, len(r.CWE))
		copy(res.CWE, r.CWE)
	}
	if r.OWASP != nil {
		res.OWASP = make([]string, len(r.OWASP))
		copy(res.OWASP, r.OWASP)
	}
	return res
}

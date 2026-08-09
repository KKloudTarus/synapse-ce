// Package dastcheck defines the metadata contract for first-party DAST checks.
package dastcheck

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var idRE = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)

// Class is a clean-room DAST check category.
type Class string

const (
	ClassInjection               Class = "injection"
	ClassBrokenAccessControl     Class = "broken_access_control"
	ClassSSRF                    Class = "ssrf"
	ClassInsecureDeserialization Class = "insecure_deserialization"
	ClassMisconfiguration        Class = "security_misconfiguration"
	ClassSensitiveDataExposure   Class = "sensitive_data_exposure"
	ClassAuthenticationWeakness  Class = "authentication_weakness"
)

func (c Class) Valid() bool {
	switch c {
	case ClassInjection, ClassBrokenAccessControl, ClassSSRF, ClassInsecureDeserialization, ClassMisconfiguration, ClassSensitiveDataExposure, ClassAuthenticationWeakness:
		return true
	}
	return false
}

// BlastRadius identifies whether a check can modify application state.
type BlastRadius string

const (
	RadiusReadOnly      BlastRadius = "read_only"
	RadiusStateChanging BlastRadius = "state_changing"
)

func (r BlastRadius) Valid() bool { return r == RadiusReadOnly || r == RadiusStateChanging }

// Check is the executable check contract. ProofClass names the required evidence
// observation; checks without a proof must not create a finding.
type Check struct {
	ID             string
	CWE            string
	Class          Class
	BlastRadius    BlastRadius
	ProductionSafe bool
	ProofClass     string
}

func (c Check) Validate() error {
	if !idRE.MatchString(c.ID) || strings.TrimSpace(c.CWE) == "" || !c.Class.Valid() || !c.BlastRadius.Valid() || strings.TrimSpace(c.ProofClass) == "" {
		return fmt.Errorf("%w: invalid DAST check metadata", shared.ErrValidation)
	}
	if c.BlastRadius == RadiusStateChanging && c.ProductionSafe {
		return fmt.Errorf("%w: state-changing DAST check cannot be production-safe", shared.ErrValidation)
	}
	return nil
}

// CatalogEntry is non-executable check metadata published to operators.
type CatalogEntry struct {
	ID          string
	CWE         string
	Class       Class
	Title       string
	Description string
	Remediation string
}

func (e CatalogEntry) Validate() error {
	if !idRE.MatchString(e.ID) || strings.TrimSpace(e.CWE) == "" || !e.Class.Valid() || strings.TrimSpace(e.Title) == "" || strings.TrimSpace(e.Description) == "" || strings.TrimSpace(e.Remediation) == "" {
		return fmt.Errorf("%w: invalid DAST catalog metadata", shared.ErrValidation)
	}
	return nil
}

// ValidateParity rejects catalog drift: each implemented check must have exactly
// one catalog entry with the same stable ID and class, and vice versa.
func ValidateParity(catalog []CatalogEntry, checks []Check) error {
	catalogByID := make(map[string]CatalogEntry, len(catalog))
	for _, entry := range catalog {
		if err := entry.Validate(); err != nil {
			return err
		}
		if _, exists := catalogByID[entry.ID]; exists {
			return fmt.Errorf("%w: duplicate DAST catalog ID %q", shared.ErrValidation, entry.ID)
		}
		catalogByID[entry.ID] = entry
	}
	checkByID := make(map[string]Check, len(checks))
	for _, check := range checks {
		if err := check.Validate(); err != nil {
			return err
		}
		if _, exists := checkByID[check.ID]; exists {
			return fmt.Errorf("%w: duplicate DAST check ID %q", shared.ErrValidation, check.ID)
		}
		checkByID[check.ID] = check
		entry, found := catalogByID[check.ID]
		if !found || entry.Class != check.Class || entry.CWE != check.CWE {
			return fmt.Errorf("%w: DAST check %q has no matching catalog entry", shared.ErrValidation, check.ID)
		}
	}
	if len(catalogByID) != len(checkByID) {
		return fmt.Errorf("%w: DAST catalog and checks differ", shared.ErrValidation)
	}
	return nil
}

// SortedCatalog returns a deterministic copy for response and fixture generation.
func SortedCatalog(catalog []CatalogEntry) []CatalogEntry {
	out := append([]CatalogEntry(nil), catalog...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

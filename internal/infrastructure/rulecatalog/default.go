package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
)

// Default returns a new, immutable Catalog populated with all first-party Synapse rules.
// It aggregates rules from the SAST, secrets, code quality, reliability, and misconfiguration engines.
func Default() (*Catalog, error) {
	var all []rule.Rule

	all = append(all, sastRules()...)
	all = append(all, langPackCatalog()...)
	all = append(all, javaASTRules()...)
	all = append(all, jsASTRules()...)
	all = append(all, secretRules()...)
	all = append(all, misconfigRules()...)
	all = append(all, qualityRules()...)
	all = append(all, reliabilityRules()...)
	all = append(all, xmlRules()...)
	all = append(all, pythonRules()...)
	all = append(all, notebookRules()...)

	return New(all)
}

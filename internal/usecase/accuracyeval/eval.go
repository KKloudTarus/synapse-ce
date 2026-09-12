package accuracyeval

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// CaseScanner runs the owned detection engine over one case's SBOM against its pinned advisories and
// returns the raw findings. It is injected (the concrete implementation wraps ownadvisory.Source in
// the infrastructure layer) so this package stays free of any infrastructure import.
type CaseScanner interface {
	ScanCase(ctx context.Context, advisories []advisory.Advisory, doc *sbom.SBOM) ([]vulnerability.RawFinding, error)
}

// Observe runs the engine over one case and keys both the ground truth and the produced findings by
// "component@version|advisory-id". A produced finding is keyed STRICTLY by its own primary id
// (ownadvisory.Source reports the CVE when the advisory carries one), with no alias rescue, so a
// wrong advisory cannot be laundered into a true positive through a shared alias.
func Observe(ctx context.Context, scanner CaseScanner, c Case) (benchmark.AccuracyObservation, error) {
	raws, err := scanner.ScanCase(ctx, CaseAdvisories(c), CaseSBOM(c))
	if err != nil {
		return benchmark.AccuracyObservation{}, fmt.Errorf("case %q: scan: %w", c.Name, err)
	}
	expKeys := make([]string, 0, len(c.Expected))
	for _, e := range c.Expected {
		expKeys = append(expKeys, e.Component+"@"+e.Version+"|"+e.CVE)
	}
	prodKeys := make([]string, 0, len(raws))
	for _, r := range raws {
		prodKeys = append(prodKeys, r.Component+"@"+r.Version+"|"+r.AdvisoryID)
	}
	return benchmark.AccuracyObservation{Case: c.Name, Group: c.Group, Expected: expKeys, Produced: prodKeys}, nil
}

// Evaluate runs the engine over the whole embedded corpus and reduces it to an accuracy report
// (overall + per-group precision/recall/F1/false-discovery/false-negative). Pure and offline given
// an offline scanner.
func Evaluate(ctx context.Context, scanner CaseScanner) (benchmark.AccuracyReport, error) {
	cases, err := Load()
	if err != nil {
		return benchmark.AccuracyReport{}, err
	}
	obs := make([]benchmark.AccuracyObservation, 0, len(cases))
	for _, c := range cases {
		o, err := Observe(ctx, scanner, c)
		if err != nil {
			return benchmark.AccuracyReport{}, err
		}
		obs = append(obs, o)
	}
	return benchmark.EvaluateAccuracy(benchmark.AccuracyInput{
		SchemaVersion: benchmark.AccuracyInputSchemaVersion,
		Observations:  obs,
	})
}

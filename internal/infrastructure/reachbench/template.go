package reachbench

import (
	"fmt"

	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

// validateFrozenTemplateStaticContract prevents a controller-provided input from
// redefining the corpus, oracle, policy, evaluator, or snapshot that it then
// asks the runner to trust. Lifecycle artifacts are intentionally checked by the
// measurement input validator, not compared here.
func validateFrozenTemplateStaticContract(input measurement.MeasurementInput) error {
	baseline, err := measurement.DefaultBaselineMeasurementInput()
	if err != nil {
		return fmt.Errorf("load default reachability contract: %w", err)
	}
	for _, item := range []struct {
		name string
		got  any
		want any
	}{
		{name: "inventory", got: input.Inventory, want: baseline.Inventory},
		{name: "corpus", got: input.Corpus, want: baseline.Corpus},
		{name: "oracle", got: input.Oracle, want: baseline.Oracle},
		{name: "measurement policy", got: input.Policy, want: baseline.Policy},
		{name: "exception manifest", got: input.Exceptions, want: baseline.Exceptions},
		{name: "active snapshot", got: input.ActiveSnapshot, want: baseline.ActiveSnapshot},
	} {
		if !sameCanonical(item.got, item.want) {
			return fmt.Errorf("trusted measurement input %s does not match the frozen default contract", item.name)
		}
	}
	return nil
}

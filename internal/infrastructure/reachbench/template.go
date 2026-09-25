package reachbench

import measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"

// validateFrozenTemplateStaticContract prevents a controller-provided input from
// redefining the corpus, oracle, policy, evaluator, or snapshot that it then
// asks the runner to trust. Lifecycle artifacts are intentionally checked by the
// measurement input validator, not compared here.
func validateFrozenTemplateStaticContract(input measurement.MeasurementInput) error {
	_, err := measurement.ResolveReachabilityProfile(input)
	return err
}

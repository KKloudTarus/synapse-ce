package orchestrator

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// Observation is the result of executing an admitted action. Output is the RAW tool output;
// the orchestrator REDACTS + size-caps + fences it before it re-enters the LLM transcript or
// is sealed (untrusted tool output must not carry secrets – or instructions –
// back into the model). Secrets lists any secret values to scrub from Output (e.g. a
// credential the run injected via a {{secret}} placeholder); typically empty for recon, whose
// argv is scope-only.
type Observation struct {
	Output  []byte
	Summary string   // short, human/audit-facing (e.g. "subfinder: 12 hosts")
	Secrets [][]byte // values to scrub from Output before it re-enters the transcript
}

// Executor runs an AdmittedAction and returns its observation. It takes a
// safety.AdmittedAction – a type whose fields ONLY safety.Gate can populate – so there is no
// way to call Execute with an action that skipped scope + approval: the typed orchestration boundary is enforced
// by the compiler, not a checklist. The production implementation dispatches to the
// sandboxed recon/SCA use-cases; tests fake it.
type Executor interface {
	Execute(ctx context.Context, adm safety.AdmittedAction) (Observation, error)
}

package httpapi

import evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"

// What the core and reports seeds share lives here, owned by neither of them, so that neither reads a
// constant the other defines. The only thing they pass along is the evidence vault: the scan service
// takes its evidence store only through its constructor, so it is built once, by the "reports" seed,
// and has to receive the vault the "core" seed sealed its ledger and artifact into. Two seeds each
// building the scan service would let the later replace the earlier and silently empty its routes.
//
// Seeds run in name order, so "core" leaves the vault in harnessWorld.state before "reports" asks for
// it. A reports seed that finds no vault builds the scan service without one, and the routes that
// need the vault stay unwired rather than failing the seed.

// harnessEvidenceVaultKey is where the vault is left in harnessWorld.state.
const harnessEvidenceVaultKey = "evidence-vault"

// harnessEvidenceVault returns the vault a seed left in the shared state, or nil when none did.
func harnessEvidenceVault(w *harnessWorld) *evidenceuc.Service {
	svc, _ := w.state[harnessEvidenceVaultKey].(*evidenceuc.Service)
	return svc
}

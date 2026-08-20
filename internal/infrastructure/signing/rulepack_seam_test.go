package signing

import rulepackuc "github.com/KKloudTarus/synapse-ce/internal/usecase/rulepack"

var _ rulepackuc.GateEvidenceSigner = (*Ed25519Signer)(nil)

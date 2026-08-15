package aitriagereview

import "github.com/KKloudTarus/synapse-ce/internal/domain/shared"

// IsMachineActor reports whether actor uses one of Synapse's reserved non-human
// principal prefixes. Curation and other in-process consumers should use this
// shared predicate instead of duplicating the denylist maintained by the review
// domain.
func IsMachineActor(actor string) bool {
	return shared.IsMachineActor(actor)
}

// IsMachineOrModelActor reports whether actor is either a reserved machine
// principal or the identity of one of the supplied models. It mirrors the
// separation-of-duties check enforced by Review.Decide/Claim for consumers that
// must revalidate a durable review snapshot fail closed.
func IsMachineOrModelActor(actor string, models ...string) bool {
	if machineActor(actor) {
		return true
	}
	for _, model := range models {
		if sameIdentity(actor, model) {
			return true
		}
	}
	return false
}

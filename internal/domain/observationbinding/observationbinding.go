// Package observationbinding models the human-approved link between an external observation and a
// canonical finding.
//
// It exists because the two were the same field. An imported finding's FindingID is set by the
// deduplicator when an external result lands on the same file and line as a first-party finding, which is
// a CANDIDATE: evidence that the two may describe one issue. Readers treated it as a management decision,
// so a coincidence of location merged two remediation workflows and nobody was ever asked.
//
// A binding is that decision, made by a person, carrying the reason and the observation it was made on. A
// candidate stays a candidate until one exists.
package observationbinding

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Binding is one version of the approved link between a scoped external identity and a canonical finding.
//
// Versions are kept rather than overwritten: a binding that was replaced is the record of what the
// workflow used to believe, and the reason it stopped believing it.
type Binding struct {
	ID           shared.ID
	TenantID     shared.ID
	EngagementID shared.ID
	// Scope and ExternalIdentity together name the observation ACROSS imports. They are deliberately not
	// the observation's row id: re-importing a report mints new observation rows, and a decision a person
	// made must survive that.
	Scope            string
	ExternalIdentity string
	// FindingID is the canonical finding this observation was approved onto.
	FindingID shared.ID
	// ObservationID is the row the decision was made on. It is lineage, not identity: it says which
	// evidence the person was looking at.
	ObservationID shared.ID
	// Version starts at 1 and increases by one each time the binding is superseded.
	Version int
	// DecidedBy and Reason are what make this a decision rather than a match. Neither may be empty.
	DecidedBy shared.ID
	Reason    string
	DecidedAt time.Time
	// SupersededAt is set when a later version replaced this one, and is the zero time while current.
	SupersededAt time.Time
}

// MaxReasonBytes bounds the stored reason. A decision needs a sentence, not a document, and the column is
// read back into every binding listing.
const MaxReasonBytes = 2000

// Current reports whether this version is the one in force.
func (b Binding) Current() bool { return b.SupersededAt.IsZero() }

// Validate refuses a binding that could not be audited or reproduced.
func (b Binding) Validate() error {
	switch {
	case b.ID.IsZero():
		return fmt.Errorf("%w: an observation binding needs an id", shared.ErrValidation)
	case b.TenantID.IsZero():
		return fmt.Errorf("%w: an observation binding needs a tenant", shared.ErrValidation)
	case b.EngagementID.IsZero():
		return fmt.Errorf("%w: an observation binding needs an engagement", shared.ErrValidation)
	case strings.TrimSpace(b.Scope) == "":
		return fmt.Errorf("%w: an observation binding needs a scope", shared.ErrValidation)
	case strings.TrimSpace(b.ExternalIdentity) == "":
		return fmt.Errorf("%w: an observation binding needs an external identity", shared.ErrValidation)
	case b.FindingID.IsZero():
		return fmt.Errorf("%w: an observation binding needs the finding it was approved onto", shared.ErrValidation)
	case b.ObservationID.IsZero():
		return fmt.Errorf("%w: an observation binding needs the observation the decision was made on", shared.ErrValidation)
	case b.Version < 1:
		return fmt.Errorf("%w: an observation binding version starts at 1", shared.ErrValidation)
	case b.DecidedBy.IsZero():
		// An unattributable decision is indistinguishable from an automatic merge, which is the thing
		// this type exists to prevent.
		return fmt.Errorf("%w: an observation binding needs the actor who decided it", shared.ErrValidation)
	case strings.TrimSpace(b.Reason) == "":
		return fmt.Errorf("%w: an observation binding needs a reason", shared.ErrValidation)
	case len(b.Reason) > MaxReasonBytes:
		return fmt.Errorf("%w: an observation binding reason is longer than %d bytes", shared.ErrValidation, MaxReasonBytes)
	case b.DecidedAt.IsZero():
		return fmt.Errorf("%w: an observation binding needs a decision time", shared.ErrValidation)
	case !b.SupersededAt.IsZero() && b.SupersededAt.Before(b.DecidedAt):
		return fmt.Errorf("%w: an observation binding was superseded before it was decided", shared.ErrValidation)
	}
	return nil
}

// Identity is the key a binding is looked up by, within one tenant engagement.
type Identity struct {
	Scope            string
	ExternalIdentity string
}

// Key returns the identity of this binding.
func (b Binding) Key() Identity {
	return Identity{Scope: b.Scope, ExternalIdentity: b.ExternalIdentity}
}

// Validate refuses an identity that cannot address a binding.
func (i Identity) Validate() error {
	if strings.TrimSpace(i.Scope) == "" || strings.TrimSpace(i.ExternalIdentity) == "" {
		return fmt.Errorf("%w: an observation binding identity needs a scope and an external identity", shared.ErrValidation)
	}
	return nil
}

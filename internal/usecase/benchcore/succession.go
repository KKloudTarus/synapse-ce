package benchcore

import (
	"fmt"
	"strings"
)

// ValidateSuccession checks that next may replace prev: it is the next revision, it names prev's digest,
// and every profile it removes or downgrades is listed in its changes with a rationale. A reduced scope
// is never presented as completion of the original one.
func ValidateSuccession(prev, next ClosureManifest) error {
	if err := next.Validate(); err != nil {
		return err
	}
	prevDigest, err := DigestManifest(prev)
	if err != nil {
		return err
	}
	if next.Supersedes == nil {
		return fmt.Errorf("%w: revision %d names no predecessor", ErrInvalidManifest, next.Revision)
	}
	if next.Revision != prev.Revision+1 || next.Supersedes.Revision != prev.Revision || next.Supersedes.Digest != prevDigest {
		return fmt.Errorf("%w: revision %d must supersede revision %d at %s", ErrInvalidManifest, next.Revision, prev.Revision, prevDigest)
	}
	if strings.TrimSpace(next.Supersedes.ScopeChangeRationale) == "" {
		return fmt.Errorf("%w: a new revision needs a scope change rationale", ErrInvalidManifest)
	}
	disclosed := map[string]bool{}
	for _, change := range next.Supersedes.Changes {
		for _, p := range prev.Profiles {
			if strings.Contains(change, p.ID) {
				disclosed[p.ID] = true
			}
		}
	}
	rank := map[string]int{DispositionRequired: 3, DispositionConditional: 2, DispositionOptional: 1}
	for _, before := range prev.Profiles {
		after, ok := next.Profile(before.ID)
		switch {
		case !ok:
			if !disclosed[before.ID] {
				return fmt.Errorf("%w: profile %s was removed without being listed in changes", ErrInvalidManifest, before.ID)
			}
		case rank[after.Disposition] < rank[before.Disposition]:
			if !disclosed[before.ID] {
				return fmt.Errorf("%w: profile %s was downgraded from %s to %s without being listed in changes", ErrInvalidManifest, before.ID, before.Disposition, after.Disposition)
			}
		}
	}
	return nil
}

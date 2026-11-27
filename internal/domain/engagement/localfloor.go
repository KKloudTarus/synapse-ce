package engagement

import (
	"fmt"
	"path/filepath"
)

// CheckLocalRepos applies the operator's floor on local paths to the in-scope repository entries
// that name one. The floor is configuration, which this package cannot read, so the caller supplies
// it; a nil check admits everything. Git URLs and out-of-scope entries are not judged (#1701).
//
// inherited are entries the scope already held: the engagement's current scope on an edit, or the
// predecessor's on a re-test that copies it. They are not judged again. An engagement scoped before
// the floor existed keeps its scope and stays editable; the acquirer refuses such a target when a
// scan names it, which is where the floor is enforced.
func CheckLocalRepos(inScope, inherited []Target, check func(path string) error) error {
	if check == nil {
		return nil
	}
	held := make(map[Target]struct{}, len(inherited))
	for _, target := range inherited {
		held[target] = struct{}{}
	}
	for _, target := range inScope {
		if target.Kind != TargetRepo || !filepath.IsAbs(target.Value) {
			continue
		}
		if _, ok := held[target]; ok {
			continue
		}
		if err := check(target.Value); err != nil {
			return fmt.Errorf("in-scope repo %q: %w", target.Value, err)
		}
	}
	return nil
}

package ownadvisory

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// Alpine publishes ONE secdb document per branch, so an advisory that affects several branches appears once
// per branch, each with that branch's own fixed version. The advisory store keeps one row per advisory id, so
// feeding those separately means the last branch ingested replaces the rest: CVE-2024-56171 ended up recorded
// only for Alpine:v3.24 with the 2.13.6-r0 fix, and a scan of an Alpine 3.19 image, where the fix is
// 2.11.8-r1, matched nothing. Ten of the CVEs Trivy reports on nginx:1.25-alpine were exactly this.
//
// So a secdb feed aggregates by id across every document it reads and emits each advisory once, carrying one
// affected entry per branch.

// maxSecdbAdvisories bounds the aggregate. Alpine's whole published secdb is about 80,000 advisories, so this
// is generous headroom and still refuses a hostile mirror that streams forever.
const maxSecdbAdvisories = 1_000_000

// secdbAggregator unions per-branch advisories by id, preserving first-seen order so an ingest is deterministic.
type secdbAggregator struct {
	order []string
	byID  map[string]*advisory.Advisory
	seen  map[string]map[string]struct{} // advisory id -> set of "ecosystem\x00package\x00fixed"
}

func newSecdbAggregator() *secdbAggregator {
	return &secdbAggregator{byID: map[string]*advisory.Advisory{}, seen: map[string]map[string]struct{}{}}
}

// add folds one document's advisory into the aggregate. It returns an error only when the aggregate would grow
// past its bound, which is a hostile feed rather than a real one.
func (a *secdbAggregator) add(adv advisory.Advisory) error {
	existing := a.byID[adv.ID]
	if existing == nil {
		if len(a.order) >= maxSecdbAdvisories {
			return fmt.Errorf("secdb feed exceeds %d advisories", maxSecdbAdvisories)
		}
		copied := adv
		copied.Affected = append([]advisory.AffectedPackage(nil), adv.Affected...)
		copied.Aliases = append([]string(nil), adv.Aliases...)
		a.byID[adv.ID] = &copied
		a.order = append(a.order, adv.ID)
		a.seen[adv.ID] = map[string]struct{}{}
		for _, pkg := range copied.Affected {
			a.seen[adv.ID][affectedKey(pkg)] = struct{}{}
		}
		return nil
	}
	for _, pkg := range adv.Affected {
		key := affectedKey(pkg)
		if _, dup := a.seen[adv.ID][key]; dup {
			continue
		}
		a.seen[adv.ID][key] = struct{}{}
		existing.Affected = append(existing.Affected, pkg)
	}
	for _, alias := range adv.Aliases {
		if !containsString(existing.Aliases, alias) {
			existing.Aliases = append(existing.Aliases, alias)
		}
	}
	// A later document may carry a summary where an earlier one had none.
	if existing.Summary == "" {
		existing.Summary = adv.Summary
	}
	return nil
}

// each emits every aggregated advisory once, with its affected entries in a stable order.
func (a *secdbAggregator) each(fn func(advisory.Advisory) error) error {
	for _, id := range a.order {
		adv := *a.byID[id]
		sort.SliceStable(adv.Affected, func(i, j int) bool {
			return affectedKey(adv.Affected[i]) < affectedKey(adv.Affected[j])
		})
		if err := fn(adv); err != nil {
			return err
		}
	}
	return nil
}

func affectedKey(p advisory.AffectedPackage) string {
	return p.Ecosystem + "\x00" + p.Package + "\x00" + p.FixedVersion
}

func containsString(all []string, want string) bool {
	for _, v := range all {
		if v == want {
			return true
		}
	}
	return false
}

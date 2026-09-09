package advisory

// PreserveEnrichment returns a copy of a with its exploitation-risk signals raised to at least prior's.
//
// It exists for the OWNED store's bulk re-ingest path (advisoryingest.Service -> ports.AdvisoryWriter.Upsert):
// a re-sync refreshes the base advisory (identity, aliases, summary, CVSS, affected ranges, severity, and
// withdrawal) from the feed, but the bulk feed carries no exploitation-risk enrichment. KEV comes from CISA
// KEV, EPSS/EPSSPercentile from FIRST EPSS, and PublicExploit from the exploit feed - separate sources the
// canonical materializer merges in. A bulk advisory's zero risk signal therefore means "this feed does not
// know", not "no exploit". Blindly writing it would LOWER a value the risk pipeline already established, the
// corpus clobber this guards against. The raise-only rule matches the invariant documented on Advisory: the
// online risk enricher only ever RAISES these, never lowers a corpus value.
//
// Only the four monotonic risk signals are carried forward. The affected set, CVSS, severity, and withdrawal
// are left as the incoming feed's, so a feed that NARROWS an advisory (retracts an affected package, marks it
// withdrawn) still takes effect: those fields have per-feed authority that a blind carry-forward would break.
// Cross-feed union of affected ranges is a separate concern that requires per-source provenance (the
// observation/canonical model), not this flat merge.
func (a Advisory) PreserveEnrichment(prior Advisory) Advisory {
	a.KEV = a.KEV || prior.KEV
	a.PublicExploit = a.PublicExploit || prior.PublicExploit
	if prior.EPSS > a.EPSS {
		a.EPSS = prior.EPSS
	}
	if prior.EPSSPercentile > a.EPSSPercentile {
		a.EPSSPercentile = prior.EPSSPercentile
	}
	return a
}

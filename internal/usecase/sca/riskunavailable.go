package sca

import (
	"fmt"
	"sort"
)

// riskFeedNotes names a risk feed in operator text, says what its absence means, and names the setting that
// redirects it. The keys are the ones the enricher uses in RiskResult.Unavailable and Matches.
var riskFeedNotes = map[string]struct{ label, effect, setting string }{
	"kev": {
		label:   "CISA KEV catalogue",
		effect:  `no vulnerability was checked against it, so kev=false and risk_matches.kev=0 mean "not checked", not "not known-exploited"`,
		setting: "SYNAPSE_KEV_URL",
	},
}

// riskUnavailableWarnings turns the risk feeds a scan could not read into one operator warning each, in a
// stable order. It is a warning, not an engine outcome: a feed outage has never lowered engine coverage or
// failed --require-complete, and a CI network that blocks a feed must not start failing for that reason.
// The cause is only the enricher's short class ("http 403"), never an error string, so a feed URL carrying a
// credential cannot reach the report.
func riskUnavailableWarnings(unavailable map[string]string) []string {
	feeds := make([]string, 0, len(unavailable))
	for feed := range unavailable {
		feeds = append(feeds, feed)
	}
	sort.Strings(feeds)
	out := make([]string, 0, len(feeds))
	for _, feed := range feeds {
		note, ok := riskFeedNotes[feed]
		if !ok {
			note.label, note.effect = feed+" risk feed", "its signal is missing from this scan"
		}
		warning := fmt.Sprintf("%s could not be read (%s): %s", note.label, unavailable[feed], note.effect)
		if note.setting != "" {
			warning += fmt.Sprintf("; check network access to it, or set %s to a reachable mirror", note.setting)
		}
		out = append(out, warning)
	}
	return out
}

package correlation

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// defaultActor is the attribution stamped on correlator-authored incident events.
const defaultActor = "correlator"

// Config tunes correlation. Zero fields take documented defaults.
type Config struct {
	// Window is the session gap: within one (asset, entity) key, a signal more than Window after the
	// previous signal starts a NEW incident; otherwise it joins the current one. Must be > 0.
	Window time.Duration
	// MaxPerIncident caps how many signals an incident reflects individually (the Created signal plus
	// attaches). Beyond it, further signals are suppressed as a storm and recorded as a single note
	// (coverage-honest). Must be > 0.
	MaxPerIncident int
	// Actor is the attribution for emitted events; defaults to "correlator".
	Actor string
}

func (c Config) withDefaults() Config {
	if c.Actor == "" {
		c.Actor = defaultActor
	}
	return c
}

// Correlate folds detection signals into incidents and returns the incident.IncidentEvent log to persist
// and project. It is deterministic and event-time-based: signals are ordered by (OccurredAt, ID) so an
// out-of-order input yields the same incidents; duplicates (by signal ID) are collapsed; each (asset,
// entity) session within Window becomes one incident; a storm beyond MaxPerIncident is suppressed to a
// single recorded note.
//
// Output contract: the returned slice contains the events for MULTIPLE incidents, contiguous per incident
// and ordered by incident id. Each incident's sub-slice is internally time-ordered and Created-first, so a
// consumer (C7 persistence) appends the flat stream as-is, but a caller that PROJECTS must first partition
// by IncidentID and fold each incident separately — folding the whole flat slice through one
// incident.Project would fail on the second Created.
//
// This is BATCH correlation over a complete signal set. Incident identity is seeded on a session's
// earliest signal, so an incremental re-run over a backfilled window whose earliest signal changed would
// mint a different incident id; C7 should correlate over stable/complete windows (streaming watermark +
// late-event revision are a documented extension, not implemented here).
func Correlate(cfg Config, signals []Signal) ([]incident.IncidentEvent, error) {
	cfg = cfg.withDefaults()
	if cfg.Window <= 0 {
		return nil, fmt.Errorf("%w: correlation window must be positive", shared.ErrValidation)
	}
	if cfg.MaxPerIncident <= 0 {
		return nil, fmt.Errorf("%w: correlation max-per-incident must be positive", shared.ErrValidation)
	}

	ordered, err := dedupeAndOrder(signals)
	if err != nil {
		return nil, err
	}

	// Partition into per-key sessions, preserving event-time order within each key.
	byKey := map[correlationKey][]Signal{}
	var keyOrder []correlationKey
	for _, s := range ordered {
		k := s.key()
		if _, seen := byKey[k]; !seen {
			keyOrder = append(keyOrder, k)
		}
		byKey[k] = append(byKey[k], s)
	}

	type builtIncident struct {
		id     shared.ID
		events []incident.IncidentEvent
	}
	var incidents []builtIncident
	for _, k := range keyOrder {
		for _, session := range sessions(byKey[k], cfg.Window) {
			incidents = append(incidents, builtIncident{
				id:     incidentID(k.asset, k.entity, session[0].ID),
				events: sessionEvents(cfg, k, session),
			})
		}
	}
	// Stable output: incidents ordered by id, events already in event-time order within each.
	sort.Slice(incidents, func(i, j int) bool { return incidents[i].id < incidents[j].id })
	var out []incident.IncidentEvent
	for _, inc := range incidents {
		out = append(out, inc.events...)
	}
	return out, nil
}

// dedupeAndOrder validates every signal and folds duplicate detection ids into one representative, then
// returns the representatives ordered by (OccurredAt, ID). Folding a duplicate id by the MAX severity (and
// on a tie the earliest observation) makes dedupe total and deterministic regardless of input order, and
// keeps it coverage-honest: if the data plane ever re-emits a detection id with a higher severity (an
// escalation), the escalation is never discarded. A detection id is expected to be immutable upstream, so
// this fold is normally a no-op over identical repeats.
func dedupeAndOrder(signals []Signal) ([]Signal, error) {
	best := make(map[shared.ID]Signal, len(signals))
	for _, s := range signals {
		if err := s.Validate(); err != nil {
			return nil, err
		}
		if cur, ok := best[s.ID]; !ok || preferSignal(s, cur) {
			best[s.ID] = s
		}
	}
	out := make([]Signal, 0, len(best))
	for _, s := range best {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// preferSignal reports whether a should replace b as the representative of a duplicate detection id:
// higher severity wins (an escalation is never lost); on equal severity the earlier observation wins.
// Fully deterministic and total — two records with equal id, severity, and time keep the incumbent.
func preferSignal(a, b Signal) bool {
	ra, rb := shared.SeverityRank(a.Severity), shared.SeverityRank(b.Severity)
	if ra != rb {
		return ra > rb
	}
	return a.OccurredAt.Before(b.OccurredAt)
}

// sessions splits event-time-ordered signals for one key into sessions: a gap greater than window since
// the previous signal starts a new session.
func sessions(signals []Signal, window time.Duration) [][]Signal {
	var out [][]Signal
	var cur []Signal
	for _, s := range signals {
		if len(cur) > 0 && s.OccurredAt.Sub(cur[len(cur)-1].OccurredAt) > window {
			out = append(out, cur)
			cur = nil
		}
		cur = append(cur, s)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// sessionEvents builds the incident event log for one session: a Created (carrying the session's MAX
// severity so a later, more severe signal is not masked by the first), attaches up to the storm cap, and
// a single suppression note beyond it.
func sessionEvents(cfg Config, k correlationKey, session []Signal) []incident.IncidentEvent {
	id := incidentID(k.asset, k.entity, session[0].ID)
	first := session[0]
	title := first.Title
	if title == "" {
		title = first.RuleID // fall back to the rule name so a correlated incident is never untitled
	}
	events := []incident.IncidentEvent{{
		IncidentID: id, Kind: incident.EventCreated, At: first.OccurredAt, Actor: cfg.Actor,
		AssetID: k.asset, Title: title, Severity: maxSeverity(session), DetectionID: first.ID,
	}}
	suppressed := 0
	for _, s := range session[1:] {
		if len(events) >= cfg.MaxPerIncident {
			suppressed++
			continue
		}
		events = append(events, incident.IncidentEvent{
			IncidentID: id, Kind: incident.EventDetectionAttached, At: s.OccurredAt, Actor: cfg.Actor,
			DetectionID: s.ID,
		})
	}
	if suppressed > 0 {
		events = append(events, incident.IncidentEvent{
			IncidentID: id, Kind: incident.EventAnalystCommented, At: session[len(session)-1].OccurredAt, Actor: cfg.Actor,
			Comment: fmt.Sprintf("correlation storm: %d further signal(s) suppressed from this incident", suppressed),
		})
	}
	return events
}

// maxSeverity returns the highest severity among a session's signals (empty if none carry one).
func maxSeverity(session []Signal) shared.Severity {
	var best shared.Severity
	for _, s := range session {
		if s.Severity == "" {
			continue
		}
		if best == "" || shared.SeverityRank(s.Severity) > shared.SeverityRank(best) {
			best = s.Severity
		}
	}
	return best
}

// incidentID derives a stable incident id from (asset, entity, first-signal id) — domain-separated,
// length-prefixed sha256, so re-correlating the same signals yields the same incident id.
func incidentID(asset, entity, firstSignal shared.ID) shared.ID {
	h := sha256.New()
	for _, part := range []string{"correlation:incident:v1", asset.String(), entity.String(), firstSignal.String()} {
		var lp [8]byte
		binary.BigEndian.PutUint64(lp[:], uint64(len(part)))
		_, _ = h.Write(lp[:])
		_, _ = io.WriteString(h, part)
	}
	return shared.ID("inc_" + hex.EncodeToString(h.Sum(nil))[:32])
}

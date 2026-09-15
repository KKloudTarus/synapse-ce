package measure

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

const CouplingSchemaVersion = 1

// CouplingModule is a first-party source module. IDs include the language family
// so a mixed-language repository cannot accidentally merge equal paths.
type CouplingModule struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Language string `json:"language"`
}

// CouplingEdge is one distinct directed first-party dependency.
type CouplingEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// CouplingGap records why the graph is incomplete without retaining source text
// or host paths.
type CouplingGap struct {
	Language string `json:"language"`
	Path     string `json:"path,omitempty"`
	Reason   string `json:"reason"`
}

// CouplingReport is immutable source-graph evidence. Complete is deliberately
// explicit: a partial graph may be useful to diagnose collection, but must not
// satisfy a quality gate.
type CouplingReport struct {
	Version  int              `json:"version"`
	Complete bool             `json:"complete"`
	Modules  []CouplingModule `json:"modules"`
	Edges    []CouplingEdge   `json:"edges"`
	Gaps     []CouplingGap    `json:"gaps,omitempty"`
}

// CouplingMetrics exposes distinct incoming/outgoing neighbours. Instability is
// undefined for an isolated scope because 0/0 has no architectural meaning.
type CouplingMetrics struct {
	Afferent    CountMetric   `json:"afferent"`
	Efferent    CountMetric   `json:"efferent"`
	Instability DecimalMetric `json:"instability"`
}

// NewCouplingReport validates, sorts and de-duplicates source graph evidence.
func NewCouplingReport(modules []CouplingModule, edges []CouplingEdge, gaps []CouplingGap) (CouplingReport, error) {
	report := CouplingReport{Version: CouplingSchemaVersion, Complete: len(gaps) == 0}
	byID := make(map[string]CouplingModule, len(modules))
	for _, module := range modules {
		module.ID = strings.TrimSpace(module.ID)
		module.Language = strings.ToLower(strings.TrimSpace(module.Language))
		canonical, err := CanonicalPath(module.Path)
		if err != nil || canonical != module.Path || module.ID == "" || module.Language == "" {
			return CouplingReport{}, fmt.Errorf("coupling module is invalid: %q", module.ID)
		}
		if existing, ok := byID[module.ID]; ok && existing != module {
			return CouplingReport{}, fmt.Errorf("coupling module id %q is ambiguous", module.ID)
		}
		byID[module.ID] = module
	}
	for _, module := range byID {
		report.Modules = append(report.Modules, module)
	}
	sort.Slice(report.Modules, func(i, j int) bool { return report.Modules[i].ID < report.Modules[j].ID })

	seenEdges := map[string]bool{}
	for _, edge := range edges {
		edge.From, edge.To = strings.TrimSpace(edge.From), strings.TrimSpace(edge.To)
		if edge.From == edge.To {
			continue
		}
		if _, ok := byID[edge.From]; !ok {
			return CouplingReport{}, fmt.Errorf("coupling edge has unknown source %q", edge.From)
		}
		if _, ok := byID[edge.To]; !ok {
			return CouplingReport{}, fmt.Errorf("coupling edge has unknown target %q", edge.To)
		}
		key := edge.From + "\x00" + edge.To
		if !seenEdges[key] {
			seenEdges[key] = true
			report.Edges = append(report.Edges, edge)
		}
	}
	sort.Slice(report.Edges, func(i, j int) bool {
		if report.Edges[i].From != report.Edges[j].From {
			return report.Edges[i].From < report.Edges[j].From
		}
		return report.Edges[i].To < report.Edges[j].To
	})

	for _, gap := range gaps {
		gap.Language = strings.ToLower(strings.TrimSpace(gap.Language))
		gap.Reason = strings.TrimSpace(gap.Reason)
		if gap.Language == "" || gap.Reason == "" {
			return CouplingReport{}, errors.New("coupling gap requires language and reason")
		}
		if gap.Path != "" {
			canonical, err := CanonicalPath(gap.Path)
			if err != nil || canonical != gap.Path {
				return CouplingReport{}, fmt.Errorf("coupling gap path is invalid: %q", gap.Path)
			}
		}
		report.Gaps = append(report.Gaps, gap)
	}
	sort.Slice(report.Gaps, func(i, j int) bool {
		if report.Gaps[i].Language != report.Gaps[j].Language {
			return report.Gaps[i].Language < report.Gaps[j].Language
		}
		if report.Gaps[i].Path != report.Gaps[j].Path {
			return report.Gaps[i].Path < report.Gaps[j].Path
		}
		return report.Gaps[i].Reason < report.Gaps[j].Reason
	})
	if err := report.Validate(); err != nil {
		return CouplingReport{}, err
	}
	return report, nil
}

// Validate bounds and re-derives the canonical report to reject forged or
// corrupt aggregate evidence at import/read time.
func (r CouplingReport) Validate() error {
	if r.Version != CouplingSchemaVersion {
		return fmt.Errorf("coupling report: unsupported version %d", r.Version)
	}
	if len(r.Modules) > 50_000 || len(r.Edges) > 250_000 || len(r.Gaps) > 4_096 {
		return errors.New("coupling report: evidence limit exceeded")
	}
	if r.Complete != (len(r.Gaps) == 0) {
		return errors.New("coupling report: completeness disagrees with gaps")
	}
	seenModules := map[string]bool{}
	lastID := ""
	for i, module := range r.Modules {
		canonical, err := CanonicalPath(module.Path)
		if err != nil || canonical != module.Path || strings.TrimSpace(module.ID) != module.ID || module.ID == "" || strings.ToLower(module.Language) != module.Language || module.Language == "" {
			return fmt.Errorf("coupling report: invalid module %q", module.ID)
		}
		if seenModules[module.ID] || (i > 0 && module.ID < lastID) {
			return errors.New("coupling report: modules are duplicate or unsorted")
		}
		seenModules[module.ID], lastID = true, module.ID
	}
	lastEdge := ""
	for _, edge := range r.Edges {
		key := edge.From + "\x00" + edge.To
		if edge.From == edge.To || !seenModules[edge.From] || !seenModules[edge.To] || key <= lastEdge {
			return errors.New("coupling report: edge is invalid, duplicate, or unsorted")
		}
		lastEdge = key
	}
	lastGap := ""
	for i, gap := range r.Gaps {
		canonical, err := CanonicalPath(gap.Path)
		if gap.Path == "" {
			canonical, err = "", nil
		}
		key := gap.Language + "\x00" + gap.Path + "\x00" + gap.Reason
		if err != nil || canonical != gap.Path || strings.ToLower(strings.TrimSpace(gap.Language)) != gap.Language || gap.Language == "" || strings.TrimSpace(gap.Reason) != gap.Reason || gap.Reason == "" || (i > 0 && key < lastGap) {
			return errors.New("coupling report: gap is invalid or unsorted")
		}
		lastGap = key
	}
	return nil
}

// MetricsForPath returns an exact module's coupling or a directory boundary
// measure. The project root returns maxima across modules, which is what gates use.
func (r CouplingReport) MetricsForPath(path string, kind NodeKind) CouplingMetrics {
	if !r.Complete {
		return unavailableCoupling("coupling_incomplete")
	}
	if len(r.Modules) == 0 {
		return unavailableCoupling("no_supported_modules")
	}
	if kind == NodeProject {
		ce, ceOK := r.MaxEfferent()
		instability, instabilityOK := r.MaxInstability()
		out := CouplingMetrics{Afferent: unavailableCount("project_uses_module_maxima")}
		if ceOK {
			out.Efferent = availableCount(ce)
		} else {
			out.Efferent = unavailableCount("no_supported_modules")
		}
		if instabilityOK {
			out.Instability = availableDecimal(instability)
		} else {
			out.Instability = unavailableDecimal("no_connected_modules")
		}
		return out
	}

	inside := map[string]bool{}
	for _, module := range r.Modules {
		if module.Path == path {
			inside[module.ID] = true
		}
	}
	// A directory that is itself a Go package is a module, even when it also
	// contains child packages. Only directories without an exact module use a
	// subtree boundary aggregate.
	if len(inside) == 0 && kind == NodeDirectory && path != "" {
		for _, module := range r.Modules {
			if strings.HasPrefix(module.Path, path+"/") {
				inside[module.ID] = true
			}
		}
	}
	if len(inside) == 0 {
		return unavailableCoupling("not_a_supported_module")
	}
	incoming, outgoing := map[string]bool{}, map[string]bool{}
	for _, edge := range r.Edges {
		fromInside, toInside := inside[edge.From], inside[edge.To]
		if fromInside && !toInside {
			outgoing[edge.To] = true
		}
		if !fromInside && toInside {
			incoming[edge.From] = true
		}
	}
	ca, ce := len(incoming), len(outgoing)
	out := CouplingMetrics{Afferent: availableCount(ca), Efferent: availableCount(ce)}
	if ca+ce == 0 {
		out.Instability = unavailableDecimal("isolated_module")
	} else {
		out.Instability = availableDecimal(float64(ce) / float64(ca+ce))
	}
	return out
}

func (r CouplingReport) moduleDegrees() map[string][2]int {
	degrees := make(map[string][2]int, len(r.Modules))
	for _, edge := range r.Edges {
		from := degrees[edge.From]
		from[1]++
		degrees[edge.From] = from
		to := degrees[edge.To]
		to[0]++
		degrees[edge.To] = to
	}
	return degrees
}

func (r CouplingReport) MaxEfferent() (int, bool) {
	if !r.Complete || len(r.Modules) == 0 {
		return 0, false
	}
	max := 0
	for _, degree := range r.moduleDegrees() {
		if degree[1] > max {
			max = degree[1]
		}
	}
	return max, true
}

func (r CouplingReport) MaxInstability() (float64, bool) {
	if !r.Complete {
		return 0, false
	}
	max, ok := 0.0, false
	for _, degree := range r.moduleDegrees() {
		denominator := degree[0] + degree[1]
		if denominator == 0 {
			continue
		}
		value := float64(degree[1]) / float64(denominator)
		if !ok || value > max {
			max, ok = value, true
		}
	}
	return max, ok
}

func unavailableCoupling(reason string) CouplingMetrics {
	return CouplingMetrics{Afferent: unavailableCount(reason), Efferent: unavailableCount(reason), Instability: unavailableDecimal(reason)}
}

func availableCount(value int) CountMetric {
	return CountMetric{Availability: AvailabilityAvailable, Value: &value}
}
func unavailableCount(reason string) CountMetric {
	return CountMetric{Availability: AvailabilityUnavailable, Reason: reason}
}
func availableDecimal(value float64) DecimalMetric {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return unavailableDecimal("invalid_measurement")
	}
	return DecimalMetric{Availability: AvailabilityAvailable, Value: &value}
}
func unavailableDecimal(reason string) DecimalMetric {
	return DecimalMetric{Availability: AvailabilityUnavailable, Reason: reason}
}

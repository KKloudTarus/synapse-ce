package benchcore

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// ControlFixtureSchemaVersion names a control-suite fixture: inputs with hand-derived expected cells.
const ControlFixtureSchemaVersion = "synapse-benchmark-control-fixture-v1"

// The two control suites the core ships (#1640 WP D). Both run over the same fixture.
const (
	// ControlKnownOutcome checks that the scorer reproduces every expected cell.
	ControlKnownOutcome = "benchcore-known-outcome"
	// ControlIdentityInvariance checks that renaming the engine and reordering the observations and
	// truth units changes no cell.
	ControlIdentityInvariance = "benchcore-identity-invariance"
)

//go:embed controls/known-outcome-v1.json
var knownOutcomeFixture []byte

// ControlCase is one scenario with the cells its rules imply.
type ControlCase struct {
	Name          string        `json:"name"`
	Why           string        `json:"why"`
	Truth         TruthSet      `json:"truth"`
	Capabilities  []string      `json:"capabilities"`
	Observations  []Observation `json:"observations"`
	ExpectedCells []CellMetrics `json:"expected_cells"`
	ExpectError   bool          `json:"expect_error"`
}

// ControlFixture is a versioned set of control cases.
type ControlFixture struct {
	SchemaVersion string        `json:"schema_version"`
	ID            string        `json:"id"`
	Version       string        `json:"version"`
	Description   string        `json:"description"`
	Cases         []ControlCase `json:"cases"`
}

// KnownOutcomeFixture decodes the embedded fixture and returns it with its digest.
func KnownOutcomeFixture() (ControlFixture, string, error) {
	var f ControlFixture
	if err := benchmark.StrictDecode(bytes.NewReader(knownOutcomeFixture), &f); err != nil {
		return ControlFixture{}, "", fmt.Errorf("decode control fixture: %w", err)
	}
	if f.SchemaVersion != ControlFixtureSchemaVersion || f.ID == "" || f.Version == "" || len(f.Cases) == 0 {
		return ControlFixture{}, "", errors.New("control fixture is incomplete")
	}
	return f, benchmark.SHA256Digest(knownOutcomeFixture), nil
}

// DigestExpectedOutcomes is the identity of a fixture's expected outcomes alone, so a manifest can freeze
// what the scorer must reproduce separately from the inputs.
func DigestExpectedOutcomes(f ControlFixture) (string, error) {
	type outcome struct {
		Name          string        `json:"name"`
		ExpectedCells []CellMetrics `json:"expected_cells"`
		ExpectError   bool          `json:"expect_error"`
	}
	out := make([]outcome, 0, len(f.Cases))
	for _, c := range f.Cases {
		out = append(out, outcome{Name: c.Name, ExpectedCells: c.ExpectedCells, ExpectError: c.ExpectError})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	encoded, err := benchmark.CanonicalJSON(out)
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(encoded), nil
}

// ControlCaseOutcome records one case's result inside a control receipt.
type ControlCaseOutcome struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// ControlReceipt is the evidence a control suite ran: the fixture it ran over and each case's outcome.
type ControlReceipt struct {
	SuiteID       string               `json:"suite_id"`
	Version       string               `json:"version"`
	FixtureDigest string               `json:"fixture_digest"`
	Outcomes      []ControlCaseOutcome `json:"outcomes"`
}

// RunControlSuites runs every control suite the manifest declares against the embedded fixture and
// returns one result per suite. A suite whose frozen fixture or expected-outcome digest differs from the
// embedded fixture fails: the scorer may not be validated against controls the manifest did not freeze.
func RunControlSuites(m ClosureManifest) ([]ControlSuiteResult, []ControlReceipt, error) {
	fixture, fixtureDigest, err := KnownOutcomeFixture()
	if err != nil {
		return nil, nil, err
	}
	expectedDigest, err := DigestExpectedOutcomes(fixture)
	if err != nil {
		return nil, nil, err
	}
	var results []ControlSuiteResult
	var receipts []ControlReceipt
	for _, suite := range m.ControlSuites {
		receipt := ControlReceipt{SuiteID: suite.ID, Version: suite.Version, FixtureDigest: fixtureDigest}
		switch {
		case suite.FixtureDigest != fixtureDigest || suite.ExpectedOutcomeDigest != expectedDigest:
			receipt.Outcomes = []ControlCaseOutcome{{Name: "fixture", Detail: "the manifest froze another fixture or other expected outcomes"}}
		case suite.ID == ControlKnownOutcome && suite.Version == fixture.Version:
			receipt.Outcomes = knownOutcomes(fixture)
		case suite.ID == ControlIdentityInvariance && suite.Version == fixture.Version:
			receipt.Outcomes = invarianceOutcomes(fixture)
		default:
			receipt.Outcomes = []ControlCaseOutcome{{Name: "suite", Detail: "no runner for " + suite.ID + "@" + suite.Version}}
		}
		passed := len(receipt.Outcomes) > 0
		for _, o := range receipt.Outcomes {
			passed = passed && o.Passed
		}
		encoded, err := benchmark.CanonicalJSON(receipt)
		if err != nil {
			return nil, nil, err
		}
		results = append(results, ControlSuiteResult{ID: suite.ID, Version: suite.Version, Passed: passed, ReceiptDigest: benchmark.SHA256Digest(encoded)})
		receipts = append(receipts, receipt)
	}
	return results, receipts, nil
}

func knownOutcomes(f ControlFixture) []ControlCaseOutcome {
	out := make([]ControlCaseOutcome, 0, len(f.Cases))
	for _, c := range f.Cases {
		cells, err := Score(ScoringInput{Truth: c.Truth, Observations: c.Observations, Capabilities: c.Capabilities})
		switch {
		case c.ExpectError && err == nil:
			out = append(out, ControlCaseOutcome{Name: c.Name, Detail: "expected the scorer to refuse the input"})
		case c.ExpectError:
			out = append(out, ControlCaseOutcome{Name: c.Name, Passed: true})
		case err != nil:
			out = append(out, ControlCaseOutcome{Name: c.Name, Detail: err.Error()})
		case !reflect.DeepEqual(cells, c.ExpectedCells):
			out = append(out, ControlCaseOutcome{Name: c.Name, Detail: fmt.Sprintf("got %+v, want %+v", cells, c.ExpectedCells)})
		default:
			out = append(out, ControlCaseOutcome{Name: c.Name, Passed: true})
		}
	}
	return out
}

func invarianceOutcomes(f ControlFixture) []ControlCaseOutcome {
	out := make([]ControlCaseOutcome, 0, len(f.Cases))
	for _, c := range f.Cases {
		if c.ExpectError {
			continue
		}
		base, err := Score(ScoringInput{Truth: c.Truth, Observations: c.Observations, Capabilities: c.Capabilities})
		if err != nil {
			out = append(out, ControlCaseOutcome{Name: c.Name, Detail: err.Error()})
			continue
		}
		renamed := make([]Observation, len(c.Observations))
		for i, o := range c.Observations {
			o.Engine = EngineIdentity{EngineID: "renamed-engine", AdapterID: "renamed-adapter", AdapterVersion: "9", ScoredComponent: ScoredComponent{ID: "renamed", Provenance: "elsewhere"}}
			o.Findings = append([]Finding(nil), o.Findings...)
			for a, b := 0, len(o.Findings)-1; a < b; a, b = a+1, b-1 {
				o.Findings[a], o.Findings[b] = o.Findings[b], o.Findings[a]
			}
			renamed[len(c.Observations)-1-i] = o
		}
		truth := c.Truth
		truth.Units = append([]TruthUnit(nil), c.Truth.Units...)
		for a, b := 0, len(truth.Units)-1; a < b; a, b = a+1, b-1 {
			truth.Units[a], truth.Units[b] = truth.Units[b], truth.Units[a]
		}
		got, err := Score(ScoringInput{Truth: truth, Observations: renamed, Capabilities: c.Capabilities})
		if err != nil || !reflect.DeepEqual(base, got) {
			out = append(out, ControlCaseOutcome{Name: c.Name, Detail: "engine identity or order changed the cells"})
			continue
		}
		out = append(out, ControlCaseOutcome{Name: c.Name, Passed: true})
	}
	return out
}

package scabridge

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchcore"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const profileID = "sca.component-advisory.v1"

func corpus(t *testing.T) (scabench.Catalog, scabench.Oracle) {
	t.Helper()
	open := func(name string) *os.File {
		f, err := os.Open("../../scabench/corpus/" + name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	catalog, err := scabench.DecodeCatalog(open("catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := scabench.DecodeOracle(open("oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	return catalog, oracle
}

func legacyObservation(t *testing.T, catalog scabench.Catalog, engine scabench.Engine, target scabench.Target, state scabench.ObservationState, findings []scabench.Finding) scabench.Observation {
	t.Helper()
	digest, err := scabench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	hex := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	return scabench.Observation{
		SchemaVersion: scabench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: digest,
		Engine: engine, EngineVersion: string(engine) + "-v1", EngineBinaryDigest: hex("c"),
		DatabaseBuild: "database-2026-11-01", DatabaseDigest: hex("d"), EnvironmentID: "linux-amd64", EnvironmentDigest: hex("e"),
		TargetID: target.ID, TargetDigest: target.Digest, SBOMDigest: target.SBOMDigest, State: state,
		RawOutputDigest: hex("f"), ConfigDigest: hex("1"), Findings: findings,
	}
}

// withAlias returns the committed oracle with one alias added to its first affected case, since the
// committed oracle has none and the alias path must be exercised.
func withAlias(oracle scabench.Oracle) (scabench.Oracle, string) {
	out := oracle
	out.Cases = append([]scabench.OracleCase(nil), oracle.Cases...)
	for i, c := range out.Cases {
		if c.Truth == scabench.TruthAffected {
			out.Cases[i].Aliases = []string{"DSA-9999-1"}
			return out, c.ID
		}
	}
	return out, ""
}

// scenario builds legacy observations that exercise every path the bridge must carry:
//   - owned reports every affected relation (the aliased one under its alias, in lower case, which the
//     legacy key treats as another advisory), one fixed relation per target, a relation outside the
//     oracle twice, and a finding with an invalid purl;
//   - grype reports every other affected relation and its first target is incomplete;
//   - osv-scanner reports the Debian target only; its RPM targets are unsupported by declaration;
//   - trivy has no observation at all.
func scenario(t *testing.T, catalog scabench.Catalog, oracle scabench.Oracle, aliasCase string) []scabench.Observation {
	t.Helper()
	byTarget := map[string][]scabench.OracleCase{}
	for _, c := range oracle.Cases {
		byTarget[c.TargetID] = append(byTarget[c.TargetID], c)
	}
	var out []scabench.Observation
	for ti, target := range catalog.Targets {
		var owned, grype, osv []scabench.Finding
		fixedReported := false
		for i, c := range byTarget[target.ID] {
			switch c.Truth {
			case scabench.TruthAffected:
				advisory := c.AdvisoryID
				if c.ID == aliasCase {
					advisory = "dsa-9999-1"
				}
				owned = append(owned, scabench.Finding{Component: c.Component, AdvisoryID: advisory})
				if i%2 == 1 {
					grype = append(grype, scabench.Finding{Component: c.Component, AdvisoryID: c.AdvisoryID})
				}
				osv = append(osv, scabench.Finding{Component: c.Component, AdvisoryID: c.AdvisoryID})
			default:
				if !fixedReported {
					owned = append(owned, scabench.Finding{Component: c.Component, AdvisoryID: c.AdvisoryID})
					fixedReported = true
				}
			}
		}
		if len(byTarget[target.ID]) > 0 {
			extra := byTarget[target.ID][0].Component
			owned = append(owned,
				scabench.Finding{Component: extra, AdvisoryID: "CVE-2099-0001"},
				scabench.Finding{Component: extra, AdvisoryID: "CVE-2099-0001"},
				scabench.Finding{Component: scabench.Component{PURL: "not-a-purl"}, AdvisoryID: "CVE-2099-0002"})
		}
		out = append(out, legacyObservation(t, catalog, scabench.EngineOwned, target, scabench.ObservationComplete, owned))
		state := scabench.ObservationComplete
		if ti == 0 {
			state = scabench.ObservationIncomplete
		}
		out = append(out, legacyObservation(t, catalog, scabench.EngineGrype, target, state, grype))
		if strings.HasPrefix(target.ID, "debian") {
			out = append(out, legacyObservation(t, catalog, scabench.EngineOSVScanner, target, scabench.ObservationComplete, osv))
		}
	}
	return out
}

// TestBridgeReproducesLegacyCells: for every legacy engine, the neutral core reproduces every count the
// legacy reduction reports, through one scoring path that never sees engine identity. The legacy
// reduction folds three core states into its own: a covered case with no observation is legacy
// incomplete and core abstained; an unmatched finding is legacy unknown and core unadjudicated (or
// unmapped, when its purl cannot be normalized).
func TestBridgeReproducesLegacyCells(t *testing.T) {
	catalog, committed := corpus(t)
	oracle, aliasCase := withAlias(committed)
	if aliasCase == "" {
		t.Fatal("the corpus has no affected case to alias")
	}
	legacyObs := scenario(t, catalog, oracle, aliasCase)
	legacy, err := scabench.Reduce(catalog, oracle, legacyObs)
	if err != nil {
		t.Fatal(err)
	}
	truth, err := Truth(profileID, "oracle@"+catalog.Revision, catalog, oracle)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := Capabilities(oracle)
	if err != nil {
		t.Fatal(err)
	}
	for _, engine := range scabench.Engines() {
		var neutral []benchcore.Observation
		unmapped := 0
		for _, o := range legacyObs {
			if o.Engine != engine {
				continue
			}
			n, err := Observation(profileID, o, capabilities[engine])
			if err != nil {
				t.Fatal(err)
			}
			if n.State == benchcore.StateComplete {
				unmapped += len(n.Unmapped)
			}
			neutral = append(neutral, n)
		}
		cells, err := benchcore.Score(benchcore.ScoringInput{Truth: truth, Observations: neutral, Capabilities: capabilities[engine]})
		if err != nil {
			t.Fatal(err)
		}
		var got benchcore.Counts
		for _, c := range cells {
			e := c.EndToEnd
			got.TruePositives += e.TruePositives
			got.FalsePositives += e.FalsePositives
			got.FalseNegatives += e.FalseNegatives
			got.Unknown += e.Unknown + e.UnadjudicatedFindings
			got.Unsupported += e.Unsupported
			got.Incomplete += e.Incomplete + e.Abstained
		}
		got.Unknown += unmapped
		var want scabench.EngineResult
		for _, r := range legacy.Engines {
			if r.Engine == engine {
				want = r
			}
		}
		if got.TruePositives != want.TruePositives || got.FalsePositives != want.FalsePositives || got.FalseNegatives != want.FalseNegatives ||
			got.Unknown != want.Unknown || got.Unsupported != want.Unsupported || got.Incomplete != want.Incomplete {
			t.Fatalf("%s: core TP=%d FP=%d FN=%d unknown=%d unsupported=%d incomplete=%d; legacy TP=%d FP=%d FN=%d unknown=%d unsupported=%d incomplete=%d",
				engine, got.TruePositives, got.FalsePositives, got.FalseNegatives, got.Unknown, got.Unsupported, got.Incomplete,
				want.TruePositives, want.FalsePositives, want.FalseNegatives, want.Unknown, want.Unsupported, want.Incomplete)
		}
	}
	owned := map[scabench.Engine]scabench.EngineResult{}
	for _, r := range legacy.Engines {
		owned[r.Engine] = r
	}
	if owned[scabench.EngineOwned].TruePositives == 0 || owned[scabench.EngineGrype].Incomplete == 0 || owned[scabench.EngineOSVScanner].Unsupported == 0 || owned[scabench.EngineTrivy].Incomplete == 0 {
		t.Fatalf("the scenario must exercise true positives, incomplete, unsupported and missing observations: %+v", legacy.Engines)
	}
}

// TestBridgeAndLegacyBothRefuseADuplicateObservation: two observations of one target by one engine are
// refused by the legacy reduction and by the core.
func TestBridgeAndLegacyBothRefuseADuplicateObservation(t *testing.T) {
	catalog, oracle := corpus(t)
	target := catalog.Targets[0]
	o := legacyObservation(t, catalog, scabench.EngineOwned, target, scabench.ObservationComplete, nil)
	if _, err := scabench.Reduce(catalog, oracle, []scabench.Observation{o, o}); err == nil {
		t.Fatal("legacy accepted a duplicate observation")
	}
	truth, err := Truth(profileID, "v", catalog, oracle)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Observation(profileID, o, []string{"component-advisory/deb"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := benchcore.Score(benchcore.ScoringInput{Truth: truth, Observations: []benchcore.Observation{n, n}}); !errors.Is(err, benchcore.ErrScoring) {
		t.Fatalf("core accepted a duplicate observation: %v", err)
	}
}

// TestBridgeCapabilitiesFollowExpectedCoverage: osv-scanner is expected unsupported on the RPM targets, so
// its capability list holds only the Debian kind; the others cover both.
func TestBridgeCapabilitiesFollowExpectedCoverage(t *testing.T) {
	_, oracle := corpus(t)
	capabilities, err := Capabilities(oracle)
	if err != nil {
		t.Fatal(err)
	}
	if got := capabilities[scabench.EngineOSVScanner]; !reflect.DeepEqual(got, []string{"component-advisory/deb"}) {
		t.Fatalf("osv-scanner capabilities = %v", got)
	}
	if got := capabilities[scabench.EngineOwned]; !reflect.DeepEqual(got, []string{"component-advisory/deb", "component-advisory/rpm"}) {
		t.Fatalf("owned capabilities = %v", got)
	}
	mixed := oracle
	mixed.Cases = append([]scabench.OracleCase(nil), oracle.Cases...)
	for i, c := range mixed.Cases {
		if strings.HasPrefix(c.Component.PURL, "pkg:deb/") {
			coverage := map[scabench.Engine]scabench.Coverage{}
			for k, v := range c.ExpectedCoverage {
				coverage[k] = v
			}
			coverage[scabench.EngineTrivy] = scabench.CoverageUnsupported
			mixed.Cases[i].ExpectedCoverage = coverage
			break
		}
	}
	if _, err := Capabilities(mixed); err == nil {
		t.Fatal("coverage that differs within one unit kind must be refused")
	}
}

// TestBridgeObservationSeesNoOracle: the observation converter's signature takes no oracle, and the same
// legacy observation converts to the same neutral observation whatever the truth says.
func TestBridgeObservationSeesNoOracle(t *testing.T) {
	typ := reflect.TypeOf(Observation)
	for i := 0; i < typ.NumIn(); i++ {
		if in := typ.In(i); in == reflect.TypeOf(scabench.Oracle{}) || in == reflect.TypeOf(benchcore.TruthSet{}) {
			t.Fatalf("Observation takes %s", in)
		}
	}
	catalog, oracle := corpus(t)
	o := scenario(t, catalog, oracle, "")[0]
	a, err := Observation(profileID, o, []string{"component-advisory/deb"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Observation(profileID, o, []string{"component-advisory/deb"})
	if err != nil {
		t.Fatal(err)
	}
	da, _ := benchcore.DigestObservations([]benchcore.Observation{a})
	db, _ := benchcore.DigestObservations([]benchcore.Observation{b})
	if da != db {
		t.Fatal("conversion is not deterministic")
	}
}

package scabench

import (
	"strings"
	"testing"
)

func TestValidateRequiresAllEngineCoverageAndCataloguedComponent(t *testing.T) {
	t.Run("coverage includes exactly every engine", func(t *testing.T) {
		catalog := validCatalog()
		oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
		delete(oracle.Cases[0].ExpectedCoverage, EngineTrivy)
		if err := Validate(catalog, oracle); err == nil {
			t.Fatal("oracle missing expected engine coverage was accepted")
		}
	})
	t.Run("case component must belong to its target", func(t *testing.T) {
		catalog := validCatalog()
		oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
		oracle.Cases[0].Component = Component{PURL: "pkg:npm/not-catalogued@1.2.3"}
		if err := Validate(catalog, oracle); err == nil {
			t.Fatal("oracle component outside target inventory was accepted")
		}
	})
	t.Run("non-CVE identifiers retain their spelling", func(t *testing.T) {
		catalog := validCatalog()
		oracle := validOracle(
			validCase("upper", "GO-2024-0001", TruthAffected),
			validCase("lower", "go-2024-0001", TruthAffected),
		)
		if err := Validate(catalog, oracle); err != nil {
			t.Fatalf("non-CVE identifier spelling must not be folded: %v", err)
		}
	})
}

func TestReduceScopesKnownAdvisoryFindingsToTarget(t *testing.T) {
	catalog := validCatalog()
	second := catalog.Targets[0]
	second.ID = "second"
	catalog.Targets = append(catalog.Targets, second)
	oracle := validOracle(
		validCase("first", "CVE-2024-1111", TruthAffected),
		validCase("second", "CVE-2024-2222", TruthAffected),
	)
	oracle.Cases[1].TargetID = "second"
	result, err := Reduce(catalog, oracle, []Observation{
		withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111"),
		withFinding(completeObservationForTarget(catalog, EngineOwned, "second"), "CVE-2024-1111"),
	})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.TruePositives != 1 || owned.FalseNegatives != 1 || owned.Unknown != 1 {
		t.Fatalf("target-scoped matching = %+v", owned)
	}
}

func TestReduceUnsupportedFindingIdentityIsUnknownNotFalsePositive(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	observation := completeObservation(catalog, EngineOwned)
	observation.Findings = []Finding{{
		Component:  Component{PURL: "not-a-purl", Version: "1.2.3"},
		AdvisoryID: "CVE-2024-1111",
	}}
	result, err := Reduce(catalog, oracle, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.Unknown != 1 || owned.FalsePositives != 0 || owned.FalseNegatives != 1 {
		t.Fatalf("unsupported finding identity must remain unknown: %+v", owned)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != DiagnosticInvalidFinding {
		t.Fatalf("diagnostics = %+v", result.Diagnostics)
	}
}

func TestReduceNotAffectedFindingIsFalsePositive(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("not-affected", "CVE-2024-1111", TruthNotAffected))
	oracle.Cases = append(oracle.Cases, validCase("affected", "CVE-2024-2222", TruthAffected))
	oracle.Cases[1].ExpectedCoverage = expectedCoverage(CoverageUnsupported)
	result, err := Reduce(catalog, oracle, []Observation{
		withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111"),
	})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.FalsePositives != 1 || owned.TruePositives != 0 || owned.FalseNegatives != 0 {
		t.Fatalf("not-affected finding must be an FP: %+v", owned)
	}
}

func TestDecodeCatalogRejectsDeepDuplicateAndBoundedInput(t *testing.T) {
	valid := `{"schema_version":"synapse-sca-benchmark-catalog-v1","revision":"r1","targets":[{"id":"image","oci_ref":"registry.example/repo@sha256:` + hexDigest('a') + `","digest":"sha256:` + hexDigest('a') + `","components":[{"purl":"pkg:npm/example@1.2.3"}]}]}`
	deepDuplicate := strings.Replace(valid, `"purl":"pkg:npm/example@1.2.3"`, `"purl":"pkg:npm/example@1.2.3","purl":"pkg:npm/other@1.2.3"`, 1)
	if _, err := DecodeCatalog(strings.NewReader(deepDuplicate)); err == nil {
		t.Fatal("deep duplicate JSON key was accepted")
	}
	if _, err := DecodeCatalog(strings.NewReader(strings.Repeat(" ", int(MaxJSONBytes)+1))); err == nil {
		t.Fatal("oversized JSON input was accepted")
	}
}

func TestReduceCarriesRunReproducibilityIdentity(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	observation := withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")
	observation.EngineVersion = "owned-v1"
	observation.DatabaseBuild = "db-2026-09-13"
	observation.DatabaseDigest = "sha256:" + hexDigest('c')
	observation.EnvironmentID = "linux-amd64"
	result, err := Reduce(catalog, oracle, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Targets) != 1 || result.Targets[0].Digest != catalog.Targets[0].Digest || len(result.Runs) != 1 {
		t.Fatalf("result did not retain target/run identity: %+v", result)
	}
	run := result.Runs[0]
	if run.EngineVersion != observation.EngineVersion || run.DatabaseBuild != observation.DatabaseBuild || run.DatabaseDigest != observation.DatabaseDigest || run.EnvironmentID != observation.EnvironmentID {
		t.Fatalf("run identity = %+v", run)
	}
	if result.ScoringObservationDigest == "" {
		t.Fatal("result has no scoring observation digest")
	}
}

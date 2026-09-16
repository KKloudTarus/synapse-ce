package scabench

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestReduceScoresTruthsAliasesAndDuplicateFindings(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(
		validCase("affected", "CVE-2024-1111", TruthAffected),
		validCase("fixed", "CVE-2024-2222", TruthFixed),
		validCase("withdrawn", "CVE-2024-3333", TruthWithdrawn),
	)
	oracle.Cases[0].Aliases = []string{"GHSA-abcd-efgh-ijkl"}

	observation := completeObservation(catalog, EngineOwned)
	observation.Findings = []Finding{
		{Component: catalog.Targets[0].Components[0], AdvisoryID: "GHSA-abcd-efgh-ijkl"},
		{Component: catalog.Targets[0].Components[0], AdvisoryID: "GHSA-abcd-efgh-ijkl"},
		{Component: catalog.Targets[0].Components[0], AdvisoryID: "CVE-2024-2222"},
		{Component: catalog.Targets[0].Components[0], AdvisoryID: "CVE-2024-3333"},
	}
	result, err := Reduce(catalog, oracle, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}

	owned := engineResult(t, result, EngineOwned)
	if owned.Covered != 3 || owned.TruePositives != 1 || owned.FalsePositives != 2 || owned.FalseNegatives != 0 {
		t.Fatalf("owned counts = %+v", owned)
	}
	if !owned.MetricsComplete || owned.Precision == nil || *owned.Precision != 1.0/3.0 || owned.Recall == nil || *owned.Recall != 1 {
		t.Fatalf("owned metrics = %+v", owned)
	}
}

func TestReduceMissedAffectedIsFalseNegative(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	result, err := Reduce(catalog, oracle, []Observation{completeObservation(catalog, EngineOwned)})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.TruePositives != 0 || owned.FalseNegatives != 1 || owned.FalsePositives != 0 {
		t.Fatalf("owned counts = %+v", owned)
	}
}

func TestReduceUnknownIncompleteUnsupportedAndUnreviewedFindingsDoNotScore(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))

	tests := []struct {
		name  string
		state ObservationState
		check func(t *testing.T, summary EngineResult)
	}{
		{
			name:  "unknown",
			state: ObservationUnknown,
			check: func(t *testing.T, summary EngineResult) {
				t.Helper()
				if summary.Unknown != 1 || summary.TruePositives != 0 || summary.FalseNegatives != 0 {
					t.Fatalf("unknown summary = %+v", summary)
				}
			},
		},
		{
			name:  "incomplete",
			state: ObservationIncomplete,
			check: func(t *testing.T, summary EngineResult) {
				t.Helper()
				if summary.Incomplete != 1 || summary.TruePositives != 0 || summary.FalseNegatives != 0 {
					t.Fatalf("incomplete summary = %+v", summary)
				}
			},
		},
		{
			name:  "unsupported",
			state: ObservationUnsupported,
			check: func(t *testing.T, summary EngineResult) {
				t.Helper()
				if summary.Unsupported != 1 || summary.TruePositives != 0 || summary.FalseNegatives != 0 {
					t.Fatalf("unsupported summary = %+v", summary)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := completeObservation(catalog, EngineOwned)
			observation.State = test.state
			if observation.State == ObservationUnsupported {
				observation.CapabilityKind = CapabilityKindOSVScannerSUSERPM
				observation.CapabilityDigest = "sha256:" + hexDigest('8')
			}
			result, err := Reduce(catalog, oracle, []Observation{observation})
			if err != nil {
				t.Fatal(err)
			}
			test.check(t, engineResult(t, result, EngineOwned))
		})
	}

	observation := completeObservation(catalog, EngineOwned)
	observation.Findings = []Finding{{Component: catalog.Targets[0].Components[0], AdvisoryID: "UNREVIEWED-42"}}
	result, err := Reduce(catalog, oracle, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.Unknown != 1 || owned.FalsePositives != 0 || owned.FalseNegatives != 1 {
		t.Fatalf("unreviewed output must be unknown, not FP: %+v", owned)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != DiagnosticUnreviewedFinding {
		t.Fatalf("diagnostics = %+v", result.Diagnostics)
	}
}

func TestReducePreservesUnreviewedFindingPairDiagnostics(t *testing.T) {
	catalog := validCatalog()
	catalog.Targets[0].Components = append(catalog.Targets[0].Components, Component{PURL: "pkg:npm/other@4.5.6"})
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	observation := completeObservation(catalog, EngineOwned)
	observation.Findings = []Finding{
		{Component: catalog.Targets[0].Components[0], AdvisoryID: "UNREVIEWED-42"},
		{Component: catalog.Targets[0].Components[1], AdvisoryID: "UNREVIEWED-42"},
	}
	result, err := Reduce(catalog, oracle, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	if owned := engineResult(t, result, EngineOwned); owned.Unknown != 2 {
		t.Fatalf("unreviewed finding debt = %d, want 2", owned.Unknown)
	}
	if len(result.Diagnostics) != 2 {
		t.Fatalf("unreviewed pair diagnostics collapsed: %+v", result.Diagnostics)
	}
	wantDetails := []string{
		`scanner finding is not in the reviewed oracle: ecosystem="npm" package="example" version="1.2.3" advisory="UNREVIEWED-42"`,
		`scanner finding is not in the reviewed oracle: ecosystem="npm" package="other" version="4.5.6" advisory="UNREVIEWED-42"`,
	}
	for i, diagnostic := range result.Diagnostics {
		if diagnostic.Code != DiagnosticUnreviewedFinding || diagnostic.Detail != wantDetails[i] {
			t.Fatalf("diagnostic %d = %+v, want detail %q", i, diagnostic, wantDetails[i])
		}
	}
}

func TestReduceZeroDenominatorsEncodeNullMetrics(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("not-affected", "CVE-2024-1111", TruthNotAffected))
	oracle.Cases = append(oracle.Cases, validCase("affected", "CVE-2024-2222", TruthAffected))
	oracle.Cases[1].ExpectedCoverage = expectedCoverage(CoverageUnsupported)

	result, err := Reduce(catalog, oracle, []Observation{completeObservation(catalog, EngineOwned)})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.Precision != nil || owned.Recall != nil {
		t.Fatalf("undefined metrics must be nil: %+v", owned)
	}
	var encoded bytes.Buffer
	if err := EncodeResult(&encoded, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encoded.String(), `"precision":null`) || !strings.Contains(encoded.String(), `"recall":null`) {
		t.Fatalf("undefined metrics must encode as null: %s", encoded.String())
	}
}

func TestNormalizeComponentUsesStructuralIdentityNotRawPURLFingerprint(t *testing.T) {
	first, err := BenchmarkKey(Component{PURL: "pkg:npm/example@1.2.3?repository_url=https://one.example"}, "CVE-2024-1111")
	if err != nil {
		t.Fatal(err)
	}
	second, err := BenchmarkKey(Component{PURL: "pkg:npm/example@1.2.3?repository_url=https://two.example"}, "CVE-2024-1111")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.Ecosystem != "npm" || first.Package != "example" || first.Version != "1.2.3" {
		t.Fatalf("structural keys differ: first=%+v second=%+v", first, second)
	}
	for _, component := range []Component{
		{PURL: "not-a-purl", Version: "1.0.0"},
		{PURL: "pkg:npm/example@1.2.3", Version: "9.9.9"},
	} {
		if _, err := BenchmarkKey(component, "CVE-2024-1111"); err == nil {
			t.Fatalf("BenchmarkKey(%+v) accepted unsupported or ambiguous identity", component)
		}
	}
}

func TestValidateRejectsControlCharacterPURLCollisions(t *testing.T) {
	catalog := validCatalog()
	catalog.Targets[0].Components = []Component{{PURL: "pkg:npm/a%00b@c"}}
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	oracle.Cases[0].Component = Component{PURL: "pkg:npm/a@b%00c"}
	if err := Validate(catalog, oracle); err == nil {
		t.Fatal("oracle component with a decoded control-character collision was accepted")
	}
}

func TestOracleValidationRejectsInvalidEvidence(t *testing.T) {
	catalog := validCatalog()
	tests := []struct {
		name string
		edit func(*Catalog, *Oracle)
	}{
		{
			name: "empty oracle",
			edit: func(_ *Catalog, oracle *Oracle) { oracle.Cases = nil },
		},
		{
			name: "vacuous oracle has no affected truth",
			edit: func(_ *Catalog, oracle *Oracle) { oracle.Cases[0].Truth = TruthNotAffected },
		},
		{
			name: "bad digest",
			edit: func(catalog *Catalog, _ *Oracle) { catalog.Targets[0].Digest = "sha256:nope" },
		},
		{
			name: "mutable oci ref",
			edit: func(catalog *Catalog, _ *Oracle) { catalog.Targets[0].OCIRef = "registry.example/repo:latest" },
		},
		{
			name: "citation must have immutable digest",
			edit: func(_ *Catalog, oracle *Oracle) { oracle.Cases[0].Citations[0].Digest = "sha256:not-a-hash" },
		},
		{
			name: "overlapping aliases",
			edit: func(_ *Catalog, oracle *Oracle) {
				oracle.Cases = append(oracle.Cases, validCase("other", "CVE-2024-2222", TruthAffected))
				oracle.Cases[1].Aliases = []string{oracle.Cases[0].AdvisoryID}
			},
		},
		{
			name: "synthetic case without classification",
			edit: func(_ *Catalog, oracle *Oracle) {
				oracle.Cases[0].ID = "synthetic-fixture-1"
				oracle.Cases[0].Classification = ""
			},
		},
		{
			name: "reviewer overlap",
			edit: func(_ *Catalog, oracle *Oracle) { oracle.Cases[0].ReviewerIDs = []string{"labeler"} },
		},
		{
			name: "competitor citation",
			edit: func(_ *Catalog, oracle *Oracle) {
				oracle.Cases[0].Citations[0].Reference = "https://github.com/anchore/grype/issues/1"
			},
		},
		{
			name: "credential bearing citation",
			edit: func(_ *Catalog, oracle *Oracle) {
				oracle.Cases[0].Citations[0].Reference = "https://user:secret@evidence.example/case"
			},
		},
		{
			name: "noncanonical cve",
			edit: func(_ *Catalog, oracle *Oracle) { oracle.Cases[0].AdvisoryID = "cve-2024-1111" },
		},
		{
			name: "noncanonical ghsa",
			edit: func(_ *Catalog, oracle *Oracle) { oracle.Cases[0].Aliases = []string{"GHSA-ABCD-EFGH-IJKL"} },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateCatalog := validCatalog()
			candidateOracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
			test.edit(&candidateCatalog, &candidateOracle)
			if err := Validate(candidateCatalog, candidateOracle); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if err := Validate(catalog, validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))); err != nil {
		t.Fatalf("valid oracle rejected: %v", err)
	}
}

func TestDecodeCatalogRejectsDuplicateCaseVariantUnknownAndExtraValues(t *testing.T) {
	valid := `{"schema_version":"synapse-sca-benchmark-catalog-v1","revision":"r1","targets":[{"id":"image","oci_ref":"registry.example/repo@sha256:` + hexDigest('a') + `","digest":"sha256:` + hexDigest('a') + `","components":[{"purl":"pkg:npm/example@1.2.3"}]}]}`
	tests := []struct {
		name string
		body string
	}{
		{name: "duplicate root key", body: strings.Replace(valid, `"revision":"r1"`, `"revision":"r1","revision":"r2"`, 1)},
		{name: "duplicate nested key", body: strings.Replace(valid, `"id":"image"`, `"id":"image","id":"other"`, 1)},
		{name: "case variant field", body: strings.Replace(valid, `"schema_version"`, `"Schema_Version"`, 1)},
		{name: "unknown field", body: strings.Replace(valid, `"revision":"r1"`, `"revision":"r1","unknown":true`, 1)},
		{name: "multiple values", body: valid + ` {}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeCatalog(strings.NewReader(test.body)); err == nil {
				t.Fatal("expected strict decoding error")
			}
		})
	}

	invalidSchema := strings.Replace(valid, CatalogSchemaVersion, "v0", 1)
	if _, err := DecodeCatalog(strings.NewReader(invalidSchema)); err == nil {
		t.Fatal("unsupported schema was accepted")
	}
}

func TestReduceIsDeterministicAcrossInputOrder(t *testing.T) {
	catalog := validCatalog()
	secondTarget := catalog.Targets[0]
	secondTarget.ID = "second"
	catalog.Targets = append(catalog.Targets, secondTarget)
	oracle := validOracle(
		validCase("one", "CVE-2024-1111", TruthAffected),
		validCase("two", "CVE-2024-2222", TruthAffected),
	)
	oracle.Cases[1].TargetID = "second"
	first := []Observation{
		withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111"),
		withFinding(completeObservationForTarget(catalog, EngineGrype, "second"), "CVE-2024-2222"),
	}
	second := []Observation{first[1], first[0]}
	firstResult, err := Reduce(catalog, oracle, first)
	if err != nil {
		t.Fatal(err)
	}
	secondResult, err := Reduce(catalog, oracle, second)
	if err != nil {
		t.Fatal(err)
	}
	var firstJSON, secondJSON bytes.Buffer
	if err := EncodeResult(&firstJSON, firstResult); err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&secondJSON, secondResult); err != nil {
		t.Fatal(err)
	}
	if firstResult.ID != secondResult.ID || firstJSON.String() != secondJSON.String() {
		t.Fatalf("observation order changed deterministic result:\n%s\n---\n%s", firstJSON.String(), secondJSON.String())
	}

	reorderedCatalog := catalog
	reorderedCatalog.Targets = []Target{catalog.Targets[1], catalog.Targets[0]}
	reorderedOracle := oracle
	reorderedOracle.Cases = []OracleCase{oracle.Cases[1], oracle.Cases[0]}
	reorderedResult, err := Reduce(reorderedCatalog, reorderedOracle, second)
	if err != nil {
		t.Fatal(err)
	}
	var reorderedJSON bytes.Buffer
	if err := EncodeResult(&reorderedJSON, reorderedResult); err != nil {
		t.Fatal(err)
	}
	if firstResult.ID != reorderedResult.ID || firstJSON.String() != reorderedJSON.String() {
		t.Fatalf("catalog or oracle order changed deterministic result:\n%s\n---\n%s", firstJSON.String(), reorderedJSON.String())
	}
}

func TestReduceLeavesMetricsNullForPartialExpectedCoverage(t *testing.T) {
	catalog := validCatalog()
	secondTarget := catalog.Targets[0]
	secondTarget.ID = "second"
	catalog.Targets = append(catalog.Targets, secondTarget)
	oracle := validOracle(
		validCase("first", "CVE-2024-1111", TruthAffected),
		validCase("second", "CVE-2024-2222", TruthAffected),
	)
	oracle.Cases[1].TargetID = "second"

	first := withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")
	second := completeObservationForTarget(catalog, EngineOwned, "second")
	second.State = ObservationUnknown
	result, err := Reduce(catalog, oracle, []Observation{first, second})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.Covered != 1 || owned.Unknown != 1 || owned.TruePositives != 1 || owned.FalseNegatives != 0 {
		t.Fatalf("partial expected coverage counts = %+v", owned)
	}
	if owned.Precision != nil || owned.Recall != nil {
		t.Fatalf("partial expected coverage must not produce clean metrics: %+v", owned)
	}
}

func TestReduceKeepsCoveredMetricsAvailableWithExplicitNonCoveredEvidence(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(
		validCase("covered", "CVE-2024-1111", TruthAffected),
		validCase("unknown", "CVE-2024-2222", TruthAffected),
		validCase("unsupported", "CVE-2024-3333", TruthAffected),
		validCase("incomplete", "CVE-2024-4444", TruthAffected),
	)
	oracle.Cases[1].ExpectedCoverage = expectedCoverage(CoverageUnknown)
	oracle.Cases[2].ExpectedCoverage = expectedCoverage(CoverageUnsupported)
	oracle.Cases[3].ExpectedCoverage = expectedCoverage(CoverageIncomplete)
	observation := withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")
	observation.Findings = append(observation.Findings, Finding{Component: catalog.Targets[0].Components[0], AdvisoryID: "UNREVIEWED-42"})
	result, err := Reduce(catalog, oracle, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.Unknown != 2 || owned.Unsupported != 1 || owned.Incomplete != 1 || !owned.MetricsComplete || owned.Precision == nil || owned.Recall == nil || *owned.Precision != 1 || *owned.Recall != 1 {
		t.Fatalf("explicit non-covered evidence must remain visible while covered-only metrics stay available: %+v", owned)
	}
}

func TestValidateAllowsAdvisoryClosureAcrossComponentVersions(t *testing.T) {
	catalog := validCatalog()
	catalog.Targets[0].Components = []Component{
		{PURL: "pkg:npm/example@1.2.3"},
		{PURL: "pkg:npm/example@2.0.0"},
	}
	oracle := validOracle(
		validCase("affected", "CVE-2024-1111", TruthAffected),
		validCase("fixed", "CVE-2024-1111", TruthFixed),
	)
	oracle.Cases[0].Aliases = []string{"GHSA-abcd-efgh-ijkl"}
	oracle.Cases[1].Component = catalog.Targets[0].Components[1]
	oracle.Cases[1].Aliases = []string{"GHSA-abcd-efgh-ijkl"}
	if err := Validate(catalog, oracle); err != nil {
		t.Fatalf("same advisory closure across component versions was rejected: %v", err)
	}

	observation := completeObservation(catalog, EngineOwned)
	observation.Findings = []Finding{
		{Component: catalog.Targets[0].Components[0], AdvisoryID: "GHSA-abcd-efgh-ijkl"},
		{Component: catalog.Targets[0].Components[1], AdvisoryID: "GHSA-abcd-efgh-ijkl"},
	}
	result, err := Reduce(catalog, oracle, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.TruePositives != 1 || owned.FalsePositives != 1 || owned.FalseNegatives != 0 {
		t.Fatalf("cross-version advisory matching = %+v", owned)
	}
}

func TestBenchmarkKeyAcceptsNeutralPURLTypes(t *testing.T) {
	tests := []struct {
		component Component
		ecosystem string
		pkg       string
		version   string
	}{
		{Component{PURL: "pkg:composer/vendor/package@1.2.3"}, "composer", "vendor/package", "1.2.3"},
		{Component{PURL: "pkg:hex/httpotion@3.1.0"}, "hex", "httpotion", "3.1.0"},
		{Component{PURL: "pkg:pub/http@1.0.0"}, "pub", "http", "1.0.0"},
		{Component{PURL: "pkg:rpm/fedora/curl@8.0.0"}, "rpm", "fedora/curl", "8.0.0"},
	}
	for _, test := range tests {
		t.Run(test.component.PURL, func(t *testing.T) {
			key, err := BenchmarkKey(test.component, "CVE-2024-1111")
			if err != nil {
				t.Fatal(err)
			}
			if key.Ecosystem != test.ecosystem || key.Package != test.pkg || key.Version != test.version {
				t.Fatalf("neutral identity = %+v", key)
			}
			catalog := validCatalog()
			catalog.Targets[0].Components = []Component{test.component}
			if err := catalog.Validate(); err != nil {
				t.Fatalf("neutral component cannot be catalogued: %v", err)
			}
		})
	}
}

func TestObservationValidationRequiresReproducibilityIdentity(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	for _, field := range []string{"CatalogDigest", "EngineVersion", "EngineBinaryDigest", "DatabaseBuild", "DatabaseDigest", "EnvironmentID", "EnvironmentDigest", "SBOMDigest", "RawOutputDigest", "ConfigDigest"} {
		t.Run(field, func(t *testing.T) {
			observation := completeObservation(catalog, EngineOwned)
			switch field {
			case "CatalogDigest":
				observation.CatalogDigest = ""
			case "EngineVersion":
				observation.EngineVersion = ""
			case "EngineBinaryDigest":
				observation.EngineBinaryDigest = ""
			case "DatabaseBuild":
				observation.DatabaseBuild = ""
			case "DatabaseDigest":
				observation.DatabaseDigest = ""
			case "EnvironmentID":
				observation.EnvironmentID = ""
			case "EnvironmentDigest":
				observation.EnvironmentDigest = ""
			case "SBOMDigest":
				observation.SBOMDigest = ""
			case "RawOutputDigest":
				observation.RawOutputDigest = ""
			case "ConfigDigest":
				observation.ConfigDigest = ""
			}
			if _, err := Reduce(catalog, oracle, []Observation{observation}); err == nil {
				t.Fatal("score-bearing observation without reproducibility identity was accepted")
			}
			set := ObservationSet{
				SchemaVersion:   ObservationSchemaVersion,
				CatalogRevision: catalog.Revision,
				CatalogDigest:   mustDigestCatalog(catalog),
				Observations:    []Observation{observation},
			}
			if err := set.Validate(); err == nil {
				t.Fatal("observation envelope without reproducibility identity was accepted")
			}
		})
	}
	if _, err := Reduce(catalog, oracle, nil); err == nil {
		t.Fatal("reduction without any observations was accepted")
	}
}

func TestEncodeResultRebuildsContentIDAndDecodeValidatesIt(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	result, err := Reduce(catalog, oracle, []Observation{withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")})
	if err != nil {
		t.Fatal(err)
	}
	originalID := result.ID
	result.Runs[0].EnvironmentID = "changed-environment"
	result.RunMetrics[0].Run.EnvironmentID = "changed-environment"
	newID, err := DigestResult(result)
	if err != nil {
		t.Fatal(err)
	}
	if newID == originalID {
		t.Fatal("test mutation did not change result digest")
	}
	var encoded bytes.Buffer
	if err := EncodeResult(&encoded, result); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResult(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ID != newID {
		t.Fatalf("encoded result retained stale ID %q, want %q", decoded.ID, newID)
	}
	forged := strings.Replace(encoded.String(), decoded.ID, "sha256:"+hexDigest('f'), 1)
	if _, err := DecodeResult(strings.NewReader(forged)); err == nil {
		t.Fatal("result with forged content ID was accepted")
	}

	if _, err := DecodeResult(strings.NewReader(`{"schema_version":"synapse-sca-benchmark-result-v1"}`)); err == nil {
		t.Fatal("provenance-free result was accepted")
	}
}

func TestEncodeDecodePreservesGateExpectedAndActualIdentities(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	baselineObservation := withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")
	baseline, err := Reduce(catalog, oracle, []Observation{baselineObservation})
	if err != nil {
		t.Fatal(err)
	}
	ratchet := completeRatchet(baseline, baseline.Runs[0])
	currentObservation := baselineObservation
	currentObservation.RawOutputDigest = "sha256:" + hexDigest('a')
	current, err := Reduce(catalog, oracle, []Observation{currentObservation})
	if err != nil {
		t.Fatal(err)
	}
	gated, err := ApplyRatchet(current, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := EncodeResult(&encoded, gated); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResult(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	check := gateCheck(decoded.Gate, EngineOwned, currentObservation.TargetID)
	if check == nil || check.Expected != expectedRunIdentityFromRun(baseline.Runs[0]) || check.Actual == nil || *check.Actual != current.Runs[0] {
		t.Fatalf("decoded gate identities = %+v", check)
	}
	var rendered bytes.Buffer
	if err := RenderResult(&rendered, decoded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.String(), "expected_engine:") || !strings.Contains(rendered.String(), "actual_state:") || strings.Contains(rendered.String(), "expected_state:") || strings.Contains(rendered.String(), "raw_output_digest:") {
		t.Fatalf("rendered gate does not separate expected inputs from the actual score identity: %s", rendered.String())
	}
}

func TestDecodeResultRejectsContradictoryRunAndAggregateMetrics(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	result, err := Reduce(catalog, oracle, []Observation{withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")})
	if err != nil {
		t.Fatal(err)
	}
	zero := 0.0
	for i := range result.RunMetrics {
		if result.RunMetrics[i].Run.Engine == EngineOwned {
			result.RunMetrics[i].Metrics.TruePositives = 0
			result.RunMetrics[i].Metrics.FalseNegatives = 1
			result.RunMetrics[i].Metrics.Precision = nil
			result.RunMetrics[i].Metrics.Recall = &zero
		}
	}
	var encoded bytes.Buffer
	if err := EncodeResult(&encoded, result); err == nil {
		t.Fatal("result with contradictory run and aggregate metrics was accepted")
	}
}

func TestCatalogRejectsConflictingArtifactPins(t *testing.T) {
	catalog := validCatalog()
	catalog.Pins = []ArtifactPin{
		{Reference: "scanner", Digest: "sha256:" + hexDigest('b')},
		{Reference: "scanner", Digest: "sha256:" + hexDigest('c')},
	}
	if err := catalog.Validate(); err == nil {
		t.Fatal("conflicting pins for the same reference were accepted")
	}
}

func TestRatchetRequiresThresholdsAndPerEngineExpectedIdentity(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	result, err := Reduce(catalog, oracle, []Observation{completeObservation(catalog, EngineOwned)})
	if err != nil {
		t.Fatal(err)
	}
	base := completeRatchet(result, result.Runs[0])
	if err := base.Validate(); err != nil {
		t.Fatalf("fully identified ratchet floor was rejected: %v", err)
	}
	base.Floors = nil
	if err := base.Validate(); err == nil {
		t.Fatal("ratchet without floors was accepted")
	}
	base = completeRatchet(result, result.Runs[0])
	base.Floors[0].Expected.EnvironmentDigest = ""
	if err := base.Validate(); err == nil {
		t.Fatal("ratchet floor without immutable environment content was accepted")
	}
	base = completeRatchet(result, result.Runs[0])
	base.Floors[0].MinimumCovered = nil
	if err := base.Validate(); err == nil {
		t.Fatal("ratchet floor without an explicit minimum was accepted")
	}
	base = completeRatchet(result, result.Runs[0])
	base.Floors[0].MinimumPrecision = floatPointer(math.NaN())
	if err := base.Validate(); err == nil {
		t.Fatal("ratchet floor with NaN metric was accepted")
	}
	base = completeRatchet(result, result.Runs[0])
	duplicate := base.Floors[0]
	duplicate.Expected.EngineBinaryDigest = "sha256:" + hexDigest('2')
	base.Floors = append(base.Floors, duplicate)
	if err := base.Validate(); err == nil {
		t.Fatal("ratchet floors with duplicate engine and target were accepted")
	}
}

func TestRatchetAccuracyRequiresPositiveMinimums(t *testing.T) {
	result := completeAccuracyResult(t)
	ratchet := completeRatchet(result, result.Runs[0])
	for i := range ratchet.Floors {
		ratchet.Floors[i].MinimumCovered = intPointer(2)
		ratchet.Floors[i].MinimumAffectedRelations = intPointer(1)
		ratchet.Floors[i].MinimumNegativeRelations = intPointer(1)
	}
	if err := ratchet.Validate(); err != nil {
		t.Fatalf("valid accuracy ratchet: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*RatchetFloor)
	}{
		{name: "covered", mutate: func(floor *RatchetFloor) { floor.MinimumCovered = intPointer(0) }},
		{name: "affected", mutate: func(floor *RatchetFloor) { floor.MinimumAffectedRelations = intPointer(0) }},
		{name: "negative", mutate: func(floor *RatchetFloor) { floor.MinimumNegativeRelations = intPointer(0) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := ratchet
			invalid.Floors = append([]RatchetFloor(nil), ratchet.Floors...)
			test.mutate(&invalid.Floors[0])
			if err := invalid.Validate(); err == nil {
				t.Fatalf("accuracy ratchet accepted zero %s minimum", test.name)
			}
		})
	}

	unsupported := unsupportedOnlyRatchet(fullyUnsupportedResult(t, 1, nil), 1)
	if err := unsupported.Validate(); err != nil {
		t.Fatalf("valid unsupported-only ratchet: %v", err)
	}
}

func TestDigestObservationsUsesTotalOrderAndObservationSetRejectsDuplicates(t *testing.T) {
	catalog := validCatalog()
	first := completeObservation(catalog, EngineOwned)
	second := first
	second.EngineVersion = "owned-v2"
	left, err := DigestObservations([]Observation{first, second})
	if err != nil {
		t.Fatal(err)
	}
	right, err := DigestObservations([]Observation{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("provenance digest varied with input order: %q != %q", left, right)
	}
	left, err = DigestScoringObservations([]Observation{first, second})
	if err != nil {
		t.Fatal(err)
	}
	right, err = DigestScoringObservations([]Observation{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("scoring digest varied with input order: %q != %q", left, right)
	}
	set := ObservationSet{
		SchemaVersion:   ObservationSchemaVersion,
		CatalogRevision: catalog.Revision,
		CatalogDigest:   mustDigestCatalog(catalog),
		Observations:    []Observation{first, second},
	}
	if err := set.Validate(); err == nil {
		t.Fatal("duplicate engine/target observations were accepted")
	}
}

func TestReduceRawOutputOnlyChangesPreserveScoringResult(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	baselineObservation := withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")
	changedObservation := baselineObservation
	changedObservation.RawOutputDigest = "sha256:" + hexDigest('9')

	baselineProvenance, err := DigestObservations([]Observation{baselineObservation})
	if err != nil {
		t.Fatal(err)
	}
	changedProvenance, err := DigestObservations([]Observation{changedObservation})
	if err != nil {
		t.Fatal(err)
	}
	if baselineProvenance == changedProvenance {
		t.Fatal("raw-output-only change did not alter the full provenance digest")
	}

	baselineScoring, err := DigestScoringObservations([]Observation{baselineObservation})
	if err != nil {
		t.Fatal(err)
	}
	changedScoring, err := DigestScoringObservations([]Observation{changedObservation})
	if err != nil {
		t.Fatal(err)
	}
	if baselineScoring != changedScoring {
		t.Fatalf("raw-output-only change altered scoring digest: %q != %q", baselineScoring, changedScoring)
	}

	baseline, err := Reduce(catalog, oracle, []Observation{baselineObservation})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := Reduce(catalog, oracle, []Observation{changedObservation})
	if err != nil {
		t.Fatal(err)
	}
	if baseline.ScoringObservationDigest != baselineScoring || changed.ScoringObservationDigest != changedScoring {
		t.Fatalf("result did not bind its scoring digest: %+v / %+v", baseline, changed)
	}
	if baseline.ID != changed.ID {
		t.Fatalf("raw-output-only change altered result ID: %q != %q", baseline.ID, changed.ID)
	}

	var baselineJSON, changedJSON bytes.Buffer
	if err := EncodeResult(&baselineJSON, baseline); err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&changedJSON, changed); err != nil {
		t.Fatal(err)
	}
	if baselineJSON.String() != changedJSON.String() {
		t.Fatalf("raw-output-only change altered reduced result bytes:\n%s\n---\n%s", baselineJSON.String(), changedJSON.String())
	}
	if !strings.Contains(baselineJSON.String(), `"scoring_observation_digest":`) || strings.Contains(baselineJSON.String(), `"observation_digest":`) {
		t.Fatalf("result did not encode the scoring observation digest: %s", baselineJSON.String())
	}
	if strings.Contains(baselineJSON.String(), `"raw_output_digest":`) {
		t.Fatalf("reduced result retained raw-output-only provenance: %s", baselineJSON.String())
	}
	legacy := strings.Replace(baselineJSON.String(), `"scoring_observation_digest":`, `"observation_digest":`, 1)
	if _, err := DecodeResult(strings.NewReader(legacy)); err == nil {
		t.Fatal("result with the retired observation digest key was accepted")
	}
}

func TestReduceClaimBearingObservationChangesAlterOrFail(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	baselineObservation := withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")
	baselineScoring, err := DigestScoringObservations([]Observation{baselineObservation})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := Reduce(catalog, oracle, []Observation{baselineObservation})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Observation)
	}{
		{name: "schema version", mutate: func(observation *Observation) { observation.SchemaVersion = "changed-schema" }},
		{name: "catalog revision", mutate: func(observation *Observation) { observation.CatalogRevision = "changed-revision" }},
		{name: "catalog digest", mutate: func(observation *Observation) { observation.CatalogDigest = "sha256:" + hexDigest('9') }},
		{name: "engine", mutate: func(observation *Observation) { observation.Engine = EngineGrype }},
		{name: "engine version", mutate: func(observation *Observation) { observation.EngineVersion = "changed-engine" }},
		{name: "engine binary digest", mutate: func(observation *Observation) { observation.EngineBinaryDigest = "sha256:" + hexDigest('9') }},
		{name: "database build", mutate: func(observation *Observation) { observation.DatabaseBuild = "changed-database" }},
		{name: "database digest", mutate: func(observation *Observation) { observation.DatabaseDigest = "sha256:" + hexDigest('9') }},
		{name: "environment ID", mutate: func(observation *Observation) { observation.EnvironmentID = "changed-environment" }},
		{name: "environment digest", mutate: func(observation *Observation) { observation.EnvironmentDigest = "sha256:" + hexDigest('9') }},
		{name: "target ID", mutate: func(observation *Observation) { observation.TargetID = "changed-target" }},
		{name: "target digest", mutate: func(observation *Observation) { observation.TargetDigest = "sha256:" + hexDigest('9') }},
		{name: "SBOM digest", mutate: func(observation *Observation) { observation.SBOMDigest = "sha256:" + hexDigest('9') }},
		{name: "state", mutate: func(observation *Observation) { observation.State = ObservationUnsupported }},
		{name: "config digest", mutate: func(observation *Observation) { observation.ConfigDigest = "sha256:" + hexDigest('9') }},
		{name: "capability kind", mutate: func(observation *Observation) { observation.CapabilityKind = CapabilityKindOSVScannerSUSERPM }},
		{name: "capability digest", mutate: func(observation *Observation) { observation.CapabilityDigest = "sha256:" + hexDigest('9') }},
		{name: "findings", mutate: func(observation *Observation) { observation.Findings = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedObservation := baselineObservation
			test.mutate(&changedObservation)
			changedScoring, err := DigestScoringObservations([]Observation{changedObservation})
			if err != nil {
				t.Fatal(err)
			}
			if changedScoring == baselineScoring {
				t.Fatal("claim-bearing change did not alter scoring digest")
			}
			changed, err := Reduce(catalog, oracle, []Observation{changedObservation})
			if err == nil && changed.ID == baseline.ID {
				t.Fatal("claim-bearing change did not alter or fail reduction")
			}
		})
	}
}

func TestReduceIsDeterministicForMixedValidAndInvalidFindingOrder(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	base := completeObservation(catalog, EngineOwned)
	findings := []Finding{
		{Component: Component{PURL: "pkg:npm/a@1"}, AdvisoryID: "Z"},
		{Component: Component{PURL: "pkg:npm/b@1"}, AdvisoryID: "A"},
		{Component: Component{PURL: "not-a-purl"}, AdvisoryID: "M"},
	}
	permutations := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	var want Result
	for i, permutation := range permutations {
		observation := base
		observation.Findings = []Finding{findings[permutation[0]], findings[permutation[1]], findings[permutation[2]]}
		got, err := Reduce(catalog, oracle, []Observation{observation})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			want = got
			continue
		}
		if got.ScoringObservationDigest != want.ScoringObservationDigest || got.ID != want.ID {
			t.Fatalf("finding order changed reduction identity: got %q/%q, want %q/%q", got.ScoringObservationDigest, got.ID, want.ScoringObservationDigest, want.ID)
		}
	}
}

func TestDecodeRejectsInvalidUTF8(t *testing.T) {
	valid := []byte(`{"schema_version":"synapse-sca-benchmark-catalog-v1","revision":"r1","targets":[{"id":"image","oci_ref":"registry.example/repo@sha256:` + hexDigest('a') + `","digest":"sha256:` + hexDigest('a') + `","components":[{"purl":"pkg:npm/example@1.2.3"}]}]}`)
	valid = bytes.Replace(valid, []byte(`"r1"`), []byte{'"', 0xff, '"'}, 1)
	if _, err := DecodeCatalog(bytes.NewReader(valid)); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestValidateJSONDocumentRejectsDuplicateAndTrailingValues(t *testing.T) {
	for _, document := range []string{
		`{"state":"COMMENTED","state":"APPROVED"}`,
		`{"state":"COMMENTED"} {}`,
	} {
		if err := ValidateJSONDocument(strings.NewReader(document)); err == nil {
			t.Fatalf("invalid strict JSON document %q was accepted", document)
		}
	}
	if err := ValidateJSONDocument(strings.NewReader(`{"state":"COMMENTED"}`)); err != nil {
		t.Fatalf("valid strict JSON document: %v", err)
	}
}

func validCatalog() Catalog {
	digest := "sha256:" + hexDigest('a')
	return Catalog{
		SchemaVersion: CatalogSchemaVersion,
		Revision:      "catalog-r1",
		Targets: []Target{{
			ID:         "image",
			OCIRef:     "registry.example/synapse/test@" + digest,
			Digest:     digest,
			SBOMDigest: "sha256:" + hexDigest('b'),
			Components: []Component{{PURL: "pkg:npm/example@1.2.3"}},
		}},
	}
}

func validOracle(cases ...OracleCase) Oracle {
	return Oracle{
		SchemaVersion:   OracleSchemaVersion,
		CatalogRevision: "catalog-r1",
		Cases:           cases,
	}
}

func validCase(id, advisory string, truth Truth) OracleCase {
	return OracleCase{
		ID:               id,
		Classification:   CaseReal,
		TargetID:         "image",
		Component:        Component{PURL: "pkg:npm/example@1.2.3"},
		AdvisoryID:       advisory,
		Truth:            truth,
		ExpectedCoverage: expectedCoverage(CoverageCovered),
		Provenance:       ProvenanceIndependent,
		ReviewStatus:     ReviewApproved,
		LabelerIDs:       []string{"labeler"},
		ReviewerIDs:      []string{"reviewer"},
		Rationale:        "Independently reviewed advisory status.",
		Citations: []Citation{{
			Reference: "https://evidence.example/advisories/" + advisory,
			Digest:    "sha256:" + hexDigest('b'),
		}},
	}
}

func expectedCoverage(value Coverage) map[Engine]Coverage {
	return map[Engine]Coverage{
		EngineOwned:      value,
		EngineGrype:      value,
		EngineTrivy:      value,
		EngineOSVScanner: value,
	}
}

func completeObservation(catalog Catalog, engine Engine) Observation {
	return completeObservationForTarget(catalog, engine, "image")
}

func completeObservationForTarget(catalog Catalog, engine Engine, targetID string) Observation {
	for _, target := range catalog.Targets {
		if target.ID == targetID {
			return Observation{
				SchemaVersion:      ObservationSchemaVersion,
				CatalogRevision:    catalog.Revision,
				CatalogDigest:      mustDigestCatalog(catalog),
				Engine:             engine,
				EngineVersion:      string(engine) + "-v1",
				EngineBinaryDigest: "sha256:" + hexDigest('c'),
				DatabaseBuild:      "database-2026-09-13",
				DatabaseDigest:     "sha256:" + hexDigest('d'),
				EnvironmentID:      "test-linux-amd64",
				EnvironmentDigest:  "sha256:" + hexDigest('e'),
				TargetID:           targetID,
				TargetDigest:       target.Digest,
				SBOMDigest:         target.SBOMDigest,
				State:              ObservationComplete,
				RawOutputDigest:    "sha256:" + hexDigest('f'),
				ConfigDigest:       "sha256:" + hexDigest('1'),
			}
		}
	}
	panic("test target not found")
}

func withFinding(observation Observation, advisory string) Observation {
	observation.Findings = []Finding{{Component: Component{PURL: "pkg:npm/example@1.2.3"}, AdvisoryID: advisory}}
	return observation
}

func engineResult(t *testing.T, result Result, engine Engine) EngineResult {
	t.Helper()
	for _, summary := range result.Engines {
		if summary.Engine == engine {
			return summary
		}
	}
	t.Fatalf("missing %s result", engine)
	return EngineResult{}
}

func hexDigest(ch rune) string {
	return strings.Repeat(string(ch), 64)
}

func mustDigestCatalog(catalog Catalog) string {
	digest, err := DigestCatalog(catalog)
	if err != nil {
		panic(err)
	}
	return digest
}

func intPointer(value int) *int { return &value }

func floatPointer(value float64) *float64 { return &value }

func TestReduceBindsSBOMAndContentDigests(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	observation := withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")
	result, err := Reduce(catalog, oracle, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	if result.Targets[0].SBOMDigest != catalog.Targets[0].SBOMDigest {
		t.Fatalf("target SBOM digest = %q", result.Targets[0].SBOMDigest)
	}
	run := result.Runs[0]
	if run.CatalogDigest != result.CatalogDigest || run.SBOMDigest != catalog.Targets[0].SBOMDigest || run.EngineBinaryDigest != observation.EngineBinaryDigest || run.EnvironmentDigest != observation.EnvironmentDigest || run.ConfigDigest != observation.ConfigDigest {
		t.Fatalf("incomplete score identity: %+v", run)
	}
	contradictory := observation
	contradictory.SBOMDigest = "sha256:" + hexDigest('e')
	if _, err := Reduce(catalog, oracle, []Observation{contradictory}); err == nil {
		t.Fatal("observation with a contradictory SBOM digest was accepted")
	}
	catalog.Targets[0].SBOMDigest = "not-a-digest"
	if err := catalog.Validate(); err == nil {
		t.Fatal("catalog target without immutable SBOM content was accepted")
	}
}

func TestReducePublishesPerRunMetricsWithoutTargetMasking(t *testing.T) {
	catalog := validCatalog()
	second := catalog.Targets[0]
	second.ID = "second"
	second.Digest = "sha256:" + hexDigest('e')
	second.SBOMDigest = "sha256:" + hexDigest('f')
	second.OCIRef = "registry.example/synapse/second@" + second.Digest
	catalog.Targets = append(catalog.Targets, second)
	oracle := validOracle(
		validCase("first", "CVE-2024-1111", TruthAffected),
		validCase("second", "CVE-2024-2222", TruthAffected),
	)
	oracle.Cases[1].TargetID = "second"
	first := withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")
	secondObservation := completeObservationForTarget(catalog, EngineOwned, "second")
	result, err := Reduce(catalog, oracle, []Observation{first, secondObservation})
	if err != nil {
		t.Fatal(err)
	}
	owned := engineResult(t, result, EngineOwned)
	if owned.Recall == nil || *owned.Recall != 0.5 {
		t.Fatalf("aggregate recall = %+v", owned)
	}
	var firstRun, secondRun *RunMetric
	for i := range result.RunMetrics {
		metric := &result.RunMetrics[i]
		if metric.Run.Engine != EngineOwned {
			continue
		}
		switch metric.Run.TargetID {
		case "image":
			firstRun = metric
		case "second":
			secondRun = metric
		}
	}
	if firstRun == nil || secondRun == nil || firstRun.Metrics.Recall == nil || *firstRun.Metrics.Recall != 1 || secondRun.Metrics.Recall == nil || *secondRun.Metrics.Recall != 0 {
		t.Fatalf("per-run metrics did not expose target regression: %+v", result.RunMetrics)
	}
}

func TestApplyRatchetRequiresEveryTargetAndEngineFloor(t *testing.T) {
	catalog := validCatalog()
	second := catalog.Targets[0]
	second.ID = "second"
	second.Digest = "sha256:" + hexDigest('e')
	second.SBOMDigest = "sha256:" + hexDigest('f')
	second.OCIRef = "registry.example/synapse/second@" + second.Digest
	catalog.Targets = append(catalog.Targets, second)
	oracle := validOracle(validCase("first", "CVE-2024-1111", TruthAffected), validCase("second", "CVE-2024-2222", TruthAffected))
	oracle.Cases[1].TargetID = second.ID
	result, err := Reduce(catalog, oracle, []Observation{
		withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111"),
		completeObservationForTarget(catalog, EngineOwned, second.ID),
	})
	if err != nil {
		t.Fatal(err)
	}
	partial := completeRatchet(result, result.Runs[0])
	partial.Floors = partial.Floors[:1]
	gated, err := ApplyRatchet(result, partial)
	if err == nil {
		t.Fatalf("partial ratchet produced a gate instead of rejecting the ungated matrix: %+v", gated.Gate)
	}
}

func TestRatchetGateRequiresExactPinsAndNonVacuousMetrics(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(
		validCase("affected", "CVE-2024-1111", TruthAffected),
		validCase("fixed", "CVE-2024-2222", TruthFixed),
	)
	observations := make([]Observation, 0, len(Engines()))
	for _, engine := range Engines() {
		observations = append(observations, withFinding(completeObservation(catalog, engine), "CVE-2024-1111"))
	}
	result, err := Reduce(catalog, oracle, observations)
	if err != nil {
		t.Fatal(err)
	}
	var run RunIdentity
	for _, candidate := range result.Runs {
		if candidate.Engine == EngineOwned {
			run = candidate
			break
		}
	}
	ratchet := completeRatchet(result, run)
	ratchet.Floors[0] = RatchetFloor{
		Expected:                 expectedRunIdentityFromRun(run),
		MinimumCovered:           intPointer(2),
		MinimumAffectedRelations: intPointer(1),
		MinimumNegativeRelations: intPointer(1),
		MinimumPrecision:         floatPointer(1),
		MinimumRecall:            floatPointer(1),
		MaximumFalsePositives:    intPointer(0),
		MaximumFalseNegatives:    intPointer(0),
		MaximumUnknown:           intPointer(0),
		MaximumIncomplete:        intPointer(0),
		MaximumUnsupported:       intPointer(0),
	}
	gated, err := ApplyRatchet(result, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if gated.Gate == nil || !gated.Gate.Passed || gated.ID == result.ID {
		t.Fatalf("pass gate = %+v", gated)
	}

	ratchet.Floors[0].Expected.EngineBinaryDigest = "sha256:" + hexDigest('b')
	gated, err = ApplyRatchet(result, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if gated.Gate.Passed || len(gated.Gate.Checks) != len(Engines()) || !hasGateReason(gated.Gate, GateReasonPinMismatch) || hasGateReason(gated.Gate, GateReasonThresholdBreach) {
		t.Fatalf("pin mismatch must fail without threshold comparisons: %+v", gated.Gate)
	}

	ratchet.Floors[0].Expected = expectedRunIdentityFromRun(run)
	ratchet.Floors[0].MinimumRecall = floatPointer(1.1)
	if err := ratchet.Validate(); err == nil {
		t.Fatal("out-of-range ratchet threshold was accepted")
	}
}

func TestApplyRatchetIgnoresRawOutputDigestWithMatchingPins(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(
		validCase("affected", "CVE-2024-1111", TruthAffected),
		validCase("fixed", "CVE-2024-2222", TruthFixed),
	)
	baselineObservations := make([]Observation, 0, len(Engines()))
	for _, engine := range Engines() {
		baselineObservations = append(baselineObservations, withFinding(completeObservation(catalog, engine), "CVE-2024-1111"))
	}
	baseline, err := Reduce(catalog, oracle, baselineObservations)
	if err != nil {
		t.Fatal(err)
	}
	ratchet := completeRatchet(baseline, baseline.Runs[0])
	currentObservations := append([]Observation(nil), baselineObservations...)
	for i := range currentObservations {
		if currentObservations[i].Engine == EngineOwned {
			currentObservations[i].RawOutputDigest = "sha256:" + hexDigest('a')
		}
	}
	current, err := Reduce(catalog, oracle, currentObservations)
	if err != nil {
		t.Fatal(err)
	}
	gated, err := ApplyRatchet(current, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if gated.Gate == nil || !gated.Gate.Passed {
		t.Fatalf("raw-output-only change must retain passing input pins: %+v", gated.Gate)
	}
}

func TestApplyRatchetReportsEngineBinaryPinMismatch(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	baselineObservation := completeObservation(catalog, EngineOwned)
	baseline, err := Reduce(catalog, oracle, []Observation{baselineObservation})
	if err != nil {
		t.Fatal(err)
	}
	ratchet := completeRatchet(baseline, baseline.Runs[0])
	changedBinary := baselineObservation
	changedBinary.EngineBinaryDigest = "sha256:" + hexDigest('a')
	current, err := Reduce(catalog, oracle, []Observation{changedBinary})
	if err != nil {
		t.Fatal(err)
	}
	gated, err := ApplyRatchet(current, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	check := gateCheck(gated.Gate, EngineOwned, changedBinary.TargetID)
	if check == nil || check.Actual == nil || check.Actual.EngineBinaryDigest != changedBinary.EngineBinaryDigest || !hasReason(*check, GateReasonPinMismatch) || hasReason(*check, GateReasonThresholdBreach) {
		t.Fatalf("engine binary change must be a pin mismatch without threshold comparisons: %+v", check)
	}
}

func TestApplyRatchetReportsMissingAndUnavailableMetrics(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("not-affected", "CVE-2024-1111", TruthNotAffected))
	oracle.Cases = append(oracle.Cases, validCase("affected", "CVE-2024-2222", TruthAffected))
	oracle.Cases[1].ExpectedCoverage = expectedCoverage(CoverageUnsupported)
	result, err := Reduce(catalog, oracle, []Observation{completeObservation(catalog, EngineOwned)})
	if err != nil {
		t.Fatal(err)
	}
	run := result.Runs[0]
	ratchet := completeRatchet(result, run)
	gated, err := ApplyRatchet(result, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	missing := gateCheck(gated.Gate, EngineGrype, run.TargetID)
	if gated.Gate.Passed || hasGateReason(gated.Gate, GateReasonMetricsIncomplete) || !hasGateReason(gated.Gate, GateReasonMetricUnavailable) || !hasGateReason(gated.Gate, GateReasonMissingObservation) || missing == nil || missing.Actual != nil {
		t.Fatalf("covered-only metric availability and missing observations must be reported distinctly: %+v", gated.Gate)
	}
}

func TestApplyRatchetStateChangeProducesMetricsIncompleteWithoutPinMismatch(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	baselineObservation := completeObservation(catalog, EngineOwned)
	baseline, err := Reduce(catalog, oracle, []Observation{baselineObservation})
	if err != nil {
		t.Fatal(err)
	}
	ratchet := completeRatchet(baseline, baseline.Runs[0])
	incomplete := baselineObservation
	incomplete.State = ObservationIncomplete
	current, err := Reduce(catalog, oracle, []Observation{incomplete})
	if err != nil {
		t.Fatal(err)
	}
	gated, err := ApplyRatchet(current, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	check := gateCheck(gated.Gate, EngineOwned, incomplete.TargetID)
	if check == nil || check.Actual == nil || check.Actual.State != ObservationIncomplete || !hasReason(*check, GateReasonMetricsIncomplete) || hasReason(*check, GateReasonPinMismatch) {
		t.Fatalf("state-only change must report incomplete metrics instead of a pin mismatch: %+v", check)
	}
}

func TestRenderResultIsDeterministicAndEscapesDiagnostics(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	observation := withFinding(completeObservation(catalog, EngineOwned), "unknown\nnot-a-section unicode-separator paragraph-separator")
	result, err := Reduce(catalog, oracle, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	var first, second bytes.Buffer
	if err := RenderResult(&first, result); err != nil {
		t.Fatal(err)
	}
	if err := RenderResult(&second, result); err != nil {
		t.Fatal(err)
	}
	rendered := first.String()
	if rendered != second.String() || !strings.Contains(rendered, `unknown\\nnot-a-section\\u2028unicode-separator\\u2029paragraph-separator`) || strings.Contains(rendered, "\nnot-a-section") || strings.Contains(rendered, " ") || strings.Contains(rendered, " ") {
		t.Fatalf("render must be deterministic and quote injected text: %q", rendered)
	}
}

func TestRenderResultGoldenPrelude(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	result, err := Reduce(catalog, oracle, []Observation{withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")})
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := RenderResult(&rendered, result); err != nil {
		t.Fatal(err)
	}
	const goldenPrelude = "SCA Benchmark Result\nschema_version: \"synapse-sca-benchmark-result-v1\"\n"
	if !strings.HasPrefix(rendered.String(), goldenPrelude) ||
		!strings.Contains(rendered.String(), "scoring_observation_digest:") ||
		strings.Contains(rendered.String(), "\nobservation_digest:") ||
		!strings.Contains(rendered.String(), "interpretation:\n") ||
		!strings.Contains(rendered.String(), "owned_database_coupling:") ||
		!strings.Contains(rendered.String(), "owned consumes the corresponding pinned vendor OVAL") ||
		!strings.Contains(rendered.String(), "engine_database_scope:") ||
		!strings.Contains(rendered.String(), "database_build and database_digest") ||
		!strings.Contains(rendered.String(), "comparative_limit:") ||
		!strings.Contains(rendered.String(), "run_metrics:\n") ||
		!strings.Contains(rendered.String(), "diagnostics:\n") {
		t.Fatalf("render no longer matches its stable golden structure:\n%s", rendered.String())
	}
}

func completeRatchet(result Result, run RunIdentity) Ratchet {
	actualRuns := make(map[observationKey]RunIdentity, len(result.Runs))
	for _, actual := range result.Runs {
		actualRuns[observationKey{Engine: actual.Engine, TargetID: actual.TargetID}] = actual
	}
	floors := make([]RatchetFloor, 0, len(result.Targets)*len(Engines()))
	for _, target := range result.Targets {
		for _, engine := range Engines() {
			floorRun, exists := actualRuns[observationKey{Engine: engine, TargetID: target.ID}]
			if !exists {
				floorRun = run
				floorRun.Engine = engine
				floorRun.EngineVersion = string(engine) + "-v1"
				floorRun.TargetID = target.ID
				floorRun.TargetDigest = target.Digest
				floorRun.SBOMDigest = target.SBOMDigest
			}
			expected := expectedRunIdentityFromRun(floorRun)
			expected.CapabilityKind = ""
			expected.CapabilityDigest = ""
			floors = append(floors, RatchetFloor{
				Expected:                 expected,
				MinimumCovered:           intPointer(2),
				MinimumAffectedRelations: intPointer(1),
				MinimumNegativeRelations: intPointer(1),
				MinimumPrecision:         floatPointer(0),
				MinimumRecall:            floatPointer(0),
				MaximumFalsePositives:    intPointer(100),
				MaximumFalseNegatives:    intPointer(100),
				MaximumUnknown:           intPointer(100),
				MaximumIncomplete:        intPointer(100),
				MaximumUnsupported:       intPointer(100),
			})
		}
	}
	return Ratchet{
		SchemaVersion:   RatchetSchemaVersion,
		CatalogRevision: result.CatalogRevision,
		CatalogDigest:   result.CatalogDigest,
		OracleDigest:    result.OracleDigest,
		Floors:          floors,
	}
}

func hasGateReason(gate *Gate, reason GateReasonCode) bool {
	if gate == nil {
		return false
	}
	for _, check := range gate.Checks {
		if hasReason(check, reason) {
			return true
		}
	}
	return false
}

func hasReason(check GateCheck, reason GateReasonCode) bool {
	for _, got := range check.ReasonCodes {
		if got == reason {
			return true
		}
	}
	return false
}

func gateCheck(gate *Gate, engine Engine, targetID string) *GateCheck {
	if gate == nil {
		return nil
	}
	for i := range gate.Checks {
		check := &gate.Checks[i]
		if check.Expected.Engine == engine && check.Expected.TargetID == targetID {
			return check
		}
	}
	return nil
}

func TestRatchetDecodeRequiresEveryExplicitThresholdAndCanonicalizesFloorOrder(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("affected", "CVE-2024-1111", TruthAffected))
	result, err := Reduce(catalog, oracle, []Observation{withFinding(completeObservation(catalog, EngineOwned), "CVE-2024-1111")})
	if err != nil {
		t.Fatal(err)
	}
	ratchet := completeRatchet(result, result.Runs[0])
	encoded, err := CanonicalJSON(ratchet)
	if err != nil {
		t.Fatal(err)
	}
	missing := strings.Replace(string(encoded), `"minimum_covered":2,`, "", 1)
	if _, err := DecodeRatchet(strings.NewReader(missing)); err == nil {
		t.Fatal("ratchet with an omitted zero threshold was accepted")
	}
	other := result.Runs[0]
	other.Engine = EngineGrype
	other.EngineVersion = "grype-v1"
	other.EngineBinaryDigest = "sha256:" + hexDigest('2')
	other.ConfigDigest = "sha256:" + hexDigest('3')
	ratchet.Floors = append(ratchet.Floors, completeRatchet(result, other).Floors[0])
	first, err := DigestRatchet(ratchet)
	if err != nil {
		t.Fatal(err)
	}
	ratchet.Floors[0], ratchet.Floors[1] = ratchet.Floors[1], ratchet.Floors[0]
	second, err := DigestRatchet(ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("ratchet digest changed with floor order: %q != %q", first, second)
	}
}

func TestReduceFullyUnsupportedRunMetricsRemainCompleteAndNull(t *testing.T) {
	result := fullyUnsupportedResult(t, 1, nil)
	metric := runMetric(t, result, EngineOwned, "image")
	if metric.Metrics.Unsupported != 1 ||
		metric.Metrics.Covered != 0 ||
		metric.Metrics.AffectedRelations != 0 ||
		metric.Metrics.NegativeRelations != 0 ||
		metric.Metrics.TruePositives != 0 ||
		metric.Metrics.FalsePositives != 0 ||
		metric.Metrics.FalseNegatives != 0 ||
		metric.Metrics.Unknown != 0 ||
		metric.Metrics.Incomplete != 0 ||
		!metric.Metrics.MetricsComplete ||
		metric.Metrics.Precision != nil ||
		metric.Metrics.Recall != nil {
		t.Fatalf("fully unsupported run metrics = %+v", metric.Metrics)
	}
}

func TestFloorGateModeCanonicalizesAccuracyAndValidatesUnsupportedOnly(t *testing.T) {
	unsupportedResult := fullyUnsupportedResult(t, 1, nil)
	accuracy := completeRatchet(unsupportedResult, unsupportedResult.Runs[0])
	accuracyDigest, err := DigestRatchet(accuracy)
	if err != nil {
		t.Fatal(err)
	}
	explicitAccuracy := accuracy
	explicitAccuracy.Floors = append([]RatchetFloor(nil), accuracy.Floors...)
	explicitAccuracy.Floors[0].Mode = FloorGateModeAccuracy
	explicitAccuracyDigest, err := DigestRatchet(explicitAccuracy)
	if err != nil {
		t.Fatal(err)
	}
	if accuracyDigest != explicitAccuracyDigest {
		t.Fatalf("omitted and explicit accuracy modes changed the ratchet digest: %q != %q", accuracyDigest, explicitAccuracyDigest)
	}

	unsupported := unsupportedOnlyRatchet(unsupportedResult, 1)
	unsupportedDigest, err := DigestRatchet(unsupported)
	if err != nil {
		t.Fatal(err)
	}
	if unsupportedDigest == accuracyDigest {
		t.Fatal("unsupported-only mode did not change the ratchet digest")
	}
	unsupportedGated, err := ApplyRatchet(unsupportedResult, unsupported)
	if err != nil {
		t.Fatal(err)
	}
	withoutMode := unsupportedGated
	withoutMode.Gate = copyGate(unsupportedGated.Gate)
	for i := range withoutMode.Gate.Checks {
		withoutMode.Gate.Checks[i].Mode = ""
	}
	unsupportedResultDigest, err := DigestResult(unsupportedGated)
	if err != nil {
		t.Fatal(err)
	}
	withoutModeDigest, err := DigestResult(withoutMode)
	if err != nil {
		t.Fatal(err)
	}
	if unsupportedResultDigest == withoutModeDigest {
		t.Fatal("unsupported-only mode did not change the result digest")
	}

	for _, test := range []struct {
		name   string
		mutate func(*RatchetFloor)
	}{
		{name: "minimum covered", mutate: func(floor *RatchetFloor) { floor.MinimumCovered = intPointer(1) }},
		{name: "minimum affected", mutate: func(floor *RatchetFloor) { floor.MinimumAffectedRelations = intPointer(1) }},
		{name: "minimum negative", mutate: func(floor *RatchetFloor) { floor.MinimumNegativeRelations = intPointer(1) }},
		{name: "minimum precision", mutate: func(floor *RatchetFloor) { floor.MinimumPrecision = floatPointer(0.1) }},
		{name: "minimum recall", mutate: func(floor *RatchetFloor) { floor.MinimumRecall = floatPointer(0.1) }},
		{name: "maximum false positives", mutate: func(floor *RatchetFloor) { floor.MaximumFalsePositives = intPointer(1) }},
		{name: "maximum false negatives", mutate: func(floor *RatchetFloor) { floor.MaximumFalseNegatives = intPointer(1) }},
		{name: "maximum unknown", mutate: func(floor *RatchetFloor) { floor.MaximumUnknown = intPointer(1) }},
		{name: "maximum incomplete", mutate: func(floor *RatchetFloor) { floor.MaximumIncomplete = intPointer(1) }},
		{name: "zero unsupported ceiling", mutate: func(floor *RatchetFloor) { floor.MaximumUnsupported = intPointer(0) }},
		{name: "unknown mode", mutate: func(floor *RatchetFloor) { floor.Mode = FloorGateMode("UNSUPPORTED_ONLY") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := unsupported
			invalid.Floors = append([]RatchetFloor(nil), unsupported.Floors...)
			test.mutate(&invalid.Floors[0])
			if err := invalid.Validate(); err == nil {
				t.Fatalf("unsupported-only ratchet accepted invalid %s", test.name)
			}
		})
	}

	accuracyResult := completeAccuracyResult(t)
	accuracyRatchet := completeRatchet(accuracyResult, accuracyResult.Runs[0])
	gatedAccuracy, err := ApplyRatchet(accuracyResult, accuracyRatchet)
	if err != nil {
		t.Fatal(err)
	}
	explicitAccuracyResult := gatedAccuracy
	explicitAccuracyResult.Gate = &Gate{
		RatchetDigest: gatedAccuracy.Gate.RatchetDigest,
		Ratchet:       canonicalRatchet(gatedAccuracy.Gate.Ratchet),
		Passed:        gatedAccuracy.Gate.Passed,
		Checks:        append([]GateCheck(nil), gatedAccuracy.Gate.Checks...),
	}
	explicitAccuracyResult.Gate.Checks[0].Mode = FloorGateModeAccuracy
	explicitResultDigest, err := DigestResult(explicitAccuracyResult)
	if err != nil {
		t.Fatal(err)
	}
	implicitResultDigest, err := DigestResult(gatedAccuracy)
	if err != nil {
		t.Fatal(err)
	}
	if explicitResultDigest != implicitResultDigest {
		t.Fatalf("omitted and explicit accuracy modes changed the result digest: %q != %q", implicitResultDigest, explicitResultDigest)
	}
}

func TestDecodeRatchetAndResultRejectMalformedMode(t *testing.T) {
	result := fullyUnsupportedResult(t, 1, nil)
	ratchet := unsupportedOnlyRatchet(result, 1)
	ratchetJSON, err := CanonicalJSON(ratchet)
	if err != nil {
		t.Fatal(err)
	}
	gated, err := ApplyRatchet(result, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	var resultJSON bytes.Buffer
	if err := EncodeResult(&resultJSON, gated); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		replacement string
	}{
		{name: "empty", replacement: `"mode":""`},
		{name: "unknown", replacement: `"mode":"unsupported"`},
		{name: "case variant", replacement: `"mode":"UNSUPPORTED_ONLY"`},
		{name: "null", replacement: `"mode":null`},
		{name: "number", replacement: `"mode":1`},
		{name: "object", replacement: `"mode":{}`},
		{name: "array", replacement: `"mode":[]`},
		{name: "duplicate", replacement: `"mode":"unsupported_only","mode":"unsupported_only"`},
		{name: "case variant key", replacement: `"Mode":"unsupported_only"`},
	} {
		t.Run("ratchet "+test.name, func(t *testing.T) {
			body := strings.Replace(string(ratchetJSON), `"mode":"unsupported_only"`, test.replacement, 1)
			if _, err := DecodeRatchet(strings.NewReader(body)); err == nil {
				t.Fatalf("ratchet accepted %s mode: %s", test.name, body)
			}
		})
		t.Run("result "+test.name, func(t *testing.T) {
			body := strings.Replace(resultJSON.String(), `"mode":"unsupported_only"`, test.replacement, 1)
			if _, err := DecodeResult(strings.NewReader(body)); err == nil {
				t.Fatalf("result accepted %s mode: %s", test.name, body)
			}
		})
	}

	accuracyResult := completeAccuracyResult(t)
	implicitAccuracy := completeRatchet(accuracyResult, accuracyResult.Runs[0])
	implicitAccuracyJSON, err := CanonicalJSON(implicitAccuracy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRatchet(strings.NewReader(string(implicitAccuracyJSON))); err != nil {
		t.Fatalf("ratchet without a mode is not backward compatible: %v", err)
	}
}

func TestApplyRatchetUnsupportedOnly(t *testing.T) {
	t.Run("passes with unsupported fully unsupported metrics", func(t *testing.T) {
		result := fullyUnsupportedResult(t, 1, map[Engine]ObservationState{EngineOwned: ObservationUnsupported, EngineGrype: ObservationUnsupported, EngineTrivy: ObservationUnsupported, EngineOSVScanner: ObservationUnsupported})
		gated, err := ApplyRatchet(result, unsupportedOnlyRatchet(result, 1))
		if err != nil {
			t.Fatal(err)
		}
		if gated.Gate == nil || !gated.Gate.Passed {
			t.Fatalf("unsupported-only gate = %+v", gated.Gate)
		}
		for _, check := range gated.Gate.Checks {
			if check.Mode != FloorGateModeUnsupportedOnly || !check.Passed {
				t.Fatalf("unsupported-only check = %+v", check)
			}
		}
	})

	t.Run("accuracy floors reject unsupported observations", func(t *testing.T) {
		result := fullyUnsupportedResult(t, 1, nil)
		gated, err := ApplyRatchet(result, completeRatchet(result, result.Runs[0]))
		if err != nil {
			t.Fatal(err)
		}
		if gated.Gate == nil || gated.Gate.Passed {
			t.Fatalf("accuracy gate accepted unsupported result: %+v", gated.Gate)
		}
	})

	t.Run("ceiling permits the boundary and rejects debt above it", func(t *testing.T) {
		result := fullyUnsupportedResult(t, 2, nil)
		boundary, err := ApplyRatchet(result, unsupportedOnlyRatchet(result, 2))
		if err != nil {
			t.Fatal(err)
		}
		if boundary.Gate == nil || !boundary.Gate.Passed {
			t.Fatalf("boundary ceiling must pass: %+v", boundary.Gate)
		}
		excess, err := ApplyRatchet(result, unsupportedOnlyRatchet(result, 1))
		if err != nil {
			t.Fatal(err)
		}
		if excess.Gate == nil || excess.Gate.Passed || !hasGateReason(excess.Gate, GateReasonThresholdBreach) || hasGateReason(excess.Gate, GateReasonCoverageContractBreach) {
			t.Fatalf("unsupported debt over ceiling = %+v", excess.Gate)
		}
	})

	t.Run("missing observation and duplicate floor are not accepted", func(t *testing.T) {
		result := fullyUnsupportedResult(t, 1, nil)
		result.Runs = removeRun(result.Runs, EngineGrype, "image")
		result.RunMetrics = removeRunMetric(result.RunMetrics, EngineGrype, "image")
		for i := range result.Engines {
			if result.Engines[i].Engine == EngineGrype {
				result.Engines[i].MetricsComplete = false
			}
		}
		var err error
		result.ID, err = DigestResult(result)
		if err != nil {
			t.Fatal(err)
		}
		ratchet := unsupportedOnlyRatchet(result, 1)
		gated, err := ApplyRatchet(result, ratchet)
		if err != nil {
			t.Fatal(err)
		}
		missing := gateCheck(gated.Gate, EngineGrype, "image")
		if missing == nil || missing.Actual != nil || !hasReason(*missing, GateReasonMissingObservation) {
			t.Fatalf("missing unsupported-only check = %+v", missing)
		}
		duplicate := ratchet
		duplicate.Floors = append(append([]RatchetFloor(nil), ratchet.Floors...), ratchet.Floors[0])
		if _, err := ApplyRatchet(result, duplicate); err == nil {
			t.Fatal("duplicate unsupported-only floor was accepted")
		}
	})

	t.Run("wrong pins prevent contract comparisons", func(t *testing.T) {
		result := fullyUnsupportedResult(t, 1, nil)
		ratchet := unsupportedOnlyRatchet(result, 1)
		ratchet.Floors[0].Expected.EngineBinaryDigest = "sha256:" + hexDigest('9')
		gated, err := ApplyRatchet(result, ratchet)
		if err != nil {
			t.Fatal(err)
		}
		check := gateCheck(gated.Gate, ratchet.Floors[0].Expected.Engine, ratchet.Floors[0].Expected.TargetID)
		if check == nil || !hasReason(*check, GateReasonPinMismatch) || hasReason(*check, GateReasonCoverageContractBreach) || hasReason(*check, GateReasonThresholdBreach) {
			t.Fatalf("wrong pin check = %+v", check)
		}
	})

	t.Run("state other than unsupported breaches the coverage contract", func(t *testing.T) {
		result := fullyUnsupportedResult(t, 1, map[Engine]ObservationState{EngineOwned: ObservationComplete, EngineGrype: ObservationUnsupported, EngineTrivy: ObservationUnsupported, EngineOSVScanner: ObservationUnsupported})
		metric := runMetric(t, result, EngineOwned, "image")
		if !metric.Metrics.MetricsComplete {
			t.Fatalf("expected unsupported observation unexpectedly changed reducer completeness: %+v", metric.Metrics)
		}
		gated, err := ApplyRatchet(result, unsupportedOnlyRatchet(result, 1))
		if err != nil {
			t.Fatal(err)
		}
		check := gateCheck(gated.Gate, EngineOwned, "image")
		if check == nil || !hasReason(*check, GateReasonPinMismatch) || hasReason(*check, GateReasonMetricsIncomplete) {
			t.Fatalf("non-unsupported unsupported-only check = %+v", check)
		}
	})

	t.Run("incomplete metrics retain the metrics-incomplete reason", func(t *testing.T) {
		result := fullyUnsupportedResult(t, 1, nil)
		for i := range result.RunMetrics {
			if result.RunMetrics[i].Run.Engine == EngineOwned {
				result.RunMetrics[i].Metrics.MetricsComplete = false
			}
		}
		for i := range result.Engines {
			if result.Engines[i].Engine == EngineOwned {
				result.Engines[i].MetricsComplete = false
			}
		}
		var err error
		result.ID, err = DigestResult(result)
		if err != nil {
			t.Fatal(err)
		}
		gated, err := ApplyRatchet(result, unsupportedOnlyRatchet(result, 1))
		if err != nil {
			t.Fatal(err)
		}
		check := gateCheck(gated.Gate, EngineOwned, "image")
		if check == nil || !hasReason(*check, GateReasonMetricsIncomplete) || hasReason(*check, GateReasonCoverageContractBreach) {
			t.Fatalf("incomplete unsupported-only metrics check = %+v", check)
		}
	})

	t.Run("covered scope breaches the coverage contract", func(t *testing.T) {
		result := completeAccuracyResult(t)
		gated, err := ApplyRatchet(result, unsupportedOnlyRatchet(result, 1))
		if err != nil {
			t.Fatal(err)
		}
		if gated.Gate == nil || gated.Gate.Passed || !hasGateReason(gated.Gate, GateReasonPinMismatch) {
			t.Fatalf("covered unsupported-only result = %+v", gated.Gate)
		}
	})
}

func TestUnsupportedObservationsRequireCapabilityEvidenceAndPinItInRatchets(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(validCase("unsupported", "CVE-2024-1111", TruthAffected))
	oracle.Cases[0].ExpectedCoverage = expectedCoverage(CoverageUnsupported)
	observations := make([]Observation, 0, len(Engines()))
	for _, engine := range Engines() {
		observation := completeObservation(catalog, engine)
		observation.State = ObservationUnsupported
		observation.CapabilityKind = CapabilityKindOSVScannerSUSERPM
		observation.CapabilityDigest = "sha256:" + hexDigest('8')
		observations = append(observations, observation)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Observation)
	}{
		{name: "missing kind", mutate: func(observation *Observation) { observation.CapabilityKind = "" }},
		{name: "missing digest", mutate: func(observation *Observation) { observation.CapabilityDigest = "" }},
		{name: "invalid kind", mutate: func(observation *Observation) { observation.CapabilityKind = CapabilityKind("other") }},
		{name: "invalid digest", mutate: func(observation *Observation) { observation.CapabilityDigest = "sha256:not-a-digest" }},
		{name: "findings", mutate: func(observation *Observation) {
			observation.Findings = []Finding{{Component: catalog.Targets[0].Components[0], AdvisoryID: "CVE-2024-1111"}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := append([]Observation(nil), observations...)
			test.mutate(&invalid[0])
			if _, err := Reduce(catalog, oracle, invalid); err == nil {
				t.Fatal("reducer accepted an invalid unsupported observation")
			}
			set := ObservationSet{SchemaVersion: ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: mustDigestCatalog(catalog), Observations: invalid[:1]}
			encoded, err := json.Marshal(set)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeObservationSet(bytes.NewReader(encoded)); err == nil {
				t.Fatal("observation decoder accepted an invalid unsupported observation")
			}
		})
	}

	result, err := Reduce(catalog, oracle, observations)
	if err != nil {
		t.Fatal(err)
	}
	ratchet := unsupportedOnlyRatchet(result, 1)
	if gated, err := ApplyRatchet(result, ratchet); err != nil || gated.Gate == nil || !gated.Gate.Passed {
		t.Fatalf("capability-pinned unsupported-only ratchet = %+v, %v", gated.Gate, err)
	}

	missingCapability := unsupportedOnlyRatchet(result, 1)
	missingCapability.Floors[0].Expected.CapabilityDigest = ""
	if _, err := ApplyRatchet(result, missingCapability); err == nil {
		t.Fatal("unsupported-only ratchet without capability evidence was accepted")
	}

	mismatchedCapability := unsupportedOnlyRatchet(result, 1)
	mismatchedCapability.Floors[0].Expected.CapabilityDigest = "sha256:" + hexDigest('9')
	gated, err := ApplyRatchet(result, mismatchedCapability)
	if err != nil {
		t.Fatal(err)
	}
	check := gateCheck(gated.Gate, mismatchedCapability.Floors[0].Expected.Engine, mismatchedCapability.Floors[0].Expected.TargetID)
	if check == nil || check.Passed || !hasReason(*check, GateReasonPinMismatch) {
		t.Fatalf("mismatched capability pin did not fail unsupported-only gate: %+v", check)
	}

	accuracy := completeRatchet(result, result.Runs[0])
	accuracy.Floors[0].Expected.CapabilityKind = CapabilityKindOSVScannerSUSERPM
	accuracy.Floors[0].Expected.CapabilityDigest = "sha256:" + hexDigest('8')
	if err := accuracy.Validate(); err == nil {
		t.Fatal("accuracy ratchet carrying capability evidence was accepted")
	}
}

func TestApplyRatchetAccuracyDefaultRetainsMetricUnavailableForZeroDenominators(t *testing.T) {
	result := fullyUnsupportedResult(t, 1, nil)
	omitted := completeRatchet(result, result.Runs[0])
	encoded, err := CanonicalJSON(omitted)
	if err != nil {
		t.Fatal(err)
	}
	explicitFalse, err := DecodeRatchet(strings.NewReader(strings.ReplaceAll(string(encoded), `"expected":`, `"allow_undefined_precision":false,"expected":`)))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		ratchet Ratchet
	}{
		{name: "omitted", ratchet: omitted},
		{name: "explicit false", ratchet: explicitFalse},
	} {
		t.Run(test.name, func(t *testing.T) {
			gated, err := ApplyRatchet(result, test.ratchet)
			if err != nil {
				t.Fatal(err)
			}
			check := gateCheck(gated.Gate, EngineOwned, "image")
			if check == nil || check.Mode != "" || !hasReason(*check, GateReasonPinMismatch) {
				t.Fatalf("accuracy floor must reject unsupported capability evidence: %+v", check)
			}
		})
	}
}

func TestApplyRatchetAllowUndefinedPrecision(t *testing.T) {
	result := zeroFindingAccuracyResult(t)
	ratchet := completeRatchet(result, result.Runs[0])
	for i := range ratchet.Floors {
		ratchet.Floors[i].AllowUndefinedPrecision = true
	}
	gated, err := ApplyRatchet(result, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if gated.Gate == nil || !gated.Gate.Passed {
		t.Fatalf("zero-finding accuracy baseline did not pass: %+v", gated.Gate)
	}
	for _, runMetric := range gated.RunMetrics {
		if runMetric.Metrics.Precision != nil {
			t.Fatalf("zero-finding precision = %v, want null", *runMetric.Metrics.Precision)
		}
		if runMetric.Metrics.Recall == nil || *runMetric.Metrics.Recall != 0 {
			t.Fatalf("zero-finding recall = %v, want 0", runMetric.Metrics.Recall)
		}
	}

	for _, test := range []struct {
		name   string
		mutate func(*RatchetFloor)
	}{
		{name: "recall floor", mutate: func(floor *RatchetFloor) { floor.MinimumRecall = floatPointer(0.1) }},
		{name: "affected count floor", mutate: func(floor *RatchetFloor) { floor.MinimumAffectedRelations = intPointer(2) }},
		{name: "false negative ceiling", mutate: func(floor *RatchetFloor) { floor.MaximumFalseNegatives = intPointer(0) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			failing := canonicalRatchet(ratchet)
			test.mutate(&failing.Floors[0])
			gated, err := ApplyRatchet(result, failing)
			if err != nil {
				t.Fatal(err)
			}
			if gated.Gate == nil || gated.Gate.Passed || !hasGateReason(gated.Gate, GateReasonThresholdBreach) {
				t.Fatalf("allowing undefined precision bypassed %s: %+v", test.name, gated.Gate)
			}
		})
	}

	ratchetJSON, err := CanonicalJSON(ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ratchetJSON), `"allow_undefined_precision":true`) {
		t.Fatalf("canonical ratchet omitted undefined precision policy: %s", ratchetJSON)
	}
	decodedRatchet, err := DecodeRatchet(strings.NewReader(string(ratchetJSON)))
	if err != nil {
		t.Fatal(err)
	}
	if !decodedRatchet.Floors[0].AllowUndefinedPrecision {
		t.Fatalf("ratchet policy did not round-trip: %+v", decodedRatchet.Floors[0])
	}
	var first, second bytes.Buffer
	if err := EncodeResult(&first, gated); err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&second, gated); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("gated result encoding changed: %s\n---\n%s", first.String(), second.String())
	}
	if !strings.Contains(first.String(), `"precision":null`) {
		t.Fatalf("gated result did not retain null precision: %s", first.String())
	}
	decodedResult, err := DecodeResult(strings.NewReader(first.String()))
	if err != nil {
		t.Fatal(err)
	}
	if decodedResult.Gate == nil || !decodedResult.Gate.Ratchet.Floors[0].AllowUndefinedPrecision {
		t.Fatalf("embedded ratchet policy did not round-trip: %+v", decodedResult.Gate)
	}
	var rendered bytes.Buffer
	if err := RenderResult(&rendered, gated); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.String(), "allow_undefined_precision: true") {
		t.Fatalf("rendered gate omitted undefined precision policy: %s", rendered.String())
	}

	forged := copyResult(gated)
	forged.Gate = copyGate(gated.Gate)
	forged.Gate.Ratchet.Floors[0].AllowUndefinedPrecision = false
	forged.Gate.RatchetDigest, err = DigestRatchet(forged.Gate.Ratchet)
	if err != nil {
		t.Fatal(err)
	}
	forged.ID, err = DigestResult(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := forged.Validate(); err == nil {
		t.Fatal("self-digested gate accepted an altered undefined precision policy")
	}
}

func TestRatchetAllowUndefinedPrecisionValidation(t *testing.T) {
	accuracyResult := completeAccuracyResult(t)
	unsupportedResult := fullyUnsupportedResult(t, 1, nil)
	for _, test := range []struct {
		name    string
		ratchet Ratchet
		mutate  func(*RatchetFloor)
	}{
		{
			name:    "nonzero accuracy minimum precision",
			ratchet: completeRatchet(accuracyResult, accuracyResult.Runs[0]),
			mutate: func(floor *RatchetFloor) {
				floor.AllowUndefinedPrecision = true
				floor.MinimumPrecision = floatPointer(0.1)
			},
		},
		{
			name:    "unsupported-only mode",
			ratchet: unsupportedOnlyRatchet(unsupportedResult, 1),
			mutate: func(floor *RatchetFloor) {
				floor.AllowUndefinedPrecision = true
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.mutate(&test.ratchet.Floors[0])
			if err := test.ratchet.Validate(); err == nil {
				t.Fatalf("ratchet accepted invalid undefined precision policy: %+v", test.ratchet.Floors[0])
			}
		})
	}
}

func TestResultGateBindsActualRunMetricsAndUnsupportedOnlyPassedShape(t *testing.T) {
	t.Run("self-digested forged actual identity is rejected", func(t *testing.T) {
		gated := passingUnsupportedOnlyResult(t)
		forged := gated
		forged.Gate = copyGate(gated.Gate)
		actual := *forged.Gate.Checks[0].Actual
		actual.EnvironmentDigest = "sha256:" + hexDigest('9')
		forged.Gate.Checks[0].Actual = &actual
		var err error
		forged.ID, err = DigestResult(forged)
		if err != nil {
			t.Fatal(err)
		}
		if err := forged.Validate(); err == nil {
			t.Fatal("self-digested forged gate actual was accepted")
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*Result, GateCheck)
	}{
		{
			name: "non-complete run",
			mutate: func(result *Result, check GateCheck) {
				mutateBoundRun(result, check, func(run *RunIdentity) { run.State = ObservationIncomplete })
			},
		},
		{
			name: "incomplete metrics",
			mutate: func(result *Result, check GateCheck) {
				mutateBoundMetrics(result, check, func(metrics *EngineResult) { metrics.MetricsComplete = false })
			},
		},
		{
			name: "covered scope and non-null metrics",
			mutate: func(result *Result, check GateCheck) {
				mutateBoundMetrics(result, check, func(metrics *EngineResult) {
					one := 1.0
					metrics.Covered = 1
					metrics.AffectedRelations = 1
					metrics.TruePositives = 1
					metrics.Precision = &one
					metrics.Recall = &one
				})
			},
		},
		{
			name: "unknown evidence",
			mutate: func(result *Result, check GateCheck) {
				mutateBoundMetrics(result, check, func(metrics *EngineResult) { metrics.Unknown++ })
			},
		},
		{
			name: "incomplete evidence",
			mutate: func(result *Result, check GateCheck) {
				mutateBoundMetrics(result, check, func(metrics *EngineResult) { metrics.Incomplete++ })
			},
		},
		{
			name: "zero unsupported evidence",
			mutate: func(result *Result, check GateCheck) {
				mutateBoundMetrics(result, check, func(metrics *EngineResult) { metrics.Unsupported = 0 })
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := passingUnsupportedOnlyResult(t)
			forged.Gate = copyGate(forged.Gate)
			check := forged.Gate.Checks[0]
			test.mutate(&forged, check)
			updated := runMetric(t, forged, check.Expected.Engine, check.Expected.TargetID).Run
			forged.Gate.Checks[0].Actual = &updated
			var err error
			forged.ID, err = DigestResult(forged)
			if err != nil {
				t.Fatal(err)
			}
			if err := forged.Validate(); err == nil {
				t.Fatalf("passed unsupported-only check accepted %s", test.name)
			}
		})
	}
}

func TestUnsupportedOnlyGateEncodingAndRenderingAreDeterministic(t *testing.T) {
	gated := passingUnsupportedOnlyResult(t)
	var first, second bytes.Buffer
	if err := EncodeResult(&first, gated); err != nil {
		t.Fatal(err)
	}
	if err := EncodeResult(&second, gated); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("unsupported-only encoding changed: %s\n---\n%s", first.String(), second.String())
	}
	decoded, err := DecodeResult(strings.NewReader(first.String()))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Gate == nil || decoded.Gate.Checks[0].Mode != FloorGateModeUnsupportedOnly {
		t.Fatalf("unsupported-only mode did not survive result encoding: %+v", decoded.Gate)
	}
	var rendered bytes.Buffer
	if err := RenderResult(&rendered, gated); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.String(), `mode: "unsupported_only"`) ||
		!strings.Contains(rendered.String(), `gate_outcome: "unsupported_only_passed"`) ||
		!strings.Contains(rendered.String(), `accuracy_status: "unmeasured"`) ||
		strings.Contains(rendered.String(), "accuracy pass") ||
		strings.Contains(rendered.String(), `gate_outcome: "accuracy_passed"`) {
		t.Fatalf("unsupported-only render is misleading: %s", rendered.String())
	}

	accuracyResult := completeAccuracyResult(t)
	accuracyGated, err := ApplyRatchet(accuracyResult, completeRatchet(accuracyResult, accuracyResult.Runs[0]))
	if err != nil {
		t.Fatal(err)
	}
	var accuracyRendered bytes.Buffer
	if err := RenderResult(&accuracyRendered, accuracyGated); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(accuracyRendered.String(), `mode: "accuracy"`) {
		t.Fatalf("default accuracy mode was not rendered: %s", accuracyRendered.String())
	}
}

func fullyUnsupportedResult(t *testing.T, caseCount int, states map[Engine]ObservationState, observed ...Engine) Result {
	t.Helper()
	catalog := validCatalog()
	cases := []OracleCase{validCase("unsupported-one", "CVE-2024-1111", TruthAffected)}
	if caseCount == 2 {
		cases = append(cases, validCase("unsupported-two", "CVE-2024-2222", TruthAffected))
	}
	for i := range cases {
		cases[i].ExpectedCoverage = expectedCoverage(CoverageUnsupported)
	}
	oracle := validOracle(cases...)
	if len(observed) == 0 {
		observed = Engines()
	}
	observations := make([]Observation, 0, len(observed))
	for _, engine := range observed {
		observation := completeObservation(catalog, engine)
		observation.State = ObservationUnsupported
		if state, exists := states[engine]; exists {
			observation.State = state
		}
		if observation.State == ObservationUnsupported {
			observation.CapabilityKind = CapabilityKindOSVScannerSUSERPM
			observation.CapabilityDigest = "sha256:" + hexDigest('8')
		}
		observations = append(observations, observation)
	}
	result, err := Reduce(catalog, oracle, observations)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func completeAccuracyResult(t *testing.T) Result {
	t.Helper()
	catalog := validCatalog()
	oracle := validOracle(
		validCase("affected", "CVE-2024-1111", TruthAffected),
		validCase("fixed", "CVE-2024-2222", TruthFixed),
	)
	observations := make([]Observation, 0, len(Engines()))
	for _, engine := range Engines() {
		observations = append(observations, withFinding(completeObservation(catalog, engine), "CVE-2024-1111"))
	}
	result, err := Reduce(catalog, oracle, observations)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func zeroFindingAccuracyResult(t *testing.T) Result {
	t.Helper()
	catalog := validCatalog()
	oracle := validOracle(
		validCase("affected", "CVE-2024-1111", TruthAffected),
		validCase("fixed", "CVE-2024-2222", TruthFixed),
	)
	observations := make([]Observation, 0, len(Engines()))
	for _, engine := range Engines() {
		observations = append(observations, completeObservation(catalog, engine))
	}
	result, err := Reduce(catalog, oracle, observations)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func unsupportedOnlyRatchet(result Result, maximumUnsupported int) Ratchet {
	ratchet := completeRatchet(result, result.Runs[0])
	for i := range ratchet.Floors {
		floor := &ratchet.Floors[i]
		floor.Expected.CapabilityKind = CapabilityKindOSVScannerSUSERPM
		floor.Expected.CapabilityDigest = "sha256:" + hexDigest('8')
		for _, actual := range result.Runs {
			if actual.Engine == floor.Expected.Engine && actual.TargetID == floor.Expected.TargetID {
				if actual.CapabilityKind != "" {
					floor.Expected.CapabilityKind = actual.CapabilityKind
					floor.Expected.CapabilityDigest = actual.CapabilityDigest
				}
				break
			}
		}
		floor.Mode = FloorGateModeUnsupportedOnly
		floor.MinimumCovered = intPointer(0)
		floor.MinimumAffectedRelations = intPointer(0)
		floor.MinimumNegativeRelations = intPointer(0)
		floor.MinimumPrecision = floatPointer(0)
		floor.MinimumRecall = floatPointer(0)
		floor.MaximumFalsePositives = intPointer(0)
		floor.MaximumFalseNegatives = intPointer(0)
		floor.MaximumUnknown = intPointer(0)
		floor.MaximumIncomplete = intPointer(0)
		floor.MaximumUnsupported = intPointer(maximumUnsupported)
	}
	return ratchet
}

func passingUnsupportedOnlyResult(t *testing.T) Result {
	t.Helper()
	result := fullyUnsupportedResult(t, 1, nil)
	gated, err := ApplyRatchet(result, unsupportedOnlyRatchet(result, 1))
	if err != nil {
		t.Fatal(err)
	}
	if gated.Gate == nil || !gated.Gate.Passed {
		t.Fatalf("unsupported-only setup gate = %+v", gated.Gate)
	}
	return gated
}

func runMetric(t *testing.T, result Result, engine Engine, targetID string) RunMetric {
	t.Helper()
	for _, metric := range result.RunMetrics {
		if metric.Run.Engine == engine && metric.Run.TargetID == targetID {
			return metric
		}
	}
	t.Fatalf("run metric not found for engine %q and target %q", engine, targetID)
	return RunMetric{}
}

func copyGate(gate *Gate) *Gate {
	copy := *gate
	copy.Ratchet = canonicalRatchet(gate.Ratchet)
	copy.Checks = append([]GateCheck(nil), gate.Checks...)
	for i := range copy.Checks {
		if copy.Checks[i].Actual != nil {
			actual := *copy.Checks[i].Actual
			copy.Checks[i].Actual = &actual
		}
		copy.Checks[i].ReasonCodes = append([]GateReasonCode(nil), gate.Checks[i].ReasonCodes...)
	}
	return &copy
}

func mutateBoundRun(result *Result, check GateCheck, mutate func(*RunIdentity)) {
	for i := range result.Runs {
		if result.Runs[i].Engine == check.Expected.Engine && result.Runs[i].TargetID == check.Expected.TargetID {
			mutate(&result.Runs[i])
			break
		}
	}
	for i := range result.RunMetrics {
		if result.RunMetrics[i].Run.Engine == check.Expected.Engine && result.RunMetrics[i].Run.TargetID == check.Expected.TargetID {
			mutate(&result.RunMetrics[i].Run)
			break
		}
	}
}

func mutateBoundMetrics(result *Result, check GateCheck, mutate func(*EngineResult)) {
	for i := range result.RunMetrics {
		if result.RunMetrics[i].Run.Engine == check.Expected.Engine && result.RunMetrics[i].Run.TargetID == check.Expected.TargetID {
			mutate(&result.RunMetrics[i].Metrics)
			break
		}
	}
	for i := range result.Engines {
		if result.Engines[i].Engine == check.Expected.Engine {
			mutate(&result.Engines[i])
			break
		}
	}
}

func removeRun(runs []RunIdentity, engine Engine, targetID string) []RunIdentity {
	out := make([]RunIdentity, 0, len(runs)-1)
	for _, run := range runs {
		if run.Engine != engine || run.TargetID != targetID {
			out = append(out, run)
		}
	}
	return out
}

func removeRunMetric(metrics []RunMetric, engine Engine, targetID string) []RunMetric {
	out := make([]RunMetric, 0, len(metrics)-1)
	for _, metric := range metrics {
		if metric.Run.Engine != engine || metric.Run.TargetID != targetID {
			out = append(out, metric)
		}
	}
	return out
}

func TestGateEmbedsReplayableRatchetAndRejectsTampering(t *testing.T) {
	result := fullyUnsupportedResult(t, 2, nil)
	ratchet := unsupportedOnlyRatchet(result, 1)
	gated, err := ApplyRatchet(result, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if gated.Gate == nil || gated.Gate.Passed || len(gated.Gate.Ratchet.Floors) != len(ratchet.Floors) {
		t.Fatalf("replayable failed gate = %+v", gated.Gate)
	}
	if digest, err := DigestRatchet(gated.Gate.Ratchet); err != nil || digest != gated.Gate.RatchetDigest {
		t.Fatalf("embedded ratchet digest = %q, %v; want %q", digest, err, gated.Gate.RatchetDigest)
	}
	if !hasGateReason(gated.Gate, GateReasonThresholdBreach) {
		t.Fatalf("one-target unsupported=2/max=1 must be a threshold breach: %+v", gated.Gate)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Result)
	}{
		{
			name: "clearing a real threshold breach",
			mutate: func(result *Result) {
				result.Gate.Checks[0].ReasonCodes = nil
				result.Gate.Checks[0].Passed = true
			},
		},
		{
			name: "adding a reason",
			mutate: func(result *Result) {
				addGateReason(&result.Gate.Checks[0], GateReasonCoverageContractBreach)
			},
		},
		{
			name: "removing a reason",
			mutate: func(result *Result) {
				result.Gate.Checks[0].ReasonCodes = []GateReasonCode{GateReasonCoverageContractBreach}
			},
		},
		{
			name: "flipping a check pass",
			mutate: func(result *Result) {
				result.Gate.Checks[0].Passed = true
			},
		},
		{
			name: "flipping aggregate pass",
			mutate: func(result *Result) {
				result.Gate.Passed = true
			},
		},
		{
			name: "altering every expected pin",
			mutate: func(result *Result) {
				expected := &result.Gate.Checks[0].Expected
				expected.TargetID = "tampered-target"
				expected.TargetDigest = "sha256:" + hexDigest('a')
				expected.SBOMDigest = "sha256:" + hexDigest('b')
				expected.Engine = EngineTrivy
				expected.EngineVersion = "tampered-engine"
				expected.EngineBinaryDigest = "sha256:" + hexDigest('c')
				expected.DatabaseBuild = "tampered-database"
				expected.DatabaseDigest = "sha256:" + hexDigest('d')
				expected.EnvironmentID = "tampered-environment"
				expected.EnvironmentDigest = "sha256:" + hexDigest('e')
				expected.ConfigDigest = "sha256:" + hexDigest('f')
			},
		},
		{
			name: "changing actual run",
			mutate: func(result *Result) {
				actual := *result.Gate.Checks[0].Actual
				actual.EnvironmentDigest = "sha256:" + hexDigest('a')
				result.Gate.Checks[0].Actual = &actual
			},
		},
		{
			name: "altering embedded threshold without ratchet digest",
			mutate: func(result *Result) {
				*result.Gate.Ratchet.Floors[0].MaximumUnsupported = 2
			},
		},
		{
			name: "altering ratchet digest",
			mutate: func(result *Result) {
				result.Gate.RatchetDigest = "sha256:" + hexDigest('a')
			},
		},
		{
			name: "deleting embedded policy",
			mutate: func(result *Result) {
				result.Gate.Ratchet = Ratchet{}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tampered := copyResult(gated)
			test.mutate(&tampered)
			var err error
			tampered.ID, err = DigestResult(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if err := tampered.Validate(); err == nil {
				t.Fatal("self-digested tampered gate was accepted")
			}
		})
	}

	var encoded bytes.Buffer
	if err := EncodeResult(&encoded, gated); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "null policy", mutate: func(gate map[string]any) { gate["ratchet"] = nil }},
		{name: "missing policy", mutate: func(gate map[string]any) { delete(gate, "ratchet") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copyDocument := cloneJSONDocument(t, document)
			test.mutate(copyDocument["gate"].(map[string]any))
			body, err := json.Marshal(copyDocument)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeResult(strings.NewReader(string(body))); err == nil {
				t.Fatal("digest-only or null-policy gate was accepted")
			}
		})
	}
}

func TestGateReplayRejectsBothModeFlips(t *testing.T) {
	for _, test := range []struct {
		name   string
		result func(*testing.T) Result
		mode   FloorGateMode
	}{
		{
			name: "accuracy to unsupported-only",
			result: func(t *testing.T) Result {
				base := completeAccuracyResult(t)
				gated, err := ApplyRatchet(base, completeRatchet(base, base.Runs[0]))
				if err != nil {
					t.Fatal(err)
				}
				return gated
			},
			mode: FloorGateModeUnsupportedOnly,
		},
		{
			name: "unsupported-only to accuracy",
			result: func(t *testing.T) Result {
				return passingUnsupportedOnlyResult(t)
			},
			mode: FloorGateModeAccuracy,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tampered := copyResult(test.result(t))
			tampered.Gate.Checks[0].Mode = test.mode
			var err error
			tampered.ID, err = DigestResult(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if err := tampered.Validate(); err == nil {
				t.Fatal("self-digested mode flip was accepted")
			}
		})
	}
}

func TestGateSnapshotsRatchetAndPreservesFailedEvidence(t *testing.T) {
	result := completeAccuracyResult(t)
	for _, test := range []struct {
		name   string
		mutate func(*Ratchet)
	}{
		{
			name: "pin mismatch",
			mutate: func(ratchet *Ratchet) {
				ratchet.Floors[0].Expected.EngineBinaryDigest = "sha256:" + hexDigest('a')
			},
		},
		{
			name: "catalog mismatch",
			mutate: func(ratchet *Ratchet) {
				ratchet.CatalogDigest = "sha256:" + hexDigest('a')
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ratchet := completeRatchet(result, result.Runs[0])
			test.mutate(&ratchet)
			gated, err := ApplyRatchet(result, ratchet)
			if err != nil {
				t.Fatal(err)
			}
			if gated.Gate == nil || gated.Gate.Passed || !hasGateReason(gated.Gate, GateReasonPinMismatch) {
				t.Fatalf("failed %s gate = %+v", test.name, gated.Gate)
			}
			var encoded, rendered bytes.Buffer
			if err := EncodeResult(&encoded, gated); err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeResult(bytes.NewReader(encoded.Bytes()))
			if err != nil {
				t.Fatalf("failed %s evidence did not decode: %v", test.name, err)
			}
			if err := RenderResult(&rendered, decoded); err != nil {
				t.Fatalf("failed %s evidence did not render: %v", test.name, err)
			}
		})
	}

	base := fullyUnsupportedResult(t, 1, nil)
	original := unsupportedOnlyRatchet(base, 1)
	gated, err := ApplyRatchet(base, original)
	if err != nil {
		t.Fatal(err)
	}
	before, err := DigestResult(gated)
	if err != nil {
		t.Fatal(err)
	}
	original.Floors[0].Expected.EngineVersion = "changed-after-apply"
	*original.Floors[0].MaximumUnsupported = 99
	if gated.Gate.Ratchet.Floors[0].Expected.EngineVersion == original.Floors[0].Expected.EngineVersion || *gated.Gate.Ratchet.Floors[0].MaximumUnsupported == *original.Floors[0].MaximumUnsupported {
		t.Fatal("gate retained aliases to the caller ratchet")
	}
	after, err := DigestResult(gated)
	if err != nil {
		t.Fatal(err)
	}
	if before != after || gated.Validate() != nil {
		t.Fatal("mutating the caller ratchet changed the result snapshot")
	}
}

func TestEncodeResultRejectsReplayableGateExpansionBeforeWriting(t *testing.T) {
	catalog, oracle, observations, result, ratchet := mixedMatrixResultWithVersionSuffix(t, strings.Repeat("x", 350_000))
	requireSubLimit := func(name string, document []byte) {
		t.Helper()
		if int64(len(document)) >= MaxJSONBytes {
			t.Fatalf("%s is %d bytes, not below %d", name, len(document), MaxJSONBytes)
		}
	}

	catalogDocument, err := CanonicalJSON(canonicalCatalog(catalog))
	if err != nil {
		t.Fatal(err)
	}
	catalogDocument = append(catalogDocument, '\n')
	requireSubLimit("catalog", catalogDocument)
	if _, err := DecodeCatalog(bytes.NewReader(catalogDocument)); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}

	oracleDocument, err := CanonicalJSON(canonicalOracle(oracle))
	if err != nil {
		t.Fatal(err)
	}
	oracleDocument = append(oracleDocument, '\n')
	requireSubLimit("oracle", oracleDocument)
	if _, err := DecodeOracle(bytes.NewReader(oracleDocument)); err != nil {
		t.Fatalf("decode oracle: %v", err)
	}

	ratchetDocument, err := CanonicalJSON(canonicalRatchet(ratchet))
	if err != nil {
		t.Fatal(err)
	}
	ratchetDocument = append(ratchetDocument, '\n')
	requireSubLimit("ratchet", ratchetDocument)
	if _, err := DecodeRatchet(bytes.NewReader(ratchetDocument)); err != nil {
		t.Fatalf("decode ratchet: %v", err)
	}

	for _, observation := range observations {
		set := ObservationSet{
			SchemaVersion:   ObservationSchemaVersion,
			CatalogRevision: catalog.Revision,
			CatalogDigest:   result.CatalogDigest,
			Observations:    []Observation{observation},
		}
		var document bytes.Buffer
		if err := EncodeObservationSet(&document, set); err != nil {
			t.Fatalf("encode %s/%s observation: %v", observation.Engine, observation.TargetID, err)
		}
		requireSubLimit(string(observation.Engine)+"/"+observation.TargetID+" observation", document.Bytes())
		if _, err := DecodeObservationSet(bytes.NewReader(document.Bytes())); err != nil {
			t.Fatalf("decode %s/%s observation: %v", observation.Engine, observation.TargetID, err)
		}
	}

	var ungated bytes.Buffer
	if err := EncodeResult(&ungated, result); err != nil {
		t.Fatal(err)
	}
	requireSubLimit("ungated result", ungated.Bytes())
	if _, err := DecodeResult(bytes.NewReader(ungated.Bytes())); err != nil {
		t.Fatalf("decode ungated result: %v", err)
	}

	gated, err := ApplyRatchet(result, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	gatedDocument, err := CanonicalJSON(canonicalResult(gated))
	if err != nil {
		t.Fatal(err)
	}
	gatedDocument = append(gatedDocument, '\n')
	if int64(len(gatedDocument)) <= MaxJSONBytes {
		t.Fatalf("gated result is %d bytes, not above %d", len(gatedDocument), MaxJSONBytes)
	}

	var output bytes.Buffer
	err = EncodeResult(&output, gated)
	if err == nil {
		t.Fatal("oversized gated result was encoded")
	}
	if !strings.Contains(err.Error(), "8388608") {
		t.Fatalf("oversized gated result error = %q", err)
	}
	if output.Len() != 0 {
		t.Fatalf("oversized gated result wrote %d bytes", output.Len())
	}
}

func TestRenderResultReportsMixedGateOutcomesWithoutClaimingUnsupportedAccuracy(t *testing.T) {
	result, ratchet := mixedMatrixResult(t)
	gated, err := ApplyRatchet(result, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if gated.Gate == nil || !gated.Gate.Passed {
		t.Fatalf("mixed gate = %+v", gated.Gate)
	}
	for _, targetID := range []string{"debian", "suse"} {
		for _, engine := range Engines() {
			check := gateCheck(gated.Gate, engine, targetID)
			metric := runMetric(t, gated, engine, targetID).Metrics
			unsupported := engine == EngineOSVScanner && targetID == "suse"
			if check == nil || !check.Passed {
				t.Fatalf("missing or failed %s/%s check: %+v", engine, targetID, check)
			}
			if unsupported {
				if check.Mode.effective() != FloorGateModeUnsupportedOnly || renderCheckOutcome(*check) != "unsupported_only_passed" || metric.Unsupported != 2 || metric.Precision != nil || metric.Recall != nil {
					t.Fatalf("unsupported-only %s/%s metric = %+v, check = %+v", engine, targetID, metric, check)
				}
			} else if check.Mode.effective() != FloorGateModeAccuracy || renderCheckOutcome(*check) != "accuracy_passed" || metric.Covered != 2 || metric.AffectedRelations != 1 || metric.NegativeRelations != 1 || metric.Precision == nil || metric.Recall == nil {
				t.Fatalf("accuracy %s/%s metric = %+v, check = %+v", engine, targetID, metric, check)
			}
		}
	}

	var first, second bytes.Buffer
	if err := EncodeResult(&first, gated); err != nil {
		t.Fatal(err)
	}
	if len(first.Bytes()) >= int(MaxJSONBytes) {
		t.Fatalf("intended mixed matrix encoding is %d bytes, exceeding %d", first.Len(), MaxJSONBytes)
	}
	decoded, err := DecodeResult(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ID != gated.ID {
		t.Fatalf("mixed matrix round-trip digest = %q, want %q", decoded.ID, gated.ID)
	}
	if err := RenderResult(&second, decoded); err != nil {
		t.Fatal(err)
	}
	rendered := second.String()
	if strings.Count(rendered, `gate_outcome: "accuracy_passed"`) != 7 ||
		strings.Count(rendered, `gate_outcome: "unsupported_only_passed"`) != 1 ||
		!strings.Contains(rendered, `gate_outcome: "mixed_passed"`) ||
		!strings.Contains(rendered, `accuracy_status: "partially_measured"`) ||
		!strings.Contains(rendered, `accuracy_status: "unmeasured"`) {
		t.Fatalf("mixed gate rendering = %s", rendered)
	}

	permuted := copyResult(result)
	reverseTargets(permuted.Targets)
	reverseRuns(permuted.Runs)
	reverseRunMetrics(permuted.RunMetrics)
	reverseEngineResults(permuted.Engines)
	permutedRatchet := canonicalRatchet(ratchet)
	reverseRatchetFloors(permutedRatchet.Floors)
	permutedGated, err := ApplyRatchet(permuted, permutedRatchet)
	if err != nil {
		t.Fatal(err)
	}
	if permutedGated.ID != gated.ID {
		t.Fatalf("mixed gate permutation changed result digest: %q != %q", permutedGated.ID, gated.ID)
	}
	var permutedRendered bytes.Buffer
	if err := RenderResult(&permutedRendered, permutedGated); err != nil {
		t.Fatal(err)
	}
	if permutedRendered.String() != rendered {
		t.Fatalf("mixed gate permutation changed rendering:\n%s\n---\n%s", permutedRendered.String(), rendered)
	}
}

func copyResult(result Result) Result {
	copy := result
	copy.Targets = append([]TargetIdentity(nil), result.Targets...)
	copy.Runs = append([]RunIdentity(nil), result.Runs...)
	copy.RunMetrics = append([]RunMetric(nil), result.RunMetrics...)
	copy.Engines = append([]EngineResult(nil), result.Engines...)
	copy.Diagnostics = append([]Diagnostic(nil), result.Diagnostics...)
	if result.Gate != nil {
		copy.Gate = copyGate(result.Gate)
	}
	return copy
}

func cloneJSONDocument(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var copy map[string]any
	if err := json.Unmarshal(encoded, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func mixedMatrixResult(t *testing.T) (Result, Ratchet) {
	_, _, _, result, ratchet := mixedMatrixResultWithVersionSuffix(t, "")
	return result, ratchet
}

func mixedMatrixResultWithVersionSuffix(t *testing.T, versionSuffix string) (Catalog, Oracle, []Observation, Result, Ratchet) {
	t.Helper()
	catalog := validCatalog()
	debian := catalog.Targets[0]
	debian.ID = "debian"
	debian.OCIRef = "registry.example/synapse/debian@" + debian.Digest
	debian.Components = []Component{{PURL: "pkg:deb/debian-example@1.2.3"}}
	catalog.Targets[0] = debian
	suse := debian
	suse.ID = "suse"
	suse.Digest = "sha256:" + hexDigest('e')
	suse.SBOMDigest = "sha256:" + hexDigest('f')
	suse.OCIRef = "registry.example/synapse/suse@" + suse.Digest
	suse.Components = []Component{{PURL: "pkg:rpm/suse-example@1.2.3"}}
	catalog.Targets = append(catalog.Targets, suse)
	debianAffected := validCase("debian-affected", "CVE-2024-1111", TruthAffected)
	debianAffected.TargetID = debian.ID
	debianAffected.Component = debian.Components[0]
	debianFixed := validCase("debian-fixed", "CVE-2024-1112", TruthFixed)
	debianFixed.TargetID = debian.ID
	debianFixed.Component = debian.Components[0]
	suseAffected := validCase("suse-affected", "CVE-2024-2222", TruthAffected)
	suseAffected.TargetID = suse.ID
	suseAffected.Component = suse.Components[0]
	suseAffected.ExpectedCoverage[EngineOSVScanner] = CoverageUnsupported
	suseFixed := validCase("suse-fixed", "CVE-2024-2223", TruthFixed)
	suseFixed.TargetID = suse.ID
	suseFixed.Component = suse.Components[0]
	suseFixed.ExpectedCoverage[EngineOSVScanner] = CoverageUnsupported
	oracle := validOracle(debianAffected, debianFixed, suseAffected, suseFixed)
	observations := make([]Observation, 0, len(catalog.Targets)*len(Engines()))
	for _, target := range catalog.Targets {
		for _, engine := range Engines() {
			observation := completeObservationForTarget(catalog, engine, target.ID)
			observation.EngineVersion += versionSuffix
			if target.ID == "suse" && engine == EngineOSVScanner {
				observation.State = ObservationUnsupported
				observation.CapabilityKind = CapabilityKindOSVScannerSUSERPM
				observation.CapabilityDigest = "sha256:" + hexDigest('8')
			} else {
				advisory := "CVE-2024-1111"
				if target.ID == "suse" {
					advisory = "CVE-2024-2222"
				}
				observation.Findings = []Finding{{Component: target.Components[0], AdvisoryID: advisory}}
			}
			observations = append(observations, observation)
		}
	}
	result, err := Reduce(catalog, oracle, observations)
	if err != nil {
		t.Fatal(err)
	}
	ratchet := completeRatchet(result, result.Runs[0])
	for i := range ratchet.Floors {
		floor := &ratchet.Floors[i]
		if floor.Expected.Engine == EngineOSVScanner && floor.Expected.TargetID == "suse" {
			floor.Expected.CapabilityKind = CapabilityKindOSVScannerSUSERPM
			floor.Expected.CapabilityDigest = "sha256:" + hexDigest('8')
			floor.Mode = FloorGateModeUnsupportedOnly
			floor.MinimumCovered = intPointer(0)
			floor.MinimumAffectedRelations = intPointer(0)
			floor.MinimumNegativeRelations = intPointer(0)
			floor.MinimumPrecision = floatPointer(0)
			floor.MinimumRecall = floatPointer(0)
			floor.MaximumFalsePositives = intPointer(0)
			floor.MaximumFalseNegatives = intPointer(0)
			floor.MaximumUnknown = intPointer(0)
			floor.MaximumIncomplete = intPointer(0)
			floor.MaximumUnsupported = intPointer(2)
			continue
		}
		floor.MinimumCovered = intPointer(2)
		floor.MinimumAffectedRelations = intPointer(1)
		floor.MinimumNegativeRelations = intPointer(1)
		floor.MinimumPrecision = floatPointer(1)
		floor.MinimumRecall = floatPointer(1)
		floor.MaximumFalsePositives = intPointer(0)
		floor.MaximumFalseNegatives = intPointer(0)
		floor.MaximumUnknown = intPointer(0)
		floor.MaximumIncomplete = intPointer(0)
		floor.MaximumUnsupported = intPointer(0)
	}
	return catalog, oracle, observations, result, ratchet
}

func reverseTargets(values []TargetIdentity) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reverseRuns(values []RunIdentity) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reverseRunMetrics(values []RunMetric) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reverseEngineResults(values []EngineResult) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reverseRatchetFloors(values []RatchetFloor) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

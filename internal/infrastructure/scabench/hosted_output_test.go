package scabench

import (
	"strings"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestParseHostedExternalOutputNormalizesSupportedComparatorWires(t *testing.T) {
	target := bench.Target{Components: []bench.Component{{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"}}}
	cases := []struct {
		name    string
		engine  bench.Engine
		version string
		scan    string
		probe   string
	}{
		{
			name:    "grype",
			engine:  bench.EngineGrype,
			version: "0.115.0",
			scan:    `{"descriptor":{"name":"grype","version":"0.115.0"},"matches":[{"vulnerability":{"id":"CVE-2024-0001"},"artifact":{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"}},{"vulnerability":{"id":"CVE-2024-0001"},"artifact":{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"}}]}`,
		},
		{
			name:    "trivy",
			engine:  bench.EngineTrivy,
			version: "0.74.0",
			scan:    `{"SchemaVersion":2,"Trivy":{"Version":"0.74.0"},"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","PkgIdentifier":{"PURL":"pkg:npm/a@1.0.0"},"InstalledVersion":"1.0.0"}]}]}`,
		},
		{
			name:    "osv",
			engine:  bench.EngineOSVScanner,
			version: "v2.5.1",
			probe:   "osv-scanner version: v2.5.1\n",
			scan:    `{"results":[{"packages":[{"package":{"name":"a","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":"CVE-2024-0001"}]}]}]}`,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			findings, err := ParseHostedExternalOutput(test.engine, target, test.version, []byte(test.scan), []byte(test.probe))
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].AdvisoryID != "CVE-2024-0001" || findings[0].Component.PURL != target.Components[0].PURL {
				t.Fatalf("normalized findings = %#v", findings)
			}
		})
	}
}

func TestParseHostedExternalOutputRejectsUntrustedOrUnusableInputs(t *testing.T) {
	target := bench.Target{Components: []bench.Component{{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"}}}
	validGrype := `{"descriptor":{"name":"grype","version":"0.115.0"},"matches":[]}`
	cases := []struct {
		name    string
		engine  bench.Engine
		version string
		scan    []byte
		probe   []byte
	}{
		{name: "unsupported engine", engine: bench.EngineOwned, version: "1", scan: []byte(`{}`)},
		{name: "missing scan", engine: bench.EngineGrype, version: "0.115.0"},
		{name: "oversized scan", engine: bench.EngineGrype, version: "0.115.0", scan: []byte(strings.Repeat("x", int(HostedExternalOutputMaxBytes)+1))},
		{name: "malformed scan", engine: bench.EngineGrype, version: "0.115.0", scan: []byte(`{"descriptor":`)},
		{name: "wrong grype version", engine: bench.EngineGrype, version: "0.115.1", scan: []byte(validGrype)},
		{name: "missing OSV probe", engine: bench.EngineOSVScanner, version: "v2.5.1", scan: []byte(`{"results":[]}`)},
		{name: "wrong OSV version", engine: bench.EngineOSVScanner, version: "v2.5.1", scan: []byte(`{"results":[]}`), probe: []byte("osv-scanner version: v2.5.0\n")},
		{name: "unknown component", engine: bench.EngineGrype, version: "0.115.0", scan: []byte(`{"descriptor":{"name":"grype","version":"0.115.0"},"matches":[{"vulnerability":{"id":"CVE-2024-0001"},"artifact":{"purl":"pkg:npm/b@1.0.0","version":"1.0.0"}}]}`)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if findings, err := ParseHostedExternalOutput(test.engine, target, test.version, test.scan, test.probe); err == nil || findings != nil {
				t.Fatalf("findings=%#v err=%v, want rejection", findings, err)
			}
		})
	}
}

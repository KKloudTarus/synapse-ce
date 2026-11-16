package sca

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/grype"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type grypeUnfixedRunner struct{ t *testing.T }

func (r grypeUnfixedRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	r.t.Helper()
	if !slices.Contains(spec.Args, "--add-cpes-if-none") {
		r.t.Error("Grype needs CPE synthesis to find Alpine advisories outside secdb")
	}
	return ports.ToolResult{Stdout: []byte(`{
	  "matches": [
	    {"vulnerability":{"id":"CVE-2025-60876","severity":"Medium","fix":{"versions":[],"state":""}},"artifact":{"name":"busybox","version":"1.36.1-r19","purl":"pkg:apk/alpine/busybox@1.36.1-r19?distro=alpine-3.19"}},
	    {"vulnerability":{"id":"CVE-2025-60876","severity":"Medium","fix":{"versions":[],"state":""}},"artifact":{"name":"busybox-binsh","version":"1.36.1-r19","purl":"pkg:apk/alpine/busybox-binsh@1.36.1-r19?distro=alpine-3.19&upstream=busybox"}},
	    {"vulnerability":{"id":"CVE-2025-60876","severity":"Medium","fix":{"versions":[],"state":""}},"artifact":{"name":"ssl_client","version":"1.36.1-r19","purl":"pkg:apk/alpine/ssl_client@1.36.1-r19?distro=alpine-3.19&upstream=busybox"}},
	    {"vulnerability":{"id":"CVE-2026-27171","severity":"High","fix":{"versions":[],"state":"unknown"}},"artifact":{"name":"zlib","version":"1.3.1-r0","purl":"pkg:apk/alpine/zlib@1.3.1-r0?distro=alpine-3.19"}},
	    {"vulnerability":{"id":"CVE-2025-46394","severity":"Low","fix":{"versions":["1.36.1-r21"],"state":"fixed"}},"artifact":{"name":"busybox","version":"1.36.1-r19","purl":"pkg:apk/alpine/busybox@1.36.1-r19?distro=alpine-3.19"}}
	  ],
	  "descriptor":{"version":"0.121.2","db":{"status":{"schemaVersion":"v6.1.10","built":"2026-11-08T06:19:57Z"}}}
	}`)}, nil
}

func TestGrypeUnfixedAdvisoriesSurviveScan(t *testing.T) {
	for _, ignoreUnfixed := range []bool{false, true} {
		name := "default"
		if ignoreUnfixed {
			name = "ignore-unfixed"
		}
		t.Run(name, func(t *testing.T) {
			doc := &sbom.SBOM{Components: []sbom.Component{
				{Name: "busybox", Version: "1.36.1-r19", PURL: "pkg:apk/alpine/busybox@1.36.1-r19?distro=alpine-3.19"},
				{Name: "busybox-binsh", Version: "1.36.1-r19", PURL: "pkg:apk/alpine/busybox-binsh@1.36.1-r19?distro=alpine-3.19&upstream=busybox"},
				{Name: "ssl_client", Version: "1.36.1-r19", PURL: "pkg:apk/alpine/ssl_client@1.36.1-r19?distro=alpine-3.19&upstream=busybox"},
				{Name: "zlib", Version: "1.3.1-r0", PURL: "pkg:apk/alpine/zlib@1.3.1-r0?distro=alpine-3.19"},
			}}
			svc := NewService(
				&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
				ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityInfo, 0,
				&fakeAcquirer{dir: t.TempDir()}, &fakeDetector{}, staticSBOM{doc: doc},
				[]ports.DetectionSource{fakeSource{name: "osv"}, grype.New("grype", "").WithRunner(grypeUnfixedRunner{t})}, nil, nil, nil,
			)
			svc.SetIgnoreUnfixed(ignoreUnfixed)
			res, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"}, ScanOptions{Mode: ScanModeVulnerabilities})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Vulnerabilities) != 5 || !res.Completeness.Confident {
				t.Fatalf("expected complete inventory of five advisories: vulns=%+v completeness=%+v", res.Vulnerabilities, res.Completeness)
			}
			for _, v := range res.Vulnerabilities {
				if v.ID == "CVE-2025-46394" {
					if v.FixedVersion != "1.36.1-r21" || v.FixStatus != vulnerability.FixStatusAvailable {
						t.Fatalf("lost fixed advisory remediation: %+v", v)
					}
				} else if v.FixedVersion != "" || v.FixStatus != vulnerability.FixStatusUnknown {
					t.Fatalf("unknown fix must remain visible without an invented fix: %+v", v)
				}
			}
			wantFindings, wantSuppressed := 5, 0
			if ignoreUnfixed {
				wantFindings, wantSuppressed = 1, 4
			}
			if len(res.Findings) != wantFindings || res.UnfixedSuppressed != wantSuppressed {
				t.Fatalf("findings=%d suppressed=%d, want %d/%d", len(res.Findings), res.UnfixedSuppressed, wantFindings, wantSuppressed)
			}
		})
	}
}

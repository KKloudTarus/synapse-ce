package codeanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSwiftATSPlist(t *testing.T) {
	const open = `<?xml version="1.0"?><plist version="1.0"><dict>
<key>NSAppTransportSecurity</key><dict>
<key>NSAllowsArbitraryLoads</key><true/>
<key>NSAllowsArbitraryLoadsInWebContent</key><true/>
<key>NSAllowsArbitraryLoadsForMedia</key><true/>
<key>NSExceptionDomains</key><dict><key>example.test</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict></dict>
</dict></dict></plist>`
	got := scanSwiftATSPlist("Info.plist", []byte(open))
	if len(got) != 4 {
		t.Fatalf("findings = %d, want 4: %+v", len(got), got)
	}
	for _, f := range got {
		if f.RuleID != swiftATSDisabledRuleID || f.Line < 1 || f.CWE != "CWE-319" {
			t.Fatalf("invalid ATS finding: %+v", f)
		}
	}

	const safe = `<?xml version="1.0"?><plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><false/></dict></dict></plist>`
	if got := scanSwiftATSPlist("Info.plist", []byte(safe)); len(got) != 0 {
		t.Fatalf("safe plist findings = %+v", got)
	}
	const unrelated = `<?xml version="1.0"?><plist version="1.0"><dict><key>Other</key><string>NSAllowsArbitraryLoads true</string></dict></plist>`
	if got := scanSwiftATSPlist("Info.plist", []byte(unrelated)); len(got) != 0 {
		t.Fatalf("unrelated plist findings = %+v", got)
	}
	if got := scanSwiftATSPlist("Info.plist", []byte("<plist><dict>")); len(got) != 0 {
		t.Fatalf("malformed plist findings = %+v", got)
	}
	for _, boolean := range []string{"<true>false</true>", "<false>true</false>"} {
		plist := `<plist><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key>` + boolean + `</dict></dict></plist>`
		if got := scanSwiftATSPlist("Info.plist", []byte(plist)); len(got) != 0 {
			t.Fatalf("boolean content findings = %+v", got)
		}
	}
}

func TestSwiftATSPlistLimitExhaustionTruncates(t *testing.T) {
	deep := `<plist><dict><key>NSAppTransportSecurity</key>` + strings.Repeat(`<dict><key>x</key>`, maxPlistDepth) + `<true/>` + strings.Repeat(`</dict>`, maxPlistDepth) + `</dict></plist>`
	if _, truncated := scanSwiftATSPlistWithTruncation("Info.plist", []byte(deep)); !truncated {
		t.Fatal("depth limit did not truncate")
	}
	if _, truncated := scanXMLFileWithTruncation("Info.plist", []byte(deep)); !truncated {
		t.Fatal("XML scanner did not propagate plist depth truncation")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Info.plist"), []byte(deep), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !report.Truncated {
		t.Fatal("analyzer did not propagate plist depth truncation")
	}

	p := newPlistParser([]byte(`<string>x</string>`))
	p.values = maxPlistValues
	if _, ok := p.parseValue(1); ok || !p.limited {
		t.Fatal("value limit did not truncate")
	}
}

func TestSwiftATSPlistRejectsNamespacesAndDeepValues(t *testing.T) {
	const namespaced = `<plist xmlns="urn:test"><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>`
	if got := scanSwiftATSPlist("Info.plist", []byte(namespaced)); len(got) != 0 {
		t.Fatalf("namespaced plist findings = %+v", got)
	}
	const namespacedValue = `<plist><dict><key>NSAppTransportSecurity</key><dict xmlns="urn:test"><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>`
	if got := scanSwiftATSPlist("Info.plist", []byte(namespacedValue)); len(got) != 0 {
		t.Fatalf("namespaced value findings = %+v", got)
	}

	deep := `<plist><dict><key>NSAppTransportSecurity</key>` + strings.Repeat(`<dict><key>x</key>`, maxPlistDepth) + `<true/>` + strings.Repeat(`</dict>`, maxPlistDepth) + `</dict></plist>`
	if got := scanSwiftATSPlist("Info.plist", []byte(deep)); len(got) != 0 {
		t.Fatalf("deep plist findings = %+v", got)
	}
}

func TestSwiftATSPlistCapsAndOrdersDomainFindings(t *testing.T) {
	var domains strings.Builder
	for i := maxFindings + 10; i > 0; i-- {
		fmt.Fprintf(&domains, `<key>%04d.test</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict>`, i)
	}
	plist := `<plist><dict><key>NSAppTransportSecurity</key><dict><key>NSExceptionDomains</key><dict>` + domains.String() + `</dict></dict></dict></plist>`
	got := scanSwiftATSPlist("Info.plist", []byte(plist))
	if len(got) != maxFindings {
		t.Fatalf("ATS finding count = %d, want cap %d", len(got), maxFindings)
	}
	if got[0].Description != "App Transport Security permits insecure HTTP loads for domain 0001.test." || got[len(got)-1].Description != "App Transport Security permits insecure HTTP loads for domain 2000.test." {
		t.Fatalf("ATS domain order = first %+v, last %+v", got[0], got[len(got)-1])
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Info.plist"), []byte(plist), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings.Findings) != maxFindings {
		t.Fatalf("analyzer finding count = %d, want cap %d", len(findings.Findings), maxFindings)
	}
}

func TestSwiftATSPlistTemporaryDomainExceptions(t *testing.T) {
	const plist = `<?xml version="1.0"?>
<plist version="1.0">
<dict>
<key>NSAppTransportSecurity</key>
<dict>
<key>NSExceptionDomains</key>
<dict>
<key>alpha.test</key>
<dict>
<key>NSTemporaryExceptionAllowsInsecureHTTPLoads</key>
<true/>
<key>NSExceptionAllowsInsecureHTTPLoads</key>
<true/>
</dict>
<key>beta.test</key>
<dict>
<key>NSExceptionAllowsInsecureHTTPLoads</key>
<false/>
<key>NSTemporaryExceptionAllowsInsecureHTTPLoads</key>
<false/>
</dict>
</dict>
</dict>
</dict>
</plist>`
	got := scanSwiftATSPlist("Info.plist", []byte(plist))
	if len(got) != 2 {
		t.Fatalf("ATS findings = %d, want 2: %+v", len(got), got)
	}
	if got[0].Line != 13 || got[1].Line != 11 {
		t.Fatalf("ATS key order or lines = %+v", got)
	}
	for _, finding := range got {
		if finding.Description != "App Transport Security permits insecure HTTP loads for domain alpha.test." {
			t.Fatalf("unexpected domain finding: %+v", finding)
		}
	}
}

func TestSwiftATSPlistDispatchOrderAndLines(t *testing.T) {
	const plist = `<?xml version="1.0"?>
<plist version="1.0">
<dict>
<key>NSAppTransportSecurity</key>
<dict>
<key>NSAllowsArbitraryLoads</key>
<true/>
<key>NSAllowsArbitraryLoadsInWebContent</key>
<true/>
<key>NSExceptionDomains</key>
<dict>
<key>z.test</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict>
<key>a.test</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict>
</dict>
</dict>
</dict>
</plist>`
	got := scanXMLFile("Info.plist", []byte(plist))
	var ats []string
	for _, finding := range got {
		if finding.RuleID == swiftATSDisabledRuleID {
			ats = append(ats, finding.Description)
		}
		if finding.RuleID == xmlSchemaMissingRuleID {
			t.Fatalf("generic XML maintainability finding on plist: %+v", finding)
		}
	}
	if len(ats) != 4 || got[0].Line != 7 || got[1].Line != 9 {
		t.Fatalf("ATS findings or lines = %+v", got)
	}
	direct := scanSwiftATSPlist("Info.plist", []byte(plist))
	if direct[2].Description != "App Transport Security permits insecure HTTP loads for domain a.test." || direct[3].Description != "App Transport Security permits insecure HTTP loads for domain z.test." {
		t.Fatalf("direct domain finding order = %+v", direct)
	}

	const nested = `<config><plist><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist></config>`
	for _, finding := range scanXMLFile("Info.plist", []byte(nested)) {
		if finding.RuleID == swiftATSDisabledRuleID {
			t.Fatalf("nested plist emitted ATS finding: %+v", finding)
		}
	}
}

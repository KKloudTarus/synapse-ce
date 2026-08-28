package license

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestClassify(t *testing.T) {
	cases := map[string]sbom.LicenseCategory{
		"MIT":                  sbom.LicensePermissive,
		"apache-2.0":           sbom.LicensePermissive, // case-insensitive
		"BSD-3-Clause":         sbom.LicensePermissive,
		"MPL-2.0":              sbom.LicenseWeakCopyleft,
		"LGPL-3.0-only":        sbom.LicenseWeakCopyleft, // -only suffix stripped
		"GPL-3.0-only":         sbom.LicenseCopyleft,
		"AGPL-3.0-or-later":    sbom.LicenseCopyleft,   // -or-later suffix stripped
		"GPL-2.0+":             sbom.LicenseCopyleft,   // + stripped
		"MIT OR Apache-2.0":    sbom.LicensePermissive, // OR → most permissive
		"MIT AND GPL-3.0-only": sbom.LicenseCopyleft,   // AND → most restrictive
		"GPL-3.0-only OR MIT":  sbom.LicensePermissive,
		"(MIT OR Apache-2.0)":  sbom.LicensePermissive, // parens
		"SomeUnknownThing":     sbom.LicenseUnknown,
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyFreeTextNames(t *testing.T) {
	// Human license NAMES (from registries / JAR pom <licenses>) that are NOT SPDX ids —
	// these previously classified as unknown.
	cases := map[string]sbom.LicenseCategory{
		"MIT License":                              sbom.LicensePermissive,
		"The MIT License":                          sbom.LicensePermissive, // leading "The" dropped
		"Apache License, Version 2.0":              sbom.LicensePermissive,
		"Apache License 2.0":                       sbom.LicensePermissive,
		"The Apache Software License, Version 2.0": sbom.LicensePermissive,
		"BSD License":                              sbom.LicensePermissive,
		"New BSD License":                          sbom.LicensePermissive,
		"BSD 3-Clause License":                     sbom.LicensePermissive,
		"ISC License":                              sbom.LicensePermissive,
		"The Unlicense":                            sbom.LicensePermissive, // via id table on name form
		"Mozilla Public License 2.0":               sbom.LicenseWeakCopyleft,
		"Eclipse Public License 2.0":               sbom.LicenseWeakCopyleft,
		"GNU Lesser General Public License v3.0":   sbom.LicenseWeakCopyleft,
		"GNU General Public License v3.0":          sbom.LicenseCopyleft,
		"GPLv2":                                    sbom.LicenseCopyleft,
		"GNU Affero General Public License v3.0":   sbom.LicenseCopyleft,
		"Totally Made Up License":                  sbom.LicenseUnknown, // still unknown, not a false match
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLicenseMetadataParsingIsQuoteAndCommaAware(t *testing.T) {
	cases := map[string]string{
		`"The Apache Software License, Version 2.0";link="https://www.apache.org/licenses/LICENSE-2.0.txt"`: "Apache-2.0",
		"Apache License, Version 2.0; see: http://www.apache.org/licenses/LICENSE-2.0.txt":                  "Apache-2.0",
	}
	for raw, want := range cases {
		if got := canonicalLicenseKey(raw); got != want {
			t.Errorf("canonicalLicenseKey(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestLicensePolicyPreservesOROptionsAndReason(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "jaxb-api", Version: "2.3.1", PURL: "pkg:maven/javax.xml.bind/jaxb-api@2.3.1",
		Licenses: []sbom.License{{SPDXID: "CDDL-1.1 OR GPL-2.0-with-classpath-exception"}},
	}}}
	out, err := New().Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("findings = %+v, want one preserved expression", out)
	}
	got := out[0]
	if got.License != "CDDL-1.1 OR GPL-2.0-with-classpath-exception" || got.RecommendedChoice != "CDDL-1.1" || got.SelectionReason != "Lowest-risk valid OR option" {
		t.Fatalf("policy = %+v", got)
	}
	if len(got.Options) != 2 || got.PolicyRuleID == "" {
		t.Fatalf("policy options/rule = %+v", got)
	}
}

func TestLicensePolicyLeavesRecommendationBlankWithoutAChoice(t *testing.T) {
	for _, expression := range []string{"MIT", "MIT AND GPL-3.0-only"} {
		_, recommendation, rule, _ := licensePolicy(expression)
		if recommendation != "" {
			t.Errorf("licensePolicy(%q) recommendation = %q, want blank", expression, recommendation)
		}
		if rule == "" {
			t.Errorf("licensePolicy(%q) must still emit an effective policy rule", expression)
		}
	}
}

func TestAmbiguousBSDStaysUnspecified(t *testing.T) {
	for _, raw := range []string{"BSD", "BSD License", "http://www.opensource.org/licenses/bsd-license.php"} {
		if got := canonicalLicenseKey(raw); got != "BSD-UNSPECIFIED" {
			t.Errorf("canonicalLicenseKey(%q) = %q, want BSD-UNSPECIFIED", raw, got)
		}
	}
}

func TestScanSplitsBareLicenseListAsSeparateNotAnd(t *testing.T) {
	// jakarta.annotation-api is dual-licensed (EPL-2.0 OR GPL-2.0-with-classpath-exception).
	// Syft emits it as a bare comma list; we must list the two SEPARATELY (choose-any/OR),
	// never fabricate "EPL-2.0 AND GPL-2.0", and preserve the classpath exception in the id.
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "jakarta.annotation-api", Licenses: []sbom.License{{Name: "EPL-2.0, GPL-2.0-with-classpath-exception"}}},
	}}
	out, err := New().Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := map[string]ports.LicenseFinding{}
	for _, f := range out {
		got[f.License] = f
	}
	if _, bad := got["EPL-2.0 AND GPL-2.0"]; bad {
		t.Fatalf("multiple licenses wrongly joined with AND: %+v", out)
	}
	epl, hasEPL := got["EPL-2.0"]
	gpl, hasGPL := got["GPL-2.0-with-classpath-exception"]
	if !hasEPL || !hasGPL {
		t.Fatalf("want two separate licenses [EPL-2.0, GPL-2.0-with-classpath-exception], got %v", out)
	}
	if epl.RiskCategory != "reciprocal" || epl.Severity != "medium" {
		t.Errorf("EPL-2.0 risk = %q/%q, want reciprocal/medium", epl.RiskCategory, epl.Severity)
	}
	if gpl.RiskCategory != "restricted" || gpl.Severity != "high" {
		t.Errorf("GPL-classpath risk = %q/%q, want restricted/high", gpl.RiskCategory, gpl.Severity)
	}
	// The component itself now carries the two licenses separately (so the UI shows chips).
	if len(doc.Components[0].Licenses) != 2 {
		t.Errorf("component should carry 2 separate licenses, got %+v", doc.Components[0].Licenses)
	}
}

func TestScanResolvesDualLicenseURLList(t *testing.T) {
	// logback-classic is dual-licensed and Syft emits the licenses as a comma-separated list
	// of URLs. They must resolve (not stay unknown → coverage loss) and stay SEPARATE.
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "logback-classic", Licenses: []sbom.License{
			{Name: "http://www.eclipse.org/legal/epl-v10.html, http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html"},
		}},
	}}
	out, err := New().Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := map[string]ports.LicenseFinding{}
	for _, f := range out {
		got[f.License] = f
	}
	if _, ok := got["EPL-1.0"]; !ok {
		t.Errorf("EPL-1.0 URL not resolved (coverage loss); got %v", out)
	}
	if _, ok := got["LGPL-2.1"]; !ok {
		t.Errorf("LGPL-2.1 URL not resolved (coverage loss); got %v", out)
	}
	if len(doc.Components[0].Licenses) != 2 {
		t.Errorf("want 2 separate resolved licenses, got %+v", doc.Components[0].Licenses)
	}
}

// Mechanical family+version normalization (Trivy's standardizeKeyAndSuffix technique) resolves
// abbreviated forms to canonical SPDX ids WITHOUT a per-variant hand alias — display id + category.
// Replaces the deleted gplv3/gpl-3.0/lgplv2.1/mpl-2.0/apache-2.0 aliases and covers new variants.
func TestAbbreviatedFamilyNormalization(t *testing.T) {
	wantKey := map[string]string{
		"GPLv3": "GPL-3.0", "GPL 3.0": "GPL-3.0", "GPL 3": "GPL-3.0",
		"GPLv2": "GPL-2.0", "GPL 2.0": "GPL-2.0", "GPL v2.0": "GPL-2.0",
		"LGPLv3": "LGPL-3.0", "LGPLv2.1": "LGPL-2.1", "LGPL v2.1": "LGPL-2.1",
		"AGPLv3": "AGPL-3.0", "MPL 2.0": "MPL-2.0", "EPL 2.0": "EPL-2.0", "Apache 2.0": "Apache-2.0",
	}
	for in, want := range wantKey {
		if got := canonicalLicenseKey(in); got != want {
			t.Errorf("canonicalLicenseKey(%q) = %q, want %q", in, got, want)
		}
	}
	// Categories stay correct through the mechanical path.
	wantCat := map[string]sbom.LicenseCategory{
		"GPLv3": sbom.LicenseCopyleft, "LGPL v2.1": sbom.LicenseWeakCopyleft,
		"MPL 2.0": sbom.LicenseWeakCopyleft, "Apache 2.0": sbom.LicensePermissive,
		"AGPLv3": sbom.LicenseCopyleft,
	}
	for in, want := range wantCat {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
	// A verbose human name also displays as its canonical SPDX id (consistent with the category path).
	for in, want := range map[string]string{
		"GNU Lesser General Public License v3.0": "LGPL-3.0",
		"Apache License 2.0":                     "Apache-2.0",
		"Mozilla Public License 2.0":             "MPL-2.0",
		"MIT License":                            "MIT",
	} {
		if got := canonicalLicenseKey(in); got != want {
			t.Errorf("canonicalLicenseKey(%q) = %q, want canonical %q", in, got, want)
		}
	}
	// A non-existent version is NEVER invented — stays raw/unknown (no false attribution).
	if got := canonicalLicenseKey("GPLv4"); got != "GPLv4" {
		t.Errorf("GPLv4 canonicalLicenseKey = %q, want raw GPLv4 (not invented)", got)
	}
	if got := classify("GPLv4"); got != sbom.LicenseUnknown {
		t.Errorf("GPLv4 classify = %q, want unknown", got)
	}
}

func TestSPDXFromURLHostPatterns(t *testing.T) {
	// The host-pattern engine resolves license URLs without a per-URL alias table, across
	// scheme/www/extension/trailing-slash variants, and PRESERVES a license exception.
	cases := map[string]string{
		// Apache — scheme + www + trailing-slash variants all fold to one id.
		"http://www.apache.org/licenses/LICENSE-2.0.txt":   "Apache-2.0",
		"https://apache.org/licenses/LICENSE-2.0":          "Apache-2.0",
		"http://www.apache.org/licenses/":                  "Apache-2.0",
		"https://www.apache.org/licenses/LICENSE-2.0.html": "Apache-2.0",
		// Eclipse — EPL 2.0 / EPL 1.0 (the "v10" spelling) / EDL.
		"https://www.eclipse.org/legal/epl-2.0":            "EPL-2.0",
		"http://www.eclipse.org/legal/epl-v10.html":        "EPL-1.0",
		"http://www.eclipse.org/org/documents/epl-v10.php": "EPL-1.0",
		"http://www.eclipse.org/org/documents/edl-v10.php": "EDL-1.0",
		// GNU family via regex — version + family, any path depth.
		"http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html": "LGPL-2.1",
		"https://www.gnu.org/licenses/gpl-3.0.html":              "GPL-3.0",
		"https://www.gnu.org/licenses/agpl-3.0":                  "AGPL-3.0",
		"https://www.gnu.org/licenses/gpl-2.0.txt":               "GPL-2.0",
		"http://www.fsf.org/licensing/licenses/agpl-3.0":         "AGPL-3.0",
		// GNU Classpath exception — the EXACT id must survive (regression for D).
		"https://www.gnu.org/software/classpath/license.html": "GPL-2.0-with-classpath-exception",
		"http://www.gnu.org/software/classpath/license":       "GPL-2.0-with-classpath-exception",
		// Mozilla.
		"https://www.mozilla.org/en-US/MPL/2.0/": "MPL-2.0",
		// Creative Commons.
		"https://creativecommons.org/publicdomain/zero/1.0/": "CC0-1.0",
		"https://creativecommons.org/licenses/by-sa/4.0/":    "CC-BY-SA-4.0",
		// SPDX + OSI canonical pages — the path segment IS the SPDX id.
		"https://spdx.org/licenses/Apache-2.0.html": "Apache-2.0",
		"https://opensource.org/licenses/MIT":       "MIT",
		"https://opensource.org/license/mit":        "MIT",
		// BouncyCastle (MIT-style, permissive) + Oracle FUTC (proprietary free-use, a LicenseRef) —
		// declared-URL forms real SBOMs (cyclonedx-maven-plugin) emit; must resolve, not show a raw URL.
		"https://www.bouncycastle.org/licence.html":                          "Bouncy-Castle",
		"https://www.oracle.com/downloads/licenses/oracle-free-license.html": "LicenseRef-Oracle-Free-Use-Terms-and-Conditions-FUTC",
		// (OSI's legacy "bsd-license.php" slug — ambiguous 2-vs-3-clause — stays a curated
		// rawLicenseAliases entry, verified end-to-end below, not a host-pattern rule.)
	}
	for in, want := range cases {
		got, ok := spdxFromURL(canonicalizeLicenseURL(in))
		if !ok || got != want {
			t.Errorf("spdxFromURL(%q) = %q,%v, want %q,true", in, got, ok, want)
		}
	}
	// BouncyCastle URL → permissive; Oracle FUTC URL → proprietary. The pipeline categorizes the
	// RESOLVED id (canonicalLicenseKey → classify), not the raw URL — regression for the #225
	// URL-over-name precedence that left these raw + unknown-category.
	if k := canonicalLicenseKey("https://www.bouncycastle.org/licence.html"); k != "Bouncy-Castle" || classify(k) != sbom.LicensePermissive {
		t.Errorf("bouncycastle URL → key %q / %q, want Bouncy-Castle / permissive", k, classify(k))
	}
	if k := canonicalLicenseKey("https://www.oracle.com/downloads/licenses/oracle-free-license.html"); k != "LicenseRef-Oracle-Free-Use-Terms-and-Conditions-FUTC" || classify(k) != sbom.LicenseProprietary {
		t.Errorf("oracle FUTC URL → key %q / %q, want LicenseRef / proprietary", k, classify(k))
	}
	// The legacy OSI slug is not a host-pattern rule, but the full classify path still
	// resolves it via the curated fallback table (no coverage regression).
	if c := classify("http://www.opensource.org/licenses/bsd-license.php"); c != sbom.LicensePermissive {
		t.Errorf("legacy OSI bsd-license.php classify = %q, want permissive (via fallback)", c)
	}
}

func TestSPDXFromURLRejectsNonLicenseAndLists(t *testing.T) {
	// Must NOT match: non-license URLs, unknown hosts, plain ids, and multi-URL LISTS
	// (a list is split into separate licenses by the caller — swallowing it as the first
	// URL would drop the rest and is a false attribution).
	for _, in := range []string{
		"",
		"MIT",                     // a bare id, not a URL
		"MIT OR Apache-2.0",       // an expression
		"https://example.com/foo", // unknown host
		"https://github.com/me/repo/blob/main/LICENSE",                                                      // a repo file, not a license host
		"http://www.eclipse.org/legal/epl-v10.html, http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html", // a LIST
	} {
		if got, ok := spdxFromURL(canonicalizeLicenseURL(in)); ok {
			t.Errorf("spdxFromURL(%q) = %q,true, want _,false", in, got)
		}
	}
}

func TestURLListNoDowngrade(t *testing.T) {
	// A "," OR ";" separated URL list must take the MOST RESTRICTIVE member, never collapse
	// to the permissive head. Regression: spdxFromURL must reject list separators (incl. ';',
	// which splitLicenseList treats as a separator) so a forbidden license can't hide behind
	// a permissive one — a silent downgrade (classification integrity).
	cases := map[string]sbom.LicenseCategory{
		"http://www.apache.org/licenses/LICENSE-2.0.txt;http://www.gnu.org/licenses/gpl-3.0.html": sbom.LicenseCopyleft,
		"http://www.apache.org/licenses/LICENSE-2.0.txt,http://www.gnu.org/licenses/gpl-3.0.html": sbom.LicenseCopyleft,
		"MIT;GPL-3.0-only": sbom.LicenseCopyleft,
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q (DOWNGRADE)", in, got, want)
		}
	}
}

func TestEDLByURLHasRiskNotPlainUnknown(t *testing.T) {
	// The Eclipse Distribution License resolved from its URL (EDL-1.0) is a BSD-3-Clause
	// variant — it must classify permissive AND carry a real risk (notice/low), not fall to
	// an "unknown" severity that reads as "review manually".
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "jaxb-api", Licenses: []sbom.License{{Name: "http://www.eclipse.org/org/documents/edl-v10.php"}}},
	}}
	out, err := New().Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out) != 1 || out[0].License != "EDL-1.0" {
		t.Fatalf("finding = %+v, want EDL-1.0", out)
	}
	if out[0].Category != sbom.LicensePermissive || out[0].RiskCategory != "notice" || out[0].Severity != "low" {
		t.Errorf("finding = %+v, want permissive/notice/low", out[0])
	}
}

func TestScanClasspathExceptionURLPreservesDisplayID(t *testing.T) {
	// End-to-end (D): a component whose only license is the GNU Classpath URL must DISPLAY
	// the exact exception id, not collapse to GPL-2.0, while still classifying as copyleft.
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "jansi", Licenses: []sbom.License{{Name: "http://www.gnu.org/software/classpath/license.html"}}},
	}}
	out, err := New().Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out) != 1 || out[0].License != "GPL-2.0-with-classpath-exception" {
		t.Fatalf("finding = %+v, want license GPL-2.0-with-classpath-exception", out)
	}
	if out[0].Category != sbom.LicenseCopyleft || out[0].RiskCategory != "restricted" || out[0].Severity != "high" {
		t.Errorf("finding = %+v, want copyleft/restricted/high", out[0])
	}
}

func TestFamilyFallbackClassifiesSPDXLongTail(t *testing.T) {
	// SPDX ids absent from the CURATED policy table must still get a category — via the
	// authoritative ScanCode-derived spdxFamily table (primary) or the naming heuristic
	// (fallback). Values below are the ScanCode-authoritative categories. A non-SPDX string
	// with no family MUST stay unknown (conservative).
	cases := map[string]sbom.LicenseCategory{
		"OSL-2.1":         sbom.LicenseCopyleft,     // ScanCode: Copyleft
		"QPL-1.0":         sbom.LicenseWeakCopyleft, // ScanCode: Copyleft Limited (not strong)
		"RPL-1.5":         sbom.LicenseWeakCopyleft, // ScanCode: Copyleft Limited
		"RPSL-1.0":        sbom.LicenseWeakCopyleft, // ScanCode: Copyleft Limited
		"AFL-2.1":         sbom.LicensePermissive,
		"AFL-3.0":         sbom.LicensePermissive,
		"ZPL-2.1":         sbom.LicensePermissive,
		"PHP-3.01":        sbom.LicensePermissive,
		"APSL-2.0":        sbom.LicenseWeakCopyleft,
		"CDDL-1.1":        sbom.LicenseWeakCopyleft,
		"MS-RL":           sbom.LicenseWeakCopyleft,
		"Vim":             sbom.LicenseCopyleft,    // ScanCode: Copyleft (heuristic had wrongly said permissive)
		"CC-BY-4.0":       sbom.LicensePermissive,  // plain attribution
		"CC-BY-SA-4.0":    sbom.LicenseCopyleft,    // share-alike (curated stance wins)
		"CC-BY-ND-4.0":    sbom.LicenseProprietary, // no-derivatives → ScanCode Source-available
		"CC-BY-NC-4.0":    sbom.LicenseProprietary, // non-commercial
		"CC-BY-NC-SA-3.0": sbom.LicenseProprietary,
		"NASA-1.3":        sbom.LicenseWeakCopyleft,
		"LiLiQ-Rplus-1.1": sbom.LicenseCopyleft,
		"AAL":             sbom.LicensePermissive,
		"OFL-1.1":         sbom.LicenseWeakCopyleft, // font copyleft, not bare permissive
		"BSD-Protection":  sbom.LicenseCopyleft,     // GPL-style clause — never permissive
		"Frobnicate-9.9":  sbom.LicenseUnknown,      // not a real id, no family → unknown
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
	// Severity must travel with the family (e.g. a strong-copyleft long-tail id is high).
	if r, sev := RiskOf("OSL-2.1"); r != RiskRestricted || sev != "high" {
		t.Errorf("RiskOf(OSL-2.1) = %q/%q, want restricted/high", r, sev)
	}
	if r, _ := RiskOf("CC-BY-NC-4.0"); r != RiskForbidden {
		t.Errorf("RiskOf(CC-BY-NC-4.0) = %q, want forbidden", r)
	}
	if r, _ := RiskOf("Frobnicate-9.9"); r != RiskUnknown {
		t.Errorf("RiskOf(unknown) = %q, want unknown", r)
	}
}

func TestClassifyRiskReconciledAndConsistent(t *testing.T) {
	// Regression for the curated/family reconciliation: category and risk must agree, and the
	// reviewer-found downgrades must stay fixed.
	type want struct {
		cat  sbom.LicenseCategory
		risk RiskCategory
	}
	cases := map[string]want{
		// BSD-Protection has a GPL-style same-license clause → strong copyleft, NOT permissive
		// (it would otherwise be swallowed by the broad "bsd-" permissive family — a downgrade).
		"BSD-Protection": {sbom.LicenseCopyleft, RiskRestricted},
		// WTFPL is public-domain-equivalent — permissive/unencumbered, never a "forbidden" ban.
		"WTFPL": {sbom.LicensePermissive, RiskUnencumbered},
		// MS-PL is weak copyleft (FSF) → reciprocal, not the laxer notice.
		"MS-PL": {sbom.LicenseWeakCopyleft, RiskReciprocal},
		// OSL / EUPL are strong (network/whole-work) copyleft.
		"OSL-3.0":  {sbom.LicenseCopyleft, RiskRestricted},
		"EUPL-1.2": {sbom.LicenseCopyleft, RiskRestricted},
	}
	for id, w := range cases {
		gotCat := classify(id)
		gotRisk, _ := RiskOf(id)
		if gotCat != w.cat || gotRisk != w.risk {
			t.Errorf("%s = %s/%s, want %s/%s", id, gotCat, gotRisk, w.cat, w.risk)
		}
	}
	// INTENTIONAL non-correspondence: LGPL is weak-copyleft POLICY
	// (warn) but restricted RISK (high). Lock it so a future "consistency fix" can't flatten it.
	if c := classify("LGPL-2.1-only"); c != sbom.LicenseWeakCopyleft {
		t.Errorf("LGPL-2.1 category = %s, want weak-copyleft", c)
	}
	if r, sev := RiskOf("LGPL-2.1-only"); r != RiskRestricted || sev != "high" {
		t.Errorf("LGPL-2.1 risk = %s/%s, want restricted/high", r, sev)
	}
}

func TestScanPolicyVerdicts(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Licenses: []sbom.License{{SPDXID: "MIT"}}},
		{Name: "gpl-lib", Licenses: []sbom.License{{SPDXID: "GPL-3.0-only"}}},
		{Name: "lodash-clone", Licenses: []sbom.License{{SPDXID: "MIT"}}}, // shares MIT
		{Name: "mpl-lib", Licenses: []sbom.License{{Name: "MPL-2.0"}}},    // license via Name
		{Name: "mystery", Licenses: []sbom.License{{SPDXID: "Weird-1.0"}}},
	}}

	out, err := New().Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := map[string]ports.LicenseFinding{}
	for _, f := range out {
		got[f.License] = f
	}

	if f := got["MIT"]; f.Verdict != ports.LicenseAllow || f.Category != sbom.LicensePermissive || len(f.Components) != 2 {
		t.Errorf("MIT = %+v, want allow/permissive with 2 components", f)
	}
	if f := got["GPL-3.0-only"]; f.Verdict != ports.LicenseDeny || f.Category != sbom.LicenseCopyleft {
		t.Errorf("GPL-3.0-only = %+v, want deny/copyleft", f)
	}
	if f := got["MPL-2.0"]; f.Verdict != ports.LicenseWarn || f.Category != sbom.LicenseWeakCopyleft {
		t.Errorf("MPL-2.0 = %+v, want warn/weak-copyleft", f)
	}
	if f := got["Weird-1.0"]; f.Verdict != ports.LicenseWarn || f.Category != sbom.LicenseUnknown {
		t.Errorf("Weird-1.0 = %+v, want warn/unknown", f)
	}
}

func TestClassifyNestedAndWith(t *testing.T) {
	cases := map[string]sbom.LicenseCategory{
		"(MIT OR Apache-2.0) AND GPL-3.0-only":  sbom.LicenseCopyleft,   // GPL unavoidable → deny (regression: was the bypass bug)
		"MIT OR GPL-3.0-only AND Apache-2.0":    sbom.LicensePermissive, // MIT OR (GPL AND Apache) → pick MIT
		"MIT AND (GPL-3.0-only OR Apache-2.0)":  sbom.LicensePermissive, // satisfy the OR with Apache
		"GPL-2.0-only WITH Classpath-exception": sbom.LicenseCopyleft,   // WITH exception, base is GPL
		"Apache-2.0 WITH LLVM-exception":        sbom.LicensePermissive,
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyTrivyObservedAliasesAndExceptions(t *testing.T) {
	cases := map[string]sbom.LicenseCategory{
		"Artistic-1":                       sbom.LicenseWeakCopyleft,
		"Artistic-2":                       sbom.LicenseWeakCopyleft,
		"BSD-2-Clause-NetBSD":              sbom.LicensePermissive,
		"BSL-1.0":                          sbom.LicensePermissive,
		"CC0-1.0":                          sbom.LicensePermissive,
		"PSF-2":                            sbom.LicensePermissive,
		"GPL-2+ with exception":            sbom.LicenseCopyleft,
		"GPL-2.0-with-autoconf-exception+": sbom.LicenseCopyleft,
		"GPL-2.0-with-bison-exception+":    sbom.LicenseCopyleft,
		"GPL-3.0-with-autoconf-exception+": sbom.LicenseCopyleft,
		"GFDL-1.2-only":                    sbom.LicenseCopyleft,
		"GFDL-1.2-or-later":                sbom.LicenseCopyleft,
		"CUSTOM License: Permission is hereby granted, free of charge": sbom.LicensePermissive,
		"Bouncy-Castle":                        sbom.LicensePermissive,
		"Bouncy Castle Licence":                sbom.LicensePermissive,
		"Eclipse Distribution License - v 1.0": sbom.LicensePermissive,
		"CPL":                                  sbom.LicenseWeakCopyleft,
		"PD":                                   sbom.LicensePermissive,
		"public-domain":                        sbom.LicensePermissive,
		"BZIP":                                 sbom.LicensePermissive,
		"REGCOMP":                              sbom.LicensePermissive,
		"GAP":                                  sbom.LicensePermissive,
		"Unicode":                              sbom.LicensePermissive,
		"RFC-Reference":                        sbom.LicensePermissive,
		"http://www.eclipse.org/legal/epl-2.0, https://www.gnu.org/software/classpath/license.html": sbom.LicenseCopyleft,
		"same-as-rest-of-p11kit": sbom.LicenseUnknown,
		"see above":              sbom.LicenseUnknown,
		"none":                   sbom.LicenseUnknown,
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanDropsUnresolvedEvidenceWhenEffectiveLicenseExists(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "openjdk",
		Licenses: []sbom.License{
			{SPDXID: "sha256:deadbeef"},
			{SPDXID: "GPL-2.0-only WITH Classpath-exception"},
			{SPDXID: "LicenseRef-LICENSE"},
		},
	}}}
	out, err := New().Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("findings = %+v, want only effective license", out)
	}
	if out[0].License != "GPL-2.0-only WITH Classpath-exception" || out[0].Category != sbom.LicenseCopyleft {
		t.Fatalf("finding = %+v, want Classpath GPL copyleft", out[0])
	}
}

package ownadvisory

import (
	"strings"
	"testing"
)

// sleArchDefinition builds one ordinary SLES 15 SP6 definition whose package criterion is scoped to an
// architecture set, mirroring the real feed shape:
//
//	<linux:arch datatype="string" operation="pattern match">(aarch64|ppc64le|s390x|x86_64)</linux:arch>
//	<linux:evr datatype="evr_string" operation="less than">0:2.4.0-150000.4.6.1</linux:evr>
func sleArchDefinition(id, packageTest, packageComment string) string {
	return `<definition id="oval:org.opensuse.security:def:` + id + `" version="1" class="vulnerability">
	  <metadata><title>CVE-2026-54369</title><affected family="unix"><platform>SUSE Linux Enterprise Server 15 SP6</platform></affected></metadata>
	  <criteria operator="AND">
	    <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	    <criteria operator="OR"><criterion test_ref="` + packageTest + `" comment="` + packageComment + `"/></criteria>
	  </criteria>
	</definition>`
}

// sleArchDoc wires the definition above to an architecture-scoped rpminfo_state. archValue is injected
// verbatim so a test can supply an unsupported regular expression and assert it fails closed.
func sleArchDoc(definitions, archValue string) []byte {
	return oracleDoc(`<definitions>` + definitions + `</definitions>
	<tests>
	  <linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:archfixed" check="at least one" comment="libacl1 is &lt;0:2.4.0-150000.4.6.1 for aarch64,ppc64le,s390x,x86_64"><linux:object object_ref="oval:obj:libacl1"/><linux:state state_ref="oval:state:archfixed"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:archopen" check="at least one" comment="libacl1 is &gt;0"><linux:object object_ref="oval:obj:libacl1"/><linux:state state_ref="oval:state:archopen"/></linux:rpminfo_test>
	</tests>
	<objects>
	  <linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:libacl1"><linux:name>libacl1</linux:name></linux:rpminfo_object>
	</objects>
	<states>
	  <linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:archfixed"><linux:arch datatype="string" operation="pattern match">` + archValue + `</linux:arch><linux:evr datatype="evr_string" operation="less than">0:2.4.0-150000.4.6.1</linux:evr></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:archopen"><linux:arch datatype="string" operation="pattern match">` + archValue + `</linux:arch><linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr></linux:rpminfo_state>
	</states>`)
}

// TestSLESArchQualifiedBoundedEvidenceBindsToItsArchitectures is the #1295 recall regression. Before the
// architecture identity existed, an arch-qualified criterion was suppressed outright, so these bounded
// relations were invisible. They must now bind, and bind ONLY to the vendor's architectures.
func TestSLESArchQualifiedBoundedEvidenceBindsToItsArchitectures(t *testing.T) {
	doc := sleArchDoc(
		sleArchDefinition("202654369", "oval:test:archfixed", "libacl1-2.4.0-150000.4.6.1 is installed"),
		"(aarch64|ppc64le|s390x|x86_64)",
	)
	advs, err := ParseOVALSnapshot([][]byte{doc})
	if err != nil {
		t.Fatalf("parse arch-qualified SLES snapshot: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("want exactly one advisory, got %d", len(advs))
	}
	if len(advs[0].Affected) != 1 {
		t.Fatalf("want exactly one affected block, got %+v", advs[0].Affected)
	}
	affected := advs[0].Affected[0]
	if affected.Ecosystem != "SUSE:15.6" || affected.Package != "libacl1" {
		t.Fatalf("unexpected affected identity: %+v", affected)
	}
	if got, want := strings.Join(affected.Architectures, ","), "aarch64,ppc64le,s390x,x86_64"; got != want {
		t.Fatalf("architectures = %q, want %q", got, want)
	}
	if affected.FixedVersion != "0:2.4.0-150000.4.6.1" {
		t.Fatalf("fixed version = %q, want the bounded upper bound", affected.FixedVersion)
	}

	// An in-set architecture below the boundary matches and reports the remediation.
	if ok, fixed := advs[0].Match("SUSE:15.6", "libacl1", "0:2.2.52-4.3.1", "x86_64"); !ok || fixed != "0:2.4.0-150000.4.6.1" {
		t.Fatalf("in-set architecture must match with a fixed hint, got ok=%v fixed=%q", ok, fixed)
	}
	// Bounded behavior is preserved: at the boundary it no longer matches.
	if ok, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:2.4.0-150000.4.6.1", "x86_64"); ok {
		t.Fatal("a version at the fixed boundary must not match")
	}
	// An architecture OUTSIDE the vendor's set must not match. This is the over-match the suppression
	// previously prevented and the reason the set is carried at all.
	if ok, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:2.2.52-4.3.1", "i586"); ok {
		t.Fatal("an out-of-set architecture must not match")
	}
	// An unknown component architecture cannot be proven inside the set, so it must not match either.
	if ok, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:2.2.52-4.3.1", ""); ok {
		t.Fatal("an unknown component architecture must not satisfy an architecture-scoped block")
	}
}

// TestSLESArchQualifiedOpenRangeBindsToItsArchitectures covers the not-yet-fixed shape carrying an
// architecture predicate: the open range must survive AND stay architecture-scoped.
func TestSLESArchQualifiedOpenRangeBindsToItsArchitectures(t *testing.T) {
	doc := sleArchDoc(
		sleArchDefinition("202654370", "oval:test:archopen", "libacl1 is affected"),
		"(x86_64)",
	)
	advs, err := ParseOVALSnapshot([][]byte{doc})
	if err != nil {
		t.Fatalf("parse arch-qualified open SLES snapshot: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("want one advisory with one affected block, got %+v", advs)
	}
	affected := advs[0].Affected[0]
	if got, want := strings.Join(affected.Architectures, ","), "x86_64"; got != want {
		t.Fatalf("architectures = %q, want %q", got, want)
	}
	if affected.FixedVersion != "" {
		t.Fatalf("a not-yet-fixed block must carry no fixed version, got %q", affected.FixedVersion)
	}
	// Open range: any version on the named architecture is affected.
	if ok, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:99.0-1", "x86_64"); !ok {
		t.Fatal("an open range must match every version on an in-set architecture")
	}
	// But never on another architecture, however high the version.
	if ok, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:99.0-1", "aarch64"); ok {
		t.Fatal("an open range must not widen across architectures")
	}
}

// TestSLESUnsupportedArchPredicateFailsClosed asserts the fail-closed contract: an architecture predicate
// the parser cannot read EXACTLY must suppress the package fact rather than be approximated. Approximating
// would either invent applicability or silently drop it, both of which #1295 forbids.
func TestSLESUnsupportedArchPredicateFailsClosed(t *testing.T) {
	for _, current := range []struct {
		name string
		arch string
	}{
		{name: "wildcard", arch: ".*"},
		{name: "character class", arch: "(x86_[0-9]+)"},
		{name: "quantifier", arch: "(x86_64)+"},
		{name: "anchored", arch: "^(x86_64)$"},
		{name: "nested group", arch: "((x86_64|aarch64))"},
		{name: "unbalanced", arch: "(x86_64"},
		{name: "empty alternation member", arch: "(x86_64|)"},
	} {
		t.Run(current.name, func(t *testing.T) {
			doc := sleArchDoc(
				sleArchDefinition("202654371", "oval:test:archfixed", "libacl1-2.4.0-150000.4.6.1 is installed"),
				current.arch,
			)
			advs, err := ParseOVALSnapshot([][]byte{doc})
			if err != nil {
				// Failing closed by rejecting the document outright is also acceptable.
				return
			}
			for _, adv := range advs {
				if len(adv.Affected) != 0 {
					t.Fatalf("an unreadable architecture predicate must not bind a package, got %+v", adv.Affected)
				}
			}
		})
	}
}

// TestSLESArchVariantsOfOnePackageAreBothRetained guards the keying decision. One CVE legitimately
// publishes several architecture-scoped facts for the same package from different product clauses (the real
// feed ships libacl1 for both "(aarch64|ppc64le|s390x|x86_64)" and "(ppc64le|x86_64)" under CVE-2026-54369).
// Keying bindings by package alone would let one silently overwrite the other.
func TestSLESArchVariantsOfOnePackageAreBothRetained(t *testing.T) {
	doc := oracleDoc(`<definitions>` + `<definition id="oval:org.opensuse.security:def:202654369" version="1" class="vulnerability">
	  <metadata><title>CVE-2026-54369</title><affected family="unix"><platform>SUSE Linux Enterprise Server 15 SP6</platform></affected></metadata>
	  <criteria operator="OR">
	    <criteria operator="AND">
	      <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	      <criteria operator="OR"><criterion test_ref="oval:test:wide" comment="libacl1-2.4.0-150000.4.6.1 is installed"/></criteria>
	    </criteria>
	    <criteria operator="AND">
	      <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	      <criteria operator="OR"><criterion test_ref="oval:test:narrow" comment="libacl1-2.4.0-150000.4.6.1 is installed"/></criteria>
	    </criteria>
	  </criteria>
	</definition>` + `</definitions>
	<tests>
	  <linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:wide" check="at least one" comment="libacl1 is &lt;0:2.4.0-150000.4.6.1 for aarch64,ppc64le,s390x,x86_64"><linux:object object_ref="oval:obj:libacl1"/><linux:state state_ref="oval:state:wide"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:narrow" check="at least one" comment="libacl1 is &lt;0:2.4.0-150000.4.6.1 for ppc64le,x86_64"><linux:object object_ref="oval:obj:libacl1"/><linux:state state_ref="oval:state:narrow"/></linux:rpminfo_test>
	</tests>
	<objects>
	  <linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:libacl1"><linux:name>libacl1</linux:name></linux:rpminfo_object>
	</objects>
	<states>
	  <linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:wide"><linux:arch datatype="string" operation="pattern match">(aarch64|ppc64le|s390x|x86_64)</linux:arch><linux:evr datatype="evr_string" operation="less than">0:2.4.0-150000.4.6.1</linux:evr></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:narrow"><linux:arch datatype="string" operation="pattern match">(ppc64le|x86_64)</linux:arch><linux:evr datatype="evr_string" operation="less than">0:2.4.0-150000.4.6.1</linux:evr></linux:rpminfo_state>
	</states>`)

	advs, err := ParseOVALSnapshot([][]byte{doc})
	if err != nil {
		t.Fatalf("parse multi-architecture SLES snapshot: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("want exactly one advisory, got %d", len(advs))
	}
	sets := map[string]bool{}
	for _, affected := range advs[0].Affected {
		sets[strings.Join(affected.Architectures, ",")] = true
	}
	for _, want := range []string{"aarch64,ppc64le,s390x,x86_64", "ppc64le,x86_64"} {
		if !sets[want] {
			t.Fatalf("architecture set %q was dropped; got %v", want, sets)
		}
	}
	// s390x appears only in the wider set, and must still match through it.
	if ok, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:2.2.52-4.3.1", "s390x"); !ok {
		t.Fatal("an architecture present in only one variant must still match")
	}
}

// TestSLESNoarchIsComparedLiterally pins the noarch reading. A noarch block describes
// architecture-independent content and the component carrying it is itself tagged noarch, so the comparison
// is literal; treating noarch as a wildcard would match every architecture.
func TestSLESNoarchIsComparedLiterally(t *testing.T) {
	doc := oracleDoc(`<definitions>` + sleArchDefinition("202654372", "oval:test:noarchfixed", "libacl1-2.4.0-150000.4.6.1 is installed") + `</definitions>
	<tests>
	  <linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:noarchfixed" check="at least one" comment="libacl1 is &lt;0:2.4.0-150000.4.6.1 for noarch"><linux:object object_ref="oval:obj:libacl1"/><linux:state state_ref="oval:state:noarchfixed"/></linux:rpminfo_test>
	</tests>
	<objects>
	  <linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:libacl1"><linux:name>libacl1</linux:name></linux:rpminfo_object>
	</objects>
	<states>
	  <linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:noarchfixed"><linux:arch datatype="string" operation="pattern match">(noarch)</linux:arch><linux:evr datatype="evr_string" operation="less than">0:2.4.0-150000.4.6.1</linux:evr></linux:rpminfo_state>
	</states>`)
	advs, err := ParseOVALSnapshot([][]byte{doc})
	if err != nil {
		t.Fatalf("parse noarch SLES snapshot: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("want one advisory with one affected block, got %+v", advs)
	}
	if ok, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:2.2.52-4.3.1", "noarch"); !ok {
		t.Fatal("a noarch component must match a noarch-scoped block")
	}
	if ok, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:2.2.52-4.3.1", "x86_64"); ok {
		t.Fatal("noarch must not act as a wildcard across architectures")
	}
}

// TestSLESBareArchTokenBindsWithoutParentheses covers the unparenthesised single-token form. The regex
// accepts it, so it must bind to exactly that one architecture rather than being read as a wildcard.
func TestSLESBareArchTokenBindsWithoutParentheses(t *testing.T) {
	doc := sleArchDoc(
		sleArchDefinition("202654374", "oval:test:archopen", "libacl1 is affected"),
		"x86_64",
	)
	advs, err := ParseOVALSnapshot([][]byte{doc})
	if err != nil {
		t.Fatalf("parse bare-token arch snapshot: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("want one advisory with one affected block, got %+v", advs)
	}
	if got, want := strings.Join(advs[0].Affected[0].Architectures, ","), "x86_64"; got != want {
		t.Fatalf("architectures = %q, want %q", got, want)
	}
	if ok, _ := advs[0].Match("SUSE:15.6", "libacl1", "0:1.0-1", "aarch64"); ok {
		t.Fatal("a bare architecture token must not widen to other architectures")
	}
}

// TestSLESFixedCommentMustAgreeWithArchPredicate pins the cross-check: when a bounded criterion's prose names
// a different architecture set than its arch predicate, the evidence is contradictory and must fail closed
// rather than bind on the predicate alone.
func TestSLESFixedCommentMustAgreeWithArchPredicate(t *testing.T) {
	doc := sleArchDoc(
		sleArchDefinition("202654373", "oval:test:archfixed", "libacl1-2.4.0-150000.4.6.1 is installed"),
		"(noarch)", // the test comment in sleArchDoc names aarch64,ppc64le,s390x,x86_64
	)
	advs, err := ParseOVALSnapshot([][]byte{doc})
	if err != nil {
		return // rejecting outright is also failing closed
	}
	for _, adv := range advs {
		if len(adv.Affected) != 0 {
			t.Fatalf("a comment disagreeing with the arch predicate must not bind, got %+v", adv.Affected)
		}
	}
}

// TestSLESSuppressionStillWithdrawsEveryArchVariant pins the fail-closed retirement direction. Suppression
// is package-wide on purpose: unreadable or contradictory evidence about any variant must withdraw the whole
// package, never leave sibling architecture variants matching.
func TestSLESSuppressionStillWithdrawsEveryArchVariant(t *testing.T) {
	doc := oracleDoc(`<definitions>` + `<definition id="oval:org.opensuse.security:def:202654369" version="1" class="vulnerability">
	  <metadata><title>CVE-2026-54369</title><affected family="unix"><platform>SUSE Linux Enterprise Server 15 SP6</platform></affected></metadata>
	  <criteria operator="OR">
	    <criteria operator="AND">
	      <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	      <criteria operator="OR"><criterion test_ref="oval:test:wide" comment="libacl1-2.4.0-150000.4.6.1 is installed"/></criteria>
	    </criteria>
	    <criteria operator="AND">
	      <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	      <criteria operator="OR"><criterion test_ref="oval:test:unreadable" comment="libacl1-2.4.0-150000.4.6.1 is installed"/></criteria>
	    </criteria>
	  </criteria>
	</definition>` + `</definitions>
	<tests>
	  <linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:wide" check="at least one" comment="libacl1 is &lt;0:2.4.0-150000.4.6.1 for aarch64,ppc64le,s390x,x86_64"><linux:object object_ref="oval:obj:libacl1"/><linux:state state_ref="oval:state:wide"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:unreadable" check="at least one" comment="libacl1 is &lt;0:2.4.0-150000.4.6.1 for anything"><linux:object object_ref="oval:obj:libacl1"/><linux:state state_ref="oval:state:unreadable"/></linux:rpminfo_test>
	</tests>
	<objects>
	  <linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:libacl1"><linux:name>libacl1</linux:name></linux:rpminfo_object>
	</objects>
	<states>
	  <linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:wide"><linux:arch datatype="string" operation="pattern match">(aarch64|ppc64le|s390x|x86_64)</linux:arch><linux:evr datatype="evr_string" operation="less than">0:2.4.0-150000.4.6.1</linux:evr></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:unreadable"><linux:arch datatype="string" operation="pattern match">.*</linux:arch><linux:evr datatype="evr_string" operation="less than">0:2.4.0-150000.4.6.1</linux:evr></linux:rpminfo_state>
	</states>`)

	advs, err := ParseOVALSnapshot([][]byte{doc})
	if err != nil {
		return // rejecting outright is also failing closed
	}
	for _, adv := range advs {
		if len(adv.Affected) != 0 {
			t.Fatalf("an unreadable variant must withdraw every architecture variant of the package, got %+v", adv.Affected)
		}
	}
}

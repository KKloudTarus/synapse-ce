package sbom

import "testing"

func TestIdentityFromCPEFailsClosedAndUsesComponentVersion(t *testing.T) {
	identity := IdentityFromCPE(`cpe:2.3:a:acme:widget:*:*:*:*:*:python:*:*`, "1.2.3")
	if identity.Status != IdentityResolved || identity.CPE.Version != "1.2.3" || identity.CPE.Vendor != "acme" {
		t.Fatalf("identity=%+v", identity)
	}
	for _, raw := range []string{"", "cpe:/a:acme:widget", `cpe:2.3:a:acme:widget:1.0:*:*:*:*:python:*`, `cpe:2.3:a:acme:widget:1.0:*:*:*:*:python:*:\`} {
		if got := IdentityFromCPE(raw, "1.0"); got.Status == IdentityResolved {
			t.Fatalf("malformed CPE resolved: %q", raw)
		}
	}
	if got := IdentityFromCPE(`cpe:2.3:a:acme:widget:1.0:*:*:*:*:python:*:*`, "2.0"); got.Status != IdentityAmbiguous {
		t.Fatalf("version mismatch=%+v", got)
	}
}

func TestCPEMatchAttributesHonorsWildcardAndNA(t *testing.T) {
	criteria, err := ParseCPE23(`cpe:2.3:a:acme:widget:*:*:*:*:*:python:*:*`)
	if err != nil {
		t.Fatal(err)
	}
	component, err := ParseCPE23(`cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:python:x64:*`)
	if err != nil {
		t.Fatal(err)
	}
	if !criteria.MatchAttributes(component) {
		t.Fatal("wildcard criteria did not match")
	}
	criteria.TargetHW = "-"
	if criteria.MatchAttributes(component) {
		t.Fatal("NA target hardware matched concrete value")
	}
}

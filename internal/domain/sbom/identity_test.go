package sbom

import "testing"

func TestIdentityFromComponentUsesAdvisoryKeys(t *testing.T) {
	tests := []struct {
		name, purl, version, ecosystem, packageName string
	}{
		{"maven", "pkg:maven/org.apache.commons/commons-lang3@3.14.0", "3.14.0", "Maven", "org.apache.commons:commons-lang3"},
		{"maven namespace", "pkg:maven/org/apache/commons/commons-lang3@3.14.0", "3.14.0", "Maven", "org.apache.commons:commons-lang3"},
		{"go", "pkg:golang/github.com/foo/bar@v1.2.3", "v1.2.3", "Go", "github.com/foo/bar"},
		{"npm", "pkg:npm/%40scope/pkg@1.0.0", "1.0.0", "npm", "@scope/pkg"},
		{"pypi", "pkg:pypi/Flask@3.0.0", "3.0.0", "PyPI", "flask"},
		{"debian", "pkg:deb/debian/openssl@1.0?distro=debian-12", "1.0", "Debian:12", "openssl"},
		{"alpine", "pkg:apk/alpine/musl@1.2?distro=alpine-3.19", "1.2", "Alpine:v3.19", "musl"},
		{"oracle linux", "pkg:rpm/ol/openssl@3.0-1?distro=ol-9", "3.0-1", "Oracle Linux:9", "openssl"},
	}
	for _, test := range tests {
		identity := IdentityFromComponent(Component{PURL: test.purl, Version: test.version})
		if identity.Status != IdentityResolved || identity.Ecosystem != test.ecosystem || identity.Package != test.packageName || identity.Fingerprint == "" {
			t.Errorf("%s: identity=%+v", test.name, identity)
		}
	}
}

func TestIdentityFromComponentFailsClosed(t *testing.T) {
	for _, component := range []Component{
		{PURL: "", Version: "1.0"},
		{PURL: "pkg:unknown/foo@1.0", Version: "1.0"},
		{PURL: "pkg:maven/org/foo@1.0", Version: "2.0"},
		{PURL: "pkg:deb/debian/openssl@1.0", Version: "1.0"},
	} {
		identity := IdentityFromComponent(component)
		if identity.Status == IdentityResolved || identity.Fingerprint != "" {
			t.Fatalf("unsupported component matched: %+v", identity)
		}
	}
}

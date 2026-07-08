package licensemeta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// fakePyPI serves version-specific PyPI JSON for a fixed set of packages, exercising each license
// source (license_expression, trove classifiers, free-text) + the not-found fall-through.
func fakePyPI(t *testing.T) *httptest.Server {
	t.Helper()
	bodies := map[string]string{
		// classifier path (the deps.dev "non-standard" case this resolver exists for)
		"/pypi/amqp/5.3.1/json": `{"info":{"license":"BSD","classifiers":["License :: OSI Approved :: BSD License","Programming Language :: Python"]}}`,
		// PEP 639 license_expression path (most authoritative)
		"/pypi/rich/13.0.0/json": `{"info":{"license":"","license_expression":"MIT","classifiers":[]}}`,
		// free-text info.license path
		"/pypi/reqs/2.0.0/json": `{"info":{"license":"Apache 2.0","classifiers":[]}}`,
		// no usable license anywhere → stays unknown
		"/pypi/mystery/1.0.0/json": `{"info":{"license":"","classifiers":["Programming Language :: Python"]}}`,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := bodies[r.URL.Path]; ok {
			_, _ = w.Write([]byte(b))
			return
		}
		http.NotFound(w, r)
	}))
}

func TestPyPIEnrichResolvesLicenses(t *testing.T) {
	srv := fakePyPI(t)
	defer srv.Close()
	e := NewPyPI(srv.URL, srv.Client())

	comps := []sbom.Component{
		{Name: "amqp", Version: "5.3.1", PURL: "pkg:pypi/amqp@5.3.1"},       // classifier → BSD-3-Clause
		{Name: "rich", Version: "13.0.0", PURL: "pkg:pypi/rich@13.0.0"},     // expression → MIT
		{Name: "reqs", Version: "2.0.0", PURL: "pkg:pypi/reqs@2.0.0"},       // free-text → Apache-2.0
		{Name: "mystery", Version: "1.0.0", PURL: "pkg:pypi/mystery@1.0.0"}, // unresolved
		{Name: "left", Version: "1.0.0", PURL: "pkg:npm/left@1.0.0"},        // not pypi → skipped
		{Name: "done", Version: "9", PURL: "pkg:pypi/done@9", // already licensed → untouched
			Licenses: []sbom.License{{SPDXID: "MIT"}}, LicenseSource: "sbom"},
	}
	out := e.Enrich(context.Background(), comps)
	got := map[string]string{}
	for _, c := range out {
		if len(c.Licenses) > 0 {
			got[c.Name] = c.Licenses[0].SPDXID + "/" + c.LicenseSource
		}
	}
	want := map[string]string{
		"amqp": "BSD-3-Clause/registry",
		"rich": "MIT/registry",
		"reqs": "Apache-2.0/registry",
		"done": "MIT/sbom", // untouched
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// mystery stays unknown; npm is not handled by the PyPI resolver.
	for _, c := range out {
		if c.Name == "mystery" && len(c.Licenses) > 0 {
			t.Errorf("mystery must stay unresolved, got %v", c.Licenses)
		}
		if c.Name == "left" && len(c.Licenses) > 0 {
			t.Errorf("npm component must be skipped by the PyPI resolver, got %v", c.Licenses)
		}
	}
}

func TestTroveAndFreeTextMapping(t *testing.T) {
	if troveSPDX["License :: OSI Approved :: Apache Software License"] != "Apache-2.0" {
		t.Error("Apache trove classifier must map to Apache-2.0")
	}
	cases := map[string]string{
		"MIT": "MIT", "BSD": "BSD-3-Clause", "Apache 2.0": "Apache-2.0", "ISC": "ISC",
		"BSD-3-Clause": "BSD-3-Clause", // bare SPDX id passes through
		"":             "", "this is a very long license body that clearly is not an identifier at all": "",
	}
	for in, want := range cases {
		if got := normalizePyLicenseText(in); got != want {
			t.Errorf("normalizePyLicenseText(%q) = %q, want %q", in, got, want)
		}
	}
}

//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func assertExactHTMLMaintainabilityRules(t *testing.T, source string, expected ...string) {
	t.Helper()
	findings := scanHTMLFixture(source)
	var got []string
	for _, finding := range findings {
		if finding.Kind == "quality" {
			got = append(got, finding.Rule)
		}
	}
	sort.Strings(got)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("maintainability rules mismatch:\ngot:  %v\nwant: %v\nsource:\n%s", got, want, source)
	}
}

func TestHTMLMaintainabilityPerRuleMatrix(t *testing.T) {
	tests := []struct {
		name      string
		positive  string
		expected  []string
		negatives []string
	}{
		{
			name: "img-alt-missing", positive: `<img src="chart.png">`,
			expected:  []string{"html:img-alt-missing"},
			negatives: []string{`<img src="chart.png" alt="">`, `<img src="chart.png" role="presentation">`},
		},
		{
			name: "area-alt-missing", positive: `<area href="/map" alt="  ">`,
			expected:  []string{"html:area-alt-missing"},
			negatives: []string{`<area href="/map" alt="North">`, `<area alt="">`},
		},
		{
			name: "input-image-alt-missing", positive: `<input type="image" src="search.png">`,
			expected:  []string{"html:input-image-alt-missing"},
			negatives: []string{`<input type="image" alt="Search">`, `<input type="submit">`},
		},
		{
			name: "object-fallback-missing", positive: `<object data="report.pdf"><param name="page" value="1"></object>`,
			expected:  []string{"html:deprecated-tag", "html:object-fallback-missing"},
			negatives: []string{`<object data="report.pdf">Download the report</object>`, `<object data="report.pdf"><a>Download</a></object>`},
		},
		{
			name: "iframe-title-missing", positive: `<iframe></iframe>`,
			expected:  []string{"html:iframe-title-missing"},
			negatives: []string{`<iframe title="Weather"></iframe>`, `<span id="frame-name">Weather</span><iframe aria-labelledby="frame-name"></iframe>`},
		},
		{
			name:     "html-title-missing",
			positive: `<!doctype html><html lang="en"><head></head><body><main>Content</main></body></html>`,
			expected: []string{"html:html-title-missing"},
			negatives: []string{
				`<div>Fragment</div>`,
				`<!doctype html><html lang="en"><head><title>Home</title></head><body><main>Content</main></body></html>`,
			},
		},
		{
			name:     "missing-lang",
			positive: `<!doctype html><html><head><title>Home</title></head><body><main>Content</main></body></html>`,
			expected: []string{"html:missing-lang"},
			negatives: []string{
				`<div>Fragment</div>`,
				`<!doctype html><html lang="en"><head><title>Home</title></head><body><main>Content</main></body></html>`,
			},
		},
		{
			name: "label-missing", positive: `<input type="text">`,
			expected:  []string{"html:label-missing"},
			negatives: []string{`<label>Name <input type="text"></label>`, `<input type="text" aria-label="Name">`},
		},
		{
			name: "button-name-missing", positive: `<button type="button"></button>`,
			expected:  []string{"html:button-name-missing"},
			negatives: []string{`<button type="button">Save</button>`, `<input type="submit">`},
		},
		{
			name: "link-name-missing", positive: `<a href="/account"></a>`,
			expected:  []string{"html:link-name-missing"},
			negatives: []string{`<a href="/account">Account</a>`, `<a href="/account" title="Account"></a>`},
		},
		{
			name:     "fieldset-legend-missing",
			positive: `<fieldset><input aria-label="Email"><input aria-label="Phone"></fieldset>`,
			expected: []string{"html:fieldset-legend-missing"},
			negatives: []string{
				`<fieldset><legend>Contact</legend><input aria-label="Email"><input aria-label="Phone"></fieldset>`,
				`<fieldset aria-label="Contact"><input aria-label="Email"><input aria-label="Phone"></fieldset>`,
			},
		},
		{
			name:     "table-caption-missing",
			positive: `<table><tr><th>Month</th></tr></table>`,
			expected: []string{"html:table-caption-missing"},
			negatives: []string{
				`<table><caption>Months</caption><tr><th>Month</th></tr></table>`,
				`<table aria-label="Months"><tr><th>Month</th></tr></table>`,
			},
		},
		{
			name:     "table-header-reference-missing",
			positive: `<table><caption>People</caption><tr><th id="name">Name</th></tr><tr><td headers="missing">Ada</td></tr></table>`,
			expected: []string{"html:table-header-reference-missing"},
			negatives: []string{
				`<table><caption>People</caption><tr><th id="name">Name</th></tr><tr><td headers="name">Ada</td></tr></table>`,
				`<table><caption>People</caption><tr><th>Name</th></tr><tr><td>Ada</td></tr></table>`,
			},
		},
		{
			name: "heading-empty", positive: `<h2></h2>`,
			expected:  []string{"html:heading-empty"},
			negatives: []string{`<h2>Settings</h2>`, `<div role="heading" aria-level="2" aria-label="Settings"></div>`},
		},
		{
			name: "heading-order", positive: `<h2>Settings</h2><h4>Notifications</h4>`,
			expected:  []string{"html:heading-order"},
			negatives: []string{`<h2>Settings</h2><h3>Notifications</h3>`, `<h3>Details</h3><h2>Settings</h2>`},
		},
		{
			name:     "main-landmark-missing",
			positive: `<!doctype html><html lang="en"><head><title>Home</title></head><body>Content</body></html>`,
			expected: []string{"html:main-landmark-missing"},
			negatives: []string{
				`<div>Fragment</div>`,
				`<!doctype html><html lang="en"><head><title>Home</title></head><body><main>Content</main></body></html>`,
			},
		},
		{
			name: "duplicate-main-landmark", positive: `<main>Primary</main><div role="main">Secondary</div>`,
			expected: []string{"html:duplicate-main-landmark"},
			negatives: []string{
				`<main>Primary</main>`,
				`<main>Primary</main><main hidden>Hidden</main>`,
				`<main aria-label="Primary"></main><main aria-label="Secondary"></main>`,
			},
		},
		{
			name: "tabindex-positive", positive: `<div tabindex="2">Panel</div>`,
			expected:  []string{"html:tabindex-positive"},
			negatives: []string{`<div tabindex="0">Panel</div>`, `<div tabindex="-1">Panel</div>`},
		},
		{
			name: "accesskey-used", positive: `<button accesskey="s">Save</button>`,
			expected:  []string{"html:accesskey-used"},
			negatives: []string{`<button>Save</button>`, `<button accesskey="">Save</button>`},
		},
		{
			name: "autofocus-used", positive: `<input aria-label="Search" autofocus>`,
			expected:  []string{"html:autofocus-used"},
			negatives: []string{`<input aria-label="Search">`, `<button>Search</button>`},
		},
		{
			name: "nested-interactive-control", positive: `<a href="/details">Details <button>Edit</button></a>`,
			expected:  []string{"html:nested-interactive-control"},
			negatives: []string{`<a href="/details">Details <span>Edit</span></a>`, `<a href="/details">Details</a><button>Edit</button>`},
		},
		{
			name: "aria-hidden-focusable", positive: `<div aria-hidden="true"><button>Hidden action</button></div>`,
			expected:  []string{"html:aria-hidden-focusable"},
			negatives: []string{`<div aria-hidden="true"><button tabindex="-1">Hidden action</button></div>`, `<div aria-hidden="false"><button>Action</button></div>`},
		},
		{
			name:     "aria-hidden-body",
			positive: `<!doctype html><html lang="en"><head><title>Home</title></head><body aria-hidden="true"><main>Content</main></body></html>`,
			expected: []string{"html:aria-hidden-body", "html:main-landmark-missing"},
			negatives: []string{
				`<!doctype html><html lang="en"><head><title>Home</title></head><body aria-hidden="false"><main>Content</main></body></html>`,
				`<div aria-hidden="true">Decorative</div>`,
			},
		},
		{
			name: "aria-reference-missing", positive: `<button aria-describedby="missing">Save</button>`,
			expected:  []string{"html:aria-reference-missing"},
			negatives: []string{`<button aria-describedby="help">Save</button><span id="help">Help</span>`, `<button aria-describedby="{{ helpID }}">Save</button>`},
		},
		{
			name: "aria-role-invalid", positive: `<div role="widget">Control</div>`,
			expected:  []string{"html:aria-role-invalid"},
			negatives: []string{`<div role="unknown button">Control</div>`, `<div role="{{ dynamicRole }}">Control</div>`},
		},
		{
			name: "aria-required-attribute-missing", positive: `<div role="checkbox">Remember me</div>`,
			expected:  []string{"html:aria-required-attribute-missing"},
			negatives: []string{`<div role="checkbox" aria-checked="false">Remember me</div>`, `<input type="checkbox" role="checkbox" aria-label="Remember me">`},
		},
		{
			name: "role-img-name-missing", positive: `<div role="img"><span>Chart</span></div>`,
			expected:  []string{"html:role-img-name-missing"},
			negatives: []string{`<div role="img" aria-label="Chart"></div>`, `<img role="img" alt="Chart">`},
		},
		{
			name: "meta-refresh-used", positive: `<meta http-equiv="refresh" content="5;url=/next">`,
			expected: []string{"html:meta-refresh-used"},
			negatives: []string{
				`<meta http-equiv="content-security-policy" content="default-src 'self'">`,
				`<meta http-equiv="refresh" content="{{ refresh }}">`,
				`<meta http-equiv="refresh" content="">`,
				`<meta http-equiv="refresh" content="not a refresh directive">`,
			},
		},
		{
			name: "viewport-zoom-disabled", positive: `<meta name="viewport" content="width=device-width, maximum-scale=1">`,
			expected:  []string{"html:viewport-zoom-disabled"},
			negatives: []string{`<meta name="viewport" content="width=device-width, maximum-scale=2">`, `<meta name="viewport" content="maximum-scale=wide">`},
		},
		{
			name: "media-autoplay", positive: `<video autoplay></video>`,
			expected:  []string{"html:media-autoplay"},
			negatives: []string{`<video autoplay muted></video>`, `<video controls></video>`},
		},
		{
			name: "deprecated-tag", positive: `<center>Notice</center>`,
			expected:  []string{"html:deprecated-tag"},
			negatives: []string{`<div class="center">Notice</div>`, `<svg><font-face></font-face></svg>`},
		},
		{
			name: "deprecated-attribute", positive: `<p align="center">Notice</p>`,
			expected:  []string{"html:deprecated-attribute"},
			negatives: []string{`<p class="center">Notice</p>`, `<section align="center">Notice</section>`},
		},
	}

	if len(tests) != 32 {
		t.Fatalf("expected 32 rule matrix entries, got %d", len(tests))
	}
	for _, test := range tests {
		t.Run(test.name+"/positive", func(t *testing.T) {
			assertExactHTMLMaintainabilityRules(t, test.positive, test.expected...)
		})
		for index, negative := range test.negatives {
			t.Run(fmt.Sprintf("%s/negative-%d", test.name, index+1), func(t *testing.T) {
				assertExactHTMLMaintainabilityRules(t, negative)
			})
		}
	}
}

func TestHTMLMaintainabilityEntityDecoding(t *testing.T) {
	assertExactHTMLMaintainabilityRules(t, `<area href="/map" alt="&#x20;">`, "html:area-alt-missing")
	assertExactHTMLMaintainabilityRules(t, `<a aria-label="&#x20;" href="/"></a>`, "html:link-name-missing")
	assertExactHTMLMaintainabilityRules(t, `<div role="he&#x61;ding" aria-level="2">Title</div>`)
	assertExactHTMLMaintainabilityRules(t, `<meta name="view&#x70;ort" content="maximum-scale=1">`, "html:viewport-zoom-disabled")
	assertExactHTMLMaintainabilityRules(t, `<div role="he&amp;#x61;ding"></div>`, "html:aria-role-invalid")
}

func TestHTMLMaintainabilityTemplates(t *testing.T) {
	assertExactHTMLMaintainabilityRules(t, `<img alt="{{ description }}">`)
	assertExactHTMLMaintainabilityRules(t, `<iframe title="${ title }"></iframe>`)
	assertExactHTMLMaintainabilityRules(t, `<!doctype html><html lang="{{ locale }}"><head><title>{% title %}</title></head><body><main>Content</main></body></html>`)
	assertExactHTMLMaintainabilityRules(t, `<button aria-label="<% label %>"></button>`)
	assertExactHTMLMaintainabilityRules(t, `<button aria-labelledby="{{ labelID }}"></button>`)
	assertExactHTMLMaintainabilityRules(t, `<label for="{{ field }}">Name</label><input id="{{ field }}">`)
	assertExactHTMLMaintainabilityRules(t, `<div role="{{ role }}"></div>`)
	assertExactHTMLMaintainabilityRules(t, `<div role="heading" aria-level="{{ level }}">Title</div>`)
	assertExactHTMLMaintainabilityRules(t, `<table><caption>Data</caption><tr><td headers="{{ header }}">Value</td></tr></table>`)
	assertExactHTMLMaintainabilityRules(t, `<meta name="viewport" content="{{ viewport }}">`)
}

func TestHTMLMaintainabilityFirstCompleteDuplicateSelection(t *testing.T) {
	assertExactHTMLMaintainabilityRules(t, `<input alt alt="Search" type="image">`, "html:input-image-alt-missing")
	assertExactHTMLMaintainabilityRules(t, `<div role role="button"></div>`)
	assertExactHTMLMaintainabilityRules(t, `<meta name="viewport" content content="maximum-scale=1">`)
	assertExactHTMLMaintainabilityRules(t, `<button aria-describedby></button>`, "html:aria-reference-missing", "html:button-name-missing")
	assertExactHTMLMaintainabilityRules(t, `<table><caption>Data</caption><tr><td headers></td></tr></table>`, "html:table-header-reference-missing")
}

func TestHTMLMaintainabilityAccessibleNameReferences(t *testing.T) {
	assertExactHTMLMaintainabilityRules(t, `<span id="name">Save</span><button aria-labelledby="missing name"></button>`, "html:aria-reference-missing")
	assertExactHTMLMaintainabilityRules(t, `<span id="a" aria-labelledby="b"></span><span id="b" aria-labelledby="a"></span><button aria-labelledby="a"></button>`, "html:button-name-missing")

	var chain strings.Builder
	for i := 0; i < maxHTMLReferenceDepth+3; i++ {
		fmt.Fprintf(&chain, `<span id="n%d" aria-labelledby="n%d"></span>`, i, i+1)
	}
	fmt.Fprintf(&chain, `<span id="n%d">Too deep</span><button aria-labelledby="n0"></button>`, maxHTMLReferenceDepth+3)
	assertExactHTMLMaintainabilityRules(t, chain.String())
}

func TestHTMLMaintainabilityFocusabilityMatrix(t *testing.T) {
	assertExactHTMLMaintainabilityRules(t, `<div aria-hidden="true"><button disabled>Disabled</button></div>`)
	assertExactHTMLMaintainabilityRules(t, `<div aria-hidden="true"><input type="hidden"></div>`)
	assertExactHTMLMaintainabilityRules(t, `<div aria-hidden="true"><span tabindex="0">Focusable</span></div>`, "html:aria-hidden-focusable")
	assertExactHTMLMaintainabilityRules(t, `<div aria-hidden="true"><span contenteditable>Editable</span></div>`, "html:aria-hidden-focusable")
	assertExactHTMLMaintainabilityRules(t, `<div aria-hidden="true"><audio controls></audio></div>`, "html:aria-hidden-focusable")
	assertExactHTMLMaintainabilityRules(t, `<div aria-hidden="true"><button aria-disabled="true">Still focusable</button></div>`, "html:aria-hidden-focusable")
	assertExactHTMLMaintainabilityRules(t, `<fieldset disabled><legend><button>Exception</button></legend><button>Disabled</button></fieldset>`)
	assertExactHTMLMaintainabilityRules(t, `<div aria-hidden="true"><fieldset disabled><legend><button>Exception</button></legend></fieldset></div>`, "html:aria-hidden-focusable")
	assertExactHTMLMaintainabilityRules(t, `<details><summary>First</summary><summary>Later</summary></details>`)
	assertExactHTMLMaintainabilityRules(t, `<div aria-hidden="true"><details><summary>First</summary><summary>Later</summary></details></div>`, "html:aria-hidden-focusable")
	assertExactHTMLMaintainabilityRules(t, `<div inert><button>Ignored</button></div>`)
}

func TestHTMLMaintainabilityStructureRegressions(t *testing.T) {
	assertExactHTMLMaintainabilityRules(t, `<html><head><title>Bodyless</title></head><main>Content</main></html>`, "html:missing-lang")
	assertExactHTMLMaintainabilityRules(t, `<!doctype html><html lang="en"><head></head><body><title>Wrong place</title><main>Content</main></body></html>`, "html:html-title-missing")
	assertExactHTMLMaintainabilityRules(t, `<fieldset><span>Intro</span><legend>Later</legend><input aria-label="A"><input aria-label="B"></fieldset>`, "html:fieldset-legend-missing")
	assertExactHTMLMaintainabilityRules(t, `<table><caption>Outer</caption><tr><td headers="inner">Value</td></tr></table><table><caption>Inner</caption><tr><th id="inner">Header</th></tr></table>`, "html:table-header-reference-missing")
	assertExactHTMLMaintainabilityRules(t, `<h4>First may be any level</h4><h4>Same</h4><h2>Decrease</h2>`)
	assertExactHTMLMaintainabilityRules(t, `<div role="heading" aria-level="2">Two</div><div role="heading" aria-level="4">Four</div>`, "html:heading-order")
	assertExactHTMLMaintainabilityRules(t, `<div role="heading"></div>`, "html:aria-required-attribute-missing", "html:heading-empty")
}

func TestHTMLMaintainabilityV3ReviewRegressions(t *testing.T) {
	t.Run("uniquely-named-main-landmarks", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(t, `<main aria-label="Primary"></main><main aria-label="Secondary"></main>`)
		assertExactHTMLMaintainabilityRules(
			t,
			`<span id="primary">Primary</span><span id="secondary">Secondary</span><main aria-labelledby="primary"></main><main aria-labelledby="secondary"></main>`,
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<main aria-label="Primary"></main><main aria-label=" primary "></main>`,
			"html:duplicate-main-landmark",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<main aria-label="Primary"></main><main></main>`,
			"html:duplicate-main-landmark",
		)
	})

	t.Run("direct-hidden-labelledby-text", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(
			t,
			`<span id="button-name" hidden>Save</span><button aria-labelledby="button-name"></button>`,
		)
	})

	t.Run("fieldset-and-table-resolve-labelledby", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(
			t,
			`<fieldset aria-labelledby="missing"><input aria-label="A"><input aria-label="B"></fieldset>`,
			"html:aria-reference-missing",
			"html:fieldset-legend-missing",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<table aria-labelledby="missing"><tr><th>Header</th></tr></table>`,
			"html:aria-reference-missing",
			"html:table-caption-missing",
		)
	})

	t.Run("hidden-policy", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(t, `<area hidden href="/map">`)
		assertExactHTMLMaintainabilityRules(t, `<input hidden type="image">`)
		assertExactHTMLMaintainabilityRules(t, `<fieldset hidden><input><input></fieldset>`)
		assertExactHTMLMaintainabilityRules(t, `<table hidden><tr><th>Header</th></tr></table>`)
		assertExactHTMLMaintainabilityRules(t, `<fieldset><input hidden><input aria-label="Only visible"></fieldset>`)
	})

	t.Run("select-implicit-roles", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(t, `<select role="combobox" aria-label="Choice"></select>`)
		assertExactHTMLMaintainabilityRules(t, `<select multiple role="listbox" aria-label="Choices"></select>`)
		assertExactHTMLMaintainabilityRules(t, `<select size="2" role="listbox" aria-label="Choices"></select>`)
		assertExactHTMLMaintainabilityRules(t, `<select size="" role="combobox" aria-label="Country"></select>`)
		assertExactHTMLMaintainabilityRules(t, `<select size="invalid" role="combobox" aria-label="Country"></select>`)
		assertExactHTMLMaintainabilityRules(t, `<select size role="combobox" aria-label="Country"></select>`)
		assertExactHTMLMaintainabilityRules(t, `<select size="{{ rows }}" role="combobox" aria-label="Country"></select>`)
		assertExactHTMLMaintainabilityRules(t, `<input type="{{ kind }}" role="checkbox" aria-label="Choice">`)
	})

	t.Run("hidden-elements-skip-required-aria-properties", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(t, `<div hidden role="checkbox"></div>`)
		assertExactHTMLMaintainabilityRules(t, `<div inert role="checkbox"></div>`)
		assertExactHTMLMaintainabilityRules(t, `<div aria-hidden="true" role="checkbox"></div>`)
	})

	t.Run("href-presence-defines-link-semantics", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(t, `<a href=""></a>`, "html:link-name-missing")
		assertExactHTMLMaintainabilityRules(t, `<a href></a>`, "html:link-name-missing")
		assertExactHTMLMaintainabilityRules(
			t,
			`<a href><button>Nested</button></a>`,
			"html:nested-interactive-control",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<div aria-hidden="true"><a href></a></div>`,
			"html:aria-hidden-focusable",
		)
	})

	t.Run("template-contenteditable-is-unknown", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(
			t,
			`<div aria-hidden="true"><span contenteditable="{{ editable }}">Text</span></div>`,
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<button><span contenteditable="{{ editable }}">Text</span></button>`,
		)
	})

	t.Run("meta-refresh-syntax", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(t, `<meta http-equiv="refresh" content="0">`, "html:meta-refresh-used")
		assertExactHTMLMaintainabilityRules(t, `<meta http-equiv="refresh" content="5;">`, "html:meta-refresh-used")
		assertExactHTMLMaintainabilityRules(t, `<meta http-equiv="refresh" content="5;/next">`, "html:meta-refresh-used")
		assertExactHTMLMaintainabilityRules(t, `<meta http-equiv="refresh" content="-1">`)
		assertExactHTMLMaintainabilityRules(t, `<meta http-equiv="refresh" content="5 seconds">`)
		assertExactHTMLMaintainabilityRules(t, `<meta http-equiv="refresh" content="5;url=">`)
	})

	t.Run("deprecated-attribute-per-name", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(
			t,
			`<table align="left" width="100" cellpadding="2"></table>`,
			"html:deprecated-attribute",
			"html:deprecated-attribute",
			"html:deprecated-attribute",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<table align="left" align="right" width="100"></table>`,
			"html:deprecated-attribute",
			"html:deprecated-attribute",
		)
	})
}

func TestHTMLMaintainabilitySecondAuditRegressions(t *testing.T) {
	t.Run("direct-child-scans", func(t *testing.T) {
		commentPrefix := strings.Repeat(`<!-- prefix -->`, 256)
		disabledControls := strings.Repeat(`<button>Disabled</button>`, 512)
		assertExactHTMLMaintainabilityRules(
			t,
			`<fieldset disabled>`+commentPrefix+`<legend>Group</legend>`+disabledControls+`</fieldset>`,
		)

		elementPrefix := strings.Repeat(`<span></span>`, 256)
		summaries := strings.Repeat(`<summary>Later</summary>`, 512)
		assertExactHTMLMaintainabilityRules(
			t,
			`<details>`+commentPrefix+elementPrefix+`<summary>First</summary>`+summaries+`</details>`,
		)

		assertExactHTMLMaintainabilityRules(
			t,
			`<fieldset><script></script><legend>Later</legend><input aria-label="A"><input aria-label="B"></fieldset>`,
			"html:fieldset-legend-missing",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<table>`+commentPrefix+`<script></script><caption>Data</caption><tr><th>Header</th></tr></table>`,
		)
	})

	t.Run("case-sensitive-id-references", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(
			t,
			`<span id="SaveLabel">Save</span><button aria-labelledby="SaveLabel"></button>`,
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<span id="SaveLabel">Save</span><button aria-labelledby="savelabel"></button>`,
			"html:aria-reference-missing",
			"html:button-name-missing",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<span id="Save&nbsp;Label">Save</span><button aria-labelledby="Save&nbsp;Label"></button>`,
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<table><caption>Data</caption><tr><th id="HeaderID">Header</th><td headers="HeaderID">Value</td></tr></table>`,
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<table><caption>Data</caption><tr><th id="HeaderID">Header</th><td headers="headerid">Value</td></tr></table>`,
			"html:table-header-reference-missing",
		)
	})

	t.Run("valid-area-hyperlink-attributes", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(
			t,
			`<area href="/fr" hreflang="fr" type="text/html" alt="Francais">`,
		)
	})

	t.Run("template-content-does-not-contribute-facts", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(
			t,
			`<template id="SaveLabel">Save</template><button aria-labelledby="SaveLabel"></button>`,
			"html:button-name-missing",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<template id="SaveLabel" aria-label="Save"></template><button aria-labelledby="SaveLabel"></button>`,
			"html:button-name-missing",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<template><span id="SaveLabel">Save</span></template><button aria-labelledby="SaveLabel"></button>`,
			"html:aria-reference-missing",
			"html:button-name-missing",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<template><label for="field">Name</label></template><input id="field">`,
			"html:label-missing",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<template><html lang="en"><head><title>Fake</title></head><body><main>Fake</main></body></html></template>`+
				`<html><head></head><body></body></html>`,
			"html:missing-lang",
			"html:html-title-missing",
			"html:main-landmark-missing",
		)
	})

	t.Run("explicit-button-role-on-input", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(
			t,
			`<input type="text" role="button">`,
			"html:label-missing",
			"html:button-name-missing",
		)
		assertExactHTMLMaintainabilityRules(t, `<input type="image" role="button" alt="Search">`)
	})
}

func TestHTMLMaintainabilityThirdAuditRegressions(t *testing.T) {
	t.Run("fieldset-first-child-and-first-legend-are-distinct", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(
			t,
			`<div aria-hidden="true"><fieldset disabled><span>Intro</span>`+
				`<legend><button>Exception</button></legend><button>Disabled</button></fieldset></div>`,
			"html:aria-hidden-focusable",
		)
		assertExactHTMLMaintainabilityRules(
			t,
			`<div aria-hidden="true"><fieldset disabled><span>Intro</span>`+
				`<legend>Group</legend><button>Disabled</button></fieldset></div>`,
		)
	})

	t.Run("incomplete-global-traversal-suppresses-maintainability", func(t *testing.T) {
		var source strings.Builder
		source.WriteString(`<button aria-labelledby="DeepLabel"></button>`)
		for i := 0; i < maxHTMLDepth+16; i++ {
			source.WriteString(`<div>`)
		}
		source.WriteString(`<span id="DeepLabel">Save</span>`)
		for i := 0; i < maxHTMLDepth+16; i++ {
			source.WriteString(`</div>`)
		}
		assertExactHTMLMaintainabilityRules(t, source.String())
	})

	t.Run("meta-refresh-delay-grammar", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(t, `<meta http-equiv="refresh" content="+5; /next">`)
	})

	t.Run("negative-maximum-scale-does-not-limit-zoom", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(t, `<meta name="viewport" content="maximum-scale=-1">`)
	})

	t.Run("template-applicability-is-unknown", func(t *testing.T) {
		assertExactHTMLMaintainabilityRules(t, `<area href="{{ target }}">`)
		assertExactHTMLMaintainabilityRules(t, `<button accesskey="{{ key }}">Save</button>`)
	})

	t.Run("role-img-finding-uses-role-attribute-line", func(t *testing.T) {
		assertHTMLRuleLine(t, "<div\n  role=\"img\">\n</div>", "html:role-img-name-missing", 2)
	})
}

func TestHTMLMaintainabilityBoundExhaustionSuppressesFindings(t *testing.T) {
	t.Run("object-fallback-scan", func(t *testing.T) {
		source := `<object>` + strings.Repeat(`<span></span>`, maxHTMLNameNodes+1) +
			`<a href="report.pdf">Download report</a></object>`
		assertExactHTMLMaintainabilityRules(t, source)
	})

	t.Run("name-scan", func(t *testing.T) {
		source := `<button>` + strings.Repeat(`<span></span>`, maxHTMLNameNodes+1) + `Late name</button>`
		assertExactHTMLMaintainabilityRules(t, source)
	})

	t.Run("id-index", func(t *testing.T) {
		var source strings.Builder
		for i := 0; i < maxTrackedIDs; i++ {
			fmt.Fprintf(&source, `<span id="tracked-%d"></span>`, i)
		}
		source.WriteString(`<span id="late-name">Late name</span><button aria-labelledby="late-name"></button>`)
		assertExactHTMLMaintainabilityRules(t, source.String())
	})

	t.Run("relation-token-list", func(t *testing.T) {
		var tokens strings.Builder
		for i := 0; i < maxHTMLRelationTokens+1; i++ {
			fmt.Fprintf(&tokens, "missing-%d ", i)
		}
		source := fmt.Sprintf(`<button aria-describedby="%s">Save</button>`, tokens.String())
		assertExactHTMLMaintainabilityRules(t, source)
	})

	t.Run("label-index", func(t *testing.T) {
		var source strings.Builder
		for i := 0; i < maxHTMLRelationTokens+1; i++ {
			source.WriteString(`<label for="target"></label>`)
		}
		source.WriteString(`<input id="target">`)
		assertExactHTMLMaintainabilityRules(t, source.String())
	})
}

func TestHTMLMaintainabilityDeprecatedInventories(t *testing.T) {
	tags := make([]string, 0, len(htmlDeprecatedTags))
	for tag := range htmlDeprecatedTags {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		t.Run("tag/"+tag, func(t *testing.T) {
			findings := scanHTMLFixture("<" + tag + ">legacy</" + tag + ">")
			count := 0
			for _, finding := range findings {
				if finding.Rule == "html:deprecated-tag" {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("expected one deprecated-tag finding for %s, got %d: %v", tag, count, findings)
			}
		})
	}

	elements := make([]string, 0, len(htmlDeprecatedAttributes))
	for element := range htmlDeprecatedAttributes {
		elements = append(elements, element)
	}
	sort.Strings(elements)
	for _, element := range elements {
		attrs := htmlDeprecatedAttributes[element]
		names := make([]string, 0, len(attrs))
		for name := range attrs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			t.Run("attribute/"+element+"/"+name, func(t *testing.T) {
				source := fmt.Sprintf("<%s %s=\"legacy\">content</%s>", element, name, element)
				findings := scanHTMLFixture(source)
				count := 0
				for _, finding := range findings {
					if finding.Rule == "html:deprecated-attribute" {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("expected one deprecated-attribute finding for %s[%s], got %d: %v", element, name, count, findings)
				}

				negative := fmt.Sprintf(`<section %s="legacy">content</section>`, name)
				for _, finding := range scanHTMLFixture(negative) {
					if finding.Rule == "html:deprecated-attribute" {
						t.Fatalf("unexpected deprecated-attribute finding for nonmatching section[%s]: %v", name, finding)
					}
				}
			})
		}
	}

	assertExactHTMLMaintainabilityRules(t, `<script type="text/javascript"></script>`, "html:deprecated-attribute")
	assertExactHTMLMaintainabilityRules(t, `<script type=""></script>`, "html:deprecated-attribute")
	assertExactHTMLMaintainabilityRules(t, `<script type="module"></script>`)
	assertExactHTMLMaintainabilityRules(t, `<script type="application/json"></script>`)
	assertExactHTMLMaintainabilityRules(t, `<input type="number" maxlength="3" aria-label="Count">`, "html:deprecated-attribute")
	assertExactHTMLMaintainabilityRules(t, `<input type="number" size="3" aria-label="Count">`, "html:deprecated-attribute")
	assertExactHTMLMaintainabilityRules(t, `<input type="text" maxlength="3" aria-label="Code">`)
	assertExactHTMLMaintainabilityRules(t, `<section align="center" width="2" name="x" type="x">Content</section>`)
}

func TestHTMLMaintainabilityMalformedAttributesFailClosed(t *testing.T) {
	source := "<img alt=\"description\"\n<input type=\"image\" alt=\"Search\">"
	findings := scanHTMLFixture(source)
	for _, finding := range findings {
		if finding.Kind == "quality" && finding.Line == 1 {
			t.Fatalf("unexpected maintainability finding from malformed first tag: %v", finding)
		}
	}
}

func TestHTMLMaintainabilityCommentsAndRawTextIsolation(t *testing.T) {
	source := `<!-- <img><button></button> -->
<script>const fake = '<a href="/"></a>';</script>
<style>p::before { content: '<iframe></iframe>'; }</style>
<template><img><button></button></template>
<div>Rendered</div>`
	assertExactHTMLMaintainabilityRules(t, source)
}

func TestHTMLMaintainabilityValidSiblingRecovery(t *testing.T) {
	source := "<img alt=\"broken\"\n<img src=\"real.png\">"
	findings := scanHTMLFixture(source)
	found := false
	for _, finding := range findings {
		if finding.Rule == "html:img-alt-missing" && finding.Line == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected valid sibling finding after malformed markup, got %v", findings)
	}
}

func TestHTMLMaintainabilityCRLFLineMapping(t *testing.T) {
	source := "<div>\r\n<button>\r\n</button>\r\n</div>"
	assertHTMLRuleLine(t, source, "html:button-name-missing", 2)
}

func TestHTMLMaintainabilityAttributeAndTagLines(t *testing.T) {
	tests := []struct {
		name, source, rule string
		line               int
	}{
		{"area alt", "<!doctype html>\n<area href=\"/map\" alt=\" \">", "html:area-alt-missing", 2},
		{"input image alt", "<!doctype html>\n<input type=\"image\">", "html:input-image-alt-missing", 2},
		{"iframe title", "<!doctype html>\n<iframe\n title=\" \"></iframe>", "html:iframe-title-missing", 3},
		{"html title", "<html lang=\"en\"><head></head><body><main>x</main></body></html>", "html:html-title-missing", 1},
		{"missing lang", "<html><head><title>x</title></head><body><main>x</main></body></html>", "html:missing-lang", 1},
		{"label", "<!doctype html>\n<input type=\"text\">", "html:label-missing", 2},
		{"table headers", "<table><caption>x</caption><tr><td headers=\"missing\">x</td></tr></table>", "html:table-header-reference-missing", 1},
		{"tabindex", "<div tabindex=\"1\">x</div>", "html:tabindex-positive", 1},
		{"accesskey", "<button accesskey=\"s\">Save</button>", "html:accesskey-used", 1},
		{"autofocus", "<input aria-label=\"Search\" autofocus>", "html:autofocus-used", 1},
		{"aria reference", "<button aria-describedby=\"missing\">Save</button>", "html:aria-reference-missing", 1},
		{"aria role", "<div role=\"widget\">x</div>", "html:aria-role-invalid", 1},
		{"aria required", "<div role=\"checkbox\">x</div>", "html:aria-required-attribute-missing", 1},
		{"meta refresh", `<meta http-equiv="refresh" content="1">`, "html:meta-refresh-used", 1},
		{"viewport", `<meta name="viewport" content="maximum-scale=1">`, "html:viewport-zoom-disabled", 1},
		{"autoplay", `<video autoplay></video>`, "html:media-autoplay", 1},
		{"deprecated attribute", `<p align="center">x</p>`, "html:deprecated-attribute", 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertHTMLRuleLine(t, test.source, test.rule, test.line)
		})
	}
}

func TestHTMLAllFamiliesSourceOrdering(t *testing.T) {
	source := `<!doctype html><a onclick="run()" class="a" class="b" href="javascript:run()" tabindex="2"></a>`
	tree := parseRoot(context.Background(), specs["HTML"], []byte(source))
	findings := htmlFindings(tree, []byte(source), "test.html")
	var rules []string
	for _, finding := range findings {
		rules = append(rules, finding.Rule)
	}
	want := []string{
		"html:link-name-missing",
		"html:inline-event-handler",
		"html:duplicate-attribute",
		"html:javascript-url",
		"html:tabindex-positive",
	}
	if strings.Join(rules, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected cross-family order:\ngot  %v\nwant %v", rules, want)
	}
}

func TestHTMLMaintainabilityInventoryParity(t *testing.T) {
	catalog, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("catalog.List(): %v", err)
	}

	var htmlRules []rule.Rule
	typeCounts := map[rule.Type]int{}
	qualityCounts := map[rule.Quality]int{}
	sourceURLs := map[string]bool{}
	sourceOccurrences := 0
	maintainabilityRationales := map[string]string{}
	for _, entry := range rules {
		if entry.Language != "HTML" {
			continue
		}
		htmlRules = append(htmlRules, entry)
		typeCounts[entry.Type]++
		for _, quality := range entry.Qualities {
			qualityCounts[quality]++
			if quality != rule.QualityMaintainability {
				continue
			}
			maintainabilityRationales[string(entry.Key)] = entry.Rationale
			for _, token := range strings.Fields(entry.Rationale) {
				if strings.HasPrefix(token, "https://") {
					sourceURLs[strings.Trim(token, ";,.")] = true
					sourceOccurrences++
				}
			}
		}
	}
	if len(htmlRules) != 50 || len(htmlRuntimeRules) != 50 {
		t.Fatalf("expected runtime/catalog counts 50/50, got %d/%d", len(htmlRuntimeRules), len(htmlRules))
	}
	if typeCounts[rule.TypeBug] != 10 || typeCounts[rule.TypeVulnerability] != 2 ||
		typeCounts[rule.TypeSecurityHotspot] != 6 || typeCounts[rule.TypeCodeSmell] != 32 {
		t.Fatalf("unexpected HTML type counts: %v", typeCounts)
	}
	if qualityCounts[rule.QualityReliability] != 10 || qualityCounts[rule.QualitySecurity] != 8 ||
		qualityCounts[rule.QualityMaintainability] != 32 {
		t.Fatalf("unexpected HTML quality counts: %v", qualityCounts)
	}

	runtimeKinds := map[string]int{}
	for _, runtimeRule := range htmlRuntimeRules {
		runtimeKinds[runtimeRule.kind]++
		catalogRule, getErr := catalog.Get(context.Background(), rule.Key(runtimeRule.id))
		if getErr != nil {
			t.Fatalf("runtime rule missing from catalog: %s: %v", runtimeRule.id, getErr)
		}
		if string(catalogRule.DefaultSeverity) != runtimeRule.severity {
			t.Fatalf("severity mismatch for %s: catalog=%s runtime=%s", runtimeRule.id, catalogRule.DefaultSeverity, runtimeRule.severity)
		}
	}
	if runtimeKinds["reliability"] != 10 || runtimeKinds["security"] != 8 || runtimeKinds["quality"] != 32 {
		t.Fatalf("unexpected runtime kind counts: %v", runtimeKinds)
	}
	for key, expected := range map[string]struct {
		title       string
		description string
	}{
		"duplicate-main-landmark": {
			title:       "Main landmarks need unique accessible names",
			description: "Second or later visible main landmark is unnamed or repeats an earlier main landmark name.",
		},
		"meta-refresh-used": {
			title:       "Meta refresh requires accessibility review",
			description: "Syntactically valid static meta refresh or redirect requires accessibility and usability review.",
		},
	} {
		runtimeRule := htmlRuntimeRules[key]
		if runtimeRule.title != expected.title || runtimeRule.description != expected.description {
			t.Fatalf(
				"runtime metadata mismatch for %s: got %q / %q, want %q / %q",
				key,
				runtimeRule.title,
				runtimeRule.description,
				expected.title,
				expected.description,
			)
		}
	}
	expectedSources := map[string]string{
		"html:img-alt-missing":                 "https://www.w3.org/WAI/WCAG22/Techniques/html/H37",
		"html:area-alt-missing":                "https://www.w3.org/WAI/WCAG22/Techniques/html/H24",
		"html:input-image-alt-missing":         "https://www.w3.org/WAI/WCAG22/Techniques/html/H36",
		"html:object-fallback-missing":         "https://www.w3.org/WAI/WCAG22/Techniques/html/H53",
		"html:iframe-title-missing":            "https://www.w3.org/WAI/WCAG22/Techniques/html/H64",
		"html:html-title-missing":              "https://www.w3.org/WAI/WCAG22/Techniques/html/H25",
		"html:missing-lang":                    "https://www.w3.org/WAI/WCAG22/Techniques/html/H57",
		"html:label-missing":                   "https://www.w3.org/WAI/standards-guidelines/act/rules/e086e5/",
		"html:button-name-missing":             "https://www.w3.org/WAI/standards-guidelines/act/rules/97a4e1/",
		"html:link-name-missing":               "https://www.w3.org/WAI/standards-guidelines/act/rules/c487ae/",
		"html:fieldset-legend-missing":         "https://www.w3.org/WAI/WCAG22/Techniques/html/H71",
		"html:table-caption-missing":           "https://www.w3.org/WAI/WCAG22/Techniques/html/H39",
		"html:table-header-reference-missing":  "https://www.w3.org/WAI/WCAG22/Techniques/html/H43",
		"html:heading-empty":                   "https://www.w3.org/TR/wai-aria-1.2/#heading",
		"html:heading-order":                   "https://www.w3.org/WAI/WCAG22/Techniques/general/G141",
		"html:main-landmark-missing":           "https://www.w3.org/WAI/ARIA/apg/practices/landmark-regions/",
		"html:duplicate-main-landmark":         "https://www.w3.org/WAI/ARIA/apg/patterns/landmarks/examples/main.html",
		"html:tabindex-positive":               "https://www.w3.org/WAI/WCAG22/Techniques/html/H4",
		"html:accesskey-used":                  "https://html.spec.whatwg.org/multipage/interaction.html#the-accesskey-attribute",
		"html:autofocus-used":                  "https://html.spec.whatwg.org/multipage/interaction.html#the-autofocus-attribute",
		"html:nested-interactive-control":      "https://html.spec.whatwg.org/multipage/dom.html#interactive-content-2",
		"html:aria-hidden-focusable":           "https://www.w3.org/WAI/standards-guidelines/act/rules/6cfa84/",
		"html:aria-hidden-body":                "https://www.w3.org/TR/wai-aria-1.2/#aria-hidden",
		"html:aria-reference-missing":          "https://www.w3.org/TR/wai-aria-1.2/#attrs_relationships",
		"html:aria-role-invalid":               "https://www.w3.org/TR/wai-aria-1.2/#role_definitions",
		"html:aria-required-attribute-missing": "https://www.w3.org/WAI/standards-guidelines/act/rules/4e8ab6/",
		"html:role-img-name-missing":           "https://www.w3.org/TR/wai-aria-1.2/#img",
		"html:meta-refresh-used":               "https://www.w3.org/WAI/standards-guidelines/act/rules/bc659a/",
		"html:viewport-zoom-disabled":          "https://www.w3.org/WAI/standards-guidelines/act/rules/b4f0c3/",
		"html:media-autoplay":                  "https://html.spec.whatwg.org/multipage/media.html#attr-media-autoplay",
		"html:deprecated-tag":                  "https://html.spec.whatwg.org/multipage/obsolete.html#non-conforming-features",
		"html:deprecated-attribute":            "https://html.spec.whatwg.org/multipage/obsolete.html#non-conforming-features",
	}
	if len(maintainabilityRationales) != len(expectedSources) {
		t.Fatalf("expected %d maintainability rationales, got %d", len(expectedSources), len(maintainabilityRationales))
	}
	for ruleID, expectedSource := range expectedSources {
		rationale, exists := maintainabilityRationales[ruleID]
		if !exists || !strings.Contains(rationale, expectedSource) {
			t.Fatalf("%s rationale must cite V3 source %s; got %q", ruleID, expectedSource, rationale)
		}
	}
	if sourceOccurrences != 37 || len(sourceURLs) != 36 {
		t.Fatalf(
			"expected 37 official source citations and 36 unique URLs, got %d/%d",
			sourceOccurrences,
			len(sourceURLs),
		)
	}
	for _, requiredSource := range []string{
		"https://www.w3.org/TR/accname-1.2/",
		"https://www.w3.org/TR/wai-aria-1.2/",
		"https://www.w3.org/TR/html-aria/",
		"https://www.w3.org/TR/html-aam-1.0/",
		"https://html.spec.whatwg.org/",
	} {
		if !sourceURLs[requiredSource] {
			t.Fatalf("required cross-cutting source missing from HTML catalog: %s", requiredSource)
		}
	}

	profile, ok := qualityprofile.BuiltIn("HTML", rules)
	if !ok || len(profile.ActivatedRules) != 50 {
		t.Fatalf("expected built-in HTML profile with 50 rules, got ok=%v count=%d", ok, len(profile.ActivatedRules))
	}
}

func TestHTMLMaintainabilityPerRuleFindingCap(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 30; i++ {
		source.WriteString(`<div tabindex="2">Panel</div>`)
	}
	findings := scanHTMLFixture(source.String())
	count := 0
	for _, finding := range findings {
		if finding.Rule == "html:tabindex-positive" {
			count++
		}
	}
	if count != 20 {
		t.Fatalf("expected per-rule cap 20, got %d", count)
	}
}

func TestHTMLAllFamiliesSharedGlobalCap(t *testing.T) {
	var source strings.Builder
	source.WriteString("<!doctype html>\n")
	for i := 0; i < 80; i++ {
		fmt.Fprintf(&source, `<a id="same" id="duplicate" href="javascript:run()" onclick="run()" tabindex="2"></a>`)
	}
	findings := scanHTMLFixture(source.String())
	if len(findings) != 100 {
		t.Fatalf("expected shared global cap 100, got %d", len(findings))
	}
}

func TestHTMLMaintainabilityDeterminism(t *testing.T) {
	source := `<!doctype html>
<html><head><meta name="viewport" content="maximum-scale=1"><title></title></head>
<body aria-hidden="true">
<a href="javascript:run()" onclick="run()" tabindex="2" class="a" class="b"></a>
<div role="checkbox"></div>
<table><tr><th id="h">Header</th><td headers="missing">Value</td></tr></table>
<center align="center">Legacy</center>
</body></html>`
	var reference string
	for iteration := 0; iteration < 50; iteration++ {
		findings := scanHTMLFixture(source)
		var current strings.Builder
		for _, finding := range findings {
			fmt.Fprintf(
				&current,
				"%s|%s|%s|%s|%s|%s|%s|%d\n",
				finding.Rule,
				finding.Kind,
				finding.CWE,
				finding.Severity,
				finding.Title,
				finding.Description,
				finding.File,
				finding.Line,
			)
		}
		if iteration == 0 {
			reference = current.String()
		} else if current.String() != reference {
			t.Fatalf("nondeterministic findings at iteration %d", iteration)
		}
	}
}

func TestHTMLMaintainabilityQualityForE2E(t *testing.T) {
	source := `<!doctype html>
<html>
<head><meta name="viewport" content="maximum-scale=1"></head>
<body>
<a href="javascript:run()" onclick="run()" tabindex="2" class="a" class="b"></a>
<div role="checkbox"></div>
<center>Legacy</center>
</body>
</html>`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "maintainability.html")
	if err := os.WriteFile(filePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write HTML fixture: %v", err)
	}
	result, err := QualityFor(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("QualityFor(%s): %v", tmpDir, err)
	}
	findings := result.Findings
	required := map[string]bool{
		"html:duplicate-attribute":             false,
		"html:javascript-url":                  false,
		"html:link-name-missing":               false,
		"html:main-landmark-missing":           false,
		"html:tabindex-positive":               false,
		"html:aria-required-attribute-missing": false,
		"html:deprecated-tag":                  false,
		"html:viewport-zoom-disabled":          false,
	}
	for _, finding := range findings {
		if _, exists := required[finding.Rule]; exists {
			required[finding.Rule] = true
		}
	}
	for ruleID, found := range required {
		if !found {
			t.Errorf("expected E2E finding %s, got %v", ruleID, findings)
		}
	}
}

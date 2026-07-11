package licensemeta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PyPI resolves a PyPI component's license from the PyPI registry (pypi.org JSON API). It exists
// because deps.dev classifies a large share of PyPI packages as "non-standard" – their license lives
// in the trove classifiers or the free-text info.license, not deps.dev's normalized field – so the
// deps.dev enricher leaves them unresolved. PyPI's own metadata carries the authoritative license:
// PEP 639 license_expression (SPDX), the trove "License :: ..." classifiers, or free-text info.license.
// Placed AFTER the deps.dev enricher in the chain, so it only fills what deps.dev could not.
type PyPI struct {
	baseURL string
	client  *http.Client
}

// NewPyPI returns a PyPI-registry license enricher. baseURL defaults to https://pypi.org (override for
// tests/mirrors); client defaults to a 15s timeout.
func NewPyPI(baseURL string, client *http.Client) *PyPI {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://pypi.org"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &PyPI{baseURL: baseURL, client: client}
}

var _ ports.LicenseEnricher = (*PyPI)(nil)

// Enrich fills the license of PyPI components that are still unresolved, concurrency-bounded + cached.
// Best-effort: a network/parse failure leaves the component unchanged (still unknown), never errors.
func (p *PyPI) Enrich(ctx context.Context, comps []sbom.Component) []sbom.Component {
	cache := map[string][]sbom.License{}
	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i := range comps {
		c := &comps[i]
		if len(c.Licenses) > 0 && !onlyUnresolvedLicenseEvidence(c.Licenses) {
			continue // already resolved (declared or by an earlier chain enricher)
		}
		if !strings.HasPrefix(c.PURL, "pkg:pypi/") || !sbom.IsResolvedVersion(c.Version) {
			continue
		}
		sys, name, ver, ok := parsePURL(c.PURL)
		if !ok || sys != "pypi" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(c *sbom.Component, name, ver string) {
			defer wg.Done()
			defer func() { <-sem }()
			key := name + "@" + ver
			mu.Lock()
			lics, hit := cache[key]
			mu.Unlock()
			if !hit {
				lics = p.lookup(ctx, name, ver)
				mu.Lock()
				cache[key] = lics
				mu.Unlock()
			}
			if len(lics) > 0 {
				c.Licenses = lics
				c.LicenseSource = sbom.LicenseSourceRegistry
				c.LicenseConfidence = "registry"
				c.UnknownReason = ""
			}
		}(c, name, ver)
	}
	wg.Wait()
	return comps
}

// lookup queries the PyPI JSON API for one package version and derives its SPDX license from, in order
// of authority: PEP 639 license_expression, the trove classifiers, then the free-text info.license.
func (p *PyPI) lookup(ctx context.Context, name, ver string) []sbom.License {
	if lics := p.fetch(ctx, fmt.Sprintf("%s/pypi/%s/%s/json", p.baseURL, url.PathEscape(name), url.PathEscape(ver))); lics != nil {
		return lics
	}
	// Some versions lack a per-version document; fall back to the package's latest metadata.
	return p.fetch(ctx, fmt.Sprintf("%s/pypi/%s/json", p.baseURL, url.PathEscape(name)))
}

func (p *PyPI) fetch(ctx context.Context, u string) []sbom.License {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body struct {
		Info struct {
			License           string   `json:"license"`
			LicenseExpression string   `json:"license_expression"`
			Classifiers       []string `json:"classifiers"`
		} `json:"info"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&body); err != nil {
		return nil
	}
	// 1. PEP 639 license_expression is already an SPDX expression – the most authoritative.
	if e := strings.TrimSpace(body.Info.LicenseExpression); e != "" {
		return []sbom.License{{SPDXID: e, Name: e}}
	}
	// 2. Trove classifiers ("License :: ...") map deterministically to SPDX.
	var out []sbom.License
	seen := map[string]bool{}
	for _, cl := range body.Info.Classifiers {
		if !strings.HasPrefix(cl, "License ::") {
			continue
		}
		if id := troveSPDX[strings.TrimSpace(cl)]; id != "" && !seen[id] {
			seen[id] = true
			out = append(out, sbom.License{SPDXID: id, Name: id})
		}
	}
	if len(out) > 0 {
		return out
	}
	// 3. Free-text info.license as a last resort (best-effort normalization).
	if id := normalizePyLicenseText(body.Info.License); id != "" {
		return []sbom.License{{SPDXID: id, Name: id}}
	}
	return nil
}

// troveSPDX maps PyPI trove license classifiers to SPDX ids. Covers the classifiers that account for
// the overwhelming majority of PyPI packages; an unmapped classifier falls through to the free-text path.
var troveSPDX = map[string]string{
	"License :: OSI Approved :: MIT License":                                             "MIT",
	"License :: OSI Approved :: MIT No Attribution License (MIT-0)":                      "MIT-0",
	"License :: OSI Approved :: BSD License":                                             "BSD-3-Clause",
	"License :: OSI Approved :: Apache Software License":                                 "Apache-2.0",
	"License :: OSI Approved :: ISC License (ISCL)":                                      "ISC",
	"License :: OSI Approved :: Python Software Foundation License":                      "PSF-2.0",
	"License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)":                    "MPL-1.1",
	"License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)":                    "MPL-2.0",
	"License :: OSI Approved :: The Unlicense (Unlicense)":                               "Unlicense",
	"License :: OSI Approved :: Boost Software License 1.0 (BSL-1.0)":                    "BSL-1.0",
	"License :: OSI Approved :: Zope Public License":                                     "ZPL-2.1",
	"License :: OSI Approved :: Universal Permissive License (UPL)":                      "UPL-1.0",
	"License :: OSI Approved :: Academic Free License (AFL)":                             "AFL-3.0",
	"License :: OSI Approved :: Artistic License":                                        "Artistic-2.0",
	"License :: OSI Approved :: Eclipse Public License 1.0 (EPL-1.0)":                    "EPL-1.0",
	"License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)":                    "EPL-2.0",
	"License :: OSI Approved :: GNU General Public License v2 (GPLv2)":                   "GPL-2.0-only",
	"License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)":         "GPL-2.0-or-later",
	"License :: OSI Approved :: GNU General Public License v3 (GPLv3)":                   "GPL-3.0-only",
	"License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)":         "GPL-3.0-or-later",
	"License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)":           "LGPL-2.0-only",
	"License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
	"License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)":           "LGPL-3.0-only",
	"License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
	"License :: OSI Approved :: GNU Affero General Public License v3":                    "AGPL-3.0-only",
	"License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
	"License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)":     "LGPL-2.1-or-later",
	"License :: Public Domain":                                                           "CC0-1.0",
	"License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication":                    "CC0-1.0",
}

// normalizePyLicenseText maps a short free-text info.license value to an SPDX id. It is deliberately
// conservative: it only accepts values that unambiguously name a known license, so a long license
// BODY or an ambiguous string stays unknown rather than mislabeled.
func normalizePyLicenseText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 40 { // a long value is usually the full license text, not an id
		return ""
	}
	switch strings.ToLower(strings.TrimRight(s, ".")) {
	case "mit", "mit license":
		return "MIT"
	case "bsd", "bsd license", "bsd-3-clause", "bsd 3-clause", "new bsd", "new bsd license":
		return "BSD-3-Clause"
	case "bsd-2-clause", "bsd 2-clause", "simplified bsd":
		return "BSD-2-Clause"
	case "apache", "apache 2", "apache 2.0", "apache-2.0", "apache license 2.0", "apache software license":
		return "Apache-2.0"
	case "isc", "isc license":
		return "ISC"
	case "mpl-2.0", "mpl 2.0", "mozilla public license 2.0":
		return "MPL-2.0"
	case "lgpl", "lgplv3", "lgpl-3.0":
		return "LGPL-3.0-or-later"
	case "gpl", "gplv3", "gpl-3.0", "gplv3+":
		return "GPL-3.0-or-later"
	case "gplv2", "gpl-2.0":
		return "GPL-2.0-only"
	case "psf", "psf-2.0", "python software foundation license":
		return "PSF-2.0"
	case "unlicense", "the unlicense":
		return "Unlicense"
	case "wtfpl":
		return "WTFPL"
	case "zlib":
		return "Zlib"
	}
	// If the value already looks like a bare SPDX id (single token, alnum + . - +), accept it as-is.
	if isBareSPDXID(s) {
		return s
	}
	return ""
}

func isBareSPDXID(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\n") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '+') {
			return false
		}
	}
	return true
}

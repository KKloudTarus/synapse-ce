package engagement

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNormalizeDomain(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".example.com"
	cases := []struct {
		name string
		in   string
		want string
		bad  bool
	}{
		{name: "case and root dot", in: "WWW.Example.COM.", want: "www.example.com"},
		{name: "unicode IDNA", in: "BÜCHER.example", want: "xn--bcher-kva.example"},
		{name: "punycode IDNA", in: "XN--BCHER-KVA.example.", want: "xn--bcher-kva.example"},
		{name: "empty", in: "", bad: true},
		{name: "IP literal", in: "192.0.2.1", bad: true},
		{name: "empty label", in: "example..com", bad: true},
		{name: "leading hyphen", in: "-example.com", bad: true},
		{name: "trailing hyphen", in: "example-.com", bad: true},
		{name: "long label", in: longLabel, bad: true},
		{name: "control character", in: "example\x00.com", bad: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeDomain(tc.in)
			if tc.bad {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("NormalizeDomain(%q) error = %v, want validation error", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDomain(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
			}
			again, err := NormalizeDomain(got)
			if err != nil || again != got {
				t.Errorf("canonical domain is not idempotent: (%q, %v)", again, err)
			}
		})
	}
}

func TestNormalizeDomainPattern(t *testing.T) {
	cases := []struct {
		in   string
		want string
		bad  bool
	}{
		{in: "*.Example.COM.", want: "*.example.com"},
		{in: "example.com", want: "example.com"},
		{in: "api.*.example.com", bad: true},
		{in: "*.192.0.2.1", bad: true},
	}
	for _, tc := range cases {
		got, err := NormalizeDomainPattern(tc.in)
		if tc.bad {
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("NormalizeDomainPattern(%q) error = %v", tc.in, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("NormalizeDomainPattern(%q) = (%q, %v), want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestNormalizeHostAndEndpoint(t *testing.T) {
	host, err := NormalizeHost("2001:DB8::1")
	if err != nil || host != "2001:db8::1" {
		t.Fatalf("NormalizeHost IPv6 = (%q, %v)", host, err)
	}
	gotHost, gotPort, endpoint, err := NormalizeEndpoint("[2001:DB8::1]:8443")
	if err != nil || gotHost != "2001:db8::1" || gotPort != 8443 || endpoint != "[2001:db8::1]:8443" {
		t.Errorf("NormalizeEndpoint = (%q, %d, %q, %v)", gotHost, gotPort, endpoint, err)
	}
	for _, raw := range []string{"example.com", "example.com:0", "example.com:65536", "[2001:db8::1]"} {
		if _, _, _, err := NormalizeEndpoint(raw); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("NormalizeEndpoint(%q) error = %v, want validation error", raw, err)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantURL  string
		wantHost string
		wantPort uint16
		bad      bool
	}{
		{name: "HTTPS default port", in: "HTTPS://WWW.Example.COM./a?x=1", wantURL: "https://www.example.com/a?x=1", wantHost: "www.example.com", wantPort: 443},
		{name: "explicit IPv6 port", in: "http://[2001:DB8::1]:8080/a", wantURL: "http://[2001:db8::1]:8080/a", wantHost: "2001:db8::1", wantPort: 8080},
		{name: "userinfo", in: "https://user@example.com/a", bad: true},
		{name: "unsupported scheme", in: "ftp://example.com/a", bad: true},
		{name: "missing host", in: "https:///a", bad: true},
		{name: "bad port", in: "https://example.com:65536/a", bad: true},
		{name: "opaque", in: "https:example.com", bad: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeURL(tc.in)
			if tc.bad {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("NormalizeURL(%q) error = %v, want validation error", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeURL(%q): %v", tc.in, err)
			}
			if got.URL != tc.wantURL || got.Host != tc.wantHost || got.Port != tc.wantPort {
				t.Errorf("NormalizeURL(%q) = %+v", tc.in, got)
			}
			again, err := NormalizeURL(got.URL)
			if err != nil || again != got {
				t.Errorf("canonical URL is not idempotent: (%+v, %v)", again, err)
			}
		})
	}
}

func TestNormalizeTarget(t *testing.T) {
	domain, err := NormalizeTarget(Target{Kind: TargetDomain, Value: "*.Example.com."}, true)
	if err != nil || domain.Value != "*.example.com" {
		t.Fatalf("NormalizeTarget wildcard scope = (%+v, %v)", domain, err)
	}
	if _, err := NormalizeTarget(Target{Kind: TargetDomain, Value: "*.example.com"}, false); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("wildcard request error = %v, want validation error", err)
	}
	urlTarget, err := NormalizeTarget(Target{Kind: TargetURL, Value: "HTTPS://app.example.com/a"}, true)
	if err != nil || urlTarget.Value != "https://app.example.com/a" {
		t.Errorf("NormalizeTarget URL = (%+v, %v)", urlTarget, err)
	}
}

func FuzzNormalizeDomain(f *testing.F) {
	for _, seed := range []string{"example.com", "WWW.Example.COM.", "bücher.example", "", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		canonical, err := NormalizeDomain(raw)
		if err != nil {
			return
		}
		again, err := NormalizeDomain(canonical)
		if err != nil || canonical != again {
			t.Fatalf("not idempotent: NormalizeDomain(%q) = (%q, %v)", canonical, again, err)
		}
	})
}

func FuzzNormalizeURL(f *testing.F) {
	for _, seed := range []string{"https://example.com", "http://[2001:db8::1]:8080/a", "https://user@example.com", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		canonical, err := NormalizeURL(raw)
		if err != nil {
			return
		}
		again, err := NormalizeURL(canonical.URL)
		if err != nil || canonical != again {
			t.Fatalf("not idempotent: NormalizeURL(%q) = (%+v, %v)", canonical.URL, again, err)
		}
	})
}

package selfhosted

import (
	"net/url"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	base, _ := url.Parse("https://ci.example/jenkins")
	for raw, want := range map[string]bool{
		"https://ci.example/job/a":      true,
		"https://CI.example:443/job/a":  true,
		"http://ci.example/job/a":       false,
		"https://ci.example:8443/job/a": false,
		"https://evil.example/job/a":    false,
		"https://ci.example.evil/job/a": false,
	} {
		other, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := SameOrigin(other, base); got != want {
			t.Errorf("SameOrigin(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestEffectivePort(t *testing.T) {
	for raw, want := range map[string]string{
		"https://a.example":      "443",
		"http://a.example":       "80",
		"https://a.example:8443": "8443",
		"ftp://a.example":        "",
	} {
		parsed, _ := url.Parse(raw)
		if got := EffectivePort(parsed); got != want {
			t.Errorf("EffectivePort(%s) = %q, want %q", raw, got, want)
		}
	}
}

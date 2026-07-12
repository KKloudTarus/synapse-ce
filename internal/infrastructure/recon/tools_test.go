package recon

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
)

func TestRegistryHasTools(t *testing.T) {
	reg := Registry()
	for _, name := range []string{"subfinder", "httpx", "naabu"} {
		if _, ok := reg[name]; !ok {
			t.Errorf("registry missing %q", name)
		}
	}
	if !reg["naabu"].CapabilitySensitive() {
		t.Error("naabu must be flagged capability-sensitive")
	}
	if reg["subfinder"].CapabilitySensitive() {
		t.Error("subfinder is pure-Go, not capability-sensitive")
	}
}

func TestSubfinderBuildArgsAndParse(t *testing.T) {
	spec, err := Subfinder{}.BuildArgs(engagement.Target{Kind: engagement.TargetDomain, Value: "example.com"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if spec.Name != "subfinder" {
		t.Errorf("binary = %q", spec.Name)
	}
	// argv passes the domain as its own token after -d (never concatenated).
	want := []string{"-silent", "-json", "-d", "example.com"}
	if len(spec.Args) != len(want) {
		t.Fatalf("args = %v", spec.Args)
	}
	for i := range want {
		if spec.Args[i] != want[i] {
			t.Fatalf("args = %v, want %v", spec.Args, want)
		}
	}
	out := []byte(`{"host":"www.example.com","source":"crtsh"}
not-json-banner-line
{"host":"API.example.com"}
`)
	res, err := Subfinder{}.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %v", res)
	}
	if res[0].Kind != recon.ResultSubdomain || res[0].Value != "www.example.com" {
		t.Errorf("result[0] = %+v", res[0])
	}
	if res[1].Value != "api.example.com" {
		t.Errorf("host not lowercased: %q", res[1].Value)
	}
}

func TestHTTPXParse(t *testing.T) {
	out := []byte(`{"url":"https://www.example.com","status_code":200,"title":"Home"}
{"url":"http://api.example.com","status_code":403}
{"no_url":true}
`)
	res, err := HTTPX{}.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("want 2, got %v", res)
	}
	if res[0].Kind != recon.ResultURL || res[0].Detail != "200 · Home" {
		t.Errorf("result[0] = %+v", res[0])
	}
	if res[1].Detail != "403" {
		t.Errorf("result[1].Detail = %q", res[1].Detail)
	}
}

func TestNaabuParse(t *testing.T) {
	out := []byte(`{"ip":"93.184.216.34","port":443,"host":"example.com"}
{"ip":"93.184.216.34","port":80}
{"ip":"1.2.3.4"}
`)
	res, err := Naabu{}.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("want 2 (port-0 row dropped), got %v", res)
	}
	if res[0].Value != "example.com:443" {
		t.Errorf("result[0].Value = %q", res[0].Value)
	}
	if res[1].Value != "93.184.216.34:80" {
		t.Errorf("result[1] should fall back to ip: %q", res[1].Value)
	}
}

func TestBuildArgsRejectsFlagInjection(t *testing.T) {
	if _, err := (Subfinder{}).BuildArgs(engagement.Target{Kind: engagement.TargetDomain, Value: "-oG/tmp/x"}); err == nil {
		t.Error("a target starting with '-' must be rejected (flag injection)")
	}
	if _, err := (HTTPX{}).BuildArgs(engagement.Target{Kind: engagement.TargetURL, Value: "https://good.example.com/path"}); err != nil {
		t.Errorf("a URL target should reduce to host and pass: %v", err)
	}
}

func TestBuildArgsURLPreservesAuthorizedURL(t *testing.T) {
	spec, err := HTTPX{}.BuildArgs(engagement.Target{Kind: engagement.TargetURL, Value: "HTTPS://shop.Example.com:8443/cart?x=1"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got, want := spec.Args[len(spec.Args)-1], "https://shop.example.com:8443/cart?x=1"; got != want {
		t.Errorf("HTTPX target = %q, want %q", got, want)
	}
}

func TestBuildArgsRejectsAmbiguousURLAuthority(t *testing.T) {
	for _, value := range []string{
		"https://user@shop.example.com/cart",
		"https://shop.example.com:65536/cart",
		"ftp://shop.example.com/cart",
	} {
		if _, err := (HTTPX{}).BuildArgs(engagement.Target{Kind: engagement.TargetURL, Value: value}); err == nil {
			t.Errorf("BuildArgs(%q) unexpectedly succeeded", value)
		}
	}
}

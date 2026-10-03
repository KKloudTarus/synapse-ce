package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

type resolvedAddresses []netip.Addr

func (ips resolvedAddresses) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return ips, nil
}

func TestPublicResolutionRejectsEveryMixedAndReboundAnswer(t *testing.T) {
	public := netip.MustParseAddr("8.8.8.8")
	for _, private := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "198.18.0.1", "169.254.169.254", "::ffff:127.0.0.1", "::1", "fc00::1", "64:ff9b::a00:1"} {
		t.Run(private, func(t *testing.T) {
			for _, answers := range []resolvedAddresses{{public, netip.MustParseAddr(private)}, {netip.MustParseAddr(private), public}} {
				if _, err := resolvePublicWith(t.Context(), "issuer.example", answers); err == nil {
					t.Fatal("mixed public/private answer accepted")
				}
			}
			if _, err := resolvePublicWith(t.Context(), "issuer.example", resolvedAddresses{public}); err != nil {
				t.Fatal(err)
			}
			if _, err := resolvePublicWith(t.Context(), "issuer.example", resolvedAddresses{netip.MustParseAddr(private)}); err == nil {
				t.Fatal("subsequent rebound answer accepted")
			}
		})
	}
	if _, err := resolvePublicWith(t.Context(), "issuer.example", resolvedAddresses{}); err == nil {
		t.Fatal("empty answer accepted")
	}
}

func TestSafeClientDoesNotUseAmbientProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	transport := newSafeClient().Transport.(cappedTransport).next.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("ambient proxy enabled")
	}
}

func TestVerifiedAuthTimeExactSensitiveBoundary(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, age := range []time.Duration{15*time.Minute - time.Second, 15 * time.Minute, 15*time.Minute + time.Second, -time.Second} {
		raw, _ := json.Marshal(now.Add(-age).Unix())
		_, err := verifiedAuthTime(raw, now, 15*time.Minute)
		allowed := age >= 0 && age < 15*time.Minute
		if (err == nil) != allowed {
			t.Fatalf("age=%s err=%v", age, err)
		}
	}
}

package sca

import (
	"strings"
	"testing"
	"time"
)

func TestDBFreshnessWarnings(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	tv := map[string]string{
		"kev-catalog": "2026.01.01",                    // ~187 days old → stale
		"epss-date":   "2026-07-05",                    // 2 days old → fresh
		"grype-db":    "schema-6@2026-05-01T00:00:00Z", // ~67 days old → stale
		"go-enry":     "v2.9.6",                        // not a dated DB → ignored
	}
	got := dbFreshnessWarnings(tv, now, 30)
	if len(got) != 2 {
		t.Fatalf("want 2 stale warnings (KEV + grype-db), got %d: %v", len(got), got)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "CISA KEV catalog") || !strings.Contains(joined, "grype-db vulnerability DB") {
		t.Errorf("stale KEV + grype-db must be surfaced, got %v", got)
	}
	if strings.Contains(joined, "EPSS") {
		t.Error("a fresh EPSS date must NOT warn")
	}
}

func TestDBFreshnessDisabledAndFresh(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	tv := map[string]string{"kev-catalog": "2026.01.01"}
	// maxAgeDays <= 0 disables the check.
	if got := dbFreshnessWarnings(tv, now, 0); got != nil {
		t.Errorf("maxAgeDays=0 must disable the check, got %v", got)
	}
	// Everything fresh → no warnings.
	fresh := map[string]string{"kev-catalog": "2026.07.06", "epss-date": "2026-07-06"}
	if got := dbFreshnessWarnings(fresh, now, 30); got != nil {
		t.Errorf("fresh DBs must not warn, got %v", got)
	}
}

func TestDBFreshnessUnparseableSurfaced(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	// A PRESENT-but-unreadable date must be surfaced ("freshness cannot be verified"), not silently skipped –
	// so the freshness guarantee itself can't vanish if a feed changes its date format. A truly-absent date
	// (empty) is a different concern and stays a skip.
	tv := map[string]string{"kev-catalog": "not-a-date", "grype-db": "schema-6@garbage", "epss-date": ""}
	got := dbFreshnessWarnings(tv, now, 30)
	if len(got) != 2 {
		t.Fatalf("want 2 unverifiable warnings (KEV + grype-db present-but-unreadable), got %d: %v", len(got), got)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "freshness cannot be verified") || !strings.Contains(joined, "CISA KEV catalog") {
		t.Errorf("a present-but-unreadable date must be surfaced, got %v", got)
	}
	// A truly-absent (empty) date must NOT warn.
	if got := dbFreshnessWarnings(map[string]string{"epss-date": ""}, now, 30); got != nil {
		t.Errorf("an absent date must stay a skip, got %v", got)
	}
}

func TestDBFreshnessDeterministicOrder(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	tv := map[string]string{
		"zzz-db":      "schema-1@2020-01-01T00:00:00Z",
		"aaa-db":      "schema-1@2020-01-01T00:00:00Z",
		"kev-catalog": "2020.01.01",
	}
	first := dbFreshnessWarnings(tv, now, 30)
	for i := 0; i < 5; i++ {
		if got := dbFreshnessWarnings(tv, now, 30); strings.Join(got, "|") != strings.Join(first, "|") {
			t.Fatal("warning order must be deterministic across runs")
		}
	}
}

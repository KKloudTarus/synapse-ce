package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Migration 0002 seeded a tenants row with an empty id for the original single-tenant mode, and every
// install still carries it. Nothing can be done with it: WithTenant maps an empty id to NULL, which
// RLS denies, and 0129 already backfilled the rows that used to carry it. Left in a listing it made
// three periodic reconcilers log an error once a pass forever on a healthy install, and cost the job
// queue an RLS-denied round trip on every poll.
//
// Seven places in this package list tenants and only one of them filtered the row. This asserts every
// listing does, so the next one added does not reintroduce the same report.
var tenantListing = regexp.MustCompile(`SELECT\s+id\s+FROM\s+tenants\b[^` + "`" + `]*`)

func TestEveryTenantListingExcludesTheLegacyEmptyID(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		for _, query := range tenantListing.FindAllString(string(source), -1) {
			flat := strings.Join(strings.Fields(query), " ")
			// A single-tenant lookup names the id it wants, so it can never return the empty row.
			if strings.Contains(flat, "WHERE id=$") || strings.Contains(flat, "WHERE id = $") {
				continue
			}
			checked++
			if !strings.Contains(flat, "id <> ''") && !strings.Contains(flat, "id<>''") {
				t.Errorf("%s lists tenants without excluding the legacy empty id: %s", name, flat)
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no tenant listing to check; the query shape must have changed")
	}
	t.Logf("checked %d tenant listings", checked)
}

package main

import (
	"strings"
	"testing"
)

func TestRenderReceiptMarkdownDisclosesDatabaseProvenance(t *testing.T) {
	rendered := renderReceiptMarkdown(candidateReceipt{})
	for _, required := range []string{
		"scanner-independent truth derived from frozen vendor evidence",
		"owned runtime database consumes the corresponding pinned vendor OVAL",
		"comparator engines consume their own pinned database snapshots",
		"Database provenance or snapshot timing can affect differences",
		"not an abstract market-wide accuracy ranking",
		"Exact database builds and digests are retained in the report",
	} {
		if !strings.Contains(rendered, required) {
			t.Fatalf("receipt summary does not disclose %q:\n%s", required, rendered)
		}
	}
}

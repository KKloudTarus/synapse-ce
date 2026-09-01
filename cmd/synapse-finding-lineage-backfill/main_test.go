package main

import (
	"bytes"
	"testing"
)

func TestParseLineageBackfillOptions(t *testing.T) {
	options, err := parseLineageBackfillOptions([]string{"--tenants", "tenant-a,tenant-b", "--producers", "sca,iac,offensive", "--dry-run", "--batch-size", "2000"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.tenants) != 2 || len(options.producers) != 4 || !options.dryRun || options.batchSize != 2000 {
		t.Fatalf("unexpected options: %+v", options)
	}
}

func TestParseLineageBackfillOptionsRejectsUnsafeLimits(t *testing.T) {
	for _, args := range [][]string{
		{"--tenants", ""},
		{"--tenants", "a,b,c,d,e"},
		{"--tenants", "a", "--batch-size", "2001"},
		{"--tenants", "a,b", "--resume-after", "finding"},
		{"--tenants", "a", "--producers", "unknown"},
	} {
		if _, err := parseLineageBackfillOptions(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("expected rejection for %v", args)
		}
	}
}

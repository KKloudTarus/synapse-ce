package main

import (
	"io"
	"testing"
	"time"
)

func TestParseSnapshotBackfillOptions(t *testing.T) {
	options, err := parseSnapshotBackfillOptions([]string{"--tenants", "tenant-a,tenant-b,tenant-a", "--dry-run", "--batch-size", "2000", "--timeout", "1h"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.tenants) != 2 || !options.dryRun || options.batchSize != 2000 || options.timeout != time.Hour {
		t.Fatalf("options=%+v", options)
	}
	for _, args := range [][]string{
		{},
		{"--tenants", "a,b,c,d,e"},
		{"--tenants", "a", "--batch-size", "2001"},
		{"--tenants", "a,b", "--resume-after", "assessment-1"},
	} {
		if _, err := parseSnapshotBackfillOptions(args, io.Discard); err == nil {
			t.Fatalf("expected invalid options for %v", args)
		}
	}
}

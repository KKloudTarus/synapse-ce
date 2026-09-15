package scabench

import "testing"

func TestRPMEVRCanonicalizesAbsentEpochToZero(t *testing.T) {
	value, err := (RPMEVR{Version: "1.2.3", Release: "4.fc40"}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if value != "0:1.2.3-4.fc40" {
		t.Fatalf("canonical RPM EVR = %q", value)
	}
	epoch := 2
	value, err = (RPMEVR{Epoch: &epoch, Version: "1.2.3", Release: "4.fc40"}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if value != "2:1.2.3-4.fc40" {
		t.Fatalf("canonical RPM EVR with epoch = %q", value)
	}
}

func TestCanonicalRPMEVRNormalizesComparisonOperands(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		valid bool
	}{
		{name: "omitted epoch", input: "1.66.0-12.3.1", want: "0:1.66.0-12.3.1", valid: true},
		{name: "explicit zero epoch", input: "0:1.66.0-150200.12.7.1", want: "0:1.66.0-150200.12.7.1", valid: true},
		{name: "version-only boundary", input: "2", want: "0:2", valid: true},
		{name: "canonicalizes epoch digits", input: "00:1-1", want: "0:1-1", valid: true},
		{name: "multiple releases", input: "1-2-3"},
		{name: "embedded whitespace", input: "1.0 1-1"},
		{name: "missing version", input: "0:"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := canonicalRPMEVR(test.input)
			if (err == nil) != test.valid {
				t.Fatalf("canonicalRPMEVR(%q) error = %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("canonicalRPMEVR(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

package main

import (
	"strings"
	"testing"
)

func TestWindowsBuildSupported(t *testing.T) {
	tests := []struct {
		name    string
		build   uint32
		wantErr bool
	}{
		// 9600 is the number msiexec reports for EVERY release after Windows 8.1, because it reads the
		// version through the compatibility shim. It is in this table as a regression guard: if a future
		// change ever routes this check through GetVersionEx, supported hosts start returning 9600 and
		// this case stops being a refusal of Windows 8.1 and becomes a refusal of everything.
		{name: "windows 8.1, and the number a shimmed API reports", build: 9600, wantErr: true},
		{name: "windows 7", build: 7601, wantErr: true},
		{name: "one build below the floor", build: MinWindowsBuild - 1, wantErr: true},
		{name: "a build of zero is not treated as unknown-therefore-fine", build: 0, wantErr: true},
		{name: "exactly the floor: server 2019 / 1809", build: MinWindowsBuild, wantErr: false},
		{name: "windows 11 / server 2022", build: 20348, wantErr: false},
		{name: "server 2025", build: 26100, wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := windowsBuildSupported(tc.build)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("build %d: want a refusal, got nil", tc.build)
				}
				// The message has to name the build it saw and the build it wants, or an operator
				// cannot tell an unsupported host from a broken agent.
				if !strings.Contains(err.Error(), "17763") {
					t.Errorf("refusal does not state the required build: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("build %d: want supported, got %v", tc.build, err)
			}
		})
	}
}

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestExecuteCLIRoutesMaterializedArchiveSubcommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
		text string
	}{
		{
			name: "direct raw archive remains compatible",
			args: nil,
			want: 1,
			text: "synapse-sca-archive --corpus-root",
		},
		{
			name: "collect requires its explicit inputs",
			args: []string{"collect"},
			want: 1,
			text: "trusted-input-root",
		},
		{
			name: "restore requires its explicit inputs",
			args: []string{"restore"},
			want: 1,
			text: "destination-root",
		},
		{
			name: "collect help",
			args: []string{"collect", "--help"},
			want: 0,
			text: "absolute prepared trusted input root",
		},
		{
			name: "restore help",
			args: []string{"restore", "--help"},
			want: 0,
			text: "absolute existing empty trusted input destination root",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if got := executeCLI(context.Background(), test.args, &stdout, &stderr); got != test.want {
				t.Fatalf("executeCLI(%q) = %d, want %d; stderr: %s", test.args, got, test.want, stderr.String())
			}
			if !strings.Contains(stderr.String(), test.text) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.text)
			}
		})
	}
}

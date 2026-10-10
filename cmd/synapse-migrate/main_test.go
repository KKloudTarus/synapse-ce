package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestParseCaptureModeFlags(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantMode  string
		wantAllow bool
		wantErr   bool
	}{
		{name: "no mode", args: nil},
		{name: "identity", args: []string{"--notification-capture-mode", "identity"}, wantMode: "identity"},
		{name: "controlled legacy drain", args: []string{"--notification-capture-mode=legacy", "--allow-pending"}, wantMode: "legacy", wantAllow: true},
		{name: "invalid mode", args: []string{"--notification-capture-mode", "other"}, wantErr: true},
		{name: "unpaired allow pending", args: []string{"--allow-pending"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, allow, err := parseCaptureModeFlags(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parse err=%v, wantErr=%t", err, tt.wantErr)
			}
			if err == nil && (mode != tt.wantMode || allow != tt.wantAllow) {
				t.Fatalf("parse mode=%q allow=%t, want mode=%q allow=%t", mode, allow, tt.wantMode, tt.wantAllow)
			}
		})
	}
}

func TestCaptureModeHelpPreservesStandardUsageAndSuccessSignal(t *testing.T) {
	_, _, err := parseCaptureModeFlags([]string{"--help"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help parse error=%v, want flag.ErrHelp", err)
	}
	var usage bytes.Buffer
	writeCaptureModeUsage(&usage)
	for _, want := range []string{"Usage of synapse-migrate:", "-notification-capture-mode", "-allow-pending"} {
		if !strings.Contains(usage.String(), want) {
			t.Fatalf("usage=%q, missing %q", usage.String(), want)
		}
	}
}

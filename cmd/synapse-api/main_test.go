package main

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

func TestShouldStartVulnerabilityWorker(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{name: "in-memory topology", cfg: config.Config{}, want: true},
		{name: "postgres defaults to external worker", cfg: config.Config{DBDSN: "postgres://db/synapse"}, want: false},
		{name: "postgres explicit inline worker", cfg: config.Config{DBDSN: "postgres://db/synapse", VulnerabilityInlineWorkerEnabled: true}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldStartVulnerabilityWorker(tt.cfg); got != tt.want {
				t.Fatalf("shouldStartVulnerabilityWorker() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetricsAddrIsLoopback(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{name: "ipv4 loopback", addr: "127.0.0.1:9090", want: true},
		{name: "ipv6 loopback", addr: "[::1]:9090", want: true},
		{name: "localhost hostname", addr: "localhost:9090", want: true},
		{name: "empty host binds all interfaces", addr: ":9090", want: false},
		{name: "explicit all interfaces", addr: "0.0.0.0:9090", want: false},
		{name: "routable ip", addr: "10.0.0.5:9090", want: false},
		{name: "malformed address", addr: "not-a-valid-addr", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := metricsAddrIsLoopback(tt.addr); got != tt.want {
				t.Fatalf("metricsAddrIsLoopback(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

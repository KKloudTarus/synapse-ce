package main

import (
	"testing"
)

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

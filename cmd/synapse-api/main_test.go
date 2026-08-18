package main

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

func TestMigrationDSNForStartup(t *testing.T) {
	devDSN := "postgres://synapse_app:runtime-secret@localhost/synapse?sslmode=disable"
	ownerDSN := "postgres://synapse_owner:owner-secret@localhost/synapse?sslmode=disable"

	tests := []struct {
		name string
		cfg  config.Config
		want string
		fail bool
	}{
		{
			name: "development falls back to runtime DSN",
			cfg:  config.Config{Environment: "development", DBDSN: devDSN},
			want: devDSN,
		},
		{
			name: "production requires migration DSN",
			cfg:  config.Config{Environment: "production", DBDSN: devDSN},
			fail: true,
		},
		{
			name: "production accepts distinct migration role",
			cfg:  config.Config{Environment: "production", DBDSN: devDSN, DBMigrationDSN: ownerDSN},
			want: ownerDSN,
		},
		{
			name: "production rejects same migration role",
			cfg:  config.Config{Environment: "production", DBDSN: devDSN, DBMigrationDSN: "postgres://synapse_app:owner-secret@localhost/synapse?application_name=migrate&sslmode=require"},
			fail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := migrationDSNForStartup(tt.cfg)
			if (err != nil) != tt.fail {
				t.Fatalf("migrationDSNForStartup() error = %v, fail %t", err, tt.fail)
			}
			if got != tt.want {
				t.Fatalf("migrationDSNForStartup() = %q, want %q", got, tt.want)
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

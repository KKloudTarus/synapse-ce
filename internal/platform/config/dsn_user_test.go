package config

import "testing"

func TestPostgresDSNUserAcceptsBothDSNForms(t *testing.T) {
	for _, tc := range []struct {
		name, dsn, want string
		wantErr         bool
	}{
		{name: "url", dsn: "postgres://synapse_app:pw@db:5432/synapse?sslmode=require", want: "synapse_app"},
		{name: "url no user", dsn: "postgres://db:5432/synapse", wantErr: true},
		{name: "keyword", dsn: "host=db port=5432 user=synapse_app password=pw dbname=synapse sslmode=require", want: "synapse_app"},
		{name: "keyword quoted", dsn: "host=/var/run user='odd name' dbname=synapse", want: "odd name"},
		{name: "keyword escaped quote", dsn: `host=db user='o\'brien' dbname=synapse`, want: "o'brien"},
		{name: "keyword user last", dsn: "host=db dbname=synapse user=synapse_halt", want: "synapse_halt"},
		{name: "keyword no user", dsn: "host=db dbname=synapse", wantErr: true},
		{name: "empty", dsn: "   ", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := postgresDSNUser(tc.dsn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got user %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("user = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResponseRoleSeparationAcceptsKeywordDSNs(t *testing.T) {
	err := validateResponseDatabaseRoleSeparation(
		"host=db user=synapse_migration dbname=synapse",
		"host=db user=synapse_app dbname=synapse",
		"host=db user=synapse_halt dbname=synapse",
	)
	if err != nil {
		t.Fatalf("distinct keyword/value roles should pass: %v", err)
	}
	if err := validateResponseDatabaseRoleSeparation(
		"host=db user=synapse_app dbname=synapse",
		"host=db user=synapse_app dbname=synapse",
		"host=db user=synapse_halt dbname=synapse",
	); err == nil {
		t.Fatal("a shared role must still be refused")
	}
}

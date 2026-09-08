package scacompose

import (
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

func TestValidateProductionNetworkedTools(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Config
		wantErr bool
		want    []string
	}{
		{
			name: "production offline tools",
			cfg:  config.Config{Environment: "production"},
		},
		{
			name: "development networked tools",
			cfg: config.Config{
				Environment:         "development",
				MavenResolveEnabled: true,
			},
		},
		{
			name: "production networked tools",
			cfg: config.Config{
				Environment:            "production",
				NPMResolveEnabled:      true,
				MavenResolveEnabled:    true,
				ManifestResolveEnabled: true,
			},
			wantErr: true,
			want: []string{
				"authoritative signed scan grants",
				"SYNAPSE_MANIFEST_RESOLVE_ENABLED, SYNAPSE_MAVEN_RESOLVE_ENABLED, SYNAPSE_NPM_RESOLVE_ENABLED",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProductionNetworkedTools(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateProductionNetworkedTools() error = %v, wantErr %v", err, tt.wantErr)
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestResolveDetectionSourceNames(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Config
		want    []string
		wantErr bool
	}{
		{
			name: "legacy default: online with owned advisory on",
			cfg:  config.Config{DetectionSources: "", Offline: false, OwnedAdvisoryEnabled: true},
			want: []string{"osv", "grype", "advisory-store"},
		},
		{
			name: "legacy default: offline drops live osv",
			cfg:  config.Config{DetectionSources: "", Offline: true, OwnedAdvisoryEnabled: true},
			want: []string{"grype", "advisory-store"},
		},
		{
			name: "legacy default: owned advisory off",
			cfg:  config.Config{DetectionSources: "", Offline: false, OwnedAdvisoryEnabled: false},
			want: []string{"osv", "grype"},
		},
		{
			name: "explicit list is authoritative and can drop grype (Anchore-free)",
			cfg:  config.Config{DetectionSources: "osv,advisory-store", OwnedAdvisoryEnabled: false},
			want: []string{"osv", "advisory-store"},
		},
		{
			name: "explicit list is lowercased and trimmed",
			cfg:  config.Config{DetectionSources: " OSV , Grype "},
			want: []string{"osv", "grype"},
		},
		{
			name:    "explicit but empty after trimming is an error",
			cfg:     config.Config{DetectionSources: " , , "},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveDetectionSourceNames(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

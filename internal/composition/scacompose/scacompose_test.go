package scacompose

import (
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

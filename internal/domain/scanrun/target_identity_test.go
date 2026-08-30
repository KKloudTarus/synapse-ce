package scanrun_test

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestCanonicalizeRepositoryTarget(t *testing.T) {
	tests := []struct {
		name          string
		rawURL        string
		rawRevision   string
		wantCanonical string
		wantRevision  string
		wantErr       bool
	}{
		{
			name:          "standard https github url with .git and 40-hex sha",
			rawURL:        "https://github.com/org/repo.git",
			rawRevision:   "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04",
			wantCanonical: "https://github.com/org/repo",
			wantRevision:  "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04",
			wantErr:       false,
		},
		{
			name:          "ssh scp-style url with 64-hex sha256 commit",
			rawURL:        "git@github.com:KKloudTarus/synapse-ce.git",
			rawRevision:   "8d38da973971e4eb4aa8ec5bb980d249d9c735238d38da973971e4eb4aa8ec5b",
			wantCanonical: "ssh://github.com/KKloudTarus/synapse-ce",
			wantRevision:  "8d38da973971e4eb4aa8ec5bb980d249d9c735238d38da973971e4eb4aa8ec5b",
			wantErr:       false,
		},
		{
			name:          "trailing slash and default port 443 stripped",
			rawURL:        "https://GitLab.Example.COM:443/Group/Project/",
			rawRevision:   "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04",
			wantCanonical: "https://gitlab.example.com/Group/Project",
			wantRevision:  "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04",
			wantErr:       false,
		},
		{
			name:        "mutable branch rejected",
			rawURL:      "https://github.com/org/repo",
			rawRevision: "main",
			wantErr:     true,
		},
		{
			name:        "short sha rejected",
			rawURL:      "https://github.com/org/repo",
			rawRevision: "e54b4a0",
			wantErr:     true,
		},
		{
			name:        "empty url rejected",
			rawURL:      "",
			rawRevision: "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scanrun.CanonicalizeRepositoryTarget(tt.rawURL, tt.rawRevision)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CanonicalizeRepositoryTarget() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if got.TargetKind != scanrun.TargetRepository {
					t.Errorf("TargetKind = %v, want %v", got.TargetKind, scanrun.TargetRepository)
				}
				if got.TargetIdentityCanonical != tt.wantCanonical {
					t.Errorf("TargetIdentityCanonical = %q, want %q", got.TargetIdentityCanonical, tt.wantCanonical)
				}
				if got.EvaluatedRevision != tt.wantRevision {
					t.Errorf("EvaluatedRevision = %q, want %q", got.EvaluatedRevision, tt.wantRevision)
				}
				if err := got.Validate(); err != nil {
					t.Errorf("Validate() failed: %v", err)
				}
			}
		})
	}
}

func TestCanonicalizeOCITarget(t *testing.T) {
	validDigest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	tests := []struct {
		name          string
		rawRef        string
		wantCanonical string
		wantRevision  string
		wantErr       bool
	}{
		{
			name:          "standard image with digest",
			rawRef:        "ghcr.io/kkloudtarus/synapse-ce@" + validDigest,
			wantCanonical: "ghcr.io/kkloudtarus/synapse-ce@" + validDigest,
			wantRevision:  validDigest,
			wantErr:       false,
		},
		{
			name:          "image with tag and digest strips mutable tag",
			rawRef:        "docker.io/library/alpine:v3.18@" + validDigest,
			wantCanonical: "docker.io/library/alpine@" + validDigest,
			wantRevision:  validDigest,
			wantErr:       false,
		},
		{
			name:    "mutable tag only fails closed",
			rawRef:  "docker.io/library/alpine:latest",
			wantErr: true,
		},
		{
			name:    "invalid digest hex length",
			rawRef:  "docker.io/library/alpine@sha256:1234abcd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scanrun.CanonicalizeOCITarget(tt.rawRef)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CanonicalizeOCITarget() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if got.TargetKind != scanrun.TargetOCI {
					t.Errorf("TargetKind = %v, want %v", got.TargetKind, scanrun.TargetOCI)
				}
				if got.TargetIdentityCanonical != tt.wantCanonical {
					t.Errorf("TargetIdentityCanonical = %q, want %q", got.TargetIdentityCanonical, tt.wantCanonical)
				}
				if got.EvaluatedRevision != tt.wantRevision {
					t.Errorf("EvaluatedRevision = %q, want %q", got.EvaluatedRevision, tt.wantRevision)
				}
				if err := got.Validate(); err != nil {
					t.Errorf("Validate() failed: %v", err)
				}
			}
		})
	}
}

func TestCanonicalizeHostTarget(t *testing.T) {
	tests := []struct {
		name          string
		rawHost       string
		wantCanonical string
		wantErr       bool
	}{
		{
			name:          "domain with trailing dot",
			rawHost:       "API.Example.com.",
			wantCanonical: "api.example.com",
			wantErr:       false,
		},
		{
			name:          "domain with explicit port",
			rawHost:       "api.example.com:8443",
			wantCanonical: "api.example.com:8443",
			wantErr:       false,
		},
		{
			name:          "ipv4 address",
			rawHost:       "192.168.1.1",
			wantCanonical: "192.168.1.1",
			wantErr:       false,
		},
		{
			name:          "ipv6 bracketed with port",
			rawHost:       "[2001:db8::1]:8080",
			wantCanonical: "[2001:db8::1]:8080",
			wantErr:       false,
		},
		{
			name:    "empty host",
			rawHost: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scanrun.CanonicalizeHostTarget(tt.rawHost)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CanonicalizeHostTarget() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if got.TargetKind != scanrun.TargetHost {
					t.Errorf("TargetKind = %v, want %v", got.TargetKind, scanrun.TargetHost)
				}
				if got.TargetIdentityCanonical != tt.wantCanonical {
					t.Errorf("TargetIdentityCanonical = %q, want %q", got.TargetIdentityCanonical, tt.wantCanonical)
				}
				if err := got.Validate(); err != nil {
					t.Errorf("Validate() failed: %v", err)
				}
			}
		})
	}
}

func TestCanonicalizeURLTarget(t *testing.T) {
	tests := []struct {
		name          string
		rawURL        string
		wantCanonical string
		wantErr       bool
	}{
		{
			name:          "https url with fragment and default port 443",
			rawURL:        "HTTPS://API.Example.com:443/v1/users?query=test#section",
			wantCanonical: "https://api.example.com/v1/users?query=test",
			wantErr:       false,
		},
		{
			name:          "http url with default port 80 and dot segments",
			rawURL:        "http://example.com:80/a/b/../c",
			wantCanonical: "http://example.com/a/c",
			wantErr:       false,
		},
		{
			name:    "url with credentials fails closed",
			rawURL:  "https://user:password@example.com/api",
			wantErr: true,
		},
		{
			name:    "non http scheme",
			rawURL:  "ftp://example.com/file",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scanrun.CanonicalizeURLTarget(tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CanonicalizeURLTarget() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if got.TargetKind != scanrun.TargetURL {
					t.Errorf("TargetKind = %v, want %v", got.TargetKind, scanrun.TargetURL)
				}
				if got.TargetIdentityCanonical != tt.wantCanonical {
					t.Errorf("TargetIdentityCanonical = %q, want %q", got.TargetIdentityCanonical, tt.wantCanonical)
				}
				if err := got.Validate(); err != nil {
					t.Errorf("Validate() failed: %v", err)
				}
			}
		})
	}
}

func TestCanonicalizeCloudResourceTarget(t *testing.T) {
	got, err := scanrun.CanonicalizeCloudResourceTarget("AWS", "123456789012", "arn:aws:s3:::my-bucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.TargetKind != scanrun.TargetCloudResource {
		t.Errorf("TargetKind = %v, want %v", got.TargetKind, scanrun.TargetCloudResource)
	}
	want := "aws/123456789012/arn:aws:s3:::my-bucket"
	if got.TargetIdentityCanonical != want {
		t.Errorf("TargetIdentityCanonical = %q, want %q", got.TargetIdentityCanonical, want)
	}

	// Missing field fails
	if _, err := scanrun.CanonicalizeCloudResourceTarget("", "123", "res"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation for empty provider, got %v", err)
	}
}

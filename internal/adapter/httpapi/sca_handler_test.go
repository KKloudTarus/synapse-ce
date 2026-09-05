package httpapi

import (
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestValidateScanTarget(t *testing.T) {
	absRepo, err := filepath.Abs(filepath.Join("tmp", "repo"))
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	absSrv, err := filepath.Abs(filepath.Join("srv", "repo"))
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	cases := []struct {
		name, kind, target string
		wantOK             bool
	}{
		{"git https ok", "git", "https://github.com/org/repo", true},
		{"git http ok", "git", "http://h/x", true},
		{"git ftp rejected", "git", "ftp://evil/x", false},
		{"git no host", "git", "https://", false},
		{"git leading dash", "git", "--upload-pack=x", false},
		{"local absolute ok", "local", absRepo, true},
		{"local default-kind ok", "", absSrv, true},
		{"local relative rejected", "local", "repo", false},
		{"archive by reference rejected", "archive", "/tmp/x.tar", false},
		{"image ref ok", "image", "docker.io/library/alpine:3.19", true},
		{"image short ref ok", "image", "alpine:3", true},
		{"image digest ok", "image", "nginx@sha256:abc123", true},
		{"image with space rejected", "image", "alpine 3", false},
		{"image leading dash rejected", "image", "-alpine", false},
		{"upload managed target", ports.TargetUpload, "", true},
		{"upload forged target rejected", ports.TargetUpload, "uploaded-source/sha256/forged", false},
		{"unknown kind", "weird", "/tmp/x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := validateScanTarget(c.kind, c.target)
			if (msg == "") != c.wantOK {
				t.Errorf("validateScanTarget(%q,%q) msg=%q, wantOK=%v", c.kind, c.target, msg, c.wantOK)
			}
		})
	}
}

func TestValidateScanMode(t *testing.T) {
	cases := []struct {
		mode   string
		wantOK bool
	}{
		{"", true},
		{"full", true},
		{"vulnerabilities", true},
		{"licenses", true},
		{"secrets", false},
	}
	for _, c := range cases {
		if got := validateScanMode(c.mode); (got == "") != c.wantOK {
			t.Errorf("validateScanMode(%q) = %q, wantOK=%v", c.mode, got, c.wantOK)
		}
	}
}

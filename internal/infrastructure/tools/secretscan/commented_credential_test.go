package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// A commented-out setting in a configuration file is the value that was applied until someone commented it
// out. It is still in the working tree and in every commit that carried it, so gitleaks reports it and this
// scanner reported nothing: seven of these were found on one live estate.
func TestCommentedCredentialInAConfigFile(t *testing.T) {
	dir := t.TempDir()
	values := "postgres:\n" +
		"  enabled: true\n" +
		"  # DB_PASSWORD: \"kR7mQ2xJ9vB4nT6wY1sL\"\n" +
		"  host: db.internal\n"
	write(t, filepath.Join(dir, "values.yaml"), values)

	got := scanIDs(t, dir)
	f, ok := got["commented-credential"]
	if !ok {
		t.Fatalf("a commented-out credential in a config file must be reported, got %v", idList(got))
	}
	if f.Line != 3 {
		t.Errorf("the finding must land on the commented line, got %d", f.Line)
	}
	// generic-secret reads the masked file, so one commented credential is one finding, not two.
	if _, dup := got["generic-secret"]; dup {
		t.Error("the masked keyword rule must not also fire on a comment")
	}
}

// Source code is where a commented-out assignment is dead code or a documented example, which is why comments
// stay masked there. Admitting them would report every example as a live credential.
func TestCommentedCredentialIgnoresSourceCode(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "main.go"), "// dbPassword = \"kR7mQ2xJ9vB4nT6wY1sL\"\nfunc main() {}\n")
	write(t, filepath.Join(dir, "settings.py"), "# API_KEY = \"kR7mQ2xJ9vB4nT6wY1sL\"\n")
	for id := range scanIDs(t, dir) {
		if id == "commented-credential" {
			t.Error("a commented assignment in source code must stay masked")
		}
	}
}

// The value guards are the ones the live-code rule uses, so a placeholder, a reference to somewhere else and a
// plain identifier are not credentials in a comment either.
func TestCommentedCredentialKeepsTheValueGuards(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "values.yaml"),
		"app:\n"+
			"  # password: CHANGEME_IN_PRODUCTION\n"+
			"  # api_key: replace-me-with-your-key\n"+
			"  # secret: /var/run/secrets/app/token\n"+
			"  # token: ${VAULT_APP_TOKEN}\n")
	for id := range scanIDs(t, dir) {
		if id == "commented-credential" {
			t.Error("a placeholder or a reference to somewhere else is not a credential")
		}
	}
}

// A comment that merely talks about a credential is prose, not an assignment, and is left alone.
func TestCommentedCredentialIgnoresProse(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "values.yaml"),
		"app:\n"+
			"  # The password is read from DB_PASSWORD in the environment kR7mQ2xJ9vB4nT6wY1sL\n"+
			"  replicas: 2\n")
	for id := range scanIDs(t, dir) {
		if id == "commented-credential" {
			t.Error("prose mentioning a credential is not an assignment")
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func scanIDs(t *testing.T, dir string) map[string]ports.SecretRawFinding {
	t.Helper()
	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := make(map[string]ports.SecretRawFinding, len(report.Findings))
	for _, f := range report.Findings {
		if _, seen := out[f.RuleID]; !seen {
			out[f.RuleID] = f
		}
	}
	return out
}

func idList(m map[string]ports.SecretRawFinding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A key whose value NAMES a credential store is not a credential. In a Helm values file `existingSecret:
// app-db-credentials` points at a Kubernetes Secret, and that name belongs in the repository.
func TestCommentedCredentialIgnoresAStoreName(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "values.yaml"),
		"postgres:\n"+
			"  # existingSecret: \"temporal-db-credentials-v2\"\n"+
			"  # secretName: app-tls-certificate-prod\n"+
			"  # DB_PASSWORD: \"kR7mQ2xJ9vB4nT6wY1sL\"\n")
	got := scanIDs(t, dir)
	f, ok := got["commented-credential"]
	if !ok {
		t.Fatalf("the real credential must still be reported, got %v", idList(got))
	}
	if f.Line != 4 {
		t.Errorf("only the credential line must be reported, got line %d", f.Line)
	}
}

package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestPlaintextListenerSkipsLoopback pins the precision this rule exists for. A competitor reports every
// http.ListenAndServe, which in an estate where every service sits behind a TLS-terminating load balancer
// is one finding per service and no signal. Excluding a loopback bind is what makes the remaining hits
// worth reading: 127.0.0.1 is not reachable from off the host, so that listener needs no TLS.
func TestPlaintextListenerSkipsLoopback(t *testing.T) {
	dir := t.TempDir()
	flagged := map[string]string{
		"public.go":   "func main() { http.ListenAndServe(\":8080\", nil) }\n",
		"fromvar.go":  "func main() { http.ListenAndServe(\":\"+cfg.HTTP.Port, nil) }\n",
		"allifaces.go": "func main() { http.ListenAndServe(\"0.0.0.0:9090\", mux) }\n",
	}
	quiet := map[string]string{
		"loopback.go":  "func main() { http.ListenAndServe(\"127.0.0.1:6060\", nil) }\n",
		"localhost.go": "func main() { http.ListenAndServe(\"localhost:6060\", nil) }\n",
		"ipv6.go":      "func main() { http.ListenAndServe(\"[::1]:6060\", nil) }\n",
		"tls.go":       "func main() { http.ListenAndServeTLS(\":443\", c, k, nil) }\n",
	}
	for name, body := range flagged {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range quiet {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	found, err := New().AnalyzeSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	hit := map[string]bool{}
	for _, f := range found {
		if f.RuleID == "go-plaintext-listener" {
			hit[f.File] = true
		}
	}
	for name := range flagged {
		if !hit[name] {
			t.Errorf("%s: a listener reachable off-host must be reported", name)
		}
	}
	for name := range quiet {
		if hit[name] {
			t.Errorf("%s: must stay silent", name)
		}
	}
}

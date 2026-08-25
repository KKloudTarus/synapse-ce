package privacy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactArgvClosesGluedMySQLPasswordResidual(t *testing.T) {
	secret := "glue" + "dSecret42"
	for _, argv0 := range []string{"mysql", "/usr/bin/mysqldump", `C:\\Program Files\\MariaDB\\bin\\mariadb.exe`} {
		t.Run(argv0, func(t *testing.T) {
			out, redacted, dropped := DefaultPolicy().RedactArgv([]string{argv0, "-p" + secret, "app_db"})
			if dropped != 0 || redacted != 1 {
				t.Fatalf("glued password redaction counts = %d/%d, want redacted=1 dropped=0: %#v", redacted, dropped, out)
			}
			if out[1] != "-p"+RedactionPlaceholder || strings.Contains(strings.Join(out, "\x00"), secret) {
				t.Fatalf("glued MySQL password survived: %#v", out)
			}
		})
	}
}

func TestRedactArgvShortPIsCommandScoped(t *testing.T) {
	p := DefaultPolicy()
	for _, args := range [][]string{
		{"psql", "-p5432", "app_db"},
		{"tool", "-progress", "42"},
	} {
		out, redacted, dropped := p.RedactArgv(args)
		if redacted != 0 || dropped != 0 {
			t.Fatalf("ambiguous non-MySQL -p argument was redacted: in=%#v out=%#v", args, out)
		}
		if strings.Join(out, "\x00") != strings.Join(args, "\x00") {
			t.Fatalf("non-credential argv changed: in=%#v out=%#v", args, out)
		}
	}
}

func TestRedactArgvClosesInternalSpaceCredentialResidual(t *testing.T) {
	left := "alpha" + "Secret"
	right := "beta" + "Secret"
	tokenLeft := "gamma" + "Token"
	tokenRight := "delta" + "Token"
	splitLeft := "epsilon" + "Pass"
	splitRight := "zeta" + "Pass"
	args := []string{
		"tool",
		"DB_PASSWORD=" + left + " " + right,
		"--token=" + tokenLeft + " " + tokenRight,
		"--password",
		splitLeft + " " + splitRight,
		"keep-me",
	}
	out, redacted, dropped := DefaultPolicy().RedactArgv(args)
	if dropped != 0 || redacted != 3 {
		t.Fatalf("spaced credential redaction counts = %d/%d, want redacted=3 dropped=0: %#v", redacted, dropped, out)
	}
	if out[1] != "DB_PASSWORD="+RedactionPlaceholder || out[2] != "--token="+RedactionPlaceholder || out[4] != RedactionPlaceholder {
		t.Fatalf("credential values with spaces were not redacted wholesale: %#v", out)
	}
	joined := strings.Join(out, "\x00")
	for _, forbidden := range []string{left, right, tokenLeft, tokenRight, splitLeft, splitRight} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("credential fragment %q survived: %#v", forbidden, out)
		}
	}
	if out[0] != "tool" || out[3] != "--password" || out[5] != "keep-me" {
		t.Fatalf("non-secret argv context was lost: %#v", out)
	}

	// Replay/idempotence: already-redacted argv must not be counted as a fresh privacy mutation.
	again, redactedAgain, droppedAgain := DefaultPolicy().RedactArgv(out)
	if redactedAgain != 0 || droppedAgain != 0 || strings.Join(again, "\x00") != joined {
		t.Fatalf("redaction replay changed output or report: out=%#v again=%#v redacted=%d dropped=%d", out, again, redactedAgain, droppedAgain)
	}
}

func TestResidualCredentialFormsNeverReachTelemetryOrDetection(t *testing.T) {
	glued := "glued" + "Leak93"
	spaceLeft := "left" + "Leak"
	spaceRight := "right" + "Leak"
	// Deliberately omit the executable from Args. The canonical process record carries authoritative Path
	// and Comm separately, and A6 must still interpret MySQL's ambiguous -p suffix as password material.
	args := []string{"-p" + glued, "DB_PASSWORD=" + spaceLeft + " " + spaceRight, "app_db"}

	env, _, err := Scrub(mkEnvelope(args, "/usr/bin/mysqldump"), DefaultPolicy())
	if err != nil {
		t.Fatalf("scrub telemetry: %v", err)
	}
	det, _, err := ScrubDetection(mkDetectionWithArgs(t, args), DefaultPolicy())
	if err != nil {
		t.Fatalf("scrub detection: %v", err)
	}

	for name, value := range map[string]any{"telemetry": env, "detection": det} {
		blob, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		for _, forbidden := range []string{glued, spaceLeft, spaceRight} {
			if strings.Contains(string(blob), forbidden) {
				t.Fatalf("%s source-side scrub leaked %q: %s", name, forbidden, blob)
			}
		}
	}
}

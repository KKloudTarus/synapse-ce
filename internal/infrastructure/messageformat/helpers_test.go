package messageformat

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files")

// sampleMessage is the message the golden files show: every construct of the subset, escaped
// values the way msgtemplate interpolates them, and one link.
func sampleMessage() ports.RenderedMessage {
	title := "Critical finding in " + "payments-api"
	body := "**" + msgtemplate.EscapeMarkdown("SQL injection in /login") + "** on _" + msgtemplate.EscapeMarkdown("prod_eu") + "_\n" +
		"Rule `CWE-89`, severity **critical**\n" +
		"\n" +
		"- Host: " + msgtemplate.EscapeMarkdown("api.example.com") + "\n" +
		"- Owner: " + msgtemplate.EscapeMarkdown("team <platform> & ops") + "\n" +
		"\n" +
		"Reported by Synapse."
	return ports.RenderedMessage{
		Fields: map[string]string{"title": title, "body": body, "subject": "[Synapse] " + title},
		Links:  []ports.RenderedLink{{Label: "Open finding", URL: "https://synapse.example.com/engagements/e1/findings/f1"}},
	}
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create it)", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s changed:\n got  %s\n want %s", name, got, want)
	}
}

// injectionValues are values a scanner or an attacker controls, one per technique the channels
// care about. Each must reach the recipient as literal text.
var injectionValues = []string{
	"<!channel>", "<!here|here>", "<!everyone>", "<@U024BE7LH>", "<#C024BE7LR>", "<https://evil.test|Reset password>",
	"@everyone", "@here", "<users/all>", "[Reset password](https://evil.test)", "*bold* _it_ ~strike~ `code`",
	"<script>alert(1)</script>", `"><img src=x onerror=alert(1)>`, "&amp; &lt;b&gt;", "\\*escaped\\*",
	"_ * [ ] ( ) ~ ` > # + - = | { } . !", "x\u202eevil",
}

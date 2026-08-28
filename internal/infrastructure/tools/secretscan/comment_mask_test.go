package secretscan

import (
	"strings"
	"testing"
)

func TestMaskCommentsBlanksCommentsButKeepsLiveCode(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	cases := []struct {
		name       string
		rel        string
		in         string
		masked     bool // is the secret expected to be blanked?
		keepOffset bool // must byte length + newline count be preserved?
	}{
		{"yaml full-line comment", "config.yml", "# key = " + secret + "\nname: app\n", true, true},
		{"yaml inline comment", "config.yml", "name: app # note " + secret + "\n", true, true},
		{"yaml live value not masked", "config.yml", "token: " + secret + "\n", false, true},
		{"yaml hash-in-value not a comment", "config.yml", "url: value#" + secret + "\n", false, true},
		{"yaml hash inside quotes not a comment", "config.yml", "token: \"" + secret + "#x\"\n", false, true},
		{"shell full-line comment", "deploy.sh", "  # export KEY=" + secret + "\necho hi\n", true, true},
		{"go slash comment", "main.go", "// key := \"" + secret + "\"\nfunc x() {}\n", true, true},
		{"go slash inline comment", "main.go", "x := 1 // " + secret + "\n", true, true},
		{"go url in string not masked", "main.go", "u := \"http://" + secret + "\"\n", false, true},
		{"go live string secret not masked", "main.go", "k := \"" + secret + "\"\n", false, true},
		{"c block comment", "a.c", "/* creds:\n" + secret + "\n*/\nint main(){}\n", true, true},
		{"c block on one line", "a.c", "int x; /* " + secret + " */\n", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := maskComments(tc.rel, []byte(tc.in))
			if tc.keepOffset {
				if len(out) != len(tc.in) {
					t.Fatalf("byte length changed %d -> %d (offsets must be preserved)", len(tc.in), len(out))
				}
				if strings.Count(string(out), "\n") != strings.Count(tc.in, "\n") {
					t.Fatalf("newline count changed (line numbers must be preserved)")
				}
			}
			got := strings.Contains(string(out), secret)
			if tc.masked && got {
				t.Fatalf("secret in a comment must be blanked, but survived:\n%q", out)
			}
			if !tc.masked && !got {
				t.Fatalf("secret in LIVE code/data must NOT be blanked (false negative):\n%q", out)
			}
		})
	}
}

func TestMaskCommentsLeavesUnknownFileTypesUntouched(t *testing.T) {
	in := []byte("plain text # not a known comment language\n")
	if string(maskComments("notes.txt", in)) != string(in) {
		t.Fatal("an unknown file type must be scanned verbatim")
	}
}

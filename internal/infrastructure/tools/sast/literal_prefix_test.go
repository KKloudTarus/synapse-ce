package sast

import "testing"

// syntheticValue builds a deterministic credential-SHAPED value without committing one. A rule that
// reports a hardcoded credential is only testable against a value that looks like one, and writing that
// value as a literal plants a credential-shaped string in the repository for every scanner that reads
// this file afterwards. Generating it keeps the bytes the rule sees identical while leaving nothing
// here for a later real mistake to hide behind.
func syntheticValue(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	state := uint32(0xc2b2ae35)
	for i := range out {
		state = state*1664525 + 1013904223
		out[i] = alphabet[int((state>>16)%uint32(len(alphabet)))]
	}
	return string(out)
}

// dotted spreads a value across dot-separated labels, so a credential that merely LOOKS like a hostname
// is still assessed on its value rather than on its punctuation.
func dotted(v string) string {
	if len(v) < 12 {
		return v
	}
	return v[:3] + "." + v[3:9] + "." + v[9:]
}

// The u-prefix rule matched the letter wherever it sat, so a safe argument such as "-u" inside a
// list was reported as a redundant string prefix (#1638). The prefix only counts when it opens a
// literal from outside one.
func TestRedundantUPrefixNeedsALiteralPrefix(t *testing.T) {
	skip := skipUnlessStringPrefix("uU")
	for _, tc := range []struct {
		name string
		line string
		want bool // want=true means the line is skipped, i.e. no finding
	}{
		{"flag inside a list", `subprocess.run(["date", "-u"], check=True)`, true},
		{"flag inside a single-quoted list", `subprocess.run(['date', '-u'], check=True)`, true},
		{"word ending in u inside a literal", `print("menu")`, true},
		{"identifier ending in u", `value_u = compute()`, true},
		{"dict key ending in u", `config["menu"] = 1`, true},
		{"comment", `# u"legacy"`, true},
		{"real prefix", `title = u"Tiêu đề"`, false},
		{"real prefix, single quotes", `title = u'legacy'`, false},
		{"real prefix after a paren", `print(u"legacy")`, false},
		{"real prefix after a comma", `fn(a, u"legacy")`, false},
		{"upper-case prefix", `title = U"legacy"`, false},
		{"prefix after an escaped quote inside a literal", `s = "he said \"hi\"" + u"x"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := skip(tc.line); got != tc.want {
				t.Fatalf("skip=%v want %v for %s", got, tc.want, tc.line)
			}
		})
	}
}

// A secret-like key assigned a hostname is an endpoint mapping, not an embedded credential. A real
// literal assigned to the same key shape must still report, in test and production scope alike.
func TestEndpointHostnameIsNotACredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want bool // want=true means the line is skipped, i.e. no finding
	}{
		{"secretsmanager endpoint", `  secrets_manager_endpoint = "secretsmanager.ap-southeast-1.amazonaws.com"`, true},
		{"endpoint with a scheme", `  secret_url = "https://secretsmanager.ap-southeast-1.amazonaws.com"`, true},
		{"endpoint with a port", `  secret_host = "vault.internal.example.com:8200"`, true},
		{"endpoint with a path", `  api_key_url = "https://vault.example.com/v1/secret/data"`, true},
		{"real credential", `  api_key = "` + syntheticValue(24) + `"`, false},
		{"credential that looks dotted", `  secret = "` + dotted(syntheticValue(24)) + `"`, false},
		{"password literal", `  password = "` + syntheticValue(14) + `"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := skipCommentPlaceholderOrLabelSecret(tc.line); got != tc.want {
				t.Fatalf("skip=%v want %v for %s", got, tc.want, tc.line)
			}
		})
	}
}

// A line can carry more than one assignment. Reading only the first let an unrelated endpoint beside a
// real credential suppress the finding, so the exclusion is applied to every credential-shaped
// assignment and the line is skipped only when none of them is a credential.
func TestEndpointBesideACredentialDoesNotSuppressIt(t *testing.T) {
	cred := syntheticValue(24)
	for _, tc := range []struct {
		name string
		line string
		want bool // want=true means the line is skipped, i.e. no finding
	}{
		{
			name: "endpoint first, credential second",
			line: `const host = "https://api.prod.internal"; const api_key = "` + cred + `";`,
			want: false,
		},
		{
			name: "credential first, endpoint second",
			line: `const api_key = "` + cred + `"; const host = "https://api.prod.internal";`,
			want: false,
		},
		{
			name: "two endpoints only",
			line: `const secret_host = "vault.prod.internal"; const secret_url = "https://vault.prod.internal/v1";`,
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := skipCommentPlaceholderOrLabelSecret(tc.line); got != tc.want {
				t.Fatalf("skip=%v want %v for %s", got, tc.want, tc.line)
			}
		})
	}
}

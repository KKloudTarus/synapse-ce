package misconfig

import "testing"

func TestDockerfileCommentInsideContinuation(t *testing.T) {
	// A full-line comment inside a backslash continuation must not end the RUN early. The apt cleanup
	// that follows the comment is still part of the same RUN, so apt-no-clean must NOT fire.
	df := "FROM debian:bookworm-slim\n" +
		"RUN apt-get update \\\n" +
		"    && apt-get install -y --no-install-recommends curl \\\n" +
		"    # resolve JAVA_HOME wherever java actually points\n" +
		"    && rm -rf /var/lib/apt/lists/*\n"
	got := ruleIDs(scan(t, map[string]string{"Dockerfile": df}))
	if _, ok := got["dockerfile-apt-no-clean"]; ok {
		t.Errorf("apt cleanup after an inline comment must be recognized; got %v", keys(got))
	}
}

func TestDockerfileAptNoCleanStillFlagged(t *testing.T) {
	// The rule must still catch a genuine apt install with no cleanup.
	df := "FROM debian:bookworm-slim\n" +
		"RUN apt-get update \\\n" +
		"    && apt-get install -y curl\n"
	got := ruleIDs(scan(t, map[string]string{"Dockerfile": df}))
	if _, ok := got["dockerfile-apt-no-clean"]; !ok {
		t.Errorf("apt install without cleanup should still be flagged; got %v", keys(got))
	}
}

func TestDockerfileRulePackAdditions(t *testing.T) {
	cases := []struct {
		name     string
		df       string
		wantRule string
	}{
		{"maintainer", "FROM alpine:3.19\nMAINTAINER team@example.com\n", "dockerfile-maintainer-deprecated"},
		{"workdir relative", "FROM alpine:3.19\nWORKDIR app\n", "dockerfile-workdir-relative"},
		{"apt no-recommends", "FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n", "dockerfile-apt-no-norecommends"},
		{"apt upgrade", "FROM debian:bookworm-slim\nRUN apt-get update && apt-get upgrade -y\n", "dockerfile-apt-upgrade"},
		{"expose ssh", "FROM alpine:3.19\nEXPOSE 22\n", "dockerfile-expose-ssh"},
		{"multiple cmd", "FROM alpine:3.19\nCMD [\"one\"]\nCMD [\"two\"]\n", "dockerfile-multiple-cmd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"Dockerfile": tc.df}))
			if _, ok := got[tc.wantRule]; !ok {
				t.Errorf("expected %s, got %v", tc.wantRule, keys(got))
			}
		})
	}
}

func TestDockerfileRulePackNoFalsePositives(t *testing.T) {
	// A tidy Dockerfile must trigger none of the new rules.
	df := "FROM debian:bookworm-slim\n" +
		"LABEL org.opencontainers.image.authors=\"team@example.com\"\n" +
		"WORKDIR /app\n" +
		"RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\n" +
		"EXPOSE 8080\n" +
		"USER app\n" +
		"HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1\n" +
		"CMD [\"app\"]\n"
	got := ruleIDs(scan(t, map[string]string{"Dockerfile": df}))
	for _, r := range []string{
		"dockerfile-maintainer-deprecated", "dockerfile-workdir-relative",
		"dockerfile-apt-no-norecommends", "dockerfile-apt-upgrade",
		"dockerfile-expose-ssh", "dockerfile-multiple-cmd",
	} {
		if _, bad := got[r]; bad {
			t.Errorf("clean Dockerfile must not trigger %q; got %v", r, keys(got))
		}
	}
}

func TestDockerfileFullPackNoFalsePositives(t *testing.T) {
	// A realistic, well-formed Dockerfile must trigger none of the pack's rules.
	df := "FROM debian:bookworm-slim\n" +
		"LABEL org.opencontainers.image.authors=\"team@example.com\"\n" +
		"WORKDIR /app\n" +
		"RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\n" +
		"COPY app.py /app/\n" +
		"RUN chmod 0755 /app/app.py\n" +
		"EXPOSE 8080\n" +
		"USER app\n" +
		"HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1\n" +
		"ENTRYPOINT [\"python\", \"/app/app.py\"]\n"
	got := ruleIDs(scan(t, map[string]string{"Dockerfile": df}))
	for _, r := range []string{
		"dockerfile-multiple-entrypoint", "dockerfile-shell-form-entrypoint", "dockerfile-from-platform-pinned",
		"dockerfile-copy-to-root", "dockerfile-private-key-copy", "dockerfile-world-writable",
		"dockerfile-setuid-chmod", "dockerfile-secret-in-run", "dockerfile-apt-no-yes",
		"dockerfile-apk-no-cache", "dockerfile-yum-no-clean", "dockerfile-pip-no-cache-dir", "dockerfile-cd-in-run",
	} {
		if _, bad := got[r]; bad {
			t.Errorf("clean Dockerfile must not trigger %q; got %v", r, keys(got))
		}
	}
}

func TestDockerfilePackEdgeCaseNoFalsePositives(t *testing.T) {
	cases := []struct {
		name    string
		df      string
		notRule string
	}{
		{"password-stdin is safe", "FROM alpine:3.19\nRUN echo x | docker login -u u --password-stdin\n", "dockerfile-secret-in-run"},
		{"public key is not a secret", "FROM alpine:3.19\nCOPY id_rsa.pub /home/app/.ssh/id_rsa.pub\n", "dockerfile-private-key-copy"},
		{"non-setuid chmod is fine", "FROM alpine:3.19\nRUN chmod 0644 /etc/app.conf\n", "dockerfile-setuid-chmod"},
		{"templated platform is fine", "FROM --platform=$TARGETPLATFORM alpine:3.19\n", "dockerfile-from-platform-pinned"},
		{"env-var secret ref is fine", "FROM alpine:3.19\nRUN ./deploy --token-file=/run/secrets/token\n", "dockerfile-secret-in-run"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"Dockerfile": tc.df}))
			if _, bad := got[tc.notRule]; bad {
				t.Errorf("%s: must not trigger %q; got %v", tc.name, tc.notRule, keys(got))
			}
		})
	}
}

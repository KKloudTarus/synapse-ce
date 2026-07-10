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

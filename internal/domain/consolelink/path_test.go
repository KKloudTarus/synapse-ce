package consolelink

import "testing"

func TestPathJoinsOnlyConsolePaths(t *testing.T) {
	b, err := NewBuilder("https://synapse.example/app")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := b.Path("/engagements/e1/findings#finding-f1"); !ok || got != "https://synapse.example/app/engagements/e1/findings#finding-f1" {
		t.Fatalf("path = %q %v", got, ok)
	}
	for _, bad := range []string{"", "engagements", "//evil.example/x", "/x://y", "/a\b", "/a b", "/a\u202eb", "/a/../admin", "/a/./b", "/a\nb"} {
		if got, ok := b.Path(bad); ok {
			t.Errorf("%q joined to %q", bad, got)
		}
	}
	if _, ok := (Builder{}).Path("/inbox"); ok {
		t.Error("an unconfigured builder joined a path")
	}
}

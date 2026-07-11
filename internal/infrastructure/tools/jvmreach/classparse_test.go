package jvmreach

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseClassRealFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "target", "classes", "com", "demo", "App.class"))
	if err != nil {
		t.Fatal(err)
	}
	name, refs, err := parseClass(data)
	if err != nil {
		t.Fatal(err)
	}
	if name != "com/demo/App" {
		t.Errorf("name = %q, want com/demo/App", name)
	}
	has := func(s string) bool {
		for _, r := range refs {
			if r == s {
				return true
			}
		}
		return false
	}
	if !has("com/deplib/Helper") {
		t.Errorf("App must reference com/deplib/Helper; refs=%v", refs)
	}
	if has("com/demo/App") {
		t.Error("refs must exclude the class's own name")
	}
}

func TestParseClassRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"bad magic", []byte{0x00, 0x01, 0x02, 0x03, 0x04}},
		{"truncated after magic", []byte{0xCA, 0xFE, 0xBA, 0xBE}},
	} {
		if _, _, err := parseClass(tc.data); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

func TestNormalizeClassName(t *testing.T) {
	cases := map[string]string{
		"com/foo/Bar":         "com/foo/Bar",
		"[Ljava/lang/Object;": "java/lang/Object",
		"[[Lcom/foo/Bar;":     "com/foo/Bar",
		"[I":                  "", // primitive array element – not a class
		"":                    "",
	}
	for in, want := range cases {
		if got := normalizeClassName(in); got != want {
			t.Errorf("normalizeClassName(%q) = %q, want %q", in, got, want)
		}
	}
}

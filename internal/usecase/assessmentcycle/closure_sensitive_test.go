package assessmentcycle

import "testing"

func TestSafeClosureTextRejectsGenericCredentialShapes(t *testing.T) {
	unsafe := []string{
		"password=hunter2",
		"Authorization: Basic Zm9vOmJhcg==",
		"use this credential for the release",
		"https://user:secret@example.com/build/1",
		"https://example.com/build/1?access-token=secret",
		"-----BEGIN PRIVATE KEY-----",
	}
	for _, value := range unsafe {
		if safeClosureText(value) {
			t.Errorf("accepted sensitive closure text %q", value)
		}
	}
	if !safeClosureText("Release approved after independent remediation verification.") {
		t.Fatal("rejected ordinary closure rationale")
	}
}

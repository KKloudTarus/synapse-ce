package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledCentOS7BashFixtureHasPinnedDigest(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "infrastructure", "tools", "ospkg", "testdata", "centos7-bash-header.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hashHex(b); got != "0decb4f28b574bcc0caeb04a1c0b440c1f7cd51d041f3a677fda0bef5d7470a3" {
		t.Fatalf("fixture digest = %s", got)
	}
}

func TestOfficialCentOS7BashRPMDerivesPinnedImmutableDigest(t *testing.T) {
	rpm, err := os.ReadFile(filepath.Join("..", "..", ".git", "taurus", "centos7-rpms", "bash-4.2.46-34.el7.x86_64.rpm"))
	if err != nil {
		t.Skip("run the generator's documented live command to cache the audited RPM")
	}
	if got := hashHex(rpm); got != "f3a182414840db46fb19b893c33191dda43951f517234ff9393aa610daf3259e" {
		t.Fatalf("RPM digest=%s", got)
	}
	header, err := immutableMainHeader(rpm)
	if err != nil {
		t.Fatal(err)
	}
	if got := hashHex(header); got != "91b32a50e95a388d3b1aa00dd5b6708c6107871397440ad10f1760c0221beafc" {
		t.Fatalf("immutable header digest=%s", got)
	}
}

func TestLegacyArmoredSignatureDecodes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", ".git", "taurus", "centos7-repomd.asc"))
	if err != nil {
		t.Skip("live signature is not cached")
	}
	repomd, err := os.ReadFile(filepath.Join("..", "..", ".git", "taurus", "centos7-repomd.xml"))
	if err != nil {
		t.Skip("live metadata is not cached")
	}
	key := filepath.Join("..", "..", "internal", "infrastructure", "tools", "ospkg", "testdata", "centos-7-signing-key.asc")
	keys, err := pinnedKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRepomdSignature(keys, repomd, b); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedKeyringRejectsDifferentKey(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "infrastructure", "tools", "ospkg", "testdata", "centos-7-signing-key.asc")
	keys, err := pinnedKeyring(path)
	if err != nil {
		t.Fatalf("pinned key: %v", err)
	}
	if got := keys.KeysById(keys[0].PrimaryKey.KeyId); len(got) == 0 {
		t.Fatal("entity list did not return primary key")
	}
	tmp := filepath.Join(t.TempDir(), "key.asc")
	if err := os.WriteFile(tmp, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pinnedKeyring(tmp); err == nil {
		t.Fatal("malformed key accepted")
	}
}

func TestRepositoryPathsRemainRelative(t *testing.T) {
	for _, p := range []string{"Packages/bash-4.2.rpm", "repodata/primary.xml.gz"} {
		if !isSafeRepoPath(p) {
			t.Fatalf("safe path %q rejected", p)
		}
	}
	for _, p := range []string{"/Packages/bash.rpm", "https://example.test/a", "../escape", "a/../../b", "a?x=1"} {
		if isSafeRepoPath(p) {
			t.Fatalf("unsafe path %q accepted", p)
		}
	}
}

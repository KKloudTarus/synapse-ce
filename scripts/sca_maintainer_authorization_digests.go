//go:build ignore

// SCA maintainer authorization digest helper emits the exact digest projection
// consumed by the trusted benchmark runner.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func main() {
	corpusRoot := flag.String("corpus-root", "", "absolute or relative SCA corpus root")
	flag.Parse()
	if *corpusRoot == "" {
		fail("corpus-root is required")
	}
	catalogBytes := read(filepath.Join(*corpusRoot, "catalog.json"))
	oracleBytes := read(filepath.Join(*corpusRoot, "oracle.json"))
	ratchetBytes := read(filepath.Join(*corpusRoot, "ratchet.json"))
	policyBytes := read(filepath.Join(*corpusRoot, "cycle-policy.json"))
	catalog, err := bench.DecodeCatalog(bytes.NewReader(catalogBytes))
	if err != nil {
		fail("decode catalog: %v", err)
	}
	oracle, err := bench.DecodeOracle(bytes.NewReader(oracleBytes))
	if err != nil {
		fail("decode oracle: %v", err)
	}
	ratchet, err := bench.DecodeRatchet(bytes.NewReader(ratchetBytes))
	if err != nil {
		fail("decode ratchet: %v", err)
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		fail("digest catalog: %v", err)
	}
	oracleDigest, err := bench.DigestOracle(oracle)
	if err != nil {
		fail("digest oracle: %v", err)
	}
	ratchetDigest, err := bench.DigestRatchet(ratchet)
	if err != nil {
		fail("digest ratchet: %v", err)
	}
	output := map[string]string{
		"catalog": catalogDigest,
		"oracle":  oracleDigest,
		"ratchet": ratchetDigest,
		"policy":  sha256Digest(policyBytes),
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		fail("encode digests: %v", err)
	}
	fmt.Println(string(encoded))
}

func read(path string) []byte {
	value, err := os.ReadFile(path)
	if err != nil {
		fail("read %s: %v", path, err)
	}
	return value
}

func sha256Digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

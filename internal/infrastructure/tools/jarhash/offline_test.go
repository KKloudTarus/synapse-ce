package jarhash

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// writeJavaDB builds a fixture SQLite file in the trivy-java-db schema with the given sha1(hex)->coord rows.
func writeJavaDB(t *testing.T, rows map[string][3]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trivy-java.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range []string{
		`CREATE TABLE artifacts(id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT)`,
		`CREATE TABLE indices(artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT, foreign key(artifact_id) references artifacts(id))`,
		`CREATE UNIQUE INDEX artifacts_idx ON artifacts(artifact_id, group_id)`,
		`CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	id := 0
	for sha1hex, gav := range rows {
		id++
		if _, err := db.Exec(`INSERT INTO artifacts(id, group_id, artifact_id) VALUES(?,?,?)`, id, gav[0], gav[1]); err != nil {
			t.Fatal(err)
		}
		blob, err := hex.DecodeString(sha1hex)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO indices(artifact_id, version, sha1, archive_type) VALUES(?,?,?,'jar')`, id, gav[2], blob); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestOfflineResolvesFromDB(t *testing.T) {
	sha1 := "6505a72a097d9270f7a9e7bf42c4238283247755"
	dbPath := writeJavaDB(t, map[string][3]string{
		sha1: {"org.apache.commons", "commons-lang3", "3.8.1"},
	})
	r, err := NewOffline(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	comps := []sbom.Component{{Name: "shaded", PURL: "", SHA1: sha1}}
	if n := r.Resolve(context.Background(), comps); n != 1 {
		t.Fatalf("recovered = %d, want 1", n)
	}
	if comps[0].PURL != "pkg:maven/org.apache.commons/commons-lang3@3.8.1" || comps[0].Name != "org.apache.commons:commons-lang3" {
		t.Fatalf("offline coord not applied: %+v", comps[0])
	}
}

func TestOfflineMissLeavesUnchanged(t *testing.T) {
	dbPath := writeJavaDB(t, map[string][3]string{
		"1111111111111111111111111111111111111111": {"g", "a", "1"},
	})
	r, err := NewOffline(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	comps := []sbom.Component{{Name: "x", SHA1: "2222222222222222222222222222222222222222"}}
	if n := r.Resolve(context.Background(), comps); n != 0 || comps[0].PURL != "" {
		t.Fatalf("miss must leave unchanged: n=%d comp=%+v", n, comps[0])
	}
}

func TestOfflineRejectsWrongSchema(t *testing.T) {
	// a valid SQLite file but not the trivy-java-db schema → NewOffline must error (fail loud at wiring).
	path := filepath.Join(t.TempDir(), "wrong.db")
	db, _ := sql.Open("sqlite", path)
	_, _ = db.Exec(`CREATE TABLE something(x INT)`)
	_ = db.Close()
	if _, err := NewOffline(path); err == nil {
		t.Error("NewOffline must reject a non-trivy-java-db schema")
	}
}

// Chain: the offline DB resolves what it has; the online client is the fallback for the DB's misses –
// and it must NOT be queried for a component the offline DB already resolved.
func TestChainOfflineFirstOnlineFallback(t *testing.T) {
	offSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	onSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dbPath := writeJavaDB(t, map[string][3]string{offSHA: {"off.g", "off-a", "1.0"}})
	off, err := NewOffline(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer off.Close()

	// online stub: only knows onSHA; asserts it is never asked for offSHA (offline already resolved it).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query().Get("q")
		if len(q) >= 43 && q[3:43] == offSHA {
			t.Errorf("online must NOT be queried for a component the offline DB resolved")
		}
		w.Header().Set("Content-Type", "application/json")
		docs := []map[string]string{}
		if len(q) >= 43 && q[3:43] == onSHA {
			docs = []map[string]string{{"g": "on.g", "a": "on-a", "v": "2.0"}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"docs": docs}})
	}))
	defer srv.Close()

	chain := NewChain(off, New(srv.URL, srv.Client()))
	comps := []sbom.Component{
		{Name: "shaded-offline", SHA1: offSHA},
		{Name: "shaded-online", SHA1: onSHA},
	}
	if n := chain.Resolve(context.Background(), comps); n != 2 {
		t.Fatalf("chain recovered = %d, want 2 (1 offline + 1 online)", n)
	}
	if comps[0].Name != "off.g:off-a" {
		t.Errorf("offline component = %q, want off.g:off-a", comps[0].Name)
	}
	if comps[1].Name != "on.g:on-a" {
		t.Errorf("online-fallback component = %q, want on.g:on-a", comps[1].Name)
	}
}

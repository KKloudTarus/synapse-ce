package ownadvisory

import (
	"testing"
)

func TestParseProviderMetadata(t *testing.T) {
	doc := `{
		"public_openpgp_keys":[{"fingerprint":"ABC","url":"https://p.example/key.asc"}],
		"distributions":[{"rolie":{"feeds":[
			{"tlp_label":"WHITE","url":"https://p.example/feed-white.json"},
			{"tlp_label":"GREEN","url":"https://p.example/feed-green.json"}
		]}}]
	}`
	keys, feeds, err := ParseProviderMetadata([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 1 || keys[0].URL != "https://p.example/key.asc" || keys[0].Fingerprint != "ABC" {
		t.Fatalf("keys=%+v", keys)
	}
	if len(feeds) != 2 || feeds[0] != "https://p.example/feed-white.json" {
		t.Fatalf("feeds=%v", feeds)
	}
	// No feed -> error (nothing to discover).
	if _, _, err := ParseProviderMetadata([]byte(`{"public_openpgp_keys":[{"url":"k"}]}`)); err == nil {
		t.Fatal("a provider-metadata with no feed must error")
	}
	if _, _, err := ParseProviderMetadata([]byte(`{bad`)); err == nil {
		t.Fatal("malformed provider-metadata must error")
	}
}

func TestParseROLIEFeed(t *testing.T) {
	doc := `{"feed":{"entry":[
		{"content":{"type":"application/json","src":"https://p.example/a/adv-1.json"}},
		{"link":[{"rel":"alternate","href":"https://x/html"},{"rel":"self","href":"https://p.example/a/adv-2.json"}]}
	]}}`
	urls, err := ParseROLIEFeed([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(urls) != 2 || urls[0] != "https://p.example/a/adv-1.json" || urls[1] != "https://p.example/a/adv-2.json" {
		t.Fatalf("urls=%v", urls)
	}
	if _, err := ParseROLIEFeed([]byte(`{bad`)); err == nil {
		t.Fatal("malformed feed must error")
	}
}

// TestParseROLIEFeedRejectsEntryWithoutURL: an entry with neither content.src nor a self link is fail-closed,
// so a structural surprise aborts discovery instead of silently under-ingesting a provider's advisories.
func TestParseROLIEFeedRejectsEntryWithoutURL(t *testing.T) {
	doc := `{"feed":{"entry":[
		{"content":{"type":"application/json","src":"https://p.example/adv-1.json"}},
		{"link":[{"rel":"alternate","href":"https://x/html"}]}
	]}}`
	if _, err := ParseROLIEFeed([]byte(doc)); err == nil {
		t.Fatal("a ROLIE entry with no advisory document URL must fail closed")
	}
	// An empty feed (no entries) is not an error here; the caller treats zero documents as the error.
	if urls, err := ParseROLIEFeed([]byte(`{"feed":{"entry":[]}}`)); err != nil || len(urls) != 0 {
		t.Fatalf("empty feed: urls=%v err=%v", urls, err)
	}
}

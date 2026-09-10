package ownadvisory

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CSAF 2.0 trusted-provider discovery (spec section 7.1): a provider publishes a provider-metadata.json that
// lists its OpenPGP public keys and its ROLIE feeds; each ROLIE feed lists the advisory documents. These
// parsers turn those documents into the URLs the ingester fetches, so an operator can point one config value
// at the provider-metadata.json instead of listing every advisory and pasting the key by hand (EPIC #860
// D1.8). Only URL fields are read; nothing is trusted from these documents beyond where to fetch next, and
// every fetched advisory is still signature-verified against the discovered key.

// ProviderMetadata is the subset of a CSAF provider-metadata.json the discoverer reads.
type ProviderMetadata struct {
	PublicOpenPGPKeys []struct {
		URL         string `json:"url"`
		Fingerprint string `json:"fingerprint"`
	} `json:"public_openpgp_keys"`
	Distributions []struct {
		Rolie struct {
			Feeds []struct {
				URL string `json:"url"`
			} `json:"feeds"`
		} `json:"rolie"`
	} `json:"distributions"`
}

// DiscoveredKey is one provider signing key as published in the provider-metadata: the URL to fetch the
// armored key from and the fingerprint the fetched key must match. The fingerprint is the trust binding, so a
// key entry with no fingerprint cannot be trusted (the caller drops it).
type DiscoveredKey struct {
	URL         string
	Fingerprint string
}

// ParseProviderMetadata extracts the published signing keys (URL plus fingerprint) and the ROLIE feed URLs
// from a provider-metadata.json. It errors when the document is malformed or lists no ROLIE feed (nothing to
// discover). A key entry without a URL is dropped here; the fingerprint binding is enforced by the caller.
func ParseProviderMetadata(data []byte) (keys []DiscoveredKey, feedURLs []string, err error) {
	var meta ProviderMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, nil, fmt.Errorf("%w: parse provider-metadata.json: %v", shared.ErrValidation, err)
	}
	for _, k := range meta.PublicOpenPGPKeys {
		if u := strings.TrimSpace(k.URL); u != "" {
			keys = append(keys, DiscoveredKey{URL: u, Fingerprint: strings.TrimSpace(k.Fingerprint)})
		}
	}
	for _, d := range meta.Distributions {
		for _, f := range d.Rolie.Feeds {
			if u := strings.TrimSpace(f.URL); u != "" {
				feedURLs = append(feedURLs, u)
			}
		}
	}
	if len(feedURLs) == 0 {
		return nil, nil, fmt.Errorf("%w: provider-metadata.json lists no ROLIE feed", shared.ErrValidation)
	}
	return keys, feedURLs, nil
}

// rolieFeed is the subset of a ROLIE feed document the discoverer reads.
type rolieFeed struct {
	Feed struct {
		Entry []struct {
			Content struct {
				Src string `json:"src"`
			} `json:"content"`
			Link []struct {
				Rel  string `json:"rel"`
				Href string `json:"href"`
			} `json:"link"`
		} `json:"entry"`
	} `json:"feed"`
}

// ParseROLIEFeed extracts the advisory document URLs from a ROLIE feed. CSAF 2.0 (section 7.1.4) mandates the
// JSON serialization of ROLIE (RFC 8322), not the Atom/XML one, so this parser is JSON-only by design. Each
// entry names its document via content.src, falling back to a link with rel="self". A malformed feed is an
// error. An entry that carries NEITHER a content.src NOR a self link is fail-closed (an error): silently
// dropping it would under-ingest a provider's advisories and hide the structural surprise, so an unexpected
// entry shape aborts discovery rather than quietly missing advisories. An empty feed (no entries) yields no
// URLs; the caller treats zero documents across all feeds as an error.
func ParseROLIEFeed(data []byte) ([]string, error) {
	var feed rolieFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("%w: parse ROLIE feed: %v", shared.ErrValidation, err)
	}
	var urls []string
	for i, entry := range feed.Feed.Entry {
		if src := strings.TrimSpace(entry.Content.Src); src != "" {
			urls = append(urls, src)
			continue
		}
		self := ""
		for _, link := range entry.Link {
			if strings.EqualFold(strings.TrimSpace(link.Rel), "self") && strings.TrimSpace(link.Href) != "" {
				self = strings.TrimSpace(link.Href)
				break
			}
		}
		if self == "" {
			return nil, fmt.Errorf("%w: ROLIE feed entry %d has no advisory document URL (no content.src or self link)", shared.ErrValidation, i)
		}
		urls = append(urls, self)
	}
	return urls, nil
}

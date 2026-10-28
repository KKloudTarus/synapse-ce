package documentproviders

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const notionContainer = "0123456789abcdef0123456789abcdef"

type notionFake struct {
	bot      string
	page     string
	botCode  int
	pageCode int
	paths    []string
	authSeen []string
	version  []string
}

func (f *notionFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.paths = append(f.paths, r.URL.Path)
	f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
	f.version = append(f.version, r.Header.Get("Notion-Version"))
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/v1/users/me":
		if f.botCode != 0 {
			w.WriteHeader(f.botCode)
			_, _ = w.Write([]byte(`{"object":"error","code":"unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(f.bot))
	case strings.HasPrefix(r.URL.Path, "/v1/pages/"):
		if f.pageCode != 0 {
			w.WriteHeader(f.pageCode)
			_, _ = w.Write([]byte(`{"object":"error","code":"object_not_found"}`))
			return
		}
		_, _ = w.Write([]byte(f.page))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"object":"error","code":"not_found"}`))
	}
}

func newNotionAdapter(t *testing.T, fake *notionFake) *notionAdapter {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 10 * time.Second
	base := strings.TrimPrefix(server.URL, "http://")
	client.Transport = notionRewrite{host: base, inner: client.Transport}
	return &notionAdapter{client: client, token: "secret_notion_token_value", container: notionContainer}
}

// notionRewrite sends the pinned api.notion.com URL to the test server while the
// adapter keeps building the real origin.
type notionRewrite struct {
	host  string
	inner http.RoundTripper
}

func (t notionRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = t.host
	return t.inner.RoundTrip(clone)
}

func notionPageJSON(overrides map[string]any) string {
	page := map[string]any{
		"object": "page", "id": notionContainer, "in_trash": false, "archived": false,
		"public_url": nil, "parent": map[string]any{"type": "workspace"},
	}
	for key, value := range overrides {
		page[key] = value
	}
	raw, _ := json.Marshal(page)
	return string(raw)
}

func TestNotionConnectionTest(t *testing.T) {
	bot := `{"object":"user","type":"bot","id":"bot-1"}`
	for _, tc := range []struct {
		name           string
		fake           *notionFake
		wantCode       string
		wantRestricted bool
		wantOK         bool
	}{
		{name: "private container", fake: &notionFake{bot: bot, page: notionPageJSON(nil)}, wantOK: true},
		{name: "dashed id", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"id": "01234567-89ab-cdef-0123-456789abcdef"})}, wantOK: true},
		{name: "published to web", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"public_url": "https://example.notion.site/report"})}, wantCode: "page_published_to_web", wantRestricted: true},
		{name: "unreadable sharing state", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"public_url": 42})}, wantCode: "invalid_public_url"},
		{name: "container in trash", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"in_trash": true})}, wantCode: "page_in_trash", wantRestricted: true},
		{name: "legacy archived flag", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"archived": true})}, wantCode: "page_in_trash", wantRestricted: true},
		{name: "another page", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"id": "ffffffffffffffffffffffffffffffff"})}, wantCode: "invalid_remote_identity"},
		{name: "database instead of page", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"object": "database"})}, wantCode: "invalid_remote_identity"},
		{name: "parent withheld", fake: &notionFake{bot: bot, page: `{"object":"page","id":"` + notionContainer + `","in_trash":false,"public_url":null}`}, wantCode: "complete_identity_unverifiable"},
		{name: "person token", fake: &notionFake{bot: `{"object":"user","type":"person","id":"user-1"}`, page: notionPageJSON(nil)}, wantCode: "invalid_identity"},
		{name: "revoked token", fake: &notionFake{botCode: http.StatusUnauthorized, page: notionPageJSON(nil)}, wantCode: "permission_denied"},
		{name: "container not shared with the integration", fake: &notionFake{bot: bot, pageCode: http.StatusNotFound}, wantCode: "container_not_shared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := newNotionAdapter(t, tc.fake)
			err := adapter.TestConnection(context.Background())
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected the connection to pass, got %v", err)
				}
				if len(tc.fake.version) == 0 || tc.fake.version[0] != notionAPIVersion {
					t.Fatalf("every call must pin the API version, saw %v", tc.fake.version)
				}
				return
			}
			var refusal *ports.DocumentProviderError
			if !errors.As(err, &refusal) {
				t.Fatalf("expected a refusal, got %v", err)
			}
			if refusal.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", refusal.Code, tc.wantCode)
			}
			if refusal.RestrictionLost != tc.wantRestricted {
				t.Fatalf("RestrictionLost = %v, want %v", refusal.RestrictionLost, tc.wantRestricted)
			}
		})
	}
}

func TestNotionPublicationRequiresExplicitProfile(t *testing.T) {
	registry := integration.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatalf("register: %v", err)
	}
	descriptor, err := registry.Descriptor(Notion)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if !descriptor.Supports(integration.CapabilityDocuments) {
		t.Fatalf("Notion must declare the opt-in snapshot capability")
	}
	a := &notionAdapter{container: notionContainer, group: "readers"}
	if err := a.CheckDocumentRelease(context.Background(), notionContainer, "readers"); err == nil {
		t.Fatal("omitted publication_profile must refuse release before I/O")
	}
	if _, ok := any(a).(ports.DocumentSnapshotProvider); !ok {
		t.Fatal("the opt-in adapter must satisfy the snapshot port")
	}
}

func TestNotionFactoryValidation(t *testing.T) {
	secrets := integration.CredentialBundle{"integration_token": "secret_notion_token_value"}
	config := func(overrides map[string]string) []byte {
		values := map[string]string{"space": notionContainer, "read_group": "Security reviewers", "data_class": "detail"}
		for key, value := range overrides {
			values[key] = value
		}
		raw, err := json.Marshal(values)
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		return raw
	}
	for _, tc := range []struct {
		name     string
		endpoint string
		config   []byte
		secrets  integration.CredentialBundle
		wantErr  bool
	}{
		{name: "pinned origin", endpoint: notionAPIOrigin, config: config(nil), secrets: secrets},
		{name: "another origin", endpoint: "https://notion.example.com", config: config(nil), secrets: secrets, wantErr: true},
		{name: "plaintext origin", endpoint: "http://api.notion.com", config: config(nil), secrets: secrets, wantErr: true},
		{name: "container is not an identifier", endpoint: notionAPIOrigin, config: config(map[string]string{"space": "my page"}), secrets: secrets, wantErr: true},
		{name: "summary data class", endpoint: notionAPIOrigin, config: config(map[string]string{"data_class": "summary"}), secrets: secrets, wantErr: true},
		{name: "missing reader group", endpoint: notionAPIOrigin, config: config(map[string]string{"read_group": " "}), secrets: secrets, wantErr: true},
		{name: "missing token", endpoint: notionAPIOrigin, config: config(nil), secrets: integration.CredentialBundle{}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter, err := newNotion(integration.Integration{Provider: Notion, Endpoint: tc.endpoint, Config: tc.config}, tc.secrets, selfhosted.Rules{})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected a rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
			built, ok := adapter.(*notionAdapter)
			if !ok {
				t.Fatalf("factory returned %T", adapter)
			}
			built.Close()
			if built.token != "" {
				t.Fatalf("Close must clear the held credential")
			}
		})
	}
}

func TestNotionPageIdentityRejectsUnsafeDestinationShapes(t *testing.T) {
	base := notionPage{}
	if err := json.Unmarshal([]byte(notionPageJSON(map[string]any{
		"parent": map[string]any{"type": "page_id", "page_id": notionContainer},
	})), &base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*notionPage){
		"missing public URL":   func(p *notionPage) { p.PublicURL = nil },
		"malformed public URL": func(p *notionPage) { p.PublicURL = json.RawMessage(`42`) },
		"moved child":          func(p *notionPage) { p.Parent.PageID = "ffffffffffffffffffffffffffffffff" },
		"trashed child":        func(p *notionPage) { v := true; p.InTrash = &v },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			if err := p.validate(notionContainer, notionContainer, true, false); err == nil {
				t.Fatal("unsafe page shape was accepted")
			}
		})
	}
}

func TestNotionSnapshotValidationPreservesPDFAndBoundsBlocks(t *testing.T) {
	a := &notionAdapter{token: "secret-token"}
	valid := ports.DocumentArtifact{Title: "Report", Paragraphs: []string{"One"}, PDF: []byte("%PDF-1.7"), EvidenceHead: ""}
	if err := a.ValidateDocumentSnapshot(valid); err != nil {
		t.Fatalf("empty evidence head is represented explicitly later: %v", err)
	}
	tooLarge := valid
	tooLarge.PDF = make([]byte, notionMaxFileBytes+1)
	if err := a.ValidateDocumentSnapshot(tooLarge); err == nil {
		t.Fatal("oversized PDF must never be truncated or accepted")
	}
	tooMany := valid
	tooMany.Paragraphs = make([]string, notionMaxBlocks)
	for i := range tooMany.Paragraphs {
		tooMany.Paragraphs[i] = "x"
	}
	if err := a.ValidateDocumentSnapshot(tooMany); err == nil {
		t.Fatal("append that exceeds Notion's bounded block request was accepted")
	}
}

func TestNotionAppendReadbackRequiresExactArtifactProjection(t *testing.T) {
	artifact := ports.DocumentArtifact{Title: "Report", Paragraphs: []string{"expected paragraph"}, PDF: []byte("%PDF-1.7"), EvidenceHead: "evidence"}
	hash := strings.Repeat("a", 64)
	blocks := []notionBlock{
		{Type: "paragraph", Paragraph: notionParagraph("expected paragraph")},
		{Type: "paragraph", Paragraph: notionParagraph("Evidence: evidence")},
		{Type: "paragraph", Paragraph: notionParagraph("Artifact SHA-256: " + hash)},
		{Type: "pdf"},
	}
	if !matchesSnapshotAppend(blocks, artifact, hash) {
		t.Fatal("exact append projection was rejected")
	}
	blocks[0].Paragraph = notionParagraph("substituted paragraph")
	if matchesSnapshotAppend(blocks, artifact, hash) {
		t.Fatal("changed paragraph was accepted by readback proof")
	}
	blocks[0].Paragraph = notionParagraph("expected paragraph")
	blocks[3].Type = "image"
	if matchesSnapshotAppend(blocks, artifact, hash) {
		t.Fatal("wrong PDF block kind was accepted by readback proof")
	}
}

func notionParagraph(value string) struct {
	RichText []notionRichText `json:"rich_text"`
} {
	var out struct {
		RichText []notionRichText `json:"rich_text"`
	}
	out.RichText = []notionRichText{{PlainText: value}}
	return out
}

func TestNotionSnapshotHTTPFlowAndWrongTitleAcknowledgement(t *testing.T) {
	const pageID = "11111111-1111-1111-1111-111111111111"
	const uploadID = "22222222-2222-2222-2222-222222222222"
	marker := "synapse-intent-http-fixture"
	contentHash := strings.Repeat("a", 64)
	state := struct {
		title      string
		blocks     []map[string]any
		sent       bool
		wrongTitle bool
	}{title: notionNeutralTitle, blocks: []map[string]any{snapshotParagraph("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", marker)}}
	page := func(id, parent, title string) map[string]any {
		value := map[string]any{"object": "page", "id": id, "in_trash": false, "archived": false, "public_url": nil,
			"properties": map[string]any{"title": map[string]any{"type": "title", "title": []any{map[string]any{"plain_text": title}}}}}
		if parent == "" {
			value["parent"] = map[string]any{"type": "workspace"}
		} else {
			value["parent"] = map[string]any{"type": "page_id", "page_id": parent}
		}
		return value
	}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/pages/"+notionContainer:
			write(page(notionContainer, "", notionNeutralTitle))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/pages/"+pageID:
			write(page(pageID, notionContainer, state.title))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/blocks/"+pageID+"/children":
			write(map[string]any{"results": state.blocks, "has_more": false})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/file_uploads":
			write(map[string]any{"id": uploadID})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/file_uploads/"+uploadID+"/send":
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
				t.Errorf("send content type = %q", r.Header.Get("Content-Type"))
			}
			state.sent = true
			write(map[string]any{"id": uploadID, "status": "uploaded", "content_length": len("%PDF-1.7")})
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/blocks/"+pageID+"/children":
			if !state.sent {
				t.Error("append occurred before upload send")
			}
			state.blocks = append(state.blocks,
				snapshotParagraph("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "paragraph"),
				snapshotParagraph("cccccccc-cccc-cccc-cccc-cccccccccccc", "Evidence: evidence"),
				snapshotParagraph("dddddddd-dddd-dddd-dddd-dddddddddddd", "Artifact SHA-256: "+contentHash),
				map[string]any{"object": "block", "id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee", "type": "pdf", "pdf": map[string]any{"name": "report.pdf", "file": map[string]any{"url": "https://files.notion.so/report.pdf?signature=ephemeral"}}},
			)
			write(map[string]any{"results": state.blocks[1:]})
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/pages/"+pageID:
			if state.wrongTitle {
				state.title = "wrong title"
			} else {
				state.title = "Published title"
			}
			write(page(pageID, notionContainer, state.title))
		default:
			w.WriteHeader(http.StatusNotFound)
			write(map[string]any{"code": "not_found"})
		}
	}))
	defer fake.Close()
	client := fake.Client()
	client.Transport = notionRewrite{host: strings.TrimPrefix(fake.URL, "http://"), inner: client.Transport}
	a := &notionAdapter{client: client, token: "secret", container: notionContainer, group: "readers", profile: ports.DestinationManagedSnapshot}
	initialPage := page(pageID, notionContainer, notionNeutralTitle)
	raw, _ := json.Marshal(initialPage)
	var parsed notionPage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	initialBlocks := []notionBlock{{Object: "block", ID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Type: "paragraph", Paragraph: notionParagraph(marker)}}
	remote := remote(parsed, initialBlocks)
	file := ports.DocumentImage{Name: "report-aaaaaaaaaaaaaaaa.pdf", MediaType: "application/pdf", Data: []byte("%PDF-1.7")}
	artifact := ports.DocumentArtifact{Title: "Published title", Paragraphs: []string{"paragraph"}, PDF: file.Data, EvidenceHead: "evidence"}
	id, err := a.AllocateDocumentUpload(context.Background(), file)
	if err != nil || id != uploadID {
		t.Fatalf("allocate = %q, %v", id, err)
	}
	if err = a.SendDocumentUpload(context.Background(), id, file); err != nil {
		t.Fatalf("send: %v", err)
	}
	receipt, err := a.AppendDocumentSnapshot(context.Background(), remote, artifact, []ports.DocumentUploadReceipt{{Key: "attachment:0:" + fileDigest(file.Data), Digest: fileDigest(file.Data), UploadID: id}}, marker, contentHash)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	updated, err := a.SetDocumentSnapshotTitle(context.Background(), receipt.Remote, artifact.Title)
	if err != nil {
		t.Fatalf("title: %v", err)
	}
	receipt.Remote = updated
	if _, err = a.VerifyDocumentSnapshot(context.Background(), pageID, receipt, marker); err != nil {
		t.Fatalf("verify: %v", err)
	}
	state.wrongTitle = true
	if _, err = a.SetDocumentSnapshotTitle(context.Background(), updated, artifact.Title); err == nil {
		t.Fatal("wrong title acknowledgement was accepted")
	} else if provider, ok := err.(*ports.DocumentProviderError); !ok || !provider.Ambiguous || provider.Code != "invalid_title_response" {
		t.Fatalf("wrong title error = %#v", err)
	}
}

func snapshotParagraph(id, value string) map[string]any {
	return map[string]any{"object": "block", "id": id, "type": "paragraph", "paragraph": map[string]any{"rich_text": []any{map[string]any{"plain_text": value}}}}
}

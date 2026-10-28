package documentproviders

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const Notion integration.Provider = "notion"
const (
	notionAPIOrigin    = "https://api.notion.com"
	notionAPIVersion   = "2022-06-28"
	notionMaxBytes     = 1 << 20
	notionMaxFileBytes = 5 << 20
	notionMaxBlocks    = 100
	notionMaxText      = 2000
	notionMaxRequest   = 500 << 10
	notionNeutralTitle = "Synapse report"
)

var notionIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var notionDescriptor = integration.ProviderDescriptor{Provider: Notion, Name: "Notion", Description: "Owner-managed Notion report snapshots. Publication requires the destination_managed_snapshot_v1 profile; destination owners control sharing, including anonymous links.", Capabilities: []integration.Capability{integration.CapabilityTestConnection, integration.CapabilityDocuments}, ConfigFields: []integration.FieldDescriptor{{Name: "space", Label: "Container page ID", Kind: integration.FieldText, Required: true}, {Name: "read_group", Label: "Intended reader group", Kind: integration.FieldText, Required: true}, {Name: "publication_profile", Label: "Publication profile", Kind: integration.FieldText}, {Name: "data_class", Label: "Data classification (detail)", Kind: integration.FieldText, Required: true}}, SecretFields: []integration.FieldDescriptor{{Name: "integration_token", Label: "Internal integration token", Kind: integration.FieldPassword, Required: true}}}

type notionAdapter struct {
	client                           *http.Client
	token, container, group, profile string
}

var _ integration.Adapter = (*notionAdapter)(nil)
var _ integration.ConnectionTester = (*notionAdapter)(nil)
var _ ports.DocumentProvider = (*notionAdapter)(nil)
var _ ports.DocumentSnapshotProvider = (*notionAdapter)(nil)
var _ ports.DocumentReleasePreflighter = (*notionAdapter)(nil)

func newNotion(item integration.Integration, c integration.CredentialBundle, _ selfhosted.Rules) (integration.Adapter, error) {
	if item.Provider != Notion || item.Endpoint != notionAPIOrigin {
		return nil, fmt.Errorf("%w: Notion requires its pinned HTTPS API origin", shared.ErrValidation)
	}
	if err := notionDescriptor.ValidateSecrets(map[string]string(c)); err != nil {
		return nil, err
	}
	if err := validateToken(c["integration_token"]); err != nil {
		return nil, err
	}
	var v struct {
		Space   string `json:"space"`
		Group   string `json:"read_group"`
		Profile string `json:"publication_profile"`
		Class   string `json:"data_class"`
	}
	if json.Unmarshal(item.Config, &v) != nil || !notionIDPattern.MatchString(v.Space) || strings.TrimSpace(v.Group) == "" || len(v.Group) > 255 || v.Class != "detail" || (v.Profile != "" && v.Profile != ports.DestinationManagedSnapshot) {
		return nil, shared.ErrValidation
	}
	return &notionAdapter{client: safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(h, p string) bool { return h == "api.notion.com" && p == "443" }}), token: c["integration_token"], container: v.Space, group: v.Group, profile: v.Profile}, nil
}
func (*notionAdapter) Descriptor() integration.ProviderDescriptor { return notionDescriptor }
func (a *notionAdapter) Close()                                   { a.client.CloseIdleConnections(); a.token = "" }
func (a *notionAdapter) DocumentAccessProfile() string            { return a.profile }
func (a *notionAdapter) enabled() error {
	if a.profile != ports.DestinationManagedSnapshot {
		return docError(0, "publication_profile_required", false)
	}
	return nil
}
func (a *notionAdapter) ValidateDocumentText(s string) error {
	if containsCredential(s, a.token) {
		return docError(0, "credential_in_payload", false)
	}
	return nil
}

func (a *notionAdapter) request(ctx context.Context, m, p string, q url.Values, body, out any, want ...int) error {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, "?#\\") {
		return docError(0, "invalid_request", false)
	}
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil || len(raw) > notionMaxRequest {
			return shared.ErrValidation
		}
		if containsCredential(string(raw), a.token) {
			return docError(0, "credential_in_payload", false)
		}
	}
	u := url.URL{Scheme: "https", Host: "api.notion.com", Path: p, RawQuery: q.Encode()}
	r, err := http.NewRequestWithContext(ctx, m, u.String(), bytes.NewReader(raw))
	if err != nil {
		return docError(0, "invalid_request", false)
	}
	r.Header.Set("Authorization", "Bearer "+a.token)
	r.Header.Set("Notion-Version", notionAPIVersion)
	r.Header.Set("Accept", "application/json")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	data, _, err := readResponse(a.client, r, notionMaxBytes, want...)
	if err != nil {
		return err
	}
	if containsCredential(string(data), a.token) {
		return docError(http.StatusOK, "unsafe_provider_response", m != http.MethodGet)
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return docError(http.StatusOK, "invalid_response", m != http.MethodGet)
	}
	return nil
}

type notionPage struct {
	Object    string          `json:"object"`
	ID        string          `json:"id"`
	InTrash   *bool           `json:"in_trash"`
	Archived  *bool           `json:"archived"`
	PublicURL json.RawMessage `json:"public_url"`
	Parent    struct {
		Type   string `json:"type"`
		PageID string `json:"page_id"`
	} `json:"parent"`
	Properties map[string]json.RawMessage `json:"properties"`
}
type notionRichText struct {
	PlainText string `json:"plain_text"`
	Text      struct {
		Content string `json:"content"`
	} `json:"text"`
}
type notionBlock struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Type      string `json:"type"`
	Paragraph struct {
		RichText []notionRichText `json:"rich_text"`
	} `json:"paragraph"`
	PDF   notionMedia `json:"pdf"`
	Image notionMedia `json:"image"`
}
type notionMedia struct {
	Name    string           `json:"name"`
	Caption []notionRichText `json:"caption"`
	File    struct {
		URL string `json:"url"`
	} `json:"file"`
}

func notionSameID(a, b string) bool {
	return strings.EqualFold(strings.ReplaceAll(a, "-", ""), strings.ReplaceAll(b, "-", ""))
}
func notionPageURL(id string) string {
	return "https://www.notion.so/" + strings.ReplaceAll(strings.ToLower(id), "-", "")
}
func validPublicURL(raw json.RawMessage) error {
	if raw == nil {
		return docError(http.StatusOK, "complete_identity_unverifiable", false)
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || strings.TrimSpace(s) == "" {
		return docError(http.StatusOK, "invalid_public_url", false)
	}
	if _, err := docpublish.CanonicalURL(s); err != nil {
		return docError(http.StatusOK, "invalid_public_url", false)
	}
	return restrictionLostError(http.StatusOK, "page_published_to_web")
}
func (p notionPage) validate(id, parent string, child, allowTrash bool) error {
	if p.Object != "page" || !notionIDPattern.MatchString(p.ID) || !notionSameID(p.ID, id) {
		return docError(http.StatusOK, "invalid_remote_identity", false)
	}
	if p.InTrash == nil && p.Archived == nil {
		return docError(http.StatusOK, "complete_identity_unverifiable", false)
	}
	if !allowTrash && ((p.InTrash != nil && *p.InTrash) || (p.Archived != nil && *p.Archived)) {
		return restrictionLostError(http.StatusOK, "page_in_trash")
	}
	if err := validPublicURL(p.PublicURL); err != nil {
		return err
	}
	if child {
		if p.Parent.Type != "page_id" || !notionIDPattern.MatchString(p.Parent.PageID) || !notionSameID(p.Parent.PageID, parent) {
			return restrictionLostError(http.StatusOK, "remote_identity_changed")
		}
	} else if p.Parent.Type == "" {
		return docError(http.StatusOK, "complete_identity_unverifiable", false)
	}
	return nil
}
func (a *notionAdapter) page(ctx context.Context, id string) (notionPage, error) {
	var p notionPage
	if !notionIDPattern.MatchString(id) {
		return p, shared.ErrValidation
	}
	return p, a.request(ctx, http.MethodGet, "/v1/pages/"+id, nil, nil, &p, http.StatusOK)
}
func (a *notionAdapter) checkContainer(ctx context.Context) error {
	p, e := a.page(ctx, a.container)
	if e != nil {
		return e
	}
	return p.validate(a.container, "", false, false)
}
func (a *notionAdapter) TestConnection(ctx context.Context) error {
	var b struct {
		Object string `json:"object"`
		Type   string `json:"type"`
	}
	if e := a.request(ctx, http.MethodGet, "/v1/users/me", nil, nil, &b, http.StatusOK); e != nil {
		return e
	}
	if b.Object != "user" || b.Type != "bot" {
		return docError(http.StatusOK, "invalid_identity", false)
	}
	e := a.checkContainer(ctx)
	var pe *ports.DocumentProviderError
	if errors.As(e, &pe) && pe.Status == http.StatusNotFound {
		return docError(http.StatusNotFound, "container_not_shared", false)
	}
	return e
}
func (a *notionAdapter) CheckDocumentRelease(ctx context.Context, c, g string) error {
	if e := a.enabled(); e != nil {
		return e
	}
	if !notionSameID(c, a.container) || g != a.group {
		return shared.ErrConflict
	}
	return a.checkContainer(ctx)
}
func (a *notionAdapter) children(ctx context.Context, id string) ([]notionBlock, error) {
	if !notionIDPattern.MatchString(id) {
		return nil, shared.ErrValidation
	}
	var r struct {
		Results []notionBlock `json:"results"`
		HasMore *bool         `json:"has_more"`
	}
	if e := a.request(ctx, http.MethodGet, "/v1/blocks/"+id+"/children", url.Values{"page_size": {"100"}}, nil, &r, http.StatusOK); e != nil {
		return nil, e
	}
	if r.HasMore == nil || *r.HasMore || len(r.Results) > notionMaxBlocks {
		return nil, docError(http.StatusOK, "incomplete_children", false)
	}
	seen := map[string]bool{}
	for _, b := range r.Results {
		if b.Object != "block" || !notionIDPattern.MatchString(b.ID) || seen[b.ID] {
			return nil, docError(http.StatusOK, "invalid_child", false)
		}
		if b.Type == "pdf" || b.Type == "image" {
			media := b.PDF
			if b.Type == "image" {
				media = b.Image
			}
			u, err := url.Parse(media.File.URL)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
				return nil, docError(http.StatusOK, "invalid_attachment_identity", false)
			}
		}
		seen[b.ID] = true
	}
	return r.Results, nil
}
func blockText(b notionBlock) (string, error) {
	if b.Type != "paragraph" {
		return "", docError(http.StatusOK, "invalid_block", false)
	}
	var x strings.Builder
	for _, v := range b.Paragraph.RichText {
		if v.PlainText != "" {
			x.WriteString(v.PlainText)
		} else {
			x.WriteString(v.Text.Content)
		}
	}
	s := x.String()
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) || utf8.RuneCountInString(s) > notionMaxText {
		return "", docError(http.StatusOK, "invalid_block", false)
	}
	return s, nil
}
func hasMarker(bs []notionBlock, m string) bool {
	n := 0
	for _, b := range bs {
		if b.Type == "paragraph" {
			s, e := blockText(b)
			if e == nil && s == m {
				n++
			}
		}
	}
	return n == 1
}
func digest(bs []notionBlock) string {
	type x struct{ ID, Type, Text string }
	v := make([]x, 0, len(bs))
	for _, b := range bs {
		s, _ := blockText(b)
		if b.Type == "pdf" || b.Type == "image" {
			media := b.PDF
			if b.Type == "image" {
				media = b.Image
			}
			u, err := url.Parse(media.File.URL)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
				s = "invalid-media"
			} else {
				caption := ""
				for _, c := range media.Caption {
					if c.PlainText != "" {
						caption += c.PlainText
					} else {
						caption += c.Text.Content
					}
				}
				s = media.Name + "\x00" + strings.ToLower(u.Host) + "\x00" + u.EscapedPath() + "\x00" + caption
			}
		}
		v = append(v, x{strings.ToLower(strings.ReplaceAll(b.ID, "-", "")), b.Type, s})
	}
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func remote(p notionPage, bs []notionBlock) docpublish.RemotePage {
	title, _ := titleOf(p)
	h := sha256.Sum256([]byte(digest(bs) + "\x00" + title))
	return docpublish.RemotePage{ID: p.ID, Version: 1, Revision: hex.EncodeToString(h[:]), URL: notionPageURL(p.ID)}
}
func (a *notionAdapter) ObserveDocumentDestination(ctx context.Context, id, c string) (ports.DocumentRemoteState, error) {
	if e := a.enabled(); e != nil {
		return ports.DocumentRemoteState{}, e
	}
	if !notionSameID(c, a.container) {
		return ports.DocumentRemoteState{}, shared.ErrConflict
	}
	if e := a.checkContainer(ctx); e != nil {
		return ports.DocumentRemoteState{}, e
	}
	p, e := a.page(ctx, id)
	if e != nil {
		return ports.DocumentRemoteState{}, e
	}
	if e = p.validate(id, a.container, true, false); e != nil {
		return ports.DocumentRemoteState{}, e
	}
	bs, e := a.children(ctx, p.ID)
	if e != nil {
		return ports.DocumentRemoteState{}, e
	}
	marker := ""
	for _, b := range bs {
		if b.Type == "paragraph" {
			s, _ := blockText(b)
			if validMarker(s) {
				if marker != "" {
					return ports.DocumentRemoteState{}, docError(http.StatusOK, "invalid_marker", false)
				}
				marker = s
			}
		}
	}
	return ports.DocumentRemoteState{RemotePage: remote(p, bs), Container: a.container, Marker: marker, Neutral: marker != "" && len(bs) == 1}, nil
}
func (a *notionAdapter) GetDocument(ctx context.Context, id string) (ports.DocumentRemoteState, error) {
	return a.ObserveDocumentDestination(ctx, id, a.container)
}
func textBlock(s string) map[string]any {
	return map[string]any{"object": "block", "type": "paragraph", "paragraph": map[string]any{"rich_text": []any{map[string]any{"type": "text", "text": map[string]any{"content": s}}}}}
}
func fileBlock(kind, id string) map[string]any {
	return map[string]any{"object": "block", "type": kind, kind: map[string]any{"type": "file_upload", "file_upload": map[string]string{"id": id}}}
}
func (a *notionAdapter) CreateDocumentShell(ctx context.Context, c, m string) (docpublish.RemotePage, error) {
	if e := a.CheckDocumentRelease(ctx, c, a.group); e != nil {
		return docpublish.RemotePage{}, e
	}
	if !validMarker(m) {
		return docpublish.RemotePage{}, shared.ErrValidation
	}
	body := map[string]any{"parent": map[string]string{"type": "page_id", "page_id": a.container}, "properties": map[string]any{"title": map[string]any{"title": []any{map[string]any{"type": "text", "text": map[string]string{"content": notionNeutralTitle}}}}}, "children": []any{textBlock(m)}}
	var p notionPage
	if e := a.request(ctx, http.MethodPost, "/v1/pages", nil, body, &p, http.StatusOK); e != nil {
		return docpublish.RemotePage{}, e
	}
	if e := p.validate(p.ID, a.container, true, false); e != nil {
		return docpublish.RemotePage{}, docError(http.StatusOK, "invalid_shell_response", true)
	}
	bs, e := a.children(ctx, p.ID)
	if e != nil || !hasMarker(bs, m) {
		return docpublish.RemotePage{}, docError(http.StatusOK, "invalid_shell_response", true)
	}
	return remote(p, bs), nil
}
func (*notionAdapter) RestrictDocument(context.Context, string, string) error {
	return docError(0, "destination_managed_snapshot", false)
}
func (*notionAdapter) VerifyDocumentRestriction(context.Context, string, string, string) error {
	return docError(0, "destination_managed_snapshot", false)
}
func (*notionAdapter) UploadDocumentAttachment(context.Context, string, ports.DocumentImage) error {
	return docError(0, "destination_managed_snapshot", false)
}
func (*notionAdapter) WriteDocument(context.Context, string, int, string, string, string) (docpublish.RemotePage, error) {
	return docpublish.RemotePage{}, docError(0, "destination_managed_snapshot", false)
}
func (*notionAdapter) PurgeDocument(context.Context, string, func(context.Context) error) error {
	return docError(0, "destination_managed_snapshot", false)
}
func goodText(s string) bool {
	return strings.TrimSpace(s) != "" && utf8.ValidString(s) && !strings.ContainsRune(s, 0) && utf8.RuneCountInString(s) <= notionMaxText
}
func (a *notionAdapter) ValidateDocumentSnapshot(x ports.DocumentArtifact) error {
	if !goodText(x.Title) || (x.EvidenceHead != "" && !goodText(x.EvidenceHead)) || len(x.Paragraphs) == 0 || len(x.PDF) == 0 || len(x.PDF) > notionMaxFileBytes || len(x.Paragraphs)+len(x.Images)+4 > notionMaxBlocks {
		return shared.ErrValidation
	}
	values := append([]string{x.Title}, x.Paragraphs...)
	if x.EvidenceHead != "" {
		values = append(values, x.EvidenceHead)
	}
	for _, s := range append(values, names(x.Images)...) {
		if !goodText(s) {
			return shared.ErrValidation
		}
		if e := a.ValidateDocumentText(s); e != nil {
			return e
		}
	}
	for _, f := range x.Images {
		if len(f.Data) == 0 || len(f.Data) > notionMaxFileBytes || !validAttachmentName(f.Name) || !strings.HasPrefix(f.MediaType, "image/") {
			return shared.ErrValidation
		}
	}
	if !notionAppendFits(x) {
		return shared.ErrValidation
	}
	return nil
}

// notionAppendFits uses the exact native block envelope and fixed-width values
// supplied by the release workflow. It proves the bounded append fits before a
// shell or file upload is allocated; it does not truncate report content.
func notionAppendFits(x ports.DocumentArtifact) bool {
	blocks := make([]any, 0, len(x.Paragraphs)+len(x.Images)+2)
	for _, paragraph := range x.Paragraphs {
		blocks = append(blocks, textBlock(paragraph))
	}
	evidence := x.EvidenceHead
	if evidence == "" {
		evidence = "none (no verified evidence-chain head is available)"
	}
	blocks = append(blocks, textBlock("Evidence: "+evidence), textBlock("Artifact SHA-256: "+strings.Repeat("a", 64)))
	for i := 0; i <= len(x.Images); i++ {
		kind := "image"
		if i == 0 {
			kind = "pdf"
		}
		blocks = append(blocks, fileBlock(kind, "01234567-89ab-cdef-0123-456789abcdef"))
	}
	body, err := json.Marshal(map[string]any{"children": blocks})
	return err == nil && len(body) <= notionMaxRequest
}
func names(v []ports.DocumentImage) []string {
	o := make([]string, len(v))
	for i := range v {
		o[i] = v[i].Name
	}
	return o
}
func fileDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func notionHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'f') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
func (a *notionAdapter) AllocateDocumentUpload(ctx context.Context, f ports.DocumentImage) (string, error) {
	if e := a.enabled(); e != nil {
		return "", e
	}
	if len(f.Data) == 0 || len(f.Data) > notionMaxFileBytes || !validAttachmentName(f.Name) || (!strings.HasPrefix(f.MediaType, "image/") && f.MediaType != "application/pdf") {
		return "", shared.ErrValidation
	}
	if e := a.ValidateDocumentText(f.Name); e != nil {
		return "", e
	}
	var out struct {
		ID string `json:"id"`
	}
	e := a.request(ctx, http.MethodPost, "/v1/file_uploads", nil, map[string]string{"mode": "single_part", "filename": f.Name, "content_type": f.MediaType}, &out, http.StatusOK)
	if e != nil {
		return "", e
	}
	if !notionIDPattern.MatchString(out.ID) {
		return "", docError(http.StatusOK, "invalid_upload_response", true)
	}
	return out.ID, nil
}
func (a *notionAdapter) SendDocumentUpload(ctx context.Context, id string, f ports.DocumentImage) error {
	if e := a.enabled(); e != nil {
		return e
	}
	if !notionIDPattern.MatchString(id) || len(f.Data) == 0 || len(f.Data) > notionMaxFileBytes {
		return shared.ErrValidation
	}
	if !validAttachmentName(f.Name) || (!strings.HasPrefix(f.MediaType, "image/") && f.MediaType != "application/pdf") {
		return shared.ErrValidation
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreatePart(textproto.MIMEHeader{"Content-Disposition": {`form-data; name="file"; filename="` + f.Name + `"`}, "Content-Type": {f.MediaType}})
	if err != nil {
		return shared.ErrValidation
	}
	if _, err = part.Write(f.Data); err != nil {
		return docError(0, "upload_body", false)
	}
	if err = w.Close(); err != nil {
		return docError(0, "upload_body", false)
	}
	u := url.URL{Scheme: "https", Host: "api.notion.com", Path: "/v1/file_uploads/" + id + "/send"}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), &body)
	if err != nil {
		return docError(0, "invalid_request", false)
	}
	r.Header.Set("Authorization", "Bearer "+a.token)
	r.Header.Set("Notion-Version", notionAPIVersion)
	r.Header.Set("Content-Type", w.FormDataContentType())
	r.Header.Set("Accept", "application/json")
	var ack struct {
		ID            string `json:"id"`
		Status        string `json:"status"`
		ContentLength int64  `json:"content_length"`
	}
	raw, _, err := readResponse(a.client, r, notionMaxBytes, http.StatusOK)
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, &ack) != nil || !notionSameID(ack.ID, id) || ack.Status != "uploaded" || ack.ContentLength != int64(len(f.Data)) {
		return docError(http.StatusOK, "invalid_upload_response", true)
	}
	return nil
}
func selected(all []notionBlock, ids []string) ([]notionBlock, error) {
	m := map[string]notionBlock{}
	for _, b := range all {
		m[strings.ToLower(strings.ReplaceAll(b.ID, "-", ""))] = b
	}
	out := make([]notionBlock, 0, len(ids))
	for _, id := range ids {
		b, ok := m[strings.ToLower(strings.ReplaceAll(id, "-", ""))]
		if !ok {
			return nil, docError(http.StatusOK, "snapshot_blocks_missing", false)
		}
		out = append(out, b)
	}
	return out, nil
}

// matchesSnapshotAppend proves that the returned block identities still carry
// the exact artifact projection just dispatched. The block IDs alone are not
// sufficient: a provider response or readback could otherwise acknowledge a
// different paragraph body while the workflow records the original hash.
func matchesSnapshotAppend(blocks []notionBlock, artifact ports.DocumentArtifact, contentHash string) bool {
	expectedCount := len(artifact.Paragraphs) + 2 + 1 + len(artifact.Images)
	if len(blocks) != expectedCount {
		return false
	}
	index := 0
	for _, paragraph := range artifact.Paragraphs {
		actual, err := blockText(blocks[index])
		if err != nil || actual != paragraph {
			return false
		}
		index++
	}
	evidence := artifact.EvidenceHead
	if evidence == "" {
		evidence = "none (no verified evidence-chain head is available)"
	}
	for _, expected := range []string{"Evidence: " + evidence, "Artifact SHA-256: " + contentHash} {
		actual, err := blockText(blocks[index])
		if err != nil || actual != expected {
			return false
		}
		index++
	}
	if blocks[index].Type != "pdf" {
		return false
	}
	index++
	for range artifact.Images {
		if blocks[index].Type != "image" {
			return false
		}
		index++
	}
	return true
}

func ambiguous(e error) error {
	var p *ports.DocumentProviderError
	if errors.As(e, &p) {
		q := *p
		q.Ambiguous = true
		return &q
	}
	return docError(0, "reconciliation_required", true)
}
func (a *notionAdapter) AppendDocumentSnapshot(ctx context.Context, r docpublish.RemotePage, x ports.DocumentArtifact, uploads []ports.DocumentUploadReceipt, m, contentHash string) (ports.DocumentSnapshotReceipt, error) {
	if e := a.enabled(); e != nil {
		return ports.DocumentSnapshotReceipt{}, e
	}
	if e := a.ValidateDocumentSnapshot(x); e != nil {
		return ports.DocumentSnapshotReceipt{}, e
	}
	if !validMarker(m) || !notionHash(contentHash) || len(uploads) != len(x.Images)+1 {
		return ports.DocumentSnapshotReceipt{}, shared.ErrValidation
	}
	if e := a.checkContainer(ctx); e != nil {
		return ports.DocumentSnapshotReceipt{}, e
	}
	p, e := a.page(ctx, r.ID)
	if e != nil {
		return ports.DocumentSnapshotReceipt{}, e
	}
	if e = p.validate(r.ID, a.container, true, false); e != nil {
		return ports.DocumentSnapshotReceipt{}, e
	}
	old, e := a.children(ctx, p.ID)
	if e != nil {
		return ports.DocumentSnapshotReceipt{}, e
	}
	if !hasMarker(old, m) {
		return ports.DocumentSnapshotReceipt{}, restrictionLostError(http.StatusOK, "remote_identity_changed")
	}
	if r.Revision != "" && r.Revision != remote(p, old).Revision {
		return ports.DocumentSnapshotReceipt{}, docError(http.StatusConflict, "revision_conflict", false)
	}
	keys := make([]string, 0, len(uploads))
	keys = append(keys, "attachment:0:"+fileDigest(x.PDF))
	for i, image := range x.Images {
		keys = append(keys, fmt.Sprintf("attachment:%d:%s", i+1, fileDigest(image.Data)))
	}
	by := map[string]ports.DocumentUploadReceipt{}
	for _, u := range uploads {
		if u.Key == "" || u.UploadID == "" || !notionIDPattern.MatchString(u.UploadID) || by[u.Key].UploadID != "" {
			return ports.DocumentSnapshotReceipt{}, shared.ErrValidation
		}
		by[u.Key] = u
	}
	blocks := make([]any, 0, len(x.Paragraphs)+3+len(uploads))
	for _, s := range x.Paragraphs {
		blocks = append(blocks, textBlock(s))
	}
	evidence := x.EvidenceHead
	if evidence == "" {
		evidence = "none (no verified evidence-chain head is available)"
	}
	blocks = append(blocks, textBlock("Evidence: "+evidence), textBlock("Artifact SHA-256: "+contentHash))
	for i, k := range keys {
		u := by[k]
		if u.UploadID == "" {
			return ports.DocumentSnapshotReceipt{}, shared.ErrValidation
		}
		kind := "image"
		if i == 0 {
			kind = "pdf"
		}
		blocks = append(blocks, fileBlock(kind, u.UploadID))
	}
	body := map[string]any{"children": blocks}
	raw, _ := json.Marshal(body)
	if len(raw) > notionMaxRequest {
		return ports.DocumentSnapshotReceipt{}, shared.ErrValidation
	}
	var out struct {
		Results []notionBlock `json:"results"`
	}
	if e = a.request(ctx, http.MethodPatch, "/v1/blocks/"+p.ID+"/children", nil, body, &out, http.StatusOK); e != nil {
		return ports.DocumentSnapshotReceipt{}, e
	}
	if len(out.Results) != len(blocks) {
		return ports.DocumentSnapshotReceipt{}, docError(http.StatusOK, "invalid_append_response", true)
	}
	ids := make([]string, len(out.Results))
	for i, b := range out.Results {
		if !notionIDPattern.MatchString(b.ID) {
			return ports.DocumentSnapshotReceipt{}, docError(http.StatusOK, "invalid_append_response", true)
		}
		ids[i] = b.ID
	}
	all, e := a.children(ctx, p.ID)
	if e != nil {
		return ports.DocumentSnapshotReceipt{}, ambiguous(e)
	}
	save, e := selected(all, ids)
	if e != nil {
		return ports.DocumentSnapshotReceipt{}, ambiguous(e)
	}
	if !matchesSnapshotAppend(save, x, contentHash) {
		return ports.DocumentSnapshotReceipt{}, docError(http.StatusOK, "append_readback_mismatch", true)
	}
	return ports.DocumentSnapshotReceipt{BlockIDs: ids, Digest: digest(save), Remote: remote(p, all)}, nil
}
func (a *notionAdapter) SetDocumentSnapshotTitle(ctx context.Context, r docpublish.RemotePage, title string) (docpublish.RemotePage, error) {
	if e := a.enabled(); e != nil {
		return docpublish.RemotePage{}, e
	}
	if !goodText(title) {
		return docpublish.RemotePage{}, shared.ErrValidation
	}
	if e := a.checkContainer(ctx); e != nil {
		return docpublish.RemotePage{}, e
	}
	p, e := a.page(ctx, r.ID)
	if e != nil {
		return docpublish.RemotePage{}, e
	}
	if e = p.validate(r.ID, a.container, true, false); e != nil {
		return docpublish.RemotePage{}, e
	}
	before, e := a.children(ctx, p.ID)
	if e != nil {
		return docpublish.RemotePage{}, e
	}
	if r.Revision != "" && r.Revision != remote(p, before).Revision {
		return docpublish.RemotePage{}, docError(http.StatusConflict, "revision_conflict", false)
	}
	body := map[string]any{"properties": map[string]any{"title": map[string]any{"title": []any{map[string]any{"type": "text", "text": map[string]string{"content": title}}}}}}
	var u notionPage
	if e = a.request(ctx, http.MethodPatch, "/v1/pages/"+p.ID, nil, body, &u, http.StatusOK); e != nil {
		return docpublish.RemotePage{}, e
	}
	if e = u.validate(r.ID, a.container, true, false); e != nil {
		return docpublish.RemotePage{}, docError(http.StatusOK, "invalid_title_response", true)
	}
	ackTitle, titleErr := titleOf(u)
	if titleErr != nil || ackTitle != title {
		return docpublish.RemotePage{}, docError(http.StatusOK, "invalid_title_response", true)
	}
	bs, e := a.children(ctx, u.ID)
	if e != nil {
		return docpublish.RemotePage{}, ambiguous(e)
	}
	return remote(u, bs), nil
}
func titleOf(p notionPage) (string, error) {
	for _, raw := range p.Properties {
		var v struct {
			Type  string           `json:"type"`
			Title []notionRichText `json:"title"`
		}
		if json.Unmarshal(raw, &v) == nil && v.Type == "title" {
			var b strings.Builder
			for _, x := range v.Title {
				if x.PlainText != "" {
					b.WriteString(x.PlainText)
				} else {
					b.WriteString(x.Text.Content)
				}
			}
			return b.String(), nil
		}
	}
	return "", docError(http.StatusOK, "title_unverifiable", false)
}
func (a *notionAdapter) VerifyDocumentSnapshot(ctx context.Context, id string, receipt ports.DocumentSnapshotReceipt, m string) (docpublish.RemotePage, error) {
	if e := a.enabled(); e != nil {
		return docpublish.RemotePage{}, e
	}
	if len(receipt.BlockIDs) == 0 || !validMarker(m) {
		return docpublish.RemotePage{}, shared.ErrValidation
	}
	if e := a.checkContainer(ctx); e != nil {
		return docpublish.RemotePage{}, e
	}
	p, e := a.page(ctx, id)
	if e != nil {
		return docpublish.RemotePage{}, e
	}
	if e = p.validate(id, a.container, true, false); e != nil {
		return docpublish.RemotePage{}, e
	}
	bs, e := a.children(ctx, p.ID)
	if e != nil {
		return docpublish.RemotePage{}, e
	}
	if !hasMarker(bs, m) {
		return docpublish.RemotePage{}, restrictionLostError(http.StatusOK, "remote_identity_changed")
	}
	saved, e := selected(bs, receipt.BlockIDs)
	if e != nil {
		return docpublish.RemotePage{}, e
	}
	if digest(saved) != receipt.Digest {
		return docpublish.RemotePage{}, restrictionLostError(http.StatusOK, "snapshot_changed")
	}
	return remote(p, bs), nil
}
func (a *notionAdapter) TrashDocument(ctx context.Context, r docpublish.RemotePage) error {
	if e := a.enabled(); e != nil {
		return e
	}
	if e := a.checkContainer(ctx); e != nil {
		return e
	}
	p, e := a.page(ctx, r.ID)
	if e != nil {
		return e
	}
	if e = p.validate(r.ID, a.container, true, false); e != nil {
		return e
	}
	before, e := a.children(ctx, p.ID)
	if e != nil {
		return e
	}
	if r.Revision != "" && r.Revision != remote(p, before).Revision {
		return docError(http.StatusConflict, "revision_conflict", false)
	}
	return a.request(ctx, http.MethodPatch, "/v1/pages/"+p.ID, nil, map[string]bool{"in_trash": true}, nil, http.StatusOK)
}
func (a *notionAdapter) ConfirmDocumentTrash(ctx context.Context, id, c string) (bool, error) {
	if e := a.enabled(); e != nil {
		return false, e
	}
	if !notionSameID(c, a.container) {
		return false, shared.ErrConflict
	}
	p, e := a.page(ctx, id)
	if e != nil {
		return false, e
	}
	if e = p.validate(id, a.container, true, true); e != nil {
		return false, e
	}
	return (p.InTrash != nil && *p.InTrash) || (p.Archived != nil && *p.Archived), nil
}
func (a *notionAdapter) FindDocumentMarker(ctx context.Context, c, m string) ([]ports.DocumentRemoteState, error) {
	if e := a.enabled(); e != nil {
		return nil, e
	}
	if !notionSameID(c, a.container) || !validMarker(m) {
		return nil, shared.ErrValidation
	}
	if e := a.checkContainer(ctx); e != nil {
		return nil, e
	}
	kids, e := a.children(ctx, a.container)
	if e != nil {
		return nil, e
	}
	out := []ports.DocumentRemoteState{}
	for _, b := range kids {
		if b.Type != "child_page" {
			continue
		}
		p, e := a.page(ctx, b.ID)
		if e != nil {
			return nil, e
		}
		if e = p.validate(b.ID, a.container, true, false); e != nil {
			return nil, e
		}
		bs, e := a.children(ctx, p.ID)
		if e != nil {
			return nil, e
		}
		if hasMarker(bs, m) {
			out = append(out, ports.DocumentRemoteState{RemotePage: remote(p, bs), Container: a.container, Marker: m, Neutral: len(bs) == 1})
		}
	}
	return out, nil
}

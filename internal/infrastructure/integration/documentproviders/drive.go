package documentproviders

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // Drive exposes md5Checksum for transport readback; security identities use SHA-256.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const Drive integration.Provider = "google-drive"
const folderMIME = "application/vnd.google-apps.folder"
const driveFields = "id,title,mimeType,etag,description,parents(id),owners(permissionId),teamDriveId,labels(trashed),properties(key,value,visibility),headRevisionId,md5Checksum"

var driveDescriptor = integration.ProviderDescriptor{
	Provider: Drive, Name: "Google Drive", Description: "Governed HTML report folders in a dedicated service-owned My Drive folder. Exact reader permission and owner are verified before every upload; shared drives are refused.",
	Capabilities: []integration.Capability{integration.CapabilityTestConnection, integration.CapabilityDocuments},
	ConfigFields: []integration.FieldDescriptor{{Name: "space", Label: "Restricted parent folder ID", Kind: integration.FieldText, Required: true}, {Name: "read_group", Label: "Exact group permission ID", Kind: integration.FieldText, Required: true}, {Name: "data_class", Label: "Data classification (detail)", Kind: integration.FieldText, Required: true}},
	SecretFields: []integration.FieldDescriptor{{Name: "access_token", Label: "Scoped Drive access token", Kind: integration.FieldPassword, Required: true}},
}

type driveAdapter struct {
	client                  *http.Client
	token, container, group string
}

var _ ports.DocumentProvider = (*driveAdapter)(nil)
var _ ports.DocumentRevisionWriter = (*driveAdapter)(nil)
var _ ports.DocumentReleasePreflighter = (*driveAdapter)(nil)
var _ ports.DocumentRestrictedReader = (*driveAdapter)(nil)
var _ integration.ConnectionTester = (*driveAdapter)(nil)

func newDrive(item integration.Integration, c integration.CredentialBundle, _ selfhosted.Rules) (integration.Adapter, error) {
	if item.Provider != Drive || item.Endpoint != "https://www.googleapis.com" {
		return nil, fmt.Errorf("%w: Drive requires its pinned HTTPS API origin", shared.ErrValidation)
	}
	if err := driveDescriptor.ValidateSecrets(map[string]string(c)); err != nil {
		return nil, err
	}
	if err := validateToken(c["access_token"]); err != nil {
		return nil, err
	}
	var cfg struct {
		Space string `json:"space"`
		Group string `json:"read_group"`
		Class string `json:"data_class"`
	}
	if json.Unmarshal(item.Config, &cfg) != nil || !safeID(cfg.Space) || !safeID(cfg.Group) || cfg.Class != "detail" {
		return nil, shared.ErrValidation
	}
	return &driveAdapter{client: safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(h, p string) bool { return h == "www.googleapis.com" && p == "443" }}), token: c["access_token"], container: cfg.Space, group: cfg.Group}, nil
}
func (*driveAdapter) Descriptor() integration.ProviderDescriptor { return driveDescriptor }
func (a *driveAdapter) Close()                                   { a.client.CloseIdleConnections(); a.token = "" }
func (a *driveAdapter) ValidateDocumentText(value string) error {
	if containsCredential(value, a.token) {
		return docError(0, "credential_in_payload", false)
	}
	return nil
}
func (a *driveAdapter) request(ctx context.Context, method, path string, q url.Values, body []byte, headers http.Header, want ...int) ([]byte, http.Header, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\") {
		return nil, nil, docError(0, "invalid_request", false)
	}
	u := url.URL{Scheme: "https", Host: "www.googleapis.com", Path: path, RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, docError(0, "invalid_request", false)
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = http.Header{}
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/json")
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return readResponse(a.client, req, 24<<20, want...)
}
func (a *driveAdapter) json(ctx context.Context, method, path string, q url.Values, body any, out any, want ...int) error {
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return shared.ErrValidation
		}
	}
	data, _, err := a.request(ctx, method, path, q, raw, nil, want...)
	if err != nil {
		return err
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return docError(200, "invalid_response", method != http.MethodGet)
	}
	return nil
}
func (a *driveAdapter) identity(ctx context.Context) (string, error) {
	var out struct {
		User struct {
			ID string `json:"permissionId"`
		} `json:"user"`
	}
	if err := a.json(ctx, "GET", "/drive/v2/about", url.Values{"fields": {"user(permissionId)"}}, nil, &out, 200); err != nil {
		return "", err
	}
	if !safeID(out.User.ID) || containsCredential(out.User.ID, a.token) {
		return "", docError(200, "invalid_identity", false)
	}
	return out.User.ID, nil
}
func (a *driveAdapter) TestConnection(ctx context.Context) error {
	return a.CheckDocumentRelease(ctx, a.container, a.group)
}

type driveFile struct {
	ID          string `json:"id"`
	Name        string `json:"title"`
	MIME        string `json:"mimeType"`
	ETag        string `json:"etag"`
	Description string `json:"description"`
	TeamDriveID string `json:"teamDriveId"`
	Parents     []struct {
		ID string `json:"id"`
	} `json:"parents"`
	Owners []struct {
		ID string `json:"permissionId"`
	} `json:"owners"`
	Labels struct {
		Trashed bool `json:"trashed"`
	} `json:"labels"`
	Properties []struct {
		Key        string `json:"key"`
		Value      string `json:"value"`
		Visibility string `json:"visibility"`
	} `json:"properties"`
	HeadRevision                                   string `json:"headRevisionId"`
	MD5                                            string `json:"md5Checksum"`
	mimePresent, parentsPresent, propertiesPresent bool
}

func (f *driveFile) UnmarshalJSON(data []byte) error {
	type plain driveFile
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields struct {
		MIME       json.RawMessage `json:"mimeType"`
		Parents    json.RawMessage `json:"parents"`
		Properties json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	decoded.mimePresent = presentFacet(fields.MIME)
	decoded.parentsPresent = presentFacet(fields.Parents)
	decoded.propertiesPresent = presentFacet(fields.Properties)
	*f = driveFile(decoded)
	return nil
}

func (f driveFile) property(key string) string {
	value := ""
	for _, p := range f.Properties {
		if p.Key == key {
			if value != "" || p.Visibility != "PRIVATE" {
				return ""
			}
			value = p.Value
		}
	}
	return value
}

func (f driveFile) shellIdentity(container, body string) error {
	if !f.mimePresent || !f.parentsPresent || !f.propertiesPresent {
		return docError(http.StatusOK, "complete_identity_unverifiable", false)
	}
	if mediaType, _, err := mime.ParseMediaType(f.MIME); err != nil || !strings.Contains(mediaType, "/") {
		return docError(http.StatusOK, "complete_identity_unverifiable", false)
	}
	for _, parent := range f.Parents {
		if !safeID(parent.ID) {
			return docError(http.StatusOK, "complete_identity_unverifiable", false)
		}
	}
	if f.MIME != folderMIME || len(f.Parents) != 1 || f.Parents[0].ID != container {
		return restrictionLostError(http.StatusOK, "remote_identity_changed")
	}
	seenBody, seenMarker := false, false
	for _, property := range f.Properties {
		if property.Key == "" {
			return docError(http.StatusOK, "complete_identity_unverifiable", false)
		}
		switch property.Key {
		case "synapse-body":
			if property.Value == "" || property.Visibility == "" {
				return docError(http.StatusOK, "complete_identity_unverifiable", false)
			}
			if seenBody {
				return docError(http.StatusOK, "complete_identity_unverifiable", false)
			}
			seenBody = true
			if property.Visibility != "PRIVATE" || property.Value != body {
				return restrictionLostError(http.StatusOK, "remote_identity_changed")
			}
		case "synapse-marker":
			if property.Value == "" || property.Visibility == "" {
				return docError(http.StatusOK, "complete_identity_unverifiable", false)
			}
			if seenMarker {
				return docError(http.StatusOK, "complete_identity_unverifiable", false)
			}
			seenMarker = true
			if property.Visibility != "PRIVATE" || !validMarker(property.Value) {
				return restrictionLostError(http.StatusOK, "remote_identity_changed")
			}
		}
	}
	if !seenBody || !seenMarker {
		return restrictionLostError(http.StatusOK, "remote_identity_changed")
	}
	return nil
}
func (a *driveAdapter) file(ctx context.Context, id string) (driveFile, error) {
	return a.fileWithHeaders(ctx, id, nil)
}

func (a *driveAdapter) fileWithETag(ctx context.Context, id, etag string) (driveFile, error) {
	if !validDriveETag(etag, a.token) {
		return driveFile{}, shared.ErrValidation
	}
	return a.fileWithHeaders(ctx, id, http.Header{"If-Match": {etag}})
}

func (a *driveAdapter) fileWithHeaders(ctx context.Context, id string, headers http.Header) (driveFile, error) {
	var f driveFile
	if !safeID(id) {
		return f, shared.ErrValidation
	}
	raw, _, err := a.request(ctx, "GET", "/drive/v2/files/"+id, url.Values{"fields": {driveFields}}, nil, headers, 200)
	if err != nil {
		return f, err
	}
	if json.Unmarshal(raw, &f) != nil {
		return f, docError(200, "invalid_response", false)
	}
	if f.ID != id || f.Labels.Trashed || f.TeamDriveID != "" || !validDriveETag(f.ETag, a.token) {
		return f, docError(200, "invalid_remote_identity", false)
	}
	return f, nil
}

func validDriveETag(etag, token string) bool {
	return etag != "" && len(etag) <= 512 && !strings.ContainsAny(etag, "\r\n") && !containsCredential(etag, token)
}

func validDriveMD5(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// readFileBytes binds a body read to the immutable Drive revision, then confirms
// that the metadata used to select it has not changed. Drive media and metadata
// responses may expose different ETags, so only the final metadata request uses
// the metadata ETag as a conditional fence.
func (a *driveAdapter) readFileBytes(ctx context.Context, f driveFile) ([]byte, error) {
	if !safeID(f.ID) || !safeID(f.HeadRevision) || !validDriveMD5(f.MD5) || !validDriveETag(f.ETag, a.token) {
		return nil, docError(200, "invalid_blob_identity", false)
	}
	raw, _, err := a.request(ctx, "GET", "/drive/v2/files/"+f.ID, url.Values{"alt": {"media"}, "revisionId": {f.HeadRevision}}, nil, nil, 200)
	if err != nil {
		return nil, err
	}
	sum := md5.Sum(raw) //nolint:gosec // Compare the vendor content checksum; this does not authenticate or authorize content.
	if hex.EncodeToString(sum[:]) != f.MD5 {
		return nil, docError(200, "content_checksum_mismatch", false)
	}
	confirmed, err := a.fileWithETag(ctx, f.ID, f.ETag)
	if err != nil {
		return nil, err
	}
	if confirmed.ETag != f.ETag || confirmed.HeadRevision != f.HeadRevision || confirmed.MD5 != f.MD5 {
		return nil, docError(200, "blob_metadata_changed", false)
	}
	return raw, nil
}
func (a *driveAdapter) checkACL(ctx context.Context, id, group string) error {
	owner, err := a.identity(ctx)
	if err != nil {
		return err
	}
	f, err := a.file(ctx, id)
	if err != nil {
		return err
	}
	return a.checkKnownFileACL(ctx, f, owner, group)
}

// Metadata and actor identity are reused only within one fresh proof. Each ACL
// page is read for the actual item immediately before the guarded operation.
func (a *driveAdapter) checkKnownFileACL(ctx context.Context, f driveFile, owner, group string) error {
	id := f.ID
	if len(f.Owners) != 1 || !safeID(f.Owners[0].ID) {
		return docError(200, "complete_acl_unverifiable", false)
	}
	if f.Owners[0].ID != owner {
		return restrictionLostError(http.StatusOK, "restricted_sharing_unverified")
	}
	token := ""
	seen := map[string]bool{}
	hasGroup, hasOwner := false, false
	for page := 0; page < 20; page++ {
		var out struct {
			Items json.RawMessage `json:"items"`
			Next  string          `json:"nextPageToken"`
		}
		query := url.Values{"maxResults": {"100"}, "fields": {"items(id,type,role,deleted,additionalRoles),nextPageToken"}}
		if token != "" {
			query.Set("pageToken", token)
		}
		if err := a.json(ctx, "GET", "/drive/v2/files/"+id+"/permissions", query, nil, &out, 200); err != nil {
			return err
		}
		if out.Next != "" && (len(out.Next) > 2048 || out.Next == token) {
			return docError(200, "incomplete_permissions", false)
		}
		if !presentFacet(out.Items) {
			return docError(200, "complete_acl_unverifiable", false)
		}
		var permissions []struct {
			ID              string   `json:"id"`
			Type            string   `json:"type"`
			Role            string   `json:"role"`
			Deleted         bool     `json:"deleted"`
			AdditionalRoles []string `json:"additionalRoles"`
		}
		if json.Unmarshal(out.Items, &permissions) != nil {
			return docError(200, "complete_acl_unverifiable", false)
		}
		for _, p := range permissions {
			if seen[p.ID] || !safeID(p.ID) {
				return docError(200, "complete_acl_unverifiable", false)
			}
			if !validDrivePermissionType(p.Type) || !validDrivePermissionRole(p.Role) {
				return docError(200, "complete_acl_unverifiable", false)
			}
			for _, role := range p.AdditionalRoles {
				if !validDrivePermissionRole(role) {
					return docError(200, "complete_acl_unverifiable", false)
				}
			}
			if p.Deleted || len(p.AdditionalRoles) > 0 {
				return restrictionLostError(200, "restricted_sharing_unverified")
			}
			seen[p.ID] = true
			switch {
			case p.Type == "user" && p.Role == "owner" && p.ID == owner:
				hasOwner = true
			case p.Type == "group" && p.Role == "reader" && p.ID == group:
				hasGroup = true
			default:
				return restrictionLostError(200, "restricted_sharing_unverified")
			}
		}
		if out.Next == "" {
			if !hasGroup || !hasOwner {
				return restrictionLostError(200, "restricted_sharing_unverified")
			}
			return nil
		}
		token = out.Next
	}
	return docError(200, "incomplete_permissions", false)
}

func validDrivePermissionType(value string) bool {
	switch value {
	case "user", "group", "domain", "anyone":
		return true
	default:
		return false
	}
}

func validDrivePermissionRole(value string) bool {
	switch value {
	case "owner", "organizer", "fileOrganizer", "writer", "commenter", "reader":
		return true
	default:
		return false
	}
}
func (a *driveAdapter) CheckDocumentRelease(ctx context.Context, container, group string) error {
	if container != a.container || group != a.group {
		return shared.ErrConflict
	}
	f, err := a.file(ctx, container)
	if err != nil {
		return err
	}
	if f.MIME != folderMIME {
		return docError(200, "invalid_container", false)
	}
	return a.checkACL(ctx, container, group)
}
func splitDrivePage(page string) (string, string, error) {
	parts := strings.Split(page, "~")
	if len(parts) != 2 || !safeID(parts[0]) || !safeID(parts[1]) {
		return "", "", shared.ErrValidation
	}
	return parts[0], parts[1], nil
}
func driveRemote(folder, body, revision string) docpublish.RemotePage {
	return docpublish.RemotePage{ID: folder + "~" + body, Version: 1, Revision: revision, URL: "https://drive.google.com/drive/folders/" + folder}
}
func (a *driveAdapter) CreateDocumentShell(ctx context.Context, container, marker string) (docpublish.RemotePage, error) {
	if !validMarker(marker) {
		return docpublish.RemotePage{}, shared.ErrValidation
	}
	if err := a.CheckDocumentRelease(ctx, container, a.group); err != nil {
		return docpublish.RemotePage{}, err
	}
	var ids struct {
		IDs []string `json:"ids"`
	}
	if err := a.json(ctx, "GET", "/drive/v2/files/generateIds", url.Values{"maxResults": {"2"}, "space": {"drive"}}, nil, &ids, 200); err != nil {
		return docpublish.RemotePage{}, err
	}
	if len(ids.IDs) != 2 || !safeID(ids.IDs[0]) || !safeID(ids.IDs[1]) || ids.IDs[0] == ids.IDs[1] {
		return docpublish.RemotePage{}, docError(200, "invalid_generated_identity", false)
	}
	if err := a.CheckDocumentRelease(ctx, container, a.group); err != nil {
		return docpublish.RemotePage{}, err
	}
	var f driveFile
	body := map[string]any{"id": ids.IDs[0], "title": marker, "mimeType": folderMIME, "parents": []map[string]string{{"id": container}}, "properties": []map[string]string{{"key": "synapse-body", "value": ids.IDs[1], "visibility": "PRIVATE"}, {"key": "synapse-marker", "value": marker, "visibility": "PRIVATE"}}}
	if err := a.json(ctx, "POST", "/drive/v2/files", url.Values{"fields": {driveFields}}, body, &f, 200, 201); err != nil {
		return docpublish.RemotePage{}, err
	}
	if f.ID != ids.IDs[0] {
		return docpublish.RemotePage{}, docError(201, "invalid_shell_response", true)
	}
	return driveRemote(f.ID, ids.IDs[1], "new:"+ids.IDs[1]), nil
}
func (a *driveAdapter) RestrictDocument(ctx context.Context, page, group string) error {
	return a.VerifyDocumentRestriction(ctx, page, a.container, group)
}
func (a *driveAdapter) VerifyDocumentRestriction(ctx context.Context, page, container, group string) error {
	folder, body, err := splitDrivePage(page)
	if err != nil {
		return err
	}
	if container != a.container || group != a.group {
		return shared.ErrConflict
	}
	owner, err := a.identity(ctx)
	if err != nil {
		return err
	}
	parent, err := a.file(ctx, container)
	if err != nil {
		return err
	}
	if parent.MIME != folderMIME {
		return docError(200, "invalid_container", false)
	}
	if err = a.checkKnownFileACL(ctx, parent, owner, group); err != nil {
		return err
	}
	f, err := a.file(ctx, folder)
	if err != nil {
		return err
	}
	if err = f.shellIdentity(container, body); err != nil {
		return err
	}
	if err = a.checkKnownFileACL(ctx, f, owner, group); err != nil {
		return err
	}
	children, err := a.children(ctx, folder)
	if err != nil {
		return err
	}
	for _, child := range children {
		if child.MIME == folderMIME || child.property("synapse-folder") != folder {
			return docError(200, "unmanaged_child", false)
		}
		if err = a.checkKnownFileACL(ctx, child, owner, group); err != nil {
			return err
		}
	}
	return nil
}
func (a *driveAdapter) children(ctx context.Context, parent string) ([]driveFile, error) {
	return a.allChildren(ctx, parent, false)
}

func (a *driveAdapter) allChildren(ctx context.Context, parent string, includeTrashed bool) ([]driveFile, error) {
	if !safeID(parent) {
		return nil, shared.ErrValidation
	}
	query := "'" + parent + "' in parents"
	if !includeTrashed {
		query += " and trashed = false"
	}
	result := []driveFile{}
	token := ""
	seen := map[string]bool{}
	for page := 0; page < 20; page++ {
		var out struct {
			Items []driveFile `json:"items"`
			Next  string      `json:"nextPageToken"`
		}
		pageQuery := url.Values{"q": {query}, "maxResults": {"100"}, "fields": {"items(" + driveFields + "),nextPageToken"}}
		if token != "" {
			pageQuery.Set("pageToken", token)
		}
		if err := a.json(ctx, "GET", "/drive/v2/files", pageQuery, nil, &out, 200); err != nil {
			return nil, err
		}
		for _, f := range out.Items {
			if !safeID(f.ID) || seen[f.ID] || (!includeTrashed && f.Labels.Trashed) || len(f.Parents) != 1 || f.Parents[0].ID != parent {
				return nil, docError(200, "invalid_child", false)
			}
			seen[f.ID] = true
			result = append(result, f)
		}
		if out.Next == "" {
			return result, nil
		}
		if len(out.Next) > 2048 || out.Next == token {
			return nil, docError(200, "incomplete_children", false)
		}
		token = out.Next
	}
	return nil, docError(200, "incomplete_children", false)
}
func (a *driveAdapter) GetDocument(ctx context.Context, page string) (ports.DocumentRemoteState, error) {
	folder, body, err := splitDrivePage(page)
	if err != nil {
		return ports.DocumentRemoteState{}, err
	}
	f, err := a.file(ctx, folder)
	if err != nil {
		return ports.DocumentRemoteState{}, err
	}
	if f.MIME != folderMIME || len(f.Parents) != 1 || f.property("synapse-body") != body || !validMarker(f.property("synapse-marker")) {
		return ports.DocumentRemoteState{}, docError(200, "invalid_shell", false)
	}
	out := ports.DocumentRemoteState{RemotePage: driveRemote(folder, body, "new:"+body), Container: f.Parents[0].ID, Marker: f.property("synapse-marker"), Neutral: true}
	children, err := a.children(ctx, folder)
	if err != nil {
		return out, err
	}
	return a.documentState(ctx, folder, body, f, children)
}

func (a *driveAdapter) documentState(ctx context.Context, folder, body string, f driveFile, children []driveFile) (ports.DocumentRemoteState, error) {
	out := ports.DocumentRemoteState{RemotePage: driveRemote(folder, body, "new:"+body), Container: f.Parents[0].ID, Marker: f.property("synapse-marker"), Neutral: true}
	found := false
	for _, child := range children {
		if child.ID != body {
			continue
		}
		if found || child.property("synapse-folder") != folder || child.MIME != "text/html" || child.ETag == "" {
			return out, docError(200, "invalid_body", false)
		}
		found = true
		raw, err := a.readFileBytes(ctx, child)
		if err != nil {
			return out, err
		}
		title, storage, marker, err := decodeDriveHTML(raw)
		if err != nil {
			return out, err
		}
		if err = a.ValidateDocumentText(title + storage + string(raw)); err != nil {
			return out, err
		}
		out.RemotePage = driveRemote(folder, body, child.ETag)
		out.Title = title
		out.Storage = storage
		out.Marker = marker
		out.Neutral = false
	}
	return out, nil
}

// ReadRestrictedDocument obtains the state and its complete ACL proof from the
// same current metadata/children snapshot. It is a read-only optimisation for a
// caller's guard; every actual outbound operation still calls its own preflight.
func (a *driveAdapter) ReadRestrictedDocument(ctx context.Context, page, container, group string) (ports.DocumentRemoteState, error) {
	folder, body, err := splitDrivePage(page)
	if err != nil {
		return ports.DocumentRemoteState{}, err
	}
	if container != a.container || group != a.group {
		return ports.DocumentRemoteState{}, shared.ErrConflict
	}
	owner, err := a.identity(ctx)
	if err != nil {
		return ports.DocumentRemoteState{}, err
	}
	parent, err := a.file(ctx, container)
	if err != nil {
		return ports.DocumentRemoteState{}, err
	}
	if parent.MIME != folderMIME {
		return ports.DocumentRemoteState{}, docError(200, "invalid_container", false)
	}
	if err = a.checkKnownFileACL(ctx, parent, owner, group); err != nil {
		return ports.DocumentRemoteState{}, err
	}
	f, err := a.file(ctx, folder)
	if err != nil {
		return ports.DocumentRemoteState{}, err
	}
	if err = f.shellIdentity(container, body); err != nil {
		return ports.DocumentRemoteState{}, err
	}
	if err = a.checkKnownFileACL(ctx, f, owner, group); err != nil {
		return ports.DocumentRemoteState{}, err
	}
	children, err := a.children(ctx, folder)
	if err != nil {
		return ports.DocumentRemoteState{}, err
	}
	for _, child := range children {
		if child.MIME == folderMIME || child.property("synapse-folder") != folder {
			return ports.DocumentRemoteState{}, docError(200, "unmanaged_child", false)
		}
		if err = a.checkKnownFileACL(ctx, child, owner, group); err != nil {
			return ports.DocumentRemoteState{}, err
		}
	}
	return a.documentState(ctx, folder, body, f, children)
}
func (a *driveAdapter) FindDocumentMarker(ctx context.Context, container, marker string) ([]ports.DocumentRemoteState, error) {
	if container != a.container || !validMarker(marker) {
		return nil, shared.ErrValidation
	}
	children, err := a.children(ctx, container)
	if err != nil {
		return nil, err
	}
	matches := []ports.DocumentRemoteState{}
	for _, f := range children {
		if f.MIME != folderMIME || f.property("synapse-marker") != marker {
			continue
		}
		body := f.property("synapse-body")
		if !safeID(body) {
			return nil, docError(200, "invalid_shell", false)
		}
		remote, err := a.GetDocument(ctx, f.ID+"~"+body)
		if err != nil {
			return nil, err
		}
		matches = append(matches, remote)
	}
	return matches, nil
}
func (a *driveAdapter) upload(ctx context.Context, folder, id, name, mime string, data []byte, revision string) (driveFile, error) {
	var out driveFile
	var content bytes.Buffer
	writer := multipart.NewWriter(&content)
	header := textproto.MIMEHeader{"Content-Type": {"application/json; charset=UTF-8"}}
	part, _ := writer.CreatePart(header)
	meta := map[string]any{"title": name, "mimeType": mime, "properties": []map[string]string{{"key": "synapse-folder", "value": folder, "visibility": "PRIVATE"}}}
	method, path := "PUT", "/upload/drive/v2/files/"+id
	if revision == "" {
		method, path = "POST", "/upload/drive/v2/files"
		meta["parents"] = []map[string]string{{"id": folder}}
		if id != "" {
			meta["id"] = id
		}
	}
	if err := json.NewEncoder(part).Encode(meta); err != nil {
		return out, shared.ErrValidation
	}
	part, _ = writer.CreatePart(textproto.MIMEHeader{"Content-Type": {mime}})
	_, _ = part.Write(data)
	_ = writer.Close()
	headers := http.Header{"Content-Type": {"multipart/related; boundary=" + writer.Boundary()}}
	if revision != "" {
		headers.Set("If-Match", revision)
	}
	raw, _, err := a.request(ctx, method, path, url.Values{"uploadType": {"multipart"}, "fields": {driveFields}}, content.Bytes(), headers, 200, 201)
	if err != nil {
		return out, err
	}
	if json.Unmarshal(raw, &out) != nil || !safeID(out.ID) || (id != "" && out.ID != id) || out.ETag == "" || len(out.ETag) > 512 || strings.ContainsAny(out.ETag, "\r\n") || containsCredential(out.ETag, a.token) {
		return out, docError(200, "invalid_upload_response", true)
	}
	sum := md5.Sum(data) //nolint:gosec // Compare the vendor content checksum; this does not authenticate or authorize content.
	if out.MD5 != hex.EncodeToString(sum[:]) {
		return out, docError(200, "upload_digest_unverified", true)
	}
	return out, nil
}
func (a *driveAdapter) UploadDocumentAttachment(ctx context.Context, page string, file ports.DocumentImage) error {
	folder, body, err := splitDrivePage(page)
	if err != nil {
		return err
	}
	if len(file.Data) == 0 || len(file.Data) > 20<<20 || !validAttachmentName(file.Name) || (!strings.HasPrefix(file.MediaType, "image/") && file.MediaType != "application/pdf") {
		return shared.ErrValidation
	}
	if err = a.ValidateDocumentText(file.Name); err != nil {
		return err
	}
	children, err := a.children(ctx, folder)
	if err != nil {
		return err
	}
	for _, f := range children {
		if f.Name == file.Name {
			if f.ID == body || f.property("synapse-folder") != folder {
				return shared.ErrConflict
			}
			if f.MIME != file.MediaType {
				return shared.ErrConflict
			}
			if err = a.VerifyDocumentRestriction(ctx, page, a.container, a.group); err != nil {
				return err
			}
			existing, readErr := a.readFileBytes(ctx, f)
			if readErr != nil {
				return readErr
			}
			if !bytes.Equal(existing, file.Data) {
				return docError(409, "attachment_name_conflict", false)
			}
			return nil
		}
	}
	if err = a.VerifyDocumentRestriction(ctx, page, a.container, a.group); err != nil {
		return err
	}
	_, err = a.upload(ctx, folder, "", file.Name, file.MediaType, file.Data, "")
	return err
}
func (*driveAdapter) WriteDocument(context.Context, string, int, string, string, string) (docpublish.RemotePage, error) {
	return docpublish.RemotePage{}, docError(0, "opaque_revision_required", false)
}
func (a *driveAdapter) WriteDocumentRevision(ctx context.Context, expected docpublish.RemotePage, title, storage, marker string) (docpublish.RemotePage, error) {
	folder, body, err := splitDrivePage(expected.ID)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	current, err := a.GetDocument(ctx, expected.ID)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	if current.Revision != expected.Revision {
		return docpublish.RemotePage{}, shared.ErrConflict
	}
	children, err := a.children(ctx, folder)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	fileIDs := map[string]string{}
	for _, child := range children {
		if child.ID == body {
			continue
		}
		if child.property("synapse-folder") != folder || fileIDs[child.Name] != "" {
			return docpublish.RemotePage{}, shared.ErrConflict
		}
		fileIDs[child.Name] = child.ID
	}
	rendered, err := encodeDocumentHTML(title, storage, marker, fileIDs)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	if err = a.ValidateDocumentText(title + storage); err != nil {
		return docpublish.RemotePage{}, err
	}
	etag := expected.Revision
	if current.Neutral {
		if etag != "new:"+body {
			return docpublish.RemotePage{}, shared.ErrConflict
		}
		etag = ""
	}
	if err = a.VerifyDocumentRestriction(ctx, expected.ID, a.container, a.group); err != nil {
		return docpublish.RemotePage{}, err
	}
	f, err := a.upload(ctx, folder, body, "report.html", "text/html", rendered, etag)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	return driveRemote(folder, body, f.ETag), nil
}
func (a *driveAdapter) PurgeDocument(ctx context.Context, page string, guard func(context.Context) error) error {
	folder, body, err := splitDrivePage(page)
	if err != nil || guard == nil {
		return shared.ErrValidation
	}
	owner, err := a.identity(ctx)
	if err != nil {
		return err
	}
	shell, err := a.file(ctx, folder)
	if err != nil {
		return err
	}
	if shell.MIME != folderMIME || len(shell.Parents) != 1 || shell.Parents[0].ID != a.container || shell.property("synapse-body") != body || !validMarker(shell.property("synapse-marker")) || len(shell.Owners) != 1 || shell.Owners[0].ID != owner {
		return restrictionLostError(200, "remote_identity_changed")
	}
	// Include trashed publication artifacts: trash is retained provider history,
	// not evidence of permanent removal. A broader ACL must not block unpublish.
	children, err := a.allChildren(ctx, folder, true)
	if err != nil {
		return err
	}
	for _, f := range children {
		if f.property("synapse-folder") != folder || f.MIME == folderMIME || len(f.Owners) != 1 || f.Owners[0].ID != owner {
			return docError(200, "unmanaged_child", false)
		}
	}
	deleteDispatched := false
	for _, f := range children {
		if err = guard(ctx); err != nil {
			if deleteDispatched {
				return partialEffectAmbiguity(err, "purge_incomplete")
			}
			return err
		}
		deleteDispatched = true
		if _, _, err = a.request(ctx, "DELETE", "/drive/v2/files/"+f.ID, nil, nil, nil, 204); err != nil {
			return partialEffectAmbiguity(err, "purge_incomplete")
		}
	}
	if err = guard(ctx); err != nil {
		if deleteDispatched {
			return partialEffectAmbiguity(err, "purge_incomplete")
		}
		return err
	}
	_, _, err = a.request(ctx, "DELETE", "/drive/v2/files/"+folder, nil, nil, nil, 204)
	if err != nil {
		return partialEffectAmbiguity(err, "purge_incomplete")
	}
	return nil
}

func validMarker(marker string) bool {
	return strings.HasPrefix(marker, "synapse-intent-") && safeID(marker) && len(marker) <= 124
}

func encodeDriveHTML(title, storage, marker string) ([]byte, error) {
	return encodeDocumentHTML(title, storage, marker, nil)
}
func encodeDocumentHTML(title, storage, marker string, files map[string]string) ([]byte, error) {
	return encodeCanonicalDocumentHTML(title, storage, marker, files, driveAttachmentHTML)
}

func driveAttachmentHTML(filename, id string, image bool) string {
	if image {
		return "<img alt=\"" + html.EscapeString(filename) + "\" src=\"https://drive.google.com/uc?export=view&amp;id=" + id + "\">"
	}
	return "<a href=\"https://drive.google.com/file/d/" + id + "/view\" rel=\"noreferrer\">"
}

func decodeDriveHTML(data []byte) (string, string, string, error) {
	source, err := decodeCanonicalDocumentHTML(data, encodeDocumentHTML)
	if err != nil {
		return "", "", "", err
	}
	return source.Title, source.Storage, source.Marker, nil
}

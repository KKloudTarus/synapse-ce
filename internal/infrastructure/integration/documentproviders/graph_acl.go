package documentproviders

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SharePoint's built-in role type and permission masks are stable even though a
// site's numeric role-definition IDs are not. A custom role with a friendly
// name such as "Read" is deliberately not accepted.
const (
	sharePointReadRoleType = 2
	sharePointFullRoleType = 5
	sharePointReadHigh     = "176"
	sharePointReadLow      = "138612833"
	sharePointFullHigh     = "2147483647"
	sharePointFullLow      = "4294967295"
)

func validSPPath(v string) bool {
	return strings.HasPrefix(v, "/") && v != "/" && path.Clean(v) == v && len(v) <= 1024 && !strings.ContainsAny(v, "\\?#") && !containsSpaceOrControl(v)
}

// SharePoint returns a file reference for every managed attachment. Attachment
// names may contain spaces, while the configured publication root may not.
// Keep the URL-delimiter and control checks common without rejecting a valid
// server-observed child solely because its display name has a space.
func validSPFileRef(v string) bool {
	if !strings.HasPrefix(v, "/") || v == "/" || path.Clean(v) != v || len(v) > 1024 || strings.ContainsAny(v, "\\?#") {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func spQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }

func (a *graphAdapter) spRequest(ctx context.Context, method, resource string, headers http.Header, body []byte, max int64, want ...int) ([]byte, http.Header, error) {
	parsed, err := parseSharePointResource(resource)
	if err != nil {
		return nil, nil, docError(0, "invalid_request", false)
	}
	u := *a.site
	u.Path = strings.TrimSuffix(a.site.Path, "/") + parsed.Path
	u.RawPath = ""
	u.RawQuery = parsed.RawQuery
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, docError(0, "invalid_request", false)
	}
	req.Header.Set("Authorization", "Bearer "+a.sharePointToken)
	req.Header.Set("Accept", "application/json;odata=verbose")
	for k, v := range headers {
		req.Header[k] = append([]string(nil), v...)
	}
	return readResponse(a.client, req, max, want...)
}

func containsSpaceOrControl(value string) bool {
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func parseSharePointResource(resource string) (*url.URL, error) {
	// OData string literals can contain a space in an already validated file
	// name. Outside that literal form, whitespace and controls are URI syntax
	// ambiguities and must not reach the HTTP client.
	inLiteral := false
	for _, r := range resource {
		switch r {
		case '\'':
			inLiteral = !inLiteral
		case '#', '\\':
			return nil, shared.ErrValidation
		default:
			if unicode.IsControl(r) || (unicode.IsSpace(r) && !inLiteral) {
				return nil, shared.ErrValidation
			}
		}
	}
	if inLiteral {
		return nil, shared.ErrValidation
	}
	resourcePath, rawQuery, hasQuery := strings.Cut(resource, "?")
	if !strings.HasPrefix(resourcePath, "/_api/") || (hasQuery && strings.Contains(rawQuery, "?")) {
		return nil, shared.ErrValidation
	}
	if _, err := url.PathUnescape(resourcePath); err != nil {
		return nil, shared.ErrValidation
	}
	if _, err := url.QueryUnescape(rawQuery); err != nil {
		return nil, shared.ErrValidation
	}
	return &url.URL{Path: resourcePath, RawQuery: rawQuery}, nil
}

func (a *graphAdapter) sp(ctx context.Context, method, resource string, headers http.Header, body []byte, out any, want ...int) (http.Header, error) {
	data, responseHeaders, err := a.spRequest(ctx, method, resource, headers, body, 4<<20, want...)
	if err != nil {
		return nil, err
	}
	if out != nil && (strings.Contains(string(data), a.sharePointToken) || json.Unmarshal(data, out) != nil) {
		return nil, docError(http.StatusOK, "unsafe_provider_response", false)
	}
	return responseHeaders, nil
}

func (a *graphAdapter) spBytes(ctx context.Context, method, resource string, headers http.Header, body []byte, want ...int) ([]byte, http.Header, error) {
	return a.spRequest(ctx, method, resource, headers, body, 24<<20, want...)
}

type graphSharePointIDs struct {
	SiteID           string `json:"siteId"`
	ListID           string `json:"listId"`
	ListItemUniqueID string `json:"listItemUniqueId"`
	SiteURL          string `json:"siteUrl"`
}

type sharePointListItem struct {
	ID       int    `json:"Id"`
	UniqueID string `json:"UniqueId"`
	FileRef  string `json:"FileRef"`
	Unique   bool   `json:"HasUniqueRoleAssignments"`
	Parent   struct {
		ID string `json:"Id"`
	} `json:"ParentList"`
}

func normalizedGUID(v string) string { return strings.ToLower(strings.Trim(v, "{}")) }

func (a *graphAdapter) spListItem(ctx context.Context, fileRef string, folder bool) (sharePointListItem, error) {
	var out struct {
		D sharePointListItem `json:"d"`
	}
	resource := "/_api/web/GetFileByServerRelativeUrl(" + spQuote(fileRef) + ")/ListItemAllFields"
	if folder {
		resource = "/_api/web/GetFolderByServerRelativeUrl(" + spQuote(fileRef) + ")/ListItemAllFields"
	}
	resource += "?$select=Id,UniqueId,FileRef,HasUniqueRoleAssignments,ParentList/Id&$expand=ParentList"
	if _, err := a.sp(ctx, http.MethodGet, resource, nil, nil, &out, http.StatusOK); err != nil {
		return sharePointListItem{}, err
	}
	if out.D.ID <= 0 || normalizedGUID(out.D.UniqueID) == "" || !validSPFileRef(out.D.FileRef) || normalizedGUID(out.D.Parent.ID) == "" {
		return sharePointListItem{}, docError(http.StatusOK, "invalid_sharepoint_identity", false)
	}
	return out.D, nil
}

func (a *graphAdapter) spFileETag(ctx context.Context, fileRef string) (string, error) {
	var out struct {
		D struct {
			ETag string `json:"ETag"`
		} `json:"d"`
	}
	resource := "/_api/web/GetFileByServerRelativeUrl(" + spQuote(fileRef) + ")?$select=ETag"
	if _, err := a.sp(ctx, http.MethodGet, resource, nil, nil, &out, http.StatusOK); err != nil {
		return "", err
	}
	if out.D.ETag == "" || len(out.D.ETag) > 512 || strings.ContainsAny(out.D.ETag, "\r\n") || containsCredential(out.D.ETag, a.token) || containsCredential(out.D.ETag, a.sharePointToken) {
		return "", docError(http.StatusOK, "invalid_revision", false)
	}
	return out.D.ETag, nil
}

func (a *graphAdapter) spCurrentUser(ctx context.Context) error {
	var out struct {
		D struct {
			ID            int `json:"Id"`
			PrincipalType int `json:"PrincipalType"`
		} `json:"d"`
	}
	if _, err := a.sp(ctx, http.MethodGet, "/_api/web/currentuser?$select=Id,PrincipalType", nil, nil, &out, http.StatusOK); err != nil {
		return err
	}
	if out.D.ID <= 0 || out.D.PrincipalType != 1 || strconv.Itoa(out.D.ID) != a.custodian {
		return docError(http.StatusOK, "custodian_identity_unverified", false)
	}
	return nil
}

func sameSiteURL(config *url.URL, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return strings.EqualFold(u.Hostname(), config.Hostname()) && strings.TrimSuffix(u.EscapedPath(), "/") == strings.TrimSuffix(config.EscapedPath(), "/")
}

func presentFacet(v json.RawMessage) bool {
	return len(v) > 0 && string(v) != "null" && json.Valid(v)
}

func (a *graphAdapter) checkDestinationIdentity(ctx context.Context) error {
	var drive struct {
		ID            string             `json:"id"`
		DriveType     string             `json:"driveType"`
		SharePointIDs graphSharePointIDs `json:"sharepointIds"`
	}
	if err := a.get(ctx, "/drives/"+a.drive, url.Values{"$select": {"id,driveType,sharepointIds"}}, &drive); err != nil {
		return err
	}
	if drive.ID != a.drive || (a.provider == SharePoint && drive.DriveType != "documentLibrary") || (a.provider == OneDrive && drive.DriveType != "business") || normalizedGUID(drive.SharePointIDs.SiteID) == "" || normalizedGUID(drive.SharePointIDs.ListID) == "" || !sameSiteURL(a.site, drive.SharePointIDs.SiteURL) {
		return docError(http.StatusOK, "invalid_drive", false)
	}
	containerItem, err := a.graphItem(ctx, a.container)
	if err != nil {
		return err
	}
	if !presentFacet(containerItem.Folder) || containerItem.Parent.DriveID != a.drive || normalizedGUID(containerItem.SharePointIDs.SiteID) != normalizedGUID(drive.SharePointIDs.SiteID) || normalizedGUID(containerItem.SharePointIDs.ListID) != normalizedGUID(drive.SharePointIDs.ListID) || normalizedGUID(containerItem.SharePointIDs.ListItemUniqueID) == "" {
		return docError(http.StatusOK, "invalid_container", false)
	}
	spFolder, err := a.spListItem(ctx, a.folderPath, true)
	if err != nil {
		return err
	}
	if spFolder.FileRef != a.folderPath || normalizedGUID(spFolder.Parent.ID) != normalizedGUID(drive.SharePointIDs.ListID) || normalizedGUID(spFolder.UniqueID) != normalizedGUID(containerItem.SharePointIDs.ListItemUniqueID) || !spFolder.Unique {
		return docError(http.StatusOK, "graph_sharepoint_binding_unverified", false)
	}
	return nil
}

func (a *graphAdapter) CheckDocumentRelease(ctx context.Context, container, group string) error {
	if container != a.container || group != a.group {
		return shared.ErrConflict
	}
	if err := a.checkDestinationIdentity(ctx); err != nil {
		return err
	}
	if err := a.rejectPublicGraphPermissions(ctx, a.container); err != nil {
		return err
	}
	if err := a.spCurrentUser(ctx); err != nil {
		return err
	}
	return a.assertExactACL(ctx, a.folderPath, true)
}

type sharePointRoleAssignment struct {
	Member struct {
		ID            int `json:"Id"`
		PrincipalType int `json:"PrincipalType"`
	} `json:"Member"`
	Roles struct {
		Results []struct {
			RoleType int `json:"RoleTypeKind"`
			Base     struct {
				High string `json:"High"`
				Low  string `json:"Low"`
			} `json:"BasePermissions"`
		} `json:"results"`
		Next string `json:"__next"`
	} `json:"RoleDefinitionBindings"`
}

func roleIs(role struct {
	RoleType int `json:"RoleTypeKind"`
	Base     struct {
		High string `json:"High"`
		Low  string `json:"Low"`
	} `json:"BasePermissions"`
}, typ int, high, low string) bool {
	return role.RoleType == typ && role.Base.High == high && role.Base.Low == low
}

func validSharePointPrincipalType(value int) bool {
	switch value {
	case 1, 2, 4, 8:
		return true
	default:
		return false
	}
}

func validSharePointRole(role struct {
	RoleType int `json:"RoleTypeKind"`
	Base     struct {
		High string `json:"High"`
		Low  string `json:"Low"`
	} `json:"BasePermissions"`
}) bool {
	if role.RoleType <= 0 || role.Base.High == "" || role.Base.Low == "" {
		return false
	}
	_, highErr := strconv.ParseUint(role.Base.High, 10, 64)
	_, lowErr := strconv.ParseUint(role.Base.Low, 10, 64)
	return highErr == nil && lowErr == nil
}

// assertExactACL accepts precisely the configured direct read group and the
// currently authenticated full-control custodian. It deliberately rejects a
// partial page, duplicate grant, custom role, and every extra principal.
func (a *graphAdapter) assertExactACL(ctx context.Context, fileRef string, folder bool) error {
	base := "/_api/web/GetFileByServerRelativeUrl(" + spQuote(fileRef) + ")/ListItemAllFields"
	if folder {
		base = "/_api/web/GetFolderByServerRelativeUrl(" + spQuote(fileRef) + ")/ListItemAllFields"
	}
	var payload struct {
		D json.RawMessage `json:"d"`
	}
	resource := base + "/RoleAssignments?$select=Member/Id,Member/PrincipalType,RoleDefinitionBindings/RoleTypeKind,RoleDefinitionBindings/BasePermissions&$expand=Member,RoleDefinitionBindings"
	if _, err := a.sp(ctx, http.MethodGet, resource, nil, nil, &payload, http.StatusOK); err != nil {
		return err
	}
	if !presentFacet(payload.D) {
		return docError(http.StatusOK, "complete_acl_unverifiable", false)
	}
	var roles struct {
		Results json.RawMessage `json:"results"`
		Next    string          `json:"__next"`
	}
	if json.Unmarshal(payload.D, &roles) != nil || !presentFacet(roles.Results) {
		return docError(http.StatusOK, "complete_acl_unverifiable", false)
	}
	var assignments []sharePointRoleAssignment
	if json.Unmarshal(roles.Results, &assignments) != nil {
		return docError(http.StatusOK, "complete_acl_unverifiable", false)
	}
	if roles.Next != "" {
		return docError(http.StatusOK, "incomplete_permissions", false)
	}
	// Establish complete structural proof before interpreting the grant set.
	// An empty or additional valid binding contradicts the exact-role policy;
	// an omitted, null, malformed or paginated binding proves no such change.
	for _, assignment := range assignments {
		if assignment.Member.ID <= 0 || !validSharePointPrincipalType(assignment.Member.PrincipalType) || assignment.Roles.Results == nil || assignment.Roles.Next != "" {
			return docError(http.StatusOK, "complete_acl_unverifiable", false)
		}
		for _, role := range assignment.Roles.Results {
			if !validSharePointRole(role) {
				return docError(http.StatusOK, "complete_acl_unverifiable", false)
			}
		}
	}
	if len(assignments) != 2 {
		return restrictionLostError(http.StatusOK, "restricted_sharing_unverified")
	}
	seenGroup, seenCustodian := false, false
	for _, assignment := range assignments {
		if len(assignment.Roles.Results) != 1 {
			return restrictionLostError(http.StatusOK, "restricted_sharing_unverified")
		}
		id := strconv.Itoa(assignment.Member.ID)
		switch {
		case id == a.group && !seenGroup && (assignment.Member.PrincipalType == 4 || assignment.Member.PrincipalType == 8) && roleIs(assignment.Roles.Results[0], sharePointReadRoleType, sharePointReadHigh, sharePointReadLow):
			seenGroup = true
		case id == a.custodian && !seenCustodian && assignment.Member.PrincipalType == 1 && roleIs(assignment.Roles.Results[0], sharePointFullRoleType, sharePointFullHigh, sharePointFullLow):
			seenCustodian = true
		default:
			return restrictionLostError(http.StatusOK, "restricted_sharing_unverified")
		}
	}
	if !seenGroup || !seenCustodian {
		return restrictionLostError(http.StatusOK, "restricted_sharing_unverified")
	}
	return nil
}

func (a *graphAdapter) verifyChildACL(ctx context.Context, item graphItem, fileRef string, folder bool) error {
	spItem, err := a.childBinding(ctx, item, fileRef, folder)
	if err != nil {
		return err
	}
	if err := a.rejectPublicGraphPermissions(ctx, item.ID); err != nil {
		return err
	}
	if spItem.Unique {
		return a.assertExactACL(ctx, fileRef, folder)
	}
	// A child that inherits the already-proven unique publication folder is
	// acceptable. Its Graph parent is checked by the caller before this point.
	return nil
}

func (a *graphAdapter) verifyChildBinding(ctx context.Context, item graphItem, fileRef string, folder bool) error {
	_, err := a.childBinding(ctx, item, fileRef, folder)
	return err
}

// childBinding returns the same checked ListItem used by both identity and ACL
// validation. Reusing it avoids a second mutable SharePoint metadata read in
// one proof operation; it is never retained across operations or writes.
func (a *graphAdapter) childBinding(ctx context.Context, item graphItem, fileRef string, folder bool) (sharePointListItem, error) {
	spItem, err := a.spListItem(ctx, fileRef, folder)
	if err != nil {
		return sharePointListItem{}, err
	}
	if spItem.FileRef != fileRef || normalizedGUID(spItem.UniqueID) != normalizedGUID(item.SharePointIDs.ListItemUniqueID) || normalizedGUID(spItem.Parent.ID) == "" || normalizedGUID(spItem.Parent.ID) != normalizedGUID(item.SharePointIDs.ListID) {
		return sharePointListItem{}, docError(http.StatusOK, "graph_sharepoint_binding_unverified", false)
	}
	return spItem, nil
}

func (a *graphAdapter) rejectPublicGraphPermissions(ctx context.Context, id string) error {
	var out struct {
		Value []struct {
			Link json.RawMessage `json:"link"`
		} `json:"value"`
		Next string `json:"@odata.nextLink"`
	}
	if err := a.get(ctx, "/drives/"+a.drive+"/items/"+id+"/permissions", url.Values{"$select": {"id,link"}}, &out); err != nil {
		return err
	}
	if out.Next != "" {
		return docError(http.StatusOK, "incomplete_permissions", false)
	}
	for _, permission := range out.Value {
		if len(permission.Link) == 0 || string(permission.Link) == "null" {
			continue
		}
		var link struct {
			Scope string `json:"scope"`
		}
		if json.Unmarshal(permission.Link, &link) != nil || link.Scope == "" {
			return docError(http.StatusOK, "invalid_permission", false)
		}
		// The restricted profile does not use sharing links. Explicitly naming
		// public scopes keeps the reason stable while remaining fail-closed for
		// an unrecognised link scope.
		if link.Scope == "anonymous" || link.Scope == "organization" || link.Scope != "" {
			return restrictionLostError(http.StatusOK, "restricted_sharing_unverified")
		}
	}
	return nil
}

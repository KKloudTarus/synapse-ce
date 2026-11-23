package documentproviders

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/integration/selfhostedhttp"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// S3 publishes a governed report into a restricted bucket prefix. The bucket
// policy is the only access authority this profile accepts: object ACLs are not
// readable on every S3-compatible implementation, so a destination must keep
// ACLs disabled and express its reader as one policy statement.
const S3 integration.Provider = "s3-compatible"

const (
	s3ShellName          = ".synapse-shell"
	s3BodyName           = "report.html"
	s3MarkerMeta         = "Synapse-Marker"
	s3MaxObjects         = 64
	s3MaxHistoryVersions = 256
	s3WriteHistoryLimit  = s3MaxHistoryVersions - s3MaxObjects
	s3MaxBodyBytes       = 8 << 20
	s3MaxAttachment      = 20 << 20
)

var s3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var s3PrefixPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_\-/.]{0,255}$`)
var s3PrincipalPattern = regexp.MustCompile(`^[A-Za-z0-9:_\-/.@+=,]{1,512}$`)
var s3RegionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)

// s3CredentialPattern admits printable ASCII without whitespace. A SigV4 key or
// an STS token never contains a space, and one that does is a paste that would
// otherwise be signed and rejected by the destination at every call.
var s3CredentialPattern = regexp.MustCompile(`^[\x21-\x7e]+$`)

func validateS3Credential(value string, minimum int) error {
	if err := validateToken(value); err != nil {
		return err
	}
	if len(value) < minimum || len(value) > 4096 || !s3CredentialPattern.MatchString(value) {
		return shared.ErrValidation
	}
	return nil
}

var s3Descriptor = integration.ProviderDescriptor{
	Provider: S3, Name: "S3-compatible bucket", Description: "Governed HTML reports in a restricted prefix of an S3-compatible bucket. Versioning and an exact single-reader bucket policy are proved before every upload; a public grant refuses the release.",
	Capabilities: []integration.Capability{integration.CapabilityTestConnection, integration.CapabilityDocuments},
	ConfigFields: []integration.FieldDescriptor{
		{Name: "space", Label: "Bucket", Kind: integration.FieldText, Required: true},
		{Name: "prefix", Label: "Publication key prefix", Kind: integration.FieldText, Required: true},
		{Name: "read_group", Label: "Exact reader principal", Kind: integration.FieldText, Required: true},
		{Name: "region", Label: "Region", Kind: integration.FieldText, Required: true},
		{Name: "read_endpoint", Label: "Authenticated reader base URL for this bucket", Kind: integration.FieldText, Required: true},
		{Name: "data_class", Label: "Data classification (detail)", Kind: integration.FieldText, Required: true},
	},
	SecretFields: []integration.FieldDescriptor{
		{Name: "access_key_id", Label: "Access key ID", Kind: integration.FieldPassword, Required: true},
		{Name: "secret_access_key", Label: "Secret access key", Kind: integration.FieldPassword, Required: true},
		{Name: "session_token", Label: "Session token", Kind: integration.FieldPassword},
	},
}

type s3Adapter struct {
	client                              *minio.Client
	transport                           *http.Transport
	bucket, prefix, principal, endpoint string
	readEndpoint                        string
	accessKey, secretKey, sessionToken  string
}

var _ ports.DocumentProvider = (*s3Adapter)(nil)
var _ ports.DocumentRevisionWriter = (*s3Adapter)(nil)
var _ ports.DocumentReleasePreflighter = (*s3Adapter)(nil)
var _ ports.DocumentRestrictedReader = (*s3Adapter)(nil)
var _ integration.ConnectionTester = (*s3Adapter)(nil)

func newS3(item integration.Integration, c integration.CredentialBundle, rules selfhosted.Rules) (integration.Adapter, error) {
	if item.Provider != S3 {
		return nil, shared.ErrValidation
	}
	endpoint, err := url.Parse(item.Endpoint)
	if err != nil || !strings.EqualFold(endpoint.Scheme, "https") || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || strings.Trim(endpoint.Path, "/") != "" {
		return nil, fmt.Errorf("%w: S3 endpoint must be an https origin without path, query or credentials", shared.ErrValidation)
	}
	if err := s3Descriptor.ValidateSecrets(map[string]string(c)); err != nil {
		return nil, err
	}
	if err := validateS3Credential(c["access_key_id"], 3); err != nil {
		return nil, err
	}
	if err := validateS3Credential(c["secret_access_key"], 8); err != nil {
		return nil, err
	}
	if c["session_token"] != "" {
		if err := validateS3Credential(c["session_token"], 16); err != nil {
			return nil, err
		}
	}
	var cfg struct {
		Space        string `json:"space"`
		Prefix       string `json:"prefix"`
		Group        string `json:"read_group"`
		Region       string `json:"region"`
		Class        string `json:"data_class"`
		ReadEndpoint string `json:"read_endpoint"`
	}
	if json.Unmarshal(item.Config, &cfg) != nil {
		return nil, shared.ErrValidation
	}
	prefix := strings.Trim(strings.TrimSpace(cfg.Prefix), "/")
	if !s3BucketPattern.MatchString(cfg.Space) || !s3PrefixPattern.MatchString(prefix) || strings.Contains(prefix, "//") ||
		strings.Contains(prefix, "..") || !s3PrincipalPattern.MatchString(cfg.Group) || strings.Contains(cfg.Group, "*") ||
		!s3RegionPattern.MatchString(cfg.Region) || cfg.Class != "detail" {
		return nil, shared.ErrValidation
	}
	readEndpoint, err := docpublish.CanonicalURL(cfg.ReadEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: an authenticated S3 reader base URL is required", shared.ErrValidation)
	}
	reader, _ := url.Parse(readEndpoint)
	if reader.RawPath != "" || strings.Contains(reader.Path, "\\") {
		return nil, shared.ErrValidation
	}
	for _, segment := range strings.Split(reader.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, shared.ErrValidation
		}
	}
	// Check the longest supported page identity before any remote mutation can
	// return a URL that the publication model cannot store.
	if _, err := docpublish.CanonicalURL(strings.TrimRight(readEndpoint, "/") + "/" + prefix + "/" + strings.Repeat("a", 124) + "/" + s3BodyName); err != nil {
		return nil, fmt.Errorf("%w: S3 reader base URL is too long", shared.ErrValidation)
	}
	policy, err := s3Policy(item, endpoint, rules)
	if err != nil {
		return nil, err
	}
	transport := s3Transport(policy)
	client, err := minio.New(endpoint.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(c["access_key_id"], c["secret_access_key"], c["session_token"]),
		Secure:       true,
		Region:       cfg.Region,
		Transport:    transport,
		BucketLookup: minio.BucketLookupPath,
		MaxRetries:   1,
	})
	if err != nil {
		return nil, shared.ErrValidation
	}
	client.SetS3EnableDualstack(false)
	return &s3Adapter{
		readEndpoint: strings.TrimRight(readEndpoint, "/"),
		client:       client, transport: transport, bucket: cfg.Space, prefix: prefix, principal: cfg.Group,
		endpoint: endpoint.Scheme + "://" + endpoint.Host, accessKey: c["access_key_id"],
		secretKey: c["secret_access_key"], sessionToken: c["session_token"],
	}, nil
}

// s3Policy pins SaaS endpoints to their own host and holds a self-hosted
// endpoint to the deployment's reviewed allowlist, exactly as the self-hosted
// forge and Confluence profiles do.
func s3Policy(item integration.Integration, endpoint *url.URL, rules selfhosted.Rules) (safehttp.Policy, error) {
	host := strings.ToLower(endpoint.Hostname())
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	if strings.HasSuffix(host, ".amazonaws.com") {
		if port != "443" {
			return safehttp.Policy{}, shared.ErrValidation
		}
		return safehttp.Policy{AllowHost: func(h, p string) bool { return p == "443" && strings.EqualFold(h, host) }}, nil
	}
	if err := rules.CheckListedEndpoint(item.Endpoint, item.AllowPrivateNetwork); err != nil {
		return safehttp.Policy{}, fmt.Errorf("%w: S3 endpoint is not an allowed self-hosted destination", shared.ErrValidation)
	}
	listed := selfhostedhttp.Policy(rules, item.AllowPrivateNetwork)
	inner := listed.AllowHost
	listed.AllowHost = func(h, p string) bool {
		if !strings.EqualFold(h, host) || p != port {
			return false
		}
		return inner == nil || inner(h, p)
	}
	return listed, nil
}

func s3Transport(policy safehttp.Policy) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		MaxConnsPerHost:       8,
		DialContext:           safehttp.NewDialer(policy, 0).DialContext,
	}
}

func (*s3Adapter) Descriptor() integration.ProviderDescriptor { return s3Descriptor }

func (a *s3Adapter) Close() {
	if a.transport != nil {
		a.transport.CloseIdleConnections()
	}
	a.accessKey, a.secretKey, a.sessionToken = "", "", ""
}

// ValidateDocumentText scans for the signing secret and the temporary token. The
// access key ID is an identifier rather than a secret, and a deployment is free
// to use a short word for it, so scanning for it refuses legitimate report text.
func (a *s3Adapter) ValidateDocumentText(value string) error {
	for _, secret := range []string{a.secretKey, a.sessionToken} {
		if containsCredential(value, secret) {
			return docError(0, "credential_in_payload", false)
		}
	}
	return nil
}

// s3Err keeps provider responses out of the error while preserving the
// distinction the release workflow depends on: a definite refusal, a throttle
// with its deferral, and an ambiguous outcome after a dispatched write.
func s3Err(err error, write bool) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	response := minio.ToErrorResponse(err)
	switch response.StatusCode {
	case http.StatusNotFound:
		return docError(http.StatusNotFound, "not_found", false)
	case http.StatusUnauthorized, http.StatusForbidden:
		return docError(response.StatusCode, "permission_denied", false)
	case http.StatusPreconditionFailed, http.StatusConflict:
		return docError(response.StatusCode, "revision_conflict", false)
	case http.StatusTooManyRequests:
		// minio.ErrorResponse drops response headers, so the throttle carries no
		// Retry-After and the release schedule applies its own deferral.
		return &ports.DocumentProviderError{Status: response.StatusCode, Code: "rate_limited"}
	}
	if response.StatusCode >= 500 {
		return docError(response.StatusCode, "provider_unavailable", true)
	}
	if response.StatusCode == 0 {
		return docError(0, "network", write)
	}
	return docError(response.StatusCode, "request_rejected", write)
}

func (a *s3Adapter) key(marker, name string) string {
	return a.publicationPrefix(marker) + name
}

func (a *s3Adapter) publicationPrefix(marker string) string {
	return a.prefix + "/" + marker + "/"
}

func (a *s3Adapter) browserURL(marker string) string {
	return a.readEndpoint + "/" + a.publicationPrefix(marker) + s3BodyName
}

func s3Remote(marker, browser, revision string) docpublish.RemotePage {
	return docpublish.RemotePage{ID: marker, Version: 1, Revision: revision, URL: browser}
}

func (a *s3Adapter) TestConnection(ctx context.Context) error {
	return a.CheckDocumentRelease(ctx, a.bucket, a.principal)
}

// CheckDocumentRelease proves the destination before a neutral shell exists:
// the configured bucket, versioning for exact historical reads and removal,
// and a policy that grants read to exactly the configured principal.
func (a *s3Adapter) CheckDocumentRelease(ctx context.Context, container, group string) error {
	if container != a.bucket || group != a.principal {
		return shared.ErrConflict
	}
	versioning, err := a.client.GetBucketVersioning(ctx, a.bucket)
	if err != nil {
		return s3Err(err, false)
	}
	if !strings.EqualFold(versioning.Status, "Enabled") {
		return docError(http.StatusOK, "versioning_required", false)
	}
	return a.checkBucketPolicy(ctx)
}

// checkBucketPolicy is the access proof. A policy that cannot be read or parsed
// leaves the reader unproven and refuses without claiming a breach; an observed
// public or foreign grant over the publication prefix is a breach.
func (a *s3Adapter) checkBucketPolicy(ctx context.Context) error {
	raw, err := a.client.GetBucketPolicy(ctx, a.bucket)
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchBucketPolicy" {
			return docError(http.StatusOK, "reader_policy_unverifiable", false)
		}
		return s3Err(err, false)
	}
	if strings.TrimSpace(raw) == "" {
		return docError(http.StatusOK, "reader_policy_unverifiable", false)
	}
	return verifyS3ReaderPolicy(raw, a.bucket, a.prefix, a.principal)
}

type s3Object struct {
	key, versionID, etag, marker string
	size                         int64
	deleteMarker, latest         bool
}

// s3Marker reads the publication stamp. A listing spells it as the raw
// x-amz-meta header, a stat response as the bare name, and neither casing is
// guaranteed, so both forms are matched case-insensitively.
func s3Marker(meta map[string]string) string {
	for key, value := range meta {
		if strings.EqualFold(key, "X-Amz-Meta-"+s3MarkerMeta) || strings.EqualFold(key, s3MarkerMeta) {
			return value
		}
	}
	return ""
}

// publicationObjects reads only live keys. History has its own bounded snapshot
// for purge; it does not consume the current-object budget.
func (a *s3Adapter) publicationObjects(ctx context.Context, marker string) (map[string]s3Object, error) {
	prefix := a.publicationPrefix(marker)
	out := map[string]s3Object{}
	count := 0
	for item := range a.client.ListObjectsIter(ctx, a.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true, WithMetadata: true}) {
		if item.Err != nil {
			return nil, s3Err(item.Err, false)
		}
		count++
		if count > s3MaxObjects {
			return nil, docError(http.StatusOK, "publication_too_large", false)
		}
		name := strings.TrimPrefix(item.Key, prefix)
		if name == "" || strings.Contains(name, "/") {
			return nil, docError(http.StatusOK, "unmanaged_child", false)
		}
		if _, duplicate := out[name]; duplicate {
			return nil, docError(http.StatusOK, "unmanaged_child", false)
		}
		out[name] = s3Object{
			key: item.Key, versionID: item.VersionID, etag: strings.Trim(item.ETag, `"`),
			marker: s3Marker(item.UserMetadata), size: item.Size,
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return a.resolveMarkers(ctx, out)
}

// resolveMarkers fills the publication stamp for implementations that keep user
// metadata out of a listing. AWS S3 is one of them: only a HEAD returns it, so
// the bounded object count is what keeps the preflight to a handful of calls.
func (a *s3Adapter) resolveMarkers(ctx context.Context, objects map[string]s3Object) (map[string]s3Object, error) {
	for name, object := range objects {
		if object.marker != "" && object.versionID != "" {
			continue
		}
		stat, err := a.client.StatObject(ctx, a.bucket, object.key, minio.StatObjectOptions{VersionID: object.versionID})
		if err != nil {
			return nil, s3Err(err, false)
		}
		if object.etag != "" && object.etag != strings.Trim(stat.ETag, `"`) {
			return nil, shared.ErrConflict
		}
		if stat.VersionID == "" {
			return nil, docError(http.StatusOK, "versioning_required", false)
		}
		object.marker = s3Marker(stat.UserMetadata)
		object.size = stat.Size
		object.versionID = stat.VersionID
		object.etag = strings.Trim(stat.ETag, `"`)
		objects[name] = object
	}
	return objects, nil
}

func (a *s3Adapter) readObject(ctx context.Context, key, versionID string, limit int64) ([]byte, error) {
	object, err := a.client.GetObject(ctx, a.bucket, key, minio.GetObjectOptions{VersionID: versionID})
	if err != nil {
		return nil, s3Err(err, false)
	}
	defer func() { _ = object.Close() }()
	data, err := io.ReadAll(io.LimitReader(object, limit+1))
	if err != nil {
		return nil, s3Err(err, false)
	}
	if int64(len(data)) > limit {
		return nil, docError(http.StatusOK, "invalid_response", false)
	}
	return data, nil
}

// verifyPublicationIdentity proves, from one listing, that the publication is
// the neutral shell this workflow created and holds nothing else. A missing
// stamp is unverifiable rather than lost: an S3 implementation that omits user
// metadata from a listing must refuse instead of claiming a breach.
func (a *s3Adapter) verifyPublicationIdentity(marker string, objects map[string]s3Object) error {
	shell, ok := objects[s3ShellName]
	if !ok {
		return restrictionLostError(http.StatusOK, "remote_identity_changed")
	}
	if shell.marker == "" {
		return docError(http.StatusOK, "complete_identity_unverifiable", false)
	}
	if shell.marker != marker || shell.size != 0 {
		return restrictionLostError(http.StatusOK, "remote_identity_changed")
	}
	for name, object := range objects {
		if name != s3ShellName && name != s3BodyName && !validAttachmentName(name) {
			return docError(http.StatusOK, "unmanaged_child", false)
		}
		if object.marker == "" {
			return docError(http.StatusOK, "complete_identity_unverifiable", false)
		}
		if object.marker != marker {
			return docError(http.StatusOK, "unmanaged_child", false)
		}
	}
	return nil
}

// verifiedPublication is the preflight every outbound operation shares: the
// destination proof, one listing, and the publication identity proof.
func (a *s3Adapter) verifiedPublication(ctx context.Context, marker, container, group string) (map[string]s3Object, error) {
	if !validMarker(marker) {
		return nil, shared.ErrValidation
	}
	if err := a.CheckDocumentRelease(ctx, container, group); err != nil {
		return nil, err
	}
	objects, err := a.publicationObjects(ctx, marker)
	if err != nil {
		return nil, err
	}
	if err = a.verifyPublicationIdentity(marker, objects); err != nil {
		return nil, err
	}
	return objects, nil
}

func (a *s3Adapter) CreateDocumentShell(ctx context.Context, container, marker string) (docpublish.RemotePage, error) {
	if !validMarker(marker) {
		return docpublish.RemotePage{}, shared.ErrValidation
	}
	if err := a.CheckDocumentRelease(ctx, container, a.principal); err != nil {
		return docpublish.RemotePage{}, err
	}
	objects, err := a.publicationObjects(ctx, marker)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	if len(objects) > 0 {
		return docpublish.RemotePage{}, shared.ErrConflict
	}
	versions, err := a.allVersions(ctx, marker)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	if len(versions) != 0 {
		return docpublish.RemotePage{}, shared.ErrConflict
	}
	opts := minio.PutObjectOptions{
		ContentType: "application/octet-stream", DisableMultipart: true,
		UserMetadata: map[string]string{s3MarkerMeta: marker},
	}
	opts.SetMatchETagExcept("*")
	if _, err = a.client.PutObject(ctx, a.bucket, a.key(marker, s3ShellName), bytes.NewReader(nil), 0, opts); err != nil {
		return docpublish.RemotePage{}, s3Err(err, true)
	}
	return s3Remote(marker, a.browserURL(marker), "new:"+marker), nil
}

// RestrictDocument has nothing to grant: the reader is the operator's bucket
// policy and Synapse never widens access. It proves the current state instead.
func (a *s3Adapter) RestrictDocument(ctx context.Context, page, group string) error {
	return a.VerifyDocumentRestriction(ctx, page, a.bucket, group)
}

func (a *s3Adapter) VerifyDocumentRestriction(ctx context.Context, page, container, group string) error {
	_, err := a.ReadRestrictedDocument(ctx, page, container, group)
	return err
}

func (a *s3Adapter) GetDocument(ctx context.Context, page string) (ports.DocumentRemoteState, error) {
	if !validMarker(page) {
		return ports.DocumentRemoteState{}, shared.ErrValidation
	}
	objects, err := a.publicationObjects(ctx, page)
	if err != nil {
		return ports.DocumentRemoteState{}, err
	}
	if err = a.verifyPublicationIdentity(page, objects); err != nil {
		return ports.DocumentRemoteState{}, err
	}
	return a.documentState(ctx, page, objects)
}

func (a *s3Adapter) documentState(ctx context.Context, marker string, objects map[string]s3Object) (ports.DocumentRemoteState, error) {
	out := ports.DocumentRemoteState{
		RemotePage: s3Remote(marker, a.browserURL(marker), "new:"+marker),
		Container:  a.bucket, Marker: marker, Neutral: true,
	}
	body, ok := objects[s3BodyName]
	if !ok {
		return out, nil
	}
	if body.versionID == "" {
		return out, docError(http.StatusOK, "invalid_revision", false)
	}
	raw, err := a.readObject(ctx, body.key, body.versionID, s3MaxBodyBytes)
	if err != nil {
		return out, err
	}
	source, err := decodeS3HTML(raw)
	if err != nil {
		return out, err
	}
	if err = a.ValidateDocumentText(source.Title + source.Storage + string(raw)); err != nil {
		return out, err
	}
	if !validMarker(source.Marker) {
		return out, restrictionLostError(http.StatusOK, "remote_identity_changed")
	}
	for name, etag := range source.Files {
		object, present := objects[name]
		if !present || object.etag != etag {
			return out, docError(http.StatusOK, "remote_content_changed", false)
		}
	}
	out.RemotePage = s3Remote(marker, a.browserURL(marker), body.etag)
	out.Title, out.Storage, out.Marker, out.Neutral = source.Title, source.Storage, source.Marker, false
	out.ContentHash = body.etag
	return out, nil
}

func (a *s3Adapter) ReadRestrictedDocument(ctx context.Context, page, container, group string) (ports.DocumentRemoteState, error) {
	objects, err := a.verifiedPublication(ctx, page, container, group)
	if err != nil {
		return ports.DocumentRemoteState{}, err
	}
	return a.documentState(ctx, page, objects)
}

func (a *s3Adapter) FindDocumentMarker(ctx context.Context, container, marker string) ([]ports.DocumentRemoteState, error) {
	if container != a.bucket || !validMarker(marker) {
		return nil, shared.ErrValidation
	}
	objects, err := a.publicationObjects(ctx, marker)
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return []ports.DocumentRemoteState{}, nil
	}
	if err = a.verifyPublicationIdentity(marker, objects); err != nil {
		return nil, err
	}
	state, err := a.documentState(ctx, marker, objects)
	if err != nil {
		return nil, err
	}
	return []ports.DocumentRemoteState{state}, nil
}

func (a *s3Adapter) UploadDocumentAttachment(ctx context.Context, page string, file ports.DocumentImage) error {
	if !validMarker(page) {
		return shared.ErrValidation
	}
	if len(file.Data) == 0 || len(file.Data) > s3MaxAttachment || !validAttachmentName(file.Name) ||
		(!strings.HasPrefix(file.MediaType, "image/") && file.MediaType != "application/pdf") {
		return shared.ErrValidation
	}
	if err := a.ValidateDocumentText(file.Name); err != nil {
		return err
	}
	objects, err := a.verifiedPublication(ctx, page, a.bucket, a.principal)
	if err != nil {
		return err
	}
	if existing, ok := objects[file.Name]; ok {
		current, readErr := a.readObject(ctx, existing.key, existing.versionID, s3MaxAttachment)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(current, file.Data) {
			return docError(http.StatusConflict, "attachment_name_conflict", false)
		}
		return nil
	}
	count := len(objects) + 1
	if _, hasBody := objects[s3BodyName]; !hasBody {
		count++ // Keep the body slot available after a staged attachment.
	}
	if count > s3MaxObjects {
		return docError(http.StatusOK, "publication_too_large", false)
	}
	if err = a.checkWriteHistory(ctx, page); err != nil {
		return err
	}
	opts := minio.PutObjectOptions{
		ContentType: file.MediaType, DisableMultipart: true,
		UserMetadata: map[string]string{s3MarkerMeta: page},
	}
	opts.SetMatchETagExcept("*")
	if _, err = a.client.PutObject(ctx, a.bucket, a.key(page, file.Name), bytes.NewReader(file.Data), int64(len(file.Data)), opts); err != nil {
		return s3Err(err, true)
	}
	return nil
}

func (*s3Adapter) WriteDocument(context.Context, string, int, string, string, string) (docpublish.RemotePage, error) {
	return docpublish.RemotePage{}, docError(0, "opaque_revision_required", false)
}

// WriteDocumentRevision conditionally replaces the expected content ETag. Every
// managed release embeds a unique intent marker in its canonical body. Version
// IDs address exact reads and history, but are not S3 PUT preconditions.
func (a *s3Adapter) WriteDocumentRevision(ctx context.Context, expected docpublish.RemotePage, title, storage, marker string) (docpublish.RemotePage, error) {
	if !validMarker(expected.ID) || !validMarker(marker) {
		return docpublish.RemotePage{}, shared.ErrValidation
	}
	objects, err := a.verifiedPublication(ctx, expected.ID, a.bucket, a.principal)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	current, err := a.documentState(ctx, expected.ID, objects)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	if current.Revision != expected.Revision {
		return docpublish.RemotePage{}, shared.ErrConflict
	}
	files := map[string]string{}
	for name, object := range objects {
		if name == s3ShellName || name == s3BodyName {
			continue
		}
		if !safeID(object.etag) {
			return docpublish.RemotePage{}, docError(http.StatusOK, "invalid_attachment_identity", false)
		}
		files[name] = object.etag
	}
	rendered, err := encodeS3HTML(title, storage, marker, files)
	if err != nil {
		return docpublish.RemotePage{}, err
	}
	if err = a.ValidateDocumentText(title + storage); err != nil {
		return docpublish.RemotePage{}, err
	}
	if err = a.checkWriteHistory(ctx, expected.ID); err != nil {
		return docpublish.RemotePage{}, err
	}
	opts := minio.PutObjectOptions{
		ContentType: "text/html; charset=utf-8", DisableMultipart: true,
		UserMetadata: map[string]string{s3MarkerMeta: expected.ID},
	}
	if body, exists := objects[s3BodyName]; exists {
		if !safeID(body.etag) {
			return docpublish.RemotePage{}, docError(http.StatusOK, "invalid_revision", false)
		}
		opts.SetMatchETag(expected.Revision)
	} else {
		if len(objects) >= s3MaxObjects {
			return docpublish.RemotePage{}, docError(http.StatusOK, "publication_too_large", false)
		}
		opts.SetMatchETagExcept("*")
	}
	info, err := a.client.PutObject(ctx, a.bucket, a.key(expected.ID, s3BodyName), bytes.NewReader(rendered), int64(len(rendered)), opts)
	if err != nil {
		return docpublish.RemotePage{}, s3Err(err, true)
	}
	etag := strings.Trim(info.ETag, `"`)
	if info.VersionID == "" || !safeID(etag) {
		return docpublish.RemotePage{}, docError(http.StatusOK, "invalid_revision", true)
	}
	return s3Remote(expected.ID, a.browserURL(expected.ID), etag), nil
}

func encodeS3HTML(title, storage, marker string, files map[string]string) ([]byte, error) {
	return encodeCanonicalDocumentHTML(title, storage, marker, files, graphAttachmentHTML)
}

func decodeS3HTML(data []byte) (htmlSource, error) {
	return decodeCanonicalDocumentHTML(data, encodeS3HTML)
}

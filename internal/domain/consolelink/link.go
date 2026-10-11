// Package consolelink creates trusted, typed links to existing Synapse console routes.
// It never accepts a request parameter or event payload as the URL origin.
package consolelink

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type SubjectKind string

const (
	KindFinding    SubjectKind = "finding"
	KindScan       SubjectKind = "scan"
	KindEngagement SubjectKind = "engagement"
	KindIncident   SubjectKind = "incident"
)

// Link is immutable outside this package, so a formatter cannot manufacture
// a link from untrusted event data. Use the accessors or MarshalJSON for output.
type Link struct {
	kind      SubjectKind
	subjectID shared.ID
	href      string
}

func (l Link) Kind() SubjectKind    { return l.kind }
func (l Link) SubjectID() shared.ID { return l.subjectID }
func (l Link) Href() string         { return l.href }

// MarshalJSON preserves the public wire shape while keeping construction sealed.
func (l Link) MarshalJSON() ([]byte, error) {
	if l.href == "" {
		return nil, ErrInvalidOrigin
	}
	return json.Marshal(struct {
		Kind      SubjectKind `json:"kind"`
		SubjectID shared.ID   `json:"subject_id"`
		Href      string      `json:"href"`
	}{l.kind, l.subjectID, l.href})
}

// UnmarshalJSON prevents externally supplied notification content from forging
// a typed, builder-produced link.
func (*Link) UnmarshalJSON([]byte) error {
	return errors.New("console links must be built by the server")
}

var (
	ErrInvalidOrigin  = errors.New("console links require a trusted absolute HTTPS base URL without credentials, query or fragment")
	ErrInvalidSubject = errors.New("invalid console link subject ID")
)

// Builder holds only a validated operator-controlled URL, never user-supplied content.
type Builder struct {
	base string
}

// NewBuilder validates the origin and optional deployment prefix. Errors never
// echo the supplied URL, which might accidentally include credentials.
func NewBuilder(raw string) (Builder, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\\\r\n\t") ||
		strings.ContainsAny(raw, "?#") {
		return Builder{}, ErrInvalidOrigin
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			return Builder{}, ErrInvalidOrigin
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" ||
		u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.RawFragment != "" || strings.HasSuffix(u.Host, ":") {
		return Builder{}, ErrInvalidOrigin
	}
	// url.Parse decodes percent escapes inside hosts. Recheck the decoded host,
	// otherwise an encoded bidi control can bypass the raw-string validation.
	if strings.ContainsRune(u.Host, '%') {
		return Builder{}, ErrInvalidOrigin
	}
	for _, r := range u.Host {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			return Builder{}, ErrInvalidOrigin
		}
	}
	if port := u.Port(); port != "" {
		n, portErr := strconv.Atoi(port)
		if portErr != nil || n < 1 || n > 65535 {
			return Builder{}, ErrInvalidOrigin
		}
	}
	// A decoded percent sign would admit a double-encoded path that a reverse
	// proxy might decode a second time (e.g. %252e%252e). Fail closed.
	if strings.ContainsRune(u.Path, '%') {
		return Builder{}, ErrInvalidOrigin
	}
	// Reject path traversal, even if the dot segments were percent-encoded.
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return Builder{}, ErrInvalidOrigin
		}
		for _, r := range segment {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return Builder{}, ErrInvalidOrigin
			}
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return Builder{base: strings.TrimRight(u.String(), "/")}, nil
}

// Finding links to the existing Findings tab's finding-ID hash anchor.
func (b Builder) Finding(engagementID, findingID shared.ID) (Link, error) {
	e, err := escapeID(engagementID)
	if err != nil {
		return Link{}, err
	}
	f, err := escapeID(findingID)
	if err != nil {
		return Link{}, err
	}
	return b.link(KindFinding, findingID, "/engagements/"+e+"/findings#finding-"+f)
}

// Scan opens the scan history and preserves scan identity in the URL fragment.
// The current console does not automatically select a run from this fragment.
func (b Builder) Scan(engagementID, scanID shared.ID) (Link, error) {
	e, err := escapeID(engagementID)
	if err != nil {
		return Link{}, err
	}
	s, err := escapeID(scanID)
	if err != nil {
		return Link{}, err
	}
	return b.link(KindScan, scanID, "/engagements/"+e+"/scanruns#scan-"+s)
}

func (b Builder) Engagement(engagementID shared.ID) (Link, error) {
	e, err := escapeID(engagementID)
	if err != nil {
		return Link{}, err
	}
	return b.link(KindEngagement, engagementID, "/engagements/"+e)
}

func (b Builder) Incident(incidentID shared.ID) (Link, error) {
	i, err := escapeID(incidentID)
	if err != nil {
		return Link{}, err
	}
	return b.link(KindIncident, incidentID, "/fleet/incidents/"+i)
}

func (b Builder) link(kind SubjectKind, subject shared.ID, route string) (Link, error) {
	if b.base == "" {
		return Link{}, ErrInvalidOrigin
	}
	return Link{kind: kind, subjectID: subject, href: b.base + route}, nil
}

func escapeID(id shared.ID) (string, error) {
	s := id.String()
	if s == "" || s == "." || s == ".." || strings.TrimSpace(s) != s {
		return "", ErrInvalidSubject
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", ErrInvalidSubject
		}
	}
	return url.PathEscape(s), nil
}

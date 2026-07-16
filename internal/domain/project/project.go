// Package project is the aggregate root for a long-lived code-quality project.
package project

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	SourceLocal   = "local"
	SourceGit     = "git"
	SourceArchive = "archive"
)

var (
	keyPattern    = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	gitRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

// SourceBinding identifies source that a later analysis run can acquire.
type SourceBinding struct {
	Kind  string
	Value string
	Ref   string
}

// Project is a long-lived code-quality identity, independent of an Engagement.
type Project struct {
	ID                   shared.ID
	TenantID             shared.ID
	Name                 string
	Key                  string
	SourceBinding        SourceBinding
	DefaultProfileByLang map[string]string
	GateID               string
	Audit                shared.Audit
}

// New creates a validated Project.
func New(id, tenantID shared.ID, name, key string, source SourceBinding, profiles map[string]string, gateID string, now time.Time) (*Project, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: project id is required", shared.ErrValidation)
	}
	name, key = strings.TrimSpace(name), strings.TrimSpace(key)
	if name == "" {
		return nil, fmt.Errorf("%w: project name is required", shared.ErrValidation)
	}
	if !keyPattern.MatchString(key) {
		return nil, fmt.Errorf("%w: project key must be a lowercase hyphenated slug", shared.ErrValidation)
	}
	source.Kind, source.Value, source.Ref = strings.TrimSpace(source.Kind), strings.TrimSpace(source.Value), strings.TrimSpace(source.Ref)
	if source.Value == "" {
		return nil, fmt.Errorf("%w: project source value is required", shared.ErrValidation)
	}
	switch source.Kind {
	case SourceLocal, SourceArchive:
		if source.Ref != "" {
			return nil, fmt.Errorf("%w: source ref is only valid for git", shared.ErrValidation)
		}
		source.Value = filepath.Clean(source.Value)
	case SourceGit:
		u, err := url.Parse(source.Value)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("%w: git source must be an https URL with a host", shared.ErrValidation)
		}
		if u.User != nil {
			return nil, fmt.Errorf("%w: git source must not contain embedded credentials", shared.ErrValidation)
		}
		if len(source.Ref) > 255 || (source.Ref != "" && !gitRefPattern.MatchString(source.Ref)) {
			return nil, fmt.Errorf("%w: invalid git source ref", shared.ErrValidation)
		}
	default:
		return nil, fmt.Errorf("%w: unknown project source kind %q", shared.ErrValidation, source.Kind)
	}
	profileCopy := make(map[string]string, len(profiles))
	for lang, profile := range profiles {
		lang, profile = strings.TrimSpace(lang), strings.TrimSpace(profile)
		if lang == "" || profile == "" {
			return nil, fmt.Errorf("%w: profile language and key are required", shared.ErrValidation)
		}
		profileCopy[lang] = profile
	}
	return &Project{
		ID: id, TenantID: tenantID, Name: name, Key: key, SourceBinding: source,
		DefaultProfileByLang: profileCopy, GateID: strings.TrimSpace(gateID),
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}

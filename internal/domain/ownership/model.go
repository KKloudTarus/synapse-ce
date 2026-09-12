package ownership

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Team struct {
	TenantID  shared.ID `json:"-"`
	ID        shared.ID `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Archived  bool      `json:"archived"`
	Revision  int       `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (t Team) Validate() error {
	if t.TenantID.IsZero() || t.ID.IsZero() || t.Name != strings.TrimSpace(t.Name) || t.Name == "" || len(t.Name) > 200 || len(t.Slug) < 1 || len(t.Slug) > 80 || t.Revision < 1 || t.CreatedAt.IsZero() || t.UpdatedAt.Before(t.CreatedAt) {
		return invalid("team")
	}
	for i, r := range t.Slug {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && i > 0 && i < len(t.Slug)-1) {
			return invalid("team slug")
		}
	}
	return nil
}

type Membership struct {
	TenantID  shared.ID `json:"-"`
	TeamID    shared.ID `json:"team_id"`
	UserID    shared.ID `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

type Mapping struct {
	Repository      string    `json:"repository"`
	Owner           string    `json:"owner"`
	TeamID          shared.ID `json:"team_id"`
	SuggestedUserID shared.ID `json:"suggested_user_id,omitempty"`
}

func (m Mapping) Validate() error {
	if strings.TrimSpace(m.Repository) == "" || strings.ContainsAny(m.Repository, "\x00\r\n") || len(m.Repository) > 2048 || !ValidOwner(m.Owner) || m.TeamID.IsZero() {
		return invalid("owner mapping")
	}
	return nil
}

type AssetMapping struct {
	AssetID shared.ID `json:"asset_id"`
	TeamID  shared.ID `json:"team_id"`
}

type Snapshot struct {
	TenantID          shared.ID `json:"-"`
	ID                shared.ID `json:"id"`
	EngagementID      shared.ID `json:"engagement_id"`
	Repository        string    `json:"repository"`
	Revision          string    `json:"source_revision"`
	FilePath          string    `json:"file_path"`
	Content           string    `json:"-"`
	Hash              string    `json:"content_hash"`
	ParserVersion     string    `json:"parser_version"`
	Trust             string    `json:"trust"` // untrusted, base_ref, admin_import
	ApprovedBy        string    `json:"approved_by,omitempty"`
	AcceptDiagnostics bool      `json:"accept_diagnostics"`
	CreatedAt         time.Time `json:"created_at"`
}

func (s Snapshot) Parse() (Codeowners, error) {
	if s.TenantID.IsZero() || s.ID.IsZero() || s.EngagementID.IsZero() || s.Repository == "" || strings.ContainsAny(s.Repository, "\x00\r\n") || len(s.Repository) > 2048 || !PinnedRevision(s.Revision) || s.CreatedAt.IsZero() || s.ParserVersion != ParserVersion || ContentHash(s.Content) != s.Hash {
		return Codeowners{}, invalid("source snapshot")
	}
	if s.FilePath != ".github/CODEOWNERS" && s.FilePath != "CODEOWNERS" && s.FilePath != "docs/CODEOWNERS" {
		return Codeowners{}, invalid("snapshot file")
	}
	if s.Trust != "untrusted" && s.Trust != "base_ref" && s.Trust != "admin_import" {
		return Codeowners{}, invalid("snapshot trust")
	}
	if s.Trust != "untrusted" && strings.TrimSpace(s.ApprovedBy) == "" {
		return Codeowners{}, invalid("snapshot approval")
	}
	return ParseCodeowners(s.Content)
}

type Conditions struct {
	EngagementIDs []shared.ID       `json:"engagement_ids,omitempty"`
	Repositories  []string          `json:"repositories,omitempty"`
	ProjectIDs    []shared.ID       `json:"project_ids,omitempty"`
	Paths         []string          `json:"paths,omitempty"`
	Kinds         []string          `json:"kinds,omitempty"`
	Severities    []shared.Severity `json:"severities,omitempty"`
	AssetIDs      []shared.ID       `json:"asset_ids,omitempty"`
}

type Rule struct {
	ID       string     `json:"id"`
	Priority int        `json:"priority"`
	When     Conditions `json:"when"`
	TeamID   shared.ID  `json:"team_id,omitempty"`
	Exclude  bool       `json:"exclude"`
}

// PolicyVersion is immutable. Mapping edits create a new version rather than
// changing the explanation for decisions previously evaluated against it.
type PolicyVersion struct {
	TenantID     shared.ID      `json:"-"`
	PolicyID     shared.ID      `json:"policy_id"`
	EngagementID shared.ID      `json:"engagement_id"`
	Repository   string         `json:"repository,omitempty"` // empty = engagement fallback
	Version      int            `json:"version"`
	SnapshotID   shared.ID      `json:"snapshot_id,omitempty"`
	Rules        []Rule         `json:"rules"`
	Mappings     []Mapping      `json:"mappings"`
	Assets       []AssetMapping `json:"assets"`
	CreatedBy    string         `json:"created_by"`
	CreatedAt    time.Time      `json:"created_at"`
}

func (p PolicyVersion) Validate() error {
	if p.TenantID.IsZero() || p.PolicyID.IsZero() || p.EngagementID.IsZero() || len(p.Repository) > 2048 || p.Version < 1 || strings.TrimSpace(p.CreatedBy) == "" || p.CreatedAt.IsZero() || len(p.Rules) > 200 || len(p.Mappings) > 20000 || len(p.Assets) > 2000 {
		return invalid("policy version")
	}
	priorities, ids := map[int]bool{}, map[string]bool{}
	for _, r := range p.Rules {
		if r.ID == "" || len(r.ID) > 100 || r.Priority < 0 || priorities[r.Priority] || ids[r.ID] || r.Exclude == !r.TeamID.IsZero() {
			return invalid("routing rule")
		}
		priorities[r.Priority], ids[r.ID] = true, true
		c := r.When
		if len(c.EngagementIDs)+len(c.Repositories)+len(c.ProjectIDs)+len(c.Paths)+len(c.Kinds)+len(c.Severities)+len(c.AssetIDs) > 200 {
			return invalid("rule conditions limit")
		}
		for _, path := range c.Paths {
			if _, err := compilePattern(path); err != nil {
				return err
			}
		}
		for _, severity := range c.Severities {
			if !severity.Valid() {
				return invalid("rule severity")
			}
		}
		for _, list := range [][]shared.ID{c.EngagementIDs, c.ProjectIDs, c.AssetIDs} {
			for _, id := range list {
				if id.IsZero() {
					return invalid("rule identity")
				}
			}
		}
		for _, list := range [][]string{c.Repositories, c.Kinds} {
			for _, v := range list {
				if strings.TrimSpace(v) == "" || len(v) > 2048 {
					return invalid("rule value")
				}
			}
		}
	}
	keys := map[string]bool{}
	for _, m := range p.Mappings {
		if err := m.Validate(); err != nil {
			return err
		}
		key := m.Repository + "\x00" + m.Owner
		if keys[key] {
			return invalid("duplicate owner mapping")
		}
		keys[key] = true
	}
	assets := map[shared.ID]bool{}
	for _, a := range p.Assets {
		if a.AssetID.IsZero() || a.TeamID.IsZero() || assets[a.AssetID] {
			return invalid("asset mapping")
		}
		assets[a.AssetID] = true
	}
	return nil
}

// Hash covers exact policy content (including its frozen mappings). A caller
// cannot change a candidate after preview and still activate its old hash.
func (p PolicyVersion) Hash() string { b, _ := json.Marshal(p); return ContentHash(string(b)) }

type Resolution string

const (
	Resolved    Resolution = "resolved"
	Unresolved  Resolution = "unresolved"
	Ambiguous   Resolution = "ambiguous"
	Excluded    Resolution = "excluded"
	Unsupported Resolution = "unsupported"
)

func (r Resolution) Valid() bool {
	return slices.Contains([]Resolution{Resolved, Unresolved, Ambiguous, Excluded, Unsupported}, r)
}

type Assignment struct {
	TeamID           shared.ID `json:"team_id,omitempty"`
	AssigneeID       shared.ID `json:"assignee_id,omitempty"`
	LegacyAssignee   string    `json:"legacy_assignee,omitempty"`
	Mode             string    `json:"mode"`
	Revision         int       `json:"revision"`
	ManualGeneration int64     `json:"manual_generation"`
}

func (a Assignment) Validate() error {
	if a.Mode != "auto" && a.Mode != "manual" || a.Revision < 0 || a.ManualGeneration < 0 || len(a.LegacyAssignee) > 4096 {
		return invalid("assignment")
	}
	if !a.AssigneeID.IsZero() && a.LegacyAssignee != a.AssigneeID.String() {
		return invalid("canonical assignee mirror")
	}
	return nil
}

type PathEvidence struct {
	Path    string   `json:"path"`
	Line    int      `json:"line,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	Owners  []string `json:"owners,omitempty"`
	Reason  string   `json:"reason"`
}

type Result struct {
	Resolution   Resolution     `json:"resolution"`
	Reason       string         `json:"reason"`
	TeamID       shared.ID      `json:"team_id,omitempty"`
	Candidates   []shared.ID    `json:"candidates"`
	Evidence     []PathEvidence `json:"evidence"`
	RuleID       string         `json:"rule_id,omitempty"`
	PolicyHash   string         `json:"policy_hash"`
	SnapshotHash string         `json:"snapshot_hash,omitempty"`
	InputHash    string         `json:"input_hash"`
}

type Decision struct {
	TenantID     shared.ID  `json:"-"`
	ID           shared.ID  `json:"id"`
	EngagementID shared.ID  `json:"engagement_id"`
	FindingID    shared.ID  `json:"finding_id"`
	Key          string     `json:"transition_key"`
	Actor        string     `json:"actor"`
	Before       Assignment `json:"before"`
	After        Assignment `json:"after"`
	Result       Result     `json:"result"`
	CreatedAt    time.Time  `json:"created_at"`
}

func invalid(what string) error {
	return fmt.Errorf("%w: invalid ownership %s", shared.ErrValidation, what)
}

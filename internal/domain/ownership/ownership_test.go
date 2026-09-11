package ownership

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestCodeownersMatches(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"*.go", "main.go", true}, {"*.go", "src/main.go", true}, {"*.go", "main.GO", false},
		{"/apps/", "apps/a.go", true}, {"/apps/", "src/apps/a.go", false}, {"apps/", "src/apps/a.go", true},
		{"docs/*", "docs/a.md", true}, {"docs/*", "docs/sub/a.md", false}, {"docs/*", "src/docs/a.md", false},
		{"**/logs", "logs/a.txt", true}, {"**/logs", "a/logs/x/y.txt", true}, {"/a/**/b.go", "a/b.go", true},
		{"/a/**/b.go", "a/x/y/b.go", true}, {"a/**", "a/b/c.go", true}, {"a/?/c.go", "a/x/c.go", true},
		{"a/?/c.go", "a/xx/c.go", false}, {"src/foo.go", "other/src/foo.go", false}, {"foo", "a/foo/x.txt", true},
		{"my\\ folder/*", "my folder/a.go", true},
		{"alert!.go", "alert!.go", true},
	} {
		t.Run(tc.pattern+":"+tc.path, func(t *testing.T) {
			c, err := ParseCodeowners(tc.pattern + " @org/team")
			if err != nil {
				t.Fatal(err)
			}
			_, got := c.Match(tc.path)
			if got != tc.want {
				t.Fatalf("match=%v want=%v diagnostics=%v", got, tc.want, c.Diagnostics)
			}
		})
	}
}

func TestCodeownersPrecedenceAndDiagnostics(t *testing.T) {
	c, err := ParseCodeowners("# comment\r\n* @all\r\n/apps/ @org/a @org/b # comment\n/apps/free\n!bad @a\n[abc] @a\n\\#bad @a\nbad not-an-owner\n*.go dev@example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Diagnostics) != 4 {
		t.Fatalf("diagnostics=%+v", c.Diagnostics)
	}
	p, ok := c.Match("apps/test.txt")
	if !ok || p.Line != 3 || len(p.Owners) != 2 {
		t.Fatalf("multi owner=%+v", p)
	}
	p, _ = c.Match("apps/free/x.txt")
	if p.Line != 4 || len(p.Owners) != 0 {
		t.Fatalf("empty exclusion=%+v", p)
	}
	p, _ = c.Match("apps/free/x.go")
	if p.Line != 9 || p.Owners[0] != "dev@example.com" {
		t.Fatalf("last line=%+v", p)
	}
	name, content, ok := SelectFile(map[string]string{"CODEOWNERS": "* @a", ".github/CODEOWNERS": ""})
	if !ok || name != ".github/CODEOWNERS" || content != "" {
		t.Fatal("empty priority file lost")
	}
	if _, _, ok := SelectFile(nil); ok {
		t.Fatal("missing file selected")
	}
}

func TestCodeownersResourceBounds(t *testing.T) {
	for _, content := range []string{strings.Repeat("x", MaxSourceBytes+1), "* @a\x00", string([]byte{0xff}), "* " + strings.Repeat("@a ", MaxOwners+1), strings.Repeat("* @a\n", MaxPatterns+1)} {
		if _, err := ParseCodeowners(content); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("accepted invalid or excessive document: %v", err)
		}
	}
}

func TestOwnershipPaths(t *testing.T) {
	for _, path := range []string{"/etc/passwd", "C:\\src\\x", "\\\\server\\x", "../x", "a/../x", "a//x", "a/./b", "a\x00b", "", "a/", strings.Repeat("a", MaxPathBytes+1)} {
		if _, err := NormalizePath(path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
	if got, err := NormalizePath("./src\\Payment.go"); err != nil || got != "src/Payment.go" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func fixture() (PolicyVersion, Snapshot, Input) {
	at := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	s := Snapshot{TenantID: "t", ID: "s", EngagementID: "e", Repository: "repo", Revision: "git:1111111111111111111111111111111111111111", FilePath: "CODEOWNERS", Content: "/pay/ @org/pay\n/ops/ @org/ops\n/free/\n/unknown/ @missing\n/shared/ @org/pay @org/ops", ParserVersion: ParserVersion, Trust: "base_ref", ApprovedBy: "admin", CreatedAt: at}
	s.Hash = ContentHash(s.Content)
	p := PolicyVersion{TenantID: "t", PolicyID: "p", EngagementID: "e", Version: 1, SnapshotID: "s", Mappings: []Mapping{{Repository: "repo", Owner: "@org/pay", TeamID: "pay"}, {Repository: "repo", Owner: "@org/ops", TeamID: "ops"}}, Assets: []AssetMapping{{AssetID: "asset", TeamID: "ops"}}, CreatedBy: "admin", CreatedAt: at}
	i := Input{TenantID: "t", EngagementID: "e", FindingID: "f", Repository: "repo", Kind: "sast", Severity: shared.SeverityHigh, Paths: []string{"pay/handler.go"}, SourceRevision: "git:2222222222222222222222222222222222222222", SourceBound: true, Supported: true, Current: Assignment{Mode: "auto"}, ActiveTeams: []shared.ID{"pay", "ops"}}
	return p, s, i
}

func TestResolverOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		change       func(*PolicyVersion, *Snapshot, *Input)
		status       Resolution
		reason, team string
	}{
		{"codeowners", func(*PolicyVersion, *Snapshot, *Input) {}, Resolved, "codeowners", "pay"},
		{"multi manifest", func(_ *PolicyVersion, _ *Snapshot, i *Input) {
			i.Paths = []string{"pay/package.json", "ops/package.json"}
		}, Ambiguous, "multiple_teams", ""},
		{"multi owner", func(_ *PolicyVersion, _ *Snapshot, i *Input) { i.Paths = []string{"shared/main.go"} }, Ambiguous, "multiple_teams", ""},
		{"unmapped", func(_ *PolicyVersion, _ *Snapshot, i *Input) {
			i.Paths = []string{"unknown/a.go"}
			i.AssetIDs = []shared.ID{"asset"}
		}, Unresolved, "incomplete_ownership", ""},
		{"partial evidence", func(_ *PolicyVersion, _ *Snapshot, i *Input) { i.Paths = append(i.Paths, "unmatched/a.go") }, Unresolved, "incomplete_ownership", ""},
		{"empty owner", func(_ *PolicyVersion, _ *Snapshot, i *Input) {
			i.Paths = []string{"free/a.go"}
			i.AssetIDs = []shared.ID{"asset"}
		}, Excluded, "codeowners_exclusion", ""},
		{"mixed exclusion", func(_ *PolicyVersion, _ *Snapshot, i *Input) { i.Paths = append(i.Paths, "free/a.go") }, Ambiguous, "mixed_exclusion", ""},
		{"asset fallback", func(_ *PolicyVersion, _ *Snapshot, i *Input) { i.Paths = nil; i.AssetIDs = []shared.ID{"asset"} }, Resolved, "business_asset", "ops"},
		{"unbound", func(_ *PolicyVersion, _ *Snapshot, i *Input) { i.SourceBound = false }, Unresolved, "missing_source_binding", ""},
		{"untrusted", func(_ *PolicyVersion, s *Snapshot, _ *Input) { s.Trust = "untrusted" }, Unresolved, "untrusted_snapshot", ""},
		{"bad diagnostics", func(_ *PolicyVersion, s *Snapshot, _ *Input) {
			s.Content += "\n!bad @org/pay"
			s.Hash = ContentHash(s.Content)
		}, Unresolved, "unaccepted_diagnostics", ""},
		{"archived", func(_ *PolicyVersion, _ *Snapshot, i *Input) { i.ActiveTeams = []shared.ID{"ops"} }, Unresolved, "inactive_team", ""},
		{"manual clear", func(_ *PolicyVersion, _ *Snapshot, i *Input) {
			i.Current.Mode = "manual"
			i.Current.ManualGeneration = 1
		}, Unresolved, "manual_protected", ""},
		{"legacy", func(_ *PolicyVersion, _ *Snapshot, i *Input) { i.Current.LegacyAssignee = "Old display name" }, Unresolved, "manual_protected", ""},
		{"unsupported", func(_ *PolicyVersion, _ *Snapshot, i *Input) { i.Supported = false }, Unsupported, "unsupported_finding", ""},
		{"unsafe path", func(_ *PolicyVersion, _ *Snapshot, i *Input) { i.Paths = []string{"../pay/a.go"} }, Unresolved, "invalid_path", ""},
		{"rule override", func(p *PolicyVersion, _ *Snapshot, _ *Input) {
			p.Rules = []Rule{{ID: "r", Priority: 0, TeamID: "ops", When: Conditions{Severities: []shared.Severity{shared.SeverityHigh}}}}
		}, Resolved, "explicit_rule", "ops"},
		{"rule exclude", func(p *PolicyVersion, _ *Snapshot, _ *Input) { p.Rules = []Rule{{ID: "r", Priority: 0, Exclude: true}} }, Excluded, "explicit_exclusion", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, s, i := fixture()
			tc.change(&p, &s, &i)
			r, err := NewResolver(p, &s)
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.Resolve(i)
			if err != nil || got.Resolution != tc.status || got.Reason != tc.reason || got.TeamID.String() != tc.team {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestResolverFrozenAndDeterministic(t *testing.T) {
	p, s, i := fixture()
	r, err := NewResolver(p, &s)
	if err != nil {
		t.Fatal(err)
	}
	p.Mappings[0].TeamID = "mutated"
	s.Content = "* @attacker"
	first, err := r.Resolve(i)
	if err != nil {
		t.Fatal(err)
	}
	i.Paths = append(i.Paths, i.Paths[0])
	i.ActiveTeams = []shared.ID{"ops", "pay", "pay"}
	i.Current.Revision = 71
	second, err := r.Resolve(i)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || first.TeamID != "pay" {
		t.Fatalf("not deterministic: %+v %+v", first, second)
	}
	i.TenantID = "other"
	if _, err := r.Resolve(i); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross tenant=%v", err)
	}
}

func TestPolicyValidationAndPrecedence(t *testing.T) {
	p, s, i := fixture()
	p.Rules = []Rule{{ID: "later", Priority: 20, TeamID: "ops"}, {ID: "earlier", Priority: 1, TeamID: "pay"}}
	r, err := NewResolver(p, &s)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := r.Resolve(i)
	if got.RuleID != "earlier" {
		t.Fatalf("rule=%s", got.RuleID)
	}
	p.Rules[0].Priority = 1
	if _, err := NewResolver(p, &s); err == nil {
		t.Fatal("duplicate priorities accepted")
	}
	p, _, _ = fixture()
	p.Mappings = append(p.Mappings, p.Mappings[0])
	if err := p.Validate(); err == nil {
		t.Fatal("duplicate owner mapping accepted")
	}
	p, s, i = fixture()
	s.Hash = "tampered"
	if _, err := NewResolver(p, &s); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
	p, s, i = fixture()
	p.Rules = []Rule{{ID: "partial", Priority: 0, TeamID: "pay", When: Conditions{Paths: []string{"pay/*"}}}}
	i.Paths = append(i.Paths, "ops/b.go")
	r, _ = NewResolver(p, &s)
	got, _ = r.Resolve(i)
	if got.Resolution != Ambiguous {
		t.Fatalf("partial path rule hid ambiguity: %+v", got)
	}
}

func TestTeamAndAssignmentValidation(t *testing.T) {
	at := time.Now()
	team := Team{TenantID: "t", ID: "team", Slug: "payments", Name: "Payments", Revision: 1, CreatedAt: at, UpdatedAt: at}
	if err := team.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"", "Pay", "-pay", "pay-", "pay/team"} {
		team.Slug = slug
		if err := team.Validate(); err == nil {
			t.Fatalf("accepted slug=%s", slug)
		}
	}
	if err := (Assignment{Mode: "manual", AssigneeID: "u", LegacyAssignee: "display name"}).Validate(); err == nil {
		t.Fatal("divergent assignee accepted")
	}
}

func TestOwnershipPinnedSourcesAndWorkBounds(t *testing.T) {
	for _, revision := range []string{"main", "refs/heads/main", "git:abc", "sha256:abc", "git:" + strings.Repeat("G", 40)} {
		if PinnedRevision(revision) {
			t.Fatalf("accepted moving/invalid source %s", revision)
		}
	}
	for _, revision := range []string{"git:" + strings.Repeat("a", 40), "git:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("c", 64)} {
		if !PinnedRevision(revision) {
			t.Fatalf("rejected pinned source %s", revision)
		}
	}
	p, s, i := fixture()
	s.Revision = "main"
	if _, err := NewResolver(p, &s); err == nil {
		t.Fatal("accepted mutable snapshot")
	}
	p, s, i = fixture()
	s.Content = strings.Repeat("* @org/pay\n", 6000)
	s.Hash = ContentHash(s.Content)
	r, err := NewResolver(p, &s)
	if err != nil {
		t.Fatal(err)
	}
	i.Paths = []string{strings.Repeat("a", 4000)}
	if _, err := r.Resolve(i); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("unbounded match=%v", err)
	}
	p, s, i = fixture()
	r, _ = NewResolver(p, &s)
	a, _ := r.Resolve(i)
	i.Paths = []string{"./pay\\handler.go"}
	b, _ := r.Resolve(i)
	if a.InputHash != b.InputHash {
		t.Fatal("path normalization changed logical input hash")
	}
}

func BenchmarkOwnershipResolver(b *testing.B) {
	for _, position := range []string{"last_match", "first_match"} {
		b.Run(position, func(b *testing.B) {
			p, s, i := fixture()
			other := strings.Repeat("/other/* @org/ops\n", 1999)
			if position == "last_match" {
				s.Content = other + "/pay/* @org/pay"
			} else {
				s.Content = "/pay/* @org/pay\n" + other
			}
			s.Hash = ContentHash(s.Content)
			r, err := NewResolver(p, &s)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := r.Resolve(i); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestOwnershipResolverRejectsOversizedInput(t *testing.T) {
	p, s, i := fixture()
	r, err := NewResolver(p, &s)
	if err != nil {
		t.Fatal(err)
	}
	i.Paths = []string{strings.Repeat("x", MaxPathBytes+1)}
	if _, err := r.Resolve(i); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized path hashed or matched: %v", err)
	}
}

func FuzzCodeowners(f *testing.F) {
	for _, v := range []string{"* @a", "/a/**/b @org/team", "!bad @a", "\\#bad @a", "a\\ b/* @a"} {
		f.Add(v, "a/b.go")
	}
	f.Fuzz(func(t *testing.T, source, path string) {
		if len(source) > 8192 || len(path) > 512 {
			t.Skip()
		}
		c, err := ParseCodeowners(source)
		if err != nil {
			return
		}
		normalized, err := NormalizePath(path)
		if err != nil {
			return
		}
		a, ok := c.Match(normalized)
		b, ok2 := c.Match(normalized)
		if ok != ok2 || a.Line != b.Line {
			t.Fatal("nondeterministic matcher")
		}
	})
}

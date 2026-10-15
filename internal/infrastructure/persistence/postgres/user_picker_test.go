package postgres

import (
	"context"
	"database/sql"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"testing"
)

func TestUserPickerScopesMembershipAndKeepsDuplicateNamesDistinct(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 181, nil)
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('other','Other')`); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id, tenant string
		disabled   bool
	}{
		{"picker-alex-1", "default", false}, {"picker-alex-2", "default", false},
		{"picker-disabled", "default", true}, {"picker-outsider", "default", false}, {"picker-other", "other", false},
	} {
		if _, err := db.Exec(`INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES($1,'Alex','consultant',$1,$2,$3)`, row.id, row.tenant, row.disabled); err != nil {
			t.Fatal(err)
		}
	}
	withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO ownership_teams(tenant_id,id,slug,name,archived,revision,created_at,updated_at) VALUES('default','picker-team','picker-team','Team',false,1,now(),now())`); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"picker-alex-1", "picker-alex-2", "picker-disabled"} {
			if _, err := tx.Exec(`INSERT INTO ownership_memberships(tenant_id,team_id,user_id,created_at) VALUES('default','picker-team',$1,now())`, id); err != nil {
				t.Fatal(err)
			}
		}
	})
	reader := NewUserPickerReader(pool)
	first, err := reader.ListUserChoices(context.Background(), shared.DefaultTenant, shared.ID("picker-team"), "Alex", "", 1)
	if err != nil || len(first) != 1 || first[0].ID != "picker-alex-1" {
		t.Fatalf("first page: %+v %v", first, err)
	}
	second, err := reader.ListUserChoices(context.Background(), shared.DefaultTenant, shared.ID("picker-team"), "Alex", first[0].ID, 10)
	if err != nil || len(second) != 1 || second[0].ID != "picker-alex-2" {
		t.Fatalf("second page: %+v %v", second, err)
	}
	for _, query := range []string{"%", "_"} {
		got, err := reader.ListUserChoices(context.Background(), shared.DefaultTenant, "", query, "", 50)
		if err != nil || len(got) != 0 {
			t.Fatalf("wildcard %q expanded: %+v %v", query, got, err)
		}
	}
	other, err := reader.ListUserChoices(context.Background(), shared.ID("other"), "", "Alex", "", 50)
	if err != nil || len(other) != 1 || other[0].ID != "picker-other" {
		t.Fatalf("cross-tenant roster: %+v %v", other, err)
	}
}

func TestUserPickerMentionChoicesIncludeEveryActiveHumanViewerOnly(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 182, nil)
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('other-picker','Other picker')`); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id, tenant, role string
		disabled         bool
	}{
		{"mention-admin", "default", "admin", false},
		{"mention-consultant", "default", "consultant", false},
		{"mention-reviewer", "default", "reviewer", false},
		{"mention-member", "default", "member", false},
		{"mention-readonly", "default", "readonly", false},
		{"mention-integration", "default", "integration_admin", false},
		{"mention-disabled", "default", "readonly", true},
		{"mention-machine", "default", "mcp", false},
		{"mention-other-tenant", "other-picker", "readonly", false},
	} {
		if _, err := db.Exec(`INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES($1,$1,$3,$1,$2,$4)`, row.id, row.tenant, row.role, row.disabled); err != nil {
			t.Fatal(err)
		}
	}
	reader := NewUserPickerReader(pool)
	assignees, err := reader.ListUserChoices(context.Background(), shared.DefaultTenant, "", "mention-", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if got := choiceIDs(assignees); len(got) != 4 || got[0] != "mention-admin" || got[1] != "mention-consultant" || got[2] != "mention-member" || got[3] != "mention-reviewer" {
		t.Fatalf("assignee choices = %v", got)
	}
	mentions, err := reader.ListMentionChoices(context.Background(), shared.DefaultTenant, "", "mention-", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := choiceIDs(mentions), []shared.ID{"mention-admin", "mention-consultant", "mention-integration", "mention-member", "mention-readonly", "mention-reviewer"}; len(got) != len(want) {
		t.Fatalf("mention choices = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("mention choices = %v, want %v", got, want)
			}
		}
	}
}

func choiceIDs(choices []ports.UserChoice) []shared.ID {
	ids := make([]shared.ID, len(choices))
	for i := range choices {
		ids[i] = choices[i].ID
	}
	return ids
}

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func declareLegacyConfigurationTenant(t *testing.T, f *identityFixture, tenant string) shared.ID {
	t.Helper()
	ctx := context.Background()
	f.tenants(t, tenant)
	f.seedIssued(t, tenant, "configuration-admin", user.RoleAdmin, false)
	f.backfill(t, tenant, 10)
	prepared, err := f.store.PrepareCutover(ctx, shared.ID(tenant), 0, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	canary, err := f.store.CanaryCutover(ctx, shared.ID(tenant))
	if err != nil || !canary.Ready {
		t.Fatalf("canary=%+v err=%v", canary, err)
	}
	at := time.Now().UTC()
	if err = f.store.RecordCutoverWriterHeartbeat(ctx, shared.ID(tenant), "shared-authentication:configuration", "api", at); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.DeclareCutover(ctx, shared.ID(tenant), prepared.PolicyVersion, ports.IdentityCutoverEvidence{ShadowReportID: canary.ID, OldWriterGeneration: "shared-authentication:configuration", MigrationVersion: identityMigrationCeiling(t)}, "operator", at); err != nil {
		t.Fatal(err)
	}
	return legacyIdentityID("connection_", shared.ID(tenant), shared.ID(testIssuer))
}

func legacyConfigurationDraft(tenant string, id shared.ID, version int, secret string) ports.IdentityConnectionDraft {
	return ports.IdentityConnectionDraft{
		TenantID: shared.ID(tenant), ID: id, DisplayName: "Configured legacy issuer", Issuer: testIssuer, ExpectedVersion: version,
		Settings: ports.IdentityOIDCSettings{ClientID: "configured-client", RedirectURL: "https://app.example/api/auth/enterprise/callback", SealedClientSecret: secret},
	}
}

func mutateLegacyConfigurationScaffold(t *testing.T, f *identityFixture, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := f.admin.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertLegacyConfigurationDenied(t *testing.T, f *identityFixture, tenant string, id shared.ID) {
	t.Helper()
	beforeRevisions := f.adminCount(t, `SELECT count(*) FROM identity_connection_revisions WHERE tenant_id=$1`, tenant)
	beforeVersion := f.adminCount(t, `SELECT version FROM identity_connections WHERE tenant_id=$1 AND id=$2`, tenant, id.String())
	beforeMemberships := f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, tenant)
	if _, err := f.store.SaveIdentityConnectionDraft(context.Background(), legacyConfigurationDraft(tenant, id, beforeVersion, "sealed-denied"), bootstrapConnectionProof(tenant, time.Now().UTC())); err == nil {
		t.Fatal("invalid legacy scaffold accepted configuration")
	}
	if revisions := f.adminCount(t, `SELECT count(*) FROM identity_connection_revisions WHERE tenant_id=$1`, tenant); revisions != beforeRevisions {
		t.Fatalf("denied configuration changed revisions=%d want %d", revisions, beforeRevisions)
	}
	if version := f.adminCount(t, `SELECT version FROM identity_connections WHERE tenant_id=$1 AND id=$2`, tenant, id.String()); version != beforeVersion {
		t.Fatalf("denied configuration changed version=%d want %d", version, beforeVersion)
	}
	if memberships := f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, tenant); memberships != beforeMemberships {
		t.Fatalf("denied configuration changed memberships=%d want %d", memberships, beforeMemberships)
	}
	connections, err := f.store.ListIdentityConnections(context.Background(), shared.ID(tenant), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, connection := range connections {
		if connection.ConfigurationPending {
			t.Fatalf("invalid legacy scaffold exposed pending metadata=%+v", connection)
		}
	}
}

func TestLegacyConfigurationRejectsCorruptImporterScaffolds(t *testing.T) {
	for name, mutate := range map[string]func(*identityFixture, string, shared.ID){
		"wrong importer actor": func(f *identityFixture, tenant string, id shared.ID) {
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connection_revisions SET actor='other' WHERE tenant_id=$1 AND connection_id=$2 AND revision=1`, tenant, id.String())
		},
		"mismatched importer timestamp": func(f *identityFixture, tenant string, id shared.ID) {
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connection_revisions SET created_at=created_at+interval '1 second' WHERE tenant_id=$1 AND connection_id=$2 AND revision=1`, tenant, id.String())
		},
		"extra importer setting": func(f *identityFixture, tenant string, id shared.ID) {
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connection_revisions SET settings='{"issuer":"https://idp.example.test","provenance":"legacy_fixed_tenant_oidc","extra":"x"}' WHERE tenant_id=$1 AND connection_id=$2 AND revision=1`, tenant, id.String())
		},
		"partial importer marker": func(f *identityFixture, tenant string, id shared.ID) {
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connection_revisions SET settings='{"issuer":"https://idp.example.test"}' WHERE tenant_id=$1 AND connection_id=$2 AND revision=1`, tenant, id.String())
		},
		"null importer setting": func(f *identityFixture, tenant string, id shared.ID) {
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connection_revisions SET settings='{"issuer":null,"provenance":"legacy_fixed_tenant_oidc"}' WHERE tenant_id=$1 AND connection_id=$2 AND revision=1`, tenant, id.String())
		},
		"advanced epoch": func(f *identityFixture, tenant string, id shared.ID) {
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connections SET epoch=2 WHERE tenant_id=$1 AND id=$2`, tenant, id.String())
		},
		"enabled scaffold": func(f *identityFixture, tenant string, id shared.ID) {
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connections SET enabled=true WHERE tenant_id=$1 AND id=$2`, tenant, id.String())
		},
		"advanced active revision": func(f *identityFixture, tenant string, id shared.ID) {
			mutateLegacyConfigurationScaffold(t, f, `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at) VALUES($1,$2,2,'{}','other',CURRENT_TIMESTAMP)`, tenant, id.String())
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connections SET revision=2 WHERE tenant_id=$1 AND id=$2`, tenant, id.String())
		},
		"wrong deterministic identifier": func(f *identityFixture, tenant string, id shared.ID) {
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connections SET trust_namespace='https://other.example' WHERE tenant_id=$1 AND id=$2`, tenant, id.String())
			mutateLegacyConfigurationScaffold(t, f, `UPDATE identity_connection_revisions SET settings='{"issuer":"https://other.example","provenance":"legacy_fixed_tenant_oidc"}' WHERE tenant_id=$1 AND connection_id=$2 AND revision=1`, tenant, id.String())
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityFixture(t)
			tenant := "legacy-configuration-corrupt-" + identityRandomHex(t, 3)
			id := declareLegacyConfigurationTenant(t, f, tenant)
			mutate(f, tenant, id)
			assertLegacyConfigurationDenied(t, f, tenant, id)
		})
	}
}

func TestLegacyConfigurationRejectsUndeclaredAndContractedPhases(t *testing.T) {
	for _, phase := range []string{"legacy", "shadow", "contracted"} {
		t.Run(phase, func(t *testing.T) {
			f := newIdentityFixture(t)
			tenant := "legacy-configuration-phase-" + phase
			var id shared.ID
			if phase == "contracted" {
				id = declareLegacyConfigurationTenant(t, f, tenant)
				state, err := f.store.CutoverState(context.Background(), shared.ID(tenant))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.store.ContractCutover(context.Background(), shared.ID(tenant), state.PolicyVersion, "operator", time.Now().UTC()); err != nil {
					t.Fatal(err)
				}
			} else {
				f.tenants(t, tenant)
				f.seedIssued(t, tenant, "configuration-admin", user.RoleAdmin, false)
				f.backfill(t, tenant, 10)
				id = legacyIdentityID("connection_", shared.ID(tenant), shared.ID(testIssuer))
			}
			if phase == "shadow" {
				if _, err := f.store.PrepareCutover(context.Background(), shared.ID(tenant), 0, "operator", time.Now().UTC()); err != nil {
					t.Fatal(err)
				}
			}
			assertLegacyConfigurationDenied(t, f, tenant, id)
		})
	}
}

func TestLegacyImportedConnectionAcceptsFirstConfiguredDraftOnlyAfterDeclaredCutover(t *testing.T) {
	f := newIdentityFixture(t)
	const tenant = "legacy-configuration"
	id := declareLegacyConfigurationTenant(t, f, tenant)
	at := time.Now().UTC()
	proof := bootstrapConnectionProof(tenant, at)

	before, err := f.store.GetIdentityConnection(context.Background(), tenant, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if before.Enabled || before.Revision != 1 || before.DraftRevision != 1 || before.Version != 1 || before.Epoch != 1 {
		t.Fatalf("imported scaffold=%+v", before)
	}
	listed, err := f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(listed) != 1 || !listed[0].ConfigurationPending || listed[0].ConfigurationClientID != "" {
		t.Fatalf("initial configuration metadata=%+v err=%v", listed, err)
	}
	configured, err := f.store.SaveIdentityConnectionDraft(context.Background(), legacyConfigurationDraft(tenant, id, before.Version, "sealed-first"), proof)
	if err != nil {
		t.Fatal(err)
	}
	if configured.Enabled || configured.Revision != 1 || configured.DraftRevision != 2 || configured.Version != 2 || configured.Epoch != 1 || configured.Settings.ClientID != "configured-client" {
		t.Fatalf("configured pending connection=%+v", configured)
	}
	if !configured.ConfigurationPending || configured.ConfigurationClientID != "configured-client" {
		t.Fatalf("save did not return pending metadata=%+v", configured)
	}
	if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), legacyConfigurationDraft(tenant, id, before.Version, "sealed-stale"), proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale first-configuration version accepted: %v", err)
	}
	listed, err = f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(listed) != 1 || !listed[0].ConfigurationPending || listed[0].ConfigurationClientID != "configured-client" {
		t.Fatalf("configured metadata=%+v err=%v", listed, err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_connection_revisions WHERE tenant_id=$1 AND connection_id=$2`, tenant, id.String()); n != 2 {
		t.Fatalf("revisions=%d want 2", n)
	}
	if _, err = f.store.ActivateIdentityConnection(context.Background(), tenant, id, 2, configured.Version, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("activated without current test: %v", err)
	}
	if err = f.store.RecordIdentityConnectionTest(context.Background(), ports.IdentityConnectionTest{ID: "configured-test", TenantID: tenant, ConnectionID: id, Revision: 2, Passed: true, At: at.Add(time.Second), ExpiresAt: at.Add(30 * time.Minute)}, bootstrapConnectionProof(tenant, at.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	active, err := f.store.ActivateIdentityConnection(context.Background(), tenant, id, 2, configured.Version, bootstrapConnectionProof(tenant, at.Add(2*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if !active.Enabled || active.Revision != 2 || active.Epoch != 1 {
		t.Fatalf("activated configured connection=%+v", active)
	}
	listed, err = f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(listed) != 1 || listed[0].ConfigurationPending || listed[0].ConfigurationClientID != "" {
		t.Fatalf("activation retained pending metadata=%+v err=%v", listed, err)
	}
}

func TestLegacyImportedConnectionFirstConfigurationHasOneWinnerAndPinsConfiguredTrust(t *testing.T) {
	f := newIdentityFixture(t)
	const tenant = "legacy-configuration-concurrent"
	id := declareLegacyConfigurationTenant(t, f, tenant)
	at := time.Now().UTC()
	proof := bootstrapConnectionProof(tenant, at)
	draft := legacyConfigurationDraft(tenant, id, 1, "sealed-first")

	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.store.SaveIdentityConnectionDraft(context.Background(), draft, proof)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("concurrent first configuration = %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("first configuration winners=%d want 1", wins)
	}
	current, err := f.store.GetIdentityConnection(context.Background(), tenant, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	secretOnly := legacyConfigurationDraft(tenant, id, current.Version, "sealed-corrected")
	updated, err := f.store.SaveIdentityConnectionDraft(context.Background(), secretOnly, bootstrapConnectionProof(tenant, at.Add(time.Second)))
	if err != nil || updated.DraftRevision != 3 {
		t.Fatalf("pending secret correction=%+v err=%v", updated, err)
	}
	f.exec(t, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at)
		VALUES($1,'stale-configuration-test',$2,2,'passed',$3,$4)`, tenant, id.String(), at, at.Add(time.Hour))
	if _, err = f.store.ActivateIdentityConnection(context.Background(), tenant, id, 2, updated.Version, bootstrapConnectionProof(tenant, at.Add(2*time.Second))); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale configured revision activated after secret correction: %v", err)
	}
	listed, err := f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(listed) != 1 || !listed[0].ConfigurationPending {
		t.Fatalf("pending secret correction metadata=%+v err=%v", listed, err)
	}
	for _, mutate := range []func(*ports.IdentityConnectionDraft){
		func(d *ports.IdentityConnectionDraft) { d.Settings.ClientID = "other-client" },
		func(d *ports.IdentityConnectionDraft) { d.Settings.RedirectURL = "https://other.example/callback" },
		func(d *ports.IdentityConnectionDraft) { d.Settings.Auth0OrganizationID = "org_restricted" },
	} {
		candidate := legacyConfigurationDraft(tenant, id, updated.Version, "sealed-again")
		mutate(&candidate)
		if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), candidate, bootstrapConnectionProof(tenant, at.Add(2*time.Second))); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("pending trust change = %v, want conflict", err)
		}
	}
	afterPinnedRejections, err := f.store.GetIdentityConnection(context.Background(), tenant, id, 0)
	if err != nil || afterPinnedRejections.DraftRevision != updated.DraftRevision || afterPinnedRejections.Version != updated.Version {
		t.Fatalf("pending trust rejection mutated scaffold=%+v err=%v", afterPinnedRejections, err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_connection_revisions WHERE tenant_id=$1 AND connection_id=$2`, tenant, id.String()); n != 3 {
		t.Fatalf("pending trust rejections appended revisions=%d", n)
	}
	f.exec(t, `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at)
		VALUES($1,$2,4,'{"client_id":"forged-client","redirect_url":"https://app.example/api/auth/enterprise/callback","sealed_client_secret":"sealed"}','admin',$3)`, tenant, id.String(), at.Add(2*time.Second))
	listed, err = f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(listed) != 1 || listed[0].ConfigurationPending {
		t.Fatalf("mismatched configured history retained metadata=%+v err=%v", listed, err)
	}
	if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), legacyConfigurationDraft(tenant, id, updated.Version, "sealed-again"), bootstrapConnectionProof(tenant, at.Add(2*time.Second))); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("mismatched configured history accepted draft: %v", err)
	}
}

func TestLegacyConfigurationMetadataSkipsNativeRevisionHistory(t *testing.T) {
	f := newIdentityFixture(t)
	const tenant = "legacy-configuration-native-history"
	f.tenants(t, tenant)
	now := time.Now().UTC()
	f.exec(t, `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name,enabled,revision,epoch,version,created_at,updated_at)
		SELECT $1,'native-'||lpad(n::text,3,'0'),'oidc','https://native-'||n::text||'.example','Native',false,1,1,32,$2,$2
		FROM generate_series(1,100) AS n`, tenant, now)
	f.exec(t, `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at)
		SELECT $1,'native-'||lpad(connection::text,3,'0'),revision,
		jsonb_build_object('client_id','native-'||connection::text,'redirect_url','https://app.example/callback','sealed_client_secret','sealed-'||revision::text),'native',$2
		FROM generate_series(1,100) AS connection CROSS JOIN generate_series(1,32) AS revision`, tenant, now)
	f.declare(t, tenant)

	connections, err := f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(connections) != 100 {
		t.Fatalf("native connections=%d err=%v", len(connections), err)
	}
	ids := make([]string, 0, len(connections))
	for _, connection := range connections {
		if connection.ConfigurationPending || connection.ConfigurationClientID != "" {
			t.Fatalf("native connection exposed pending metadata=%+v", connection)
		}
		ids = append(ids, connection.ID.String())
	}
	if err := f.store.withIdentityTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		states, err := loadLegacyConfigurationStates(context.Background(), tx, tenant, ids)
		if err != nil {
			return err
		}
		if len(states) != 0 {
			t.Fatalf("native revision history crossed metadata boundary: %d states", len(states))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

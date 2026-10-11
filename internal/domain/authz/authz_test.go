package authz

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

func bootstrapPrincipal() Principal {
	return Principal{ActorID: BootstrapActorID, Role: user.RoleAdmin, Credential: Credential{Kind: KindBootstrap}, Provenance: "bearer"}
}

func member(role user.Role, kind CredentialKind) Principal {
	return Principal{ActorID: "u-1", TenantID: "tenant-a", Role: role, Credential: Credential{Kind: kind}}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name   string
		p      Principal
		a      Action
		allow  bool
		reason string
	}{
		{"missing principal", Principal{}, Action{Permission: user.PermView}, false, ReasonUnauthenticated},
		{"missing principal on no-role action", Principal{}, Action{}, false, ReasonUnauthenticated},
		{"unknown credential kind", Principal{ActorID: "u", TenantID: "t", Role: user.RoleAdmin, Credential: Credential{Kind: "token"}}, Action{Permission: user.PermView}, false, ReasonInvalidCredential},
		{"operator id without bootstrap credential", Principal{ActorID: BootstrapActorID, TenantID: "default", Role: user.RoleAdmin, Credential: Credential{Kind: KindAPIKey}}, Action{Permission: user.PermView}, false, ReasonInvalidCredential},
		{"bootstrap credential on another actor", Principal{ActorID: "u", Role: user.RoleAdmin, Credential: Credential{Kind: KindBootstrap}}, Action{Permission: user.PermView}, false, ReasonInvalidCredential},
		{"api key without tenant", Principal{ActorID: "u", Role: user.RoleAdmin, Credential: Credential{Kind: KindAPIKey}}, Action{Permission: user.PermView}, false, ReasonNoMembership},
		{"role floor grants", member(user.RoleConsultant, KindAPIKey), Action{Permission: user.PermOperate}, true, ReasonAllowed},
		{"role floor denies", member(user.RoleReadOnly, KindBrowserSession), Action{Permission: user.PermOperate}, false, ReasonPermissionNotGranted},
		{"authenticated no-role action", member(user.RoleReadOnly, KindAPIKey), Action{}, true, ReasonAllowed},
		{"machine role gets nothing", member("agent", KindAPIKey), Action{Permission: user.PermView}, false, ReasonPermissionNotGranted},
		{"integration admin manages integrations", member(user.RoleIntegrationAdmin, KindBrowserSession), Action{Permission: user.PermManageIntegrations}, true, ReasonAllowed},
		{"integration admin is not an administrator", member(user.RoleIntegrationAdmin, KindBrowserSession), Action{Permission: user.PermAdminister}, false, ReasonPermissionNotGranted},
		{"integration admin cannot operate", member(user.RoleIntegrationAdmin, KindAPIKey), Action{Permission: user.PermOperate}, false, ReasonPermissionNotGranted},
		{"platform-only for bootstrap", bootstrapPrincipal(), Action{Permission: user.PermAdminister, PlatformOnly: true}, true, ReasonAllowed},
		{"platform-only denies tenant admin key", member(user.RoleAdmin, KindAPIKey), Action{Permission: user.PermAdminister, PlatformOnly: true}, false, ReasonPlatformOnly},
		{"platform-only denies tenant admin session", member(user.RoleAdmin, KindBrowserSession), Action{Permission: user.PermAdminister, PlatformOnly: true}, false, ReasonPlatformOnly},
		{"break glass reaches logout", member(user.RoleAdmin, KindBreakGlass), Action{Recovery: RecoveryLogout}, true, ReasonAllowed},
		{"break glass restores a role", member(user.RoleAdmin, KindBreakGlass), Action{Permission: user.PermAdminister, Recovery: RecoveryAssignRole}, true, ReasonAllowed},
		{"break glass cannot read data", member(user.RoleAdmin, KindBreakGlass), Action{Permission: user.PermView}, false, ReasonRecoveryOnly},
		{"break glass cannot run scans", member(user.RoleAdmin, KindBreakGlass), Action{Permission: user.PermOperate}, false, ReasonRecoveryOnly},
		{"break glass cannot manage integrations", member(user.RoleAdmin, KindBreakGlass), Action{Permission: user.PermManageIntegrations}, false, ReasonRecoveryOnly},
		{"break glass cannot mint keys", member(user.RoleAdmin, KindBreakGlass), Action{Permission: user.PermAdminister, Recovery: "rotate_key"}, false, ReasonRecoveryOnly},
		{"break glass cannot link identities", member(user.RoleAdmin, KindBreakGlass), Action{Permission: user.PermAdminister, Recovery: "link_identity"}, false, ReasonRecoveryOnly},
		{"break glass cannot reach platform-only recovery", member(user.RoleAdmin, KindBreakGlass), Action{Permission: user.PermAdminister, PlatformOnly: true, Recovery: RecoveryAssignRole}, false, ReasonRecoveryOnly},
		{"break glass still needs the role", member(user.RoleReadOnly, KindBreakGlass), Action{Permission: user.PermAdminister, Recovery: RecoveryAssignRole}, false, ReasonPermissionNotGranted},
		{"recovery tag does not widen an ordinary credential", member(user.RoleReadOnly, KindAPIKey), Action{Permission: user.PermAdminister, Recovery: RecoveryAssignRole}, false, ReasonPermissionNotGranted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(tc.p, tc.a)
			if got.Allowed != tc.allow || got.Reason != tc.reason {
				t.Fatalf("Decide() = %+v, want allowed=%v reason=%q", got, tc.allow, tc.reason)
			}
		})
	}
}

func TestDecideUnderSSORequired(t *testing.T) {
	cases := []struct {
		name  string
		p     Principal
		allow bool
	}{
		{"browser session is SSO", member(user.RoleReadOnly, KindBrowserSession), true},
		{"legacy bearer key keeps its grace", member(user.RoleReadOnly, KindAPIKey), true},
		{"bootstrap is exempt", bootstrapPrincipal(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideUnder(SSORequired, tc.p, Action{Permission: user.PermView}); got.Allowed != tc.allow {
				t.Fatalf("DecideUnder(required) = %+v, want allowed=%v", got, tc.allow)
			}
		})
	}
	if got := DecideUnder("unknown", member(user.RoleAdmin, KindBrowserSession), Action{}); got.Allowed || got.Reason != ReasonSSORequired {
		t.Fatalf("unknown SSO requirement must fail closed: %+v", got)
	}
}

func TestRecoveryAllowlistIsClosed(t *testing.T) {
	want := map[RecoveryAction]bool{RecoveryLogout: true, RecoveryReadSelf: true, RecoveryListUsers: true, RecoveryAssignRole: true, RecoveryDisableUser: true, RecoveryEnableUser: true, RecoveryReadIdentity: true, RecoveryRepairConnection: true, RecoveryRelaxSSO: true}
	got := RecoveryActions()
	if len(got) != len(want) {
		t.Fatalf("recovery allowlist = %v, want exactly %d actions", got, len(want))
	}
	for _, action := range got {
		if !want[action] {
			t.Errorf("unexpected recovery action %q", action)
		}
	}
	for _, denied := range []RecoveryAction{"", "switch_organization", "link_identity", "rotate_key", "create_user", "run_scan", "manage_fleet", "manage_integrations"} {
		if denied.Allowed() {
			t.Errorf("recovery allowlist admits %q", denied)
		}
	}
}

func TestRecentlyAuthenticated(t *testing.T) {
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	session := member(user.RoleAdmin, KindBrowserSession)
	session.AuthenticatedAt = at
	cases := []struct {
		name string
		p    Principal
		now  time.Time
		want bool
	}{
		{"inside window", session, at.Add(14 * time.Minute), true},
		{"at window end", session, at.Add(15 * time.Minute), false},
		{"future authentication", session, at.Add(-time.Second), false},
		{"zero time", member(user.RoleAdmin, KindBrowserSession), at, false},
		{"bootstrap never recent", func() Principal { p := bootstrapPrincipal(); p.AuthenticatedAt = at; return p }(), at, false},
		{"api key never recent", func() Principal { p := member(user.RoleAdmin, KindAPIKey); p.AuthenticatedAt = at; return p }(), at, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RecentlyAuthenticated(tc.p, tc.now); got != tc.want {
				t.Fatalf("RecentlyAuthenticated() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCredentialKindsAreClosed(t *testing.T) {
	for _, kind := range []CredentialKind{KindBootstrap, KindAPIKey, KindBrowserSession, KindBreakGlass} {
		if !kind.Valid() || SourceOf(kind) == "" {
			t.Errorf("credential kind %q has no policy row", kind)
		}
	}
	if CredentialKind("hook_signature").Valid() {
		t.Fatal("a webhook signature must never be a human credential kind")
	}
}

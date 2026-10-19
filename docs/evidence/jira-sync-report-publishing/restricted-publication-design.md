# Automatic restricted publication

Cloud V1 rejects a group-only restriction as self-eviction even when the actor is
a member of that group and the group has effective space read and update rights.
A content-free live probe established the documented Cloud V2 alternative:
replace direct permissions with the configured group's update grant, then set
`VIEW_RESTRICTED`. Both writes keep the provider's default self-lockout protection.

The adapter retains the existing neutral shell and persisted restrictions
checkpoint. It introduces no new port, executor, retry state, or permission grant
inside Synapse. A refusal or ambiguous write stops before content upload.

Before each sensitive upload, Cloud verification requires `VIEW_RESTRICTED` and
an unfiltered, complete V2 permission result containing exactly the configured
group. A sole read grant remains valid for existing restricted pages. The existing
V1 read/update ACL checks and published public-link blocking policy must also
verify; disagreement, missing fields, extra principals, or pagination fails closed.

Data Center has the same direct-user-only REST guard on the tested 10.2 release.
Atlassian documents `setContentPermissions` as a workaround in
[CONFSERVER-56405](https://jira.atlassian.com/browse/CONFSERVER-56405).
An explicit `legacy_xmlrpc_restrictions` option uses that compatibility path with
the existing PAT and trusted origin. The deployment operator must enable the
authenticated Remote API separately and keep anonymous access disabled. The
adapter does not change provider settings or fall back after a REST failure.

The tested 10.2.17 server accepts PAT ambient authentication with an empty RPC
token, numeric `i8` page IDs, and exact group View/Edit permissions. Both operations
were proved on a content-free page and independently read back through REST with
zero direct users. Runtime version and membership checks must precede writes;
unknown XML or an uncertain response must stop before content. The protocol is
deprecated and planned for removal in Confluence 11, so this mode is limited to
the verified 10.2 line. Provider acceptance must still demonstrate normal fresh
publication without manual ACL repair.

The [Cloud V2 permissions contract](https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-content-permissions/)
separates direct grants from restriction state. Existing deployments need that API
available; an unsupported endpoint fails closed rather than selecting a weaker
fallback. Rollback retains neutral shells and existing command receipts.

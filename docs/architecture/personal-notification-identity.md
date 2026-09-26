# Personal notification identity and canonical assignee

`findings.assignee_user_id` is the authoritative user reference for personal
notification routing. `findings.assignee` remains the legacy display/write field.
`ownership_assignments.assignee_id` remains the ownership workflow's decision
projection and is written in the same transaction as the finding. Recipient
resolution reads only the finding's canonical user ID. It never guesses a person
from the legacy label, notification payload, email address, or display name at
send time.

Migration backfills a same-tenant exact user ID first, then an exact display
name only if it identifies one user in that tenant. Ambiguous and unmatched
labels remain visible with a null canonical ID and a bounded review table. A
disabled user's historical binding may survive; eligibility is rechecked before
new assignment and before delivery. A trigger on the legacy finding field is
the rolling-deploy bridge: a changed free-text label clears the canonical ID;
an exact enabled user ID binds it. This prevents old binaries from leaving a
stale personal destination. Typed ownership writes set both fields inside the
existing revision-guarded assignment transaction. No email, fuzzy-name, or
case-insensitive inference is performed.

Self-managed contacts and OIDC-imported contacts are separate records. An OIDC
address is imported only after issuer/subject resolves an existing or newly
provisioned user and only if the signed `email_verified` claim is the JSON
boolean true. A later unverified claim revokes that provider-managed contact.
Contact versions fence queued mail; the queue payload contains only a challenge
ID. User and tenant scope are derived from the authenticated principal at the
HTTP boundary and rechecked in PostgreSQL under RLS.

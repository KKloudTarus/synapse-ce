# Durable Jira status comments

Problem: the live Cloud fixture accepted a bundled status transition with HTTP
204 but omitted its comment. The dedicated comment endpoint returned HTTP 201,
and a read by the returned comment ID confirmed persistence. A transition receipt
therefore cannot establish the explanatory comment required for status sync.

Decision criteria fixed before review: correctness/idempotency 40, recovery 25,
application boundaries 20, and change scope 15.

Use the existing `Comment` action and durable intent store. New status episodes
perform transition → dedicated comment → field refresh. Derive the comment request
key from the existing episode; a new progress table or queue is unnecessary.
Version the immutable snapshot semantics and preserve legacy bundled commands.
Do not automatically backfill comments for a legacy completed transition: another
Jira deployment may already have persisted its unmarked bundled comment.

Freeze the parent transition, episode, source facts and integration author. Before
each comment write, verify the current progress still names that exact completed
transition, together with current tenant, mapping, destination, credential, scope
and privacy authority. Repeated close/reopen states must not admit an old episode.

The Jira adapter owns literal Cloud ADF / Data Center text, credential checks,
bounded receipts and comment reads. A receipt must identify the actual comment;
the intent's remote identity remains the issue key, because completion links refer
to issues. Recovery matches the exact issue, author, complete body and unique
intent marker. Issue labels and current status cannot prove comment delivery.
Zero, duplicate, malformed, truncated or unreadable results leave uncertainty.
Lost acknowledgement never permits automatic resend.

Putting the comment inside a field update lacks an independently validated comment
receipt and still needs comment-specific recovery. Refusing all screenless
transitions would leave this proven dedicated-endpoint path unsupported. Neither
alternative is a smaller complete implementation of the acceptance requirement.

Validate stage ordering, concurrent planners, lost acknowledgements, exact recovery
proof, stale episodes and configuration, body/author forgery, pagination limits,
legacy commands and crash recovery before repeating real provider acceptance.

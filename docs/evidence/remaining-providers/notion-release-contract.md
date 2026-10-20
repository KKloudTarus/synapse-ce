# Notion release contract feasibility

Checked on 20 October 2026 against issue #1446, the B08 document step and the
EPIC WS6 release-control contract. Native Notion publication remains an open product requirement. The maintainer
adapted this draft delivery to connection checks and early release refusal, with
native publication retained as a provider-blocked follow-up in #1446. E2E is
deferred. The current draft does not claim native Notion publication is implemented.

## Required provider evidence

The shared release executor requires a current, complete effective read ACL for
both the configured parent and created page before any report bytes or attachments
are uploaded. The configured reader group must be proved, including inherited,
workspace, guest and public access. Subsequent writes and monitoring repeat that
proof. Unpublish must permanently remove report versions and attachments; a
restorable Trash result or an inaccessible object is insufficient.

These requirements come from the existing release controls and the maintainer's
instructions. A successful integration login, a configured group ID, a private
page location or a null public URL does not establish the complete effective ACL.

## Official surfaces inspected

| Surface | Actual contract | Consequence |
| --- | --- | --- |
| [Page object](https://developers.notion.com/reference/page) | Identity, parent, properties and public URL; no complete effective page ACL. | Cannot implement the required read-only restriction proof. |
| [Trash page](https://developers.notion.com/reference/trash-page) | Trash and restore are supported; permanent page deletion is not. | Cannot acknowledge permanent unpublish. |
| [Delete block](https://developers.notion.com/reference/delete-a-block) | Sets the block, including page blocks, to `in_trash`; content remains restorable. | Deleting blocks does not supply permanent-purge evidence. |
| [Update page](https://developers.notion.com/reference/patch-page) | `erase_content` clears existing page content. | No documented assertion that versions and uploaded files are permanently erased. |
| [Admin API](https://developers.notion.com/reference/admin/intro) and [scopes](https://developers.notion.com/reference/admin/scopes) | Groups/membership, users, legal holds, exports and Custom Agent controls. | Group membership is not a page grant; releasing a legal hold is not a purge. |
| [MCP tools](https://developers.notion.com/guides/mcp/mcp-supported-tools) | Page/database delete moves objects to restorable Trash. | MCP does not bridge permanent purge. |
| [Workers API client](https://developers.notion.com/workers/guides/api-client) | Uses the Notion SDK and its API contract. | No separate privileged ACL or purge contract established. |

The official [documentation index](https://developers.notion.com/llms.txt) also
links three OpenAPI specifications. All were downloaded and inspected. The
internal specification includes `PATCH /v1/_/pages/{page_id}/permissions`, but
explicitly excludes production reliance. Its success schema permits a partial
page containing only object type and ID; even the full page schema contains no
ACL. There is no corresponding GET page-permissions operation. Workspace search
can filter by a sharing ID but does not return the complete effective grants.
Teamspace permissions describe the teamspace rather than an individual page.
No permanent page/version/attachment purge operation appears in these specs.

## Current implementation boundary

`documentproviders/notion.go` supports a pinned-origin, sealed-token connection
check and explicitly refuses release before artifacts or shells are created.
It advertises no Documents capability. This preserves safety but does not fulfill
issue #1446 and must not be labeled a completed Notion destination.

A production implementation still needs an authoritative Notion contract for
complete effective page ACL readback and irreversible version/attachment purge.
A new bridge without an implementation of those provider operations, guessed
endpoints, operator assertions or mocked success responses would not close this
gap. No such substitute has been added. All other current Docker checks remain
valid; this research changes no runtime source.

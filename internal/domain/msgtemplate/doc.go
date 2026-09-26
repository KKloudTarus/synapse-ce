// Package msgtemplate is the safe template engine for tenant-editable message content, such as
// notification messages and ticket bodies.
//
// Tenant administrators write the templates, and scanned data (finding titles, hosts, advisory
// text) fills them, so neither side is trusted. The engine enforces four properties:
//
//   - Deny by default. Templates are parsed with text/template/parse and every node of the tree is
//     checked against an allowlist before a template is accepted. Unknown node types, including any
//     a future Go release adds, are rejected. Only allowlisted functions may be called.
//   - Closed data. Every variable must be declared in a Schema, and the render context is built from
//     flat string maps only, so a template can never reach a method, a struct or a secret.
//   - Bounded cost. Source size, node count, nesting, the iteration product and a weighted
//     evaluation cost are bounded statically, and output is capped per field at render time.
//   - Literal values. Every interpolated value is sanitized and escaped against the Markdown subset,
//     so markup and links can only come from the template's literal text.
//
// Function arguments are type-checked at compile time, so a compiled template can only fail at
// render time on a runtime value. Errors carry a stable Code and never a rendered value.
//
// The package is stdlib only, performs no I/O, and imports neither the notification nor the
// ticketing packages that use it.
package msgtemplate

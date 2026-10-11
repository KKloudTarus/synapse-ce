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
//   - Bounded cost. Source size, node count, nesting and the iteration product are bounded
//     statically, and so is the work of every function call, weighted by the length bounds of its
//     inputs (cost.go). A per-render meter enforces the same budget again (meter.go), and output is
//     capped per field.
//   - Literal values. Every interpolated value is sanitized and escaped (escape.go).
//
// # Escaping contract
//
// Output is an intermediate CommonMark representation of the message Markdown subset (bold, italic,
// inline code, bullet lists). Channel formatters parse it, honouring backslash escapes, and emit
// each channel's own syntax and escaping. The escape step runs at the end of every output action,
// so:
//
//   - Markup can only come from literal template text outside an action. A string argument to a
//     function is data: {{.owner | default "**none**"}} prints the asterisks. Write a formatted
//     fallback as {{with .owner}}{{.}}{{else}}**none**{{end}}.
//   - An action may not sit between backticks (`{{.cve}}`), because CommonMark shows escapes
//     literally inside a code span and a backtick in the value would end the span early.
//   - An empty value leaves the delimiters around it adjacent, so **{{.x}}** becomes ****. The
//     subset has no thematic breaks or fences, so a formatter shows that as text; guard optional
//     values with {{with}} to keep the message tidy.
//   - Bare URLs and email addresses in values are escaped against CommonMark and GFM autolinks, but
//     chat clients linkify plain text on their own. Neutralizing links in a given client (a code
//     span, defanging) is the job of that channel's formatter.
//
// Function arguments are type-checked at compile time, so a compiled template can only fail at
// render time on a runtime value. Errors carry a stable Code and never a rendered value.
//
// The package performs no I/O and imports only the standard library and package textsafety. It does
// not import the notification or ticketing packages that use it.
package msgtemplate

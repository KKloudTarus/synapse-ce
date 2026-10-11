// Package siem is the pure model for durable audit and incident export.
//
// Streams are not notification deliveries. A sink has one open batch per
// source partition. The cursor advances only over a contiguous handled prefix
// after the remote result is stored. A broken source chain stops that
// partition; it is never skipped. Export acknowledgements are not written
// back into the audit log, because that would feed the stream forever.
//
// The v2 audit hash is audit.ComputeHash of the entry content. It does not
// include tenant_id. Tenant isolation is the per-tenant previous-hash link
// and the row-level policy, not a claim that the digest itself names the
// tenant. A remote payload cannot be used to recompute that hash after
// redaction; the exported source hash is a reference to the local chain.
package siem

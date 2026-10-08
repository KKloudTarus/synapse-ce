# Pinned OCSF finding schemas

The three JSON Schema documents are byte-for-byte snapshots from the OCSF schema
server for OCSF **1.5.0**. `manifest.json` records each download URL and SHA-256,
the upstream release tag `1.5.0`, and its commit
`78bf68a24b38c0d6441ddd13b9028c1b1eb53f07`. The tag has no `v` prefix.
The upstream Apache-2.0 LICENSE and NOTICE accompany these artifacts.

Detection (2004) and vulnerability (2002) snapshots contain all optional profiles.
The upstream generator makes the cloud and osint fields required in that combined
view. Synapse emits neither profile: the validator compiles the base class by
removing only those two profile requirements. It keeps every property, definition,
reference, enum and object constraint from the upstream document. The domain
contract rejects optional profiles on these exports. Incident (2005) was downloaded
with the incident profile selected and compiles without adjustment; the domain
contract requires `metadata.profiles = ["incident"]`.

`jsonschema/v6` validates Draft 7, including nested objects, array items,
additional properties, `anyOf`, `oneOf` and `not`. Compilation uses an offline
loader that refuses external references. Mapper-specific constraints (version,
producer, class/type/activity relationships and nonempty identities) supplement
schema validation. Validation errors are reduced to a fixed diagnostic before
storage, so source values cannot appear in errors or attempt records.

To upgrade, choose a new upstream release and commit, download all three URLs
with the intended profiles, update the manifest checksums and domain version/tag,
and run the schema, source and mapping tests. Do not rewrite the vendored JSON
files to fit an invalid mapping. `TestVendoredSchemaProvenance` checks artifact
integrity; `TestSchemasValidateEveryExportedClass` checks actual mapper output.

package identity

// HumanPrincipal is the protocol-neutral authenticated-human identity carried across the human
// request plane. It deliberately contains only the legacy fields D1 can prove today; later
// organization-identity slices extend this type with membership, credential, authentication and
// revocation provenance rather than creating adapter-specific principal shapes.
//
// An empty ID is never authenticated. Bootstrap/operator authority is represented by an explicit
// authenticated principal whose ID is the bootstrap ID; absence of this value carries no authority.
type HumanPrincipal struct {
	ID       string
	Name     string
	Role     string
	TenantID string
}

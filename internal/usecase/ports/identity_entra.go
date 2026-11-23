package ports

import (
	"fmt"
	"regexp"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var entraIssuerPattern = regexp.MustCompile(`^https://login\.microsoftonline\.com/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/v2\.0$`)

// EntraDirectoryID returns the tenant ID only for the canonical public-cloud v2 issuer.
func EntraDirectoryID(issuer string) (string, bool) {
	match := entraIssuerPattern.FindStringSubmatch(issuer)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// ValidateEntraSettings binds alias metadata discovery to a canonical tenant authority.
func ValidateEntraSettings(issuer, mode, auth0OrganizationID string) error {
	if mode != "" && mode != "common" && mode != "organizations" {
		return fmt.Errorf("%w: invalid Entra discovery mode", shared.ErrValidation)
	}
	_, entra := EntraDirectoryID(issuer)
	if (mode != "" && !entra) || (entra && auth0OrganizationID != "") {
		return fmt.Errorf("%w: incompatible Entra connection settings", shared.ErrValidation)
	}
	return nil
}

package ports

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestEntraSettings(t *testing.T) {
	const issuer = "https://login.microsoftonline.com/01234567-89ab-cdef-0123-456789abcdef/v2.0"
	for _, tc := range []struct {
		issuer, mode, org string
		valid             bool
	}{
		{issuer, "", "", true}, {issuer, "common", "", true}, {issuer, "organizations", "", true},
		{issuer, "Common", "", false}, {issuer, "common", "org_abc", false}, {issuer, "", "org_abc", false},
		{"https://example.com", "common", "", false}, {"https://example.com", "", "org_abc", true},
	} {
		err := ValidateEntraSettings(tc.issuer, tc.mode, tc.org)
		if (err == nil) != tc.valid || (err != nil && !errors.Is(err, shared.ErrValidation)) {
			t.Errorf("ValidateEntraSettings(%q,%q,%q)=%v", tc.issuer, tc.mode, tc.org, err)
		}
	}
	if id, ok := EntraDirectoryID(issuer); !ok || id != "01234567-89ab-cdef-0123-456789abcdef" {
		t.Fatalf("directory=%q ok=%v", id, ok)
	}
	for _, value := range []string{issuer + "/", issuer + "?x=1", "https://login.microsoftonline.com/01234567-89AB-cdef-0123-456789abcdef/v2.0", "https://login.microsoftonline.com/common/v2.0", "https://login.microsoftonline.com.evil/01234567-89ab-cdef-0123-456789abcdef/v2.0"} {
		if _, ok := EntraDirectoryID(value); ok {
			t.Errorf("accepted %q", value)
		}
	}
}

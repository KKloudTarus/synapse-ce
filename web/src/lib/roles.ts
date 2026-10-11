// Console mirrors of the server's permission buckets (internal/domain/user/user.go). The server is
// the authority and answers 403 on its own; these only decide which controls the console offers.

/** Holds `administer`: user management, and creating or re-pointing an integration destination. */
export function isAdminRole(role: string | undefined): boolean {
  return role === 'admin' || role === 'owner'
}

/**
 * Holds `manage_integrations` (#1358): read and test channels, edit rules and templates, read
 * delivery history, and operate CI and SIEM integrations. Admin keeps it; integration_admin adds it
 * without `administer`, so creating a destination or changing its URL, secret or recipients stays
 * admin-only.
 */
export function canManageIntegrations(role: string | undefined): boolean {
  return isAdminRole(role) || role === 'integration_admin'
}

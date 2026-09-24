import type { AupStatus, CurrentUser, User, UserRole } from '../types'
import { req } from './client'

export const authApi = {
  aup: (): Promise<AupStatus> => req('/aup'),

  acceptAup: (version: string): Promise<unknown> =>
    req('/aup/accept', { method: 'POST', body: JSON.stringify({ version }) }),

  me: async (): Promise<CurrentUser> => {
    const value = await req('/me')
    return {
      id: value.id ?? '', name: value.name ?? '', role: value.role ?? '',
      features: value.features ? {
        assessmentLifecycleRead: Boolean(value.features.assessment_lifecycle_read),
        assessmentLifecycleUIDefault: Boolean(value.features.assessment_lifecycle_ui_default),
      } : undefined,
    }
  },
}

export const teamApi = {
  listUsers: async (): Promise<User[]> => (await req('/users')) ?? [],

  // Sends only the fields being changed. The server treats an empty name as "leave it alone"
  // (users/service.go update), so echoing back a name from a roster snapshot would silently revert
  // a rename another admin made after this screen loaded, and attribute the reversion to whoever
  // changed the role.
  updateUser: async (id: string, role: UserRole): Promise<User> =>
    await req(`/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ role }) }),

  // Disabling is how access is revoked; the account and its audit trail are kept.
  setUserDisabled: async (id: string, disabled: boolean): Promise<User> =>
    await req(`/users/${encodeURIComponent(id)}/${disabled ? 'disable' : 'enable'}`, { method: 'POST' }),

  // Returns the new key exactly once. The server keeps only its hash, so a caller that loses the
  // response cannot recover the key and must rotate again.
  rotateUserAPIKey: async (id: string): Promise<{ user: User; apiKey: string }> =>
    await req(`/users/${encodeURIComponent(id)}/rotate-key`, { method: 'POST' }),

  createUser: async (name: string, role: UserRole): Promise<{ user: User; apiKey: string }> =>
    req('/users', { method: 'POST', body: JSON.stringify({ name, role }) }),
}

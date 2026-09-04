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

  createUser: async (name: string, role: UserRole): Promise<{ user: User; apiKey: string }> =>
    req('/users', { method: 'POST', body: JSON.stringify({ name, role }) }),
}

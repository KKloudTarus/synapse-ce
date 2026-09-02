import type { AupStatus, CurrentUser, User, UserRole } from '../types'
import { req } from './client'

export const authApi = {
  aup: (): Promise<AupStatus> => req('/aup'),

  acceptAup: (version: string): Promise<unknown> =>
    req('/aup/accept', { method: 'POST', body: JSON.stringify({ version }) }),

  me: async (): Promise<CurrentUser> => req('/me'),
}

export const teamApi = {
  listUsers: async (): Promise<User[]> => (await req('/users')) ?? [],

  createUser: async (name: string, role: UserRole): Promise<{ user: User; apiKey: string }> =>
    req('/users', { method: 'POST', body: JSON.stringify({ name, role }) }),
}

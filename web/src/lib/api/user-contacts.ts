import { req } from './client'

export type UserContact = {
  id: string
  /** email, a Slack account (#1419) or a Microsoft Teams account (#1420). */
  kind: 'email' | 'slack' | 'teams'
  source: 'manual' | 'oidc'
  /** An email address, a Slack team_id:member_id pair, or a Microsoft Entra object ID. */
  value: string
  verified_at?: string
  version: number
  created_at: string
  updated_at: string
}

/** The personal channels this deployment can link (#1419, #1420). */
export type PersonalChannels = {
  slack: { available: boolean; workspaces: { team_id: string; team_name: string }[] }
  teams: { available: boolean }
}

const id = (value: string) => encodeURIComponent(value)

export const userContactsApi = {
  listMyContacts: (): Promise<UserContact[]> => req('/me/contacts'),
  addMyEmail: (value: string): Promise<UserContact> => req('/me/contacts', { method: 'POST', body: JSON.stringify({ kind: 'email', value }) }),
  addMySlack: (teamID: string, memberID: string): Promise<UserContact> =>
    req('/me/contacts', { method: 'POST', body: JSON.stringify({ kind: 'slack', team_id: teamID, member_id: memberID }) }),
  linkMyTeams: (code: string): Promise<UserContact> => req('/me/contacts/teams', { method: 'POST', body: JSON.stringify({ code }) }),
  myPersonalChannels: (): Promise<PersonalChannels> => req('/me/personal-channels'),
  deleteMyContact: (contactID: string): Promise<void> => req(`/me/contacts/${id(contactID)}`, { method: 'DELETE' }),
  requestMyContactVerification: (contactID: string): Promise<void> => req(`/me/contacts/${id(contactID)}/verification`, { method: 'POST' }),
  verifyMyContact: (contactID: string, code: string): Promise<UserContact> => req(`/me/contacts/${id(contactID)}/verify`, { method: 'POST', body: JSON.stringify({ code }) }),
}

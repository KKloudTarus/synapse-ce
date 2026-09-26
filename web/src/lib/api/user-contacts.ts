import { req } from './client'

export type UserContact = {
  id: string
  kind: 'email'
  source: 'manual' | 'oidc'
  value: string
  verified_at?: string
  version: number
  created_at: string
  updated_at: string
}

const id = (value: string) => encodeURIComponent(value)

export const userContactsApi = {
  listMyContacts: (): Promise<UserContact[]> => req('/me/contacts'),
  addMyEmail: (value: string): Promise<UserContact> => req('/me/contacts', { method: 'POST', body: JSON.stringify({ kind: 'email', value }) }),
  deleteMyContact: (contactID: string): Promise<void> => req(`/me/contacts/${id(contactID)}`, { method: 'DELETE' }),
  requestMyContactVerification: (contactID: string): Promise<void> => req(`/me/contacts/${id(contactID)}/verification`, { method: 'POST' }),
  verifyMyContact: (contactID: string, code: string): Promise<UserContact> => req(`/me/contacts/${id(contactID)}/verify`, { method: 'POST', body: JSON.stringify({ code }) }),
}

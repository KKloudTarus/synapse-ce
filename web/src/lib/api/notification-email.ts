import { req } from './client'

export interface NotificationEmailSettings {
  revision: number
  relay_configured: boolean
  relay_host?: string
  relay_port?: number
  relay_from?: string
  auth_mode?: string
  domains: string[]
  dns_txt_value: string
}

export interface NotificationEmailSettingsInput {
  revision: number
  clear_relay?: boolean
  domains?: string[]
  relay?: {
    host: string
    port: number
    from: string
    username: string
    password?: string
    oauth?: { provider: 'google' | 'microsoft'; client_id: string; client_secret: string; refresh_token?: string; directory_id?: string }
  }
}

export const notificationEmailApi = {
  notificationEmailSettings: () => req('/notifications/email-settings') as Promise<NotificationEmailSettings>,
  updateNotificationEmailSettings: (input: NotificationEmailSettingsInput) => req('/notifications/email-settings', { method: 'PUT', body: JSON.stringify(input) }) as Promise<NotificationEmailSettings>,
}

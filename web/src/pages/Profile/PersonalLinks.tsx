import { useEffect, useState, type FormEvent } from 'react'
import { api, type PersonalChannels, type UserContact } from '../../lib/api'

const inputClass = 'min-w-0 flex-1 rounded-lg border border-primary bg-primary px-3 py-2 text-primary'
const secondaryButton = 'rounded-lg border border-secondary px-3 py-2 text-sm text-secondary disabled:opacity-50'
const primaryButton = 'rounded-lg bg-brand-solid px-4 py-2 font-medium text-white disabled:opacity-50'

/**
 * Slack (#1419) and Microsoft Teams (#1420) accounts for personal notifications. Slack is linked by
 * the person's own member ID in a workspace the tenant has a Slack app in, then verified by a code
 * the app sends as a direct message. Teams is linked by a code the Synapse bot gives the person
 * when they message it. Synapse never looks anyone up by email.
 */
export function PersonalLinks({
  contacts,
  busy,
  run,
}: {
  contacts: UserContact[]
  busy: string | null
  run: (key: string, action: () => Promise<unknown>, success: string) => Promise<void>
}) {
  const [channels, setChannels] = useState<PersonalChannels | null>(null)
  const [team, setTeam] = useState('')
  const [member, setMember] = useState('')
  const [teamsCode, setTeamsCode] = useState('')
  const [codes, setCodes] = useState<Record<string, string>>({})
  useEffect(() => {
    let live = true
    if (typeof api.myPersonalChannels !== 'function') return
    api
      .myPersonalChannels()
      .then((c) => {
        if (!live) return
        setChannels(c)
        setTeam(c.slack.workspaces[0]?.team_id ?? '')
      })
      .catch(() => live && setChannels(null))
    return () => {
      live = false
    }
  }, [])
  if (!channels || (!channels.slack.available && !channels.teams.available)) return null
  const slackContacts = contacts.filter((c) => c.kind === 'slack')
  const teamsContacts = contacts.filter((c) => c.kind === 'teams')
  const workspaceName = (value: string) => {
    const [teamID, memberID] = value.split(':')
    const name = channels.slack.workspaces.find((w) => w.team_id === teamID)?.team_name ?? teamID
    return `${memberID} in ${name}`
  }
  function addSlack(e: FormEvent) {
    e.preventDefault()
    void run('slack-add', async () => {
      await api.addMySlack(team, member.trim())
      setMember('')
    }, 'Slack account added. Send a verification code to activate it.')
  }
  function linkTeams(e: FormEvent) {
    e.preventDefault()
    void run('teams-link', async () => {
      await api.linkMyTeams(teamsCode)
      setTeamsCode('')
    }, 'Microsoft Teams account linked.')
  }
  return (
    <>
      {channels.slack.available && (
        <section aria-labelledby="profile-slack-heading" className="space-y-3">
          <h2 id="profile-slack-heading" className="text-lg font-semibold text-primary">Slack</h2>
          <form onSubmit={addSlack} className="space-y-3 rounded-xl border border-secondary bg-primary p-5">
            <p className="text-sm text-secondary">
              In Slack, open your profile, choose <strong>More</strong>, then <strong>Copy member ID</strong>, and paste it
              here. Synapse sends a code from its Slack app to check it is you.
            </p>
            <div className="flex flex-col gap-2 sm:flex-row">
              <label htmlFor="profile-slack-workspace" className="sr-only">Slack workspace</label>
              <select id="profile-slack-workspace" value={team} onChange={(e) => setTeam(e.target.value)} className={inputClass}>
                {channels.slack.workspaces.map((w) => (
                  <option key={w.team_id} value={w.team_id}>{w.team_name}</option>
                ))}
              </select>
              <label htmlFor="profile-slack-member" className="sr-only">Slack member ID</label>
              <input id="profile-slack-member" required pattern="[UW][A-Z0-9]{2,30}" maxLength={31} value={member}
                onChange={(e) => setMember(e.target.value.toUpperCase())} placeholder="U0123ABC" className={inputClass} autoComplete="off" />
              <button type="submit" disabled={busy !== null || !team} className={primaryButton}>Add Slack account</button>
            </div>
          </form>
          {slackContacts.length === 0 ? (
            <p className="rounded-lg border border-secondary p-4 text-secondary">No Slack account linked yet.</p>
          ) : (
            slackContacts.map((contact) => (
              <article key={contact.id} className="space-y-3 rounded-xl border border-secondary bg-primary p-5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p className="font-medium text-primary">{workspaceName(contact.value)}</p>
                    <p className="text-sm text-secondary">{contact.verified_at ? 'Verified' : 'Pending verification'}</p>
                  </div>
                  <button type="button" disabled={busy !== null} onClick={() => void run(contact.id, () => api.deleteMyContact(contact.id), 'Slack account removed.')} className={secondaryButton}>Remove</button>
                </div>
                {!contact.verified_at && (
                  <div className="space-y-2">
                    <button type="button" disabled={busy !== null} onClick={() => void run(contact.id, () => api.requestMyContactVerification(contact.id), 'Code sent as a Slack direct message.')} className={secondaryButton}>Send code in Slack</button>
                    <form onSubmit={(e) => { e.preventDefault(); void run(contact.id, () => api.verifyMyContact(contact.id, codes[contact.id] ?? ''), 'Slack account verified.') }} className="flex flex-col gap-2 sm:flex-row">
                      <label htmlFor={`slack-code-${contact.id}`} className="sr-only">Eight-digit code for Slack {workspaceName(contact.value)}</label>
                      <input id={`slack-code-${contact.id}`} inputMode="numeric" pattern="[0-9]{8}" maxLength={8} autoComplete="one-time-code" required value={codes[contact.id] ?? ''}
                        onChange={(e) => setCodes((prev) => ({ ...prev, [contact.id]: e.target.value }))} className={inputClass} placeholder="8-digit code" />
                      <button type="submit" disabled={busy !== null} className={primaryButton}>Verify</button>
                    </form>
                  </div>
                )}
              </article>
            ))
          )}
        </section>
      )}
      {channels.teams.available && (
        <section aria-labelledby="profile-teams-heading" className="space-y-3">
          <h2 id="profile-teams-heading" className="text-lg font-semibold text-primary">Microsoft Teams</h2>
          <form onSubmit={linkTeams} className="space-y-3 rounded-xl border border-secondary bg-primary p-5">
            <p className="text-sm text-secondary">
              In Microsoft Teams, open a chat with the Synapse app and send it any message. It answers with a link code
              that works once for 10 minutes; enter it here.
            </p>
            <div className="flex flex-col gap-2 sm:flex-row">
              <label htmlFor="profile-teams-code" className="sr-only">Teams link code</label>
              <input id="profile-teams-code" required maxLength={64} value={teamsCode} onChange={(e) => setTeamsCode(e.target.value)}
                placeholder="ABCDE-FGHJK" className={inputClass} autoComplete="one-time-code" />
              <button type="submit" disabled={busy !== null} className={primaryButton}>Link Teams</button>
            </div>
          </form>
          {teamsContacts.length === 0 ? (
            <p className="rounded-lg border border-secondary p-4 text-secondary">No Teams account linked yet.</p>
          ) : (
            teamsContacts.map((contact) => (
              <article key={contact.id} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-secondary bg-primary p-5">
                <div>
                  <p className="font-medium text-primary">Teams account linked</p>
                  <p className="text-sm text-secondary">Verified through the Synapse app</p>
                </div>
                <button type="button" disabled={busy !== null} onClick={() => void run(contact.id, () => api.deleteMyContact(contact.id), 'Teams account removed.')} className={secondaryButton}>Remove</button>
              </article>
            ))
          )}
        </section>
      )}
    </>
  )
}

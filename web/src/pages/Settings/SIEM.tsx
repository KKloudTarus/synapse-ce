import { FormEvent, useCallback, useEffect, useState } from 'react'
import { Dataflow03 } from '@untitledui/icons'
import { ApiError, api } from '../../lib/api'
import type { SIEMAckMode, SIEMProvider, SIEMSink, SIEMStatus } from '../../lib/api'
import { Button, Card, EmptyState, ErrorState, Field, Input, Select, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { canManageIntegrations, isAdminRole } from '../../lib/roles'

export const SIEM_PROVIDER_OPTIONS: Array<{ value: SIEMProvider; label: string }> = [
  { value: 'splunk_hec', label: 'Splunk HEC' },
  { value: 'elasticsearch', label: 'Elasticsearch' },
  { value: 'syslog_tls', label: 'Syslog TLS (RFC 5424)' },
  { value: 'microsoft_sentinel', label: 'Microsoft Sentinel' },
]

export const SIEM_PROVIDER_FIELDS: Record<SIEMProvider, {
  originPlaceholder: string
  originLabel?: string
  targetLabel: string
  targetPlaceholder: string
  credentialLabel: string
  credentialPlaceholder?: string
  targetHint?: string
}> = {
  splunk_hec: {
    originPlaceholder: 'https://splunk.example:8088',
    targetLabel: 'Collector path',
    targetPlaceholder: '/services/collector/event',
    credentialLabel: 'Credential',
  },
  elasticsearch: {
    originPlaceholder: 'https://elasticsearch.example:9200',
    targetLabel: 'Index',
    targetPlaceholder: 'synapse-siem',
    credentialLabel: 'Credential',
  },
  syslog_tls: {
    originPlaceholder: 'tls://syslog.example:6514',
    originLabel: 'Syslog TLS endpoint',
    targetLabel: 'Application name',
    targetPlaceholder: 'synapse',
    credentialLabel: 'TLS credential JSON',
    credentialPlaceholder: '{"ca_pem":"...","client_cert_pem":"...","client_key_pem":"..."}',
  },
  microsoft_sentinel: {
    originPlaceholder: 'https://<endpoint>.<region>.ingest.monitor.azure.com',
    targetLabel: 'DCR / stream',
    targetPlaceholder: 'dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM',
    credentialLabel: 'Entra client credential JSON',
    credentialPlaceholder: '{"tenant_id":"...","client_id":"...","client_secret":"..."}',
    targetHint: 'Use the DCR immutable ID and a Custom- stream declaration.',
  },
}

const guarantees: Record<SIEMAckMode, string> = {
  hec_acceptance: 'Splunk accepted the HTTP batch. That is not indexer acknowledgement, and it does not prove the event is searchable.',
  indexer_ack: 'Splunk indexer acknowledgement was requested. A true ack can still be lost, and a later replay can duplicate.',
  bulk_item: 'Elasticsearch item results advance only the contiguous successful prefix. A conflict is not treated as already stored.',
  transport_write: 'The TLS transport accepted the complete frame. Syslog has no application acknowledgement, so a replay can duplicate it.',
  ingestion_acceptance: 'Microsoft Sentinel Logs Ingestion API returned 204 for the batch. This confirms API acceptance, not immediate searchability.',
}

export function SIEM() {
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  // Reading, pausing, resuming and status need manage_integrations; adding a sink needs administer (#1358).
  const canAdmin = isAdminRole(me?.role)
  const canManage = canManageIntegrations(me?.role)
  const [sinks, setSinks] = useState<SIEMSink[] | null | undefined>(undefined)
  const [status, setStatus] = useState<SIEMStatus | null>(null)
  const [tested, setTested] = useState<{ id: string; guarantee: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [denied, setDenied] = useState(false)
  const [unsupported, setUnsupported] = useState(false)
  const load = useCallback(async () => {
    setError(null)
    try {
      const items = await api.listSIEMSinks()
      if (items === null) {
        setUnsupported(true)
        setSinks([])
        return
      }
      setUnsupported(false)
      setSinks(items)
    } catch (caught) {
      setSinks([])
      if (caught instanceof ApiError && caught.status === 403) {
        setDenied(true)
        return
      }
      setError(caught instanceof Error ? caught.message : 'SIEM settings could not be loaded')
    }
  }, [])
  useEffect(() => {
    if (canManage) void load()
  }, [canManage, load])
  async function testConnection(id: string) {
    setTested(null)
    setError(null)
    try {
      const result = await api.testSIEMSink(id)
      setTested({ id, guarantee: result.guarantee })
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Connection test failed')
    }
  }

  if (!me) return <Spinner label="Loading permissions" />
  if (!canManage) {
    return (
      <EmptyState
        icon={Dataflow03}
        title="Administrator access required"
        hint="Only a tenant administrator or an integration administrator can see SIEM destinations and their status."
      />
    )
  }
  if (denied) return <ErrorState message="Permission denied. This session cannot manage SIEM streams." />
  if (sinks == null) return <Spinner label="Loading SIEM streams" />
  if (error && sinks.length === 0) return <ErrorState message={error} />
  if (unsupported) {
    return <EmptyState icon={Dataflow03} title="SIEM streams are not enabled" hint="This server has no SIEM sink API." />
  }

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-lg font-semibold text-primary">SIEM streams</h2>
        <p className="mt-1 text-sm text-secondary">
          Audit and incident records are exported at least once. A gap stops the stream until someone resumes it. Legacy audit history from before tenant chains is not included.
        </p>
      </header>
      {canAdmin ? (
        <CreateSink onCreated={() => void load()} />
      ) : (
        <p className="text-sm text-tertiary">Only tenant administrators can add a sink or change its host, secret or data class.</p>
      )}
      {error ? <ErrorState message={error} /> : null}
      {sinks.length === 0 ? (
        <EmptyState icon={Dataflow03} title="No SIEM destinations" hint="Add a Splunk, Elasticsearch, syslog, or Microsoft Sentinel sink to start a stream." />
      ) : (
        <ul className="space-y-3">
          {sinks.map((sink) => (
            <li key={sink.id}>
              <Card>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="font-semibold text-primary">{sink.name}</h3>
                    <p className="text-sm text-secondary">{sink.origin}</p>
                    <p className="mt-1 text-sm text-tertiary">{guarantees[sink.ack_mode]}</p>
                    {sink.blocked_reason ? <p className="mt-2 text-sm text-error-primary">{sink.blocked_reason}</p> : null}
                    {sink.paused ? <p className="mt-1 text-sm text-warning-primary">Paused</p> : null}
                    {tested?.id === sink.id ? <p role="status" className="mt-2 text-sm text-success-primary">Connection test accepted ({tested.guarantee}).</p> : null}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button type="button" onClick={() => void showStatus(sink.id, setStatus, setError)}>Status</Button>
                    <Button type="button" onClick={() => void testConnection(sink.id)}>Test</Button>
                    {sink.paused ? (
                      <Button type="button" onClick={() => void run(() => api.resumeSIEMSink(sink.id, sink.version), load, setError)}>Resume</Button>
                    ) : (
                      <>
                        <Button type="button" onClick={() => void run(() => api.pauseSIEMSink(sink.id, sink.version), load, setError)}>Pause</Button>
                        {sink.blocked_reason ? (
                          <Button type="button" onClick={() => void run(() => api.resumeSIEMSink(sink.id, sink.version), load, setError)}>Resume</Button>
                        ) : null}
                      </>
                    )}
                  </div>
                </div>
              </Card>
            </li>
          ))}
        </ul>
      )}
      {status ? <StatusPanel status={status} /> : null}
    </div>
  )
}

function CreateSink({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState('')
  const [provider, setProvider] = useState<SIEMProvider>('splunk_hec')
  const [origin, setOrigin] = useState('')
  const [target, setTarget] = useState('')
  const [secret, setSecret] = useState('')
  const [error, setError] = useState<string | null>(null)
  const fields = SIEM_PROVIDER_FIELDS[provider]
  async function submit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    try {
      await api.createSIEMSink({ name, provider, origin, target, data_class: 'signal', secret })
      setName('')
      setOrigin('')
      setTarget('')
      setSecret('')
      onCreated()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The sink could not be created')
    }
  }
  return (
    <Card>
      <form className="grid gap-4 md:grid-cols-2" onSubmit={submit}>
        <Field label="Name" htmlFor="siem-name">
          <Input id="siem-name" value={name} onChange={(event) => setName(event.target.value)} required />
        </Field>
        <Field label="Provider" htmlFor="siem-provider">
          <Select
            id="siem-provider"
            ariaLabel="Provider"
            value={provider}
            onValueChange={(value) => setProvider(value as SIEMProvider)}
            options={SIEM_PROVIDER_OPTIONS}
          />
        </Field>
        <Field label={fields.originLabel ?? 'HTTPS origin'} htmlFor="siem-origin">
          <Input
            id="siem-origin"
            value={origin}
            onChange={(event) => setOrigin(event.target.value)}
            placeholder={fields.originPlaceholder}
            required
          />
        </Field>
        <Field label={fields.targetLabel} htmlFor="siem-target">
          <Input
            id="siem-target"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder={fields.targetPlaceholder}
            required={provider === 'elasticsearch' || provider === 'microsoft_sentinel'}
          />
          {fields.targetHint ? <p className="mt-1 text-xs text-tertiary">{fields.targetHint}</p> : null}
        </Field>
        <div className="text-sm">
          <p className="font-medium">Data class: Signal</p>
          <p>Summary and Detail require a wired engagement policy and are not currently available.</p>
        </div>
        <Field label={fields.credentialLabel} htmlFor="siem-secret">
          <Input
            id="siem-secret"
            type="password"
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            placeholder={fields.credentialPlaceholder}
            autoComplete="new-password"
            required
          />
        </Field>
        {error ? <p className="text-sm text-error-primary md:col-span-2">{error}</p> : null}
        <div className="md:col-span-2">
          <Button type="submit">Add sink</Button>
        </div>
      </form>
    </Card>
  )
}

function StatusPanel({ status }: { status: SIEMStatus }) {
  return (
    <Card>
      <h3 className="font-semibold text-primary">Status for {status.sink.name}</h3>
      <ul className="mt-3 space-y-2">
        {status.partitions.map((partition) => (
          <li key={partition.source} className="text-sm text-secondary">
            <span className="font-medium text-primary">{partition.source}</span>
            {' '}cursor {partition.cursor}, lag {partition.lag_records}. {partition.coverage_note}
          </li>
        ))}
      </ul>
    </Card>
  )
}

async function showStatus(id: string, setStatus: (status: SIEMStatus) => void, setError: (value: string) => void) {
  try {
    setStatus(await api.siemSinkStatus(id))
  } catch (caught) {
    setError(caught instanceof Error ? caught.message : 'Status could not be loaded')
  }
}

async function run(action: () => Promise<unknown>, reload: () => Promise<void>, setError: (value: string) => void) {
  try {
    await action()
    await reload()
  } catch (caught) {
    setError(caught instanceof Error ? caught.message : 'The change could not be saved')
  }
}

export default SIEM

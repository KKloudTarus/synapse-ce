import { BriefcaseBusiness, ClipboardCheck, Pencil, Plus, Trash2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { Assessment, BusinessService, BusinessServiceCriticality, BusinessServiceLifecycle } from '../lib/types'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner } from '../components/ui'

const criticalityOptions = ['low', 'medium', 'high', 'critical'].map((value) => ({ value, label: value[0].toUpperCase() + value.slice(1) }))
const lifecycleOptions = ['planned', 'active', 'retired'].map((value) => ({ value, label: value[0].toUpperCase() + value.slice(1) }))

const emptyService = (): Omit<BusinessService, 'id'> => ({ name: '', description: '', criticality: 'medium', lifecycle: 'planned' })

export function BusinessServices() {
  const [services, setServices] = useState<BusinessService[] | null>(null)
  const [selected, setSelected] = useState<BusinessService | null>(null)
  const [assessments, setAssessments] = useState<Assessment[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState<Omit<BusinessService, 'id'> | null>(null)
  const [assessmentForm, setAssessmentForm] = useState(false)

  async function load() {
    try {
      setError(null)
      const next = await api.listBusinessServices()
      setServices(next)
      setSelected((current) => next.find((item) => item.id === current?.id) ?? next[0] ?? null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load business services')
    }
  }

  async function loadAssessments(service: BusinessService | null) {
    if (!service) { setAssessments(null); return }
    try { setAssessments(await api.listAssessments(service.id)) }
    catch (err) { setError(err instanceof Error ? err.message : 'Unable to load assessments') }
  }

  useEffect(() => { void load() }, [])
  useEffect(() => { void loadAssessments(selected) }, [selected?.id])

  async function remove(service: BusinessService) {
    if (!window.confirm(`Delete ${service.name}? Services with Assessments cannot be deleted.`)) return
    try { await api.deleteBusinessService(service.id); await load() }
    catch (err) { setError(err instanceof Error ? err.message : 'Unable to delete business service') }
  }

  if (services === null) return <Spinner label="Loading Business Services…" className="mt-24" />

  return (
    <div className="mx-auto max-w-7xl space-y-6 animate-fade-in">
      <header className="flex flex-col gap-4 border-b border-border pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-brand"><BriefcaseBusiness className="size-5" /><span className="text-xs font-semibold uppercase tracking-widest">AppSec management</span></div>
          <h1 className="text-2xl font-bold tracking-tight">Business Services</h1>
          <p className="mt-1 max-w-2xl text-sm text-mutedfg">Define the services your program protects, then record the assessments and engagements that prove their coverage.</p>
        </div>
        <Button onClick={() => setEditing(emptyService())}><Plus className="size-4" /> Add service</Button>
      </header>
      {error && <ErrorState message={error} />}
      <div className="grid gap-6 lg:grid-cols-[minmax(18rem,0.8fr)_minmax(0,1.2fr)]">
        <Card title={`Services · ${services.length}`} bodyClass="p-3">
          {services.length === 0 ? <EmptyState icon={BriefcaseBusiness} title="No Business Services" hint="Add the first service to begin organizing assessments." action={<Button onClick={() => setEditing(emptyService())}><Plus className="size-4" /> Add service</Button>} /> :
            <div className="space-y-1">{services.map((service) => <button key={service.id} onClick={() => setSelected(service)} className={`w-full rounded-lg px-3 py-3 text-left transition-colors ${selected?.id === service.id ? 'bg-brand/10 ring-1 ring-brand/25' : 'hover:bg-elevated'}`}>
              <div className="flex items-center justify-between gap-3"><span className="font-medium">{service.name}</span><Pill className={service.criticality === 'critical' ? 'bg-danger/10 text-danger' : service.criticality === 'high' ? 'bg-warning/10 text-warning' : 'bg-muted text-mutedfg'}>{service.criticality}</Pill></div>
              <p className="mt-1 line-clamp-1 text-xs text-mutedfg">{service.description || 'No description'}</p>
            </button>)}</div>}
        </Card>
        <section className="space-y-6">
          {selected ? <>
            <Card title={selected.name} actions={<div className="flex gap-2"><Button variant="ghost" aria-label={`Edit ${selected.name}`} onClick={() => setEditing({ name: selected.name, description: selected.description, criticality: selected.criticality, lifecycle: selected.lifecycle })}><Pencil className="size-4" /> Edit</Button><Button variant="danger" aria-label={`Delete ${selected.name}`} onClick={() => void remove(selected)}><Trash2 className="size-4" /> Delete</Button></div>}>
              <div className="grid gap-4 sm:grid-cols-2"><div><p className="text-xs font-medium uppercase tracking-wide text-subtlefg">Criticality</p><p className="mt-1 font-medium capitalize">{selected.criticality}</p></div><div><p className="text-xs font-medium uppercase tracking-wide text-subtlefg">Lifecycle</p><p className="mt-1 font-medium capitalize">{selected.lifecycle}</p></div></div>
              <p className="mt-5 whitespace-pre-wrap text-sm leading-6 text-mutedfg">{selected.description || 'No description has been provided.'}</p>
            </Card>
            <Card title="Assessments" actions={<Button variant="secondary" onClick={() => setAssessmentForm(true)}><Plus className="size-4" /> Add assessment</Button>}>
              {assessments === null ? <Spinner label="Loading assessments…" /> : assessments.length === 0 ? <EmptyState icon={ClipboardCheck} title="No Assessments" hint="Create an assessment with at least one engagement to establish coverage." /> : <div className="divide-y divide-border">{assessments.map((assessment) => <div key={assessment.id} className="py-4 first:pt-0 last:pb-0"><div className="flex items-center justify-between gap-3"><p className="font-medium">{assessment.name}</p><Pill className="bg-info/10 text-info">{assessment.status}</Pill></div><p className="mt-1 text-sm text-mutedfg">{assessment.objective || 'No objective provided.'}</p>{(assessment.policy.release || assessment.policy.environment || assessment.policy.cadence) && <p className="mt-2 text-xs text-subtlefg">{[assessment.policy.release, assessment.policy.environment, assessment.policy.cadence].filter(Boolean).join(' · ')}</p>}</div>)}</div>}
            </Card>
          </> : <EmptyState icon={BriefcaseBusiness} title="Select a service" hint="Choose a Business Service to view its assessments." />}
        </section>
      </div>
      {editing && <ServiceForm initial={editing} isUpdate={Boolean(selected && editing.name === selected.name)} onCancel={() => setEditing(null)} onSaved={async () => { setEditing(null); await load() }} serviceId={selected?.id} />}
      {assessmentForm && selected && <AssessmentForm service={selected} onCancel={() => setAssessmentForm(false)} onSaved={async () => { setAssessmentForm(false); await loadAssessments(selected) }} />}
    </div>
  )
}

function ServiceForm({ initial, serviceId, isUpdate, onCancel, onSaved }: { initial: Omit<BusinessService, 'id'>; serviceId?: string; isUpdate: boolean; onCancel: () => void; onSaved: () => Promise<void> }) {
  const [form, setForm] = useState(initial); const [error, setError] = useState<string | null>(null); const [saving, setSaving] = useState(false)
  async function submit(event: React.FormEvent) { event.preventDefault(); setSaving(true); setError(null); try { if (isUpdate && serviceId) await api.updateBusinessService(serviceId, form); else await api.createBusinessService(form); onCancel(); await onSaved() } catch (err) { setError(err instanceof Error ? err.message : 'Unable to save service') } finally { setSaving(false) } }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" aria-labelledby="service-form-title">
      <form onSubmit={submit} className="w-full max-w-xl rounded-xl border border-border bg-surface p-6 shadow-xl">
        <h2 id="service-form-title" className="text-lg font-semibold">{isUpdate ? 'Edit Business Service' : 'Add Business Service'}</h2>
        {error && <p role="alert" className="mt-3 text-sm text-danger">{error}</p>}
        <div className="mt-5 space-y-4">
          <Field label="Name" htmlFor="service-name"><Input id="service-name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label="Description" htmlFor="service-description"><textarea id="service-description" className="min-h-24 w-full rounded-md border border-border bg-page px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/25" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Criticality"><Select value={form.criticality} options={criticalityOptions} ariaLabel="Criticality" onValueChange={(value) => setForm({ ...form, criticality: value as BusinessServiceCriticality })} /></Field>
            <Field label="Lifecycle"><Select value={form.lifecycle} options={lifecycleOptions} ariaLabel="Lifecycle" onValueChange={(value) => setForm({ ...form, lifecycle: value as BusinessServiceLifecycle })} /></Field>
          </div>
        </div>
        <div className="mt-6 flex justify-end gap-3"><Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button><Button type="submit" loading={saving}>{isUpdate ? 'Save changes' : 'Create service'}</Button></div>
      </form>
    </div>
  )
}

function AssessmentForm({ service, onCancel, onSaved }: { service: BusinessService; onCancel: () => void; onSaved: () => Promise<void> }) {
  const [name, setName] = useState(''); const [objective, setObjective] = useState(''); const [engagement, setEngagement] = useState(''); const [error, setError] = useState<string | null>(null); const [saving, setSaving] = useState(false)
  async function submit(event: React.FormEvent) { event.preventDefault(); setSaving(true); setError(null); try { await api.createAssessment(service.id, { name, objective, policy: { cadence: '', release: '', environment: '' }, engagements: [{ name: engagement, client: '' }] }); onCancel(); await onSaved() } catch (err) { setError(err instanceof Error ? err.message : 'Unable to create assessment') } finally { setSaving(false) } }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" aria-labelledby="assessment-form-title">
      <form onSubmit={submit} className="w-full max-w-xl rounded-xl border border-border bg-surface p-6 shadow-xl">
        <h2 id="assessment-form-title" className="text-lg font-semibold">New Assessment</h2>
        <p className="mt-1 text-sm text-mutedfg">{service.name} · an assessment must begin with one engagement.</p>
        {error && <p role="alert" className="mt-3 text-sm text-danger">{error}</p>}
        <div className="mt-5 space-y-4">
          <Field label="Assessment name" htmlFor="assessment-name"><Input id="assessment-name" required value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Objective" htmlFor="assessment-objective"><textarea id="assessment-objective" className="min-h-20 w-full rounded-md border border-border bg-page px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/25" value={objective} onChange={(e) => setObjective(e.target.value)} /></Field>
          <Field label="First engagement" hint="Required" htmlFor="assessment-engagement"><Input id="assessment-engagement" required value={engagement} onChange={(e) => setEngagement(e.target.value)} /></Field>
        </div>
        <div className="mt-6 flex justify-end gap-3"><Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button><Button type="submit" loading={saving}>Create assessment</Button></div>
      </form>
    </div>
  )
}

import type { ReactNode } from 'react'
import { Markdown } from '../../../components/synapse/Markdown'
import type { TicketPreview } from '../../../lib/api'

type RecordValue = Record<string, unknown>

const entries = (fields: Record<string, unknown>) => Object.entries(fields).filter(([key]) => key !== 'summary' && key !== 'description')
const value = (field: unknown) => typeof field === 'string' ? field : JSON.stringify(field)
const isRecord = (value: unknown): value is RecordValue => typeof value === 'object' && value !== null && !Array.isArray(value)

function trustedURL(value: unknown, links: TicketPreview['links']): string | null {
  if (typeof value !== 'string' || !links?.some((link) => link.url === value)) return null
  try { return new URL(value).protocol === 'https:' ? value : null } catch { return null }
}

const wikiURL = (value: string) => value.replaceAll('[', '%5B').replaceAll(']', '%5D')

function trustedWikiURL(value: unknown, links: TicketPreview['links']) {
  if (typeof value !== 'string') return null
  const link = links?.find((candidate) => wikiURL(candidate.url) === value)
  return link ? trustedURL(link.url, links) : null
}

function marks(node: RecordValue) { return Array.isArray(node.marks) ? node.marks.filter(isRecord) : [] }
function hasMark(node: RecordValue, type: string) { return marks(node).some((mark) => mark.type === type) }
function adfLink(node: RecordValue, links: TicketPreview['links']) {
  const link = marks(node).find((mark) => mark.type === 'link')
  return link && isRecord(link.attrs) ? trustedURL(link.attrs.href, links) : null
}

function adfInlines(nodes: unknown, links: TicketPreview['links'], prefix: string): ReactNode[] {
  if (!Array.isArray(nodes)) return []
  return nodes.flatMap((value, index) => {
    if (!isRecord(value)) return []
    if (value.type === 'hardBreak') return [<br key={`${prefix}-break-${index}`} />]
    if (value.type !== 'text' || typeof value.text !== 'string') return []
    const code = hasMark(value, 'code')
    let content: ReactNode = value.text
    if (code) content = <code className="rounded bg-elevated px-1 py-0.5 font-mono text-[0.85em] text-branddim">{content}</code>
    if (!code && hasMark(value, 'strong')) content = <strong className="font-semibold text-foreground">{content}</strong>
    if (!code && hasMark(value, 'em')) content = <em>{content}</em>
    const href = adfLink(value, links)
    if (href) content = <a className="text-brand-secondary hover:underline" href={href} target="_blank" rel="noreferrer">{content}</a>
    return [<span key={`${prefix}-text-${index}`}>{content}</span>]
  })
}

function adfListItem(node: unknown, links: TicketPreview['links'], key: string): ReactNode | null {
  if (!isRecord(node) || node.type !== 'listItem' || !Array.isArray(node.content)) return null
  const content = node.content.flatMap((child, index) => isRecord(child) && child.type === 'paragraph' ? adfInlines(child.content, links, `${key}-${index}`) : [])
  return <li key={key} className="ml-4 list-outside">{content}</li>
}

function adfBlocks(nodes: unknown, links: TicketPreview['links'], prefix: string): ReactNode[] {
  if (!Array.isArray(nodes)) return []
  return nodes.flatMap((value, index) => {
    if (!isRecord(value)) return []
    if (value.type === 'paragraph') return [<p key={`${prefix}-paragraph-${index}`} className="break-words">{adfInlines(value.content, links, `${prefix}-${index}`)}</p>]
    if (value.type === 'bulletList' && Array.isArray(value.content)) {
      const items = value.content.map((item, itemIndex) => adfListItem(item, links, `${prefix}-${index}-${itemIndex}`)).filter((item): item is ReactNode => item !== null)
      return items.length ? [<ul key={`${prefix}-list-${index}`} className="list-disc space-y-0.5">{items}</ul>] : []
    }
    return []
  })
}

function decodeWikiLiteral(value: string) {
  let decoded = ''
  for (let index = 0; index < value.length;) {
    if (value.startsWith('&#92;', index)) { decoded += '\\'; index += 5; continue }
    if (value.startsWith('&#58;', index)) { decoded += ':'; index += 5; continue }
    if (value.startsWith('&amp;', index)) { decoded += '&'; index += 5; continue }
    if (value[index] === '\\' && index + 1 < value.length) { decoded += value[index + 1]; index += 2; continue }
    decoded += value[index++]
  }
  return decoded
}

function wikiDelimiter(value: string, delimiter: string, from: number) {
  for (let index = from; index < value.length; index++) {
    if (value[index] === '\\') { index++; continue }
    if (value.startsWith(delimiter, index)) return index
  }
  return -1
}

function wikiInlines(value: string, links: TicketPreview['links'], prefix: string): ReactNode[] {
  const out: ReactNode[] = []
  let text = ''
  let key = 0
  const flush = () => { if (text) { out.push(<span key={`${prefix}-text-${key++}`}>{decodeWikiLiteral(text)}</span>); text = '' } }
  for (let index = 0; index < value.length;) {
    if (value[index] === '\n') { flush(); out.push(<br key={`${prefix}-break-${key++}`} />); index++; continue }
    if (value[index] === '\\' && index + 1 < value.length) { text += value.slice(index, index + 2); index += 2; continue }
    if (value.startsWith('{{', index)) {
      const end = wikiDelimiter(value, '}}', index + 2)
      if (end >= 0) { flush(); out.push(<code key={`${prefix}-code-${key++}`} className="rounded bg-elevated px-1 py-0.5 font-mono text-[0.85em] text-branddim">{decodeWikiLiteral(value.slice(index + 2, end))}</code>); index = end + 2; continue }
    }
    if (value[index] === '[') {
      const end = wikiDelimiter(value, ']', index + 1)
      const separator = end < 0 ? -1 : wikiDelimiter(value, '|', index + 1)
      if (end >= 0 && separator > index && separator < end) {
        const href = trustedWikiURL(value.slice(separator + 1, end), links)
        flush()
        if (href) out.push(<a key={`${prefix}-link-${key++}`} className="text-brand-secondary hover:underline" href={href} target="_blank" rel="noreferrer">{decodeWikiLiteral(value.slice(index + 1, separator))}</a>)
        else out.push(<span key={`${prefix}-literal-link-${key++}`}>{decodeWikiLiteral(value.slice(index, end + 1))}</span>)
        index = end + 1
        continue
      }
    }
    if (value[index] === '*' || value[index] === '_') {
      const delimiter = value[index]
      const end = wikiDelimiter(value, delimiter, index + 1)
      if (end > index + 1) {
        flush()
        const children = wikiInlines(value.slice(index + 1, end), links, `${prefix}-${key}`)
        out.push(delimiter === '*' ? <strong key={`${prefix}-strong-${key++}`} className="font-semibold text-foreground">{children}</strong> : <em key={`${prefix}-em-${key++}`}>{children}</em>)
        index = end + 1
        continue
      }
    }
    text += value[index++]
  }
  flush()
  return out
}

function wikiDescription(value: string, links: TicketPreview['links']) {
  const blocks = value.split('\n\n')
  return <div className="space-y-1.5 leading-relaxed text-foreground text-xs text-secondary">{blocks.map((block, index) => {
    const lines = block.split('\n')
    if (lines.length > 0 && lines.every((line) => line.startsWith('* '))) return <ul key={`wiki-list-${index}`} className="list-disc space-y-0.5">{lines.map((line, lineIndex) => <li key={lineIndex} className="ml-4 list-outside">{wikiInlines(line.slice(2), links, `wiki-${index}-${lineIndex}`)}</li>)}</ul>
    return <p key={`wiki-paragraph-${index}`} className="break-words">{wikiInlines(block, links, `wiki-${index}`)}</p>
  })}</div>
}

function renderedDescription(preview: TicketPreview) {
  if (preview.wire !== undefined && preview.wire !== null) return { providerReady: false, body: <Markdown className="text-xs text-secondary">{preview.description}</Markdown> }
  const description = preview.fields.description
  if (isRecord(description) && description.type === 'doc' && Array.isArray(description.content)) return { providerReady: true, body: <div className="space-y-1.5 leading-relaxed text-foreground text-xs text-secondary">{adfBlocks(description.content, preview.links, 'adf')}</div> }
  if (typeof description === 'string') return { providerReady: true, body: wikiDescription(description, preview.links) }
  return { providerReady: false, body: <Markdown className="text-xs text-secondary">{preview.description}</Markdown> }
}

/** Renders the immutable provider-ready ticket payload before an operator submits it. */
export function TicketPreviewView({ preview, findingId }: { preview: TicketPreview; findingId?: string }) {
  const description = renderedDescription(preview)
  return <div className="space-y-2 rounded-lg border border-secondary bg-secondary/40 p-3">
    <p className="text-xs font-semibold text-primary">{findingId ? `Preview · ${findingId} · ` : 'Preview · '}{preview.dataClass}</p>
    <p className="text-sm font-medium text-primary">{preview.summary}</p>
    {preview.securityWaived && <p className="text-xs text-warning-primary">No Jira security level is set; this preview uses the recorded administrator waiver.</p>}
    {entries(preview.fields).length > 0 && <dl className="grid gap-1 text-xs text-secondary">{entries(preview.fields).map(([key, field]) => <div key={key} className="grid grid-cols-[minmax(6rem,auto)_1fr] gap-2"><dt className="font-medium text-primary">{key}</dt><dd className="break-all">{value(field)}</dd></div>)}</dl>}
    {description.body}
    {preview.wire !== undefined && preview.wire !== null && <details><summary className="cursor-pointer text-xs font-medium text-secondary">Exact provider request</summary><pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded border border-secondary p-2 text-xs text-secondary">{JSON.stringify(preview.wire, null, 2)}</pre></details>}
    {!description.providerReady && preview.links?.length ? <ul className="space-y-1 text-xs">{preview.links.map((link) => {
      const href = trustedURL(link.url, preview.links)
      return href ? <li key={href}><a className="text-brand-secondary hover:underline" href={href} target="_blank" rel="noreferrer">{link.label}</a></li> : null
    })}</ul> : null}
    {preview.markerRequired && <p className="text-xs text-tertiary">Submitting adds the correlation marker {preview.markerFormat || 'required by provider recovery'}.</p>}
  </div>
}

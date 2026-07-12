import { type ReactNode } from 'react'
import { cn } from './ui'

// Markdown is a SMALL, dependency-free, XSS-safe renderer for agent / LLM prose. It emits React elements
// ONLY — never dangerouslySetInnerHTML — so untrusted model output can never inject HTML into the page (a
// non-negotiable for a security tool). It covers the constructs the model actually emits (headings,
// bold/italic, inline + fenced code, bullet/numbered lists, paragraphs) and degrades any unrecognized
// syntax to plain text; it never throws. Links are rendered as plain styled text (their URL inline), NOT
// as clickable anchors — we do not navigate from untrusted model output.
export function Markdown({ children, className }: { children: string; className?: string }) {
  const blocks = parseBlocks((children ?? '').replace(/\r\n/g, '\n'))
  // No base font-size here — the caller controls it (cn is a naive join, not tailwind-merge, so a base
  // size would collide with a caller's text-xs). Only leading/spacing/color are fixed.
  return <div className={cn('space-y-1.5 leading-relaxed text-foreground', className)}>{blocks}</div>
}

// listItemRE matches a bullet (-, *, +) or ordered (1.) list marker at the start of a (possibly indented) line.
const listItemRE = /^\s*([-*+]|\d+[.)])\s+/
const headingRE = /^(#{1,6})\s+(.*)$/

function parseBlocks(src: string): ReactNode[] {
  const lines = src.split('\n')
  const out: ReactNode[] = []
  let i = 0
  let key = 0
  while (i < lines.length) {
    const line = lines[i]

    // Fenced code block: ``` … ```
    if (line.trimStart().startsWith('```')) {
      const code: string[] = []
      i++
      while (i < lines.length && !lines[i].trimStart().startsWith('```')) {
        code.push(lines[i])
        i++
      }
      i++ // consume the closing fence (if any)
      out.push(
        <pre key={key++} className="overflow-x-auto rounded-md border border-border bg-elevated p-2 font-mono text-xs text-foreground">
          <code>{code.join('\n')}</code>
        </pre>,
      )
      continue
    }

    // Heading: #, ##, … → weighted text (kept compact for a chat bubble).
    const h = headingRE.exec(line)
    if (h) {
      out.push(
        <div key={key++} className={cn('font-semibold text-foreground', h[1].length <= 2 ? 'mt-2 text-sm' : 'mt-1 text-xs uppercase tracking-wide text-mutedfg')}>
          {renderInline(h[2])}
        </div>,
      )
      i++
      continue
    }

    // List: consecutive bullet or ordered items.
    if (listItemRE.test(line)) {
      const ordered = /^\s*\d+[.)]\s+/.test(line)
      const items: ReactNode[] = []
      while (i < lines.length && listItemRE.test(lines[i])) {
        const text = lines[i].replace(listItemRE, '')
        items.push(
          <li key={items.length} className="ml-4 list-outside">
            {renderInline(text)}
          </li>,
        )
        i++
      }
      out.push(
        ordered ? (
          <ol key={key++} className="list-decimal space-y-0.5">
            {items}
          </ol>
        ) : (
          <ul key={key++} className="list-disc space-y-0.5">
            {items}
          </ul>
        ),
      )
      continue
    }

    // Blank line → paragraph break.
    if (line.trim() === '') {
      i++
      continue
    }

    // Paragraph: gather consecutive lines until a blank / block boundary.
    const para: string[] = []
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !listItemRE.test(lines[i]) &&
      !headingRE.test(lines[i]) &&
      !lines[i].trimStart().startsWith('```')
    ) {
      para.push(lines[i])
      i++
    }
    out.push(
      <p key={key++} className="break-words">
        {renderInline(para.join('\n'))}
      </p>,
    )
  }
  return out
}

// renderInline handles inline spans: `code`, **bold**, *italic* / _italic_. It recurses into bold/italic on
// strictly-smaller substrings (always terminates) and treats a newline inside a paragraph as a soft break.
function renderInline(text: string): ReactNode[] {
  const out: ReactNode[] = []
  let buf = ''
  let i = 0
  let key = 0
  const flush = () => {
    if (buf) {
      // Preserve intra-paragraph line breaks.
      const parts = buf.split('\n')
      parts.forEach((p, idx) => {
        if (idx > 0) out.push(<br key={`br${key++}`} />)
        if (p) out.push(p)
      })
      buf = ''
    }
  }
  while (i < text.length) {
    const rest = text.slice(i)
    // inline code `…`
    if (text[i] === '`') {
      const end = text.indexOf('`', i + 1)
      if (end > i) {
        flush()
        out.push(
          <code key={key++} className="rounded bg-elevated px-1 py-0.5 font-mono text-[0.85em] text-branddim">
            {text.slice(i + 1, end)}
          </code>,
        )
        i = end + 1
        continue
      }
    }
    // bold **…**
    if (rest.startsWith('**')) {
      const end = text.indexOf('**', i + 2)
      if (end > i) {
        flush()
        out.push(
          <strong key={key++} className="font-semibold text-foreground">
            {renderInline(text.slice(i + 2, end))}
          </strong>,
        )
        i = end + 2
        continue
      }
    }
    // italic *…* or _…_ (single delimiter, non-empty)
    if (text[i] === '*' || text[i] === '_') {
      const ch = text[i]
      const end = text.indexOf(ch, i + 1)
      if (end > i + 1) {
        flush()
        out.push(<em key={key++}>{renderInline(text.slice(i + 1, end))}</em>)
        i = end + 1
        continue
      }
    }
    buf += text[i]
    i++
  }
  flush()
  return out
}

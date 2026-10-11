import { HttpResponse } from 'msw'
import { strToU8, zipSync } from 'fflate'

type Finding = { Title: string; Severity: string; Status: string }
const escape = (value: string) => value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]!)
// A compact, dependency-free PDF for the browser-only evidence summary. All offsets use ASCII bytes.
export function reportPDF(lines: string[]): Uint8Array {
  const wrapped = lines.flatMap(line => (line.replace(/[^\x20-\x7e]/g, ' ').match(/.{1,88}(?:\s|$)|.{1,88}/g) ?? ['']).map(v => v.trim()))
  const pages = Array.from({ length: Math.max(1, Math.ceil(wrapped.length / 42)) }, (_, i) => wrapped.slice(i * 42, i * 42 + 42))
  const objects = ['<< /Type /Catalog /Pages 2 0 R >>', `<< /Type /Pages /Count ${pages.length} /Kids [${pages.map((_, i) => `${4 + i * 2} 0 R`).join(' ')}] >>`, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
  pages.forEach((page, i) => {
    const literal = (v: string) => v.replace(/[\\()]/g, '\\$&')
    const stream = `BT /F1 10 Tf 15 TL 48 790 Td ${page.map((line, j) => `${j ? 'T* ' : ''}(${literal(line)}) Tj`).join('\n')} ET\nBT /F1 9 Tf 48 30 Td (SYNAPSE PLAYGROUND - SYNTHETIC DATA | Page ${i + 1} of ${pages.length}) Tj ET`
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${5 + i * 2} 0 R >>`, `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`)
  })
  let pdf = '%PDF-1.4\n', offsets = [0]
  objects.forEach((obj, i) => { offsets.push(pdf.length); pdf += `${i + 1} 0 obj\n${obj}\nendobj\n` })
  const xref = pdf.length
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.slice(1).map(n => `${String(n).padStart(10, '0')} 00000 n \n`).join('')}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`
  return new TextEncoder().encode(pdf)
}
export function demoReport(request: Request, id: string, name: string, findings: Finding[]) {
  const url = new URL(request.url), format = url.pathname.split('.').pop(), statuses = url.searchParams.getAll('status')
  const rows = statuses.length ? findings.filter(f => statuses.includes(f.Status)) : findings
  const title = url.searchParams.get('title')?.slice(0, 200) || `${name} - Assessment summary`
  const lines = [title, '', 'SYNAPSE PLAYGROUND | Synthetic assessment evidence', `Assessment: ${id}`, `Generated: ${new Date().toISOString()}`, `Included findings: ${rows.length} of ${findings.length}`, '', ...['critical', 'high', 'medium', 'low', 'info'].map(severity => `${severity.toUpperCase()}: ${rows.filter(f => f.Severity === severity).length}`), '', 'Scope and methodology', 'Browser-local training data. No scanner, provider or host was contacted.', 'This is a compact demo summary. Production report sections and exhibits are not reproduced.', '', 'Recorded findings', ...(rows.length ? rows.map((f, i) => `${i + 1}. [${f.Severity.toUpperCase()} / ${f.Status}] ${f.Title}`) : ['No findings in this retained assessment and selected status scope.']), '', 'Verification', 'Absence alone does not prove a fix. Review comparable coverage and the assessment-cycle closure record.']
  const headers = { 'Content-Disposition': `attachment; filename="synapse-${id.replace(/[^a-zA-Z0-9-]/g, '')}-demo-report.${format}"` }
  if (format === 'pdf') return new HttpResponse(reportPDF(lines).buffer as ArrayBuffer, { headers: { ...headers, 'Content-Type': 'application/pdf' } })
  if (format === 'html') return new HttpResponse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>${escape(title)}</title><style>body{font:15px/1.65 system-ui;max-width:880px;margin:48px auto;padding:0 24px;color:#172130}h1{font-size:28px}p{margin:8px 0}.notice{padding:16px;background:#f2f4f7;border:1px solid #d0d5dd}</style><h1>${escape(title)}</h1><p class="notice">Synthetic demo summary · Not a production assessment</p>${lines.slice(2).map(line => `<p>${escape(line) || '&nbsp;'}</p>`).join('')}</html>`, { headers: { ...headers, 'Content-Type': 'text/html; charset=utf-8' } })
  if (format === 'docx') {
    const zip = zipSync({ '[Content_Types].xml': strToU8('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'), '_rels/.rels': strToU8('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'), 'word/document.xml': strToU8(`<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${lines.map(line => `<w:p><w:r><w:t xml:space="preserve">${escape(line)}</w:t></w:r></w:p>`).join('')}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1000" w:right="1000" w:bottom="1000" w:left="1000"/></w:sectPr></w:body></w:document>`) })
    return new HttpResponse(zip.buffer as ArrayBuffer, { headers: { ...headers, 'Content-Type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' } })
  }
  return HttpResponse.json({ message: 'Unsupported report format.' }, { status: 422 })
}

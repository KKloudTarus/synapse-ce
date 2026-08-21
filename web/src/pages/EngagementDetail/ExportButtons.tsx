import { AlertTriangle, CheckCircle2, Download, FileText, PackageOpen, Upload } from 'lucide-react'
import { useRef, useState } from 'react'
import { Button, Select } from '../../components/ui'
import { api, downloadBundle, downloadExport } from '../../lib/api'
import { EXCEL_EXPORT_MODE_OPTIONS, ExcelExportMode, downloadStyledExcel, excelFileSafeName } from '../../lib/excelExport'
import type { ScanResult } from '../../lib/types'
import { ReportBuilderModal } from './ReportBuilderModal'

export function ExportButtons({ engagementId, scan, onChanged }: { engagementId: string; scan: ScanResult | null; onChanged: () => void }) {
  const [busy, setBusy] = useState<'sarif' | 'openvex' | 'spdx' | 'cyclonedx' | 'bundle' | 'sbom' | 'vex' | 'excel' | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [building, setBuilding] = useState(false)
  const [excelMode, setExcelMode] = useState<ExcelExportMode>('service')
  const sbomRef = useRef<HTMLInputElement>(null)
  const vexRef = useRef<HTMLInputElement>(null)

  async function run(kind: 'sarif' | 'openvex' | 'spdx' | 'cyclonedx' | 'bundle') {
    setBusy(kind)
    setErr(null)
    setMsg(null)
    try {
      if (kind === 'bundle') await downloadBundle(engagementId)
      else await downloadExport(engagementId, kind)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Download failed')
    } finally {
      setBusy(null)
    }
  }

  async function upload(kind: 'sbom' | 'vex', e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setBusy(kind)
    setErr(null)
    setMsg(null)
    try {
      const text = await file.text()
      if (kind === 'sbom') {
        const r = await api.importSBOM(engagementId, text)
        setMsg(`Imported ${r.components} package(s) from ${r.target}.`)
      } else {
        const r = await api.applyVEX(engagementId, text)
        setMsg(`VEX: applied ${r.applied} of ${r.matched} matched (${r.statements} statement(s)).`)
      }
      onChanged()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Upload failed')
    } finally {
      setBusy(null)
    }
  }

  function exportExcel() {
    if (!scan) {
      setErr('Run a scan before exporting Excel.')
      return
    }
    setBusy('excel')
    setErr(null)
    setMsg(null)
    try {
      downloadStyledExcel(`synapse-${excelFileSafeName(engagementId)}-vulnerabilities-licenses.xlsx`, scan, excelMode)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Excel export failed')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <input ref={sbomRef} type="file" accept="application/json,.json" className="hidden" onChange={(e) => upload('sbom', e)} />
      <input ref={vexRef} type="file" accept="application/json,.json" className="hidden" onChange={(e) => upload('vex', e)} />
      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button variant="brand" onClick={() => setBuilding(true)} className="px-3 py-1.5">
          <FileText className="size-4" /> Build report
        </Button>
        <Select
          value={excelMode}
          onValueChange={(value) => setExcelMode(value as ExcelExportMode)}
          options={EXCEL_EXPORT_MODE_OPTIONS}
          ariaLabel="Excel export mode"
          disabled={!scan || busy === 'excel'}
          size="sm"
          className="w-32"
        />
        <Button variant="secondary" loading={busy === 'excel'} onClick={exportExcel} disabled={!scan} className="px-3 py-1.5" title="Export the Vulnerabilities and Licenses web tables to Excel">
          <Download className="size-4" /> Excel
        </Button>
        <Button variant="secondary" loading={busy === 'sarif'} onClick={() => run('sarif')} className="px-3 py-1.5">
          <Download className="size-4" /> SARIF
        </Button>
        <Button variant="secondary" loading={busy === 'openvex'} onClick={() => run('openvex')} className="px-3 py-1.5">
          <Download className="size-4" /> VEX
        </Button>
        <Button variant="secondary" loading={busy === 'spdx'} onClick={() => run('spdx')} className="px-3 py-1.5" title="SPDX 3.0.1 (CRA-aligned)">
          <Download className="size-4" /> SPDX
        </Button>
        <Button variant="secondary" loading={busy === 'cyclonedx'} onClick={() => run('cyclonedx')} className="px-3 py-1.5" title="CycloneDX 1.6">
          <Download className="size-4" /> CycloneDX
        </Button>
        <Button variant="secondary" loading={busy === 'bundle'} onClick={() => run('bundle')} className="px-3 py-1.5" title="Portable engagement bundle with the evidence chain (re-verified on import)">
          <PackageOpen className="size-4" /> Bundle
        </Button>
        <Button variant="secondary" loading={busy === 'sbom'} onClick={() => sbomRef.current?.click()} className="px-3 py-1.5" title="Import a client CycloneDX SBOM">
          <Upload className="size-4" /> Import SBOM
        </Button>
        <Button variant="secondary" loading={busy === 'vex'} onClick={() => vexRef.current?.click()} className="px-3 py-1.5" title="Apply a client OpenVEX document to the findings">
          <Upload className="size-4" /> Apply VEX
        </Button>
      </div>
      {err && (
        <span role="alert" className="flex items-center gap-1 text-xs text-critical">
          <AlertTriangle className="size-3.5 shrink-0" /> {err}
        </span>
      )}
      {msg && (
        <span role="status" className="flex items-center gap-1 text-xs text-accent">
          <CheckCircle2 className="size-3.5 shrink-0" /> {msg}
        </span>
      )}
      {building && <ReportBuilderModal engagementId={engagementId} onClose={() => setBuilding(false)} />}
    </div>
  )
}

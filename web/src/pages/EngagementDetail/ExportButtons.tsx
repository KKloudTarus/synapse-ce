import { useState, useRef } from 'react'
import {
  Download01,
  Upload01,
  File06,
  AlertTriangle,
  CheckCircle,
  ChevronDown,
} from '@untitledui/icons'
import { FileIcon } from '@untitledui/file-icons'
import { Button } from '@/components/base/buttons/button'
import { Dropdown } from '@/components/base/dropdown/dropdown'
import { SubmenuTrigger } from 'react-aria-components'
import { api, downloadBundle, downloadExport } from '../../lib/api'
import { ExcelExportMode, downloadStyledExcel, excelFileSafeName } from '../../lib/excelExport'
import type { ScanResult } from '../../lib/types'
import { ReportBuilderModal } from './ReportBuilderModal'

export function ExportButtons({
  engagementId,
  scan,
  onChanged,
}: {
  engagementId: string
  scan: ScanResult | null
  onChanged: () => void
}) {
  const [busy, setBusy] = useState<
    'sarif' | 'openvex' | 'spdx' | 'cyclonedx' | 'bundle' | 'sbom' | 'vex' | 'excel' | null
  >(null)
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

  function exportExcel(mode: ExcelExportMode = excelMode) {
    if (!scan) {
      setErr('Run a scan before exporting Excel.')
      return
    }
    setExcelMode(mode)
    setBusy('excel')
    setErr(null)
    setMsg(null)
    try {
      downloadStyledExcel(
        `synapse-${excelFileSafeName(engagementId)}-vulnerabilities-licenses.xlsx`,
        scan,
        mode,
      )
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Excel export failed')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="flex flex-col items-end gap-1.5">
      <input
        ref={sbomRef}
        type="file"
        accept="application/json,.json"
        className="hidden"
        onChange={(e) => upload('sbom', e)}
      />
      <input
        ref={vexRef}
        type="file"
        accept="application/json,.json"
        className="hidden"
        onChange={(e) => upload('vex', e)}
      />

      <div className="flex flex-wrap items-center gap-2">
        {/* Primary Action */}
        <Button size="sm" color="primary" onClick={() => setBuilding(true)} iconLeading={File06}>
          Build report
        </Button>

        {/* Export dropdown */}
        <Dropdown.Root>
          <Button
            size="sm"
            color="secondary"
            iconLeading={Download01}
            iconTrailing={ChevronDown}
            isLoading={busy !== null && ['sarif', 'openvex', 'spdx', 'cyclonedx', 'bundle', 'excel'].includes(busy)}
          >
            Export
          </Button>

          <Dropdown.Popover className="w-56">
            <Dropdown.Menu>
              <Dropdown.Section>
                <Dropdown.Item onAction={() => run('sarif')}>
                  <div className="flex items-center gap-2">
                    <FileIcon type="json" size={16} />
                    <span>SARIF</span>
                  </div>
                </Dropdown.Item>
                <Dropdown.Item onAction={() => run('openvex')}>
                  <div className="flex items-center gap-2">
                    <FileIcon type="json" size={16} />
                    <span>OpenVEX</span>
                  </div>
                </Dropdown.Item>
                <Dropdown.Item onAction={() => run('spdx')}>
                  <div className="flex items-center gap-2">
                    <FileIcon type="json" size={16} />
                    <span>SPDX 3.0</span>
                  </div>
                </Dropdown.Item>
                <Dropdown.Item onAction={() => run('cyclonedx')}>
                  <div className="flex items-center gap-2">
                    <FileIcon type="xml" size={16} />
                    <span>CycloneDX 1.6</span>
                  </div>
                </Dropdown.Item>
                <SubmenuTrigger>
                  <Dropdown.Item>
                    <div className="flex items-center gap-2">
                      <FileIcon type="xlsx" size={16} />
                      <span>Excel ({excelMode === 'service' ? 'By service' : 'Merged'})</span>
                    </div>
                  </Dropdown.Item>
                  <Dropdown.Popover placement="right top" offset={-6} className="w-44">
                    <Dropdown.Menu>
                      <Dropdown.Item onAction={() => exportExcel('service')}>
                        <span>By service</span>
                      </Dropdown.Item>
                      <Dropdown.Item onAction={() => exportExcel('summary')}>
                        <span>Merged</span>
                      </Dropdown.Item>
                    </Dropdown.Menu>
                  </Dropdown.Popover>
                </SubmenuTrigger>
              </Dropdown.Section>
              <Dropdown.Separator />
              <Dropdown.Section>
                <Dropdown.Item onAction={() => run('bundle')}>
                  <div className="flex items-center gap-2">
                    <FileIcon type="zip" size={16} />
                    <span>Bundle (portable)</span>
                  </div>
                </Dropdown.Item>
              </Dropdown.Section>
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown.Root>

        {/* Import dropdown */}
        <Dropdown.Root>
          <Button
            size="sm"
            color="secondary"
            iconLeading={Upload01}
            iconTrailing={ChevronDown}
            isLoading={busy === 'sbom' || busy === 'vex'}
          >
            Import
          </Button>

          <Dropdown.Popover className="w-48">
            <Dropdown.Menu>
              <Dropdown.Item onAction={() => sbomRef.current?.click()}>
                <div className="flex items-center gap-2">
                  <FileIcon type="json" size={16} />
                  <span>Import SBOM</span>
                </div>
              </Dropdown.Item>
              <Dropdown.Item onAction={() => vexRef.current?.click()}>
                <div className="flex items-center gap-2">
                  <FileIcon type="json" size={16} />
                  <span>Apply VEX</span>
                </div>
              </Dropdown.Item>
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown.Root>
      </div>

      {err && (
        <span role="alert" className="flex items-center gap-1 text-xs text-error-primary">
          <AlertTriangle className="size-3.5 shrink-0" /> {err}
        </span>
      )}
      {msg && (
        <span role="status" className="flex items-center gap-1 text-xs text-fg-success-primary">
          <CheckCircle className="size-3.5 shrink-0" /> {msg}
        </span>
      )}
      {building && <ReportBuilderModal engagementId={engagementId} onClose={() => setBuilding(false)} />}
    </div>
  )
}

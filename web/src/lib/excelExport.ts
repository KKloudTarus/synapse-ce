import { strFromU8, strToU8, unzipSync, zipSync } from 'fflate'
import XLSXModule from 'xlsx-js-style'
import type { ScanResult, Severity, Vulnerability } from './types'

type ExcelWs = Record<string, any>
type ExcelWb = any
const XLSX = XLSXModule as any

export type ExcelExportMode = 'service' | 'summary'

export const EXCEL_EXPORT_MODE_OPTIONS: { value: ExcelExportMode; label: string }[] = [
  { value: 'service', label: 'By service' },
  { value: 'summary', label: 'Merged' },
]

const EXCEL_CELL_LIMIT = 32767
const EXCEL_CELL_SAFE_LIMIT = 32000

function excelCell(value: unknown): string {
  const text = String(value ?? '')
  if (text.length <= EXCEL_CELL_LIMIT) return text
  return `${text.slice(0, EXCEL_CELL_SAFE_LIMIT)}\n... [truncated ${text.length - EXCEL_CELL_SAFE_LIMIT} chars for Excel cell limit]`
}

function excelRows(rows: unknown[][]): string[][] {
  return rows.map((row) => row.map(excelCell))
}

export function excelFileSafeName(value: string): string {
  return value.trim().replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'synapse'
}

const EXCEL_SEV_RANK: Record<string, number> = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5, UNKNOWN: 6, '-': 7 }
const EXCEL_SEVERITY_STYLES: Record<string, { fill: string; font: string }> = {
  CRITICAL: { fill: 'C00000', font: '000000' },
  HIGH: { fill: 'FF0000', font: '000000' },
  MEDIUM: { fill: 'FFC000', font: '000000' },
  LOW: { fill: '00B050', font: '000000' },
  INFO: { fill: 'D9EAF7', font: '000000' },
  UNKNOWN: { fill: 'D9EAD3', font: '000000' },
  '-': { fill: 'D9EAD3', font: '000000' },
}
const EXCEL_BORDER = {
  top: { style: 'thin', color: { rgb: '000000' } },
  right: { style: 'thin', color: { rgb: '000000' } },
  bottom: { style: 'thin', color: { rgb: '000000' } },
  left: { style: 'thin', color: { rgb: '000000' } },
}

function excelColRef(index: number): string {
  let n = index + 1
  let out = ''
  while (n > 0) {
    const rem = (n - 1) % 26
    out = String.fromCharCode(65 + rem) + out
    n = Math.floor((n - 1) / 26)
  }
  return out
}

function ensureExcelCell(ws: ExcelWs, row: number, col: number) {
  const ref = `${excelColRef(col)}${row + 1}`
  if (!ws[ref]) ws[ref] = { t: 's', v: '' }
  return ws[ref]
}

function mergeExcelColumn(merges: Array<{ s: { r: number; c: number }; e: { r: number; c: number } }>, startRow: number, endRow: number, col: number) {
  if (endRow <= startRow) return
  merges.push({ s: { r: startRow, c: col }, e: { r: endRow, c: col } })
}

function applyExcelHeader(ws: ExcelWs, totalCols: number, horizontal = 'left') {
  for (let c = 0; c < totalCols; c++) {
    const cell = ws[`${excelColRef(c)}1`]
    if (!cell) continue
    const current = cell.s || {}
    cell.s = {
      ...current,
      fill: { fgColor: { rgb: '0D1629' } },
      font: { bold: true, color: { rgb: 'B8CCE0' }, sz: 10 },
      alignment: { ...(current.alignment || {}), vertical: 'center', horizontal, wrapText: true },
    }
  }
  ws['!sheetView'] = [{ state: 'frozen', ySplit: 1 }]
}

function applyExcelSheetStyle(ws: ExcelWs, rowCount: number, colCount: number) {
  for (let r = 0; r < rowCount; r++) {
    for (let c = 0; c < colCount; c++) {
      const cell = ensureExcelCell(ws, r, c)
      const current = cell.s || {}
      cell.s = {
        ...current,
        border: EXCEL_BORDER,
        font: { sz: 11, ...(current.font || {}) },
        alignment: { ...(current.alignment || {}), horizontal: 'left', vertical: 'center', wrapText: true },
      }
    }
  }
  applyExcelHeader(ws, colCount, 'left')
}

function applyExcelSeverityColors(ws: ExcelWs, severityCol: number) {
  if (!ws['!ref']) return
  const range = XLSX.utils.decode_range(ws['!ref'])
  for (let r = 1; r <= range.e.r; r++) {
    const cell = ws[`${excelColRef(severityCol)}${r + 1}`]
    if (!cell) continue
    const style = EXCEL_SEVERITY_STYLES[String(cell.v || '').toUpperCase().split('\n')[0]]
    if (!style) continue
    const merge = (ws['!merges'] || []).find((item: any) => item.s.c === severityCol && item.s.r === r)
    const endRow = merge ? merge.e.r : r
    for (let rr = r; rr <= endRow; rr++) {
      const target = ensureExcelCell(ws, rr, severityCol)
      const current = target.s || {}
      target.s = {
        ...current,
        fill: { patternType: 'solid', fgColor: { rgb: style.fill } },
        font: { ...(current.font || {}), bold: true, color: { rgb: style.font } },
        alignment: { ...(current.alignment || {}), horizontal: 'left', vertical: 'center', wrapText: true },
      }
    }
  }
}

const ROOT_PROJECT_MANIFESTS = new Set([
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'go.mod',
  'go.sum',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'requirements.txt',
  'pyproject.toml',
  'poetry.lock',
  'Gemfile',
  'Gemfile.lock',
  'composer.json',
  'composer.lock',
  'Cargo.toml',
  'Cargo.lock',
])

function excelRelativeLocation(location: string, scanTarget: string): string {
  const normalized = location.trim().replace(/^\.\//, '').replace(/\\/g, '/')
  const target = scanTarget.trim().replace(/\\/g, '/').replace(/\/$/, '')
  const targetName = target.split('/').filter(Boolean).at(-1) ?? ''
  if (!normalized || normalized === '–') return ''
  if (target && normalized.startsWith(`${target}/`)) {
    return normalized.slice(target.length + 1)
  }
  if (targetName) {
    const marker = `/${targetName}/`
    const markerIndex = normalized.indexOf(marker)
    if (markerIndex >= 0) return normalized.slice(markerIndex + marker.length)
  }
  return normalized.replace(/^\/+/, '')
}

function excelSourcePath(location: string, scanTarget: string): string {
  const relative = excelRelativeLocation(location, scanTarget)
  if (relative) return relative
  const targetName = scanTarget.trim().replace(/\\/g, '/').replace(/\/$/, '').split('/').filter(Boolean).at(-1) ?? ''
  return targetName || 'root'
}

function scanLooksLikeSingleRootProject(scan: ScanResult): boolean {
  return scan.components.some((component) => {
    const relative = excelRelativeLocation(component.location, scan.target)
    if (!relative) return false
    return ROOT_PROJECT_MANIFESTS.has(relative) || (!relative.includes('/') && ROOT_PROJECT_MANIFESTS.has(relative.split('/').at(-1) ?? ''))
  })
}

function excelServiceFromLocation(location: string, scanTarget: string, singleRootProject: boolean): string {
  const targetName = scanTarget.trim().replace(/\\/g, '/').replace(/\/$/, '').split('/').filter(Boolean).at(-1) ?? ''
  if (singleRootProject && targetName) return targetName.toLowerCase()
  const relative = excelRelativeLocation(location, scanTarget)
  if (!relative) return targetName ? targetName.toLowerCase() : 'root'
  const parts = relative.split('/').filter(Boolean)
  if (parts.length === 0) return targetName ? targetName.toLowerCase() : 'root'
  return parts[0].toLowerCase()
}

function safeExcelSheetName(prefix: string, service: string, usedNames: Set<string>): string {
  const cleanService = String(service || 'service').replace(/[\\/?*[\]:]/g, '-').replace(/\s+/g, ' ').trim() || 'service'
  const cleanPrefix = prefix.replace(/[\\/?*[\]:]/g, '-')
  const baseLimit = Math.max(1, 31 - cleanPrefix.length)
  const base = (cleanPrefix + cleanService.slice(0, baseLimit)).slice(0, 31)
  let name = base
  let index = 2
  while (usedNames.has(name)) {
    const suffix = `_${index}`
    name = (base.slice(0, 31 - suffix.length) + suffix).slice(0, 31)
    index += 1
  }
  usedNames.add(name)
  return name
}

function sortExcelSeverity(a: string, b: string): number {
  return (EXCEL_SEV_RANK[String(a || 'UNKNOWN').toUpperCase()] ?? 99) - (EXCEL_SEV_RANK[String(b || 'UNKNOWN').toUpperCase()] ?? 99)
}

function sheetFromRows(
  rows: unknown[][],
  widths: number[],
  severityCol = 2,
  merges: Array<{ s: { r: number; c: number }; e: { r: number; c: number } }> = [],
  rowHeights: Array<{ hpt: number } | undefined> = [],
) {
  const ws = XLSX.utils.aoa_to_sheet(excelRows(rows)) as ExcelWs
  ws['!cols'] = widths.map((width) => ({ wch: width }))
  ws['!merges'] = merges
  ws['!rows'] = rowHeights
  if (rows.length > 0 && widths.length > 0) ws['!autofilter'] = { ref: `A1:${excelColRef(widths.length - 1)}${Math.max(rows.length, 1)}` }
  applyExcelSheetStyle(ws, rows.length, widths.length)
  applyExcelSeverityColors(ws, severityCol)
  return ws
}

interface ExcelVulnInstance {
  service: string
  sourcePath: string
  pkg: string
  cve: string
  severity: string
  installed: string
  fixed: string
}

interface ExcelLicenseInstance {
  service: string
  sourcePath: string
  pkg: string
  license: string
  severity: string
}

export function packageVersionKey(component: string, version: string): string {
  return `${component}\x00${version}`
}

function shortPkg(id: string): string {
  const last = id.split('/').pop() ?? id
  return last.split('@')[0] || last
}

function vulnPackageKey(v: Vulnerability): string {
  return packageVersionKey(v.component, v.version)
}

export interface VulnerabilityDisplayRow {
  key: string
  component: string
  cve: string
  severity: Severity
  installed: string
  fixedVersion: string
  location: string
  direct: boolean
  via: string
  isFirstInPackage: boolean
  packageCveCount: number
}

export function buildVulnerabilityDisplayRows(vulns: Vulnerability[], packageLocations: Map<string, string[]>): VulnerabilityDisplayRow[] {
  const packageOrder = new Map<string, number>()
  const cveOrder = new Map<string, number>()
  vulns.forEach((vuln, i) => {
    if (!packageOrder.has(vuln.component)) packageOrder.set(vuln.component, i)
    const ck = `${vuln.component}\x00${vuln.id}`
    if (!cveOrder.has(ck)) cveOrder.set(ck, i)
  })

  const rows = vulns.flatMap((vuln) => {
    const locations = packageLocations.get(vulnPackageKey(vuln)) ?? ['']
    return locations.map((location, index) => ({
      key: `${vuln.id}\x00${vuln.component}\x00${vuln.version}\x00${vuln.fixedVersion}\x00${location}\x00${index}`,
      component: vuln.component,
      cve: vuln.id,
      severity: vuln.severity,
      installed: vuln.version,
      fixedVersion: vuln.fixedVersion,
      location,
      direct: vuln.direct,
      via: vuln.path.length >= 2 ? shortPkg(vuln.path[vuln.path.length - 2]) : '',
      isFirstInPackage: false,
      packageCveCount: 0,
    }))
  })

  rows.sort((a, b) => {
    const pkgDelta = (packageOrder.get(a.component) ?? 0) - (packageOrder.get(b.component) ?? 0)
    if (pkgDelta !== 0) return pkgDelta
    const cveDelta =
      (cveOrder.get(`${a.component}\x00${a.cve}`) ?? 0) - (cveOrder.get(`${b.component}\x00${b.cve}`) ?? 0)
    if (cveDelta !== 0) return cveDelta
    return a.installed.localeCompare(b.installed) || a.location.localeCompare(b.location)
  })

  const packageCves = new Map<string, Set<string>>()
  for (const row of rows) {
    const cves = packageCves.get(row.component) ?? new Set<string>()
    cves.add(row.cve)
    packageCves.set(row.component, cves)
  }

  let previousPackage = ''
  return rows.map((row) => {
    const isFirstInPackage = row.component !== previousPackage
    previousPackage = row.component
    return { ...row, isFirstInPackage, packageCveCount: packageCves.get(row.component)?.size ?? 0 }
  })
}

export function licenseComponentKey(component: string): string {
  return component.trim().toLowerCase()
}

export function licenseSeverity(category: string): Severity {
  switch (category) {
    case 'proprietary':
      return 'critical'
    case 'copyleft':
      return 'high'
    case 'weak-copyleft':
      return 'medium'
    case 'permissive':
      return 'low'
    default:
      return 'unknown'
  }
}

export function buildLicenseComponentIndex(components: ScanResult['components']) {
  const byName = new Map<string, ScanResult['components'][number][]>()
  for (const component of components) {
    const keys = [component.name, component.version ? `${component.name}@${component.version}` : '']
      .map(licenseComponentKey)
      .filter(Boolean)
    for (const key of keys) {
      const existing = byName.get(key) ?? []
      byName.set(key, [...existing, component])
    }
  }
  return byName
}

function excelRecommendationRank(severity: string): number {
  const idx = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'].indexOf(String(severity || '').toUpperCase())
  return idx === -1 ? 99 : idx
}

function recommendedExcelLicense(licenses: ExcelLicenseInstance[]): ExcelLicenseInstance | null {
  if (licenses.length <= 1) return null
  return [...licenses].sort(
    (a, b) => excelRecommendationRank(a.severity) - excelRecommendationRank(b.severity) || a.license.localeCompare(b.license),
  )[0]
}

function buildExcelInstances(scan: ScanResult) {
  const singleRootProject = scanLooksLikeSingleRootProject(scan)
  const packageLocations = new Map<string, string[]>()
  for (const component of scan.components) {
    const location = component.location.trim()
    if (!location) continue
    const key = packageVersionKey(component.name, component.version)
    const existing = packageLocations.get(key) ?? []
    if (!existing.includes(location)) packageLocations.set(key, [...existing, location])
  }

  const vulnRows = buildVulnerabilityDisplayRows(scan.vulnerabilities, packageLocations)
  const vulns: ExcelVulnInstance[] = vulnRows.map((row) => ({
    service: excelServiceFromLocation(row.location, scan.target, singleRootProject),
    sourcePath: excelSourcePath(row.location, scan.target),
    pkg: row.component,
    cve: row.cve,
    severity: row.severity.toUpperCase(),
    installed: row.installed || 'unknown',
    fixed: row.fixedVersion || '-',
  }))

  const componentIndex = buildLicenseComponentIndex(scan.components)
  const licenses: ExcelLicenseInstance[] = []
  const licenseKeys = new Set<string>()
  const addLicenseInstance = (item: ExcelLicenseInstance) => {
    const key = `${item.service}\x00${item.sourcePath}\x00${item.pkg}\x00${item.license}\x00${item.severity}`
    if (licenseKeys.has(key)) return
    licenseKeys.add(key)
    licenses.push(item)
  }
  const licensedComponentIDs = new Set<string>()
  const componentID = (component: { name: string; version: string; location: string }) =>
    `${component.name}\x00${component.version}\x00${component.location}`
  for (const license of scan.licenses) {
    const componentNames = license.components.length > 0 ? license.components : ['']
    for (const componentName of componentNames) {
      const matchedComponents = componentIndex.get(licenseComponentKey(componentName)) ?? []
      const componentRows = matchedComponents.length > 0 ? matchedComponents : [null]
      for (const component of componentRows) {
        if (component) licensedComponentIDs.add(componentID(component))
        addLicenseInstance({
          service: excelServiceFromLocation(component?.location ?? '', scan.target, singleRootProject),
          sourcePath: excelSourcePath(component?.location ?? '', scan.target),
          pkg: component?.name || componentName || '-',
          license: license.license || 'UNKNOWN',
          severity: (license.severity || licenseSeverity(license.category)).toUpperCase(),
        })
      }
    }
  }
  for (const component of scan.components.filter((item) => !item.firstParty && item.licenses.length === 0)) {
    if (licensedComponentIDs.has(componentID(component))) continue
    addLicenseInstance({
      service: excelServiceFromLocation(component.location, scan.target, singleRootProject),
      sourcePath: excelSourcePath(component.location, scan.target),
      pkg: component.name || '-',
      license: 'UNKNOWN',
      severity: 'UNKNOWN',
    })
  }

  return { vulns, licenses, services: [...new Set([...vulns.map((row) => row.service), ...licenses.map((row) => row.service)])].sort((a, b) => a.localeCompare(b)) }
}

function vulnerabilitySheetForService(vulns: ExcelVulnInstance[], service: string) {
  const rows: unknown[][] = [['Package', 'Advisory ID', 'Severity', 'Installed Version', 'Fix To']]
  const merges: Array<{ s: { r: number; c: number }; e: { r: number; c: number } }> = []
  const rowHeights: Array<{ hpt: number } | undefined> = [{ hpt: 20 }]
  const byPackage = new Map<string, ExcelVulnInstance[]>()
  for (const vuln of vulns.filter((row) => row.service === service)) byPackage.set(vuln.pkg, [...(byPackage.get(vuln.pkg) ?? []), vuln])
  ;[...byPackage.entries()]
    .sort(([, aItems], [, bItems]) => bItems.length - aItems.length || sortExcelSeverity(aItems[0]?.severity ?? 'UNKNOWN', bItems[0]?.severity ?? 'UNKNOWN'))
    .forEach(([pkg, items]) => {
      const start = rows.length
      items
        .sort((a, b) => sortExcelSeverity(a.severity, b.severity) || a.cve.localeCompare(b.cve))
        .forEach((item, index) => {
          rows.push([index === 0 ? pkg : '', item.cve || '-', item.severity || 'UNKNOWN', item.installed || '-', item.fixed || '-'])
          rowHeights[rows.length - 1] = { hpt: 24 }
        })
      mergeExcelColumn(merges, start, rows.length - 1, 0)
    })
  return sheetFromRows(rows, [38, 24, 14, 18, 24], 2, merges, rowHeights)
}

function licenseSheetForService(licenses: ExcelLicenseInstance[], service: string) {
  const rows: unknown[][] = [['Package', 'License', 'Severity', 'Recommendation (multiple licenses)']]
  const merges: Array<{ s: { r: number; c: number }; e: { r: number; c: number } }> = []
  const rowHeights: Array<{ hpt: number } | undefined> = [{ hpt: 20 }]
  const byPackage = new Map<string, ExcelLicenseInstance[]>()
  for (const row of licenses.filter((item) => item.service === service)) byPackage.set(row.pkg, [...(byPackage.get(row.pkg) ?? []), row])
  ;[...byPackage.entries()]
    .sort(([aPkg, aItems], [bPkg, bItems]) => {
      const aMulti = aItems.length > 1 ? 0 : 1
      const bMulti = bItems.length > 1 ? 0 : 1
      return aMulti - bMulti || sortExcelSeverity(aItems[0]?.severity ?? 'UNKNOWN', bItems[0]?.severity ?? 'UNKNOWN') || aPkg.localeCompare(bPkg)
    })
    .forEach(([pkg, items]) => {
      const start = rows.length
      const sorted = items.sort((a, b) => sortExcelSeverity(a.severity, b.severity) || a.license.localeCompare(b.license))
      const recommended = recommendedExcelLicense(sorted)
      const recommendation = recommended ? `Prefer ${recommended.license || '-'} (${recommended.severity || 'UNKNOWN'})` : ''
      sorted.forEach((row, index) => {
        rows.push([index === 0 ? pkg : '', row.license || 'UNKNOWN', row.severity || 'UNKNOWN', index === 0 ? recommendation : ''])
        rowHeights[rows.length - 1] = { hpt: 24 }
      })
      const end = rows.length - 1
      mergeExcelColumn(merges, start, end, 0)
      mergeExcelColumn(merges, start, end, 3)

      let runStart = start
      let runSeverity = rows[start]?.[2]
      for (let row = start + 1; row <= end + 1; row++) {
        const severity = row <= end ? rows[row][2] : null
        if (severity === runSeverity) continue
        mergeExcelColumn(merges, runStart, row - 1, 2)
        for (let blankRow = runStart + 1; blankRow <= row - 1; blankRow++) rows[blankRow][2] = ''
        runStart = row
        runSeverity = severity
      }
    })
  return sheetFromRows(rows, [38, 34, 14, 44], 2, merges, rowHeights)
}

function mergedVulnerabilitySheet(vulns: ExcelVulnInstance[]) {
  const rows: unknown[][] = [['Source Path', 'Package', 'Advisory ID', 'Severity', 'Installed Version', 'Fix To']]
  const rowHeights: Array<{ hpt: number } | undefined> = [{ hpt: 20 }]
  ;[...vulns]
    .sort((a, b) => a.sourcePath.localeCompare(b.sourcePath) || a.pkg.localeCompare(b.pkg) || sortExcelSeverity(a.severity, b.severity) || a.cve.localeCompare(b.cve))
    .forEach((item) => {
      rows.push([item.sourcePath || item.service || 'root', item.pkg || '-', item.cve || '-', item.severity || 'UNKNOWN', item.installed || '-', item.fixed || '-'])
      rowHeights[rows.length - 1] = { hpt: 24 }
    })
  return sheetFromRows(rows, [42, 38, 24, 14, 18, 24], 3, [], rowHeights)
}

function mergedLicenseSheet(licenses: ExcelLicenseInstance[]) {
  const rows: unknown[][] = [['Source Path', 'Package', 'License', 'Severity', 'Recommendation (multiple licenses)']]
  const rowHeights: Array<{ hpt: number } | undefined> = [{ hpt: 20 }]
  const byPackage = new Map<string, ExcelLicenseInstance[]>()
  for (const row of licenses) {
    const key = `${row.sourcePath}\x00${row.pkg}`
    byPackage.set(key, [...(byPackage.get(key) ?? []), row])
  }
  ;[...byPackage.entries()]
    .sort(([, aItems], [, bItems]) => {
      const a = aItems[0]
      const b = bItems[0]
      return (a?.sourcePath ?? '').localeCompare(b?.sourcePath ?? '') || (a?.pkg ?? '').localeCompare(b?.pkg ?? '')
    })
    .forEach(([, items]) => {
      const sorted = items.sort((a, b) => sortExcelSeverity(a.severity, b.severity) || a.license.localeCompare(b.license))
      const recommended = recommendedExcelLicense(sorted)
      const recommendation = recommended ? `Prefer ${recommended.license || '-'} (${recommended.severity || 'UNKNOWN'})` : ''
      sorted.forEach((row, index) => {
        rows.push([row.sourcePath || row.service || 'root', row.pkg || '-', row.license || 'UNKNOWN', row.severity || 'UNKNOWN', index === 0 ? recommendation : ''])
        rowHeights[rows.length - 1] = { hpt: 24 }
      })
    })
  return sheetFromRows(rows, [42, 38, 34, 14, 44], 3, [], rowHeights)
}

function appendExcelServiceSheets(wb: ExcelWb, scan: ScanResult) {
  const { vulns, licenses, services } = buildExcelInstances(scan)
  const usedNames = new Set<string>()
  const tabColors: string[] = []
  for (const service of services) {
    const vulnSheetName = safeExcelSheetName('Vulnerability_', service, usedNames)
    XLSX.utils.book_append_sheet(wb, vulnerabilitySheetForService(vulns, service), vulnSheetName)
    tabColors.push('FF0000')

    const licenseSheetName = safeExcelSheetName('Licenses_', service, usedNames)
    XLSX.utils.book_append_sheet(wb, licenseSheetForService(licenses, service), licenseSheetName)
    tabColors.push('00B050')
  }
  return tabColors
}

function appendExcelSummarySheets(wb: ExcelWb, scan: ScanResult) {
  const { vulns, licenses } = buildExcelInstances(scan)
  XLSX.utils.book_append_sheet(wb, mergedVulnerabilitySheet(vulns), 'Vulnerabilities')
  XLSX.utils.book_append_sheet(wb, mergedLicenseSheet(licenses), 'Licenses')
  return ['FF0000', '00B050']
}

function patchWorkbookTabColors(bytes: Uint8Array, tabColors: string[]): Uint8Array {
  const files = unzipSync(bytes)
  tabColors.forEach((rgb, index) => {
    const path = `xl/worksheets/sheet${index + 1}.xml`
    const file = files[path]
    if (!file) return
    let xml = strFromU8(file)
    const color = `FF${rgb.replace(/^#/, '').toUpperCase().slice(-6)}`
    if (xml.includes('<sheetPr>')) {
      xml = xml.replace('<sheetPr>', `<sheetPr><tabColor rgb="${color}"/>`)
    } else {
      xml = xml.replace(/(<worksheet\b[^>]*>)/, `$1<sheetPr><tabColor rgb="${color}"/></sheetPr>`)
    }
    files[path] = strToU8(xml)
  })
  return zipSync(files)
}

export function buildStyledExcelWorkbook(scan: ScanResult, mode: ExcelExportMode = 'service') {
  const wb = XLSX.utils.book_new() as ExcelWb
  const tabColors = mode === 'summary' ? appendExcelSummarySheets(wb, scan) : appendExcelServiceSheets(wb, scan)
  return { wb, tabColors }
}

export function buildStyledExcelBytes(scan: ScanResult, mode: ExcelExportMode = 'service'): Uint8Array {
  const { wb, tabColors } = buildStyledExcelWorkbook(scan, mode)
  const bytes = XLSX.write(wb, { bookType: 'xlsx', type: 'array' }) as ArrayBuffer
  const patched = patchWorkbookTabColors(new Uint8Array(bytes), tabColors)
  const blobBytes = new Uint8Array(patched.byteLength)
  blobBytes.set(patched)
  return blobBytes
}

export function downloadStyledExcel(filename: string, scan: ScanResult, mode: ExcelExportMode = 'service'): void {
  const blobBytes = buildStyledExcelBytes(scan, mode)
  const blob = new Blob([blobBytes.buffer as ArrayBuffer], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

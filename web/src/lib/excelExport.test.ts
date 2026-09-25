import { describe, expect, it } from 'vitest'
import { buildStyledExcelBytes } from './excelExport'
import type { ScanResult } from './types'

// The workbook engine (xlsx-js-style and fflate) is imported on demand rather than at module load,
// so these assert that the export still produces a real workbook through that path. A regression
// here means the export button resolves without ever loading the engine.
const scan = {
  target: 'github.com/example/service',
  components: [
    { name: 'lodash', version: '4.17.20', type: 'npm', licenses: ['MIT'], firstParty: false, location: 'package.json' },
  ],
  vulnerabilities: [
    {
      id: 'CVE-2021-23337', component: 'lodash', version: '4.17.20', severity: 'high',
      title: 'Command injection in lodash', description: 'Template handling allows injection.',
      fixedVersion: '4.17.21', cvss: 7.2, references: [], path: ['app', 'lodash'], direct: true,
    },
  ],
  licenses: [
    { component: 'lodash', license: 'MIT', category: 'permissive', components: ['lodash'] },
  ],
} as unknown as ScanResult

describe('buildStyledExcelBytes', () => {
  it('produces a zip-formatted workbook in service mode', async () => {
    const bytes = await buildStyledExcelBytes(scan, 'service')

    expect(bytes.byteLength).toBeGreaterThan(0)
    // An xlsx file is a zip container: bytes 0-1 are the local file header magic "PK".
    expect(bytes[0]).toBe(0x50)
    expect(bytes[1]).toBe(0x4b)
  })

  it('produces a zip-formatted workbook in summary mode', async () => {
    const bytes = await buildStyledExcelBytes(scan, 'summary')

    expect(bytes.byteLength).toBeGreaterThan(0)
    expect(bytes[0]).toBe(0x50)
    expect(bytes[1]).toBe(0x4b)
  })

  // The engine promise is cached, so a second export must not depend on the first one's state
  // beyond the loaded modules.
  it('exports again after the engine is already loaded', async () => {
    const first = await buildStyledExcelBytes(scan, 'service')
    const second = await buildStyledExcelBytes(scan, 'service')

    expect(second.byteLength).toBeGreaterThan(0)
    expect(second.byteLength).toBe(first.byteLength)
  })
})

import test from 'node:test'
import assert from 'node:assert/strict'

const { buildStyledExcelWorkbook } = await import('../.tmp/excel-test/excelExport.js')

function baseComponent(overrides) {
  return {
    name: '',
    version: '',
    purl: '',
    licenses: [],
    licenseSource: '',
    licenseConfidence: '',
    unknownReason: '',
    firstParty: false,
    location: '',
    locations: [],
    ...overrides,
  }
}

function baseVulnerability(overrides) {
  return {
    id: '',
    source: 'osv',
    severity: 'high',
    cvssVector: '',
    cvssScore: 0,
    component: '',
    version: '',
    fixedVersion: '',
    alternativeFixedVersions: [],
    fixStatus: '',
    upgradeType: '',
    fixConfidence: '',
    fixReason: '',
    versionStatus: '',
    description: '',
    kev: false,
    epss: 0,
    path: [],
    direct: true,
    sources: [],
    confidence: '',
    detections: [],
    firstParty: false,
    unversioned: false,
    ...overrides,
  }
}

function sampleScan() {
  return {
    target: '/work/acme-repo',
    scanMode: 'full',
    languages: [],
    components: [
      baseComponent({
        name: 'lodash',
        version: '4.17.20',
        purl: 'pkg:npm/lodash@4.17.20',
        location: '/work/acme-repo/services/api/package-lock.json',
        locations: ['/work/acme-repo/services/api/package-lock.json', '/work/acme-repo/services/worker/package-lock.json'],
      }),
      baseComponent({ name: 'react', version: '18.2.0', purl: 'pkg:npm/react@18.2.0', location: '/work/acme-repo/apps/web/package.json' }),
    ],
    dependencies: [],
    vulnerabilities: [
      baseVulnerability({
        id: 'CVE-2021-23337',
        component: 'lodash',
        version: '4.17.20',
        versionStatus: 'VERSION_RESOLVED',
        fixedVersion: '4.17.21',
        alternativeFixedVersions: ['5.0.0'],
        fixStatus: 'FIX_AVAILABLE',
        upgradeType: 'SAME_BRANCH',
        fixConfidence: 'high',
        fixReason: 'Minimal valid same-branch fix',
        severity: 'high',
      }),
      baseVulnerability({
        id: 'GHSA-react-demo',
        component: 'react',
        version: '18.2.0',
        versionStatus: 'VERSION_RESOLVED',
        fixedVersion: '18.2.1',
        fixStatus: 'FIX_AVAILABLE',
        upgradeType: 'SAME_BRANCH',
        fixConfidence: 'medium',
        severity: 'medium',
      }),
    ],
    licenses: [{ license: 'MIT', category: 'permissive', verdict: 'allow', riskCategory: 'permissive', severity: 'low', components: ['lodash@4.17.20'] }],
    componentLicenses: [
      {
        component: 'lodash',
        version: '4.17.20',
        versionStatus: 'VERSION_RESOLVED',
        purl: 'pkg:npm/lodash@4.17.20',
        scope: 'runtime',
        location: '/work/acme-repo/services/api/package-lock.json',
        locations: ['/work/acme-repo/services/api/package-lock.json', '/work/acme-repo/services/worker/package-lock.json'],
        dependencyType: 'DIRECT',
        evidenceStatus: 'LOCKFILE_RESOLVED',
        rawLicense: 'MIT License',
        license: 'MIT',
        detectedExpression: 'MIT',
        category: 'permissive',
        verdict: 'allow',
        optionSeverity: 'low',
        effectiveSeverity: 'low',
        policyRuleId: 'LIC-PERMISSIVE',
        recommendedChoice: '354',
        selectionReason: 'Single detected license',
        source: 'package-metadata',
        confidence: 'high',
        unknownReason: '',
      },
      {
        component: 'react',
        version: '18.2.0',
        versionStatus: 'VERSION_RESOLVED',
        purl: 'pkg:npm/react@18.2.0',
        scope: 'runtime',
        location: '/work/acme-repo/apps/web/package.json',
        locations: ['/work/acme-repo/apps/web/package.json'],
        dependencyType: 'DIRECT',
        evidenceStatus: 'MANIFEST_DECLARED',
        rawLicense: '',
        license: 'UNKNOWN',
        detectedExpression: 'UNKNOWN',
        category: 'unknown',
        verdict: 'warn',
        optionSeverity: 'unknown',
        effectiveSeverity: 'unknown',
        policyRuleId: 'LIC-UNKNOWN',
        recommendedChoice: '',
        selectionReason: 'No license metadata resolved',
        source: '',
        confidence: '',
        unknownReason: 'missing metadata',
      },
    ],
    findings: [],
    toolVersions: {},
    vulnDBSnapshot: '',
    completeness: { lockfiles: [], componentsTotal: 0, componentsResolved: 0, confident: true, warning: '' },
    licenseCoverage: { total: 0, detected: 0, unknown: 0, pct: 0 },
    manifest: { toolVersions: {}, vulnDBSnapshot: '', grypeDBVersion: '', correlationVersion: 0, sbomSha256: '', reproScore: 0, pinnedInputs: [], unpinnedInputs: [] },
    findingQuality: { rawFindings: 0, actionable: 0, background: 0, production: 0, development: 0, exampleTest: 0, thirdParty: 0, firstPartyHistorical: 0, versionCoveragePct: 0, pathCoveragePct: 0, confidence: '', byPriority: {} },
    debugEvents: [],
  }
}

function rows(sheet) {
  const range = sheet['!ref']
  assert.ok(range, 'sheet has a range')
  const [start, end] = range.split(':')
  const startRow = Number(start.replace(/^[A-Z]+/, ''))
  const endRow = Number(end.replace(/^[A-Z]+/, ''))
  const endCol = end.replace(/[0-9]+$/, '')
  const colCount = endCol.charCodeAt(0) - 'A'.charCodeAt(0) + 1
  const out = []
  for (let r = startRow; r <= endRow; r++) {
    const row = []
    for (let c = 0; c < colCount; c++) row.push(sheet[`${String.fromCharCode('A'.charCodeAt(0) + c)}${r}`]?.v ?? '')
    out.push(row)
  }
  return out
}

function records(sheet) {
  const [header, ...body] = rows(sheet)
  return body.map((row) => Object.fromEntries(header.map((name, index) => [name, row[index]])))
}

test('service mode exports remediation metadata and source paths', () => {
  const { wb } = buildStyledExcelWorkbook(sampleScan(), 'service')

  assert.deepEqual(wb.SheetNames, ['Vulnerability_apps', 'Licenses_apps', 'Vulnerability_services', 'Licenses_services'])
  assert.deepEqual(rows(wb.Sheets.Vulnerability_services)[0], [
    'Package',
    'Advisory ID',
    'Severity',
    'Installed Version',
    'Version Status',
    'Fix Status',
    'Recommended Fix',
    'Alternative Fixes',
    'Upgrade Type',
    'Fix Confidence',
    'Fix Reason',
    'Source Path',
  ])

  const serviceRows = records(wb.Sheets.Vulnerability_services)
  assert.equal(serviceRows.length, 2)
  assert.deepEqual(serviceRows.map((row) => row['Source Path']).sort(), ['services/api/package-lock.json', 'services/worker/package-lock.json'])
  assert.ok(serviceRows.every((row) => row['Alternative Fixes'] === '5.0.0'))
})

test('summary mode merges all data into Vulnerabilities and Licenses with source path context', () => {
  const { wb } = buildStyledExcelWorkbook(sampleScan(), 'summary')

  assert.deepEqual(wb.SheetNames, ['Vulnerabilities', 'Licenses'])
  const vulnSheet = wb.Sheets.Vulnerabilities
  const licenseSheet = wb.Sheets.Licenses

  assert.deepEqual(rows(vulnSheet)[0], [
    'Source Path',
    'Package',
    'Advisory ID',
    'Severity',
    'Installed Version',
    'Version Status',
    'Fix Status',
    'Recommended Fix',
    'Alternative Fixes',
    'Upgrade Type',
    'Fix Confidence',
    'Fix Reason',
  ])
  assert.deepEqual(rows(licenseSheet)[0], [
    'Source Path',
    'Package',
    'Installed Version',
    'Version Status',
    'PURL',
    'Dependency Type',
    'Scope',
    'Raw License',
    'SPDX License',
    'SPDX Expression',
    'Effective Severity',
    'Policy Rule',
    'Recommendation (multiple licenses)',
    'Selection Reason',
    'Evidence Status',
  ])
  assert.equal(vulnSheet['!autofilter'].ref, 'A1:L4')
  assert.equal(vulnSheet['!sheetView'][0].state, 'frozen')

  const vulnerabilityRows = records(vulnSheet)
  assert.ok(vulnerabilityRows.some((row) => row['Source Path'] === 'services/api/package-lock.json' && row.Package === 'lodash'))
  assert.ok(vulnerabilityRows.some((row) => row['Source Path'] === 'services/worker/package-lock.json' && row.Package === 'lodash'))
  assert.ok(vulnerabilityRows.some((row) => row['Source Path'] === 'apps/web/package.json' && row.Package === 'react'))
  const lodashVulnerability = vulnerabilityRows.find((row) => row.Package === 'lodash')
  assert.equal(lodashVulnerability['Recommended Fix'], '4.17.21')
  assert.equal(lodashVulnerability['Alternative Fixes'], '5.0.0')
  assert.equal(lodashVulnerability['Fix Status'], 'FIX_AVAILABLE')
  assert.equal(lodashVulnerability['Upgrade Type'], 'SAME_BRANCH')
  assert.equal(lodashVulnerability['Fix Confidence'], 'high')

  const licenseRows = records(licenseSheet)
  const lodashLicenses = licenseRows.filter((row) => row.Package === 'lodash')
  assert.deepEqual(lodashLicenses.map((row) => row['Source Path']).sort(), ['services/api/package-lock.json', 'services/worker/package-lock.json'])
  assert.ok(lodashLicenses.every((row) => row['Installed Version'] === '4.17.20'))
  assert.ok(lodashLicenses.every((row) => row.PURL === 'pkg:npm/lodash@4.17.20'))
  assert.ok(lodashLicenses.every((row) => row['Evidence Status'] === 'LOCKFILE_RESOLVED'))
  assert.ok(lodashLicenses.every((row) => row['Raw License'] === 'MIT License' && row['SPDX License'] === 'MIT'))
  assert.ok(lodashLicenses.every((row) => row['Recommendation (multiple licenses)'] === ''))
  assert.ok(licenseRows.every((row) => row['Recommendation (multiple licenses)'] !== '354'))
  assert.ok(licenseRows.some((row) => row['Source Path'] === 'apps/web/package.json' && row.Package === 'react' && row['SPDX License'] === 'UNKNOWN'))
})

test('license export preserves SPDX alternatives and emits one safe recommendation', () => {
  const scan = sampleScan()
  scan.componentLicenses.push(
    {
      ...scan.componentLicenses[0],
      component: 'jaxb-api',
      version: '2.3.1',
      purl: 'pkg:maven/javax.xml.bind/jaxb-api@2.3.1',
      location: '/work/acme-repo/services/api/pom.xml',
      locations: ['/work/acme-repo/services/api/pom.xml'],
      rawLicense: 'CDDL 1.1',
      license: 'CDDL-1.1',
      detectedExpression: 'CDDL-1.1 OR GPL-2.0-with-classpath-exception',
      effectiveSeverity: 'medium',
      policyRuleId: 'LIC-DUAL',
      recommendedChoice: 'CDDL-1.1',
      selectionReason: 'Prefer the lower-risk allowed option',
    },
    {
      ...scan.componentLicenses[0],
      component: 'jaxb-api',
      version: '2.3.1',
      purl: 'pkg:maven/javax.xml.bind/jaxb-api@2.3.1',
      location: '/work/acme-repo/services/api/pom.xml',
      locations: ['/work/acme-repo/services/api/pom.xml'],
      rawLicense: 'GPL v2 with Classpath Exception',
      license: 'GPL-2.0-with-classpath-exception',
      detectedExpression: 'CDDL-1.1 OR GPL-2.0-with-classpath-exception',
      effectiveSeverity: 'medium',
      policyRuleId: 'LIC-DUAL',
      recommendedChoice: 'CDDL-1.1',
      selectionReason: 'Prefer the lower-risk allowed option',
    },
    {
      ...scan.componentLicenses[0],
      component: 'required-licenses',
      version: '1.0.0',
      purl: 'pkg:npm/required-licenses@1.0.0',
      location: '/work/acme-repo/services/api/package-lock.json',
      locations: ['/work/acme-repo/services/api/package-lock.json'],
      rawLicense: 'MIT',
      license: 'MIT',
      detectedExpression: 'MIT AND Apache-2.0',
      recommendedChoice: 'MIT',
      selectionReason: 'Both licenses are required',
    },
    {
      ...scan.componentLicenses[0],
      component: 'required-licenses',
      version: '1.0.0',
      purl: 'pkg:npm/required-licenses@1.0.0',
      location: '/work/acme-repo/services/api/package-lock.json',
      locations: ['/work/acme-repo/services/api/package-lock.json'],
      rawLicense: 'Apache License 2.0',
      license: 'Apache-2.0',
      detectedExpression: 'MIT AND Apache-2.0',
      recommendedChoice: 'MIT',
      selectionReason: 'Both licenses are required',
    },
  )

  const { wb } = buildStyledExcelWorkbook(scan, 'summary')
  const licenseRows = records(wb.Sheets.Licenses).filter((row) => row.Package === 'jaxb-api')

  assert.equal(licenseRows.length, 2)
  assert.ok(licenseRows.every((row) => row['SPDX Expression'] === 'CDDL-1.1 OR GPL-2.0-with-classpath-exception'))
  assert.deepEqual(licenseRows.map((row) => row['Recommendation (multiple licenses)']).sort(), ['', 'CDDL-1.1'])

  const requiredRows = records(wb.Sheets.Licenses).filter((row) => row.Package === 'required-licenses')
  assert.ok(requiredRows.every((row) => row['Recommendation (multiple licenses)'] === ''))
})

test('legacy scans without component license audit still export component identity', () => {
  const scan = sampleScan()
  delete scan.componentLicenses

  const { wb } = buildStyledExcelWorkbook(scan, 'summary')
  const licenseRows = records(wb.Sheets.Licenses)
  const lodashRows = licenseRows.filter((row) => row.Package === 'lodash')

  assert.equal(lodashRows.length, 2)
  assert.ok(lodashRows.every((row) => row['Installed Version'] === '4.17.20'))
  assert.ok(lodashRows.every((row) => row.PURL === 'pkg:npm/lodash@4.17.20'))
  assert.ok(lodashRows.every((row) => row['Recommendation (multiple licenses)'] === ''))
})

import { describe, expect, it, vi, beforeEach } from 'vitest'
import { api } from './api'
import { ENGAGEMENT_WIRE_KEYS, PROJECT_WIRE_KEYS } from './api/wire'
import { ENGAGEMENTS, PROJECTS } from '../mocks/handlers'

/**
 * Wire contract for engagements and projects.
 *
 * SOURCE OF TRUTH: `internal/adapter/httpapi/resource_view.go` — `engagementView` and
 * `projectView`. Both fixtures below are verbatim copies of what a real `synapse-api` answered on
 * `GET /api/v1/engagements` and `GET /api/v1/projects`; only the ids and timestamps are pinned so
 * the assertions can be exact.
 *
 * Why this file exists. These two resources moved from Go field names (`ID`, `Scope.InScope`,
 * `Audit.CreatedAt`) to snake_case, and nothing failed: the mock handlers in `src/mocks/handlers.ts`
 * still spoke the old shape, so the mappers and the fixtures agreed with each other and both
 * disagreed with the server. Every field read `undefined` against a real API.
 *
 * So the test asserts three things at once:
 *   1. the fixture carries exactly the keys the Go view serializes,
 *   2. the mapper turns that fixture into a fully populated domain object, with no field left at
 *      its `??` fallback — the symptom the old bug produced,
 *   3. the MSW fixtures every other suite runs against carry the same keys.
 *
 * When a json tag in resource_view.go changes, change this file, `src/lib/api/wire.ts`, the mappers
 * and `src/mocks/handlers.ts` in the same commit.
 */

/** Verbatim `GET /api/v1/engagements/{id}` from synapse-api, with roe, window and timezone set. */
function engagementWire() {
  return {
    id: 'cb1bff97731c858e9419fde72373867c',
    tenant_id: 'default',
    business_asset_id: 'ba-77',
    name: 'Review NodeGoat',
    client: 'Review',
    status: 'active',
    scope: {
      in_scope: [{ kind: 'repo', value: 'https://github.com/OWASP/NodeGoat' }],
      out_of_scope: [{ kind: 'host', value: '10.0.0.0/8' }],
    },
    roe: {
      allowed_tool_classes: ['scanner'],
      blackouts: [{ from: '2026-09-06T00:00:00Z', to: '2026-09-07T00:00:00Z' }],
    },
    authorized_from: '2026-09-05T00:00:00Z',
    authorized_to: '2026-09-12T00:00:00Z',
    timezone: 'Asia/Ho_Chi_Minh',
    live_recon_enabled: true,
    created_at: '2026-09-05T02:56:56.617935338Z',
    updated_at: '2026-09-05T02:57:29.686174473Z',
  }
}

/** Verbatim `GET /api/v1/projects` row from synapse-api, with a gate and a profile assigned. */
function projectWire() {
  return {
    id: '9725b3c1c30c88a7b85d5ea4034d6afc',
    tenant_id: 'default',
    name: 'Review NodeGoat',
    key: 'review-nodegoat',
    source_binding: { kind: 'git', value: 'https://github.com/OWASP/NodeGoat', ref: 'main' },
    default_profile_by_lang: { javascript: 'default' },
    gate_id: 'release',
    created_at: '2026-09-05T02:57:07.865295985Z',
    updated_at: '2026-09-05T02:57:07.865295985Z',
    latest_analysis: null,
    latest_job: null,
  }
}

describe('engagement wire contract', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  it('sends only keys engagementView declares', () => {
    for (const key of Object.keys(engagementWire())) {
      expect(ENGAGEMENT_WIRE_KEYS, `resource_view.go does not serialize "${key}"`).toContain(key)
    }
  })

  it('maps every field of a real server response', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => [engagementWire()] } as Response)
    const [engagement] = await api.listEngagements()

    // Exact, not toMatchObject: a mapper reading the wrong key would leave a field at its fallback
    // and toMatchObject on a subset would still pass.
    expect(engagement).toEqual({
      id: 'cb1bff97731c858e9419fde72373867c',
      name: 'Review NodeGoat',
      client: 'Review',
      status: 'active',
      inScope: [{ kind: 'repo', value: 'https://github.com/OWASP/NodeGoat' }],
      outOfScope: [{ kind: 'host', value: '10.0.0.0/8' }],
      authorizedFrom: '2026-09-05T00:00:00Z',
      authorizedTo: '2026-09-12T00:00:00Z',
      roe: {
        allowedToolClasses: ['scanner'],
        blackouts: [{ from: '2026-09-06T00:00:00Z', to: '2026-09-07T00:00:00Z' }],
      },
      liveReconEnabled: true,
      createdAt: '2026-09-05T02:56:56.617935338Z',
      businessAssetId: 'ba-77',
      findingsCount: undefined,
      lastScanDate: undefined,
    })
  })

  it('leaves no mapped field at its fallback', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => [engagementWire()] } as Response)
    const [engagement] = await api.listEngagements()
    // The old PascalCase mapper produced '' / null / false / [] for every one of these.
    expect(engagement.id).not.toBe('')
    expect(engagement.name).not.toBe('')
    expect(engagement.client).not.toBe('')
    expect(engagement.status).not.toBe('')
    expect(engagement.businessAssetId).not.toBe('')
    expect(engagement.createdAt).not.toBeNull()
    expect(engagement.authorizedFrom).not.toBeNull()
    expect(engagement.authorizedTo).not.toBeNull()
    expect(engagement.liveReconEnabled).toBe(true)
    expect(engagement.inScope).toHaveLength(1)
    expect(engagement.outOfScope).toHaveLength(1)
    expect(engagement.roe.allowedToolClasses).toHaveLength(1)
    expect(engagement.roe.blackouts).toHaveLength(1)
  })

  it('keeps the MSW fixtures on the server shape', () => {
    expect(ENGAGEMENTS.length).toBeGreaterThan(0)
    for (const row of ENGAGEMENTS) {
      for (const key of Object.keys(row)) {
        expect(ENGAGEMENT_WIRE_KEYS, `mock engagement key "${key}" is not in resource_view.go`).toContain(key)
      }
      // The three columns the engagements list renders must survive the mapper.
      expect(row).toHaveProperty('name')
      expect(row).toHaveProperty('client')
      expect(row).toHaveProperty('status')
      expect(row.scope).toHaveProperty('in_scope')
    }
  })
})

describe('project wire contract', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  it('sends only keys projectView (plus the list enrichment) declares', () => {
    const enrichment = ['latest_analysis', 'latest_job']
    for (const key of Object.keys(projectWire())) {
      if (enrichment.includes(key)) continue
      expect(PROJECT_WIRE_KEYS, `resource_view.go does not serialize "${key}"`).toContain(key)
    }
  })

  it('maps every field of a real server response', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => [projectWire()] } as Response)
    const [project] = await api.listProjects()

    expect(project).toEqual({
      id: '9725b3c1c30c88a7b85d5ea4034d6afc',
      name: 'Review NodeGoat',
      key: 'review-nodegoat',
      sourceBinding: { kind: 'git', value: 'https://github.com/OWASP/NodeGoat', ref: 'main' },
      defaultProfileByLang: { javascript: 'default' },
      gateId: 'release',
      createdAt: '2026-09-05T02:57:07.865295985Z',
      latestAnalysis: null,
      latestJob: null,
    })
  })

  it('leaves no mapped field at its fallback', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => [projectWire()] } as Response)
    const [project] = await api.listProjects()
    expect(project.id).not.toBe('')
    expect(project.name).not.toBe('')
    expect(project.key).not.toBe('')
    expect(project.gateId).not.toBe('')
    expect(project.createdAt).not.toBeNull()
    expect(project.sourceBinding.value).not.toBe('')
    expect(Object.keys(project.defaultProfileByLang)).toHaveLength(1)
  })

  it('keeps the MSW fixtures on the server shape', () => {
    const enrichment = ['latest_analysis', 'latest_job']
    expect(PROJECTS.length).toBeGreaterThan(0)
    for (const row of PROJECTS) {
      for (const key of Object.keys(row)) {
        if (enrichment.includes(key)) continue
        expect(PROJECT_WIRE_KEYS, `mock project key "${key}" is not in resource_view.go`).toContain(key)
      }
      expect(row).toHaveProperty('name')
      expect(row).toHaveProperty('key')
      expect(row.source_binding).toHaveProperty('kind')
    }
  })
})

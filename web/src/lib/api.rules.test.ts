import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api, ApiError } from './api'

describe('Rules API', () => {
  let fetchSpy: any

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  describe('listRules', () => {
    it('calls /rules with no filters', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [],
      } as unknown as Response)

      await api.listRules()
      expect(fetchSpy).toHaveBeenCalledWith('/api/v1/rules', expect.any(Object))
    })

    it('encodes query URL parameters', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [],
      } as unknown as Response)

      await api.listRules({ query: 'sql injection &' })
      expect(fetchSpy).toHaveBeenCalledWith('/api/v1/rules?q=sql+injection+%26', expect.any(Object))
    })

    it('repeats language values', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [],
      } as unknown as Response)

      await api.listRules({ languages: ['go', 'python'] })
      expect(fetchSpy).toHaveBeenCalledWith('/api/v1/rules?language=go&language=python', expect.any(Object))
    })

    it('repeats type values', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [],
      } as unknown as Response)

      await api.listRules({ types: ['bug', 'vulnerability'] })
      expect(fetchSpy).toHaveBeenCalledWith('/api/v1/rules?type=bug&type=vulnerability', expect.any(Object))
    })

    it('repeats severity values', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [],
      } as unknown as Response)

      await api.listRules({ severities: ['high', 'critical'] })
      expect(fetchSpy).toHaveBeenCalledWith('/api/v1/rules?severity=high&severity=critical', expect.any(Object))
    })

    it('repeats tag values', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [],
      } as unknown as Response)

      await api.listRules({ tags: ['security', 'owasp'] })
      expect(fetchSpy).toHaveBeenCalledWith('/api/v1/rules?tag=security&tag=owasp', expect.any(Object))
    })

    it('repeats CWE values', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [],
      } as unknown as Response)

      await api.listRules({ cwe: ['CWE-79', 'CWE-89'] })
      expect(fetchSpy).toHaveBeenCalledWith('/api/v1/rules?cwe=CWE-79&cwe=CWE-89', expect.any(Object))
    })

    it('combines filter dimensions and omits empty values', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [],
      } as unknown as Response)

      await api.listRules({
        query: '   x ',
        languages: ['go'],
        types: [],
      })
      expect(fetchSpy).toHaveBeenCalledWith('/api/v1/rules?q=x&language=go', expect.any(Object))
    })

    it('maps array normalization and snake_case', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [
          {
            key: 'go:sec',
            default_severity: 'high',
            remediation_effort: 30,
            tags: null,
          },
        ],
      } as unknown as Response)

      const res = await api.listRules()
      expect(res).toHaveLength(1)
      expect(res[0].key).toBe('go:sec')
      expect(res[0].defaultSeverity).toBe('high')
      expect(res[0].remediationEffort).toBe(30)
      expect(res[0].tags).toEqual([]) // nil normalized to []
    })
    
    it('propagates backend errors', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({ error: 'internal failure' }),
      } as unknown as Response)
      
      await expect(api.listRules()).rejects.toThrow('internal failure')
    })
  })

  describe('getRule', () => {
    it('encodes colon keys exactly once', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ key: 'go:sql-injection' }),
      } as unknown as Response)

      await api.getRule('go:sql-injection')
      expect(fetchSpy).toHaveBeenCalledWith('/api/v1/rules/go%3Asql-injection', expect.any(Object))
    })

    it('maps detail and snake_case', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          key: 'foo',
          compliant_example: 'good()',
          noncompliant_example: 'bad()',
        }),
      } as unknown as Response)

      const res = await api.getRule('foo')
      expect(res.key).toBe('foo')
      expect(res.compliantExample).toBe('good()')
      expect(res.noncompliantExample).toBe('bad()')
    })
    
    it('propagates 401 without suppressing', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: 'unauthorized' }),
      } as unknown as Response)
      
      await expect(api.getRule('foo')).rejects.toThrow(ApiError)
    })
  })

  describe('detection mapper', () => {
    async function mapDetection(detection: string): Promise<string> {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [{ key: 'test', detection }],
      } as unknown as Response)
      const res = await api.listRules()
      return res[0].detection
    }

    it('accepts ast', async () => {
      expect(await mapDetection('ast')).toBe('ast')
    })

    it('accepts pattern', async () => {
      expect(await mapDetection('pattern')).toBe('pattern')
    })

    it('accepts metric', async () => {
      expect(await mapDetection('metric')).toBe('metric')
    })

    it('rejects regex to fallback', async () => {
      expect(await mapDetection('regex')).toBe('pattern')
    })

    it('rejects secret to fallback', async () => {
      expect(await mapDetection('secret')).toBe('pattern')
    })

    it('rejects analyzer to fallback', async () => {
      expect(await mapDetection('analyzer')).toBe('pattern')
    })

    it('rejects empty string to fallback', async () => {
      expect(await mapDetection('')).toBe('pattern')
    })
  })
})

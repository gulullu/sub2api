import { beforeEach, describe, expect, it, vi } from 'vitest'
import { emptyEventFilters } from '../viewModel'

const client = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), post: vi.fn(), delete: vi.fn() }))
vi.mock('@/api/client', () => ({ apiClient: client }))

import promptAuditAPI from '../api'

describe('Prompt Audit API', () => {
  beforeEach(() => Object.values(client).forEach((mock) => mock.mockReset()))

  it('uses the independent admin route namespace', async () => {
    client.get.mockResolvedValue({ data: { config_version: 1 } })
    await promptAuditAPI.getConfig()
    expect(client.get).toHaveBeenCalledWith('/admin/prompt-audit/config')

    client.get.mockResolvedValue({ data: { process_status: 'running' } })
    await promptAuditAPI.getRuntime()
    expect(client.get).toHaveBeenCalledWith('/admin/prompt-audit/runtime')
  })

  it('sends a temporary probe token only in the request and never invents response credentials', async () => {
    client.post.mockResolvedValue({ data: { ok: true, token_applied: true } })
    const result = await promptAuditAPI.probeEndpoint({
      id: 'guard-1', name: 'Guard', protocol: 'openai_compatible', adapter: 'confidence_json', base_url: 'http://127.0.0.1:8000', model: 'guard',
      token: 'api-canary-secret', clear_token: false, timeout_ms: 1000, input_limit: 1000, enabled: true, has_token: false, token_status: 'missing',
    })
    expect(client.post).toHaveBeenCalledWith('/admin/prompt-audit/endpoints/probe', expect.objectContaining({ endpoint: expect.objectContaining({ token: 'api-canary-secret', adapter: 'confidence_json' }) }))
    expect(JSON.stringify(result)).not.toContain('api-canary-secret')
  })

  it('loads every account page before resolving stale risk-route IDs', async () => {
    client.get.mockImplementation(async (url: string, options?: { params?: { page?: number } }) => {
      expect(url).toBe('/admin/accounts')
      const page = options?.params?.page ?? 1
      return {
        data: page === 1
          ? { items: [{ id: 1, name: 'One', platform: 'openai', type: 'oauth', status: 'active', group_ids: [9, 3], groups: [{ id: 3, name: 'Codex Plus' }] }], total: 2, page: 1, page_size: 1, pages: 2 }
          : { items: [{ id: 2, name: 'Two', platform: 'anthropic', type: 'setup-token', status: 'inactive', group_ids: [] }], total: 2, page: 2, page_size: 1, pages: 2 },
      }
    })
    await expect(promptAuditAPI.listRiskRouteAccounts()).resolves.toEqual([
      { id: 1, name: 'One', platform: 'openai', type: 'oauth', status: 'active', groups: [{ id: 3, name: 'Codex Plus' }, { id: 9, name: '' }] },
      { id: 2, name: 'Two', platform: 'anthropic', type: 'setup-token', status: 'inactive', groups: [] },
    ])
    expect(client.get).toHaveBeenCalledTimes(2)
    expect(client.get).toHaveBeenNthCalledWith(1, '/admin/accounts', expect.objectContaining({ params: expect.objectContaining({ page: 1, page_size: 1000, lite: '1' }) }))
    expect(client.get).toHaveBeenNthCalledWith(2, '/admin/accounts', expect.objectContaining({ params: expect.objectContaining({ page: 2, page_size: 1000, lite: '1' }) }))
  })

  it('rejects an incomplete account list instead of mislabeling persisted IDs as deleted', async () => {
    client.get.mockResolvedValue({
      data: { items: [{ id: 1, name: 'One', platform: 'openai', type: 'oauth', status: 'active', group_ids: [], groups: [] }], total: 2, page: 1, page_size: 1000, pages: 1 },
    })
    await expect(promptAuditAPI.listRiskRouteAccounts()).rejects.toThrow('account list is incomplete')
  })

  it('passes a server preview token through the confirmed filter-delete contract', async () => {
    client.post.mockResolvedValue({ data: { deleted_events: 2, deleted_jobs: 2 } })
    const filters = emptyEventFilters()
    filters.start_at = '2026-07-15T00:00'
    filters.end_at = '2026-07-16T00:00'
    await promptAuditAPI.deleteEventsByFilter(filters, {
      matched_count: 2, filter_summary: {}, snapshot_max_id: 10, filter_hash: 'a'.repeat(64), confirmation_token: 'opaque-token', expires_at: '2026-07-16T00:05:00Z',
    })
    expect(client.post).toHaveBeenCalledWith('/admin/prompt-audit/events/delete-by-filter', expect.objectContaining({
      snapshot_max_id: 10, filter_hash: 'a'.repeat(64), confirmation_token: 'opaque-token', confirm: true,
    }))
  })
})

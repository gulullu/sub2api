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
      priority: 7, token: 'api-canary-secret', clear_token: false, timeout_ms: 1000, input_limit: 1000, enabled: true, has_token: false, token_status: 'missing',
    })
    expect(client.post).toHaveBeenCalledWith('/admin/prompt-audit/endpoints/probe', expect.objectContaining({ endpoint: expect.objectContaining({ token: 'api-canary-secret', adapter: 'confidence_json' }) }))
    expect(client.post.mock.calls[0][1].endpoint).not.toHaveProperty('priority')
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

  it('uses the isolated CYB feedback and rule endpoints with optimistic config versions', async () => {
    client.get.mockResolvedValue({ data: { items: [], total: 0, page: 1, page_size: 20, active_rules: [], config_version: 30 } })
    await promptAuditAPI.listCyberEvents('pending', 2, 20)
    expect(client.get).toHaveBeenCalledWith('/admin/prompt-audit/cyber/events', {
      params: { status: 'pending', page: 2, page_size: 20 },
    })

    client.get.mockResolvedValue({ data: { event: { id: 17 } } })
    await promptAuditAPI.getCyberEvent(17)
    expect(client.get).toHaveBeenCalledWith('/admin/prompt-audit/cyber/events/17')

    client.get.mockResolvedValue({ data: { available: true, full_prompt: 'raw', user_id: 9, truncated: false } })
    await expect(promptAuditAPI.getCyberEvidence(17)).resolves.toEqual(expect.objectContaining({
      available: true,
      full_prompt: 'raw',
      user_id: 9,
      api_key_id: null,
      identity_source: 'unavailable',
    }))
    expect(client.get).toHaveBeenCalledWith('/admin/prompt-audit/cyber/events/17/evidence')

    client.post.mockResolvedValue({ data: { config_version: 31 } })
    await promptAuditAPI.adoptCyberEvent(17, 'Detect abstract automation abuse patterns.', 30)
    expect(client.post).toHaveBeenCalledWith('/admin/prompt-audit/cyber/events/17/adopt', {
      rule_text: 'Detect abstract automation abuse patterns.',
      expected_config_version: 30,
    })

    await promptAuditAPI.rejectCyberEvent(17, 'Not generalizable')
    expect(client.post).toHaveBeenCalledWith('/admin/prompt-audit/cyber/events/17/reject', { reason: 'Not generalizable' })

    await promptAuditAPI.regenerateCyberCandidate(17)
    expect(client.post).toHaveBeenCalledWith('/admin/prompt-audit/cyber/events/17/regenerate')

    await promptAuditAPI.revokeCyberRule('cyb/rule 17', 31)
    expect(client.post).toHaveBeenCalledWith('/admin/prompt-audit/cyber/rules/cyb%2Frule%2017/revoke', {
      expected_config_version: 31,
    })

    await promptAuditAPI.restoreCyberRule('cyb/rule 17', 31)
    expect(client.post).toHaveBeenCalledWith('/admin/prompt-audit/cyber/rules/cyb%2Frule%2017/restore', {
      expected_config_version: 31,
    })

    client.delete.mockResolvedValue({ data: { config_version: 32 } })
    await promptAuditAPI.deleteCyberRule('cyb/rule 17', 31)
    expect(client.delete).toHaveBeenCalledWith('/admin/prompt-audit/cyber/rules/cyb%2Frule%2017', {
      data: { expected_config_version: 31, confirm_rule_id: 'cyb/rule 17' },
    })
  })

  it.each([
    { label: 'null arrays', data: { items: null, active_rules: null, total: 0, page: 1, page_size: 20, config_version: 30 } },
    { label: 'missing arrays', data: { total: 0, page: 1, page_size: 20, config_version: 30 } },
  ])('normalizes $label in legacy CYB page payloads', async ({ data }) => {
    client.get.mockResolvedValue({ data })

    await expect(promptAuditAPI.listCyberEvents('pending', 1, 20)).resolves.toEqual({
      items: [],
      active_rules: [],
      total: 0,
      page: 1,
      page_size: 20,
      config_version: 30,
    })
  })

  it('normalizes legacy CYB rule source metadata into the final DTO fields', async () => {
    client.get.mockResolvedValue({
      data: {
        items: [], total: 0, page: 1, page_size: 20, config_version: 30,
        active_rules: [{
          id: 'legacy-rule', rule_text: 'Recovered rule.', source_feedback_id: 1, status: 'disabled',
          created_at: '', created_by: 1, config_version: 29, text_source: 'recovered_candidate',
        }],
      },
    })

    const result = await promptAuditAPI.listCyberEvents('pending', 1, 20)
    expect(result.active_rules[0]).toEqual(expect.objectContaining({
      rule_text_source: 'recovered_candidate',
      recovered_candidate: true,
    }))
    expect(result.active_rules[0]).not.toHaveProperty('text_source')
  })

  it('normalizes nullable CYB evidence without exposing undefined values to the view', async () => {
    client.get.mockResolvedValue({ data: { evidence: null } })
    await expect(promptAuditAPI.getCyberEvidence(17)).resolves.toEqual({
      available: false,
      full_prompt: '',
      prompt_length: 0,
      message_count: 0,
      truncated: false,
      user_id: null,
      username: '',
      user_email: '',
      api_key_id: null,
      api_key_name: '',
      api_key_prefix: '',
      group_id: null,
      group_name: '',
      selected_account_id: null,
      selected_account_name: '',
      credential_account_id: null,
      credential_account_name: '',
      credential_account_email: '',
      credential_account_email_source: 'unavailable',
      identity_source: 'unavailable',
      client_ip: '',
      user_agent: '',
      client_request_id: '',
    })
  })
})

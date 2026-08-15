import { describe, expect, it } from 'vitest'
import type { PromptAuditConfig } from '../types'
import {
  buildUpdateRequest,
  configToDraft,
  createDefaultEndpoint,
  DEFAULT_BLOCK_MESSAGE,
  DEFAULT_PROMPT_TEMPLATE_ID,
  draftFingerprint,
  emptyEventFilters,
  eventFilterPayload,
  hasExplicitDeleteRange,
  SCANNER_CATALOG,
} from '../viewModel'

const config = (): PromptAuditConfig => ({
  enabled: true,
  blocking_enabled: false,
  blocking_latest_turn_only: false,
  store_pass_events: false,
  effective_mode: 'async_audit',
  strategy: 'priority',
  worker_count: 4,
  queue_capacity: 100,
  scanners: SCANNER_CATALOG.map((item) => item.id),
  all_groups: true,
  group_ids: [],
  endpoints: [{
    id: 'guard-1', name: 'Guard One', protocol: 'openai_compatible', base_url: 'http://127.0.0.1:8000',
    model: 'sileader/qwen3guard:0.6b', timeout_ms: 3000, input_limit: 4000, enabled: true,
    has_token: true, token_status: 'configured',
  }],
  config_version: 7,
  updated_at: '2026-07-16T00:00:00Z',
  updated_by: 1,
  change_summary: '{}',
})

describe('Prompt Audit view model', () => {
  it('normalizes legacy null collections from the public config', () => {
    const legacy = { ...config(), group_ids: null, scanners: null, endpoints: null } as unknown as PromptAuditConfig
    expect(configToDraft(legacy)).toMatchObject({
      group_ids: [], scanners: [], endpoints: [], risk_route_account_ids: [], active_prompt_template_id: DEFAULT_PROMPT_TEMPLATE_ID,
      flag_threshold: 0.4, block_threshold: 0.7, block_http_status: 403, block_message: DEFAULT_BLOCK_MESSAGE,
      max_total_input_chars: 40000,
    })
  })

  it('normalizes legacy endpoints and creates confidence nodes with DeepSeek limits', () => {
    expect(configToDraft(config()).endpoints[0].adapter).toBe('qwen3guard')
    expect(createDefaultEndpoint(1)).toMatchObject({
      adapter: 'confidence_json', model: 'deepseek-chat', timeout_ms: 4000, input_limit: 40000,
    })
  })

  it('includes templates, thresholds, block response, and endpoint adapter in updates', () => {
    const payload = buildUpdateRequest(configToDraft(config()))
    expect(payload).toMatchObject({
      active_prompt_template_id: DEFAULT_PROMPT_TEMPLATE_ID,
      flag_threshold: 0.4,
      block_threshold: 0.7,
      block_http_status: 403,
      block_message: DEFAULT_BLOCK_MESSAGE,
      max_total_input_chars: 40000,
      endpoints: [expect.objectContaining({ adapter: 'qwen3guard' })],
    })
    expect(payload.prompt_templates).toHaveLength(1)
  })

  it('preserves and canonicalizes persisted high-risk route account IDs on save', () => {
    const draft = configToDraft({ ...config(), risk_route_account_ids: [9, 2, 9] })
    expect(draft.risk_route_account_ids).toEqual([2, 9])
    expect(buildUpdateRequest(draft).risk_route_account_ids).toEqual([2, 9])
  })

  it('clamps and fingerprints the per-request total audit cap', () => {
    const draft = configToDraft({ ...config(), max_total_input_chars: 500000 })
    expect(draft.max_total_input_chars).toBe(400000)
    expect(buildUpdateRequest(draft).max_total_input_chars).toBe(400000)
    const before = draftFingerprint(draft)
    draft.max_total_input_chars = 30000
    expect(draftFingerprint(draft)).not.toBe(before)
  })

  it('models all nine official input scanners', () => {
    expect(SCANNER_CATALOG).toHaveLength(9)
    expect(SCANNER_CATALOG.map((item) => item.id)).toContain('suicide_and_self_harm')
  })

  it('keeps, replaces, or explicitly clears a saved token without copying plaintext from the server', () => {
    const draft = configToDraft(config())
    expect(draft.endpoints[0].token).toBe('')
    expect(buildUpdateRequest(draft).endpoints[0]).toMatchObject({ token: undefined, clear_token: false })

    draft.endpoints[0].token = 'temporary-canary-token'
    expect(buildUpdateRequest(draft).endpoints[0]).toMatchObject({ token: 'temporary-canary-token', clear_token: false })

    draft.endpoints[0].token = ''
    draft.endpoints[0].clear_token = true
    expect(buildUpdateRequest(draft).endpoints[0]).toMatchObject({ token: undefined, clear_token: true })
  })

  it('includes the optional narrow blocking scope in the update payload', () => {
    const draft = configToDraft(config())
    draft.blocking_latest_turn_only = true
    expect(buildUpdateRequest(draft)).toMatchObject({ blocking_latest_turn_only: true })
  })

  it('tracks dirty state from the full normalized save payload', () => {
    const original = configToDraft(config())
    const changed = configToDraft(config())
    expect(draftFingerprint(changed)).toBe(draftFingerprint(original))
    changed.queue_capacity += 1
    expect(draftFingerprint(changed)).not.toBe(draftFingerprint(original))
  })

  it('requires a valid explicit range and sends canonical ISO timestamps for filter deletion', () => {
    const filters = emptyEventFilters()
    expect(hasExplicitDeleteRange(filters)).toBe(false)
    filters.start_at = '2026-07-15T10:00'
    filters.end_at = '2026-07-16T10:00'
    filters.group_id = '9'
    expect(hasExplicitDeleteRange(filters)).toBe(true)
    expect(eventFilterPayload(filters)).toMatchObject({
      group_id: 9,
      start_at: new Date(filters.start_at).toISOString(),
      end_at: new Date(filters.end_at).toISOString(),
    })
  })
})

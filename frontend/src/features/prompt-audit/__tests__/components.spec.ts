import { beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import DataTable from '@/components/common/DataTable.vue'
import EndpointPool from '../components/EndpointPool.vue'
import PromptTemplatePanel from '../components/PromptTemplatePanel.vue'
import DecisionPolicyPanel from '../components/DecisionPolicyPanel.vue'
import RiskRouteAccountSelector from '../components/RiskRouteAccountSelector.vue'
import CyberFeedbackScopePanel from '../components/CyberFeedbackScopePanel.vue'
import PolicyPanel from '../components/PolicyPanel.vue'
import EventWorkspace from '../components/EventWorkspace.vue'
import EventDetailDialog from '../components/EventDetailDialog.vue'
import FilterDeleteDialog from '../components/FilterDeleteDialog.vue'
import type { PromptAuditDraft, PromptAuditEndpointDraft, PromptAuditEvent, PromptEventFilters } from '../types'
import { configToDraft, DEFAULT_BLOCK_MESSAGE, emptyEventFilters, resolveDeleteRangeFilters, SCANNER_CATALOG } from '../viewModel'
import promptAuditAPI from '../api'

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ locale: { value: 'en' }, t: (key: string, params?: Record<string, unknown>) => key.replace(/\{(\w+)\}/g, (_, token) => String(params?.[token] ?? `{${token}}`)) }) }
})

const DialogStub = defineComponent({ props: ['show', 'title'], emits: ['close'], template: '<div v-if="show" data-test="dialog"><slot /><slot name="footer" /></div>' })
const PaginationStub = defineComponent({ props: ['total', 'page', 'pageSize'], emits: ['update:page', 'update:pageSize'], template: '<div data-test="pagination" />' })

const endpoint = (): PromptAuditEndpointDraft => ({
  id: 'guard-1', name: 'Guard One', protocol: 'openai_compatible', base_url: 'http://127.0.0.1:8000',
  adapter: 'qwen3guard', model: 'guard-model', priority: 1, timeout_ms: 3000, input_limit: 4000, enabled: true,
  has_token: true, token_status: 'configured', token: '', clear_token: false,
})

describe('Prompt Audit components', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(promptAuditAPI, 'listUserProfiles').mockResolvedValue({
      items: [{
        user_id: 10,
        username: 'safe-user',
        email: 'safe@example.com',
        status: 'active',
        deleted: false,
        excluded: false,
        audit_jobs: 100,
        high_risk_jobs: 1,
        critical_risk_jobs: 0,
        high_or_critical_jobs: 1,
        system_exception_jobs: 2,
        unclassified_jobs: 90,
        usage_total: 120,
        cyber_blocked_total: 3,
        cyber_recorded_total: 3,
        sample_total: 120,
        audit_coverage: 0.8333,
        cyber_ratio: 0.025,
        high_risk_ratio: 0.01,
        critical_risk_ratio: 0,
        high_or_critical_ratio: 0.01,
        score: 0.125,
      }],
      total: 1,
      page: 1,
      page_size: 20,
      pages: 1,
    })
  })

  it('edits a saved endpoint with blank-secret keep, explicit clear, replacement, and probe actions', async () => {
    const wrapper = mount(EndpointPool, {
      props: { endpoints: [endpoint()], probeResults: {}, probingIds: [] },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.text()).toContain('admin.promptAudit.pool.configured')
    const edit = wrapper.findAll('button').find((button) => button.text().includes('common.edit'))
    expect(edit).toBeTruthy()
    await edit!.trigger('click')
    const token = wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.apiKey"]')
    expect(token.element.value).toBe('')
    expect(token.attributes('placeholder')).toContain('admin.promptAudit.pool.keepSecret')

    await wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.clearSecret"]').setValue(true)
    await token.setValue('replacement-canary')
    await wrapper.get('[data-test="save-endpoint"]').trigger('click')
    const updated = wrapper.emitted('update:endpoints')?.at(-1)?.[0] as PromptAuditEndpointDraft[]
    expect(updated[0]).toMatchObject({ token: 'replacement-canary', clear_token: false })

    const probe = wrapper.findAll('button').find((button) => button.text().includes('admin.promptAudit.pool.probe'))
    await probe!.trigger('click')
    expect(wrapper.emitted('probe')?.[0]?.[0]).toMatchObject({ id: 'guard-1' })
  })

  it('surfaces an undecryptable saved credential and prompts for re-entry', async () => {
    const invalidEndpoint = { ...endpoint(), token_status: 'invalid' }
    const wrapper = mount(EndpointPool, {
      props: { endpoints: [invalidEndpoint], probeResults: {}, probingIds: [] },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.text()).toContain('admin.promptAudit.pool.invalid')
    expect(wrapper.text()).not.toContain('admin.promptAudit.pool.configured')

    const edit = wrapper.findAll('button').find((button) => button.text().includes('common.edit'))
    await edit!.trigger('click')
    const token = wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.apiKey"]')
    expect(token.attributes('placeholder')).toContain('admin.promptAudit.pool.reenterSecret')
  })

  it('supports group search, stale configured groups, nine scanners, and bounded worker inputs', async () => {
    const draft: PromptAuditDraft = {
      enabled: true, blocking_enabled: false, blocking_latest_turn_only: false, store_pass_events: false, effective_mode: 'async_audit', strategy: 'priority',
      worker_count: 4, queue_capacity: 100, scanners: SCANNER_CATALOG.map((item) => item.id), all_groups: false, group_ids: [1, 99],
      risk_route_account_ids: [],
      cyber_feedback_account_ids: [],
      excluded_user_ids: [99],
      prompt_templates: [{ id: 'builtin', name: 'Built-in', system_prompt: 'Review input', builtin: true }], active_prompt_template_id: 'builtin',
      flag_threshold: 0.4, block_threshold: 0.7, block_http_status: 403, block_message: DEFAULT_BLOCK_MESSAGE,
      max_total_input_chars: 40000,
      endpoints: [endpoint()], config_version: 1, updated_at: '', updated_by: 0, change_summary: '',
    }
    const wrapper = mount(PolicyPanel, {
      props: { draft, groups: [{ id: 1, name: 'Alpha', platform: 'openai', status: 'active' }, { id: 2, name: 'Beta', platform: 'claude', status: 'inactive' }] },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('99')
    expect(wrapper.findAll('input[type="checkbox"]').filter((input) => SCANNER_CATALOG.some((scanner) => input.attributes('aria-label') === `admin.promptAudit.scanners.${scanner.id}`))).toHaveLength(9)
    await wrapper.get('[aria-label="admin.promptAudit.policy.searchGroups"]').setValue('Beta')
    expect(wrapper.get('[data-test="prompt-audit-group-results"]').text()).toContain('Beta')
    expect(wrapper.get('[data-test="prompt-audit-group-results"]').text()).not.toContain('Alpha')
    const selectPage = wrapper.findAll('button').find((button) => button.text().includes('admin.promptAudit.policy.profiles.selectPage'))
    await selectPage!.trigger('click')
    expect((wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft).excluded_user_ids).toEqual([10, 99])
    await wrapper.get('[aria-label="admin.promptAudit.policy.workerCount"]').setValue('6')
    const emitted = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(emitted.worker_count).toBe(6)
  })

  it('creates confidence JSON nodes with DeepSeek defaults and preserves Qwen defaults when switched', async () => {
    const wrapper = mount(EndpointPool, {
      props: { endpoints: [], probeResults: {}, probingIds: [] },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    await wrapper.get('[data-test="add-endpoint"]').trigger('click')
    const adapter = wrapper.get<HTMLSelectElement>('[aria-label="admin.promptAudit.pool.adapter"]')
    expect(adapter.element.value).toBe('confidence_json')
    const timeout = wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.timeout"]')
    const inputLimit = wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.inputLimit"]')
    expect(timeout.element.value).toBe('4000')
    expect(timeout.attributes('max')).toBe('40000')
    expect(inputLimit.element.value).toBe('40000')
    expect(inputLimit.attributes('max')).toBe('400000')
    await adapter.setValue('qwen3guard')
    expect(wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.timeout"]').element.value).toBe('3000')
    expect(wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.inputLimit"]').element.value).toBe('4000')
    await timeout.setValue('40001')
    expect(wrapper.get('[data-test="save-endpoint"]').attributes()).toHaveProperty('disabled')
    await timeout.setValue('40000')
    await inputLimit.setValue('400000')
    expect(wrapper.get('[data-test="save-endpoint"]').attributes()).not.toHaveProperty('disabled')
  })

  it('keeps a new moderation node disabled at priority 3 and locks imported credential routing', async () => {
    const wrapper = mount(EndpointPool, {
      props: { endpoints: [], probeResults: {}, probingIds: [] },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    await wrapper.get('[data-test="add-endpoint"]').trigger('click')
    await wrapper.get<HTMLSelectElement>('[aria-label="admin.promptAudit.pool.adapter"]').setValue('openai_moderation')

    expect(wrapper.get<HTMLInputElement>('[data-test="endpoint-priority"]').element.value).toBe('3')
    expect(wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.baseUrl"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.model"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.apiKey"]').attributes()).toHaveProperty('disabled')
    await wrapper.get('[data-test="save-endpoint"]').trigger('click')

    const updated = wrapper.emitted('update:endpoints')?.at(-1)?.[0] as PromptAuditEndpointDraft[]
    expect(updated[0]).toMatchObject({
      adapter: 'openai_moderation', priority: 3, enabled: false, credential_source: 'content_moderation',
    })
  })

  it('shows stable failover order, accepts explicit priority, and warns without changing timeouts', async () => {
    const endpoints = [
      { ...endpoint(), id: 'priority-two-a', name: 'Priority Two A', priority: 2, timeout_ms: 25000 },
      { ...endpoint(), id: 'priority-one', name: 'Priority One', priority: 1, timeout_ms: 20000 },
      { ...endpoint(), id: 'priority-two-b', name: 'Priority Two B', priority: 2, timeout_ms: 5000 },
      { ...endpoint(), id: 'disabled', name: 'Disabled', priority: 1, timeout_ms: 40000, enabled: false },
    ]
    const wrapper = mount(EndpointPool, {
      props: { endpoints, probeResults: {}, probingIds: [] },
      global: { stubs: { BaseDialog: DialogStub } },
    })

    expect(wrapper.findAll('article').map((item) => item.attributes('data-test'))).toEqual([
      'endpoint-priority-one', 'endpoint-disabled', 'endpoint-priority-two-a', 'endpoint-priority-two-b',
    ])
    expect(wrapper.get('[data-test="failover-position-priority-one"]').attributes('data-position')).toBe('1')
    expect(wrapper.get('[data-test="failover-position-priority-two-a"]').attributes('data-position')).toBe('2')
    expect(wrapper.get('[data-test="failover-position-priority-two-b"]').attributes('data-position')).toBe('3')
    expect(wrapper.get('[data-test="failover-summary"]').attributes('data-timeout-ms')).toBe('50000')
    expect(wrapper.get('[data-test="failover-timeout-warning"]').exists()).toBe(true)
    expect((wrapper.props('endpoints') as PromptAuditEndpointDraft[]).map((item) => item.timeout_ms)).toEqual([25000, 20000, 5000, 40000])

    const edit = wrapper.get('[data-test="endpoint-priority-two-a"]').findAll('button').find((button) => button.text().includes('common.edit'))
    await edit!.trigger('click')
    const priority = wrapper.get<HTMLInputElement>('[data-test="endpoint-priority"]')
    expect(priority.attributes('min')).toBe('1')
    expect(priority.attributes('max')).toBe('1000')
    await priority.setValue('1')
    await wrapper.get('[data-test="save-endpoint"]').trigger('click')
    const updated = wrapper.emitted('update:endpoints')?.at(-1)?.[0] as PromptAuditEndpointDraft[]
    expect(updated[0].priority).toBe(1)
    expect(updated.map((item) => item.id)).toEqual(endpoints.map((item) => item.id))
  })

  it('gives a new node the next available priority, capped at 1,000', async () => {
    const wrapper = mount(EndpointPool, {
      props: { endpoints: [{ ...endpoint(), priority: 1000 }], probeResults: {}, probingIds: [] },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    await wrapper.get('[data-test="add-endpoint"]').trigger('click')
    expect(wrapper.get<HTMLInputElement>('[data-test="endpoint-priority"]').element.value).toBe('1000')
  })

  it('switches templates, copies built-ins into editable custom templates, and protects built-ins', async () => {
    const draft = configToDraft({
      enabled: true, blocking_enabled: true, blocking_latest_turn_only: false, store_pass_events: false, effective_mode: 'blocking', strategy: 'priority',
      worker_count: 4, queue_capacity: 100, scanners: ['jailbreak'], all_groups: true, group_ids: [], endpoints: [],
      prompt_templates: [
        { id: 'builtin', name: 'Built-in', system_prompt: 'Built-in prompt', builtin: true },
        { id: 'custom-one', name: 'Custom', system_prompt: 'Custom prompt', builtin: false },
      ],
      active_prompt_template_id: 'builtin', config_version: 1, updated_at: '', updated_by: 0, change_summary: '',
    })
    const wrapper = mount(PromptTemplatePanel, { props: { draft }, global: { stubs: { BaseDialog: DialogStub } } })
    expect(wrapper.get('[data-test="prompt-template-builtin"]').findAll('button').some((button) => button.text() === 'common.edit')).toBe(false)
    await wrapper.get('[aria-label="admin.promptAudit.templates.activate"]').setValue()
    const customRadio = wrapper.findAll('input[type="radio"]')[1]
    await customRadio.setValue()
    expect((wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft).active_prompt_template_id).toBe('custom-one')

    const copy = wrapper.get('[data-test="prompt-template-builtin"]').findAll('button').find((button) => button.text() === 'admin.promptAudit.templates.copy')
    await copy!.trigger('click')
    await wrapper.get('[data-test="save-template"]').trigger('click')
    const copied = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(copied.prompt_templates.at(-1)).toMatchObject({ builtin: false, system_prompt: 'Built-in prompt' })
    expect(copied.active_prompt_template_id).toBe(copied.prompt_templates.at(-1)?.id)
  })

  it('keeps confidence thresholds ordered and bounds the client block response', async () => {
    const draft = configToDraft({
      enabled: true, blocking_enabled: true, blocking_latest_turn_only: false, store_pass_events: false, effective_mode: 'blocking', strategy: 'priority',
      worker_count: 4, queue_capacity: 100, scanners: ['jailbreak'], all_groups: true, group_ids: [], endpoints: [],
      config_version: 1, updated_at: '', updated_by: 0, change_summary: '',
    })
    const wrapper = mount(DecisionPolicyPanel, { props: { draft } })
    await wrapper.get('[data-test="flag-threshold"]').setValue('0.9')
    await wrapper.get('[data-test="flag-threshold"]').trigger('change')
    expect((wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft).flag_threshold).toBeCloseTo(0.69)
    await wrapper.get('[data-test="block-http-status"]').setValue('599')
    await wrapper.get('[data-test="block-http-status"]').trigger('change')
    expect((wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft).block_http_status).toBe(499)
  })

  it('bounds the total request audit cap and explains fail-closed versus hard routing', async () => {
    const draft = configToDraft({
      enabled: true, blocking_enabled: true, blocking_latest_turn_only: false, store_pass_events: false, effective_mode: 'blocking', strategy: 'priority',
      worker_count: 4, queue_capacity: 100, scanners: ['jailbreak'], all_groups: true, group_ids: [], endpoints: [],
      config_version: 1, updated_at: '', updated_by: 0, change_summary: '',
    })
    const wrapper = mount(DecisionPolicyPanel, { props: { draft } })
    expect(wrapper.text()).toContain('admin.promptAudit.decisionPolicy.overLimitClosed')
    await wrapper.get('[data-test="max-total-input-chars"]').setValue('500000')
    await wrapper.get('[data-test="max-total-input-chars"]').trigger('change')
    expect((wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft).max_total_input_chars).toBe(400000)

    await wrapper.setProps({ draft: { ...draft, risk_route_account_ids: [17] } })
    expect(wrapper.text()).toContain('admin.promptAudit.decisionPolicy.overLimitRoute')
    await wrapper.setProps({ draft: { ...draft, blocking_enabled: false, risk_route_account_ids: [17] } })
    expect(wrapper.text()).toContain('admin.promptAudit.decisionPolicy.overLimitAsync')
    await wrapper.setProps({ draft: { ...draft, enabled: false, blocking_enabled: false, risk_route_account_ids: [17] } })
    expect(wrapper.text()).toContain('admin.promptAudit.decisionPolicy.overLimitOff')
  })

  it('configures a blocking-only hard account pool while retaining removable stale IDs', async () => {
    const draft = configToDraft({
      enabled: true, blocking_enabled: true, blocking_latest_turn_only: false, store_pass_events: false, effective_mode: 'blocking', strategy: 'priority',
      worker_count: 4, queue_capacity: 100, scanners: ['jailbreak'], all_groups: true, group_ids: [], risk_route_account_ids: [2, 99], endpoints: [],
      config_version: 1, updated_at: '', updated_by: 0, change_summary: '',
    })
    const accounts = [
      { id: 1, name: 'OpenAI One', platform: 'openai', type: 'oauth', status: 'active', groups: [] },
      { id: 2, name: 'Claude Two', platform: 'anthropic', type: 'setup-token', status: 'active', groups: [{ id: 7, name: 'Codex Plus' }, { id: 9, name: '' }] },
    ]
    const wrapper = mount(RiskRouteAccountSelector, {
      props: { draft, accounts, loaded: true, loading: false, error: '' },
    })
    expect(wrapper.get('[data-test="risk-route-selected-2"]').text()).toContain('Claude Two')
    expect(wrapper.get('[data-test="risk-route-selected-2"]').text()).toContain('Codex Plus')
    expect(wrapper.get('[data-test="risk-route-selected-2"]').text()).toContain('admin.promptAudit.riskRoute.unknownGroup')
    expect(wrapper.get('[data-test="risk-route-selected-99"]').text()).toContain('admin.promptAudit.riskRoute.invalidAccount')
    expect(wrapper.get('[data-test="risk-route-hard-warning"]').exists()).toBe(true)

    await wrapper.get('[data-test="risk-route-selected-99"] button').trigger('click')
    const afterRemove = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(afterRemove.risk_route_account_ids).toEqual([2])

    const accountOne = wrapper.findAll<HTMLInputElement>('input[type="checkbox"]').find((input) => input.attributes('aria-label') === 'OpenAI One')
    await accountOne!.setValue(true)
    const afterAdd = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(afterAdd.risk_route_account_ids).toEqual([1, 2, 99])

    await wrapper.setProps({ draft: { ...draft, blocking_enabled: false } })
    expect(wrapper.get('[data-test="risk-route-blocking-required"]').exists()).toBe(true)
    expect(wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.riskRoute.search"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.findAll('input[type="checkbox"]').every((input) => input.attributes('disabled') !== undefined)).toBe(true)
  })

  it('searches risk-route accounts by group and labels ungrouped accounts explicitly', async () => {
    const draft = configToDraft({
      enabled: true, blocking_enabled: true, blocking_latest_turn_only: false, store_pass_events: false, effective_mode: 'blocking', strategy: 'priority',
      worker_count: 4, queue_capacity: 100, scanners: ['jailbreak'], all_groups: true, group_ids: [], endpoints: [],
      config_version: 1, updated_at: '', updated_by: 0, change_summary: '',
    })
    const wrapper = mount(RiskRouteAccountSelector, {
      props: {
        draft,
        accounts: [
          { id: 1, name: 'Risk One', platform: 'openai', type: 'oauth', status: 'active', groups: [{ id: 8, name: 'Dedicated Risk' }] },
          { id: 2, name: 'Ungrouped', platform: 'openai', type: 'oauth', status: 'active', groups: [] },
        ],
        loaded: true, loading: false, error: '',
      },
    })
    expect(wrapper.text()).toContain('admin.promptAudit.riskRoute.noGroup')
    await wrapper.get('[aria-label="admin.promptAudit.riskRoute.search"]').setValue('Dedicated Risk')
    expect(wrapper.text()).toContain('Risk One')
    expect(wrapper.text()).not.toContain('Ungrouped')
  })

  it('selects extra CYB feedback accounts independently from audit groups and account type', async () => {
    const draft = configToDraft({
      enabled: false, blocking_enabled: false, blocking_latest_turn_only: false, store_pass_events: false, effective_mode: 'off', strategy: 'priority',
      worker_count: 4, queue_capacity: 100, scanners: [], all_groups: false, group_ids: [12], cyber_feedback_account_ids: [99], endpoints: [],
      config_version: 1, updated_at: '', updated_by: 0, change_summary: '',
    })
    const wrapper = mount(CyberFeedbackScopePanel, {
      props: {
        draft,
        accounts: [{ id: 91, name: 'Selected API account', platform: 'openai', type: 'apikey', status: 'active', groups: [] }],
        accountsLoaded: true,
        loading: false,
        error: '',
      },
    })
    expect(wrapper.get('[data-test="cyber-scope-independent-hint"]').text()).toContain('admin.promptAudit.cyberScope.independentHint')
    expect(wrapper.text()).toContain('admin.promptAudit.cyberScope.missingAccounts')

    await wrapper.get<HTMLInputElement>('input[type="checkbox"]').setValue(true)
    const updated = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(updated.cyber_feedback_account_ids).toEqual([91, 99])
    expect(updated.group_ids).toEqual([12])
  })

  it('shows standalone email and API Key columns without copy controls', async () => {
    const event: PromptAuditEvent = {
      id: 1, job_id: 1, decision: 'critical', risk_level: 'critical', action: 'Block', categories: ['pii'], matched_scanners: ['pii'], scanner_scores: { pii: 1 }, scanner_evidence: { pii: 'redacted' }, scanner_backend: 'qwen3guard-openai', scanner_version: '1', guard_endpoint_id: 'guard-1', policy_id: 'priority', policy_version: 1, config_version: 1, chunk_total: 1, latency_ms: 10, issue_summaries: [], created_at: '2026-07-16T00:00:00Z',
      snapshot: { request_id: 'req-1', user_id: 1, username: 'profile-only-user', user_email: 'alice@example.test', api_key_id: 2, api_key_name: 'alice-key', group_id: 3, group_name: 'Alpha', provider: 'openai', endpoint: '/v1/chat/completions', protocol: 'openai_chat', model: 'gpt-test', prompt_hash: 'a'.repeat(64), redacted_preview: 'redacted preview', full_prompt: 'full prompt text', prompt_length: 10, message_count: 1, stage: 'http' },
    }
    const wrapper = mount(EventWorkspace, {
      props: { events: [event], total: 1, page: 1, pageSize: 20, filters: emptyEventFilters(), selectedIds: [], loading: false, error: '' },
      global: { stubs: { Pagination: PaginationStub } },
    })
    expect(wrapper.text()).toContain('alice@example.test')
    expect(wrapper.text()).toContain('alice-key')
    expect(wrapper.text()).not.toContain('profile-only-user')
    expect(wrapper.findComponent(DataTable).exists()).toBe(true)
    expect(wrapper.get('table [data-test="event-email"]').find('button').exists()).toBe(false)
    expect(wrapper.get('table [data-test="event-api-key"]').find('button').exists()).toBe(false)
    const pagination = wrapper.get('[data-test="event-pagination"]')
    expect(pagination.find('[data-test="pagination"]').exists()).toBe(true)
    expect(pagination.classes()).not.toContain('hidden')
    expect(pagination.element.closest('.hidden')).toBeNull()
    expect(wrapper.text()).toContain('admin.promptAudit.decisions.critical · admin.promptAudit.riskLevels.critical')
    expect(wrapper.text()).toContain('admin.promptAudit.scanners.pii')
    expect(wrapper.get('[data-test="filter-delete"]').attributes()).not.toHaveProperty('disabled')
    await wrapper.get('[data-test="filter-delete"]').trigger('click')
    expect(wrapper.emitted('preview-delete')).toHaveLength(1)
    await wrapper.get('[aria-label="admin.promptAudit.events.selectEvent"]').setValue(true)
    expect(wrapper.emitted('selection')?.at(-1)?.[0]).toEqual([1])
  })

  it('never exposes a key-shaped legacy API Key name in the event list', () => {
    const secret = 'sk-abcdefghijklmnopqrstuvwx1234567890'
    const event: PromptAuditEvent = {
      id: 2, job_id: 2, decision: 'pass', risk_level: 'low', action: 'Allow', categories: [], matched_scanners: [], scanner_scores: {}, scanner_evidence: {}, scanner_backend: 'confidence-json', scanner_version: '1', guard_endpoint_id: 'guard-1', policy_id: 'priority', policy_version: 1, config_version: 1, chunk_total: 1, latency_ms: 10, issue_summaries: [], created_at: '2026-07-16T00:00:00Z',
      snapshot: { request_id: 'req-2', user_id: 1, username: 'alice-with-an-intentionally-long-username', user_email: `${'very-long-address-'.repeat(8)}@example.test`, api_key_id: 2, api_key_name: secret, group_id: 3, group_name: 'Alpha', provider: 'openai', endpoint: '/v1/responses', protocol: 'openai_responses', model: 'gpt-test', prompt_hash: 'b'.repeat(64), redacted_preview: 'preview', full_prompt: 'prompt', prompt_length: 6, message_count: 1, stage: 'http' },
    }
    const wrapper = mount(EventWorkspace, {
      props: { events: [event], total: 1, page: 1, pageSize: 20, filters: emptyEventFilters(), selectedIds: [], loading: false, error: '' },
      global: { stubs: { Pagination: PaginationStub } },
    })
    expect(wrapper.html()).not.toContain(secret)
    expect(wrapper.text()).toContain('sk-abc…7890')
    expect(wrapper.get('table').classes()).toContain('min-w-max')
    expect(wrapper.get('table').classes()).not.toContain('table-fixed')
    expect(wrapper.get('table [data-test="event-email"]').findAll('.truncate')).toHaveLength(1)
    expect(wrapper.get('table [data-test="event-api-key"]').findAll('.truncate')).toHaveLength(1)
    expect(wrapper.get('table [data-test="event-email"]').find('button').exists()).toBe(false)
    expect(wrapper.get('table [data-test="event-api-key"]').find('button').exists()).toBe(false)
    expect(wrapper.get('table').element.parentElement?.classList.contains('table-wrapper')).toBe(true)
  })

  it('resolves delete range presets to an epoch start and a cutoff end', () => {
    const now = Date.parse('2026-07-17T12:00:00.000Z')
    const sevenDays = resolveDeleteRangeFilters(emptyEventFilters(), '7d', now)
    expect(sevenDays.start_at).toBe('1970-01-01T00:00:00.000Z')
    expect(sevenDays.end_at).toBe('2026-07-10T12:00:00.000Z')
    const all = resolveDeleteRangeFilters(emptyEventFilters(), 'all', now)
    expect(all.start_at).toBe('1970-01-01T00:00:00.000Z')
    expect(all.end_at).toBe('2026-07-17T12:00:00.000Z')
    const customSource = { ...emptyEventFilters(), start_at: '2026-07-01T00:00', end_at: '2026-07-02T00:00' }
    expect(resolveDeleteRangeFilters(customSource, 'custom', now)).toEqual(customSource)
  })

  it('drives filter deletion through presets, custom validation, preview, and confirm', async () => {
    const wrapper = mount(FilterDeleteDialog, {
      props: { show: true, initialFilters: emptyEventFilters(), preview: null, previewing: false, deleting: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get<HTMLInputElement>('[data-test="range-preset-7d"]').element.checked).toBe(true)
    expect(wrapper.find('[data-test="custom-range"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="delete-preview-empty"]').exists()).toBeTruthy()
    // A valid preset is enough: confirm is armed immediately (one-click flow)
    // and needs no disabled-reason hint.
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).not.toHaveProperty('disabled')
    expect(wrapper.find('[data-test="confirm-disabled-reason"]').exists()).toBe(false)
    await wrapper.get('[data-test="confirm-filter-delete"]').trigger('click')
    const directConfirm = wrapper.emitted('confirm')?.at(-1)?.[0] as PromptEventFilters
    expect(directConfirm.start_at).toBe('1970-01-01T00:00:00.000Z')
    expect(Date.now() - new Date(directConfirm.end_at).getTime()).toBeGreaterThanOrEqual(7 * 24 * 60 * 60 * 1000)

    await wrapper.get('[data-test="range-preset-30d"]').setValue()
    expect(wrapper.emitted('criteria-change')?.length).toBeGreaterThan(0)
    await wrapper.get('[data-test="delete-risk"]').setValue('high')
    await wrapper.get('[data-test="run-delete-preview"]').trigger('click')
    const presetPreview = wrapper.emitted('preview')?.at(-1)?.[0] as PromptEventFilters
    expect(presetPreview.risk_level).toBe('high')
    expect(presetPreview.start_at).toBe('1970-01-01T00:00:00.000Z')
    expect(Date.now() - new Date(presetPreview.end_at).getTime()).toBeGreaterThanOrEqual(30 * 24 * 60 * 60 * 1000)

    await wrapper.get('[data-test="range-preset-custom"]').setValue()
    expect(wrapper.find('[data-test="custom-range"]').exists()).toBe(true)
    expect(wrapper.get('[data-test="run-delete-preview"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.get('[data-test="confirm-disabled-reason"]').text()).toBe('admin.promptAudit.events.filterDeleteConfirmInvalidRange')
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes('title')).toBe('admin.promptAudit.events.filterDeleteConfirmInvalidRange')
    await wrapper.get('[data-test="custom-range"] [aria-label="admin.promptAudit.events.startAt"]').setValue('2026-07-01T00:00')
    await wrapper.get('[data-test="custom-range"] [aria-label="admin.promptAudit.events.endAt"]').setValue('2026-07-02T00:00')
    expect(wrapper.get('[data-test="run-delete-preview"]').attributes()).not.toHaveProperty('disabled')
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).not.toHaveProperty('disabled')
    expect(wrapper.find('[data-test="confirm-disabled-reason"]').exists()).toBe(false)
    await wrapper.get('[data-test="run-delete-preview"]').trigger('click')
    const customPreview = wrapper.emitted('preview')?.at(-1)?.[0] as PromptEventFilters
    expect(customPreview.start_at).toBe('2026-07-01T00:00')
    expect(customPreview.end_at).toBe('2026-07-02T00:00')

    await wrapper.setProps({
      preview: { matched_count: 3, filter_summary: {}, snapshot_max_id: 9, filter_hash: 'b'.repeat(64), confirmation_token: 'tok', expires_at: '2026-07-16T00:05:00Z' },
    })
    expect(wrapper.get('[data-test="delete-preview-result"]').text()).toContain('admin.promptAudit.events.filterDeleteCount')
    expect(wrapper.find('[data-test="confirm-disabled-reason"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).not.toHaveProperty('disabled')
    await wrapper.get('[data-test="confirm-filter-delete"]').trigger('click')
    const confirmed = wrapper.emitted('confirm')?.at(-1)?.[0] as PromptEventFilters
    expect(confirmed.start_at).toBe('2026-07-01T00:00')
    expect(confirmed.end_at).toBe('2026-07-02T00:00')
  })

  it('explains that a zero-match preview leaves nothing to delete', async () => {
    const wrapper = mount(FilterDeleteDialog, {
      props: {
        show: true,
        initialFilters: emptyEventFilters(),
        preview: { matched_count: 0, filter_summary: {}, snapshot_max_id: 0, filter_hash: 'c'.repeat(64), confirmation_token: 'tok', expires_at: '2026-07-16T00:05:00Z' },
        previewing: false,
        deleting: false,
      },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.get('[data-test="confirm-disabled-reason"]').text()).toBe('admin.promptAudit.events.filterDeleteConfirmNoMatches')
    await wrapper.setProps({ previewing: true })
    expect(wrapper.find('[data-test="confirm-disabled-reason"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).toHaveProperty('disabled')
  })

  it('inherits an explicit list-filter range as the custom preset', async () => {
    const initialFilters = { ...emptyEventFilters(), start_at: '2026-07-01T00:00', end_at: '2026-07-02T00:00', decision: 'critical' }
    const wrapper = mount(FilterDeleteDialog, {
      props: { show: true, initialFilters, preview: null, previewing: false, deleting: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get<HTMLInputElement>('[data-test="range-preset-custom"]').element.checked).toBe(true)
    expect(wrapper.get<HTMLInputElement>('[data-test="custom-range"] [aria-label="admin.promptAudit.events.startAt"]').element.value).toBe('2026-07-01T00:00')
    expect(wrapper.get<HTMLSelectElement>('[data-test="delete-decision"]').element.value).toBe('critical')
    expect(wrapper.get('[data-test="run-delete-preview"]').attributes()).not.toHaveProperty('disabled')
  })

  it('shows the full unredacted prompt and structured guard return on the risks tab', async () => {
    const event: PromptAuditEvent = {
      id: 1, job_id: 1, decision: 'critical', risk_level: 'critical', action: 'Block',
      categories: ['sexual_content_or_sexual_acts'], matched_scanners: ['sexual_content_or_sexual_acts'],
      scanner_scores: { sexual_content_or_sexual_acts: 1 },
      scanner_evidence: { sexual_content_or_sexual_acts: 'Sexual Content or Sexual Acts' },
      scanner_backend: 'qwen3guard-openai', scanner_version: 'qwen3guard', guard_endpoint_id: 'guard-1',
      policy_id: 'priority', policy_version: 1, config_version: 1, chunk_total: 1, latency_ms: 12,
      issue_summaries: [{
        category: 'sexual_content_or_sexual_acts', scanner_id: 'sexual_content_or_sexual_acts',
        title: '性内容或性行为', description: 'Sexual content or sexual acts', severity: 'critical',
        severity_label: '严重', action: 'Block', action_label: '阻止',
        code: 'prompt_audit_sexual_content_or_sexual_acts', score: 1,
        evidence: 'Sexual Content or Sexual Acts', evidence_hash: 'abc',
      }],
      created_at: '2026-07-16T00:00:00Z',
      snapshot: {
        request_id: 'req-1', user_id: 1, username: 'alice', user_email: 'alice@example.test',
        api_key_id: 2, api_key_name: 'alice-key', group_id: 3, group_name: 'Alpha', provider: 'openai',
        endpoint: '/v1/chat/completions', protocol: 'openai_chat', model: 'gpt-test',
        prompt_hash: 'a'.repeat(64), redacted_preview: 'redacted prompt body', full_prompt: 'complete unmasked prompt body', prompt_length: 20,
        message_count: 1, stage: 'http',
      },
    }
    const wrapper = mount(EventDetailDialog, {
      props: { show: true, event, loading: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    const panel = wrapper.get('[data-test="event-detail-tab-panel"]')
    expect(panel.classes()).toContain('h-[min(62vh,36rem)]')
    expect(panel.classes()).toContain('overflow-y-auto')

    const riskTab = wrapper.findAll('[role="tab"]').find((tab) => tab.text().includes('admin.promptAudit.events.tabs.risks'))
    expect(riskTab).toBeTruthy()
    expect(riskTab!.classes()).toContain('tab')
    await riskTab!.trigger('click')
    expect(riskTab!.classes()).toContain('tab-active')
    expect(wrapper.get('[data-test="event-detail-tab-panel"]').classes()).toContain('h-[min(62vh,36rem)]')
    expect(wrapper.get('[data-test="risk-prompt-preview"]').text()).toContain('complete unmasked prompt body')
    expect(wrapper.get('[data-test="risk-prompt-preview"]').text()).not.toContain('redacted prompt body')
    expect(wrapper.get('[data-test="risk-prompt-full"]').classes()).toContain('overflow-auto')
    expect(wrapper.get('[data-test="risk-guard-return"]').text()).toContain('"decision": "admin.promptAudit.decisions.critical"')
    expect(wrapper.get('[data-test="risk-guard-return"]').text()).toContain('admin.promptAudit.scanners.sexual_content_or_sexual_acts')
    expect(wrapper.get('[data-test="risk-issue"]').text()).toContain('admin.promptAudit.scanners.sexual_content_or_sexual_acts')
    await wrapper.get('[data-test="event-detail-close"]').trigger('click')
    expect(wrapper.emitted('close')).toHaveLength(1)
  })

  it('localizes confidence JSON risk summaries instead of showing backend labels or raw category keys', async () => {
    const fullReason = '内容为针对AI系统的越狱攻击矩阵，包含绕过规则、分阶段攻击步骤以及完整判断依据。\n第二行原因也必须原样显示。'
    const event: PromptAuditEvent = {
      id: 3, job_id: 3, decision: 'flag', risk_level: 'medium', action: 'Warn',
      categories: [], matched_scanners: ['confidence_json'], scanner_scores: { confidence_json: 0.55 },
      scanner_evidence: { confidence_json: fullReason }, scanner_backend: 'confidence-json-openai',
      scanner_version: 'deepseek-chat', guard_endpoint_id: 'deepseek', policy_id: 'relaybases-cyber-safety-v1',
      policy_version: 1, config_version: 2, chunk_total: 1, latency_ms: 20,
      issue_summaries: [{
        category: 'confidence_json', scanner_id: 'confidence_json', title: '模型置信度判定',
        description: '通用审核模型按配置的置信度阈值标记了风险', severity: 'medium', severity_label: '中',
        action: 'Warn', action_label: '警告', code: 'prompt_audit_confidence_json', score: 0.55,
        evidence: fullReason, evidence_hash: 'def',
      }],
      created_at: '2026-07-16T00:00:00Z',
      snapshot: {
        request_id: 'req-confidence', user_id: 1, username: 'alice', user_email: 'alice@example.test',
        api_key_id: 2, api_key_name: 'alice-key', group_id: 3, group_name: 'Alpha', provider: 'openai',
        endpoint: '/v1/responses', protocol: 'openai_responses', model: 'gpt-test', prompt_hash: 'c'.repeat(64),
        redacted_preview: 'preview', full_prompt: 'full prompt', prompt_length: 11, message_count: 1, stage: 'http',
      },
    }
    const wrapper = mount(EventDetailDialog, {
      props: { show: true, event, loading: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    const riskTab = wrapper.findAll('[role="tab"]').find((tab) => tab.text().includes('admin.promptAudit.events.tabs.risks'))
    await riskTab!.trigger('click')
    const issue = wrapper.get('[data-test="risk-issue"]').text()
    expect(issue).toContain('admin.promptAudit.scanners.confidence_json')
    expect(issue).toContain('admin.promptAudit.scannerDescriptions.confidence_json')
    expect(issue).not.toContain('模型置信度判定')
    expect(issue).not.toContain('通用审核模型按配置的置信度阈值标记了风险')
    expect(wrapper.get('[data-test="risk-guard-return"]').text()).toContain('admin.promptAudit.scanners.confidence_json')
    const evidence = wrapper.get('[data-test="risk-issue-evidence"]')
    expect(evidence.element.textContent).toBe(fullReason)
    expect(evidence.classes()).toContain('whitespace-pre-wrap')
    expect(evidence.classes()).toContain('overflow-auto')
    expect(wrapper.get('[data-test="risk-guard-return-json"]').text()).toContain('第二行原因也必须原样显示。')
  })

  it('localizes over-limit audit events in both the list and detail view', async () => {
    const event: PromptAuditEvent = {
      id: 4, job_id: 4, decision: 'flag', risk_level: 'high', action: 'Warn',
      categories: ['input_too_large'], matched_scanners: ['input_too_large'], scanner_scores: { input_too_large: 1 },
      scanner_evidence: { input_too_large: 'input_too_large' }, scanner_backend: 'local-policy', scanner_version: '1',
      guard_endpoint_id: '', policy_id: 'relaybases-cyber-safety-v1', policy_version: 1, config_version: 2, chunk_total: 0, latency_ms: 0,
      issue_summaries: [{
        category: 'input_too_large', scanner_id: 'input_too_large', title: 'input_too_large', description: 'input_too_large',
        severity: 'high', severity_label: 'high', action: 'Warn', action_label: 'Warn', code: 'prompt_audit_input_too_large', score: 1,
        evidence: '', evidence_hash: '',
      }],
      created_at: '2026-07-16T00:00:00Z',
      snapshot: {
        request_id: 'req-too-large', user_id: 1, username: 'alice', user_email: 'alice@example.test', api_key_id: 2,
        api_key_name: 'alice-key', group_id: 3, group_name: 'Alpha', provider: 'openai', endpoint: '/v1/responses',
        protocol: 'openai_responses', model: 'gpt-test', prompt_hash: 'd'.repeat(64), redacted_preview: 'preview', full_prompt: 'full prompt',
        prompt_length: 40001, message_count: 1, stage: 'http',
      },
    }
    const list = mount(EventWorkspace, {
      props: { events: [event], total: 1, page: 1, pageSize: 20, filters: emptyEventFilters(), selectedIds: [], loading: false, error: '' },
      global: { stubs: { Pagination: PaginationStub } },
    })
    expect(list.text()).toContain('admin.promptAudit.scanners.input_too_large')

    const detail = mount(EventDetailDialog, {
      props: { show: true, event, loading: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    const riskTab = detail.findAll('[role="tab"]').find((tab) => tab.text().includes('admin.promptAudit.events.tabs.risks'))
    await riskTab!.trigger('click')
    const issue = detail.get('[data-test="risk-issue"]').text()
    expect(issue).toContain('admin.promptAudit.scanners.input_too_large')
    expect(issue).toContain('admin.promptAudit.scannerDescriptions.input_too_large')
    expect(issue).not.toContain('prompt_audit_input_too_large')
  })

  it('falls back to the redacted preview for events stored before full prompts were kept', async () => {
    const event: PromptAuditEvent = {
      id: 2, job_id: 2, decision: 'flag', risk_level: 'medium', action: 'Warn',
      categories: ['pii'], matched_scanners: ['pii'], scanner_scores: {}, scanner_evidence: {},
      scanner_backend: 'qwen3guard-openai', scanner_version: '1', guard_endpoint_id: 'guard-1',
      policy_id: 'priority', policy_version: 1, config_version: 1, chunk_total: 1, latency_ms: 5,
      issue_summaries: [], created_at: '2026-07-16T00:00:00Z',
      snapshot: {
        request_id: 'req-2', user_id: 1, username: 'bob', user_email: '', api_key_id: 2,
        api_key_name: 'bob-key', group_id: 3, group_name: 'Alpha', provider: 'openai',
        endpoint: '/v1/chat/completions', protocol: 'openai_chat', model: 'gpt-test',
        prompt_hash: 'b'.repeat(64), redacted_preview: 'legacy redacted preview', full_prompt: '', prompt_length: 20,
        message_count: 1, stage: 'http',
      },
    }
    const wrapper = mount(EventDetailDialog, {
      props: { show: true, event, loading: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    const riskTab = wrapper.findAll('[role="tab"]').find((tab) => tab.text().includes('admin.promptAudit.events.tabs.risks'))
    await riskTab!.trigger('click')
    expect(wrapper.get('[data-test="risk-prompt-full"]').text()).toContain('legacy redacted preview')
  })
})

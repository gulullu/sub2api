import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent } from 'vue'

import DataTable from '@/components/common/DataTable.vue'
import Input from '@/components/common/Input.vue'
import Pagination from '@/components/common/Pagination.vue'
import Select from '@/components/common/Select.vue'
import ProbeGovernanceEventDetailDialog from '../components/ProbeGovernanceEventDetailDialog.vue'
import ProbeGovernanceEventsDialog from '../components/ProbeGovernanceEventsDialog.vue'
import ProbeGovernanceExemptionsDialog from '../components/ProbeGovernanceExemptionsDialog.vue'
import ProbeGovernanceWorkspace from '../components/ProbeGovernanceWorkspace.vue'
import type {
  ProbeGovernanceEvent,
  ProbeGovernanceEventDetail,
  ProbeGovernanceExemption,
  ProbeGovernancePolicy,
  PromptAuditDraft,
} from '../types'
import { configToDraft } from '../viewModel'

const mocks = vi.hoisted(() => ({
  listPolicies: vi.fn(),
  updatePolicy: vi.fn(),
  listEvents: vi.fn(),
  getEvent: vi.fn(),
  clearEvent: vi.fn(),
  listExemptions: vi.fn(),
  createExemption: vi.fn(),
  deleteExemption: vi.fn(),
  searchUsers: vi.fn(),
  searchApiKeys: vi.fn(),
  showSuccess: vi.fn(),
  showError: vi.fn(),
}))

vi.mock('../api', () => ({ default: {
  listProbeGovernancePolicies: mocks.listPolicies,
  updateProbeGovernancePolicy: mocks.updatePolicy,
  listProbeGovernanceEvents: mocks.listEvents,
  getProbeGovernanceEvent: mocks.getEvent,
  clearProbeGovernanceEvent: mocks.clearEvent,
  listProbeGovernanceExemptions: mocks.listExemptions,
  createProbeGovernanceExemption: mocks.createExemption,
  deleteProbeGovernanceExemption: mocks.deleteExemption,
} }))
vi.mock('@/api/admin', () => ({ adminAPI: { usage: { searchUsers: mocks.searchUsers, searchApiKeys: mocks.searchApiKeys } } }))
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showSuccess: mocks.showSuccess, showError: mocks.showError }) }))
vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ locale: { value: 'zh-CN' }, t: (key: string) => key }) }
})

const BaseDialogStub = defineComponent({ props: ['show'], template: '<div v-if="show"><slot/><slot name="footer"/></div>' })

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve
    reject = promiseReject
  })
  return { promise, resolve, reject }
}

function auditDraft(groupIDs: number[]): PromptAuditDraft {
  const value = configToDraft({
    enabled: true,
    blocking_enabled: true,
    blocking_latest_turn_only: true,
    store_pass_events: false,
    effective_mode: 'blocking',
    strategy: 'priority',
    worker_count: 4,
    queue_capacity: 100,
    scanners: ['confidence_json'],
    all_groups: false,
    group_ids: groupIDs,
    endpoints: [],
    config_version: 1,
    updated_at: '',
    updated_by: 1,
    change_summary: '',
  })
  value.group_policies = []
  return value
}

function policy(groupID = 1, groupName = 'claude-max', enabled = true): ProbeGovernancePolicy {
  return {
    group_id: groupID,
    group_name: groupName,
    enabled,
    interval_seconds: 300,
    health_scope: 'group_model_protocol',
    allow_first_real_probe: true,
    skip_repeat_audit: true,
    skip_repeat_upstream: true,
    healthy_response: 'healthy',
    violation_response: 'violation',
    unknown_response: 'unknown',
    local_responses_24h: 10,
    skipped_audits_24h: 9,
    skipped_upstream_24h: 8,
  }
}

function probeEvent(id: number): ProbeGovernanceEvent {
  return {
    id,
    group_id: 1,
    group_name: 'claude-max',
    family_fingerprint: `family-${id}`,
    family_preview: `preview-${id}`,
    classification: 'healthy',
    verdict: 'healthy',
    user_id: 44,
    user_email: 'user@example.com',
    api_key_id: 55,
    api_key_name: 'monitor-key',
    model: 'gpt-5.6-luna',
    protocol: 'openai_responses',
    stream: true,
    max_tokens: 16,
    first_seen_at: '2026-08-31T00:00:00Z',
    last_seen_at: '2026-08-31T00:01:00Z',
    total_count: 2,
    local_response_count: 1,
    audit_skipped_count: 1,
    upstream_skipped_count: 1,
    audit_call_count: 1,
    upstream_call_count: 1,
    handling: 'local_healthy',
  }
}

function probeDetail(): ProbeGovernanceEventDetail {
  return {
    ...probeEvent(88),
    audit_config_version: 57,
    probe_config_version: 106,
    evidence: {},
    risk_source: 'probe_family',
    response_kind: 'healthy',
    prompt_snapshot: {},
    created_at: '2026-08-31T00:00:00Z',
    updated_at: '2026-08-31T00:01:00Z',
  }
}

function exemption(id: number): ProbeGovernanceExemption {
  return {
    id,
    group_id: 1,
    user_id: null,
    user_email: '',
    api_key_id: 55,
    api_key_name: `key-${id}`,
    reason: 'monitor',
    expires_at: null,
    created_at: '2026-08-31T00:00:00Z',
    created_by: 1,
  }
}

function page<T>(items: T[], pageNumber = 1, pageSize = 20) {
  return { items, total: items.length, page: pageNumber, page_size: pageSize, pages: items.length ? 1 : 0 }
}

function localDateTime(timestamp: number): string {
  const date = new Date(timestamp)
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16)
}

describe('Probe governance reliability', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }),
    })
    localStorage.clear()
    Object.values(mocks).forEach((mock) => mock.mockReset())
    mocks.updatePolicy.mockResolvedValue(policy())
    mocks.searchUsers.mockResolvedValue([])
    mocks.searchApiKeys.mockResolvedValue([])
    mocks.listEvents.mockResolvedValue(page([]))
    mocks.listExemptions.mockResolvedValue(page([]))
    mocks.createExemption.mockResolvedValue(exemption(1))
    mocks.deleteExemption.mockResolvedValue({ deleted: true })
  })

  it('does not expose synthesized writable policies after a failed load, but does after a successful empty response', async () => {
    mocks.listPolicies.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(page([], 1, 100))
    const wrapper = mount(ProbeGovernanceWorkspace, {
      props: { draft: auditDraft([1]), groups: [{ id: 1, name: 'claude-max', status: 'active', platform: 'anthropic' }] },
      global: { stubs: { Pagination: true, ProbeGovernancePolicyDialog: true, ProbeGovernanceEventsDialog: true, ProbeGovernanceExemptionsDialog: true } },
    })
    await flushPromises()

    expect(wrapper.find('[data-test="probe-governance-table"]').exists()).toBe(false)
    expect(wrapper.get('[role="alert"]').text()).toContain('offline')
    expect(mocks.updatePolicy).not.toHaveBeenCalled()

    await wrapper.get('[data-test="probe-governance-refresh"]').trigger('click')
    await flushPromises()
    const rows = wrapper.getComponent(DataTable).props('data') as ProbeGovernancePolicy[]
    expect(rows).toEqual([expect.objectContaining({ group_id: 1, enabled: false, interval_seconds: 300 })])
  })

  it('synchronizes the visible page when persisted scope shrinks', async () => {
    const ids = Array.from({ length: 25 }, (_, index) => index + 1)
    const groups = ids.map((id) => ({ id, name: `group-${id}`, status: 'active' as const, platform: 'anthropic' }))
    mocks.listPolicies.mockResolvedValue(page(groups.map((group) => policy(group.id, group.name)), 1, 100))
    const wrapper = mount(ProbeGovernanceWorkspace, {
      props: { draft: auditDraft(ids), groups },
      global: { stubs: { ProbeGovernancePolicyDialog: true, ProbeGovernanceEventsDialog: true, ProbeGovernanceExemptionsDialog: true } },
    })
    await flushPromises()

    wrapper.getComponent(Pagination).vm.$emit('update:page', 2)
    await wrapper.vm.$nextTick()
    expect(wrapper.getComponent(Pagination).props('page')).toBe(2)

    await wrapper.setProps({ draft: auditDraft([1]) })
    await flushPromises()
    expect(wrapper.getComponent(Pagination).props('page')).toBe(1)
  })

  it('keeps the latest event filters when an older request resolves last', async () => {
    const older = deferred<ReturnType<typeof page<ProbeGovernanceEvent>>>()
    const latest = deferred<ReturnType<typeof page<ProbeGovernanceEvent>>>()
    mocks.listEvents.mockReset()
    mocks.listEvents.mockReturnValueOnce(older.promise).mockReturnValueOnce(latest.promise)
    const wrapper = mount(ProbeGovernanceEventsDialog, {
      props: { show: false, group: policy() },
      global: { stubs: { BaseDialog: BaseDialogStub, Pagination: true, ProbeGovernanceEventDetailDialog: true } },
    })
    await wrapper.setProps({ show: true })
    await wrapper.vm.$nextTick()

    wrapper.getComponent(Input).vm.$emit('update:modelValue', 'new-model')
    await wrapper.get('form').trigger('submit')
    expect(mocks.listEvents).toHaveBeenCalledTimes(2)

    latest.resolve(page([probeEvent(2)]))
    await flushPromises()
    expect((wrapper.getComponent(DataTable).props('data') as ProbeGovernanceEvent[])[0].id).toBe(2)
    older.resolve(page([probeEvent(1)]))
    await flushPromises()
    expect((wrapper.getComponent(DataTable).props('data') as ProbeGovernanceEvent[])[0].id).toBe(2)
  })

  it('keeps the latest event detail when a closed older request resolves last', async () => {
    const older = deferred<ProbeGovernanceEventDetail>()
    const latest = deferred<ProbeGovernanceEventDetail>()
    mocks.listEvents.mockResolvedValue(page([probeEvent(1), probeEvent(2)]))
    mocks.getEvent.mockReturnValueOnce(older.promise).mockReturnValueOnce(latest.promise)
    const detailStub = defineComponent({
      props: ['show', 'event'],
      emits: ['close'],
      template: '<div v-if="show" data-test="probe-detail-stub"><span data-test="probe-detail-id">{{ event?.id ?? "loading" }}</span><button data-test="probe-detail-close" @click="$emit(\'close\')">close</button></div>',
    })
    const wrapper = mount(ProbeGovernanceEventsDialog, {
      props: { show: false, group: policy() },
      global: { stubs: { BaseDialog: BaseDialogStub, Pagination: true, ProbeGovernanceEventDetailDialog: detailStub } },
    })
    await wrapper.setProps({ show: true })
    await flushPromises()

    const viewButtons = () => wrapper.findAll('button').filter((button) => button.text() === 'common.view')
    await viewButtons()[0].trigger('click')
    await wrapper.get('[data-test="probe-detail-close"]').trigger('click')
    await viewButtons()[1].trigger('click')

    latest.resolve({ ...probeDetail(), id: 2 })
    await flushPromises()
    expect(wrapper.get('[data-test="probe-detail-id"]').text()).toBe('2')

    older.resolve({ ...probeDetail(), id: 1 })
    await flushPromises()
    expect(wrapper.get('[data-test="probe-detail-id"]').text()).toBe('2')
  })

  it('immediately clears remote-search loading and invalidates stale API Key results when the user changes', async () => {
    const userRequest = deferred<Array<{ id: number; email: string; deleted: boolean }>>()
    const keyRequest = deferred<Array<{ id: number; name: string; user_id: number }>>()
    mocks.searchUsers.mockReset()
    mocks.searchApiKeys.mockReset()
    mocks.searchUsers.mockReturnValueOnce(userRequest.promise)
    mocks.searchApiKeys.mockReturnValueOnce(keyRequest.promise)
    const wrapper = mount(ProbeGovernanceEventsDialog, {
      props: { show: true, group: policy() },
      global: { stubs: { BaseDialog: BaseDialogStub, DataTable: true, Pagination: true, ProbeGovernanceEventDetailDialog: true } },
    })
    const selects = wrapper.findAllComponents(Select)

    selects[2].vm.$emit('search', 'old@example.com')
    await wrapper.vm.$nextTick()
    expect(selects[2].props('loading')).toBe(true)
    selects[2].vm.$emit('search', '')
    await wrapper.vm.$nextTick()
    expect(selects[2].props('loading')).toBe(false)
    userRequest.resolve([{ id: 44, email: 'old@example.com', deleted: false }])
    await flushPromises()
    expect((selects[2].props('options') as Array<{ value: number }>)).toEqual([])

    selects[3].vm.$emit('search', 'old-key')
    await wrapper.vm.$nextTick()
    expect(selects[3].props('loading')).toBe(true)
    selects[2].vm.$emit('change', 44, { value: 44, email: 'new@example.com' })
    await wrapper.vm.$nextTick()
    expect(selects[3].props('loading')).toBe(false)
    keyRequest.resolve([{ id: 55, name: 'old-key', user_id: 44 }])
    await flushPromises()
    expect((selects[3].props('options') as Array<{ value: number }>)).toEqual([])
  })

  it('keeps the latest exemption search when an older request resolves last', async () => {
    const older = deferred<ReturnType<typeof page<ProbeGovernanceExemption>>>()
    const latest = deferred<ReturnType<typeof page<ProbeGovernanceExemption>>>()
    mocks.listExemptions.mockReset()
    mocks.listExemptions.mockReturnValueOnce(older.promise).mockReturnValueOnce(latest.promise)
    const wrapper = mount(ProbeGovernanceExemptionsDialog, {
      props: { show: false, group: policy(), prefill: null },
      global: { stubs: { BaseDialog: BaseDialogStub, Pagination: true, ConfirmDialog: true } },
    })
    await wrapper.setProps({ show: true })
    await wrapper.vm.$nextTick()

    wrapper.get('[data-test="probe-governance-exemption-search"]').getComponent(Input).vm.$emit('update:modelValue', 'monitor')
    await wrapper.get('[data-test="probe-governance-exemption-search-submit"]').trigger('click')
    expect(mocks.listExemptions).toHaveBeenCalledTimes(2)

    latest.resolve(page([exemption(2)]))
    await flushPromises()
    expect((wrapper.getComponent(DataTable).props('data') as ProbeGovernanceExemption[])[0].id).toBe(2)
    older.resolve(page([exemption(1)]))
    await flushPromises()
    expect((wrapper.getComponent(DataTable).props('data') as ProbeGovernanceExemption[])[0].id).toBe(2)
  })

  it('immediately clears exemption remote-search loading and ignores the stale result', async () => {
    const keyRequest = deferred<Array<{ id: number; name: string; user_id: number }>>()
    mocks.searchApiKeys.mockReset()
    mocks.searchApiKeys.mockReturnValueOnce(keyRequest.promise)
    const wrapper = mount(ProbeGovernanceExemptionsDialog, {
      props: { show: true, group: policy(), prefill: null },
      global: { stubs: { BaseDialog: BaseDialogStub, DataTable: true, Pagination: true, ConfirmDialog: true } },
    })
    const keySelect = wrapper.get('[data-test="probe-governance-exemption-api-key"]').getComponent(Select)

    keySelect.vm.$emit('search', 'old-key')
    await wrapper.vm.$nextTick()
    expect(keySelect.props('loading')).toBe(true)
    keySelect.vm.$emit('search', '')
    await wrapper.vm.$nextTick()
    expect(keySelect.props('loading')).toBe(false)
    keyRequest.resolve([{ id: 55, name: 'old-key', user_id: 44 }])
    await flushPromises()
    expect(keySelect.props('options')).toEqual([])
  })

  it('requires an exemption expiration to be in the future', async () => {
    const wrapper = mount(ProbeGovernanceExemptionsDialog, {
      props: { show: true, group: policy(), prefill: null },
      global: { stubs: { BaseDialog: BaseDialogStub, DataTable: true, Pagination: true, ConfirmDialog: true } },
    })
    wrapper.get('[data-test="probe-governance-exemption-api-key"]').getComponent(Select).vm.$emit('change', 55, { value: 55, name: 'monitor-key', userID: 44 })
    wrapper.get('[data-test="probe-governance-exemption-reason"]').getComponent(Input).vm.$emit('update:modelValue', 'monitor')
    const expiry = wrapper.get('[data-test="probe-governance-exemption-expires"]').getComponent(Input)

    expiry.vm.$emit('update:modelValue', localDateTime(Date.now() + 60 * 60 * 1000))
    await wrapper.vm.$nextTick()
    expect(wrapper.get('[data-test="probe-governance-exemption-add"]').attributes()).not.toHaveProperty('disabled')

    expiry.vm.$emit('update:modelValue', localDateTime(Date.now() - 60 * 1000))
    await wrapper.vm.$nextTick()
    expect(expiry.props('error')).toContain('expiresAtError')
    expect(wrapper.get('[data-test="probe-governance-exemption-add"]').attributes()).toHaveProperty('disabled')
  })

  it('shows separate audit and governance versions in event details', () => {
    const wrapper = mount(ProbeGovernanceEventDetailDialog, {
      props: { show: true, event: probeDetail(), loading: false, clearingBusy: false },
      global: { stubs: { BaseDialog: BaseDialogStub } },
    })
    expect(wrapper.text()).toContain('admin.promptAudit.probeGovernance.detail.auditConfigVersion')
    expect(wrapper.text()).toContain('v57')
    expect(wrapper.text()).toContain('admin.promptAudit.probeGovernance.detail.probeConfigVersion')
    expect(wrapper.text()).toContain('v106')
    expect(wrapper.text()).not.toContain('v57000001')
  })
})

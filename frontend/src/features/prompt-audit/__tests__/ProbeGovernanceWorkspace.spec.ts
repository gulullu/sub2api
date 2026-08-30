import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent } from 'vue'

import DataTable from '@/components/common/DataTable.vue'
import Input from '@/components/common/Input.vue'
import Select from '@/components/common/Select.vue'
import ProbeGovernanceEventsDialog from '../components/ProbeGovernanceEventsDialog.vue'
import ProbeGovernancePolicyDialog from '../components/ProbeGovernancePolicyDialog.vue'
import ProbeGovernanceWorkspace from '../components/ProbeGovernanceWorkspace.vue'
import type { ProbeGovernancePolicy, PromptAuditDraft } from '../types'
import { configToDraft } from '../viewModel'

const mocks = vi.hoisted(() => ({
  listPolicies: vi.fn(),
  updatePolicy: vi.fn(),
  listEvents: vi.fn(),
  getEvent: vi.fn(),
  clearEvent: vi.fn(),
  showSuccess: vi.fn(),
  showError: vi.fn(),
}))

vi.mock('../api', () => ({ default: {
  listProbeGovernancePolicies: mocks.listPolicies,
  updateProbeGovernancePolicy: mocks.updatePolicy,
  listProbeGovernanceEvents: mocks.listEvents,
  getProbeGovernanceEvent: mocks.getEvent,
  clearProbeGovernanceEvent: mocks.clearEvent,
} }))
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showSuccess: mocks.showSuccess, showError: mocks.showError }) }))
vi.mock('@/api/admin', () => ({ adminAPI: { usage: { searchUsers: vi.fn().mockResolvedValue([]), searchApiKeys: vi.fn().mockResolvedValue([]) } } }))
vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ locale: { value: 'zh-CN' }, t: (key: string, params?: Record<string, unknown>) => key.replace(/\{(\w+)\}/g, (_, token) => String(params?.[token] ?? `{${token}}`)) }) }
})

const desktopMatchMedia = () => {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: true, media: query, onchange: null,
      addEventListener: vi.fn(), removeEventListener: vi.fn(), addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: vi.fn(),
    })),
  })
}

const draft = (): PromptAuditDraft => {
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
    group_ids: [1, 3],
    endpoints: [],
    config_version: 1,
    updated_at: '',
    updated_by: 1,
    change_summary: '',
  })
  value.group_policies = [{
    group_id: 2,
    in_scope: false,
    enabled: true,
    blocking_enabled: true,
    blocking_latest_turn_only: true,
    store_pass_events: false,
    strategy: 'priority',
    scanners: ['confidence_json'],
    max_total_input_chars: 120000,
    active_prompt_template_id: 'builtin-relaybases-cyber-safety',
    flag_threshold: 0.4,
    block_threshold: 0.7,
    block_http_status: 403,
    block_message: 'blocked',
    risk_route_account_ids: [],
    cyber_feedback_account_ids: [],
    excluded_user_ids: [],
    no_route_fallback_mode: 'allow',
  }]
  return value
}

const policy = (groupID: number, groupName: string, enabled: boolean): ProbeGovernancePolicy => ({
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
})

const mountWorkspace = () => mount(ProbeGovernanceWorkspace, {
  props: {
    draft: draft(),
    groups: [
      { id: 1, name: 'claude-max', status: 'active' as const, platform: 'anthropic' },
      { id: 2, name: 'not-audited', status: 'active' as const, platform: 'openai' },
      { id: 3, name: 'claude-max-ultra', status: 'active' as const, platform: 'anthropic' },
    ],
  },
  global: {
    stubs: {
      Pagination: true,
      ProbeGovernancePolicyDialog: true,
      ProbeGovernanceEventsDialog: true,
      ProbeGovernanceExemptionsDialog: true,
    },
  },
})

describe('ProbeGovernanceWorkspace', () => {
  beforeEach(() => {
    desktopMatchMedia()
    localStorage.clear()
    Object.values(mocks).forEach((mock) => mock.mockReset())
    mocks.listPolicies
      .mockResolvedValueOnce({ items: [policy(1, 'claude-max', true), policy(2, 'not-audited', true)], total: 101, page: 1, page_size: 100, pages: 2 })
      .mockResolvedValueOnce({ items: [], total: 101, page: 2, page_size: 100, pages: 2 })
    mocks.updatePolicy.mockImplementation(async (groupID: number, patch: Partial<ProbeGovernancePolicy>) => ({ ...policy(groupID, groupID === 1 ? 'claude-max' : 'claude-max-ultra', false), ...patch }))
    mocks.listEvents.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
  })

  it('loads every server page, filters strictly to persisted audit scope, and synthesizes safe defaults', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()

    expect(mocks.listPolicies).toHaveBeenNthCalledWith(1, { page: 1, page_size: 100 })
    expect(mocks.listPolicies).toHaveBeenNthCalledWith(2, { page: 2, page_size: 100 })
    const table = wrapper.getComponent(DataTable)
    const rows = table.props('data') as ProbeGovernancePolicy[]
    expect(rows.map((row) => row.group_id)).toEqual([1, 3])
    expect(rows.some((row) => row.group_id === 2)).toBe(false)
    expect(rows.find((row) => row.group_id === 3)).toEqual(expect.objectContaining({ enabled: false, interval_seconds: 300 }))
    expect(table.props('stickyFirstColumn')).toBe(true)
    expect(table.props('stickyActionsColumn')).toBe(true)
  })

  it('uses real row fields for every sortable column and keeps identity/actions fixed', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    const table = wrapper.getComponent(DataTable)
    const rows = table.props('data') as Array<Record<string, unknown>>
    const columns = table.props('columns') as Array<{ key: string; sortable?: boolean }>

    for (const column of columns.filter((item) => item.sortable)) {
      expect(Object.prototype.hasOwnProperty.call(rows[0], column.key), column.key).toBe(true)
    }
    expect(columns[0].key).toBe('group_name')
    expect(columns.at(-1)?.key).toBe('actions')
    expect(table.props('defaultSortKey')).toBe('group_name')
  })

  it('sorts the complete result set before slicing the current page', async () => {
    const scopedDraft = draft()
    scopedDraft.group_policies = []
    scopedDraft.group_ids = Array.from({ length: 25 }, (_, index) => index + 1)
    const groups = scopedDraft.group_ids.map((id) => ({
      id,
      name: `group-${String(id).padStart(2, '0')}`,
      status: 'active' as const,
      platform: 'anthropic',
    }))
    mocks.listPolicies.mockReset()
    mocks.listPolicies.mockResolvedValue({
      items: groups.map((group) => policy(group.id, group.name, true)),
      total: groups.length,
      page: 1,
      page_size: 100,
      pages: 1,
    })

    const wrapper = mount(ProbeGovernanceWorkspace, {
      props: { draft: scopedDraft, groups },
      global: {
        stubs: {
          Pagination: true,
          ProbeGovernancePolicyDialog: true,
          ProbeGovernanceEventsDialog: true,
          ProbeGovernanceExemptionsDialog: true,
        },
      },
    })
    await flushPromises()

    const table = wrapper.getComponent(DataTable)
    table.vm.$emit('sort', 'group_name', 'desc')
    await wrapper.vm.$nextTick()
    const rows = table.props('data') as ProbeGovernancePolicy[]
    expect(rows).toHaveLength(20)
    expect(rows[0].group_name).toBe('group-25')
    expect(rows.at(-1)?.group_name).toBe('group-06')
  })

  it('enables a default policy directly from the fixed action column', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    const enable = wrapper.findAll('button').find((button) => button.text().includes('probeGovernance.enableAction'))
    expect(enable).toBeTruthy()
    await enable!.trigger('click')
    await flushPromises()
    expect(mocks.updatePolicy).toHaveBeenCalledWith(3, { enabled: true })
  })

  it('preserves rolling statistics when a policy mutation returns config-only fields', async () => {
    mocks.updatePolicy.mockResolvedValueOnce({
      ...policy(1, 'claude-max', false),
      enabled: false,
      local_responses_24h: 0,
      skipped_audits_24h: 0,
      skipped_upstream_24h: 0,
    })
    const wrapper = mountWorkspace()
    await flushPromises()

    const disable = wrapper.findAll('button').find((button) => button.text().includes('probeGovernance.disableAction'))
    expect(disable).toBeTruthy()
    await disable!.trigger('click')
    await flushPromises()

    const row = (wrapper.getComponent(DataTable).props('data') as ProbeGovernancePolicy[])
      .find((item) => item.group_id === 1)
    expect(row).toEqual(expect.objectContaining({
      enabled: false,
      local_responses_24h: 10,
      skipped_audits_24h: 9,
      skipped_upstream_24h: 8,
    }))
  })

  it('reloads policies when the persisted audit scope changes', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    mocks.listPolicies.mockResolvedValueOnce({ items: [policy(1, 'claude-max', true)], total: 1, page: 1, page_size: 100, pages: 1 })

    const nextDraft = draft()
    nextDraft.group_ids = [1]
    await wrapper.setProps({ draft: nextDraft })
    await flushPromises()

    expect(mocks.listPolicies).toHaveBeenCalledTimes(3)
    expect((wrapper.getComponent(DataTable).props('data') as ProbeGovernancePolicy[]).map((row) => row.group_id)).toEqual([1])
  })

  it('retains real policies when group metadata arrives after the config', async () => {
    mocks.listPolicies.mockReset()
    mocks.listPolicies.mockResolvedValue({ items: [policy(1, 'claude-max', true)], total: 1, page: 1, page_size: 100, pages: 1 })
    const wrapper = mount(ProbeGovernanceWorkspace, {
      props: { draft: draft(), groups: [] },
      global: {
        stubs: {
          Pagination: true,
          ProbeGovernancePolicyDialog: true,
          ProbeGovernanceEventsDialog: true,
          ProbeGovernanceExemptionsDialog: true,
        },
      },
    })
    await flushPromises()
    expect(wrapper.getComponent(DataTable).props('data')).toEqual([])

    await wrapper.setProps({ groups: [{ id: 1, name: 'claude-max', status: 'active' as const, platform: 'anthropic' }] })
    await flushPromises()
    expect(wrapper.getComponent(DataTable).props('data')).toEqual([
      expect.objectContaining({ group_id: 1, enabled: true, local_responses_24h: 10 }),
    ])
  })
})

describe('Probe governance dialogs', () => {
  beforeEach(() => desktopMatchMedia())

  it('uses the shared Input for the bounded interval and rejects values below 60 seconds', async () => {
    const wrapper = mount(ProbeGovernancePolicyDialog, {
      props: { show: true, policy: policy(1, 'claude-max', true), saving: false },
      global: { stubs: { BaseDialog: defineComponent({ props: ['show'], template: '<div v-if="show"><slot/><slot name="footer"/></div>' }) } },
    })
    const interval = wrapper.get('[data-test="probe-governance-policy-interval"]').getComponent(Input)
    expect(interval.props('min')).toBe(60)
    expect(interval.props('max')).toBe(86400)
    interval.vm.$emit('update:modelValue', '59')
    await wrapper.vm.$nextTick()
    expect(wrapper.get('[data-test="probe-governance-policy-save"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.find('select').exists()).toBe(false)
  })

  it('closes both probe dialogs before forwarding a linked audit event', async () => {
    const detailStub = defineComponent({
      emits: ['view-audit-event'],
      template: '<button data-test="linked-audit" @click="$emit(\'view-audit-event\', 77)">open</button>',
    })
    const wrapper = mount(ProbeGovernanceEventsDialog, {
      props: { show: true, group: policy(1, 'claude-max', true) },
      global: {
        stubs: {
          BaseDialog: defineComponent({ props: ['show'], template: '<div v-if="show"><slot/><slot name="footer"/></div>' }),
          DataTable: true,
          Pagination: true,
          ProbeGovernanceEventDetailDialog: detailStub,
        },
      },
    })
    await wrapper.get('[data-test="linked-audit"]').trigger('click')
    expect(wrapper.emitted('close')).toHaveLength(1)
    expect(wrapper.emitted('view-audit-event')).toEqual([[77]])
  })

  it('closes both probe dialogs before opening an exemption from an event', async () => {
    const event = { id: 88, group_id: 1 }
    const detailStub = defineComponent({
      emits: ['add-exemption'],
      template: '<button data-test="event-exemption" @click="$emit(\'add-exemption\', { id: 88, group_id: 1 })">open</button>',
    })
    const wrapper = mount(ProbeGovernanceEventsDialog, {
      props: { show: true, group: policy(1, 'claude-max', true) },
      global: {
        stubs: {
          BaseDialog: defineComponent({ props: ['show'], template: '<div v-if="show"><slot/><slot name="footer"/></div>' }),
          DataTable: true,
          Pagination: true,
          ProbeGovernanceEventDetailDialog: detailStub,
        },
      },
    })
    await wrapper.get('[data-test="event-exemption"]').trigger('click')
    expect(wrapper.emitted('close')).toHaveLength(1)
    expect(wrapper.emitted('add-exemption')).toEqual([[event]])
  })

  it('submits selected user and API Key IDs without stale snapshot names', async () => {
    mocks.listEvents.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
    const wrapper = mount(ProbeGovernanceEventsDialog, {
      props: { show: true, group: policy(1, 'claude-max', true) },
      global: {
        stubs: {
          BaseDialog: defineComponent({ props: ['show'], template: '<div v-if="show"><slot/><slot name="footer"/></div>' }),
          DataTable: true,
          Pagination: true,
          ProbeGovernanceEventDetailDialog: true,
        },
      },
    })
    const selects = wrapper.findAllComponents(Select)
    expect((selects[4].props('options') as Array<{ value: string }>).map((option) => option.value)).toEqual([
      '',
      'openai_responses',
      'openai_chat_completions',
      'anthropic_messages',
    ])
    selects[2].vm.$emit('change', 44, { value: 44, label: 'old@example.com · #44', email: 'old@example.com' })
    selects[3].vm.$emit('change', 55, { value: 55, label: 'old-key · #55', name: 'old-key', userID: 44 })
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(mocks.listEvents).toHaveBeenCalledWith(1, expect.objectContaining({
      user_id: 44,
      user_email: '',
      api_key_id: 55,
      api_key_name: '',
    }), 1, 20)
  })
})

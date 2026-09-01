import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent } from 'vue'

import DataTable from '@/components/common/DataTable.vue'
import Select from '@/components/common/Select.vue'
import promptAuditAPI from '../api'
import GroupPolicyWorkspace from '../components/GroupPolicyWorkspace.vue'
import type { PromptAuditDraft, PromptAuditGroupPolicy } from '../types'
import { configToDraft, createGroupPolicyFromConfig } from '../viewModel'

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      locale: { value: 'en' },
      t: (key: string, params?: Record<string, unknown>) => key.replace(/\{(\w+)\}/g, (_, token) => String(params?.[token] ?? `{${token}}`)),
    }),
  }
})

const DialogStub = defineComponent({
  props: ['show', 'title'],
  emits: ['close'],
  template: '<div v-if="show"><slot /><slot name="footer" /></div>',
})

const desktopMatchMedia = () => {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: true,
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  })
}

const makeDraft = (includeMissingPolicy = true): PromptAuditDraft => {
  const draft = configToDraft({
    enabled: false,
    blocking_enabled: false,
    blocking_latest_turn_only: false,
    store_pass_events: false,
    effective_mode: 'off',
    strategy: 'priority',
    worker_count: 4,
    queue_capacity: 100,
    scanners: [],
    all_groups: false,
    group_ids: [2, 3],
    endpoints: [],
    config_version: 1,
    updated_at: '',
    updated_by: 0,
    change_summary: '',
  })
  const unassignedPolicy: PromptAuditGroupPolicy = createGroupPolicyFromConfig(draft, null)
  const missingPolicy: PromptAuditGroupPolicy = {
    ...createGroupPolicyFromConfig(draft, 99),
    group_id: 99,
  }
  draft.group_policies = includeMissingPolicy ? [unassignedPolicy, missingPolicy] : [unassignedPolicy]
  return draft
}

const mountWorkspace = (includeMissingPolicy = true, draft = makeDraft(includeMissingPolicy)) => mount(GroupPolicyWorkspace, {
  props: {
    draft,
    groups: [
      { id: 1, name: 'Zeta', status: 'active' as const, platform: 'openai' },
      { id: 2, name: 'Beta', status: 'inactive' as const, platform: 'anthropic' },
      { id: 3, name: 'Alpha', status: 'active' as const, platform: 'openai' },
    ],
    accounts: [],
    accountsLoaded: true,
    accountsLoading: false,
    accountsError: '',
  },
  global: { stubs: { BaseDialog: DialogStub } },
})

const renderedNames = (wrapper: ReturnType<typeof mountWorkspace>) => wrapper
  .findAll('tbody tr[data-index]')
  .map((row) => row.find('td').text().split('#')[0].trim())
const scopeButtonFor = (wrapper: ReturnType<typeof mountWorkspace>, name: string) => wrapper
  .findAll('tbody tr[data-index]')
  .find((row) => row.text().includes(name))
  ?.find('button[aria-label]')

describe('GroupPolicyWorkspace', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    desktopMatchMedia()
    localStorage.clear()
  })

  it('lists only real groups and filters them with the shared searchable Select', async () => {
    const wrapper = mountWorkspace()
    const selects = wrapper.findAllComponents(Select)
    const groupSelect = selects[0]

    expect(groupSelect.props('searchable')).toBe(true)
    expect(groupSelect.props('clearable')).toBe(true)
    const options = groupSelect.props('options') as Array<{ value: number | null; label: string }>
    expect(options.map((option) => option.value)).toEqual(expect.arrayContaining([1, 2, 3, 99]))
    expect(options.some((option) => option.value === null)).toBe(false)
    expect(options.find((option) => option.value === 99)?.label).toContain('admin.promptAudit.groups.unknownGroup')
    expect(wrapper.findComponent(DataTable).props('data')).toHaveLength(4)
    expect(wrapper.findComponent(DataTable).props('data').some((row: { group_id: number | null }) => row.group_id === null)).toBe(false)
    expect(wrapper.find('[data-test^="prompt-audit-copy-policy-"]').exists()).toBe(false)
    expect(wrapper.find('[data-test^="prompt-audit-edit-group-"]').exists()).toBe(true)

    groupSelect.vm.$emit('update:modelValue', 2)
    await wrapper.vm.$nextTick()

    expect(wrapper.findComponent(DataTable).props('data').map((row: { name: string }) => row.name)).toEqual(['Beta'])

    selects[1].vm.$emit('update:modelValue', 'openai')
    selects[2].vm.$emit('update:modelValue', 'active')
    await wrapper.vm.$nextTick()
    expect(wrapper.findComponent(DataTable).props('data')).toHaveLength(0)

    await wrapper.get('[data-test="prompt-audit-group-filter-reset"]').trigger('click')
    expect(wrapper.findComponent(DataTable).props('data')).toHaveLength(4)
  })

  it('sorts by audit scope by default and toggles the scope header', async () => {
    const wrapper = mountWorkspace(false)
    await wrapper.vm.$nextTick()

    const table = wrapper.findComponent(DataTable)
    expect(table.props('defaultSortKey')).toBe('scope')
    expect(table.props('defaultSortOrder')).toBe('desc')
    expect(table.props('sortStorageKey')).toBe('prompt-audit-groups-sort-v2')
    expect(renderedNames(wrapper)).toEqual(['Alpha', 'Beta', 'Zeta'])

    const scopeHeader = wrapper.findAll('th').find((header) => header.text().includes('admin.promptAudit.groups.scope'))
    expect(scopeHeader).toBeTruthy()
    expect(scopeHeader!.attributes('aria-sort')).toBe('descending')

    await scopeHeader!.trigger('click')
    await wrapper.vm.$nextTick()

    expect(scopeHeader!.attributes('aria-sort')).toBe('ascending')
    expect(renderedNames(wrapper)).toEqual(['Zeta', 'Alpha', 'Beta'])
  })

  it('persists scope separately from a group policy and keeps its settings', async () => {
    const draft = makeDraft(false)
    draft.group_policies = [{
      ...createGroupPolicyFromConfig(draft, 2),
      in_scope: true,
      flag_threshold: 0.33,
    }]
    const wrapper = mountWorkspace(false, draft)
    const betaScope = scopeButtonFor(wrapper, 'Beta')
    expect(betaScope).toBeTruthy()

    await betaScope!.trigger('click')
    const updated = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(updated.group_policies).toEqual([
      expect.objectContaining({ group_id: 2, in_scope: false, flag_threshold: 0.33 }),
    ])
    expect(updated.group_ids).toEqual([2, 3])
  })

  it('creates an explicit exclusion when all groups are otherwise selected', async () => {
    const draft = makeDraft(false)
    draft.all_groups = true
    draft.group_ids = []
    draft.group_policies = []
    const wrapper = mountWorkspace(false, draft)
    const zetaScope = scopeButtonFor(wrapper, 'Zeta')
    expect(zetaScope).toBeTruthy()

    await zetaScope!.trigger('click')
    const updated = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(updated.all_groups).toBe(true)
    expect(updated.group_policies).toEqual([
      expect.objectContaining({ group_id: 1, in_scope: false }),
    ])
  })

  it('uses shared controls throughout the group policy editor and persists their changes', async () => {
    const draft = makeDraft(false)
    draft.prompt_templates = [
      { id: 'builtin', name: 'Built-in', system_prompt: 'Built in', builtin: true },
      { id: 'custom', name: 'Custom', system_prompt: 'Custom', builtin: false },
    ]
    draft.active_prompt_template_id = 'builtin'
    draft.group_policies = [{
      ...createGroupPolicyFromConfig(draft, 2),
      enabled: true,
      blocking_enabled: true,
      blocking_latest_turn_only: true,
      active_prompt_template_id: 'builtin',
    }]
    const wrapper = mountWorkspace(false, draft)

    await wrapper.get('[data-test="prompt-audit-edit-group-2"]').trigger('click')

    expect(wrapper.find('select').exists()).toBe(false)
    const fallback = wrapper.get('[data-test="prompt-audit-group-no-route-fallback"]').getComponent(Select)
    const template = wrapper.get('[data-test="prompt-audit-group-template"]').getComponent(Select)
    expect(fallback.props('searchable')).toBe(false)
    expect(template.props('options')).toEqual(expect.arrayContaining([
      expect.objectContaining({ value: 'builtin' }),
      expect.objectContaining({ value: 'custom' }),
    ]))

    fallback.vm.$emit('update:modelValue', 'block')
    template.vm.$emit('update:modelValue', 'custom')
    await wrapper.vm.$nextTick()

    const updated = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(updated.group_policies).toEqual(expect.arrayContaining([
      expect.objectContaining({ group_id: 2, no_route_fallback_mode: 'block', active_prompt_template_id: 'custom' }),
    ]))

    await wrapper.get('[data-test="prompt-audit-group-enabled"]').trigger('click')
    const disabled = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(disabled.group_policies).toEqual(expect.arrayContaining([
      expect.objectContaining({ group_id: 2, enabled: false, blocking_enabled: false, blocking_latest_turn_only: false }),
    ]))
  })

  it('shows users without a profile and keeps profile toolbar buttons consistent with column settings', async () => {
    const draft = makeDraft(false)
    draft.group_policies = [{
      ...createGroupPolicyFromConfig(draft, 2),
      excluded_user_ids: [71],
    }]
    const profile = {
      user_id: 71,
      username: 'excluded-without-profile',
      email: 'excluded@example.test',
      status: 'active',
      deleted: false,
      excluded: true,
      has_profile: false,
      audit_jobs: 0,
      high_risk_jobs: 0,
      critical_risk_jobs: 0,
      high_or_critical_jobs: 0,
      system_exception_jobs: 0,
      unclassified_jobs: 0,
      usage_total: 0,
      cyber_blocked_total: 0,
      cyber_recorded_total: 0,
      sample_total: 0,
      audit_coverage: 0,
      cyber_ratio: 0,
      high_risk_ratio: 0,
      critical_risk_ratio: 0,
      high_or_critical_ratio: 0,
      score: 0,
    }
    const emptyPage = {
      items: [],
      total: 0,
      page: 1,
      page_size: 20,
      pages: 0,
    }
    vi.spyOn(promptAuditAPI, 'listUserProfiles').mockImplementation(async (filter) => filter.search ? {
      items: [profile],
      total: 1,
      page: 1,
      page_size: 20,
      pages: 1,
    } : emptyPage)
    const wrapper = mountWorkspace(false, draft)

    await wrapper.get('[data-test="prompt-audit-edit-group-2"]').trigger('click')
    await wrapper.get('[data-test="prompt-audit-group-tab-profiles"]').trigger('click')
    await flushPromises()

    expect(promptAuditAPI.listUserProfiles).toHaveBeenCalledWith(expect.objectContaining({
      group_id: 2,
      min_samples: 0,
    }), 1, 20)

    const controls = [
      wrapper.get('[data-test="prompt-audit-profile-column-settings"]'),
      wrapper.get('[data-test="prompt-audit-profile-refresh"]'),
      wrapper.get('[data-test="prompt-audit-profile-select-page"]'),
      wrapper.get('[data-test="prompt-audit-profile-clear-page"]'),
    ]
    controls.forEach((control) => {
      expect(control.classes()).toEqual(expect.arrayContaining(['btn', 'btn-secondary', 'px-2', 'md:px-3']))
      expect(control.classes()).not.toContain('btn-sm')
      expect(control.classes()).not.toContain('btn-ghost')
    })

    await wrapper.get('[data-test="prompt-audit-group-profile-search"]').setValue('excluded@example.test')
    await wrapper.get('[data-test="prompt-audit-group-profile-search"]').trigger('keyup.enter')
    await flushPromises()
    expect(promptAuditAPI.listUserProfiles).toHaveBeenLastCalledWith(expect.objectContaining({
      group_id: 2,
      search: 'excluded@example.test',
    }), 1, 20)
    expect(wrapper.get('[data-test="prompt-audit-group-profile-table"]').text()).toContain('excluded-without-profile')
    expect(wrapper.get('[data-test="prompt-audit-group-profile-table"]').text()).toContain('admin.promptAudit.groups.noProfile')
    expect(wrapper.get('[data-test="prompt-audit-group-profile-table"]').text()).toContain('admin.promptAudit.groups.excluded')

    await wrapper.get('[data-test="prompt-audit-profile-clear-page"]').trigger('click')
    expect((wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft).group_policies).toEqual(expect.arrayContaining([
      expect.objectContaining({ group_id: 2, excluded_user_ids: [] }),
    ]))
    expect(wrapper.get('[data-test="prompt-audit-group-profile-table"]').text()).toContain('admin.promptAudit.groups.included')
    expect(wrapper.get('[data-test="prompt-audit-group-profile-table"]').text()).not.toContain('admin.promptAudit.groups.excluded')
  })
})

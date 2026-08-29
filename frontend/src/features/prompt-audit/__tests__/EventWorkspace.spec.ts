import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, nextTick } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { adminAPI } from '@/api/admin'
import Select from '@/components/common/Select.vue'
import EventWorkspace from '../components/EventWorkspace.vue'
import { emptyEventFilters } from '../viewModel'

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      locale: { value: 'en' },
      t: (key: string) => key,
    }),
  }
})

const PaginationStub = defineComponent({
  props: ['total', 'page', 'pageSize'],
  template: '<div data-test="pagination" />',
})

function mountWorkspace(filters = emptyEventFilters()) {
  return mount(EventWorkspace, {
    props: {
      events: [],
      total: 0,
      page: 1,
      pageSize: 20,
      filters,
      selectedIds: [],
      loading: false,
      error: '',
      groups: [{ id: 7, name: 'Enterprise', platform: 'openai', status: 'active' }],
      endpoints: [{
        id: 'guard-1',
        name: 'Guard One',
        protocol: 'openai_compatible' as const,
        base_url: 'https://guard.example.test',
        adapter: 'qwen3guard' as const,
        model: 'guard-model',
        priority: 1,
        timeout_ms: 3000,
        input_limit: 4000,
        enabled: true,
        has_token: true,
        token_status: 'configured' as const,
        token: '',
        clear_token: false,
      }],
    },
    global: { stubs: { Pagination: PaginationStub } },
  })
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('EventWorkspace filters', () => {
  it('uses consistent Select controls and searches users and API Keys by display name', async () => {
    const searchUsers = vi.spyOn(adminAPI.usage, 'searchUsers').mockResolvedValue([
      { id: 42, email: 'alice@example.test', deleted: false },
      { id: 99, email: 'deleted@example.test', deleted: true },
    ])
    const searchAPIKeys = vi.spyOn(adminAPI.usage, 'searchApiKeys').mockResolvedValue([
      { id: 8, name: 'Production key', user_id: 42 },
    ])
    const wrapper = mountWorkspace()

    expect(wrapper.find('select').exists()).toBe(false)
    expect(wrapper.findAllComponents(Select)).toHaveLength(6)

    const userSelect = wrapper.get('[data-test="event-user-filter"]').getComponent(Select)
    userSelect.vm.$emit('search', 'alice')
    await flushPromises()

    expect(searchUsers).toHaveBeenCalledWith('alice')
    expect(userSelect.props('options')).toEqual(expect.arrayContaining([
      expect.objectContaining({ value: 42, label: 'alice@example.test · #42' }),
      expect.objectContaining({ value: 99, label: 'deleted@example.test · #99', deleted: true }),
    ]))

    userSelect.vm.$emit('change', 42, { value: 42, label: 'alice@example.test · #42' })
    await flushPromises()

    expect(searchAPIKeys).toHaveBeenCalledWith(42, '')
    const afterUser = wrapper.emitted('filters-change')?.at(-1)?.[0]
    expect(afterUser).toMatchObject({ user_id: '42', api_key_id: '' })

    const apiKeySelect = wrapper.get('[data-test="event-api-key-filter"]').getComponent(Select)
    expect(apiKeySelect.props('options')).toEqual(expect.arrayContaining([
      expect.objectContaining({ value: 8, label: 'Production key · #8' }),
    ]))

    apiKeySelect.vm.$emit('search', 'Production')
    await flushPromises()
    expect(searchAPIKeys).toHaveBeenLastCalledWith(42, 'Production')

    apiKeySelect.vm.$emit('change', 8, { value: 8, label: 'Production key · #8' })
    await nextTick()
    expect(wrapper.emitted('filters-change')?.at(-1)?.[0]).toMatchObject({
      user_id: '42',
      api_key_id: '8',
    })

    const columnSettings = wrapper.get('[data-test="event-column-settings"]')
    expect(columnSettings.classes()).toContain('btn-secondary')
    expect(columnSettings.classes()).not.toContain('btn-sm')
    wrapper.unmount()
  })

  it('keeps legacy IDs visible as fallbacks and clears every filter on reset', async () => {
    const wrapper = mountWorkspace({
      ...emptyEventFilters(),
      decision: 'flag',
      user_id: '123',
      api_key_id: '456',
    })

    const userSelect = wrapper.get('[data-test="event-user-filter"]').getComponent(Select)
    const apiKeySelect = wrapper.get('[data-test="event-api-key-filter"]').getComponent(Select)
    expect(userSelect.props('options')).toContainEqual({ value: 123, label: '#123' })
    expect(apiKeySelect.props('options')).toContainEqual({ value: 456, label: '#456' })

    const form = wrapper.get('form')
    expect(form.classes()).toEqual(expect.arrayContaining(['border-b', 'p-4', 'sm:p-6']))
    expect(form.classes()).not.toContain('m-5')
    expect(form.classes()).not.toContain('rounded-xl')
    expect(form.classes()).not.toContain('bg-gray-50')

    await wrapper.get('[data-test="event-reset-filters"]').trigger('click')
    expect(wrapper.emitted('filters-change')?.at(-1)?.[0]).toEqual(emptyEventFilters())
    expect(wrapper.emitted('search')?.at(-1)?.[0]).toEqual(emptyEventFilters())
    expect(userSelect.props('modelValue')).toBeNull()
    expect(apiKeySelect.props('modelValue')).toBeNull()
    wrapper.unmount()
  })

  it('does not let a stale user search overwrite a newer result', async () => {
    let resolveSlow: ((value: Array<{ id: number; email: string; deleted: boolean }>) => void) | undefined
    const slowResult = new Promise<Array<{ id: number; email: string; deleted: boolean }>>((resolve) => {
      resolveSlow = resolve
    })
    vi.spyOn(adminAPI.usage, 'searchUsers').mockImplementation((query) => {
      if (query === 'slow') return slowResult
      return Promise.resolve([{ id: 2, email: 'newest@example.test', deleted: false }])
    })
    const wrapper = mountWorkspace()
    const userSelect = wrapper.get('[data-test="event-user-filter"]').getComponent(Select)

    userSelect.vm.$emit('search', 'slow')
    userSelect.vm.$emit('search', 'newest')
    await flushPromises()
    expect(userSelect.props('options')).toContainEqual(expect.objectContaining({
      value: 2,
      label: 'newest@example.test · #2',
    }))

    resolveSlow?.([{ id: 1, email: 'stale@example.test', deleted: false }])
    await flushPromises()
    expect(userSelect.props('options')).not.toContainEqual(expect.objectContaining({ value: 1 }))
    wrapper.unmount()
  })
})

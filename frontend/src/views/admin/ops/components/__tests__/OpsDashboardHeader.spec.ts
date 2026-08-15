import { shallowMount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import OpsDashboardHeader from '../OpsDashboardHeader.vue'

vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vue-i18n')>()
  return {
    ...actual,
    useI18n: () => ({ t: (key: string) => key }),
  }
})

vi.mock('@/api', () => ({
  adminAPI: {
    groups: {
      getAll: vi.fn().mockResolvedValue([]),
    },
  },
}))

vi.mock('@/stores', () => ({
  useAdminSettingsStore: () => ({
    opsRealtimeMonitoringEnabled: false,
    setOpsRealtimeMonitoringEnabledLocal: vi.fn(),
  }),
}))

describe('OpsDashboardHeader SLA details', () => {
  it('requests only SLA-scoped errors from the SLA card', async () => {
    const wrapper = shallowMount(OpsDashboardHeader, {
      props: {
        overview: {},
        platform: '',
        groupId: null,
        timeRange: '1h',
        queryMode: 'auto',
        loading: false,
        lastUpdated: null,
      },
    })

    const slaDetailsButton = wrapper.findAll('button').find((button) =>
      button.element.closest('.rounded-2xl')?.textContent?.includes('admin.ops.sla'),
    )
    expect(slaDetailsButton).toBeDefined()

    await slaDetailsButton!.trigger('click')

    expect(wrapper.emitted('openRequestDetails')).toEqual([[{
      title: 'admin.ops.requestDetails.title',
      kind: 'error',
      sla_only: true,
    }]])
  })
})

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import CyberLearningWorkspace from '../components/CyberLearningWorkspace.vue'
import type { CyberFeedbackEvent, CyberFeedbackPage } from '../types'

const mocks = vi.hoisted(() => ({
  listCyberEvents: vi.fn(),
  getCyberEvent: vi.fn(),
  adoptCyberEvent: vi.fn(),
  rejectCyberEvent: vi.fn(),
  regenerateCyberCandidate: vi.fn(),
  revokeCyberRule: vi.fn(),
  showSuccess: vi.fn(),
  showError: vi.fn(),
}))

vi.mock('../api', () => ({ default: mocks }))
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showSuccess: mocks.showSuccess, showError: mocks.showError }) }))
vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ locale: { value: 'en' }, t: (key: string, params?: Record<string, unknown>) => key.replace(/\{(\w+)\}/g, (_, token) => String(params?.[token] ?? `{${token}}`)) }) }
})

const BaseDialogStub = {
  props: ['show', 'title', 'width'],
  emits: ['close'],
  template: '<div v-if="show" role="dialog"><slot /></div>',
}

function event(overrides: Partial<CyberFeedbackEvent> = {}): CyberFeedbackEvent {
  return {
    id: 17,
    request_id: 'req_safe_17',
    account_id: 9,
    group_id: 12,
    model: 'gpt-safe',
    endpoint: '/v1/responses',
    protocol: 'responses',
    stage: 'post_upstream',
    transport: 'stream',
    upstream_status: 400,
    redacted_preview: '[REDACTED] safe excerpt',
    candidate_rule_text: 'Detect repeated requests for prohibited credential automation.',
    generation_status: 'generated',
    generation_error_code: '',
    status: 'pending',
    confirm_count: 2,
    similar_count: 3,
    first_confirmed_at: '2026-08-17T00:00:00Z',
    last_confirmed_at: '2026-08-17T00:01:00Z',
    reviewed_at: null,
    reviewed_by: null,
    rule_id: null,
    config_version: 30,
    admin_alert_status: 'sent',
    ...overrides,
  }
}

function page(item: CyberFeedbackEvent = event()): CyberFeedbackPage {
  return {
    items: [item], total: 1, page: 1, page_size: 20, config_version: 30,
    active_rules: [{ id: 'rule-alpha', rule_text: 'Existing abstract safety rule.', source_feedback_id: 3, status: 'active', created_at: '2026-08-16T00:00:00Z', created_by: 1, config_version: 29 }],
  }
}

function mountWorkspace() {
  return mount(CyberLearningWorkspace, { global: { stubs: { BaseDialog: BaseDialogStub } } })
}

describe('CyberLearningWorkspace', () => {
  beforeEach(() => {
    Object.values(mocks).forEach((mock) => mock.mockReset())
    mocks.listCyberEvents.mockResolvedValue(page())
    mocks.getCyberEvent.mockResolvedValue({ event: event() })
    mocks.adoptCyberEvent.mockResolvedValue({ config_version: 31 })
    mocks.rejectCyberEvent.mockResolvedValue({})
    mocks.regenerateCyberCandidate.mockResolvedValue({ event: event({ generation_status: 'pending', candidate_rule_text: '' }) })
    mocks.revokeCyberRule.mockResolvedValue({ config_version: 31 })
  })

  it('renders only the safe CYB contract even if an API object contains extra sensitive fields', async () => {
    const unsafe = {
      ...event(),
      full_prompt: 'RAW_PROMPT_CANARY_DO_NOT_RENDER',
      prompt_hash: 'HASH_CANARY_DO_NOT_RENDER',
      account_name: 'ACCOUNT_NAME_CANARY_DO_NOT_RENDER',
      api_key_name: 'KEY_NAME_CANARY_DO_NOT_RENDER',
    }
    mocks.listCyberEvents.mockResolvedValue(page(unsafe))
    const wrapper = mountWorkspace()
    await flushPromises()

    expect(mocks.listCyberEvents).toHaveBeenCalledWith('pending', 1, 20)
    expect(wrapper.text()).toContain('[REDACTED] safe excerpt')
    expect(wrapper.html()).not.toContain('RAW_PROMPT_CANARY_DO_NOT_RENDER')
    expect(wrapper.html()).not.toContain('HASH_CANARY_DO_NOT_RENDER')
    expect(wrapper.html()).not.toContain('ACCOUNT_NAME_CANARY_DO_NOT_RENDER')
    expect(wrapper.html()).not.toContain('KEY_NAME_CANARY_DO_NOT_RENDER')

    await wrapper.get('[data-test="cyber-view-17"]').trigger('click')
    expect(wrapper.get('[data-test="cyber-redacted-preview"]').text()).toContain('[REDACTED] safe excerpt')
    expect(wrapper.html()).not.toContain('RAW_PROMPT_CANARY_DO_NOT_RENDER')
  })

  it('opens and highlights a safe deep-linked event detail', async () => {
    const wrapper = mount(CyberLearningWorkspace, {
      props: { initialEventId: 17 },
      global: { stubs: { BaseDialog: BaseDialogStub } },
    })
    await flushPromises()
    expect(mocks.getCyberEvent).toHaveBeenCalledWith(17)
    expect(wrapper.get('[data-test="cyber-event-row"]').attributes('data-highlighted')).toBe('true')
    expect(wrapper.find('[role="dialog"]').exists()).toBe(true)
    expect(wrapper.get('[data-test="cyber-redacted-preview"]').text()).toContain('[REDACTED] safe excerpt')
  })

  it('prefills the system candidate, allows an edit, and adopts with the current config version', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.get('[data-test="cyber-view-17"]').trigger('click')

    const editor = wrapper.get('#cyber-rule-text')
    expect((editor.element as HTMLTextAreaElement).value).toContain('prohibited credential automation')
    await editor.setValue('Abstract edited rule.')
    await wrapper.get('[data-test="cyber-adopt"]').trigger('click')
    await flushPromises()

    expect(mocks.adoptCyberEvent).toHaveBeenCalledWith(17, 'Abstract edited rule.', 30)
    expect(mocks.showSuccess).toHaveBeenCalled()
  })

  it('shows only a safe generation error code and can request regeneration', async () => {
    mocks.listCyberEvents.mockResolvedValue(page(event({ generation_status: 'failed', generation_error_code: 'candidate_timeout', candidate_rule_text: '' })))
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.get('[data-test="cyber-view-17"]').trigger('click')

    expect(wrapper.get('[data-test="cyber-generation-failed"]').text()).toContain('candidate_timeout')
    expect(wrapper.find('#cyber-rule-text').exists()).toBe(false)
    await wrapper.get('[data-test="cyber-regenerate"]').trigger('click')
    await flushPromises()
    expect(mocks.regenerateCyberCandidate).toHaveBeenCalledWith(17)
  })

  it('rejects feedback without requiring a manual summary', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.get('[data-test="cyber-view-17"]').trigger('click')
    await wrapper.get('[data-test="cyber-reject"]').trigger('click')
    await flushPromises()
    expect(mocks.rejectCyberEvent).toHaveBeenCalledWith(17, '')
  })

  it('loads each review state independently and revokes string rule IDs with the current version', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.get('[data-test="cyber-status-rejected"]').trigger('click')
    await flushPromises()
    expect(mocks.listCyberEvents).toHaveBeenLastCalledWith('rejected', 1, 20)

    await wrapper.get('[data-test="cyber-revoke-rule-alpha"]').trigger('click')
    await flushPromises()
    expect(mocks.revokeCyberRule).toHaveBeenCalledWith('rule-alpha', 30)
  })
})

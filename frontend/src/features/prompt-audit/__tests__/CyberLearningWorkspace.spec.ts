import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import DataTable from '@/components/common/DataTable.vue'
import CyberLearningWorkspace from '../components/CyberLearningWorkspace.vue'
import type { CyberFeedbackEvent, CyberFeedbackEvidence, CyberFeedbackPage } from '../types'

const mocks = vi.hoisted(() => ({
  listCyberEvents: vi.fn(),
  getCyberEvent: vi.fn(),
  getCyberEvidence: vi.fn(),
  adoptCyberEvent: vi.fn(),
  rejectCyberEvent: vi.fn(),
  regenerateCyberCandidate: vi.fn(),
  revokeCyberRule: vi.fn(),
  restoreCyberRule: vi.fn(),
  deleteCyberRule: vi.fn(),
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
  template: '<div v-if="show" role="dialog"><slot /><footer><slot name="footer" /></footer></div>',
}
const ConfirmDialogStub = {
  props: ['show', 'title', 'message', 'confirmText', 'danger'],
  emits: ['confirm', 'cancel'],
  template: '<div v-if="show" data-test="rule-confirm"><span>{{ message }}</span><button data-test="rule-confirm-action" @click="$emit(\'confirm\')">confirm</button></div>',
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
    active_rules: [{ id: 'cyb-feedback-3', rule_text: 'Existing abstract safety rule.', source_feedback_id: 3, status: 'active', created_at: '2026-08-16T00:00:00Z', created_by: 1, config_version: 29 }],
  }
}

function evidence(overrides: Partial<CyberFeedbackEvidence> = {}): CyberFeedbackEvidence {
  return {
    available: true,
    full_prompt: 'RAW_PROMPT_CANARY_RENDER_IN_DETAIL',
    prompt_length: 53266,
    message_count: 19,
    truncated: false,
    user_id: 42,
    username: 'caller',
    user_email: 'caller@example.test',
    api_key_id: 73,
    api_key_name: 'production key',
    api_key_prefix: 'sk-safe',
    group_id: 12,
    group_name: 'codex-pro',
    selected_account_id: 9,
    selected_account_name: 'scheduled account',
    credential_account_id: 8,
    credential_account_name: 'oauth credential',
    credential_account_email: 'oauth@example.test',
    credential_account_email_source: 'snapshot',
    identity_source: 'snapshot',
    client_ip: '192.0.2.10',
    user_agent: 'test-client/1.0',
    client_request_id: 'client-request-17',
    ...overrides,
  }
}

function mountWorkspace() {
  return mount(CyberLearningWorkspace, { global: { stubs: { BaseDialog: BaseDialogStub, ConfirmDialog: ConfirmDialogStub } } })
}

describe('CyberLearningWorkspace', () => {
  beforeEach(() => {
    Object.values(mocks).forEach((mock) => mock.mockReset())
    mocks.listCyberEvents.mockResolvedValue(page())
    mocks.getCyberEvent.mockResolvedValue({ event: event() })
    mocks.getCyberEvidence.mockResolvedValue(evidence())
    mocks.adoptCyberEvent.mockResolvedValue({ config_version: 31 })
    mocks.rejectCyberEvent.mockResolvedValue({})
    mocks.regenerateCyberCandidate.mockResolvedValue({ event: event({ generation_status: 'pending', candidate_rule_text: '' }) })
    mocks.revokeCyberRule.mockResolvedValue({ config_version: 31 })
    mocks.restoreCyberRule.mockResolvedValue({ config_version: 32 })
    mocks.deleteCyberRule.mockResolvedValue({ config_version: 32 })
  })

  it('keeps raw content out of the list and fetches administrator evidence for review', async () => {
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
    expect(wrapper.find('[data-test="cyber-rule-status-deleted"]').exists()).toBe(false)

    expect(mocks.listCyberEvents).toHaveBeenCalledWith('pending', 1, 20)
    expect(wrapper.findComponent(DataTable).exists()).toBe(true)
    expect(wrapper.text()).toContain('[REDACTED] safe excerpt')
    expect(wrapper.html()).not.toContain('RAW_PROMPT_CANARY_DO_NOT_RENDER')
    expect(wrapper.html()).not.toContain('HASH_CANARY_DO_NOT_RENDER')
    expect(wrapper.html()).not.toContain('ACCOUNT_NAME_CANARY_DO_NOT_RENDER')
    expect(wrapper.html()).not.toContain('KEY_NAME_CANARY_DO_NOT_RENDER')

    await wrapper.get('[data-test="cyber-view-17"]').trigger('click')
    await flushPromises()
    expect(mocks.getCyberEvent).toHaveBeenCalledWith(17)
    expect(mocks.getCyberEvidence).toHaveBeenCalledWith(17)
    expect(wrapper.get('[data-test="cyber-full-prompt"]').text()).toContain('RAW_PROMPT_CANARY_RENDER_IN_DETAIL')
    expect(wrapper.html()).not.toContain('RAW_PROMPT_CANARY_DO_NOT_RENDER')
    expect(wrapper.get('[data-test="cyber-review-metadata"]').text()).toContain('caller@example.test')
    expect(wrapper.get('[data-test="cyber-review-metadata"]').text()).toContain('oauth@example.test')
  })

  it('opens and highlights a safe deep-linked event detail', async () => {
    const wrapper = mount(CyberLearningWorkspace, {
      props: { initialEventId: 17 },
      global: { stubs: { BaseDialog: BaseDialogStub, ConfirmDialog: ConfirmDialogStub } },
    })
    await flushPromises()
    expect(mocks.getCyberEvent).toHaveBeenCalledWith(17)
    expect(mocks.getCyberEvidence).toHaveBeenCalledWith(17)
    expect(wrapper.get('[data-test="cyber-event-row"]').attributes('data-highlighted')).toBe('true')
    expect(wrapper.get('.cyber-highlighted-row').classes()).toContain('bg-primary-50/60')
    expect(wrapper.find('[role="dialog"]').exists()).toBe(true)
    expect(wrapper.get('[data-test="cyber-full-prompt"]').text()).toContain('RAW_PROMPT_CANARY_RENDER_IN_DETAIL')
  })

  it('prefills the system candidate, allows an edit, and adopts with the current config version', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.get('[data-test="cyber-review-17"]').trigger('click')
    await flushPromises()

    const editor = wrapper.get('#cyber-rule-text')
    expect((editor.element as HTMLTextAreaElement).value).toContain('prohibited credential automation')
    await editor.setValue('Abstract edited rule.')
    await wrapper.get('[data-test="cyber-adopt"]').trigger('click')
    await flushPromises()

    expect(mocks.adoptCyberEvent).toHaveBeenCalledWith(17, 'Abstract edited rule.', 30)
    expect(mocks.showSuccess).toHaveBeenCalled()
  })

  it('shows only a safe generation error code and can request regeneration', async () => {
    const failedEvent = event({ generation_status: 'failed', generation_error_code: 'candidate_timeout', candidate_rule_text: '' })
    mocks.listCyberEvents.mockResolvedValue(page(failedEvent))
    mocks.getCyberEvent.mockResolvedValue({ event: failedEvent })
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.get('[data-test="cyber-review-17"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[data-test="cyber-generation-failed"]').text()).toContain('candidate_timeout')
    expect(wrapper.find('#cyber-rule-text').exists()).toBe(false)
    await wrapper.get('[data-test="cyber-regenerate"]').trigger('click')
    await flushPromises()
    expect(mocks.regenerateCyberCandidate).toHaveBeenCalledWith(17)
  })

  it('explains unrecoverable historical evidence, disables regeneration, and clears raw evidence when closed', async () => {
    const failedEvent = event({ generation_status: 'failed', generation_error_code: 'source_unavailable', candidate_rule_text: '' })
    mocks.listCyberEvents.mockResolvedValue(page(failedEvent))
    mocks.getCyberEvent.mockResolvedValue({ event: failedEvent })
    mocks.getCyberEvidence.mockResolvedValue(evidence({ available: false, full_prompt: '', prompt_length: 0, message_count: 0 }))
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.get('[data-test="cyber-view-17"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[data-test="cyber-evidence-unavailable"]').exists()).toBe(true)
    await wrapper.get('[data-test="cyber-detail-review"]').trigger('click')
    expect(wrapper.find('[data-test="cyber-regenerate"]').exists()).toBe(false)

    wrapper.getComponent(BaseDialogStub).vm.$emit('close')
    await flushPromises()
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)
    expect(wrapper.html()).not.toContain('RAW_PROMPT_CANARY_RENDER_IN_DETAIL')
  })

  it('rejects feedback without requiring a manual summary', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.get('[data-test="cyber-review-17"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-test="cyber-reject"]').trigger('click')
    await flushPromises()
    expect(mocks.rejectCyberEvent).toHaveBeenCalledWith(17, '')
  })

  it('loads review states and keeps disabled rules recoverable until a confirmed deletion', async () => {
    const disabledRule = {
      id: 'cyb-feedback-2', rule_text: 'Recovered abstract rule.', source_feedback_id: 2, status: 'disabled',
      created_at: '2026-08-15T00:00:00Z', created_by: 1, config_version: 28,
      rule_text_source: 'recovered_candidate', recovered_candidate: true,
    }
    const unavailableRule = {
      id: 'cyb-feedback-1', rule_text: '', source_feedback_id: 1, status: 'disabled',
      created_at: '2026-08-14T00:00:00Z', created_by: 1, config_version: 27,
      rule_text_source: 'unavailable', recovered_candidate: false,
    }
    mocks.listCyberEvents.mockResolvedValue({
      ...page(),
      active_rules: [...page().active_rules, disabledRule, unavailableRule],
    })
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.get('[data-test="cyber-status-rejected"]').trigger('click')
    await flushPromises()
    expect(mocks.listCyberEvents).toHaveBeenLastCalledWith('rejected', 1, 20)

    await wrapper.get('[data-test="cyber-revoke-cyb-feedback-3"]').trigger('click')
    await flushPromises()
    expect(mocks.revokeCyberRule).toHaveBeenCalledWith('cyb-feedback-3', 30)

    await wrapper.get('[data-test="cyber-rule-status-disabled"]').trigger('click')
    expect(wrapper.get('[data-test="cyber-recovered-rule-warning"]').exists()).toBe(true)
    expect(wrapper.get('[data-test="cyber-unrecoverable-rule-warning"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="cyber-restore-cyb-feedback-1"]').exists()).toBe(false)
    await wrapper.get('[data-test="cyber-restore-cyb-feedback-2"]').trigger('click')
    expect(wrapper.get('[data-test="rule-confirm"]').text()).toContain('admin.promptAudit.cyber.rules.restoreRecoveredConfirmMessage')
    await wrapper.get('[data-test="rule-confirm-action"]').trigger('click')
    await flushPromises()
    expect(mocks.restoreCyberRule).toHaveBeenCalledWith('cyb-feedback-2', 30)

    await wrapper.get('[data-test="cyber-delete-cyb-feedback-2"]').trigger('click')
    expect(wrapper.get('[data-test="rule-confirm"]').text()).toContain('admin.promptAudit.cyber.rules.deleteConfirmMessage')
    await wrapper.get('[data-test="rule-confirm-action"]').trigger('click')
    await flushPromises()
    expect(mocks.deleteCyberRule).toHaveBeenCalledWith('cyb-feedback-2', 30)
  })
})

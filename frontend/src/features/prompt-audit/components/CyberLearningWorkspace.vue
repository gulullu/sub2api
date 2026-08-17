<template>
  <section class="py-6" data-test="cyber-learning-workspace">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.cyber.title') }}</h2>
        <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.cyber.description') }}</p>
      </div>
      <button type="button" class="btn btn-secondary btn-sm" :disabled="loading" @click="loadPage">
        {{ t('admin.promptAudit.cyber.refresh') }}
      </button>
    </div>

    <div class="mt-5 rounded-xl border border-primary-200 bg-primary-50 px-4 py-3 dark:border-primary-900/60 dark:bg-primary-950/30">
      <p class="text-sm font-medium text-primary-900 dark:text-primary-100">
        {{ t('admin.promptAudit.cyber.promptInjection', { version: page.config_version, count: page.active_rules.length }) }}
      </p>
      <p class="mt-1 text-xs text-primary-700 dark:text-primary-300">{{ t('admin.promptAudit.cyber.promptInjectionHint') }}</p>
    </div>

    <div class="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <div class="min-w-0">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-gray-200 pb-3 dark:border-dark-700">
          <div class="tabs inline-flex" role="tablist" :aria-label="t('admin.promptAudit.cyber.statusLabel')">
            <button
              v-for="item in statusTabs"
              :key="item"
              type="button"
              role="tab"
              class="tab"
              :class="{ 'tab-active': status === item }"
              :aria-selected="status === item"
              :data-test="`cyber-status-${item}`"
              @click="setStatus(item)"
            >
              {{ t(`admin.promptAudit.cyber.status.${item}`) }}
            </button>
          </div>
          <span class="text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.cyber.total', { count: page.total }) }}</span>
        </div>

        <div v-if="error" role="alert" class="mt-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">
          {{ error }}
        </div>
        <div v-if="loading" class="py-14 text-center text-sm text-gray-500" aria-busy="true">{{ t('common.loading') }}</div>
        <div v-else-if="page.items.length === 0" class="py-14 text-center text-sm text-gray-500 dark:text-dark-400">
          {{ t('admin.promptAudit.cyber.empty') }}
        </div>
        <div v-else class="divide-y divide-gray-100 dark:divide-dark-700">
          <article
            v-for="event in page.items"
            :key="event.id"
            class="py-5"
            :class="{ 'rounded-xl bg-primary-50/70 px-3 ring-1 ring-primary-200 dark:bg-primary-950/20 dark:ring-primary-900/60': props.initialEventId === event.id }"
            data-test="cyber-event-row"
            :data-highlighted="props.initialEventId === event.id ? 'true' : undefined"
          >
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="font-mono text-xs text-gray-500">#{{ event.id }}</span>
                  <span class="rounded-full px-2 py-0.5 text-xs font-medium" :class="statusClass(event.status)">
                    {{ t(`admin.promptAudit.cyber.status.${event.status}`) }}
                  </span>
                  <span class="text-sm font-medium text-gray-900 dark:text-white">{{ event.model || '—' }}</span>
                </div>
                <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">
                  {{ event.endpoint || '—' }} · {{ event.protocol || '—' }} · {{ formatDate(event.last_confirmed_at || event.updated_at || event.created_at) }}
                </p>
              </div>
              <button type="button" class="btn btn-secondary btn-sm" :data-test="`cyber-view-${event.id}`" @click="openEvent(event)">
                {{ t('admin.promptAudit.cyber.review') }}
              </button>
            </div>
            <p class="mt-3 line-clamp-3 whitespace-pre-wrap break-words rounded-lg bg-gray-50 px-3 py-2 text-sm text-gray-700 dark:bg-dark-900 dark:text-dark-200">
              {{ event.redacted_preview || t('admin.promptAudit.cyber.noPreview') }}
            </p>
            <dl class="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-gray-500 dark:text-dark-400">
              <div><dt class="inline">{{ t('admin.promptAudit.cyber.fields.groupId') }}: </dt><dd class="inline">{{ displayID(event.group_id) }}</dd></div>
              <div><dt class="inline">{{ t('admin.promptAudit.cyber.fields.accountId') }}: </dt><dd class="inline">{{ displayID(event.account_id) }}</dd></div>
              <div><dt class="inline">{{ t('admin.promptAudit.cyber.fields.confirmCount') }}: </dt><dd class="inline">{{ event.confirm_count }}</dd></div>
              <div><dt class="inline">{{ t('admin.promptAudit.cyber.fields.similarCount') }}: </dt><dd class="inline">{{ event.similar_count ?? 1 }}</dd></div>
              <div><dt class="inline">HTTP: </dt><dd class="inline">{{ event.upstream_status ?? '—' }}</dd></div>
            </dl>
          </article>
        </div>

        <div v-if="page.total > page.page_size" class="mt-5 flex items-center justify-between border-t border-gray-200 pt-4 dark:border-dark-700">
          <button type="button" class="btn btn-secondary btn-sm" :disabled="page.page <= 1 || loading" @click="changePage(page.page - 1)">
            {{ t('admin.promptAudit.cyber.previous') }}
          </button>
          <span class="text-xs text-gray-500">{{ t('admin.promptAudit.cyber.page', { page: page.page, pages: pageCount }) }}</span>
          <button type="button" class="btn btn-secondary btn-sm" :disabled="page.page >= pageCount || loading" @click="changePage(page.page + 1)">
            {{ t('admin.promptAudit.cyber.next') }}
          </button>
        </div>
      </div>

      <aside class="rounded-xl border border-gray-200 p-4 dark:border-dark-700" data-test="cyber-active-rules">
        <div class="flex items-center justify-between gap-3">
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.cyber.rules.title') }}</h3>
          <span class="rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-300">{{ page.active_rules.length }}</span>
        </div>
        <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.cyber.rules.description') }}</p>
        <div v-if="page.active_rules.length === 0" class="py-8 text-center text-sm text-gray-500">{{ t('admin.promptAudit.cyber.rules.empty') }}</div>
        <div v-else class="mt-4 space-y-4">
          <article v-for="rule in page.active_rules" :key="rule.id" class="rounded-lg bg-gray-50 p-3 dark:bg-dark-900">
            <p class="whitespace-pre-wrap break-words text-sm text-gray-800 dark:text-dark-100">{{ rule.rule_text }}</p>
            <div class="mt-3 flex items-center justify-between gap-3">
              <span class="text-xs text-gray-500">#{{ rule.id }} · v{{ rule.config_version }}</span>
              <button
                type="button"
                class="text-xs font-medium text-red-600 hover:text-red-700 disabled:opacity-50 dark:text-red-400"
                :disabled="mutating"
                :data-test="`cyber-revoke-${rule.id}`"
                @click="revokeRule(rule)"
              >
                {{ t('admin.promptAudit.cyber.rules.revoke') }}
              </button>
            </div>
          </article>
        </div>
      </aside>
    </div>

    <BaseDialog :show="selected !== null" :title="t('admin.promptAudit.cyber.detailTitle')" width="extra-wide" @close="closeEvent">
      <div v-if="selected" class="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(20rem,0.8fr)]">
        <div class="min-w-0">
          <h4 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.cyber.triggerContent') }}</h4>
          <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.cyber.triggerContentHint') }}</p>
          <div v-if="detailLoading" class="mt-3 rounded-lg bg-gray-50 px-4 py-8 text-center text-sm text-gray-500 dark:bg-dark-900" data-test="cyber-detail-loading">
            {{ t('common.loading') }}
          </div>
          <div v-else-if="evidenceError" role="alert" class="mt-3 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300" data-test="cyber-evidence-error">
            {{ evidenceError }}
          </div>
          <pre v-else-if="evidence?.available && evidence.full_prompt" class="mt-3 max-h-[36rem] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-gray-50 p-4 text-sm text-gray-700 dark:bg-dark-900 dark:text-dark-200" data-test="cyber-full-prompt">{{ evidence.full_prompt }}</pre>
          <div v-else class="mt-3 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200" data-test="cyber-evidence-unavailable">
            {{ t('admin.promptAudit.cyber.evidenceUnavailable') }}
          </div>

          <div class="mt-4 rounded-lg border border-amber-200 bg-amber-50/70 px-4 py-3 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/20 dark:text-amber-200">
            {{ t('admin.promptAudit.cyber.providerExplanation') }}
          </div>
        </div>
        <div class="min-w-0">
          <h4 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.cyber.reviewMetadata') }}</h4>
          <dl class="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm" data-test="cyber-review-metadata">
            <template v-for="row in detailRows(selected, evidence)" :key="row.label">
              <dt class="text-gray-500">{{ row.label }}</dt>
              <dd class="break-all text-gray-900 dark:text-dark-100">{{ row.value }}</dd>
            </template>
          </dl>
          <p v-if="evidence?.identity_source === 'current'" class="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-950/30 dark:text-amber-200" data-test="cyber-current-identity-warning">
            {{ t('admin.promptAudit.cyber.currentIdentityWarning') }}
          </p>

          <div v-if="selected.status === 'pending'" class="mt-6 space-y-4 border-t border-gray-200 pt-5 dark:border-dark-700">
            <div>
              <label class="input-label" for="cyber-rule-text">{{ t('admin.promptAudit.cyber.adopt.ruleLabel') }}</label>
              <div v-if="selected.generation_status === 'pending'" class="mt-2 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200" data-test="cyber-generation-pending">
                {{ t('admin.promptAudit.cyber.generation.pending') }}
              </div>
              <div v-else-if="selected.generation_status === 'failed'" class="mt-2 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300" data-test="cyber-generation-failed">
                <p>{{ t('admin.promptAudit.cyber.generation.failed') }}</p>
                <p class="mt-1 font-mono text-xs">{{ safeGenerationError(selected.generation_error_code) }}</p>
                <button v-if="canRegenerate" type="button" class="btn btn-secondary btn-sm mt-3" :disabled="mutating" data-test="cyber-regenerate" @click="regenerateSelected">
                  {{ t('admin.promptAudit.cyber.generation.regenerate') }}
                </button>
                <p v-else class="mt-2 text-xs">{{ t('admin.promptAudit.cyber.generation.unavailableWithoutEvidence') }}</p>
              </div>
              <textarea v-else id="cyber-rule-text" v-model="ruleText" rows="5" class="input mt-2 resize-y" :placeholder="t('admin.promptAudit.cyber.adopt.rulePlaceholder')" />
              <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.cyber.adopt.ruleHint') }}</p>
              <button type="button" class="btn btn-primary btn-sm mt-3" :disabled="mutating || selected.generation_status === 'pending' || selected.generation_status === 'failed' || !ruleText.trim()" data-test="cyber-adopt" @click="adoptSelected">
                {{ t('admin.promptAudit.cyber.adopt.action') }}
              </button>
            </div>
            <div>
              <label class="input-label" for="cyber-reject-reason">{{ t('admin.promptAudit.cyber.reject.reasonLabel') }}</label>
              <textarea id="cyber-reject-reason" v-model="rejectReason" rows="2" class="input resize-y" :placeholder="t('admin.promptAudit.cyber.reject.reasonPlaceholder')" />
              <button type="button" class="btn btn-secondary btn-sm mt-3" :disabled="mutating" data-test="cyber-reject" @click="rejectSelected">
                {{ t('admin.promptAudit.cyber.reject.action') }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </BaseDialog>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import { useAppStore } from '@/stores/app'
import { extractApiErrorCode, extractApiErrorMessage } from '@/utils/apiError'
import promptAuditAPI from '../api'
import type { CyberFeedbackDetail, CyberFeedbackEvent, CyberFeedbackEvidence, CyberFeedbackPage, CyberFeedbackStatus, CyberPolicyRule } from '../types'

const { t, locale } = useI18n()
const appStore = useAppStore()
const props = withDefaults(defineProps<{ initialEventId?: number | null }>(), { initialEventId: null })
const statusTabs: CyberFeedbackStatus[] = ['pending', 'approved', 'rejected']
const status = ref<CyberFeedbackStatus>('pending')
const loading = ref(false)
const mutating = ref(false)
const error = ref('')
const selected = ref<CyberFeedbackDetail | null>(null)
const evidence = ref<CyberFeedbackEvidence | null>(null)
const detailLoading = ref(false)
const evidenceError = ref('')
const ruleText = ref('')
const rejectReason = ref('')
const page = reactive<CyberFeedbackPage>({ items: [], total: 0, page: 1, page_size: 20, active_rules: [], config_version: 0 })
const pageCount = computed(() => Math.max(1, Math.ceil(page.total / page.page_size)))
const canRegenerate = computed(() => evidence.value?.available === true && evidence.value.full_prompt.length > 0)
let deepLinkAttempted = false
let detailRequestSequence = 0

function operationError(errorValue: unknown, fallbackKey: string): string {
  const code = extractApiErrorCode(errorValue)
  if (code) {
    const key = `admin.promptAudit.errors.${code}`
    const translated = t(key)
    if (translated !== key) return translated
  }
  return extractApiErrorMessage(errorValue, t(fallbackKey))
}

async function loadPage() {
  loading.value = true
  error.value = ''
  try {
    Object.assign(page, await promptAuditAPI.listCyberEvents(status.value, page.page, page.page_size))
    await resolveDeepLink()
  } catch (errorValue) {
    error.value = operationError(errorValue, 'admin.promptAudit.cyber.errors.load')
  } finally {
    loading.value = false
  }
}

async function resolveDeepLink() {
  const eventID = props.initialEventId
  if (!eventID || deepLinkAttempted) return
  deepLinkAttempted = true
  const listed = page.items.find((item) => item.id === eventID)
  await openEventByID(eventID, listed ?? null)
}

function setStatus(value: CyberFeedbackStatus) {
  if (status.value === value) return
  status.value = value
  page.page = 1
  closeEvent()
  void loadPage()
}

function changePage(value: number) {
  page.page = value
  void loadPage()
}

function openEvent(event: CyberFeedbackEvent) {
  void openEventByID(event.id, event)
}

async function openEventByID(eventID: number, fallback: CyberFeedbackEvent | null) {
  const requestSequence = ++detailRequestSequence
  selected.value = fallback
  evidence.value = null
  evidenceError.value = ''
  detailLoading.value = true
  ruleText.value = fallback?.candidate_rule_text || ''
  rejectReason.value = ''

  const [detailResult, evidenceResult] = await Promise.allSettled([
    promptAuditAPI.getCyberEvent(eventID),
    promptAuditAPI.getCyberEvidence(eventID),
  ])
  if (requestSequence !== detailRequestSequence) return

  if (detailResult.status === 'fulfilled' && detailResult.value.event) {
    selected.value = { ...(fallback ?? {}), ...detailResult.value.event }
  } else if (!fallback) {
    error.value = t('admin.promptAudit.cyber.errors.detail')
  }
  if (evidenceResult.status === 'fulfilled') {
    evidence.value = evidenceResult.value
  } else {
    evidenceError.value = evidenceFailureMessage(evidenceResult.reason)
  }
  detailLoading.value = false
  ruleText.value = selected.value?.candidate_rule_text || ''
}

function closeEvent() {
  detailRequestSequence += 1
  selected.value = null
  evidence.value = null
  detailLoading.value = false
  evidenceError.value = ''
  ruleText.value = ''
  rejectReason.value = ''
}

async function adoptSelected() {
  if (!selected.value || !ruleText.value.trim() || mutating.value) return
  mutating.value = true
  try {
    const result = await promptAuditAPI.adoptCyberEvent(selected.value.id, ruleText.value.trim(), page.config_version)
    closeEvent()
    await loadPage()
    appStore.showSuccess(t('admin.promptAudit.cyber.messages.adopted', { version: result.config_version ?? page.config_version }))
  } catch (errorValue) {
    await handleMutationError(errorValue, 'admin.promptAudit.cyber.errors.adopt')
  } finally {
    mutating.value = false
  }
}

async function rejectSelected() {
  if (!selected.value || mutating.value) return
  mutating.value = true
  try {
    await promptAuditAPI.rejectCyberEvent(selected.value.id, rejectReason.value.trim())
    closeEvent()
    await loadPage()
    appStore.showSuccess(t('admin.promptAudit.cyber.messages.rejected'))
  } catch (errorValue) {
    await handleMutationError(errorValue, 'admin.promptAudit.cyber.errors.reject')
  } finally {
    mutating.value = false
  }
}

async function regenerateSelected() {
  if (!selected.value || mutating.value) return
  const eventID = selected.value.id
  mutating.value = true
  try {
    const result = await promptAuditAPI.regenerateCyberCandidate(eventID)
    await loadPage()
    const refreshed = result.event ?? page.items.find((item) => item.id === eventID)
    if (refreshed) await openEventByID(refreshed.id, refreshed)
    appStore.showSuccess(t('admin.promptAudit.cyber.messages.regenerating'))
  } catch (errorValue) {
    await handleMutationError(errorValue, 'admin.promptAudit.cyber.errors.regenerate')
  } finally {
    mutating.value = false
  }
}

async function revokeRule(rule: CyberPolicyRule) {
  if (mutating.value) return
  mutating.value = true
  try {
    const result = await promptAuditAPI.revokeCyberRule(rule.id, page.config_version)
    await loadPage()
    appStore.showSuccess(t('admin.promptAudit.cyber.messages.revoked', { version: result.config_version ?? page.config_version }))
  } catch (errorValue) {
    await handleMutationError(errorValue, 'admin.promptAudit.cyber.errors.revoke')
  } finally {
    mutating.value = false
  }
}

async function handleMutationError(errorValue: unknown, fallbackKey: string) {
  const code = extractApiErrorCode(errorValue)
  if (code === 'prompt_audit_config_conflict' || code === 'cyber_policy_config_conflict') {
    await loadPage()
    appStore.showError(t('admin.promptAudit.cyber.errors.configConflict'))
    return
  }
  appStore.showError(operationError(errorValue, fallbackKey))
}

function detailRows(event: CyberFeedbackDetail, source: CyberFeedbackEvidence | null): Array<{ label: string; value: string }> {
  return [
    { label: t('admin.promptAudit.cyber.fields.requestId'), value: event.request_id || '—' },
    { label: t('admin.promptAudit.cyber.fields.userId'), value: displayID(source?.user_id) },
    { label: t('admin.promptAudit.cyber.fields.username'), value: source?.username || '—' },
    { label: t('admin.promptAudit.cyber.fields.userEmail'), value: source?.user_email || '—' },
    { label: t('admin.promptAudit.cyber.fields.apiKeyId'), value: displayID(source?.api_key_id) },
    { label: t('admin.promptAudit.cyber.fields.apiKeyName'), value: source?.api_key_name || '—' },
    { label: t('admin.promptAudit.cyber.fields.apiKeyPrefix'), value: source?.api_key_prefix || '—' },
    { label: t('admin.promptAudit.cyber.fields.group'), value: namedID(source?.group_id ?? event.group_id, source?.group_name) },
    { label: t('admin.promptAudit.cyber.fields.selectedAccount'), value: namedID(source?.selected_account_id ?? event.account_id, source?.selected_account_name || event.account_name) },
    { label: t('admin.promptAudit.cyber.fields.credentialAccount'), value: namedID(source?.credential_account_id, source?.credential_account_name) },
    { label: t('admin.promptAudit.cyber.fields.credentialAccountEmail'), value: sourcedEmail(source) },
    { label: t('admin.promptAudit.cyber.fields.identitySource'), value: identitySourceLabel(source?.identity_source) },
    { label: t('admin.promptAudit.cyber.fields.clientIp'), value: source?.client_ip || '—' },
    { label: t('admin.promptAudit.cyber.fields.userAgent'), value: source?.user_agent || '—' },
    { label: t('admin.promptAudit.cyber.fields.clientRequestId'), value: source?.client_request_id || '—' },
    { label: t('admin.promptAudit.cyber.fields.model'), value: event.model || '—' },
    { label: t('admin.promptAudit.cyber.fields.endpoint'), value: event.endpoint || '—' },
    { label: t('admin.promptAudit.cyber.fields.protocol'), value: event.protocol || '—' },
    { label: t('admin.promptAudit.cyber.fields.stage'), value: event.stage || '—' },
    { label: t('admin.promptAudit.cyber.fields.transport'), value: event.transport || '—' },
    { label: t('admin.promptAudit.cyber.fields.upstreamStatus'), value: event.upstream_status == null ? '—' : String(event.upstream_status) },
    { label: t('admin.promptAudit.cyber.fields.upstreamCode'), value: event.upstream_code || '—' },
    { label: t('admin.promptAudit.cyber.fields.upstreamMessage'), value: event.upstream_message || '—' },
    { label: t('admin.promptAudit.cyber.fields.promptLength'), value: String(source?.prompt_length ?? 0) },
    { label: t('admin.promptAudit.cyber.fields.messageCount'), value: String(source?.message_count ?? 0) },
    { label: t('admin.promptAudit.cyber.fields.truncated'), value: source?.truncated ? t('common.yes') : t('common.no') },
    { label: t('admin.promptAudit.cyber.fields.confirmCount'), value: String(event.confirm_count) },
    { label: t('admin.promptAudit.cyber.fields.similarCount'), value: String(event.similar_count ?? 1) },
    { label: t('admin.promptAudit.cyber.fields.firstConfirmed'), value: formatDate(event.first_confirmed_at || event.created_at) },
    { label: t('admin.promptAudit.cyber.fields.lastConfirmed'), value: formatDate(event.last_confirmed_at || event.updated_at) },
    { label: t('admin.promptAudit.cyber.fields.reviewedAt'), value: formatDate(event.reviewed_at) },
    { label: t('admin.promptAudit.cyber.fields.reviewedBy'), value: displayID(event.reviewed_by) },
    { label: t('admin.promptAudit.cyber.fields.ruleId'), value: event.rule_id || '—' },
    { label: t('admin.promptAudit.cyber.fields.configVersion'), value: `v${event.config_version}` },
    { label: t('admin.promptAudit.cyber.fields.adminAlert'), value: event.admin_alert_status || '—' },
  ]
}

function displayID(value: number | null | undefined): string {
  return value == null || value <= 0 ? '—' : String(value)
}

function namedID(id: number | null | undefined, name: string | null | undefined): string {
  const displayedID = displayID(id)
  const displayedName = name?.trim() || ''
  if (displayedID === '—') return displayedName || '—'
  return displayedName ? `${displayedName} (#${displayedID})` : `#${displayedID}`
}

function sourcedEmail(source: CyberFeedbackEvidence | null): string {
  if (!source?.credential_account_email) return '—'
  return source.credential_account_email_source === 'current'
    ? `${source.credential_account_email} (${t('admin.promptAudit.cyber.currentValue')})`
    : source.credential_account_email
}

function identitySourceLabel(value: string | undefined): string {
  if (value === 'snapshot') return t('admin.promptAudit.cyber.identitySnapshot')
  if (value === 'current') return t('admin.promptAudit.cyber.identityCurrent')
  return t('admin.promptAudit.cyber.identityUnavailable')
}

function evidenceFailureMessage(errorValue: unknown): string {
  return operationError(errorValue, 'admin.promptAudit.cyber.errors.evidence')
}

function safeGenerationError(value: string): string {
  const normalized = value.trim()
  return /^[a-z0-9_.:-]{1,80}$/i.test(normalized)
    ? normalized
    : t('admin.promptAudit.cyber.generation.unknownError')
}

function formatDate(value: string | null | undefined): string {
  if (!value) return '—'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'medium' }).format(parsed)
}

function statusClass(value: CyberFeedbackStatus): string {
  if (value === 'approved') return 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-300'
  if (value === 'rejected') return 'bg-gray-100 text-gray-700 dark:bg-dark-700 dark:text-dark-200'
  return 'bg-amber-50 text-amber-700 dark:bg-amber-950/30 dark:text-amber-300'
}

onMounted(loadPage)
</script>

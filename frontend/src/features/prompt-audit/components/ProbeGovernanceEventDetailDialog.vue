<template>
  <BaseDialog
    :show="show"
    :title="t('admin.promptAudit.probeGovernance.detail.title')"
    width="wide"
    :z-index="70"
    :close-on-click-outside="false"
    @close="close"
  >
    <div v-if="loading" class="flex min-h-48 items-center justify-center">
      <LoadingSpinner size="lg" />
    </div>
    <div v-else-if="event" class="space-y-6" data-test="probe-governance-event-detail">
      <div class="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-gray-200 bg-gray-50/60 p-4 dark:border-dark-700 dark:bg-dark-900/40">
        <div class="min-w-0">
          <p class="break-all font-mono text-sm font-semibold text-gray-900 dark:text-white">{{ event.family_fingerprint }}</p>
          <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ classificationLabel(event.classification) }}</p>
        </div>
        <span class="badge" :class="verdictClass(event.verdict)">{{ verdictLabel(event.verdict) }}</span>
      </div>

      <section>
        <h3 class="mb-3 text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.probeGovernance.detail.classification') }}</h3>
        <dl class="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.group')" :value="`${event.group_name} · #${event.group_id}`" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.auditConfigVersion')" :value="`v${event.audit_config_version}`" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.probeConfigVersion')" :value="`v${event.probe_config_version}`" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.riskSource')" :value="event.risk_source || '—'" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.evidence')" :value="evidenceText" wide />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.preview')" :value="event.family_preview || '—'" wide />
        </dl>
      </section>

      <section class="border-t border-gray-200 pt-5 dark:border-dark-700">
        <h3 class="mb-3 text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.probeGovernance.detail.request') }}</h3>
        <dl class="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
          <DetailItem :label="t('admin.promptAudit.probeGovernance.events.user')" :value="identityLabel(event.user_email, event.user_id, true)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.events.apiKey')" :value="identityLabel(event.api_key_name, event.api_key_id, false)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.events.modelProtocol')" :value="`${event.model || '—'} · ${protocolLabel(event.protocol)}`" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.stream')" :value="event.stream ? t('common.yes') : t('common.no')" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.maxTokens')" :value="event.max_tokens == null ? '—' : String(event.max_tokens)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.responseKind')" :value="responseKindLabel(event.response_kind)" />
        </dl>
      </section>

      <section class="border-t border-gray-200 pt-5 dark:border-dark-700">
        <h3 class="mb-3 text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.probeGovernance.detail.statistics') }}</h3>
        <dl class="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.firstSeen')" :value="formatDate(event.first_seen_at)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.lastSeen')" :value="formatDate(event.last_seen_at)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.totalCount')" :value="formatNumber(event.total_count)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.localResponseCount')" :value="formatNumber(event.local_response_count)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.savedAudit')" :value="formatNumber(event.audit_skipped_count)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.savedUpstream')" :value="formatNumber(event.upstream_skipped_count)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.actualAuditCalls')" :value="formatNumber(event.audit_call_count)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.actualUpstreamCalls')" :value="formatNumber(event.upstream_call_count)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.lastRealHealth')" :value="formatDate(event.last_real_health_at)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.windowExpires')" :value="formatDate(event.window_expires_at)" />
          <DetailItem :label="t('admin.promptAudit.probeGovernance.detail.nextRealProbe')" :value="formatDate(event.next_real_probe_at)" />
        </dl>
      </section>

      <section class="border-t border-gray-200 pt-5 dark:border-dark-700">
        <h3 class="text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.probeGovernance.detail.promptSnapshot') }}</h3>
        <p class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.probeGovernance.detail.promptSnapshotHint') }}</p>
        <pre class="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-gray-200 bg-gray-50 p-4 text-xs leading-5 text-gray-700 dark:border-dark-700 dark:bg-dark-900 dark:text-dark-200">{{ safeJSON(event.prompt_snapshot) }}</pre>
      </section>

      <section v-if="clearing" class="rounded-xl border border-amber-200 bg-amber-50/70 p-4 dark:border-amber-900/60 dark:bg-amber-950/20">
        <Input
          v-model="clearReason"
          :label="t('admin.promptAudit.probeGovernance.detail.clearReason')"
          :placeholder="t('admin.promptAudit.probeGovernance.detail.clearReasonPlaceholder')"
          required
          data-test="probe-governance-clear-reason"
          @enter="confirmClear"
        />
        <div class="mt-3 flex justify-end gap-2">
          <button type="button" class="btn btn-secondary btn-sm" :disabled="clearingBusy" @click="clearing = false">{{ t('common.cancel') }}</button>
          <button type="button" class="btn btn-danger btn-sm" :disabled="clearingBusy || !clearReason.trim()" data-test="probe-governance-clear-confirm" @click="confirmClear">
            {{ t('admin.promptAudit.probeGovernance.detail.confirmClear') }}
          </button>
        </div>
      </section>
    </div>

    <template #footer>
      <div class="flex w-full flex-wrap items-center justify-between gap-3">
        <div class="flex flex-wrap gap-2">
          <button v-if="event" type="button" class="btn btn-secondary" @click="$emit('add-exemption', event)">{{ t('admin.promptAudit.probeGovernance.detail.addExemption') }}</button>
          <button v-if="event?.linked_audit_event_id" type="button" class="btn btn-secondary" @click="$emit('view-audit-event', event.linked_audit_event_id)">{{ t('admin.promptAudit.probeGovernance.detail.viewAuditEvent') }}</button>
          <button v-if="event" type="button" class="btn btn-danger" :disabled="clearingBusy" data-test="probe-governance-clear-event" @click="clearing = true">{{ t('admin.promptAudit.probeGovernance.detail.clearClassification') }}</button>
        </div>
        <button type="button" class="btn btn-primary" @click="close">{{ t('common.close') }}</button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Input from '@/components/common/Input.vue'
import LoadingSpinner from '@/components/common/LoadingSpinner.vue'
import type { ProbeGovernanceEventDetail } from '../types'

const props = defineProps<{ show: boolean; event: ProbeGovernanceEventDetail | null; loading: boolean; clearingBusy: boolean }>()
const emit = defineEmits<{
  (event: 'close'): void
  (event: 'clear', id: number, reason: string): void
  (event: 'add-exemption', value: ProbeGovernanceEventDetail): void
  (event: 'view-audit-event', id: number): void
}>()
const { t, locale } = useI18n()
const clearing = ref(false)
const clearReason = ref('')

watch(() => props.show, (show) => {
  if (show) {
    clearing.value = false
    clearReason.value = ''
  }
})

const evidenceText = computed(() => {
  if (!props.event) return '—'
  return safeJSON(props.event.evidence)
})
function safeJSON(value: Record<string, unknown> | null | undefined): string {
  if (!value || Object.keys(value).length === 0) return '—'
  try { return JSON.stringify(value, null, 2) }
  catch { return '—' }
}
function close() {
  if (!props.clearingBusy) emit('close')
}
function confirmClear() {
  const reason = clearReason.value.trim()
  if (!props.event || !reason || props.clearingBusy) return
  emit('clear', props.event.id, reason)
}
function formatDate(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(locale.value.startsWith('zh') ? 'zh-CN' : 'en-US', { dateStyle: 'medium', timeStyle: 'medium' }).format(date)
}
function formatNumber(value: number): string { return Number(value || 0).toLocaleString() }
function identityLabel(name: string, id: number | null, user: boolean): string {
  const fallback = user ? t('admin.promptAudit.probeGovernance.events.unknownUser') : t('admin.promptAudit.probeGovernance.events.unnamedApiKey')
  return `${name || fallback}${id ? ` · #${id}` : ''}`
}
function protocolLabel(value: string): string {
  const key = `admin.promptAudit.probeGovernance.protocols.${value}`
  const translated = t(key)
  return translated === key ? (value || '—') : translated
}
function classificationLabel(value: string): string {
  const key = `admin.promptAudit.probeGovernance.classifications.${value}`
  const translated = t(key)
  return translated === key ? (value || '—') : translated
}
function responseKindLabel(value: string): string {
  const key = `admin.promptAudit.probeGovernance.responseKinds.${value}`
  const translated = t(key)
  return translated === key ? (value || '—') : translated
}
function verdictLabel(value: string): string {
  const key = `admin.promptAudit.probeGovernance.verdicts.${value}`
  const translated = t(key)
  return translated === key ? (value || '—') : translated
}
function verdictClass(value: string): string {
  if (value === 'healthy') return 'badge-success'
  if (value === 'confirmed_violation') return 'badge-danger'
  if (value === 'candidate') return 'badge-warning'
  return 'badge-gray'
}

const DetailItem = defineComponent({
  props: { label: { type: String, required: true }, value: { type: String, required: true }, wide: Boolean },
  setup(componentProps) {
    return () => h('div', { class: componentProps.wide ? 'sm:col-span-2 lg:col-span-3' : '' }, [
      h('dt', { class: 'text-xs font-medium text-gray-500 dark:text-dark-400' }, componentProps.label),
      h('dd', { class: 'mt-1 whitespace-pre-wrap break-words text-sm text-gray-900 dark:text-white' }, componentProps.value),
    ])
  },
})
</script>

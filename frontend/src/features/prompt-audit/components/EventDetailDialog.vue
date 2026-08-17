<template>
  <BaseDialog :show="show" :title="t('admin.promptAudit.events.detailTitle')" width="extra-wide" @close="$emit('close')">
    <div v-if="loading" class="py-12 text-center text-sm text-gray-500" aria-busy="true">{{ t('common.loading') }}</div>
    <div v-else-if="event" class="flex flex-col">
      <div class="rounded-2xl border border-gray-200 bg-gray-50/60 p-5 dark:border-dark-700 dark:bg-dark-900/60">
        <div class="flex flex-wrap items-center gap-3">
          <span class="rounded-full px-2.5 py-1 text-xs font-medium" :class="decisionClass(event.decision)">{{ formatDecisionAction(event.decision, event.action) }}</span>
          <span class="font-medium text-gray-900 dark:text-white">{{ event.snapshot.model || '—' }}</span>
          <span class="font-mono text-xs text-gray-500">#{{ event.id }}</span>
        </div>
        <p class="mt-2 break-all text-xs text-gray-500 dark:text-gray-400">{{ event.snapshot.endpoint }} · {{ event.snapshot.protocol }} · {{ event.snapshot.request_id || '—' }}</p>
      </div>

      <div class="mt-4 border-b border-gray-200 pb-4 dark:border-dark-700">
        <div class="tabs inline-flex w-full flex-wrap sm:w-auto" role="tablist">
          <button v-for="tab in tabs" :key="tab" type="button" role="tab" :aria-selected="activeTab === tab" class="tab flex-1 sm:flex-none" :class="{ 'tab-active': activeTab === tab }" @click="activeTab = tab">
          {{ t(`admin.promptAudit.events.tabs.${tab}`) }}
          </button>
        </div>
      </div>

      <!-- Fixed panel height so switching tabs does not resize the dialog -->
      <div class="mt-5 h-[min(62vh,36rem)] overflow-y-auto" data-test="event-detail-tab-panel">
        <div v-show="activeTab === 'summary'" class="grid gap-5 lg:grid-cols-[minmax(0,1.35fr)_minmax(20rem,0.65fr)]" role="tabpanel">
          <section>
            <h4 class="text-xs font-bold uppercase tracking-wider text-gray-400">{{ t('admin.promptAudit.events.promptFull') }}</h4>
            <pre class="mt-2 max-h-[min(46vh,26rem)] overflow-auto whitespace-pre-wrap break-words rounded-xl bg-gray-50 p-4 font-mono text-xs leading-6 text-gray-700 dark:bg-dark-900 dark:text-gray-300" data-test="summary-prompt-full">{{ displayPrompt(event) }}</pre>
          </section>
          <dl class="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
            <div v-for="row in summaryRows(event)" :key="row.label" class="rounded-xl bg-gray-50 p-4 dark:bg-dark-900">
              <dt class="text-xs font-bold uppercase tracking-wider text-gray-400">{{ row.label }}</dt>
              <dd class="mt-1 break-all text-sm font-medium text-gray-900 dark:text-white">{{ row.value }}</dd>
            </div>
          </dl>
        </div>

        <div v-show="activeTab === 'risks'" class="space-y-5" role="tabpanel">
          <div class="grid gap-4 lg:grid-cols-2">
            <section class="rounded-xl border border-gray-200 p-4 dark:border-dark-700" data-test="risk-prompt-preview">
              <h4 class="text-xs font-bold uppercase tracking-wider text-gray-400">{{ t('admin.promptAudit.events.promptFull') }}</h4>
              <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.events.promptFullHint') }}</p>
              <pre class="mt-2 h-[min(46vh,26rem)] overflow-auto whitespace-pre-wrap break-words rounded-xl bg-gray-50 p-4 font-mono text-xs leading-6 text-gray-700 dark:bg-dark-900 dark:text-gray-300" data-test="risk-prompt-full">{{ displayPrompt(event) }}</pre>
            </section>
            <section class="rounded-xl border border-gray-200 p-4 dark:border-dark-700" data-test="risk-guard-return">
              <h4 class="text-xs font-bold uppercase tracking-wider text-gray-400">{{ t('admin.promptAudit.events.guardReturn') }}</h4>
              <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.events.guardReturnHint') }}</p>
              <pre class="mt-2 h-[min(46vh,26rem)] overflow-auto whitespace-pre-wrap break-words rounded-xl bg-gray-50 p-4 font-mono text-xs leading-6 text-gray-700 dark:bg-dark-900 dark:text-gray-300">{{ formatGuardReturn(event) }}</pre>
            </section>
          </div>

          <div class="space-y-3">
            <h4 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.events.riskSummaries') }}</h4>
            <article v-for="issue in event.issue_summaries" :key="`${issue.scanner_id}-${issue.code}`" class="rounded-xl border border-gray-200 border-l-4 border-l-red-400 p-4 dark:border-dark-700 dark:border-l-red-400" data-test="risk-issue">
              <div class="flex flex-wrap items-center gap-2">
                <h5 class="font-medium text-gray-900 dark:text-white">{{ issueTitle(issue) }}</h5>
                <span class="text-xs text-red-600 dark:text-red-300">{{ issueSeverity(issue) }} · {{ issueAction(issue) }}</span>
              </div>
              <p class="mt-1 text-sm text-gray-600 dark:text-dark-300">{{ issueDescription(issue) }}</p>
              <dl class="mt-2 grid gap-1 text-xs text-gray-500 dark:text-dark-400 sm:grid-cols-2">
                <div><dt class="inline text-gray-400">{{ t('admin.promptAudit.events.categories') }} · </dt><dd class="inline">{{ translateCategory(issue.category || issue.scanner_id) }}</dd></div>
                <div><dt class="inline text-gray-400">{{ t('admin.promptAudit.events.score') }} · </dt><dd class="inline">{{ issue.score }}</dd></div>
                <div class="sm:col-span-2"><dt class="inline text-gray-400">{{ t('admin.promptAudit.events.evidence') }} · </dt><dd class="inline break-words">{{ issue.evidence ? translateEvidence(issue.evidence) : '—' }}</dd></div>
              </dl>
            </article>
            <p v-if="event.issue_summaries.length === 0" class="py-6 text-center text-sm text-gray-500">{{ t('admin.promptAudit.events.noRisks') }}</p>
          </div>
        </div>

        <dl v-show="activeTab === 'technical'" class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3" role="tabpanel">
          <div v-for="row in technicalRows(event)" :key="row.label" class="rounded-xl bg-gray-50 p-4 dark:bg-dark-900">
            <dt class="text-xs font-bold uppercase tracking-wider text-gray-400">{{ row.label }}</dt>
            <dd class="mt-1 break-all text-sm font-medium text-gray-900 dark:text-white">{{ row.value }}</dd>
          </div>
        </dl>
      </div>
    </div>
    <template #footer>
      <button type="button" class="btn btn-secondary" data-test="event-detail-close" @click="$emit('close')">{{ t('common.close') }}</button>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import type { PromptAuditEvent, PromptIssueSummary } from '../types'
import { LOCALIZED_SCANNER_IDS, SCANNER_CATALOG } from '../viewModel'

const props = defineProps<{ show: boolean; event: PromptAuditEvent | null; loading: boolean }>()
defineEmits<{ (event: 'close'): void }>()
const { t } = useI18n()
const tabs = ['summary', 'risks', 'technical'] as const
const activeTab = ref<(typeof tabs)[number]>('summary')
watch(() => props.event?.id, () => { activeTab.value = 'summary' })

const DECISIONS = new Set(['pass', 'flag', 'critical'])
const ACTIONS = new Set(['Allow', 'Warn', 'Block'])
const RISK_LEVELS = new Set(['low', 'medium', 'high', 'critical'])

function displayPrompt(event: PromptAuditEvent): string {
  return event.snapshot.full_prompt || event.snapshot.redacted_preview || '—'
}

function decisionClass(decision: string): string {
  if (decision === 'critical') return 'bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300'
  if (decision === 'flag') return 'bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300'
  return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300'
}

function formatDecisionAction(decision: string, action: string): string {
  const decisionLabel = DECISIONS.has(decision) ? t(`admin.promptAudit.decisions.${decision}`) : decision
  const actionLabel = ACTIONS.has(action) ? t(`admin.promptAudit.actions.${action}`) : action
  return `${decisionLabel} · ${actionLabel}`
}
function translateCategory(category: string): string {
  return LOCALIZED_SCANNER_IDS.has(category)
    ? t(`admin.promptAudit.scanners.${category}`)
    : category
}
function formatCategories(categories: string[]): string {
  if (!categories.length) return '—'
  return categories.map(translateCategory).join(', ')
}

function summaryRows(event: PromptAuditEvent): Array<{ label: string; value: string }> {
  return [
    { label: t('admin.promptAudit.events.decision'), value: formatDecisionAction(event.decision, event.action) },
    { label: t('admin.promptAudit.events.user'), value: event.snapshot.username || '—' },
    { label: t('admin.promptAudit.events.email'), value: event.snapshot.user_email || '—' },
    { label: t('admin.promptAudit.events.apiKey'), value: event.snapshot.api_key_name || '—' },
    { label: t('admin.promptAudit.events.group'), value: event.snapshot.group_name || '—' },
    { label: t('admin.promptAudit.events.categories'), value: formatCategories(event.categories) },
  ]
}

function technicalRows(event: PromptAuditEvent): Array<{ label: string; value: string }> {
  return [
    { label: t('admin.promptAudit.events.requestId'), value: event.snapshot.request_id || '—' },
    { label: t('admin.promptAudit.events.promptHash'), value: event.snapshot.prompt_hash },
    { label: t('admin.promptAudit.events.technical.scanner'), value: `${event.scanner_backend} · ${event.scanner_version}` },
    { label: t('admin.promptAudit.events.technical.policy'), value: `${event.policy_id} · v${event.policy_version}` },
    { label: t('admin.promptAudit.events.technical.guardEndpoint'), value: event.guard_endpoint_id || '—' },
    { label: t('admin.promptAudit.events.technical.config'), value: `v${event.config_version}` },
    { label: t('admin.promptAudit.events.technical.chunks'), value: String(event.chunk_total) },
    { label: t('admin.promptAudit.events.technical.latency'), value: `${event.latency_ms} ms` },
    { label: t('admin.promptAudit.events.stage'), value: event.snapshot.stage || 'http' },
    { label: t('admin.promptAudit.events.technical.protocol'), value: `${event.snapshot.protocol} · ${event.snapshot.endpoint}` },
  ]
}
function translateEvidence(value: string): string {
  const byId = SCANNER_CATALOG.find((scanner) => scanner.id === value)
  if (byId) return t(`admin.promptAudit.scanners.${byId.id}`)
  const byLabel = SCANNER_CATALOG.find((scanner) => scanner.label === value)
  if (byLabel) return t(`admin.promptAudit.scanners.${byLabel.id}`)
  return value
}
function formatGuardReturn(event: PromptAuditEvent): string {
  const evidence: Record<string, string> = {}
  for (const [key, value] of Object.entries(event.scanner_evidence || {})) {
    evidence[key] = translateEvidence(value)
  }
  return JSON.stringify({
    decision: DECISIONS.has(event.decision) ? t(`admin.promptAudit.decisions.${event.decision}`) : event.decision,
    risk_level: RISK_LEVELS.has(event.risk_level) ? t(`admin.promptAudit.riskLevels.${event.risk_level}`) : event.risk_level,
    action: ACTIONS.has(event.action) ? t(`admin.promptAudit.actions.${event.action}`) : event.action,
    categories: event.categories.map(translateCategory),
    matched_scanners: event.matched_scanners.map(translateCategory),
    scanner_scores: event.scanner_scores,
    scanner_evidence: evidence,
    scanner_backend: event.scanner_backend,
    scanner_version: event.scanner_version,
    guard_endpoint_id: event.guard_endpoint_id,
    chunk_total: event.chunk_total,
    latency_ms: event.latency_ms,
  }, null, 2)
}
function issueTitle(issue: PromptIssueSummary): string {
  return translateCategory(issue.category || issue.scanner_id) || issue.title
}
function issueDescription(issue: PromptIssueSummary): string {
  const category = issue.category || issue.scanner_id
  const key = `admin.promptAudit.scannerDescriptions.${category}`
  if (LOCALIZED_SCANNER_IDS.has(category)) return t(key)
  const label = t(key)
  return label === key ? issue.description : label
}
function issueSeverity(issue: PromptIssueSummary): string {
  return RISK_LEVELS.has(issue.severity) ? t(`admin.promptAudit.riskLevels.${issue.severity}`) : issue.severity_label || issue.severity
}
function issueAction(issue: PromptIssueSummary): string {
  return ACTIONS.has(issue.action) ? t(`admin.promptAudit.actions.${issue.action}`) : issue.action_label || issue.action
}
</script>

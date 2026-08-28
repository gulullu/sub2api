<template>
  <section class="space-y-6" data-test="cyber-learning-workspace">
    <div class="card overflow-hidden">
      <div class="flex flex-col gap-4 px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.cyber.title') }}</h2>
          <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-gray-400">{{ t('admin.promptAudit.cyber.description') }}</p>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" :disabled="loading" @click="loadPage">
          {{ t('admin.promptAudit.cyber.refresh') }}
        </button>
      </div>

      <div class="border-t border-gray-100 p-5 dark:border-dark-700">
        <div class="rounded-xl border border-primary-200 bg-primary-50 px-4 py-3 dark:border-primary-900/60 dark:bg-primary-950/30">
          <p class="text-sm font-medium text-primary-900 dark:text-primary-100">
            {{ t('admin.promptAudit.cyber.promptInjection', { version: page.config_version, count: activeRuleCount }) }}
          </p>
          <p class="mt-1 text-xs text-primary-700 dark:text-primary-300">{{ t('admin.promptAudit.cyber.promptInjectionHint') }}</p>
        </div>
      </div>
    </div>

    <section class="card overflow-hidden" data-test="cyber-feedback-list">
      <div class="flex flex-col gap-3 border-b border-gray-200 bg-gray-50/70 px-5 py-4 dark:border-dark-700 dark:bg-dark-900/40 sm:flex-row sm:items-center sm:justify-between">
        <div class="tabs inline-flex w-full flex-wrap sm:w-auto" role="tablist" :aria-label="t('admin.promptAudit.cyber.statusLabel')">
          <button
            v-for="item in statusTabs"
            :key="item"
            type="button"
            role="tab"
            class="tab flex-1 sm:flex-none"
            :class="{ 'tab-active': status === item }"
            :aria-selected="status === item"
            :data-test="`cyber-status-${item}`"
            @click="setStatus(item)"
          >
            {{ t(`admin.promptAudit.cyber.status.${item}`) }}
          </button>
        </div>
        <div class="flex flex-wrap items-center justify-end gap-2">
          <span class="text-xs text-gray-500 dark:text-gray-400">{{ t('admin.promptAudit.cyber.total', { count: page.total }) }}</span>
          <div class="relative">
            <button type="button" class="btn btn-secondary btn-sm" data-test="cyber-column-settings" :aria-expanded="cyberColumnMenuOpen" @click="cyberColumnMenuOpen = !cyberColumnMenuOpen">
              {{ t('admin.promptAudit.cyber.columnSettings') }}
            </button>
            <div v-if="cyberColumnMenuOpen" class="absolute right-0 z-20 mt-2 w-56 rounded-xl border border-gray-200 bg-white p-2 shadow-lg dark:border-dark-700 dark:bg-dark-800" data-test="cyber-column-menu">
              <label v-for="column in cyberConfigurableColumns" :key="column.key" class="flex cursor-pointer items-center gap-2 rounded-lg px-2 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-700">
                <input type="checkbox" :checked="isCyberColumnVisible(column.key)" @change="toggleCyberColumn(column.key)" />
                <span>{{ column.label }}</span>
              </label>
              <p class="px-2 pb-1 pt-2 text-[11px] text-gray-400 dark:text-dark-500">{{ t('admin.promptAudit.cyber.fixedColumns') }}</p>
            </div>
          </div>
        </div>
      </div>

      <div class="flex flex-wrap items-end gap-3 border-b border-gray-200 bg-white px-5 py-4 dark:border-dark-700 dark:bg-dark-900">
        <label class="min-w-[14rem] flex-1 text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.cyber.groupFilter') }}</span>
          <select v-model="groupFilter" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.cyber.groupFilter')" data-test="cyber-group-filter" @change="applyListFilters">
            <option value="">{{ t('admin.promptAudit.cyber.allGroups') }}</option>
            <option v-for="group in groupOptions" :key="group.id" :value="group.id">{{ group.name }} · #{{ group.id }}</option>
            <option v-if="groupFilter !== '' && !groupOptions.some((group) => group.id === groupFilter)" :value="groupFilter">#{{ groupFilter }}</option>
          </select>
        </label>
        <label class="min-w-[14rem] flex-1 text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.cyber.accountFilter') }}</span>
          <select v-model="accountFilter" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.cyber.accountFilter')" data-test="cyber-account-filter" @change="applyListFilters">
            <option value="">{{ t('admin.promptAudit.cyber.allAccounts') }}</option>
            <option v-for="account in accountOptions" :key="account.id" :value="account.id">{{ account.name || `#${account.id}` }} · #{{ account.id }}</option>
            <option v-if="accountFilter !== '' && !accountOptions.some((account) => account.id === accountFilter)" :value="accountFilter">#{{ accountFilter }}</option>
          </select>
        </label>
        <button type="button" class="btn btn-ghost btn-sm" :disabled="!hasListFilters || loading" data-test="cyber-reset-filters" @click="resetListFilters">{{ t('admin.promptAudit.cyber.resetFilters') }}</button>
      </div>

      <div v-if="error" role="alert" class="m-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">
        {{ error }}
      </div>
      <div class="bg-gray-50/60 p-3 dark:bg-dark-950/20 md:bg-transparent md:p-0" data-test="cyber-data-table">
        <DataTable
          :columns="visibleCyberColumns"
          :data="page.items"
          :loading="loading"
          row-key="id"
          :sticky-first-column="true"
          :sticky-actions-column="true"
          :row-class="cyberRowClass"
        >
          <template #cell-event="{ row }">
            <div data-test="cyber-event-row" :data-highlighted="props.initialEventId === row.id ? 'true' : undefined">
              <span class="font-mono text-xs text-gray-500">#{{ row.id }}</span>
              <span class="mt-2 block w-fit rounded-full px-2 py-0.5 text-xs font-medium" :class="statusClass(row.status)">{{ t(`admin.promptAudit.cyber.status.${row.status}`) }}</span>
            </div>
          </template>
          <template #cell-request="{ row }">
            <div class="min-w-0 max-w-[27rem]">
              <p class="truncate font-medium text-gray-900 dark:text-white" :title="row.model || undefined">{{ row.model || '—' }}</p>
              <p class="mt-1 truncate text-xs text-gray-500 dark:text-gray-400" :title="`${row.endpoint || '—'} · ${row.protocol || '—'}`">{{ row.endpoint || '—' }} · {{ row.protocol || '—' }}</p>
              <p class="mt-2 line-clamp-2 whitespace-normal break-words text-xs leading-5 text-gray-600 dark:text-gray-300">{{ row.redacted_preview || t('admin.promptAudit.cyber.noPreview') }}</p>
            </div>
          </template>
          <template #cell-route="{ row }">
            <div class="text-xs text-gray-600 dark:text-gray-300">
              <p>{{ t('admin.promptAudit.cyber.fields.group') }}: {{ groupLabel(row.group_id) }}</p>
              <p class="mt-1">{{ t('admin.promptAudit.cyber.fields.selectedAccount') }}: {{ accountLabel(row.account_id) }}</p>
              <p class="mt-1">HTTP {{ row.upstream_status ?? '—' }}</p>
            </div>
          </template>
          <template #cell-confirmations="{ row }">
            <div class="text-xs text-gray-600 dark:text-gray-300">
              <p>{{ t('admin.promptAudit.cyber.fields.confirmCount') }} {{ row.confirm_count }}</p>
              <p class="mt-1">{{ t('admin.promptAudit.cyber.fields.similarCount') }} {{ row.similar_count ?? 1 }}</p>
            </div>
          </template>
          <template #cell-last_confirmed="{ row }">
            <span class="whitespace-nowrap text-xs text-gray-600 dark:text-gray-300">{{ formatDate(row.last_confirmed_at || row.updated_at || row.created_at) }}</span>
          </template>
          <template #cell-actions="{ row }">
            <div class="flex flex-wrap justify-end gap-1">
              <button type="button" class="btn btn-ghost btn-sm" :data-test="`cyber-view-${row.id}`" @click.stop="openEvent(row)">{{ t('common.view') }}</button>
              <button v-if="row.status === 'pending'" type="button" class="btn btn-primary btn-sm" :data-test="`cyber-review-${row.id}`" @click.stop="openReview(row)">{{ t('admin.promptAudit.cyber.review') }}</button>
            </div>
          </template>
          <template #empty>
            <p class="py-8 text-sm text-gray-500 dark:text-gray-400">{{ t('admin.promptAudit.cyber.empty') }}</p>
          </template>
        </DataTable>
      </div>

      <div v-if="page.total > page.page_size" class="flex items-center justify-between border-t border-gray-200 px-5 py-4 dark:border-dark-700">
        <button type="button" class="btn btn-secondary btn-sm" :disabled="page.page <= 1 || loading" @click="changePage(page.page - 1)">
          {{ t('admin.promptAudit.cyber.previous') }}
        </button>
        <span class="text-xs text-gray-500">{{ t('admin.promptAudit.cyber.page', { page: page.page, pages: pageCount }) }}</span>
        <button type="button" class="btn btn-secondary btn-sm" :disabled="page.page >= pageCount || loading" @click="changePage(page.page + 1)">
          {{ t('admin.promptAudit.cyber.next') }}
        </button>
      </div>
    </section>

    <section class="card overflow-hidden" data-test="cyber-active-rules">
      <div class="flex flex-col gap-4 border-b border-gray-200 px-5 py-4 dark:border-dark-700 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h3 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.cyber.rules.title') }}</h3>
          <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.promptAudit.cyber.rules.description') }}</p>
        </div>
        <div class="tabs inline-flex w-full flex-wrap sm:w-auto" role="tablist" :aria-label="t('admin.promptAudit.cyber.rules.title')">
          <button
            v-for="item in ruleTabs"
            :key="item"
            type="button"
            role="tab"
            class="tab flex-1 sm:flex-none"
            :class="{ 'tab-active': ruleStatus === item }"
            :aria-selected="ruleStatus === item"
            :data-test="`cyber-rule-status-${item}`"
            @click="ruleStatus = item"
          >
            {{ t(`admin.promptAudit.cyber.rules.status.${item}`) }} ({{ ruleCounts[item] }})
          </button>
        </div>
      </div>

      <div v-if="visibleRules.length === 0" class="py-12 text-center text-sm text-gray-500 dark:text-gray-400">
        {{ t(`admin.promptAudit.cyber.rules.emptyStatus.${ruleStatus}`) }}
      </div>
      <div v-else class="grid gap-4 p-5 lg:grid-cols-2">
        <article v-for="rule in visibleRules" :key="rule.id" class="rounded-xl border border-gray-200 bg-gray-50/60 p-4 dark:border-dark-700 dark:bg-dark-900/50" data-test="cyber-rule-row">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <span class="rounded-full px-2 py-0.5 text-xs font-medium" :class="ruleStatusClass(rule)">
              {{ t(`admin.promptAudit.cyber.rules.status.${normalizedRuleStatus(rule)}`) }}
            </span>
            <span class="font-mono text-xs text-gray-400">#{{ rule.id }} · v{{ rule.config_version }}</span>
          </div>
          <p class="mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-gray-800 dark:text-gray-100">{{ rule.rule_text }}</p>
          <p v-if="isRecoveredCandidate(rule)" class="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-800 dark:bg-amber-950/30 dark:text-amber-200" data-test="cyber-recovered-rule-warning">
            {{ t('admin.promptAudit.cyber.rules.recoveredCandidate') }}
          </p>
          <p v-else-if="normalizedRuleStatus(rule) === 'disabled' && !canRestoreRule(rule)" class="mt-3 rounded-lg bg-gray-100 px-3 py-2 text-xs leading-5 text-gray-600 dark:bg-dark-700 dark:text-gray-300" data-test="cyber-unrecoverable-rule-warning">
            {{ t('admin.promptAudit.cyber.rules.unavailableText') }}
          </p>
          <div class="mt-4 flex flex-wrap items-center justify-end gap-2 border-t border-gray-200 pt-3 dark:border-dark-700">
            <button
              v-if="normalizedRuleStatus(rule) === 'active'"
              type="button"
              class="btn btn-secondary btn-sm"
              :disabled="mutating"
              :data-test="`cyber-revoke-${rule.id}`"
              @click="revokeRule(rule)"
            >
              {{ t('admin.promptAudit.cyber.rules.disable') }}
            </button>
            <template v-else-if="normalizedRuleStatus(rule) === 'disabled'">
              <button v-if="canRestoreRule(rule)" type="button" class="btn btn-primary btn-sm" :disabled="mutating" :data-test="`cyber-restore-${rule.id}`" @click="requestRestoreRule(rule)">
                {{ t('admin.promptAudit.cyber.rules.restore') }}
              </button>
              <button type="button" class="btn btn-danger btn-sm" :disabled="mutating" :data-test="`cyber-delete-${rule.id}`" @click="pendingRuleDelete = rule">
                {{ t('admin.promptAudit.cyber.rules.delete') }}
              </button>
            </template>
          </div>
        </article>
      </div>
    </section>

    <BaseDialog :show="showDetail" :title="t('admin.promptAudit.cyber.detailTitle')" width="extra-wide" @close="closeEvent">
      <div v-if="selected" class="space-y-5" data-test="cyber-detail-dialog">
        <div class="rounded-2xl border border-gray-200 bg-gray-50/60 p-5 dark:border-dark-700 dark:bg-dark-900/60">
          <div class="flex flex-wrap items-center gap-3">
            <span class="rounded-full px-2.5 py-1 text-xs font-medium" :class="statusClass(selected.status)">{{ t(`admin.promptAudit.cyber.status.${selected.status}`) }}</span>
            <span class="font-medium text-gray-900 dark:text-white">{{ selected.model || '—' }}</span>
            <span class="font-mono text-xs text-gray-500">#{{ selected.id }}</span>
          </div>
          <p class="mt-2 break-all text-xs text-gray-500 dark:text-gray-400">{{ selected.endpoint || '—' }} · {{ selected.protocol || '—' }} · {{ selected.request_id || '—' }}</p>
        </div>

        <section>
          <h4 class="text-xs font-bold uppercase tracking-wider text-gray-400">{{ t('admin.promptAudit.cyber.triggerContent') }}</h4>
          <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.promptAudit.cyber.triggerContentHint') }}</p>
          <div v-if="detailLoading" class="mt-3 rounded-xl bg-gray-50 px-4 py-12 text-center text-sm text-gray-500 dark:bg-dark-900" data-test="cyber-detail-loading">{{ t('common.loading') }}</div>
          <div v-else-if="evidenceError" role="alert" class="mt-3 rounded-xl bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300" data-test="cyber-evidence-error">{{ evidenceError }}</div>
          <pre v-else-if="evidence?.available && evidence.full_prompt" class="mt-3 max-h-[32rem] overflow-auto whitespace-pre-wrap break-words rounded-xl bg-gray-50 p-4 font-mono text-xs leading-6 text-gray-700 dark:bg-dark-900 dark:text-gray-300" data-test="cyber-full-prompt">{{ evidence.full_prompt }}</pre>
          <div v-else class="mt-3 rounded-xl bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200" data-test="cyber-evidence-unavailable">{{ t('admin.promptAudit.cyber.evidenceUnavailable') }}</div>
        </section>

        <div class="grid gap-4 lg:grid-cols-2" data-test="cyber-review-metadata">
          <section v-for="group in detailGroups(selected, evidence)" :key="group.title" class="rounded-xl border border-gray-200 p-4 dark:border-dark-700">
            <h4 class="text-xs font-bold uppercase tracking-wider text-gray-400">{{ group.title }}</h4>
            <dl class="mt-3 grid gap-3 sm:grid-cols-2">
              <div v-for="row in group.rows" :key="row.label" class="rounded-lg bg-gray-50 p-3 dark:bg-dark-900">
                <dt class="text-xs text-gray-400">{{ row.label }}</dt>
                <dd class="mt-1 break-all text-sm font-medium text-gray-900 dark:text-white">{{ row.value }}</dd>
              </div>
            </dl>
          </section>
        </div>

        <p v-if="evidence?.identity_source === 'current'" class="rounded-xl bg-amber-50 px-4 py-3 text-xs text-amber-800 dark:bg-amber-950/30 dark:text-amber-200" data-test="cyber-current-identity-warning">
          {{ t('admin.promptAudit.cyber.currentIdentityWarning') }}
        </p>
        <div class="rounded-xl border border-amber-200 bg-amber-50/70 px-4 py-3 text-xs leading-5 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/20 dark:text-amber-200">
          {{ t('admin.promptAudit.cyber.providerExplanation') }}
        </div>
      </div>
      <template #footer>
        <button type="button" class="btn btn-secondary" @click="closeEvent">{{ t('common.close') }}</button>
        <button v-if="selected?.status === 'pending'" type="button" class="btn btn-primary" data-test="cyber-detail-review" @click="switchToReview">{{ t('admin.promptAudit.cyber.review') }}</button>
      </template>
    </BaseDialog>

    <BaseDialog :show="showReview" :title="t('admin.promptAudit.cyber.reviewTitle')" width="wide" @close="closeEvent">
      <div v-if="selected" class="space-y-5" data-test="cyber-review-dialog">
        <div class="rounded-2xl border border-gray-200 bg-gray-50/60 p-5 dark:border-dark-700 dark:bg-dark-900/60">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-mono text-xs text-gray-500">#{{ selected.id }}</span>
            <span class="text-sm font-medium text-gray-900 dark:text-white">{{ selected.model || '—' }}</span>
            <span class="text-xs text-gray-500">{{ namedID(evidence?.group_id ?? selected.group_id, evidence?.group_name) }}</span>
          </div>
          <p class="mt-3 line-clamp-3 whitespace-pre-wrap break-words text-sm leading-6 text-gray-600 dark:text-gray-300">{{ selected.redacted_preview || t('admin.promptAudit.cyber.noPreview') }}</p>
        </div>

        <section class="rounded-xl border border-gray-200 p-4 dark:border-dark-700">
          <label class="input-label" for="cyber-rule-text">{{ t('admin.promptAudit.cyber.adopt.ruleLabel') }}</label>
          <div v-if="selected.generation_status === 'pending'" class="mt-2 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200" data-test="cyber-generation-pending">{{ t('admin.promptAudit.cyber.generation.pending') }}</div>
          <div v-else-if="selected.generation_status === 'failed'" class="mt-2 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300" data-test="cyber-generation-failed">
            <p>{{ t('admin.promptAudit.cyber.generation.failed') }}</p>
            <p class="mt-1 font-mono text-xs">{{ safeGenerationError(selected.generation_error_code) }}</p>
            <button v-if="canRegenerate" type="button" class="btn btn-secondary btn-sm mt-3" :disabled="mutating" data-test="cyber-regenerate" @click="regenerateSelected">{{ t('admin.promptAudit.cyber.generation.regenerate') }}</button>
            <p v-else class="mt-2 text-xs">{{ t('admin.promptAudit.cyber.generation.unavailableWithoutEvidence') }}</p>
          </div>
          <textarea v-else id="cyber-rule-text" v-model="ruleText" rows="6" class="input mt-2 resize-y" :placeholder="t('admin.promptAudit.cyber.adopt.rulePlaceholder')" />
          <p class="mt-2 text-xs leading-5 text-gray-500 dark:text-gray-400">{{ t('admin.promptAudit.cyber.adopt.ruleHint') }}</p>
        </section>

        <section class="rounded-xl bg-gray-50 p-4 dark:bg-dark-900">
          <label class="input-label" for="cyber-reject-reason">{{ t('admin.promptAudit.cyber.reject.reasonLabel') }}</label>
          <textarea id="cyber-reject-reason" v-model="rejectReason" rows="3" class="input mt-2 resize-y" :placeholder="t('admin.promptAudit.cyber.reject.reasonPlaceholder')" />
        </section>
      </div>
      <template #footer>
        <button type="button" class="btn btn-secondary" :disabled="mutating" @click="closeEvent">{{ t('common.cancel') }}</button>
        <button type="button" class="btn btn-danger" :disabled="mutating || detailLoading" data-test="cyber-reject" @click="rejectSelected">{{ t('admin.promptAudit.cyber.reject.action') }}</button>
        <button type="button" class="btn btn-primary" :disabled="mutating || detailLoading || selected?.generation_status === 'pending' || selected?.generation_status === 'failed' || !ruleText.trim()" data-test="cyber-adopt" @click="adoptSelected">{{ t('admin.promptAudit.cyber.adopt.action') }}</button>
      </template>
    </BaseDialog>

    <ConfirmDialog
      :show="pendingRuleRestore !== null"
      :title="t('admin.promptAudit.cyber.rules.restoreConfirmTitle')"
      :message="restoreConfirmMessage"
      :confirm-text="t('admin.promptAudit.cyber.rules.restore')"
      @confirm="confirmRestoreRule"
      @cancel="pendingRuleRestore = null"
    />
    <ConfirmDialog
      :show="pendingRuleDelete !== null"
      :title="t('admin.promptAudit.cyber.rules.deleteConfirmTitle')"
      :message="t('admin.promptAudit.cyber.rules.deleteConfirmMessage', { id: pendingRuleDelete?.id || '' })"
      :confirm-text="t('admin.promptAudit.cyber.rules.delete')"
      danger
      @confirm="confirmDeleteRule"
      @cancel="pendingRuleDelete = null"
    />
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import DataTable from '@/components/common/DataTable.vue'
import type { Column } from '@/components/common/types'
import { useAppStore } from '@/stores/app'
import { extractApiErrorCode, extractApiErrorMessage } from '@/utils/apiError'
import promptAuditAPI from '../api'
import type { CyberFeedbackDetail, CyberFeedbackEvent, CyberFeedbackEvidence, CyberFeedbackListFilter, CyberFeedbackPage, CyberFeedbackStatus, CyberPolicyRule, PromptAuditAccount, PromptAuditGroup } from '../types'

const { t, locale } = useI18n()
const appStore = useAppStore()
const props = withDefaults(defineProps<{
  initialEventId?: number | null
  groups?: PromptAuditGroup[]
  accounts?: PromptAuditAccount[]
}>(), { initialEventId: null, groups: () => [], accounts: () => [] })
const statusTabs: CyberFeedbackStatus[] = ['pending', 'approved', 'rejected']
const status = ref<CyberFeedbackStatus>('pending')
const groupFilter = ref<number | ''>('')
const accountFilter = ref<number | ''>('')
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
const cyberColumnMenuOpen = ref(false)
const hiddenCyberColumns = ref<string[]>([])
const groupOptions = computed<PromptAuditGroup[]>(() => {
  const options = props.groups.slice().sort((left, right) => left.id - right.id)
  if (!options.some((group) => group.id === 0)) {
    options.unshift({ id: 0, name: t('admin.promptAudit.groups.unassigned'), platform: '', status: 'active' })
  }
  return options
})
const accountOptions = computed(() => props.accounts.slice().sort((left, right) => left.id - right.id || left.name.localeCompare(right.name)))
const cyberColumns = computed<Column[]>(() => [
  { key: 'event', label: t('admin.promptAudit.cyber.columns.event'), class: 'min-w-36' },
  { key: 'request', label: t('admin.promptAudit.cyber.columns.request'), class: 'w-[27rem] max-w-[27rem]' },
  { key: 'route', label: t('admin.promptAudit.cyber.columns.route'), class: 'min-w-44' },
  { key: 'confirmations', label: t('admin.promptAudit.cyber.columns.confirmations'), class: 'min-w-36' },
  { key: 'last_confirmed', label: t('admin.promptAudit.cyber.columns.lastConfirmed'), class: 'min-w-48' },
  { key: 'actions', label: t('admin.promptAudit.common.actions'), class: 'min-w-48 text-right' },
])
const cyberConfigurableColumns = computed(() => cyberColumns.value.filter((column) => !['event', 'actions'].includes(column.key)))
const visibleCyberColumns = computed(() => cyberColumns.value.filter((column) => !hiddenCyberColumns.value.includes(column.key) || ['event', 'actions'].includes(column.key)))
const hasListFilters = computed(() => groupFilter.value !== '' || accountFilter.value !== '')
type RuleDisplayStatus = 'active' | 'disabled'
type NormalizedRuleStatus = RuleDisplayStatus | 'deleted'
const ruleTabs: RuleDisplayStatus[] = ['active', 'disabled']
const ruleStatus = ref<RuleDisplayStatus>('active')
const allRules = computed(() => page.rules ?? page.active_rules)
const activeRuleCount = computed(() => allRules.value.filter((rule) => normalizedRuleStatus(rule) === 'active').length)
const ruleCounts = computed<Record<RuleDisplayStatus, number>>(() => ({
  active: allRules.value.filter((rule) => normalizedRuleStatus(rule) === 'active').length,
  disabled: allRules.value.filter((rule) => normalizedRuleStatus(rule) === 'disabled').length,
}))
const visibleRules = computed(() => allRules.value.filter((rule) => normalizedRuleStatus(rule) === ruleStatus.value))
const showDetail = ref(false)
const showReview = ref(false)
const pendingRuleRestore = ref<CyberPolicyRule | null>(null)
const pendingRuleDelete = ref<CyberPolicyRule | null>(null)
const restoreConfirmMessage = computed(() => pendingRuleRestore.value && isRecoveredCandidate(pendingRuleRestore.value)
  ? t('admin.promptAudit.cyber.rules.restoreRecoveredConfirmMessage', { id: pendingRuleRestore.value.id })
  : t('admin.promptAudit.cyber.rules.restoreConfirmMessage', { id: pendingRuleRestore.value?.id || '' }))
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
    const filter: CyberFeedbackListFilter = {}
    if (typeof groupFilter.value === 'number' && groupFilter.value >= 0) filter.group_id = groupFilter.value
    if (typeof accountFilter.value === 'number' && accountFilter.value > 0) filter.account_id = accountFilter.value
    const result = Object.keys(filter).length
      ? await promptAuditAPI.listCyberEvents(status.value, page.page, page.page_size, filter)
      : await promptAuditAPI.listCyberEvents(status.value, page.page, page.page_size)
    Object.assign(page, result)
    await resolveDeepLink()
  } catch (errorValue) {
    error.value = operationError(errorValue, 'admin.promptAudit.cyber.errors.load')
  } finally {
    loading.value = false
  }
}

function applyListFilters() {
  page.page = 1
  void loadPage()
}

function resetListFilters() {
  groupFilter.value = ''
  accountFilter.value = ''
  applyListFilters()
}

function isCyberColumnVisible(key: string): boolean {
  return !hiddenCyberColumns.value.includes(key) || ['event', 'actions'].includes(key)
}

function toggleCyberColumn(key: string) {
  if (['event', 'actions'].includes(key)) return
  hiddenCyberColumns.value = hiddenCyberColumns.value.includes(key)
    ? hiddenCyberColumns.value.filter((item) => item !== key)
    : [...hiddenCyberColumns.value, key]
  try { localStorage.setItem('prompt-audit-cyber-hidden-columns', JSON.stringify(hiddenCyberColumns.value)) } catch { /* storage is optional */ }
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

function cyberRowClass(event: CyberFeedbackEvent): string {
  return props.initialEventId === event.id
    ? 'cyber-highlighted-row bg-primary-50/60 dark:bg-primary-950/20'
    : ''
}

function openEvent(event: CyberFeedbackEvent) {
  void openEventByID(event.id, event, 'detail')
}

function openReview(event: CyberFeedbackEvent) {
  void openEventByID(event.id, event, 'review')
}

async function openEventByID(eventID: number, fallback: CyberFeedbackEvent | null, mode: 'detail' | 'review' = 'detail') {
  const requestSequence = ++detailRequestSequence
  selected.value = fallback
  showDetail.value = mode === 'detail'
  showReview.value = mode === 'review'
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
  showDetail.value = false
  showReview.value = false
  selected.value = null
  evidence.value = null
  detailLoading.value = false
  evidenceError.value = ''
  ruleText.value = ''
  rejectReason.value = ''
}

function switchToReview() {
  if (!selected.value || selected.value.status !== 'pending') return
  showDetail.value = false
  showReview.value = true
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
    if (refreshed) await openEventByID(refreshed.id, refreshed, 'review')
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

function requestRestoreRule(rule: CyberPolicyRule) {
  pendingRuleRestore.value = rule
}

async function confirmRestoreRule() {
  const rule = pendingRuleRestore.value
  if (!rule || mutating.value) return
  pendingRuleRestore.value = null
  mutating.value = true
  try {
    const result = await promptAuditAPI.restoreCyberRule(rule.id, page.config_version)
    await loadPage()
    appStore.showSuccess(t('admin.promptAudit.cyber.messages.restored', { version: result.config_version ?? page.config_version }))
  } catch (errorValue) {
    await handleMutationError(errorValue, 'admin.promptAudit.cyber.errors.restore')
  } finally {
    mutating.value = false
  }
}

async function confirmDeleteRule() {
  const rule = pendingRuleDelete.value
  if (!rule || mutating.value) return
  pendingRuleDelete.value = null
  mutating.value = true
  try {
    await promptAuditAPI.deleteCyberRule(rule.id, page.config_version)
    await loadPage()
    appStore.showSuccess(t('admin.promptAudit.cyber.messages.deleted'))
  } catch (errorValue) {
    await handleMutationError(errorValue, 'admin.promptAudit.cyber.errors.delete')
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

interface DetailRow { label: string; value: string }
interface DetailGroup { title: string; rows: DetailRow[] }

function detailGroups(event: CyberFeedbackDetail, source: CyberFeedbackEvidence | null): DetailGroup[] {
  return [
    {
      title: t('admin.promptAudit.cyber.metadataGroups.identity'),
      rows: [
        { label: t('admin.promptAudit.cyber.fields.userId'), value: displayID(source?.user_id) },
        { label: t('admin.promptAudit.cyber.fields.username'), value: source?.username || '—' },
        { label: t('admin.promptAudit.cyber.fields.userEmail'), value: source?.user_email || '—' },
        { label: t('admin.promptAudit.cyber.fields.apiKeyId'), value: displayID(source?.api_key_id) },
        { label: t('admin.promptAudit.cyber.fields.apiKeyName'), value: source?.api_key_name || '—' },
        { label: t('admin.promptAudit.cyber.fields.apiKeyPrefix'), value: source?.api_key_prefix || '—' },
        { label: t('admin.promptAudit.cyber.fields.group'), value: namedID(source?.group_id ?? event.group_id, source?.group_name) },
        { label: t('admin.promptAudit.cyber.fields.identitySource'), value: identitySourceLabel(source?.identity_source) },
      ],
    },
    {
      title: t('admin.promptAudit.cyber.metadataGroups.accounts'),
      rows: [
        { label: t('admin.promptAudit.cyber.fields.selectedAccount'), value: namedID(source?.selected_account_id ?? event.account_id, source?.selected_account_name || event.account_name) },
        { label: t('admin.promptAudit.cyber.fields.credentialAccount'), value: namedID(source?.credential_account_id, source?.credential_account_name) },
        { label: t('admin.promptAudit.cyber.fields.credentialAccountEmail'), value: sourcedEmail(source) },
        { label: t('admin.promptAudit.cyber.fields.adminAlert'), value: event.admin_alert_status || '—' },
      ],
    },
    {
      title: t('admin.promptAudit.cyber.metadataGroups.request'),
      rows: [
        { label: t('admin.promptAudit.cyber.fields.requestId'), value: event.request_id || '—' },
        { label: t('admin.promptAudit.cyber.fields.clientRequestId'), value: source?.client_request_id || '—' },
        { label: t('admin.promptAudit.cyber.fields.clientIp'), value: source?.client_ip || '—' },
        { label: t('admin.promptAudit.cyber.fields.userAgent'), value: source?.user_agent || '—' },
        { label: t('admin.promptAudit.cyber.fields.model'), value: event.model || '—' },
        { label: t('admin.promptAudit.cyber.fields.endpoint'), value: event.endpoint || '—' },
        { label: t('admin.promptAudit.cyber.fields.protocol'), value: event.protocol || '—' },
        { label: t('admin.promptAudit.cyber.fields.stage'), value: `${event.stage || '—'} · ${event.transport || '—'}` },
      ],
    },
    {
      title: t('admin.promptAudit.cyber.metadataGroups.result'),
      rows: [
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
      ],
    },
  ]
}

function normalizedRuleStatus(rule: CyberPolicyRule): NormalizedRuleStatus {
  if (rule.status === 'active') return 'active'
  if (rule.status === 'deleted') return 'deleted'
  return 'disabled'
}

function isRecoveredCandidate(rule: CyberPolicyRule): boolean {
  return rule.recovered_candidate === true
    || rule.rule_text_source === 'recovered_candidate'
}

function canRestoreRule(rule: CyberPolicyRule): boolean {
  if (normalizedRuleStatus(rule) !== 'disabled' || !rule.rule_text.trim()) return false
  return rule.rule_text_source !== 'unavailable'
}

function ruleStatusClass(rule: CyberPolicyRule): string {
  const value = normalizedRuleStatus(rule)
  if (value === 'active') return 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-300'
  if (value === 'deleted') return 'bg-red-50 text-red-700 dark:bg-red-950/30 dark:text-red-300'
  return 'bg-gray-100 text-gray-700 dark:bg-dark-700 dark:text-gray-300'
}

function displayID(value: number | null | undefined): string {
  return value == null || value <= 0 ? '—' : String(value)
}

function groupLabel(value: number | null | undefined): string {
  if (value === 0) return t('admin.promptAudit.groups.unassigned')
  const group = groupOptions.value.find((item) => item.id === value)
  if (group) return `${group.name} (#${group.id})`
  return displayID(value) === '—' ? '—' : `#${displayID(value)}`
}

function accountLabel(value: number | null | undefined): string {
  const account = accountOptions.value.find((item) => item.id === value)
  if (account) return `${account.name || `#${account.id}`} (#${account.id})`
  return displayID(value) === '—' ? '—' : `#${displayID(value)}`
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

onMounted(() => {
  try {
    const raw = localStorage.getItem('prompt-audit-cyber-hidden-columns')
    const parsed = raw ? JSON.parse(raw) : []
    if (Array.isArray(parsed)) {
      hiddenCyberColumns.value = parsed.filter((item): item is string => typeof item === 'string' && cyberConfigurableColumns.value.some((column) => column.key === item))
    }
  } catch { hiddenCyberColumns.value = [] }
  void loadPage()
})
</script>

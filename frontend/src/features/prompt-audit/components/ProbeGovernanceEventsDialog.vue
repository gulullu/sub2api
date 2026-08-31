<template>
  <BaseDialog
    :show="show"
    :title="t('admin.promptAudit.probeGovernance.events.title', { name: group?.group_name || '' })"
    width="full"
    :close-on-click-outside="false"
    @close="close"
  >
    <div v-if="group" class="space-y-4" data-test="probe-governance-events-dialog">
      <form class="rounded-xl border border-gray-200 bg-gray-50/60 p-4 dark:border-dark-700 dark:bg-dark-900/30" @submit.prevent="search">
        <div class="flex flex-wrap items-end justify-between gap-4">
          <div class="flex flex-1 flex-wrap items-end gap-4">
            <div class="w-full sm:w-auto sm:min-w-[190px]">
              <label class="input-label">{{ t('admin.promptAudit.probeGovernance.events.timeRange') }}</label>
              <Select v-model="timeRange" :options="timeRangeOptions" :aria-label="t('admin.promptAudit.probeGovernance.events.timeRange')" @change="applyTimeRange" />
            </div>
            <div class="w-full sm:w-auto sm:min-w-[190px]">
              <label class="input-label">{{ t('admin.promptAudit.probeGovernance.events.verdict') }}</label>
              <Select v-model="filters.verdict" :options="verdictOptions" :aria-label="t('admin.promptAudit.probeGovernance.events.verdict')" />
            </div>
            <div class="w-full sm:w-auto sm:min-w-[240px]">
              <label class="input-label">{{ t('admin.promptAudit.probeGovernance.events.userFilter') }}</label>
              <Select
                :model-value="filters.user_id ?? null"
                :options="userOptions"
                :placeholder="t('admin.promptAudit.probeGovernance.events.allUsers')"
                :search-placeholder="t('admin.usage.searchUserPlaceholder')"
                remote
                clearable
                :loading="usersLoading"
                :aria-label="t('admin.promptAudit.probeGovernance.events.userFilter')"
                @search="searchUsers"
                @change="selectUser"
              />
            </div>
            <div class="w-full sm:w-auto sm:min-w-[240px]">
              <label class="input-label">{{ t('admin.promptAudit.probeGovernance.events.apiKeyFilter') }}</label>
              <Select
                :model-value="filters.api_key_id ?? null"
                :options="apiKeyOptions"
                :placeholder="t('admin.promptAudit.probeGovernance.events.allApiKeys')"
                :search-placeholder="t('admin.usage.searchApiKeyPlaceholder')"
                remote
                clearable
                :loading="apiKeysLoading"
                :aria-label="t('admin.promptAudit.probeGovernance.events.apiKeyFilter')"
                @search="searchAPIKeys"
                @change="selectAPIKey"
              />
            </div>
            <Input v-model="filters.model" class="w-full sm:w-auto sm:min-w-[220px]" :label="t('admin.promptAudit.probeGovernance.events.model')" />
            <div class="w-full sm:w-auto sm:min-w-[200px]">
              <label class="input-label">{{ t('admin.promptAudit.probeGovernance.events.protocol') }}</label>
              <Select v-model="filters.protocol" :options="protocolOptions" searchable :aria-label="t('admin.promptAudit.probeGovernance.events.protocol')" />
            </div>
            <template v-if="timeRange === 'custom'">
              <Input v-model="filters.start_at" type="datetime-local" class="w-full sm:w-auto sm:min-w-[220px]" :label="t('admin.promptAudit.probeGovernance.events.startAt')" />
              <Input v-model="filters.end_at" type="datetime-local" class="w-full sm:w-auto sm:min-w-[220px]" :label="t('admin.promptAudit.probeGovernance.events.endAt')" />
            </template>
          </div>
          <div class="flex w-full flex-wrap items-center justify-end gap-3 sm:w-auto">
            <button type="submit" class="btn btn-primary">{{ t('common.search') }}</button>
            <button type="button" class="btn btn-secondary" data-test="probe-governance-events-reset" @click="reset()">{{ t('common.reset') }}</button>
            <ColumnSettingsDropdown
              :label="t('admin.promptAudit.probeGovernance.columns')"
              :columns="configurableColumns"
              :is-visible="isColumnVisible"
              button-test="probe-governance-event-column-settings"
              menu-test="probe-governance-event-column-menu"
              @toggle="toggleColumn"
            />
          </div>
        </div>
      </form>

      <div v-if="error" role="alert" class="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">{{ error }}</div>
      <div class="overflow-hidden rounded-xl border border-gray-200 bg-white dark:border-dark-700 dark:bg-dark-900">
        <DataTable
          :columns="visibleColumns"
          :data="page.items"
          :loading="loading"
          row-key="id"
          :sticky-first-column="true"
          :sticky-actions-column="true"
          data-test="probe-governance-events-table"
        >
          <template #cell-family="{ row }">
            <div class="min-w-0 max-w-64">
              <p class="truncate font-mono text-xs font-semibold text-gray-900 dark:text-white" :title="row.family_fingerprint">{{ abbreviate(row.family_fingerprint) }}</p>
              <p class="mt-1 line-clamp-2 whitespace-normal break-words text-xs text-gray-500 dark:text-dark-400">{{ row.family_preview || classificationLabel(row.classification) }}</p>
            </div>
          </template>
          <template #cell-seen="{ row }">
            <div class="whitespace-nowrap text-xs text-gray-700 dark:text-dark-200">
              <p>{{ formatDate(row.first_seen_at) }}</p>
              <p class="mt-1 text-gray-500 dark:text-dark-400">{{ formatDate(row.last_seen_at) }}</p>
            </div>
          </template>
          <template #cell-user="{ row }">
            <IdentityCell :name="row.user_email" :id="row.user_id" :fallback="t('admin.promptAudit.probeGovernance.events.unknownUser')" />
          </template>
          <template #cell-api_key="{ row }">
            <IdentityCell :name="row.api_key_name" :id="row.api_key_id" :fallback="t('admin.promptAudit.probeGovernance.events.unnamedApiKey')" />
          </template>
          <template #cell-model="{ row }">
            <div class="min-w-0 max-w-56">
              <p class="truncate text-sm font-medium text-gray-900 dark:text-white" :title="row.model">{{ row.model || '—' }}</p>
              <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ protocolLabel(row.protocol) }} · {{ row.stream ? t('admin.promptAudit.probeGovernance.events.stream') : t('admin.promptAudit.probeGovernance.events.nonStream') }}</p>
            </div>
          </template>
          <template #cell-verdict="{ row }">
            <span class="badge" :class="verdictClass(row.verdict)">{{ verdictLabel(row.verdict) }}</span>
          </template>
          <template #cell-repeats="{ row }">
            <span class="tabular-nums text-sm text-gray-700 dark:text-dark-200">{{ formatNumber(row.total_count) }}</span>
          </template>
          <template #cell-handling="{ row }">
            <div class="min-w-0 max-w-56 text-xs">
              <p class="font-medium text-gray-800 dark:text-dark-100">{{ handlingLabel(row.handling) }}</p>
              <p class="mt-1 text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.probeGovernance.events.savedSummary', { audit: formatNumber(row.audit_skipped_count), upstream: formatNumber(row.upstream_skipped_count) }) }}</p>
            </div>
          </template>
          <template #cell-actions="{ row }">
            <div class="flex justify-end">
              <button type="button" class="btn btn-primary btn-sm" @click.stop="openDetail(row.id)">{{ t('common.view') }}</button>
            </div>
          </template>
          <template #empty>
            <div class="px-4 py-10 text-center text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.probeGovernance.events.empty') }}</div>
          </template>
        </DataTable>
        <Pagination
          :total="page.total"
          :page="page.page"
          :page-size="page.page_size"
          @update:page="changePage"
          @update:page-size="changePageSize"
        />
      </div>
    </div>

    <template #footer>
      <button type="button" class="btn btn-primary" @click="close">{{ t('common.close') }}</button>
    </template>
  </BaseDialog>

  <ProbeGovernanceEventDetailDialog
    :show="detailOpen"
    :event="detail"
    :loading="detailLoading"
    :clearing-busy="clearing"
    :prompt-evidence="detailEvidence"
    :evidence-loading="detailEvidenceLoading"
    :evidence-error="detailEvidenceError"
    @close="closeDetail"
    @clear="clearClassification"
    @add-exemption="forwardExemption"
    @view-audit-event="forwardAuditEvent"
  />
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import type { SimpleApiKey, SimpleUser } from '@/api/admin/usage'
import BaseDialog from '@/components/common/BaseDialog.vue'
import DataTable from '@/components/common/DataTable.vue'
import Input from '@/components/common/Input.vue'
import Pagination from '@/components/common/Pagination.vue'
import Select, { type SelectOption } from '@/components/common/Select.vue'
import type { Column } from '@/components/common/types'
import { useAppStore } from '@/stores/app'
import { extractApiErrorMessage } from '@/utils/apiError'
import promptAuditAPI from '../api'
import type { ProbeGovernanceEvent, ProbeGovernanceEventDetail, ProbeGovernanceEventEvidence, ProbeGovernanceEventFilters, ProbeGovernancePolicy } from '../types'
import ColumnSettingsDropdown from './ColumnSettingsDropdown.vue'
import ProbeGovernanceEventDetailDialog from './ProbeGovernanceEventDetailDialog.vue'

const props = defineProps<{ show: boolean; group: ProbeGovernancePolicy | null }>()
const emit = defineEmits<{
  (event: 'close'): void
  (event: 'add-exemption', value: ProbeGovernanceEventDetail): void
  (event: 'view-audit-event', id: number): void
}>()
const { t, locale } = useI18n()
const appStore = useAppStore()

type TimeRange = '24h' | '7d' | '30d' | 'all' | 'custom'
const timeRange = ref<TimeRange>('24h')
const filters = reactive<ProbeGovernanceEventFilters>(emptyFilters())
const page = reactive({ items: [] as ProbeGovernanceEvent[], total: 0, page: 1, page_size: 20, pages: 0 })
const loading = ref(false)
const error = ref('')
const hiddenColumns = ref<string[]>([])
const userResults = ref<SimpleUser[]>([])
const apiKeyResults = ref<SimpleApiKey[]>([])
const pinnedUser = ref<SimpleUser | null>(null)
const pinnedAPIKey = ref<SimpleApiKey | null>(null)
const usersLoading = ref(false)
const apiKeysLoading = ref(false)
const detailOpen = ref(false)
const detailLoading = ref(false)
const detail = ref<ProbeGovernanceEventDetail | null>(null)
const detailEvidence = ref<ProbeGovernanceEventEvidence | null>(null)
const detailEvidenceLoading = ref(false)
const detailEvidenceError = ref('')
const clearing = ref(false)
let userSearchSequence = 0
let apiKeySearchSequence = 0
let eventLoadSequence = 0
let detailLoadSequence = 0

const timeRangeOptions = computed<SelectOption[]>(() => [
  { value: '24h', label: t('admin.promptAudit.probeGovernance.events.last24Hours') },
  { value: '7d', label: t('admin.promptAudit.probeGovernance.events.last7Days') },
  { value: '30d', label: t('admin.promptAudit.probeGovernance.events.last30Days') },
  { value: 'all', label: t('admin.promptAudit.probeGovernance.events.allTime') },
  { value: 'custom', label: t('admin.promptAudit.probeGovernance.events.customRange') },
])
const verdictOptions = computed<SelectOption[]>(() => [
  { value: '', label: t('common.all') },
  { value: 'healthy', label: t('admin.promptAudit.probeGovernance.verdicts.healthy') },
  { value: 'confirmed_violation', label: t('admin.promptAudit.probeGovernance.verdicts.confirmed_violation') },
  { value: 'unknown', label: t('admin.promptAudit.probeGovernance.verdicts.unknown') },
])
const protocolOptions = computed<SelectOption[]>(() => [
  { value: '', label: t('common.all') },
  { value: 'openai_responses', label: t('admin.promptAudit.probeGovernance.protocols.openai_responses') },
  { value: 'openai_chat_completions', label: t('admin.promptAudit.probeGovernance.protocols.openai_chat_completions') },
  { value: 'anthropic_messages', label: t('admin.promptAudit.probeGovernance.protocols.anthropic_messages') },
])
const userOptions = computed<SelectOption[]>(() => withSelectedFallback(
  withPinned(userResults.value.map(userOption), pinnedUser.value ? userOption(pinnedUser.value) : null),
  filters.user_id,
))
const apiKeyOptions = computed<SelectOption[]>(() => withSelectedFallback(
  withPinned(apiKeyResults.value.map(apiKeyOption), pinnedAPIKey.value ? apiKeyOption(pinnedAPIKey.value) : null),
  filters.api_key_id,
))
const columns = computed<Column[]>(() => [
  { key: 'family', label: t('admin.promptAudit.probeGovernance.events.family'), class: 'min-w-64 max-w-64' },
  { key: 'seen', label: t('admin.promptAudit.probeGovernance.events.firstLast'), class: 'min-w-44' },
  { key: 'user', label: t('admin.promptAudit.probeGovernance.events.user'), class: 'min-w-56' },
  { key: 'api_key', label: t('admin.promptAudit.probeGovernance.events.apiKey'), class: 'min-w-48' },
  { key: 'model', label: t('admin.promptAudit.probeGovernance.events.modelProtocol'), class: 'min-w-56' },
  { key: 'verdict', label: t('admin.promptAudit.probeGovernance.events.verdict'), class: 'min-w-36' },
  { key: 'repeats', label: t('admin.promptAudit.probeGovernance.events.repeats'), class: 'min-w-28' },
  { key: 'handling', label: t('admin.promptAudit.probeGovernance.events.handling'), class: 'min-w-56' },
  { key: 'actions', label: t('admin.promptAudit.common.actions'), class: 'min-w-28 text-right' },
])
const configurableColumns = computed(() => columns.value.filter((column) => !['family', 'actions'].includes(column.key)))
const visibleColumns = computed(() => columns.value.filter((column) => !hiddenColumns.value.includes(column.key) || ['family', 'actions'].includes(column.key)))

watch(() => [props.show, props.group?.group_id] as const, ([show]) => {
  // A detail response contains administrator-only raw prompt evidence. Any
  // dialog/group transition invalidates pending reads and releases that state,
  // including a live switch from one valid group to another.
  detailLoadSequence += 1
  detailLoading.value = false
  detailOpen.value = false
  detail.value = null
  detailEvidence.value = null
  detailEvidenceLoading.value = false
  detailEvidenceError.value = ''
  if (!show || !props.group) {
    eventLoadSequence += 1
    loading.value = false
    return
  }
  reset(false)
  void load()
})
onMounted(() => {
  try {
    const parsed = JSON.parse(localStorage.getItem('prompt-audit-probe-event-hidden-columns') || '[]')
    if (Array.isArray(parsed)) hiddenColumns.value = parsed.filter((value): value is string => typeof value === 'string')
  } catch { /* optional */ }
})

function emptyFilters(): ProbeGovernanceEventFilters {
  return { verdict: '', user_email: '', api_key_name: '', model: '', protocol: '', start_at: '', end_at: '' }
}
function applyTimeRange() {
  if (timeRange.value === 'custom') return
  filters.end_at = ''
  if (timeRange.value === 'all') { filters.start_at = ''; return }
  const hours = timeRange.value === '24h' ? 24 : timeRange.value === '7d' ? 24 * 7 : 24 * 30
  filters.start_at = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString()
}
function serializedFilters(): ProbeGovernanceEventFilters {
  const result = { ...filters }
  if (result.user_id) result.user_email = ''
  if (result.api_key_id) result.api_key_name = ''
  for (const key of ['start_at', 'end_at'] as const) {
    const value = result[key]
    if (value && !value.endsWith('Z')) {
      const parsed = new Date(value)
      if (!Number.isNaN(parsed.getTime())) result[key] = parsed.toISOString()
    }
  }
  return result
}
async function load() {
  const group = props.group
  if (!group) return
  const sequence = ++eventLoadSequence
  const requestFilters = serializedFilters()
  const requestPage = page.page
  const requestPageSize = page.page_size
  loading.value = true
  error.value = ''
  try {
    const result = await promptAuditAPI.listProbeGovernanceEvents(group.group_id, requestFilters, requestPage, requestPageSize)
    if (sequence !== eventLoadSequence) return
    Object.assign(page, result)
  } catch (caught) {
    if (sequence !== eventLoadSequence) return
    error.value = extractApiErrorMessage(caught, t('admin.promptAudit.probeGovernance.errors.loadEvents'))
  } finally {
    if (sequence === eventLoadSequence) loading.value = false
  }
}
function search() { page.page = 1; void load() }
function reset(loadAfter = true) {
  userSearchSequence += 1
  apiKeySearchSequence += 1
  usersLoading.value = false
  apiKeysLoading.value = false
  Object.assign(filters, emptyFilters())
  timeRange.value = '24h'
  applyTimeRange()
  pinnedUser.value = null
  pinnedAPIKey.value = null
  userResults.value = []
  apiKeyResults.value = []
  page.page = 1
  if (loadAfter) void load()
}
function close() {
  if (!loading.value) {
    eventLoadSequence += 1
    detailLoadSequence += 1
    detailLoading.value = false
    detailOpen.value = false
    detail.value = null
    detailEvidence.value = null
    detailEvidenceLoading.value = false
    detailEvidenceError.value = ''
    emit('close')
  }
}
function changePage(value: number) { page.page = value; void load() }
function changePageSize(value: number) { page.page_size = value; page.page = 1; void load() }
function isColumnVisible(key: string): boolean { return !hiddenColumns.value.includes(key) || ['family', 'actions'].includes(key) }
function toggleColumn(key: string) {
  if (['family', 'actions'].includes(key)) return
  hiddenColumns.value = hiddenColumns.value.includes(key) ? hiddenColumns.value.filter((value) => value !== key) : [...hiddenColumns.value, key]
  try { localStorage.setItem('prompt-audit-probe-event-hidden-columns', JSON.stringify(hiddenColumns.value)) } catch { /* optional */ }
}
async function searchUsers(query: string) {
  const sequence = ++userSearchSequence
  const keyword = query.trim()
  if (!keyword) { userResults.value = []; usersLoading.value = false; return }
  usersLoading.value = true
  try {
    const result = await adminAPI.usage.searchUsers(keyword)
    if (sequence === userSearchSequence) userResults.value = result
  } catch { if (sequence === userSearchSequence) userResults.value = [] }
  finally { if (sequence === userSearchSequence) usersLoading.value = false }
}
async function searchAPIKeys(query: string) {
  const sequence = ++apiKeySearchSequence
  const keyword = query.trim()
  if (!keyword) { apiKeyResults.value = []; apiKeysLoading.value = false; return }
  apiKeysLoading.value = true
  try {
    const result = await adminAPI.usage.searchApiKeys(filters.user_id, keyword)
    if (sequence === apiKeySearchSequence) apiKeyResults.value = result
  } catch { if (sequence === apiKeySearchSequence) apiKeyResults.value = [] }
  finally { if (sequence === apiKeySearchSequence) apiKeysLoading.value = false }
}
function selectUser(value: string | number | boolean | null, option: SelectOption | null) {
  apiKeySearchSequence += 1
  apiKeysLoading.value = false
  filters.user_id = typeof value === 'number' ? value : undefined
  filters.user_email = ''
  pinnedUser.value = filters.user_id ? { id: filters.user_id, email: typeof option?.email === 'string' ? option.email : '', deleted: Boolean(option?.deleted) } : null
  filters.api_key_id = undefined
  filters.api_key_name = ''
  pinnedAPIKey.value = null
  apiKeyResults.value = []
}
function selectAPIKey(value: string | number | boolean | null, option: SelectOption | null) {
  filters.api_key_id = typeof value === 'number' ? value : undefined
  filters.api_key_name = ''
  pinnedAPIKey.value = filters.api_key_id ? { id: filters.api_key_id, name: typeof option?.name === 'string' ? option.name : '', user_id: Number(option?.userID || filters.user_id || 0) } : null
}
function userOption(user: SimpleUser): SelectOption { return { value: user.id, label: `${user.email} · #${user.id}`, email: user.email, deleted: user.deleted } }
function apiKeyOption(key: SimpleApiKey): SelectOption { return { value: key.id, label: `${key.name.trim() || t('admin.promptAudit.probeGovernance.events.unnamedApiKey')} · #${key.id}`, name: key.name, userID: key.user_id } }
function withPinned(options: SelectOption[], pinned: SelectOption | null): SelectOption[] { return !pinned || options.some((item) => item.value === pinned.value) ? options : [pinned, ...options] }
function withSelectedFallback(options: SelectOption[], selected?: number): SelectOption[] { return !selected || options.some((item) => item.value === selected) ? options : [...options, { value: selected, label: `#${selected}` }] }
async function openDetail(id: number) {
  const sequence = ++detailLoadSequence
  detailOpen.value = true
  detailLoading.value = true
  detail.value = null
  detailEvidence.value = null
  detailEvidenceLoading.value = true
  detailEvidenceError.value = ''
  try {
    const [result, evidenceResult] = await Promise.all([
      promptAuditAPI.getProbeGovernanceEvent(id),
      promptAuditAPI.getProbeGovernanceEventEvidence(id).then(
        (value) => ({ ok: true as const, value }),
        (errorValue: unknown) => ({ ok: false as const, errorValue }),
      ),
    ])
    if (sequence !== detailLoadSequence) return
    detail.value = result
    if (evidenceResult.ok) detailEvidence.value = evidenceResult.value
    else detailEvidenceError.value = extractApiErrorMessage(evidenceResult.errorValue, t('admin.promptAudit.probeGovernance.errors.loadEvidence'))
  } catch (caught) {
    if (sequence !== detailLoadSequence) return
    appStore.showError(extractApiErrorMessage(caught, t('admin.promptAudit.probeGovernance.errors.loadDetail')))
    detailOpen.value = false
  } finally {
    if (sequence === detailLoadSequence) {
      detailLoading.value = false
      detailEvidenceLoading.value = false
    }
  }
}
function closeDetail() {
  if (clearing.value) return
  detailLoadSequence += 1
  detailLoading.value = false
  detailOpen.value = false
  detail.value = null
  detailEvidence.value = null
  detailEvidenceLoading.value = false
  detailEvidenceError.value = ''
}
function forwardAuditEvent(id: number) {
  detailLoadSequence += 1
  detailLoading.value = false
  detailOpen.value = false
  detail.value = null
  detailEvidence.value = null
  detailEvidenceLoading.value = false
  detailEvidenceError.value = ''
  emit('close')
  emit('view-audit-event', id)
}
function forwardExemption(event: ProbeGovernanceEventDetail) {
  detailLoadSequence += 1
  detailLoading.value = false
  detailOpen.value = false
  detail.value = null
  detailEvidence.value = null
  detailEvidenceLoading.value = false
  detailEvidenceError.value = ''
  emit('close')
  emit('add-exemption', event)
}
async function clearClassification(id: number, reason: string) {
  clearing.value = true
  try {
    await promptAuditAPI.clearProbeGovernanceEvent(id, reason)
    appStore.showSuccess(t('admin.promptAudit.probeGovernance.messages.classificationCleared'))
    detailLoadSequence += 1
    detailLoading.value = false
    detailOpen.value = false
    detail.value = null
    detailEvidence.value = null
    detailEvidenceLoading.value = false
    detailEvidenceError.value = ''
    await load()
  } catch (caught) { appStore.showError(extractApiErrorMessage(caught, t('admin.promptAudit.probeGovernance.errors.clearClassification'))) }
  finally { clearing.value = false }
}
function formatDate(value?: string): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(locale.value.startsWith('zh') ? 'zh-CN' : 'en-US', { dateStyle: 'short', timeStyle: 'short' }).format(date)
}
function formatNumber(value: number): string { return Number(value || 0).toLocaleString() }
function abbreviate(value: string): string { return value.length > 20 ? `${value.slice(0, 20)}…` : value || '—' }
function protocolLabel(value: string): string { const key = `admin.promptAudit.probeGovernance.protocols.${value}`; const result = t(key); return result === key ? value || '—' : result }
function classificationLabel(value: string): string { const key = `admin.promptAudit.probeGovernance.classifications.${value}`; const result = t(key); return result === key ? value || '—' : result }
function verdictLabel(value: string): string { const key = `admin.promptAudit.probeGovernance.verdicts.${value}`; const result = t(key); return result === key ? value || '—' : result }
function handlingLabel(value: string): string { const key = `admin.promptAudit.probeGovernance.handling.${value}`; const result = t(key); return result === key ? value || '—' : result }
function verdictClass(value: string): string { return value === 'healthy' ? 'badge-success' : value === 'confirmed_violation' ? 'badge-danger' : 'badge-gray' }

const IdentityCell = defineComponent({
  props: { name: { type: String, default: '' }, id: { type: Number, default: null }, fallback: { type: String, required: true } },
  setup(componentProps) {
    return () => h('div', { class: 'min-w-0 max-w-56' }, [
      h('p', { class: 'truncate text-sm text-gray-900 dark:text-white', title: componentProps.name || undefined }, componentProps.name || componentProps.fallback),
      componentProps.id ? h('p', { class: 'mt-1 font-mono text-xs text-gray-500 dark:text-dark-400' }, `#${componentProps.id}`) : null,
    ])
  },
})
</script>

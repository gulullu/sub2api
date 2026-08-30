<template>
  <section aria-labelledby="probe-governance-title" class="border-b border-gray-200 py-6 dark:border-dark-700/60" data-test="probe-governance-workspace">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="probe-governance-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.probeGovernance.title') }}</h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.probeGovernance.description') }}</p>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <span class="rounded-full bg-primary-50 px-2.5 py-1 text-xs font-semibold text-primary-700 dark:bg-primary-950/40 dark:text-primary-300">
          {{ t('admin.promptAudit.probeGovernance.summary', { count: scopedRows.length }) }}
        </span>
        <button type="button" class="btn btn-secondary btn-sm" :disabled="loading" data-test="probe-governance-refresh" @click="loadPolicies">{{ t('common.refresh') }}</button>
      </div>
    </div>

    <form class="mt-5 flex flex-wrap items-end justify-between gap-4" @submit.prevent="applyFilters">
      <div class="flex flex-1 flex-wrap items-end gap-4">
        <div class="w-full sm:w-auto sm:min-w-[240px]">
          <label class="input-label">{{ t('admin.promptAudit.probeGovernance.groupFilter') }}</label>
          <Select
            v-model="pendingGroupID"
            :options="groupOptions"
            :placeholder="t('admin.promptAudit.probeGovernance.allGroups')"
            :search-placeholder="t('admin.promptAudit.probeGovernance.searchGroups')"
            :aria-label="t('admin.promptAudit.probeGovernance.groupFilter')"
            searchable
            clearable
            data-test="probe-governance-group-filter"
          />
        </div>
        <div class="w-full sm:w-auto sm:min-w-[200px]">
          <label class="input-label">{{ t('admin.promptAudit.probeGovernance.statusFilter') }}</label>
          <Select v-model="pendingStatus" :options="statusOptions" :aria-label="t('admin.promptAudit.probeGovernance.statusFilter')" data-test="probe-governance-status-filter" />
        </div>
      </div>
      <div class="flex w-full flex-wrap items-center justify-end gap-3 sm:w-auto">
        <button type="submit" class="btn btn-primary">{{ t('common.search') }}</button>
        <button type="button" class="btn btn-secondary" data-test="probe-governance-filter-reset" @click="resetFilters">{{ t('common.reset') }}</button>
        <ColumnSettingsDropdown
          :label="t('admin.promptAudit.probeGovernance.columns')"
          :columns="configurableColumns"
          :is-visible="isColumnVisible"
          button-test="probe-governance-column-settings"
          menu-test="probe-governance-column-menu"
          @toggle="toggleColumn"
        />
      </div>
    </form>

    <div v-if="error" role="alert" class="mt-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">{{ error }}</div>
    <div v-if="loading || policiesReady" class="mt-4 overflow-hidden rounded-xl border border-gray-200 bg-white dark:border-dark-700/60 dark:bg-dark-900/20">
      <DataTable
        :columns="visibleColumns"
        :data="pagedRows"
        :loading="loading"
        row-key="group_id"
        :sticky-first-column="true"
        :sticky-actions-column="true"
        sort-storage-key="prompt-audit-probe-governance-sort-v1"
        default-sort-key="group_name"
        default-sort-order="asc"
        :server-side-sort="true"
        data-test="probe-governance-table"
        @sort="applySort"
      >
        <template #cell-group_name="{ row }">
          <div class="min-w-0 max-w-64">
            <p class="truncate font-semibold text-gray-900 dark:text-white" :title="row.group_name">{{ row.group_name }}</p>
            <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">#{{ row.group_id }}<span v-if="groupPlatform(row.group_id)"> · {{ groupPlatform(row.group_id) }}</span></p>
          </div>
        </template>
        <template #cell-enabled="{ row }"><span class="badge" :class="row.enabled ? 'badge-success' : 'badge-gray'">{{ row.enabled ? t('admin.promptAudit.probeGovernance.enabled') : t('admin.promptAudit.probeGovernance.disabled') }}</span></template>
        <template #cell-interval_seconds="{ row }"><span class="tabular-nums text-sm text-gray-700 dark:text-dark-200">{{ row.enabled ? formatInterval(row.interval_seconds) : '—' }}</span></template>
        <template #cell-allow_first_real_probe="{ row }"><span class="text-sm text-gray-700 dark:text-dark-200">{{ row.enabled ? (row.allow_first_real_probe ? t('common.yes') : t('common.no')) : '—' }}</span></template>
        <template #cell-local_responses_24h="{ row }"><MetricCell :value="row.local_responses_24h" /></template>
        <template #cell-skipped_audits_24h="{ row }"><MetricCell :value="row.skipped_audits_24h" /></template>
        <template #cell-skipped_upstream_24h="{ row }"><MetricCell :value="row.skipped_upstream_24h" /></template>
        <template #cell-last_probe_at="{ row }"><span class="whitespace-nowrap text-xs text-gray-600 dark:text-dark-300">{{ formatDate(row.last_probe_at) }}</span></template>
        <template #cell-actions="{ row }">
          <div class="flex flex-wrap items-center justify-end gap-1">
            <button type="button" class="btn btn-primary btn-sm" :disabled="!policiesWritable" @click.stop="openPolicy(row)">{{ t('common.edit') }}</button>
            <button type="button" class="btn btn-ghost btn-sm" :class="row.enabled ? 'text-amber-700 dark:text-amber-300' : 'text-emerald-700 dark:text-emerald-300'" :disabled="!policiesWritable || updatingGroupID === row.group_id" @click.stop="togglePolicy(row)">{{ row.enabled ? t('admin.promptAudit.probeGovernance.disableAction') : t('admin.promptAudit.probeGovernance.enableAction') }}</button>
            <button type="button" class="btn btn-ghost btn-sm" :disabled="!policiesWritable" @click.stop="openEvents(row)">{{ t('admin.promptAudit.probeGovernance.events.action') }}</button>
            <button type="button" class="btn btn-ghost btn-sm" :disabled="!policiesWritable" @click.stop="openExemptions(row)">{{ t('admin.promptAudit.probeGovernance.exemptions.action') }}</button>
          </div>
        </template>
        <template #empty><div class="px-4 py-10 text-center text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.probeGovernance.empty') }}</div></template>
      </DataTable>
      <Pagination
        :total="filteredRows.length"
        :page="currentPage"
        :page-size="pageSize"
        @update:page="currentPage = $event"
        @update:page-size="changePageSize"
      />
    </div>

    <ProbeGovernancePolicyDialog
      :show="Boolean(editingPolicy)"
      :policy="editingPolicy"
      :saving="savingPolicy"
      @close="editingPolicy = null"
      @save="savePolicy"
    />
    <ProbeGovernanceEventsDialog
      :show="Boolean(eventsGroup)"
      :group="eventsGroup"
      @close="eventsGroup = null"
      @add-exemption="openExemptionFromEvent"
      @view-audit-event="$emit('view-audit-event', $event)"
    />
    <ProbeGovernanceExemptionsDialog
      :show="Boolean(exemptionsGroup)"
      :group="exemptionsGroup"
      :prefill="exemptionPrefill"
      @close="closeExemptions"
    />
  </section>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import DataTable from '@/components/common/DataTable.vue'
import Pagination from '@/components/common/Pagination.vue'
import Select, { type SelectOption } from '@/components/common/Select.vue'
import type { Column } from '@/components/common/types'
import { useAppStore } from '@/stores/app'
import { extractApiErrorMessage } from '@/utils/apiError'
import promptAuditAPI from '../api'
import type {
  ProbeGovernanceEventDetail,
  ProbeGovernancePolicy,
  ProbeGovernancePolicyUpdate,
  ProbeGovernanceStatusFilter,
  PromptAuditDraft,
  PromptAuditGroup,
} from '../types'
import ColumnSettingsDropdown from './ColumnSettingsDropdown.vue'
import ProbeGovernanceEventsDialog from './ProbeGovernanceEventsDialog.vue'
import ProbeGovernanceExemptionsDialog from './ProbeGovernanceExemptionsDialog.vue'
import ProbeGovernancePolicyDialog from './ProbeGovernancePolicyDialog.vue'

const props = defineProps<{ draft: PromptAuditDraft; groups: PromptAuditGroup[] }>()
defineEmits<{ (event: 'view-audit-event', id: number): void }>()
const { t, locale } = useI18n()
const appStore = useAppStore()
const policies = ref<ProbeGovernancePolicy[]>([])
const loading = ref(false)
const error = ref('')
const policiesLoaded = ref(false)
const pendingGroupID = ref<number | null>(null)
const appliedGroupID = ref<number | null>(null)
const pendingStatus = ref<ProbeGovernanceStatusFilter>('')
const appliedStatus = ref<ProbeGovernanceStatusFilter>('')
const currentPage = ref(1)
const pageSize = ref(20)
const sortKey = ref<keyof ProbeGovernancePolicy>('group_name')
const sortOrder = ref<'asc' | 'desc'>('asc')
const hiddenColumns = ref<string[]>([])
const updatingGroupID = ref<number | null>(null)
const editingPolicy = ref<ProbeGovernancePolicy | null>(null)
const savingPolicy = ref(false)
const eventsGroup = ref<ProbeGovernancePolicy | null>(null)
const exemptionsGroup = ref<ProbeGovernancePolicy | null>(null)
const exemptionPrefill = ref<ProbeGovernanceEventDetail | null>(null)
let reloadAfterCurrent = false

const scopedGroups = computed(() => props.groups.filter((group) => isGroupInScope(group.id)).sort((left, right) => left.name.localeCompare(right.name, locale.value, { numeric: true, sensitivity: 'base' }) || left.id - right.id))
const policiesReady = computed(() => policiesLoaded.value && !error.value)
const policiesWritable = computed(() => policiesReady.value && !loading.value)
const scopedRows = computed<ProbeGovernancePolicy[]>(() => {
  if (!policiesReady.value) return []
  const policyMap = new Map(policies.value.map((policy) => [policy.group_id, policy]))
  return scopedGroups.value.map((group) => normalizePolicy(policyMap.get(group.id), group))
})
const groupOptions = computed<SelectOption[]>(() => scopedRows.value.map((row) => ({ value: row.group_id, label: `${row.group_name} · #${row.group_id}` })))
const statusOptions = computed<SelectOption[]>(() => [
  { value: '', label: t('common.all') },
  { value: 'enabled', label: t('admin.promptAudit.probeGovernance.enabled') },
  { value: 'disabled', label: t('admin.promptAudit.probeGovernance.disabled') },
])
const filteredRows = computed(() => scopedRows.value.filter((row) => {
  if (appliedGroupID.value !== null && row.group_id !== appliedGroupID.value) return false
  if (appliedStatus.value === 'enabled' && !row.enabled) return false
  if (appliedStatus.value === 'disabled' && row.enabled) return false
  return true
}))
const sortedRows = computed(() => [...filteredRows.value].sort((left, right) => {
  const comparison = compareValues(left[sortKey.value], right[sortKey.value])
  if (comparison !== 0) return sortOrder.value === 'asc' ? comparison : -comparison
  return left.group_name.localeCompare(right.group_name, locale.value, { numeric: true, sensitivity: 'base' }) || left.group_id - right.group_id
}))
const pagedRows = computed(() => {
  const maxPage = Math.max(1, Math.ceil(sortedRows.value.length / pageSize.value))
  const safePage = Math.min(currentPage.value, maxPage)
  const start = (safePage - 1) * pageSize.value
  return sortedRows.value.slice(start, start + pageSize.value)
})
const columns = computed<Column[]>(() => [
  { key: 'group_name', label: t('admin.promptAudit.probeGovernance.group'), sortable: true, class: 'min-w-60 max-w-64' },
  { key: 'enabled', label: t('admin.promptAudit.probeGovernance.status'), sortable: true, class: 'min-w-32' },
  { key: 'interval_seconds', label: t('admin.promptAudit.probeGovernance.interval'), sortable: true, class: 'min-w-32' },
  { key: 'allow_first_real_probe', label: t('admin.promptAudit.probeGovernance.firstReal'), sortable: true, class: 'min-w-36' },
  { key: 'local_responses_24h', label: t('admin.promptAudit.probeGovernance.localResponses24h'), sortable: true, class: 'min-w-36 text-right' },
  { key: 'skipped_audits_24h', label: t('admin.promptAudit.probeGovernance.skippedAudits24h'), sortable: true, class: 'min-w-36 text-right' },
  { key: 'skipped_upstream_24h', label: t('admin.promptAudit.probeGovernance.skippedUpstream24h'), sortable: true, class: 'min-w-36 text-right' },
  { key: 'last_probe_at', label: t('admin.promptAudit.probeGovernance.lastProbe'), sortable: true, class: 'min-w-44' },
  { key: 'actions', label: t('admin.promptAudit.common.actions'), class: 'min-w-[300px] text-right' },
])
const configurableColumns = computed(() => columns.value.filter((column) => !['group_name', 'actions'].includes(column.key)))
const visibleColumns = computed(() => columns.value.filter((column) => !hiddenColumns.value.includes(column.key) || ['group_name', 'actions'].includes(column.key)))

watch(() => scopedGroups.value.map((group) => group.id).join(','), () => {
  if (appliedGroupID.value !== null && !scopedGroups.value.some((group) => group.id === appliedGroupID.value)) resetFilters()
  void loadPolicies()
})
watch([() => filteredRows.value.length, () => pageSize.value], ([total, size]) => {
  currentPage.value = Math.min(currentPage.value, Math.max(1, Math.ceil(total / size)))
})
onMounted(() => {
  try {
    const parsed = JSON.parse(localStorage.getItem('prompt-audit-probe-governance-sort-v1') || '{}') as { key?: string; order?: string }
    if (columns.value.some((column) => column.sortable && column.key === parsed.key)) sortKey.value = parsed.key as keyof ProbeGovernancePolicy
    if (parsed.order === 'desc') sortOrder.value = 'desc'
  } catch { /* optional */ }
  try {
    const parsed = JSON.parse(localStorage.getItem('prompt-audit-probe-governance-hidden-columns') || '[]')
    if (Array.isArray(parsed)) hiddenColumns.value = parsed.filter((value): value is string => typeof value === 'string')
  } catch { /* optional */ }
  void loadPolicies()
})

function isGroupInScope(groupID: number): boolean {
  const saved = (props.draft.group_policies ?? []).find((policy) => Number(policy.group_id) === groupID)
  if (saved && typeof saved.in_scope === 'boolean') return saved.in_scope
  return props.draft.all_groups || props.draft.group_ids.includes(groupID)
}
function normalizePolicy(policy: ProbeGovernancePolicy | undefined, group: PromptAuditGroup): ProbeGovernancePolicy {
  return {
    group_id: group.id,
    group_name: group.name,
    enabled: policy?.enabled === true,
    interval_seconds: Number.isInteger(policy?.interval_seconds) ? policy!.interval_seconds : 300,
    health_scope: policy?.health_scope === 'group_model_protocol' ? policy.health_scope : 'group_model_protocol',
    allow_first_real_probe: policy?.allow_first_real_probe !== false,
    skip_repeat_audit: policy?.skip_repeat_audit !== false,
    skip_repeat_upstream: policy?.skip_repeat_upstream !== false,
    healthy_response: policy?.healthy_response || t('admin.promptAudit.probeGovernance.defaults.healthyResponse'),
    violation_response: policy?.violation_response || t('admin.promptAudit.probeGovernance.defaults.violationResponse'),
    unknown_response: policy?.unknown_response || t('admin.promptAudit.probeGovernance.defaults.unknownResponse'),
    local_responses_24h: Number(policy?.local_responses_24h || 0),
    skipped_audits_24h: Number(policy?.skipped_audits_24h || 0),
    skipped_upstream_24h: Number(policy?.skipped_upstream_24h || 0),
    last_probe_at: policy?.last_probe_at || '',
    ...(policy?.created_at ? { created_at: policy.created_at } : {}),
    ...(policy?.updated_at ? { updated_at: policy.updated_at } : {}),
    ...(policy?.updated_by ? { updated_by: policy.updated_by } : {}),
  }
}
async function loadPolicies() {
  if (loading.value) {
    reloadAfterCurrent = true
    return
  }
  loading.value = true
  error.value = ''
  try {
    const collected = new Map<number, ProbeGovernancePolicy>()
    let page = 1
    let pages = 1
    do {
      const result = await promptAuditAPI.listProbeGovernancePolicies({ page, page_size: 100 })
      result.items.forEach((policy) => collected.set(policy.group_id, policy))
      pages = Math.max(1, result.pages || Math.ceil(result.total / Math.max(1, result.page_size || 100)))
      page += 1
    } while (page <= pages)
    // Keep every row returned by the server. Rendering is still strictly
    // constrained by scopedGroups, while retaining these rows avoids losing a
    // real policy when config and group metadata finish loading out of order.
    policies.value = [...collected.values()]
    policiesLoaded.value = true
  } catch (caught) {
    error.value = extractApiErrorMessage(caught, t('admin.promptAudit.probeGovernance.errors.loadPolicies'))
    editingPolicy.value = null
    eventsGroup.value = null
    exemptionsGroup.value = null
    exemptionPrefill.value = null
  }
  finally {
    loading.value = false
    if (reloadAfterCurrent) {
      reloadAfterCurrent = false
      void loadPolicies()
    }
  }
}
function applyFilters() { appliedGroupID.value = pendingGroupID.value; appliedStatus.value = pendingStatus.value; currentPage.value = 1 }
function resetFilters() { pendingGroupID.value = null; appliedGroupID.value = null; pendingStatus.value = ''; appliedStatus.value = ''; currentPage.value = 1 }
function changePageSize(value: number) { pageSize.value = value; currentPage.value = 1 }
function applySort(key: string, order: 'asc' | 'desc') {
  if (!columns.value.some((column) => column.sortable && column.key === key)) return
  sortKey.value = key as keyof ProbeGovernancePolicy
  sortOrder.value = order
  currentPage.value = 1
}
function isColumnVisible(key: string): boolean { return !hiddenColumns.value.includes(key) || ['group_name', 'actions'].includes(key) }
function toggleColumn(key: string) {
  if (['group_name', 'actions'].includes(key)) return
  hiddenColumns.value = hiddenColumns.value.includes(key) ? hiddenColumns.value.filter((value) => value !== key) : [...hiddenColumns.value, key]
  try { localStorage.setItem('prompt-audit-probe-governance-hidden-columns', JSON.stringify(hiddenColumns.value)) } catch { /* optional */ }
}
async function updatePolicy(groupID: number, payload: ProbeGovernancePolicyUpdate): Promise<boolean> {
  if (!policiesWritable.value) return false
  try {
    const updated = await promptAuditAPI.updateProbeGovernancePolicy(groupID, payload)
    const index = policies.value.findIndex((policy) => policy.group_id === groupID)
    if (index >= 0) {
      const current = policies.value[index]
      // The mutation endpoint returns the saved policy document, while the
      // rolling counters are populated by the list query. Preserve those live
      // counters until the next refresh instead of flashing them back to zero.
      policies.value.splice(index, 1, {
        ...current,
        ...updated,
        local_responses_24h: current.local_responses_24h,
        skipped_audits_24h: current.skipped_audits_24h,
        skipped_upstream_24h: current.skipped_upstream_24h,
        last_probe_at: current.last_probe_at,
      })
    }
    else policies.value.push(updated)
    return true
  } catch (caught) {
    appStore.showError(extractApiErrorMessage(caught, t('admin.promptAudit.probeGovernance.errors.savePolicy')))
    return false
  }
}
async function togglePolicy(policy: ProbeGovernancePolicy) {
  if (!policiesWritable.value || updatingGroupID.value !== null) return
  updatingGroupID.value = policy.group_id
  const saved = await updatePolicy(policy.group_id, { enabled: !policy.enabled })
  if (saved) appStore.showSuccess(t(policy.enabled ? 'admin.promptAudit.probeGovernance.messages.disabled' : 'admin.promptAudit.probeGovernance.messages.enabled', { name: policy.group_name }))
  updatingGroupID.value = null
}
async function savePolicy(groupID: number, payload: ProbeGovernancePolicyUpdate) {
  if (!policiesWritable.value || savingPolicy.value) return
  savingPolicy.value = true
  const saved = await updatePolicy(groupID, payload)
  if (saved) {
    editingPolicy.value = null
    appStore.showSuccess(t('admin.promptAudit.probeGovernance.messages.saved'))
  }
  savingPolicy.value = false
}
function openPolicy(policy: ProbeGovernancePolicy) { if (policiesWritable.value) editingPolicy.value = clone(policy) }
function openEvents(policy: ProbeGovernancePolicy) { if (policiesWritable.value) eventsGroup.value = policy }
function openExemptions(policy: ProbeGovernancePolicy) { if (policiesWritable.value) { exemptionPrefill.value = null; exemptionsGroup.value = policy } }
function openExemptionFromEvent(event: ProbeGovernanceEventDetail) {
  eventsGroup.value = null
  exemptionPrefill.value = event
  exemptionsGroup.value = scopedRows.value.find((policy) => policy.group_id === event.group_id) || null
}
function closeExemptions() { exemptionsGroup.value = null; exemptionPrefill.value = null }
function groupPlatform(groupID: number): string { return props.groups.find((group) => group.id === groupID)?.platform || '' }
function formatInterval(seconds: number): string { return seconds % 60 === 0 ? t('admin.promptAudit.probeGovernance.minutes', { count: seconds / 60 }) : t('admin.promptAudit.probeGovernance.seconds', { count: seconds }) }
function formatDate(value?: string): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(locale.value.startsWith('zh') ? 'zh-CN' : 'en-US', { dateStyle: 'short', timeStyle: 'short' }).format(date)
}
function compareValues(left: unknown, right: unknown): number {
  const leftEmpty = left === null || left === undefined || left === ''
  const rightEmpty = right === null || right === undefined || right === ''
  if (leftEmpty && rightEmpty) return 0
  if (leftEmpty) return 1
  if (rightEmpty) return -1
  if (typeof left === 'number' && typeof right === 'number') return left - right
  if (typeof left === 'boolean' && typeof right === 'boolean') return Number(left) - Number(right)
  return String(left).localeCompare(String(right), locale.value, { numeric: true, sensitivity: 'base' })
}
function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T }

const MetricCell = defineComponent({
  props: { value: { type: Number, required: true } },
  setup(componentProps) {
    return () => h('div', { class: 'text-right' }, [
      h('p', { class: 'tabular-nums text-sm font-medium text-gray-900 dark:text-white' }, Number(componentProps.value || 0).toLocaleString()),
      h('p', { class: 'mt-1 text-xs text-gray-500 dark:text-dark-400' }, t('admin.promptAudit.probeGovernance.last24Hours')),
    ])
  },
})
</script>

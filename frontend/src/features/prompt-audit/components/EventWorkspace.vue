<template>
  <section aria-labelledby="prompt-events-title" class="card overflow-hidden">
    <div class="card-header flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="prompt-events-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.events.title') }}</h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.events.description') }}</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button type="button" class="btn btn-secondary btn-sm" :disabled="selectedIds.length === 0" @click="$emit('batch-delete')">
          {{ t('admin.promptAudit.events.deleteSelected', { count: selectedIds.length }) }}
        </button>
        <button type="button" class="btn btn-danger btn-sm" data-test="filter-delete" @click="$emit('preview-delete')">
          {{ t('admin.promptAudit.events.deleteByFilter') }}
        </button>
      </div>
    </div>

    <form class="border-b border-gray-200 p-4 dark:border-dark-700 sm:p-6" @submit.prevent="applyFilters">
      <div class="flex flex-wrap items-end justify-between gap-4">
        <div class="flex flex-1 flex-wrap items-end gap-4">
          <div class="w-full sm:w-auto sm:min-w-[180px]">
            <label class="input-label">{{ t('admin.promptAudit.events.decision') }}</label>
            <Select
              :model-value="localFilters.decision"
              :options="decisionOptions"
              :aria-label="t('admin.promptAudit.events.decision')"
              @change="setStringFilter('decision', $event)"
            />
          </div>
          <div class="w-full sm:w-auto sm:min-w-[180px]">
            <label class="input-label">{{ t('admin.promptAudit.events.risk') }}</label>
            <Select
              :model-value="localFilters.risk_level"
              :options="riskOptions"
              :aria-label="t('admin.promptAudit.events.risk')"
              @change="setStringFilter('risk_level', $event)"
            />
          </div>
          <FilterInput v-model="localFilters.endpoint" :label="t('admin.promptAudit.events.requestEndpoint')" @change="filtersChanged" />
          <div class="w-full sm:w-auto sm:min-w-[220px]">
            <label class="input-label">{{ t('admin.promptAudit.events.guardEndpoint') }}</label>
            <Select
              :model-value="localFilters.guard_endpoint_id || ''"
              :options="guardEndpointSelectOptions"
              :aria-label="t('admin.promptAudit.events.guardEndpoint')"
              searchable
              @change="setStringFilter('guard_endpoint_id', $event)"
            />
          </div>
          <div class="w-full sm:w-auto sm:min-w-[220px]">
            <label class="input-label">{{ t('admin.promptAudit.events.groupId') }}</label>
            <Select
              :model-value="localFilters.group_id"
              :options="groupSelectOptions"
              :aria-label="t('admin.promptAudit.events.groupId')"
              searchable
              @change="setStringFilter('group_id', $event)"
            />
          </div>
          <div class="w-full sm:w-auto sm:min-w-[240px]" data-test="event-user-filter">
            <label class="input-label">{{ t('admin.promptAudit.events.userFilter') }}</label>
            <Select
              :model-value="selectedUserID"
              :options="userSelectOptions"
              :placeholder="t('admin.promptAudit.events.allUsers')"
              :search-placeholder="t('admin.usage.searchUserPlaceholder')"
              :aria-label="t('admin.promptAudit.events.userFilter')"
              remote
              clearable
              :loading="usersLoading"
              @search="searchUsers"
              @change="setUserFilter"
            >
              <template #option="{ option }">
                <span class="min-w-0 flex-1 truncate">{{ option.label }}</span>
                <span v-if="option.deleted" class="ml-2 shrink-0 text-xs text-gray-400">{{ t('admin.usage.userDeletedBadge') }}</span>
              </template>
            </Select>
          </div>
          <div class="w-full sm:w-auto sm:min-w-[240px]" data-test="event-api-key-filter">
            <label class="input-label">{{ t('admin.promptAudit.events.apiKeyFilter') }}</label>
            <Select
              :model-value="selectedAPIKeyID"
              :options="apiKeySelectOptions"
              :placeholder="t('admin.promptAudit.events.allApiKeys')"
              :search-placeholder="t('admin.usage.searchApiKeyPlaceholder')"
              :aria-label="t('admin.promptAudit.events.apiKeyFilter')"
              remote
              clearable
              :loading="apiKeysLoading"
              @search="searchAPIKeys"
              @change="setAPIKeyFilter"
            />
          </div>
          <FilterInput v-model="localFilters.request_id" :label="t('admin.promptAudit.events.requestId')" @change="filtersChanged" />
          <FilterInput v-model="localFilters.prompt_hash" :label="t('admin.promptAudit.events.promptHash')" @change="filtersChanged" />
          <FilterInput v-model="localFilters.keyword" :label="t('admin.promptAudit.events.keyword')" @change="filtersChanged" />
          <label class="w-full sm:w-auto sm:min-w-[220px]">
            <span class="input-label">{{ t('admin.promptAudit.events.startAt') }}</span>
            <input v-model="localFilters.start_at" type="datetime-local" class="input w-full" :aria-label="t('admin.promptAudit.events.startAt')" @change="filtersChanged" />
          </label>
          <label class="w-full sm:w-auto sm:min-w-[220px]">
            <span class="input-label">{{ t('admin.promptAudit.events.endAt') }}</span>
            <input v-model="localFilters.end_at" type="datetime-local" class="input w-full" :aria-label="t('admin.promptAudit.events.endAt')" @change="filtersChanged" />
          </label>
        </div>
        <div class="flex w-full flex-wrap items-center justify-end gap-3 sm:w-auto">
          <button type="submit" class="btn btn-primary">{{ t('common.search') }}</button>
          <button type="button" class="btn btn-secondary" data-test="event-reset-filters" @click="resetFilters">{{ t('common.reset') }}</button>
          <ColumnSettingsDropdown
            :label="t('admin.promptAudit.events.columns')"
            :columns="eventConfigurableColumns"
            :is-visible="isEventColumnVisible"
            button-test="event-column-settings"
            menu-test="event-column-menu"
            @toggle="toggleEventColumn"
          />
        </div>
      </div>
    </form>
    <div v-if="error" role="alert" class="mx-5 mb-5 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">{{ error }}</div>
    <div class="border-t border-gray-200 bg-gray-50/60 p-3 dark:border-dark-700 dark:bg-dark-950/20 md:bg-transparent md:p-0" data-test="event-data-table">
      <DataTable
        :columns="visibleEventColumns"
        :data="events"
        :loading="loading"
        row-key="id"
        selectable
        :selected-keys="selectedIds"
        :selection-label="eventSelectionLabel"
        :sticky-first-column="true"
        :sticky-actions-column="true"
        @update:selected-keys="updateSelection"
      >
        <template #cell-created_at="{ row }">
          <span class="whitespace-nowrap text-xs text-gray-600 dark:text-dark-300">{{ formatDate(row.created_at) }}</span>
        </template>
        <template #cell-email="{ row }">
          <div class="min-w-0 max-w-60" data-test="event-email">
            <p class="truncate text-gray-800 dark:text-dark-100" :title="row.snapshot.user_email || undefined">{{ row.snapshot.user_email || '—' }}</p>
          </div>
        </template>
        <template #cell-api_key="{ row }">
          <div class="min-w-0 max-w-44" data-test="event-api-key">
            <p class="truncate text-gray-800 dark:text-dark-100" :title="displayAPIKeyName(row)">{{ displayAPIKeyName(row) }}</p>
            <p v-if="row.snapshot.api_key_id > 0" class="mt-1 font-mono text-xs text-gray-400 dark:text-dark-500">#{{ row.snapshot.api_key_id }}</p>
          </div>
        </template>
        <template #cell-group="{ row }">
          <span class="text-gray-700 dark:text-dark-200">{{ row.snapshot.group_name || '—' }}</span>
        </template>
        <template #cell-route="{ row }">
          <div class="min-w-0 max-w-64">
            <p class="truncate font-medium text-gray-900 dark:text-white" :title="row.snapshot.endpoint">{{ row.snapshot.endpoint }}</p>
            <p class="mt-1 truncate text-xs text-gray-500" :title="`${row.snapshot.model} · ${row.snapshot.protocol} · ${row.snapshot.stage || 'http'}`">{{ row.snapshot.model }} · {{ row.snapshot.protocol }} · {{ row.snapshot.stage || 'http' }}</p>
          </div>
        </template>
        <template #cell-guard="{ row }">
          <div class="min-w-0 max-w-52">
            <p class="truncate font-medium text-gray-900 dark:text-white" :title="guardEndpointLabel(row)">{{ guardEndpointLabel(row) }}</p>
            <p class="mt-1 truncate font-mono text-xs text-gray-500 dark:text-dark-400">{{ row.guard_endpoint_id || '—' }}</p>
          </div>
        </template>
        <template #cell-result="{ row }">
          <div class="min-w-0 max-w-48">
            <span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium" :class="decisionClass(row.decision)">{{ formatDecisionRisk(row.decision, row.risk_level) }}</span>
            <p class="mt-2 truncate text-xs text-gray-500" :title="formatCategories(row.categories)">{{ formatCategories(row.categories) }}</p>
          </div>
        </template>
        <template #cell-preview="{ row }">
          <p class="line-clamp-2 min-w-0 max-w-xs whitespace-normal break-words text-gray-600 dark:text-dark-300">{{ row.snapshot.redacted_preview || '—' }}</p>
        </template>
        <template #cell-actions="{ row }">
          <div class="flex flex-wrap justify-end gap-1">
            <button type="button" class="btn btn-ghost btn-sm" @click.stop="$emit('view', row.id)">{{ t('common.view') }}</button>
            <button type="button" class="btn btn-ghost btn-sm text-red-600" @click.stop="$emit('delete', row.id)">{{ t('common.delete') }}</button>
          </div>
        </template>
        <template #empty>
          <p class="py-8 text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.events.empty') }}</p>
        </template>
      </DataTable>
    </div>
    <div data-test="event-pagination" class="border-t border-gray-200 dark:border-dark-700">
      <Pagination :total="total" :page="page" :page-size="pageSize" @update:page="$emit('page', $event)" @update:page-size="$emit('page-size', $event)" />
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import type { SimpleApiKey, SimpleUser } from '@/api/admin/usage'
import DataTable from '@/components/common/DataTable.vue'
import Pagination from '@/components/common/Pagination.vue'
import Select, { type SelectOption } from '@/components/common/Select.vue'
import type { Column } from '@/components/common/types'
import type { PromptAuditEndpointDraft, PromptAuditEvent, PromptAuditGroup, PromptEventFilters } from '../types'
import { cloneData, emptyEventFilters, LOCALIZED_SCANNER_IDS } from '../viewModel'
import ColumnSettingsDropdown from './ColumnSettingsDropdown.vue'

const props = defineProps<{
  events: PromptAuditEvent[]; total: number; page: number; pageSize: number
  filters: PromptEventFilters; selectedIds: number[]; loading: boolean; error: string
  groups?: PromptAuditGroup[]
  endpoints?: PromptAuditEndpointDraft[]
}>()
const emit = defineEmits<{
  (event: 'filters-change', value: PromptEventFilters): void
  (event: 'search', value: PromptEventFilters): void
  (event: 'selection', value: number[]): void
  (event: 'page', value: number): void
  (event: 'page-size', value: number): void
  (event: 'view', id: number): void
  (event: 'delete', id: number): void
  (event: 'batch-delete'): void
  (event: 'preview-delete'): void
}>()
const { t, locale } = useI18n()
const localFilters = reactive<PromptEventFilters>(cloneData(props.filters))
const hiddenEventColumns = ref<string[]>([])
const userResults = ref<SimpleUser[]>([])
const apiKeyResults = ref<SimpleApiKey[]>([])
const pinnedUser = ref<SimpleUser | null>(null)
const pinnedAPIKey = ref<SimpleApiKey | null>(null)
const usersLoading = ref(false)
const apiKeysLoading = ref(false)
let userSearchSequence = 0
let apiKeySearchSequence = 0
watch(() => props.filters, (value) => {
  Object.assign(localFilters, cloneData(value))
  if (pinnedUser.value?.id !== parsePositiveID(value.user_id)) pinnedUser.value = null
  if (pinnedAPIKey.value?.id !== parsePositiveID(value.api_key_id)) pinnedAPIKey.value = null
}, { deep: true })
const groupOptions = computed<PromptAuditGroup[]>(() => {
  const options = (props.groups ?? []).slice().sort((left, right) => left.id - right.id)
  // Group ID 0 is the server-side sentinel for events/users with no assigned
  // group. Keep it distinct from the empty value (all groups).
  if (!options.some((group) => group.id === 0)) {
    options.unshift({ id: 0, name: t('admin.promptAudit.groups.unassigned'), platform: '', status: 'active' })
  }
  return options
})
const endpointOptions = computed(() => (props.endpoints ?? []).slice().sort((left, right) => left.priority - right.priority || left.id.localeCompare(right.id)))
const decisionOptions = computed<SelectOption[]>(() => [
  { value: '', label: t('common.all') },
  { value: 'pass', label: t('admin.promptAudit.decisions.pass') },
  { value: 'flag', label: t('admin.promptAudit.decisions.flag') },
  { value: 'critical', label: t('admin.promptAudit.decisions.critical') },
])
const riskOptions = computed<SelectOption[]>(() => [
  { value: '', label: t('common.all') },
  { value: 'low', label: t('admin.promptAudit.riskLevels.low') },
  { value: 'medium', label: t('admin.promptAudit.riskLevels.medium') },
  { value: 'high', label: t('admin.promptAudit.riskLevels.high') },
  { value: 'critical', label: t('admin.promptAudit.riskLevels.critical') },
])
const guardEndpointSelectOptions = computed<SelectOption[]>(() => {
  const options: SelectOption[] = [
    { value: '', label: t('common.all') },
    ...endpointOptions.value.map((endpoint) => ({ value: endpoint.id, label: `${endpoint.name} · ${endpoint.id}` })),
  ]
  const selected = localFilters.guard_endpoint_id || ''
  if (selected && !endpointOptions.value.some((endpoint) => endpoint.id === selected)) {
    options.push({ value: selected, label: selected })
  }
  return options
})
const groupSelectOptions = computed<SelectOption[]>(() => {
  const options: SelectOption[] = [
    { value: '', label: t('common.all') },
    ...groupOptions.value.map((group) => ({ value: String(group.id), label: `${group.name} · #${group.id}` })),
  ]
  const selected = localFilters.group_id
  if (selected && !groupOptions.value.some((group) => String(group.id) === selected)) {
    options.push({ value: selected, label: `#${selected}` })
  }
  return options
})
const selectedUserID = computed(() => parsePositiveID(localFilters.user_id))
const selectedAPIKeyID = computed(() => parsePositiveID(localFilters.api_key_id))
const userSelectOptions = computed<SelectOption[]>(() => withSelectedFallback(
  withPinnedOption(userResults.value.map(userOption), pinnedUser.value ? userOption(pinnedUser.value) : null),
  selectedUserID.value,
))
const apiKeySelectOptions = computed<SelectOption[]>(() => withSelectedFallback(
  withPinnedOption(apiKeyResults.value.map(apiKeyOption), pinnedAPIKey.value ? apiKeyOption(pinnedAPIKey.value) : null),
  selectedAPIKeyID.value,
))
const eventColumns = computed<Column[]>(() => [
  { key: 'created_at', label: t('admin.promptAudit.events.time'), class: 'min-w-36' },
  { key: 'email', label: t('admin.promptAudit.events.email'), class: 'w-60 max-w-60' },
  { key: 'api_key', label: t('admin.promptAudit.events.apiKey'), class: 'w-44 max-w-44' },
  { key: 'group', label: t('admin.promptAudit.events.group'), class: 'min-w-32' },
  { key: 'route', label: t('admin.promptAudit.events.route'), class: 'min-w-64' },
  { key: 'guard', label: t('admin.promptAudit.events.guardNode'), class: 'min-w-52' },
  { key: 'result', label: t('admin.promptAudit.events.result'), class: 'min-w-48' },
  { key: 'preview', label: t('admin.promptAudit.events.preview'), class: 'min-w-72 max-w-xs' },
  { key: 'actions', label: t('admin.promptAudit.common.actions'), class: 'min-w-36 text-right' },
])
const eventConfigurableColumns = computed(() => eventColumns.value.filter((column) => !['created_at', 'actions'].includes(column.key)))
const visibleEventColumns = computed(() => eventColumns.value.filter((column) => !hiddenEventColumns.value.includes(column.key) || ['created_at', 'actions'].includes(column.key)))

function isEventColumnVisible(key: string): boolean {
  return !hiddenEventColumns.value.includes(key) || ['created_at', 'actions'].includes(key)
}
function toggleEventColumn(key: string) {
  if (['created_at', 'actions'].includes(key)) return
  hiddenEventColumns.value = hiddenEventColumns.value.includes(key)
    ? hiddenEventColumns.value.filter((item) => item !== key)
    : [...hiddenEventColumns.value, key]
  try { localStorage.setItem('prompt-audit-event-hidden-columns', JSON.stringify(hiddenEventColumns.value)) } catch { /* storage is optional */ }
}

const FilterInput = defineComponent({
  props: { modelValue: { type: String, required: true }, label: { type: String, required: true }, type: { type: String, default: 'text' } },
  emits: ['update:modelValue', 'change'],
  setup(componentProps, { emit: componentEmit }) {
    return () => h('label', { class: 'w-full sm:w-auto sm:min-w-[220px]' }, [
      h('span', { class: 'input-label' }, componentProps.label),
      h('input', {
        value: componentProps.modelValue, type: componentProps.type, class: 'input w-full', 'aria-label': componentProps.label,
        onInput: (event: Event) => componentEmit('update:modelValue', (event.target as HTMLInputElement).value),
        onChange: () => componentEmit('change'),
      }),
    ])
  },
})

function filtersChanged() {
  emit('filters-change', cloneData(localFilters))
}
type SelectValue = string | number | boolean | null
type StringFilterKey = 'decision' | 'risk_level' | 'guard_endpoint_id' | 'group_id'

function setStringFilter(key: StringFilterKey, value: SelectValue) {
  localFilters[key] = value == null ? '' : String(value)
  filtersChanged()
}

function parsePositiveID(value: string | undefined): number | null {
  if (!value || !/^\d+$/.test(value)) return null
  const id = Number(value)
  return Number.isSafeInteger(id) && id > 0 ? id : null
}

function withSelectedFallback(options: SelectOption[], selectedID: number | null): SelectOption[] {
  if (selectedID == null || options.some((option) => option.value === selectedID)) return options
  return [...options, { value: selectedID, label: `#${selectedID}` }]
}

function withPinnedOption(options: SelectOption[], pinned: SelectOption | null): SelectOption[] {
  if (!pinned || options.some((option) => option.value === pinned.value)) return options
  return [pinned, ...options]
}

function userOption(user: SimpleUser): SelectOption {
  return { value: user.id, label: `${user.email} · #${user.id}`, deleted: user.deleted }
}

function apiKeyOption(key: SimpleApiKey): SelectOption {
  return {
    value: key.id,
    label: `${key.name.trim() || t('admin.promptAudit.events.unnamedApiKey')} · #${key.id}`,
    userID: key.user_id,
  }
}

async function searchUsers(query: string) {
  const keyword = query.trim()
  const sequence = ++userSearchSequence
  if (!keyword) {
    userResults.value = []
    usersLoading.value = false
    return
  }
  usersLoading.value = true
  try {
    const users = await adminAPI.usage.searchUsers(keyword)
    if (sequence === userSearchSequence) {
      userResults.value = users.slice().sort((left, right) => Number(left.deleted) - Number(right.deleted))
    }
  } catch {
    if (sequence === userSearchSequence) userResults.value = []
  } finally {
    if (sequence === userSearchSequence) usersLoading.value = false
  }
}

async function loadAPIKeys(query: string, userID: number | null = selectedUserID.value) {
  const sequence = ++apiKeySearchSequence
  apiKeysLoading.value = true
  try {
    const keys = await adminAPI.usage.searchApiKeys(userID ?? undefined, query.trim())
    if (sequence === apiKeySearchSequence) apiKeyResults.value = keys
  } catch {
    if (sequence === apiKeySearchSequence) apiKeyResults.value = []
  } finally {
    if (sequence === apiKeySearchSequence) apiKeysLoading.value = false
  }
}

function searchAPIKeys(query: string) {
  void loadAPIKeys(query)
}

function setUserFilter(value: SelectValue) {
  const nextID = typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null
  const changed = nextID !== selectedUserID.value
  localFilters.user_id = nextID == null ? '' : String(nextID)
  pinnedUser.value = nextID == null
    ? null
    : userResults.value.find((user) => user.id === nextID) ?? (pinnedUser.value?.id === nextID ? pinnedUser.value : null)
  if (changed) {
    apiKeySearchSequence += 1
    apiKeysLoading.value = false
    apiKeyResults.value = []
    pinnedAPIKey.value = null
    localFilters.api_key_id = ''
    if (nextID != null) void loadAPIKeys('', nextID)
  }
  filtersChanged()
}

function setAPIKeyFilter(value: SelectValue) {
  const id = typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null
  localFilters.api_key_id = id == null ? '' : String(id)
  pinnedAPIKey.value = id == null
    ? null
    : apiKeyResults.value.find((key) => key.id === id) ?? (pinnedAPIKey.value?.id === id ? pinnedAPIKey.value : null)
  filtersChanged()
}

function applyFilters() {
  const value = cloneData(localFilters)
  emit('filters-change', value)
  emit('search', value)
}
function resetFilters() {
  userSearchSequence += 1
  apiKeySearchSequence += 1
  usersLoading.value = false
  apiKeysLoading.value = false
  userResults.value = []
  apiKeyResults.value = []
  pinnedUser.value = null
  pinnedAPIKey.value = null
  Object.assign(localFilters, emptyEventFilters())
  applyFilters()
}
function eventSelectionLabel(event: PromptAuditEvent): string {
  return t('admin.promptAudit.events.selectEvent', { id: event.id })
}
function updateSelection(keys: Array<string | number>) {
  emit('selection', keys.filter((key): key is number => typeof key === 'number'))
}
function formatDate(value: string): string {
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value))
}
function decisionClass(decision: string): string {
  if (decision === 'critical') return 'bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300'
  if (decision === 'flag') return 'bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300'
  return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300'
}
const DECISIONS = new Set(['pass', 'flag', 'critical'])
const RISK_LEVELS = new Set(['low', 'medium', 'high', 'critical'])

function translateDecision(decision: string): string {
  return DECISIONS.has(decision) ? t(`admin.promptAudit.decisions.${decision}`) : decision
}
function translateRiskLevel(riskLevel: string): string {
  return RISK_LEVELS.has(riskLevel) ? t(`admin.promptAudit.riskLevels.${riskLevel}`) : riskLevel
}
function translateCategory(category: string): string {
  return LOCALIZED_SCANNER_IDS.has(category)
    ? t(`admin.promptAudit.scanners.${category}`)
    : category
}
function formatDecisionRisk(decision: string, riskLevel: string): string {
  return `${translateDecision(decision)} · ${translateRiskLevel(riskLevel)}`
}
function formatCategories(categories: string[]): string {
  if (!categories.length) return '—'
  return categories.map(translateCategory).join(', ')
}

function guardEndpointLabel(event: PromptAuditEvent): string {
  if (event.guard_endpoint_name?.trim()) return event.guard_endpoint_name
  const endpoint = endpointOptions.value.find((item) => item.id === event.guard_endpoint_id)
  return endpoint?.name || event.guard_endpoint_id || '—'
}

function maskPotentialAPIKey(value: string): string {
  const normalized = value.trim()
  if (!/^sk-[A-Za-z0-9._-]{12,}$/.test(normalized)) return value
  return `${normalized.slice(0, 6)}…${normalized.slice(-4)}`
}

function displayAPIKeyName(event: PromptAuditEvent): string {
  // The snapshot contract contains the key name, never the credential. If a
  // legacy/custom record nevertheless looks like a secret, keep it masked.
  return maskPotentialAPIKey(event.snapshot.api_key_name || '') || '—'
}

onMounted(() => {
  try {
    const raw = localStorage.getItem('prompt-audit-event-hidden-columns')
    const parsed = raw ? JSON.parse(raw) : []
    if (Array.isArray(parsed)) {
      hiddenEventColumns.value = parsed.filter((item): item is string => typeof item === 'string' && eventConfigurableColumns.value.some((column) => column.key === item))
    }
  } catch { hiddenEventColumns.value = [] }
})

onUnmounted(() => {
  userSearchSequence += 1
  apiKeySearchSequence += 1
})
</script>

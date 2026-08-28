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
        <div class="relative">
          <button type="button" class="btn btn-secondary btn-sm" data-test="event-column-settings" :aria-expanded="eventColumnMenuOpen" @click="eventColumnMenuOpen = !eventColumnMenuOpen">
            {{ t('admin.promptAudit.events.columns') }}
          </button>
          <div v-if="eventColumnMenuOpen" class="absolute right-0 z-20 mt-2 w-56 rounded-xl border border-gray-200 bg-white p-2 shadow-lg dark:border-dark-700 dark:bg-dark-800" data-test="event-column-menu">
            <label v-for="column in eventConfigurableColumns" :key="column.key" class="flex cursor-pointer items-center gap-2 rounded-lg px-2 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-700">
              <input type="checkbox" :checked="isEventColumnVisible(column.key)" @change="toggleEventColumn(column.key)" />
              <span>{{ column.label }}</span>
            </label>
            <p class="px-2 pb-1 pt-2 text-[11px] text-gray-400 dark:text-dark-500">{{ t('admin.promptAudit.events.fixedColumns') }}</p>
          </div>
        </div>
      </div>
    </div>

    <form class="m-5 grid gap-3 rounded-xl bg-gray-50 p-4 dark:bg-dark-900/50 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5" @submit.prevent="applyFilters">
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.decision') }}</span>
        <select v-model="localFilters.decision" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.decision')" @change="filtersChanged">
          <option value="">{{ t('common.all') }}</option>
          <option value="pass">{{ t('admin.promptAudit.decisions.pass') }}</option>
          <option value="flag">{{ t('admin.promptAudit.decisions.flag') }}</option>
          <option value="critical">{{ t('admin.promptAudit.decisions.critical') }}</option>
        </select>
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.risk') }}</span>
        <select v-model="localFilters.risk_level" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.risk')" @change="filtersChanged">
          <option value="">{{ t('common.all') }}</option>
          <option value="low">{{ t('admin.promptAudit.riskLevels.low') }}</option>
          <option value="medium">{{ t('admin.promptAudit.riskLevels.medium') }}</option>
          <option value="high">{{ t('admin.promptAudit.riskLevels.high') }}</option>
          <option value="critical">{{ t('admin.promptAudit.riskLevels.critical') }}</option>
        </select>
      </label>
      <FilterInput v-model="localFilters.endpoint" :label="t('admin.promptAudit.events.requestEndpoint')" @change="filtersChanged" />
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.guardEndpoint') }}</span>
        <select v-model="localFilters.guard_endpoint_id" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.guardEndpoint')" @change="filtersChanged">
          <option value="">{{ t('common.all') }}</option>
          <option v-for="endpoint in endpointOptions" :key="endpoint.id" :value="endpoint.id">{{ endpoint.name }} · {{ endpoint.id }}</option>
          <option v-if="localFilters.guard_endpoint_id && !endpointOptions.some((endpoint) => endpoint.id === localFilters.guard_endpoint_id)" :value="localFilters.guard_endpoint_id">{{ localFilters.guard_endpoint_id }}</option>
        </select>
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.groupId') }}</span>
        <select v-model="localFilters.group_id" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.groupId')" @change="filtersChanged">
          <option value="">{{ t('common.all') }}</option>
          <option v-for="group in groupOptions" :key="group.id" :value="String(group.id)">{{ group.name }} · #{{ group.id }}</option>
          <option v-if="localFilters.group_id && !groupOptions.some((group) => String(group.id) === localFilters.group_id)" :value="localFilters.group_id">#{{ localFilters.group_id }}</option>
        </select>
      </label>
      <FilterInput v-model="localFilters.user_id" :label="t('admin.promptAudit.events.userId')" type="number" @change="filtersChanged" />
      <FilterInput v-model="localFilters.api_key_id" :label="t('admin.promptAudit.events.apiKeyId')" type="number" @change="filtersChanged" />
      <FilterInput v-model="localFilters.request_id" :label="t('admin.promptAudit.events.requestId')" @change="filtersChanged" />
      <FilterInput v-model="localFilters.prompt_hash" :label="t('admin.promptAudit.events.promptHash')" @change="filtersChanged" />
      <FilterInput v-model="localFilters.keyword" :label="t('admin.promptAudit.events.keyword')" @change="filtersChanged" />
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.startAt') }}</span>
        <input v-model="localFilters.start_at" type="datetime-local" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.startAt')" @change="filtersChanged" />
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.endAt') }}</span>
        <input v-model="localFilters.end_at" type="datetime-local" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.endAt')" @change="filtersChanged" />
      </label>
      <div class="flex items-end gap-2 sm:col-span-2">
        <button type="submit" class="btn btn-primary btn-sm">{{ t('common.search') }}</button>
        <button type="button" class="btn btn-ghost btn-sm" @click="resetFilters">{{ t('common.reset') }}</button>
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
import { computed, defineComponent, h, onMounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import DataTable from '@/components/common/DataTable.vue'
import Pagination from '@/components/common/Pagination.vue'
import type { Column } from '@/components/common/types'
import type { PromptAuditEndpointDraft, PromptAuditEvent, PromptAuditGroup, PromptEventFilters } from '../types'
import { cloneData, emptyEventFilters, LOCALIZED_SCANNER_IDS } from '../viewModel'

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
const eventColumnMenuOpen = ref(false)
const hiddenEventColumns = ref<string[]>([])
watch(() => props.filters, (value) => Object.assign(localFilters, cloneData(value)), { deep: true })
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
    return () => h('label', { class: 'text-xs text-gray-600 dark:text-dark-200' }, [
      h('span', componentProps.label),
      h('input', {
        value: componentProps.modelValue, type: componentProps.type, class: 'input mt-1 w-full', 'aria-label': componentProps.label,
        onInput: (event: Event) => componentEmit('update:modelValue', (event.target as HTMLInputElement).value),
        onChange: () => componentEmit('change'),
      }),
    ])
  },
})

function filtersChanged() {
  emit('filters-change', cloneData(localFilters))
}
function applyFilters() {
  const value = cloneData(localFilters)
  emit('filters-change', value)
  emit('search', value)
}
function resetFilters() {
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
</script>

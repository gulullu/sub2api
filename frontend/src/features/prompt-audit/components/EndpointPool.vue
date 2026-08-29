<template>
  <section aria-labelledby="prompt-pool-title" class="border-b border-gray-200 py-6 dark:border-dark-700/60">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="prompt-pool-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.pool.title') }}</h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.pool.description') }}</p>
      </div>
      <div class="flex flex-wrap items-center justify-end gap-2">
        <button type="button" class="btn btn-primary" data-test="add-endpoint" @click="openCreate">
          {{ t('admin.promptAudit.pool.add') }}
        </button>
        <ColumnSettingsDropdown
          :label="t('admin.promptAudit.pool.columns')"
          :columns="endpointConfigurableColumns"
          :is-visible="isEndpointColumnVisible"
          button-test="endpoint-column-settings"
          menu-test="endpoint-column-menu"
          @toggle="toggleEndpointColumn"
        />
      </div>
    </div>

    <div v-if="endpoints.length === 0" class="mt-5 rounded-xl border border-dashed border-gray-300 px-5 py-10 text-center text-sm text-gray-500 dark:border-dark-600 dark:bg-dark-900/20 dark:text-dark-300">
      {{ t('admin.promptAudit.pool.empty') }}
    </div>
    <div
      v-else
      data-test="failover-summary"
      :data-enabled-count="enabledEndpointCount"
      :data-timeout-ms="enabledTimeoutMS"
      class="mt-5 rounded-xl border px-4 py-3 text-sm"
      :class="timeoutWarning
        ? 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700/60 dark:bg-amber-950/25 dark:text-amber-200'
        : 'border-gray-200 bg-gray-50 text-gray-700 dark:border-dark-700/60 dark:bg-dark-900/40 dark:text-dark-200'"
    >
      <p class="font-medium">
        {{ t('admin.promptAudit.pool.failoverSummary', { count: enabledEndpointCount, timeout: enabledTimeoutMS }) }}
      </p>
      <p v-if="timeoutWarning" data-test="failover-timeout-warning" class="mt-1 text-xs leading-5">
        {{ t('admin.promptAudit.pool.timeoutWarning', { timeout: enabledTimeoutMS, recommended: RECOMMENDED_FAILOVER_TIMEOUT_MS }) }}
      </p>
      <p v-else class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400">
        {{ t('admin.promptAudit.pool.failoverHint', { recommended: RECOMMENDED_FAILOVER_TIMEOUT_MS }) }}
      </p>
    </div>
    <div v-if="endpoints.length > 0" class="mt-3 overflow-x-auto overflow-y-visible rounded-xl border border-gray-200 bg-white dark:border-dark-700/60 dark:bg-dark-900/20">
      <div class="endpoint-grid hidden gap-4 border-b border-l-[3px] border-b-gray-200 border-l-transparent bg-gray-50/80 px-5 py-2.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-gray-500 dark:border-b-dark-700/60 dark:bg-dark-900/70 dark:text-dark-400 xl:grid" :style="{ gridTemplateColumns: endpointGridColumns }">
        <span v-if="isEndpointColumnVisible('order')">{{ t('admin.promptAudit.pool.failoverOrder') }}</span>
        <span v-if="isEndpointColumnVisible('node')" class="endpoint-sticky-left endpoint-sticky-header">{{ t('admin.promptAudit.pool.node') }}</span>
        <span v-if="isEndpointColumnVisible('model')">{{ t('admin.promptAudit.pool.model') }}</span>
        <span v-if="isEndpointColumnVisible('limits')">{{ t('admin.promptAudit.pool.limits') }}</span>
        <span v-if="isEndpointColumnVisible('credential')">{{ t('admin.promptAudit.pool.credential') }}</span>
        <span class="endpoint-sticky-right endpoint-sticky-header text-right">{{ t('admin.promptAudit.common.actions') }}</span>
      </div>

      <div class="divide-y divide-gray-100 dark:divide-dark-800">
        <article
          v-for="endpoint in orderedEndpoints"
          :key="endpoint.id"
          :data-test="`endpoint-${endpoint.id}`"
          class="endpoint-grid group grid gap-4 border-l-[3px] border-l-transparent px-4 py-4 transition-[background-color,border-color] duration-200 hover:border-l-primary-500 hover:bg-gray-50/80 dark:hover:bg-dark-800/55 sm:px-5 xl:items-center xl:gap-4"
          :style="{ gridTemplateColumns: endpointGridColumns }"
        >
          <div v-if="isEndpointColumnVisible('order')">
            <p class="mb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-400 xl:hidden">{{ t('admin.promptAudit.pool.failoverOrder') }}</p>
            <div class="flex flex-wrap items-center gap-1.5">
              <span
                v-if="endpoint.enabled"
                :data-test="`failover-position-${endpoint.id}`"
                :data-position="failoverPosition(endpoint.id)"
                class="rounded-md bg-primary-50 px-2 py-1 text-xs font-semibold text-primary-700 dark:bg-primary-950/40 dark:text-primary-300"
              >
                {{ t('admin.promptAudit.pool.failoverPosition', { position: failoverPosition(endpoint.id) }) }}
              </span>
              <span v-else class="rounded-md bg-gray-100 px-2 py-1 text-xs text-gray-500 dark:bg-dark-800 dark:text-dark-400">
                {{ t('admin.promptAudit.status.disabled') }}
              </span>
              <span class="text-[11px] tabular-nums text-gray-500 dark:text-dark-400">
                {{ t('admin.promptAudit.pool.priorityValue', { priority: endpoint.priority }) }}
              </span>
            </div>
          </div>

          <div v-if="isEndpointColumnVisible('node')" class="endpoint-sticky-left flex min-w-0 items-center gap-3">
            <Toggle
              :model-value="endpoint.enabled"
              :aria-label="t('admin.promptAudit.pool.toggleNode', { name: endpoint.name })"
              @update:model-value="toggleEndpoint(endpoint.id)"
            />
            <div class="min-w-0">
              <div class="flex min-w-0 items-center gap-2">
                <p class="truncate font-semibold text-gray-950 dark:text-white">{{ endpoint.name }}</p>
                <span class="shrink-0 rounded-md bg-primary-50 px-1.5 py-0.5 text-[10px] font-semibold text-primary-700 dark:bg-primary-950/40 dark:text-primary-300">{{ adapterLabel(endpoint.adapter) }}</span>
                <span class="h-1.5 w-1.5 shrink-0 rounded-full" :class="endpoint.enabled ? 'bg-emerald-500' : 'bg-gray-300 dark:bg-dark-500'" aria-hidden="true" />
              </div>
              <p class="mt-0.5 truncate font-mono text-[11px] text-gray-500 dark:text-dark-400" :title="endpoint.base_url">{{ endpoint.base_url }}</p>
            </div>
          </div>

          <div v-if="isEndpointColumnVisible('model')" class="min-w-0 xl:block">
            <p class="mb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-400 xl:hidden">{{ t('admin.promptAudit.pool.model') }}</p>
            <p class="truncate text-sm font-medium text-gray-700 dark:text-dark-200" :title="endpoint.model">{{ endpoint.model }}</p>
          </div>

          <div v-if="isEndpointColumnVisible('limits')">
            <p class="mb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-400 xl:hidden">{{ t('admin.promptAudit.pool.limits') }}</p>
            <div class="flex flex-wrap gap-1.5 text-xs text-gray-600 dark:text-dark-300">
              <span class="rounded-md bg-gray-100 px-2 py-1 tabular-nums dark:bg-dark-800">{{ endpoint.timeout_ms }} ms</span>
              <span class="rounded-md bg-gray-100 px-2 py-1 tabular-nums dark:bg-dark-800">{{ endpoint.input_limit }} chars</span>
            </div>
          </div>

          <div v-if="isEndpointColumnVisible('credential')" class="min-w-0">
            <p class="mb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-400 xl:hidden">{{ t('admin.promptAudit.pool.credential') }}</p>
            <div class="flex items-center gap-1.5 text-xs font-medium" :class="credentialInvalid(endpoint) ? 'text-red-600 dark:text-red-300' : hasCredential(endpoint) ? 'text-emerald-700 dark:text-emerald-300' : 'text-gray-500 dark:text-dark-400'">
              <span class="h-1.5 w-1.5 rounded-full" :class="credentialInvalid(endpoint) ? 'bg-red-500' : hasCredential(endpoint) ? 'bg-emerald-500' : 'bg-gray-300 dark:bg-dark-500'" aria-hidden="true" />
              {{ credentialInvalid(endpoint) ? t('admin.promptAudit.pool.invalid') : hasCredential(endpoint) ? t('admin.promptAudit.pool.configured') : t('admin.promptAudit.pool.missing') }}
            </div>
            <p v-if="probingIds.includes(endpoint.id)" class="mt-1.5 text-xs text-primary-600 dark:text-primary-300">
              {{ t('admin.promptAudit.pool.probeProgress') }}
            </p>
            <p v-if="probeResults[endpoint.id]" class="mt-1.5 line-clamp-2 text-xs leading-5" :class="probeResults[endpoint.id].ok ? 'text-emerald-600 dark:text-emerald-300' : 'text-red-600 dark:text-red-300'">
              {{ t('admin.promptAudit.pool.probeResult', { status: probeResults[endpoint.id].status, http: probeResults[endpoint.id].http_status || '—', latency: probeResults[endpoint.id].latency_ms }) }}
              · {{ probeResults[endpoint.id].message }}
            </p>
          </div>

          <div class="endpoint-sticky-right flex flex-wrap items-center justify-end gap-1 border-t border-gray-100 pt-3 dark:border-dark-800 xl:flex-nowrap xl:border-0 xl:pt-0">
            <button type="button" class="btn btn-secondary btn-sm" :disabled="probingIds.includes(endpoint.id)" @click="$emit('probe', endpoint)">
              {{ probingIds.includes(endpoint.id) ? t('admin.promptAudit.pool.probing') : t('admin.promptAudit.pool.probe') }}
            </button>
            <button type="button" class="btn btn-ghost btn-sm" :data-test="`duplicate-endpoint-${endpoint.id}`" @click="duplicateEndpoint(endpoint)">{{ t('admin.promptAudit.pool.duplicate') }}</button>
            <button type="button" class="btn btn-ghost btn-sm" @click="openEdit(endpoint)">{{ t('common.edit') }}</button>
            <button type="button" class="btn btn-ghost btn-sm text-red-600 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-950/30" @click="removeEndpoint(endpoint)">{{ t('common.delete') }}</button>
          </div>
        </article>
      </div>
    </div>

    <BaseDialog :show="Boolean(editing)" :title="editingIndex < 0 ? t('admin.promptAudit.pool.add') : t('admin.promptAudit.pool.edit')" width="wide" @close="closeEditor">
      <form v-if="editing" class="grid gap-4 sm:grid-cols-2" @submit.prevent="saveEditor">
        <label class="block">
          <span class="input-label">{{ t('admin.promptAudit.pool.name') }}</span>
          <input v-model="editing.name" class="input w-full" required :aria-label="t('admin.promptAudit.pool.name')" />
        </label>
        <label class="block">
          <span class="input-label">{{ t('admin.promptAudit.pool.id') }}</span>
          <input v-model="editing.id" class="input w-full" required :disabled="editingIndex >= 0" :aria-label="t('admin.promptAudit.pool.id')" />
        </label>
        <label class="block sm:col-span-2">
          <span class="input-label">{{ t('admin.promptAudit.pool.priority') }}</span>
          <input
            v-model.number="editing.priority"
            data-test="endpoint-priority"
            class="input w-full"
            type="number"
            :min="MIN_ENDPOINT_PRIORITY"
            :max="MAX_ENDPOINT_PRIORITY"
            required
            :aria-label="t('admin.promptAudit.pool.priority')"
          />
          <span class="input-hint block">{{ t('admin.promptAudit.pool.priorityHint') }}</span>
        </label>
        <div class="sm:col-span-2">
          <label class="input-label">{{ t('admin.promptAudit.pool.adapter') }}</label>
          <Select
            :model-value="editing.adapter"
            :options="adapterOptions"
            :searchable="false"
            :aria-label="t('admin.promptAudit.pool.adapter')"
            data-test="endpoint-adapter"
            @update:model-value="changeAdapter($event as PromptAuditAdapter)"
          />
          <span class="input-hint block">{{ t(`admin.promptAudit.pool.adapterHints.${editing.adapter}`) }}</span>
        </div>
        <label class="block sm:col-span-2">
          <span class="input-label">{{ t('admin.promptAudit.pool.baseUrl') }}</span>
          <input v-model="editing.base_url" class="input w-full" required inputmode="url" :disabled="editing.credential_source === 'content_moderation'" :aria-label="t('admin.promptAudit.pool.baseUrl')" />
        </label>
        <label class="block sm:col-span-2">
          <span class="input-label">{{ t('admin.promptAudit.pool.apiKey') }}</span>
          <input v-model="editing.token" class="input w-full" type="password" autocomplete="new-password" :disabled="editing.credential_source === 'content_moderation'" :placeholder="editing.has_token ? (editing.token_status === 'invalid' ? t('admin.promptAudit.pool.reenterSecret') : t('admin.promptAudit.pool.keepSecret')) : ''" :aria-label="t('admin.promptAudit.pool.apiKey')" />
          <span class="input-hint block">{{ t('admin.promptAudit.pool.secretHint') }}</span>
        </label>
        <div v-if="editing.adapter === 'openai_moderation'" class="flex items-center justify-between gap-4 rounded-xl border border-gray-200 bg-gray-50/70 px-4 py-3 dark:border-dark-700 dark:bg-dark-900/40 sm:col-span-2">
          <span class="min-w-0">
            <span class="block text-sm font-medium text-gray-800 dark:text-dark-100">{{ t('admin.promptAudit.pool.reuseContentModerationCredential') }}</span>
            <span class="mt-0.5 block text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.pool.reuseContentModerationCredentialHint') }}</span>
          </span>
          <Toggle
            :model-value="editing.credential_source === 'content_moderation'"
            :aria-label="t('admin.promptAudit.pool.reuseContentModerationCredential')"
            data-test="reuse-content-moderation-credential"
            @update:model-value="toggleContentModerationCredential"
          />
        </div>
        <label v-if="editing.has_token && editing.credential_source !== 'content_moderation'" class="flex items-center gap-2 text-sm text-red-600 dark:text-red-300 sm:col-span-2">
          <input v-model="editing.clear_token" type="checkbox" class="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-dark-600 dark:bg-dark-800" :aria-label="t('admin.promptAudit.pool.clearSecret')" />
          {{ t('admin.promptAudit.pool.clearSecret') }}
        </label>
        <label class="block sm:col-span-2">
          <span class="input-label">{{ t('admin.promptAudit.pool.model') }}</span>
          <input v-model="editing.model" class="input w-full" :disabled="editing.credential_source === 'content_moderation'" :aria-label="t('admin.promptAudit.pool.model')" />
        </label>
        <label class="block">
          <span class="input-label">{{ t('admin.promptAudit.pool.timeout') }}</span>
          <input v-model.number="editing.timeout_ms" class="input w-full" type="number" min="100" max="40000" required :aria-label="t('admin.promptAudit.pool.timeout')" />
        </label>
        <label class="block">
          <span class="input-label">{{ t('admin.promptAudit.pool.inputLimit') }}</span>
          <input v-model.number="editing.input_limit" class="input w-full" type="number" min="128" max="400000" required :aria-label="t('admin.promptAudit.pool.inputLimit')" />
        </label>
        <p class="text-xs text-gray-500 dark:text-dark-400 sm:col-span-2">{{ t('admin.promptAudit.pool.limitBounds') }}</p>
      </form>
      <template #footer>
        <div class="flex justify-end gap-3">
          <button type="button" class="btn btn-secondary" @click="closeEditor">{{ t('common.cancel') }}</button>
          <button type="button" class="btn btn-primary" data-test="save-endpoint" :disabled="!editorValid" @click="saveEditor">{{ t('common.save') }}</button>
        </div>
      </template>
    </BaseDialog>
    <ConfirmDialog
      :show="Boolean(pendingDelete)"
      :title="t('common.delete')"
      :message="pendingDelete ? t('admin.promptAudit.pool.deleteConfirm', { name: pendingDelete.name }) : ''"
      :confirm-text="t('common.delete')"
      danger
      @confirm="confirmRemoveEndpoint"
      @cancel="pendingDelete = null"
    />
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import Select, { type SelectOption } from '@/components/common/Select.vue'
import Toggle from '@/components/common/Toggle.vue'
import type { PromptAuditAdapter, PromptAuditEndpointDraft, PromptProbeResult } from '../types'
import ColumnSettingsDropdown from './ColumnSettingsDropdown.vue'
import {
  cloneData,
  createDefaultEndpoint,
  enabledFailoverTimeoutMS,
  MAX_ENDPOINT_PRIORITY,
  MIN_ENDPOINT_PRIORITY,
  nextEndpointPriority,
  orderedPromptAuditEndpoints,
  RECOMMENDED_FAILOVER_TIMEOUT_MS,
} from '../viewModel'

const props = defineProps<{
  endpoints: PromptAuditEndpointDraft[]
  probeResults: Record<string, PromptProbeResult>
  probingIds: string[]
}>()
const emit = defineEmits<{
  (event: 'update:endpoints', value: PromptAuditEndpointDraft[]): void
  (event: 'probe', endpoint: PromptAuditEndpointDraft): void
}>()
const { t } = useI18n()
const editing = ref<PromptAuditEndpointDraft | null>(null)
const editingIndex = ref(-1)
const pendingDelete = ref<PromptAuditEndpointDraft | null>(null)
const hiddenEndpointColumns = ref<string[]>([])
const orderedEndpoints = computed(() => orderedPromptAuditEndpoints(props.endpoints))
const enabledEndpoints = computed(() => orderedEndpoints.value.filter((endpoint) => endpoint.enabled))
const enabledEndpointCount = computed(() => enabledEndpoints.value.length)
const enabledTimeoutMS = computed(() => enabledFailoverTimeoutMS(props.endpoints))
const timeoutWarning = computed(() => enabledTimeoutMS.value > RECOMMENDED_FAILOVER_TIMEOUT_MS)
const adapterOptions = computed<SelectOption[]>(() => [
  { value: 'confidence_json', label: t('admin.promptAudit.pool.adapters.confidence_json') },
  { value: 'qwen3guard', label: t('admin.promptAudit.pool.adapters.qwen3guard') },
  { value: 'openai_moderation', label: t('admin.promptAudit.pool.adapters.openai_moderation') },
])
const endpointColumns = computed(() => [
  { key: 'order', label: t('admin.promptAudit.pool.failoverOrder') },
  { key: 'node', label: t('admin.promptAudit.pool.node') },
  { key: 'model', label: t('admin.promptAudit.pool.model') },
  { key: 'limits', label: t('admin.promptAudit.pool.limits') },
  { key: 'credential', label: t('admin.promptAudit.pool.credential') },
  { key: 'actions', label: t('admin.promptAudit.common.actions') },
])
const endpointConfigurableColumns = computed(() => endpointColumns.value.filter((column) => !['node', 'actions'].includes(column.key)))
const endpointGridColumns = computed(() => endpointColumns.value
  .filter((column) => !hiddenEndpointColumns.value.includes(column.key) || ['node', 'actions'].includes(column.key))
  .map((column) => ({
    order: 'minmax(118px,.55fr)',
    node: 'minmax(240px,1.35fr)',
    model: 'minmax(180px,1fr)',
    limits: 'minmax(180px,.8fr)',
    credential: 'minmax(210px,1.1fr)',
    actions: 'max-content',
  }[column.key] ?? 'minmax(120px,1fr)')).join(' '))
const failoverPositions = computed(() => new Map(
  enabledEndpoints.value.map((endpoint, index) => [endpoint.id, index + 1]),
))
const editorValid = computed(() => {
  const endpoint = editing.value
  if (!endpoint?.id.trim() || !endpoint.name.trim() || !endpoint.base_url.trim()) return false
  return Number.isInteger(endpoint.priority)
    && endpoint.priority >= MIN_ENDPOINT_PRIORITY
    && endpoint.priority <= MAX_ENDPOINT_PRIORITY
    && Number.isInteger(endpoint.timeout_ms)
    && endpoint.timeout_ms >= 100
    && endpoint.timeout_ms <= 40000
    && Number.isInteger(endpoint.input_limit)
    && endpoint.input_limit >= 128
    && endpoint.input_limit <= 400000
})

function openCreate() {
  editingIndex.value = -1
  editing.value = createDefaultEndpoint(
    props.endpoints.length + 1,
    'confidence_json',
    nextEndpointPriority(props.endpoints),
  )
}

function isEndpointColumnVisible(key: string): boolean {
  return !hiddenEndpointColumns.value.includes(key) || ['node', 'actions'].includes(key)
}
function toggleEndpointColumn(key: string) {
  if (['node', 'actions'].includes(key)) return
  hiddenEndpointColumns.value = hiddenEndpointColumns.value.includes(key)
    ? hiddenEndpointColumns.value.filter((item) => item !== key)
    : [...hiddenEndpointColumns.value, key]
  try { localStorage.setItem('prompt-audit-endpoint-hidden-columns', JSON.stringify(hiddenEndpointColumns.value)) } catch { /* optional */ }
}
function duplicateEndpoint(endpoint: PromptAuditEndpointDraft) {
  const baseID = endpoint.id.trim() || 'guard'
  const existingIDs = new Set(props.endpoints.map((item) => item.id))
  const existingNames = new Set(props.endpoints.map((item) => item.name.trim()).filter(Boolean))
  let suffix = 1
  let id = `${baseID}-copy`
  while (existingIDs.has(id)) id = `${baseID}-copy-${suffix++}`
  const baseName = t('admin.promptAudit.pool.copyName', { name: endpoint.name.trim() || t('admin.promptAudit.pool.node') })
  let name = baseName
  let nameSuffix = 1
  while (existingNames.has(name)) name = `${baseName} ${nameSuffix++}`
  const duplicate: PromptAuditEndpointDraft = {
    ...cloneData(endpoint),
    id,
    name,
    enabled: false,
    token: '',
    has_token: false,
    token_status: 'missing',
    credential_source: '',
    clear_token: false,
  }
  emit('update:endpoints', [...props.endpoints.map((item) => cloneData(item)), duplicate])
}

function openEdit(endpoint: PromptAuditEndpointDraft) {
  editingIndex.value = props.endpoints.findIndex((item) => item.id === endpoint.id)
  editing.value = cloneData(endpoint)
}
function closeEditor() {
  editing.value = null
  editingIndex.value = -1
}
function changeAdapter(adapter: PromptAuditAdapter) {
  if (!editing.value || editing.value.adapter === adapter) return
  const previousDefaults = createDefaultEndpoint(0, editing.value.adapter)
  const nextDefaults = createDefaultEndpoint(0, adapter)
  editing.value = {
    ...editing.value,
    adapter,
    priority: editingIndex.value < 0 && adapter === 'openai_moderation' ? 3 : editing.value.priority,
    enabled: adapter === 'openai_moderation' ? false : editing.value.enabled,
    base_url: editing.value.base_url === previousDefaults.base_url ? nextDefaults.base_url : editing.value.base_url,
    model: editing.value.model === previousDefaults.model ? nextDefaults.model : editing.value.model,
    timeout_ms: editing.value.timeout_ms === previousDefaults.timeout_ms ? nextDefaults.timeout_ms : editing.value.timeout_ms,
    input_limit: editing.value.input_limit === previousDefaults.input_limit ? nextDefaults.input_limit : editing.value.input_limit,
    credential_source: nextDefaults.credential_source,
  }
}
function saveEditor() {
  if (!editing.value || !editorValid.value) return
  const next = props.endpoints.map((item) => cloneData(item))
  const value = cloneData(editing.value)
  if (value.token.trim()) {
    value.clear_token = false
    value.credential_source = ''
  }
  if (editingIndex.value < 0) next.push(value)
  else next.splice(editingIndex.value, 1, value)
  emit('update:endpoints', next)
  closeEditor()
}
function toggleEndpoint(id: string) {
  emit('update:endpoints', props.endpoints.map((item) => item.id === id ? { ...item, enabled: !item.enabled } : cloneData(item)))
}
function removeEndpoint(endpoint: PromptAuditEndpointDraft) {
  pendingDelete.value = cloneData(endpoint)
}
function confirmRemoveEndpoint() {
  const endpoint = pendingDelete.value
  if (!endpoint) return
  emit('update:endpoints', props.endpoints.filter((item) => item.id !== endpoint.id).map((item) => cloneData(item)))
  pendingDelete.value = null
}
function hasCredential(endpoint: PromptAuditEndpointDraft): boolean {
  return Boolean(endpoint.credential_source || endpoint.token.trim() || (endpoint.has_token && !endpoint.clear_token))
}
function credentialInvalid(endpoint: PromptAuditEndpointDraft): boolean {
  return !endpoint.credential_source && endpoint.token_status === 'invalid' && !endpoint.token.trim() && !endpoint.clear_token
}
function adapterLabel(adapter: PromptAuditAdapter): string {
  if (adapter === 'confidence_json') return 'JSON confidence'
  if (adapter === 'openai_moderation') return 'OpenAI Moderation'
  return 'Qwen3Guard'
}
function toggleContentModerationCredential(enabled: boolean) {
  if (!editing.value) return
  editing.value.credential_source = enabled ? 'content_moderation' : ''
  if (enabled) {
    editing.value.token = ''
    editing.value.clear_token = false
  }
}
function failoverPosition(id: string): number {
  return failoverPositions.value.get(id) ?? 0
}

onMounted(() => {
  try {
    const raw = localStorage.getItem('prompt-audit-endpoint-hidden-columns')
    const parsed = raw ? JSON.parse(raw) : []
    if (Array.isArray(parsed)) hiddenEndpointColumns.value = parsed.filter((item): item is string => typeof item === 'string' && endpointConfigurableColumns.value.some((column) => column.key === item))
  } catch { hiddenEndpointColumns.value = [] }
})
</script>

<style scoped>
.endpoint-sticky-left,
.endpoint-sticky-right {
  position: sticky;
  z-index: 2;
  background: rgb(255 255 255);
}

.endpoint-sticky-header {
  z-index: 3;
  background: rgb(249 250 251);
}

.endpoint-sticky-left {
  left: 0;
}

.endpoint-sticky-right {
  right: 0;
}

.dark .endpoint-sticky-left,
.dark .endpoint-sticky-right {
  background: rgb(17 24 39);
}

.dark .endpoint-sticky-header {
  background: rgb(17 24 39 / 0.7);
}

/* Keep the endpoint list in stacked card form below the desktop breakpoint;
   the inline grid template is only meaningful once the table has room for all
   columns. */
@media (max-width: 1279px) {
  .endpoint-grid {
    grid-template-columns: minmax(0, 1fr) !important;
  }
}
</style>

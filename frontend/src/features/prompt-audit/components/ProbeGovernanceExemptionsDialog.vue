<template>
  <BaseDialog
    :show="show"
    :title="t('admin.promptAudit.probeGovernance.exemptions.title', { name: group?.group_name || '' })"
    width="full"
    :close-on-click-outside="false"
    @close="close"
  >
    <div v-if="group" class="space-y-5" data-test="probe-governance-exemptions-dialog">
      <section class="rounded-xl border border-gray-200 bg-gray-50/60 p-4 dark:border-dark-700 dark:bg-dark-900/30 sm:p-5">
        <div>
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.probeGovernance.exemptions.addTitle') }}</h3>
          <p class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.probeGovernance.exemptions.description') }}</p>
        </div>
        <div class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div>
            <label class="input-label">{{ t('admin.promptAudit.probeGovernance.exemptions.targetType') }}</label>
            <Select v-model="targetType" :options="targetTypeOptions" :aria-label="t('admin.promptAudit.probeGovernance.exemptions.targetType')" @change="clearTarget" />
          </div>
          <div v-if="targetType === 'user'">
            <label class="input-label">{{ t('admin.promptAudit.probeGovernance.exemptions.user') }}</label>
            <Select
              :model-value="selectedUser?.id ?? null"
              :options="userOptions"
              :placeholder="t('admin.promptAudit.probeGovernance.exemptions.selectUser')"
              :search-placeholder="t('admin.usage.searchUserPlaceholder')"
              remote
              clearable
              :loading="usersLoading"
              :aria-label="t('admin.promptAudit.probeGovernance.exemptions.user')"
              data-test="probe-governance-exemption-user"
              @search="searchUsers"
              @change="selectUser"
            />
          </div>
          <div v-else>
            <label class="input-label">{{ t('admin.promptAudit.probeGovernance.exemptions.apiKey') }}</label>
            <Select
              :model-value="selectedAPIKey?.id ?? null"
              :options="apiKeyOptions"
              :placeholder="t('admin.promptAudit.probeGovernance.exemptions.selectApiKey')"
              :search-placeholder="t('admin.usage.searchApiKeyPlaceholder')"
              remote
              clearable
              :loading="apiKeysLoading"
              :aria-label="t('admin.promptAudit.probeGovernance.exemptions.apiKey')"
              data-test="probe-governance-exemption-api-key"
              @search="searchAPIKeys"
              @change="selectAPIKey"
            />
          </div>
          <Input v-model="reason" :label="t('admin.promptAudit.probeGovernance.exemptions.reason')" :placeholder="t('admin.promptAudit.probeGovernance.exemptions.reasonPlaceholder')" required data-test="probe-governance-exemption-reason" />
          <Input v-model="expiresAt" type="datetime-local" :label="t('admin.promptAudit.probeGovernance.exemptions.expiresAt')" :hint="t('admin.promptAudit.probeGovernance.exemptions.expiresAtHint')" :error="expiresAtError" :min="minimumExpiry" data-test="probe-governance-exemption-expires" />
        </div>
        <div class="mt-4 flex justify-end">
          <button type="button" class="btn btn-primary" :disabled="creating || !canCreate" data-test="probe-governance-exemption-add" @click="createExemption">
            {{ creating ? t('common.saving') : t('admin.promptAudit.probeGovernance.exemptions.add') }}
          </button>
        </div>
      </section>

      <section>
        <div class="mb-4 flex flex-wrap items-end justify-between gap-4">
          <div class="w-full sm:w-auto sm:min-w-[280px]">
            <Input v-model="keyword" :label="t('admin.promptAudit.probeGovernance.exemptions.search')" :placeholder="t('admin.promptAudit.probeGovernance.exemptions.searchPlaceholder')" data-test="probe-governance-exemption-search" @enter="applySearch" />
          </div>
          <div class="flex w-full flex-wrap items-center justify-end gap-3 sm:w-auto">
            <button type="button" class="btn btn-primary" data-test="probe-governance-exemption-search-submit" @click="applySearch">{{ t('common.search') }}</button>
            <button type="button" class="btn btn-secondary" @click="resetSearch">{{ t('common.reset') }}</button>
            <ColumnSettingsDropdown
              :label="t('admin.promptAudit.probeGovernance.columns')"
              :columns="configurableColumns"
              :is-visible="isColumnVisible"
              button-test="probe-governance-exemption-column-settings"
              menu-test="probe-governance-exemption-column-menu"
              @toggle="toggleColumn"
            />
          </div>
        </div>
        <div v-if="error" role="alert" class="mb-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">{{ error }}</div>
        <div class="overflow-hidden rounded-xl border border-gray-200 bg-white dark:border-dark-700 dark:bg-dark-900">
          <DataTable
            :columns="visibleColumns"
            :data="page.items"
            :loading="loading"
            row-key="id"
            :sticky-first-column="true"
            :sticky-actions-column="true"
            data-test="probe-governance-exemptions-table"
          >
            <template #cell-target="{ row }">
              <div class="min-w-0 max-w-64">
                <p class="truncate text-sm font-medium text-gray-900 dark:text-white" :title="targetName(row)">{{ targetName(row) }}</p>
                <p class="mt-1 font-mono text-xs text-gray-500 dark:text-dark-400">#{{ targetID(row) }}</p>
              </div>
            </template>
            <template #cell-type="{ row }">
              <span class="badge badge-gray">{{ row.api_key_id ? t('admin.promptAudit.probeGovernance.exemptions.apiKey') : t('admin.promptAudit.probeGovernance.exemptions.user') }}</span>
            </template>
            <template #cell-reason="{ row }"><p class="max-w-64 whitespace-normal break-words text-sm text-gray-700 dark:text-dark-200">{{ row.reason }}</p></template>
            <template #cell-expires="{ row }"><span class="whitespace-nowrap text-xs text-gray-600 dark:text-dark-300">{{ row.expires_at ? formatDate(row.expires_at) : t('admin.promptAudit.probeGovernance.exemptions.permanent') }}</span></template>
            <template #cell-created="{ row }">
              <div class="whitespace-nowrap text-xs text-gray-600 dark:text-dark-300">
                <p>{{ formatDate(row.created_at) }}</p>
                <p class="mt-1 text-gray-500 dark:text-dark-400">{{ row.created_by ? t('admin.promptAudit.probeGovernance.exemptions.operator', { id: row.created_by }) : '—' }}</p>
              </div>
            </template>
            <template #cell-actions="{ row }">
              <div class="flex justify-end">
                <button type="button" class="btn btn-ghost btn-sm text-red-600" @click.stop="pendingDelete = row">{{ t('common.remove') }}</button>
              </div>
            </template>
            <template #empty><div class="px-4 py-10 text-center text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.probeGovernance.exemptions.empty') }}</div></template>
          </DataTable>
          <Pagination
            :total="page.total"
            :page="page.page"
            :page-size="page.page_size"
            @update:page="changePage"
            @update:page-size="changePageSize"
          />
        </div>
      </section>
    </div>

    <template #footer>
      <button type="button" class="btn btn-primary" @click="close">{{ t('common.close') }}</button>
    </template>
  </BaseDialog>

  <ConfirmDialog
    :show="Boolean(pendingDelete)"
    :title="t('admin.promptAudit.probeGovernance.exemptions.removeTitle')"
    :message="t('admin.promptAudit.probeGovernance.exemptions.removeMessage', { name: pendingDelete ? targetName(pendingDelete) : '' })"
    :confirm-text="t('common.remove')"
    danger
    @confirm="removeExemption"
    @cancel="pendingDelete = null"
  />
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import type { SimpleApiKey, SimpleUser } from '@/api/admin/usage'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import DataTable from '@/components/common/DataTable.vue'
import Input from '@/components/common/Input.vue'
import Pagination from '@/components/common/Pagination.vue'
import Select, { type SelectOption } from '@/components/common/Select.vue'
import type { Column } from '@/components/common/types'
import { useAppStore } from '@/stores/app'
import { extractApiErrorMessage } from '@/utils/apiError'
import promptAuditAPI from '../api'
import type { ProbeGovernanceEventDetail, ProbeGovernanceExemption, ProbeGovernancePolicy } from '../types'
import ColumnSettingsDropdown from './ColumnSettingsDropdown.vue'

const props = defineProps<{
  show: boolean
  group: ProbeGovernancePolicy | null
  prefill: ProbeGovernanceEventDetail | null
}>()
const emit = defineEmits<{ (event: 'close'): void }>()
const { t, locale } = useI18n()
const appStore = useAppStore()

const targetType = ref<'user' | 'api_key'>('api_key')
const selectedUser = ref<SimpleUser | null>(null)
const selectedAPIKey = ref<SimpleApiKey | null>(null)
const userResults = ref<SimpleUser[]>([])
const apiKeyResults = ref<SimpleApiKey[]>([])
const usersLoading = ref(false)
const apiKeysLoading = ref(false)
const reason = ref('')
const expiresAt = ref('')
const keyword = ref('')
const appliedKeyword = ref('')
const hiddenColumns = ref<string[]>([])
const loading = ref(false)
const creating = ref(false)
const deleting = ref(false)
const error = ref('')
const pendingDelete = ref<ProbeGovernanceExemption | null>(null)
const page = reactive({ items: [] as ProbeGovernanceExemption[], total: 0, page: 1, page_size: 20, pages: 0 })
let userSearchSequence = 0
let apiKeySearchSequence = 0
let exemptionLoadSequence = 0

const targetTypeOptions = computed<SelectOption[]>(() => [
  { value: 'api_key', label: t('admin.promptAudit.probeGovernance.exemptions.apiKey') },
  { value: 'user', label: t('admin.promptAudit.probeGovernance.exemptions.user') },
])
const userOptions = computed<SelectOption[]>(() => {
  const options = userResults.value.map(userOption)
  if (selectedUser.value && !options.some((item) => item.value === selectedUser.value?.id)) options.unshift(userOption(selectedUser.value))
  return options
})
const apiKeyOptions = computed<SelectOption[]>(() => {
  const options = apiKeyResults.value.map(apiKeyOption)
  if (selectedAPIKey.value && !options.some((item) => item.value === selectedAPIKey.value?.id)) options.unshift(apiKeyOption(selectedAPIKey.value))
  return options
})
const expiresAtError = computed(() => {
  if (!expiresAt.value) return ''
  const timestamp = new Date(expiresAt.value).getTime()
  return Number.isFinite(timestamp) && timestamp > Date.now() ? '' : t('admin.promptAudit.probeGovernance.exemptions.expiresAtError')
})
const minimumExpiry = computed(() => formatLocalDateTime(new Date()))
const canCreate = computed(() => !expiresAtError.value && reason.value.trim().length > 0 && (targetType.value === 'user' ? Boolean(selectedUser.value) : Boolean(selectedAPIKey.value)))
const columns = computed<Column[]>(() => [
  { key: 'target', label: t('admin.promptAudit.probeGovernance.exemptions.target'), class: 'min-w-64' },
  { key: 'type', label: t('admin.promptAudit.probeGovernance.exemptions.targetType'), class: 'min-w-28' },
  { key: 'reason', label: t('admin.promptAudit.probeGovernance.exemptions.reason'), class: 'min-w-64' },
  { key: 'expires', label: t('admin.promptAudit.probeGovernance.exemptions.expiresAt'), class: 'min-w-40' },
  { key: 'created', label: t('admin.promptAudit.probeGovernance.exemptions.created'), class: 'min-w-48' },
  { key: 'actions', label: t('admin.promptAudit.common.actions'), class: 'min-w-28 text-right' },
])
const configurableColumns = computed(() => columns.value.filter((column) => !['target', 'actions'].includes(column.key)))
const visibleColumns = computed(() => columns.value.filter((column) => !hiddenColumns.value.includes(column.key) || ['target', 'actions'].includes(column.key)))

watch(() => [props.show, props.group?.group_id, props.prefill] as const, ([show]) => {
  if (!show || !props.group) {
    exemptionLoadSequence += 1
    loading.value = false
    return
  }
  resetForm()
  if (props.prefill) applyPrefill(props.prefill)
  page.page = 1
  void load()
}, { deep: true })
onMounted(() => {
  try {
    const parsed = JSON.parse(localStorage.getItem('prompt-audit-probe-exemption-hidden-columns') || '[]')
    if (Array.isArray(parsed)) hiddenColumns.value = parsed.filter((value): value is string => typeof value === 'string')
  } catch { /* optional */ }
})

async function load() {
  const group = props.group
  if (!group) return
  const sequence = ++exemptionLoadSequence
  const requestPage = page.page
  const requestPageSize = page.page_size
  const requestKeyword = appliedKeyword.value
  loading.value = true
  error.value = ''
  try {
    const result = await promptAuditAPI.listProbeGovernanceExemptions(group.group_id, requestPage, requestPageSize, requestKeyword)
    if (sequence !== exemptionLoadSequence) return
    Object.assign(page, result)
  } catch (caught) {
    if (sequence !== exemptionLoadSequence) return
    error.value = extractApiErrorMessage(caught, t('admin.promptAudit.probeGovernance.errors.loadExemptions'))
  } finally {
    if (sequence === exemptionLoadSequence) loading.value = false
  }
}
function close() {
  if (!loading.value && !creating.value && !deleting.value) {
    exemptionLoadSequence += 1
    emit('close')
  }
}
function resetForm() {
  userSearchSequence += 1
  apiKeySearchSequence += 1
  usersLoading.value = false
  apiKeysLoading.value = false
  targetType.value = 'api_key'; selectedUser.value = null; selectedAPIKey.value = null; reason.value = ''; expiresAt.value = ''; userResults.value = []; apiKeyResults.value = []
}
function clearTarget() {
  userSearchSequence += 1
  apiKeySearchSequence += 1
  usersLoading.value = false
  apiKeysLoading.value = false
  selectedUser.value = null; selectedAPIKey.value = null; userResults.value = []; apiKeyResults.value = []
}
function applyPrefill(event: ProbeGovernanceEventDetail) {
  if (event.api_key_id) {
    targetType.value = 'api_key'
    selectedAPIKey.value = { id: event.api_key_id, name: event.api_key_name || '', user_id: event.user_id || 0 }
  } else if (event.user_id) {
    targetType.value = 'user'
    selectedUser.value = { id: event.user_id, email: event.user_email || '', deleted: false }
  }
  reason.value = t('admin.promptAudit.probeGovernance.exemptions.eventReason')
}
async function createExemption() {
  if (!props.group || !canCreate.value || creating.value) return
  const expires = expiresAt.value ? new Date(expiresAt.value) : null
  if (expires && (!Number.isFinite(expires.getTime()) || expires.getTime() <= Date.now())) return
  creating.value = true
  try {
    await promptAuditAPI.createProbeGovernanceExemption(props.group.group_id, {
      ...(targetType.value === 'user' && selectedUser.value ? { user_id: selectedUser.value.id } : {}),
      ...(targetType.value === 'api_key' && selectedAPIKey.value ? { api_key_id: selectedAPIKey.value.id } : {}),
      reason: reason.value.trim(),
      ...(expires && !Number.isNaN(expires.getTime()) ? { expires_at: expires.toISOString() } : {}),
    })
    appStore.showSuccess(t('admin.promptAudit.probeGovernance.messages.exemptionAdded'))
    resetForm()
    page.page = 1
    await load()
  } catch (caught) { appStore.showError(extractApiErrorMessage(caught, t('admin.promptAudit.probeGovernance.errors.createExemption'))) }
  finally { creating.value = false }
}
async function removeExemption() {
  if (!props.group || !pendingDelete.value || deleting.value) return
  deleting.value = true
  const exemptionID = pendingDelete.value.id
  pendingDelete.value = null
  try {
    await promptAuditAPI.deleteProbeGovernanceExemption(props.group.group_id, exemptionID)
    appStore.showSuccess(t('admin.promptAudit.probeGovernance.messages.exemptionRemoved'))
    await load()
  } catch (caught) { appStore.showError(extractApiErrorMessage(caught, t('admin.promptAudit.probeGovernance.errors.deleteExemption'))) }
  finally { deleting.value = false }
}
function applySearch() { appliedKeyword.value = keyword.value.trim(); page.page = 1; void load() }
function resetSearch() { keyword.value = ''; appliedKeyword.value = ''; page.page = 1; void load() }
function changePage(value: number) { page.page = value; void load() }
function changePageSize(value: number) { page.page_size = value; page.page = 1; void load() }
function isColumnVisible(key: string): boolean { return !hiddenColumns.value.includes(key) || ['target', 'actions'].includes(key) }
function toggleColumn(key: string) {
  if (['target', 'actions'].includes(key)) return
  hiddenColumns.value = hiddenColumns.value.includes(key) ? hiddenColumns.value.filter((value) => value !== key) : [...hiddenColumns.value, key]
  try { localStorage.setItem('prompt-audit-probe-exemption-hidden-columns', JSON.stringify(hiddenColumns.value)) } catch { /* optional */ }
}
async function searchUsers(query: string) {
  const sequence = ++userSearchSequence
  const keywordValue = query.trim()
  if (!keywordValue) { userResults.value = []; usersLoading.value = false; return }
  usersLoading.value = true
  try { const result = await adminAPI.usage.searchUsers(keywordValue); if (sequence === userSearchSequence) userResults.value = result }
  catch { if (sequence === userSearchSequence) userResults.value = [] }
  finally { if (sequence === userSearchSequence) usersLoading.value = false }
}
async function searchAPIKeys(query: string) {
  const sequence = ++apiKeySearchSequence
  const keywordValue = query.trim()
  if (!keywordValue) { apiKeyResults.value = []; apiKeysLoading.value = false; return }
  apiKeysLoading.value = true
  try { const result = await adminAPI.usage.searchApiKeys(undefined, keywordValue); if (sequence === apiKeySearchSequence) apiKeyResults.value = result }
  catch { if (sequence === apiKeySearchSequence) apiKeyResults.value = [] }
  finally { if (sequence === apiKeySearchSequence) apiKeysLoading.value = false }
}
function selectUser(value: string | number | boolean | null, option: SelectOption | null) {
  selectedUser.value = typeof value === 'number' ? { id: value, email: String(option?.email || ''), deleted: Boolean(option?.deleted) } : null
}
function selectAPIKey(value: string | number | boolean | null, option: SelectOption | null) {
  selectedAPIKey.value = typeof value === 'number' ? { id: value, name: String(option?.name || ''), user_id: Number(option?.userID || 0) } : null
}
function userOption(user: SimpleUser): SelectOption { return { value: user.id, label: `${user.email} · #${user.id}`, email: user.email, deleted: user.deleted } }
function apiKeyOption(key: SimpleApiKey): SelectOption { return { value: key.id, label: `${key.name.trim() || t('admin.promptAudit.probeGovernance.events.unnamedApiKey')} · #${key.id}`, name: key.name, userID: key.user_id } }
function targetName(item: ProbeGovernanceExemption): string { return item.api_key_id ? item.api_key_name || t('admin.promptAudit.probeGovernance.events.unnamedApiKey') : item.user_email || t('admin.promptAudit.probeGovernance.events.unknownUser') }
function targetID(item: ProbeGovernanceExemption): number | string { return item.api_key_id || item.user_id || '—' }
function formatDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(locale.value.startsWith('zh') ? 'zh-CN' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}
function formatLocalDateTime(date: Date): string {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}
</script>

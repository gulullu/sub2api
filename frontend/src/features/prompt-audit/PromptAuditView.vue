<template>
  <AppLayout>
    <div class="w-full min-w-0 space-y-6 pb-8">
      <header class="page-header mb-0 rounded-3xl bg-white p-5 shadow-sm ring-1 ring-gray-900/5 dark:bg-dark-800 dark:ring-dark-700 sm:p-6">
        <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 class="page-title flex items-center gap-2 text-xl font-black text-gray-900 dark:text-white">
              <span class="inline-flex h-8 w-8 items-center justify-center rounded-xl bg-primary-50 text-primary-600 dark:bg-primary-900/30 dark:text-primary-300">
                <Icon name="shield" size="sm" />
              </span>
              {{ t('admin.promptAudit.title') }}
            </h1>
            <p class="page-description mt-1.5 max-w-3xl text-xs text-gray-500 dark:text-gray-400">{{ t('admin.promptAudit.description') }}</p>
          </div>
          <div v-if="draft" class="flex items-center gap-3 text-xs text-gray-500 dark:text-gray-400 lg:justify-end">
            <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-1 font-medium text-gray-600 dark:bg-dark-700 dark:text-gray-300">
              {{ t('admin.promptAudit.configVersion', { version: draft.config_version }) }}
            </span>
            <span v-if="draft.updated_at">{{ formatDate(draft.updated_at) }}</span>
          </div>
        </div>

        <div class="mt-4 border-t border-gray-100 pt-4 dark:border-dark-700" role="tablist" :aria-label="t('admin.promptAudit.title')">
          <div class="tabs inline-flex w-full flex-wrap sm:w-auto">
            <button
              v-for="tab in pageTabs"
              :key="tab.id"
              type="button"
              role="tab"
              class="tab flex-1 sm:flex-none"
              :class="{ 'tab-active': activeTab === tab.id }"
              :aria-selected="activeTab === tab.id"
              :tabindex="activeTab === tab.id ? 0 : -1"
              :data-test="`tab-${tab.id}`"
              @click="activeTab = tab.id"
            >
              {{ tab.label }}
            </button>
          </div>
        </div>
      </header>

      <div v-if="loadErrors.config && !draft" role="alert" class="rounded-xl border border-red-200 bg-red-50 p-5 dark:border-red-900 dark:bg-red-950/30">
        <p class="text-sm text-red-700 dark:text-red-300">{{ loadErrors.config }}</p>
        <button type="button" class="btn btn-secondary btn-sm mt-3" @click="loadConfig">{{ t('admin.promptAudit.actions.retry') }}</button>
      </div>

      <template v-else>
        <main>
          <div v-show="activeTab === 'config'" class="card px-4 sm:px-6 lg:px-8" data-test="tab-panel-config">
            <RuntimeOverview :runtime="runtime" :loading="loading.runtime" :error="loadErrors.runtime" @refresh="loadRuntime" />

            <template v-if="draft">
              <EndpointPool
                :endpoints="draft.endpoints"
                :probe-results="probeResults"
                :probing-ids="probingIds"
                @update:endpoints="updateEndpoints"
                @probe="runProbe"
              />
              <PromptTemplatePanel :draft="draft" @update:draft="replaceDraft" />
              <GroupPolicyWorkspace
                :draft="draft"
                :groups="groups"
                :accounts="riskRouteAccounts"
                :accounts-loaded="riskRouteAccountsLoaded"
                :accounts-loading="loading.accounts"
                :accounts-error="loadErrors.accounts"
                @update:draft="replaceDraft"
                @retry-accounts="loadRiskRouteAccounts"
              />
              <div v-if="loadErrors.groups" role="alert" class="mt-5 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">{{ loadErrors.groups }}</div>
              <ProbeGovernanceWorkspace
                :draft="serverConfig || draft"
                :groups="groups"
                @view-audit-event="openEvent"
              />
            </template>
          </div>

          <div v-show="activeTab === 'events'" class="space-y-6" data-test="tab-panel-events">
            <div
              v-if="draft?.enabled && !draft.store_pass_events"
              data-test="pass-events-disabled-notice"
              role="status"
              class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:border-amber-900/70 dark:bg-amber-950/30 dark:text-amber-200"
            >
              <span>{{ t('admin.promptAudit.events.passEventsDisabled') }}</span>
              <button type="button" class="btn btn-secondary btn-sm" @click="activeTab = 'config'">
                {{ t('admin.promptAudit.events.openConfiguration') }}
              </button>
            </div>
            <EventWorkspace
              :events="events.items"
              :total="events.total"
              :page="events.page"
              :page-size="events.page_size"
              :filters="filters"
              :groups="groups"
              :endpoints="draft?.endpoints ?? []"
              :selected-ids="selectedEventIds"
              :loading="loading.events"
              :error="loadErrors.events"
              @filters-change="handleFiltersChanged"
              @search="applyEventFilters"
              @selection="selectedEventIds = $event"
              @page="changePage"
              @page-size="changePageSize"
              @view="openEvent"
              @delete="requestSingleDelete"
              @batch-delete="requestBatchDelete"
              @preview-delete="requestFilterDeletePreview"
            />
          </div>

          <div v-if="activeTab === 'cyber'" data-test="tab-panel-cyber">
            <CyberLearningWorkspace
              :initial-event-id="initialCyberFeedbackId"
              :groups="groups"
              :accounts="riskRouteAccounts"
            />
          </div>
        </main>
      </template>
    </div>

    <div v-if="draft && activeTab === 'config'" class="sticky bottom-4 z-30 w-full rounded-2xl border border-gray-200 bg-white/95 px-4 py-3 shadow-xl backdrop-blur dark:border-dark-700 dark:bg-dark-900/95">
      <div class="flex w-full flex-wrap items-center justify-between gap-3">
        <div class="flex flex-wrap items-center gap-x-5 gap-y-2">
          <div class="flex items-center gap-2.5 text-sm text-gray-700 dark:text-dark-200">
            <Toggle :model-value="draft.enabled" :aria-label="t('admin.promptAudit.saveBar.enabled')" data-test="enabled-toggle" @update:model-value="setEnabled" />
            <span>{{ t('admin.promptAudit.saveBar.enabled') }}</span>
          </div>
          <div class="flex items-center gap-2.5 text-sm text-gray-700 dark:text-dark-200" :class="{ 'opacity-50': !draft.enabled }">
            <Toggle :model-value="draft.blocking_enabled" :disabled="!draft.enabled" :aria-label="t('admin.promptAudit.saveBar.blocking')" data-test="blocking-toggle" @update:model-value="setBlocking" />
            <span>{{ t('admin.promptAudit.saveBar.blocking') }}</span>
          </div>
          <div class="flex items-center gap-2.5 text-sm text-gray-700 dark:text-dark-200" :class="{ 'opacity-50': !draft.enabled || !draft.blocking_enabled }">
            <Toggle :model-value="draft.blocking_latest_turn_only" :disabled="!draft.enabled || !draft.blocking_enabled" :aria-label="t('admin.promptAudit.saveBar.blockingLatestTurnOnly')" data-test="blocking-latest-turn-only-toggle" @update:model-value="replaceDraft({ ...draft!, blocking_latest_turn_only: $event })" />
            <span>{{ t('admin.promptAudit.saveBar.blockingLatestTurnOnly') }}</span>
          </div>
          <div class="flex items-center gap-2.5 text-sm text-gray-700 dark:text-dark-200">
            <Toggle :model-value="draft.store_pass_events" :aria-label="t('admin.promptAudit.saveBar.storePass')" data-test="store-pass-toggle" @update:model-value="replaceDraft({ ...draft!, store_pass_events: $event })" />
            <span>{{ t('admin.promptAudit.saveBar.storePass') }}</span>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <span class="text-sm" :class="dirty ? 'text-amber-700 dark:text-amber-300' : 'text-gray-500 dark:text-dark-400'">
            {{ dirty ? t('admin.promptAudit.saveBar.dirty') : t('admin.promptAudit.saveBar.synced') }}
          </span>
          <button type="button" class="btn btn-secondary" :disabled="!dirty || loading.saving" @click="resetDraft">{{ t('common.reset') }}</button>
          <button type="button" class="btn btn-primary" :disabled="!dirty || loading.saving" data-test="save-config" @click="saveConfig">
            {{ loading.saving ? t('common.saving') : t('common.save') }}
          </button>
        </div>
      </div>
    </div>

    <ConfirmDialog
      :show="showBlockingConfirmation"
      :title="t('admin.promptAudit.blockingConfirm.title')"
      :message="t('admin.promptAudit.blockingConfirm.message')"
      :confirm-text="t('admin.promptAudit.blockingConfirm.confirm')"
      danger
      @confirm="confirmBlocking"
      @cancel="showBlockingConfirmation = false"
    />
    <ConfirmDialog
      :show="deleteRequest.mode !== ''"
      :title="t('admin.promptAudit.events.deleteConfirmTitle')"
      :message="t('admin.promptAudit.events.deleteConfirmMessage', { count: deleteRequest.ids.length })"
      :confirm-text="t('common.delete')"
      danger
      @confirm="confirmIDDelete"
      @cancel="clearDeleteRequest"
    />
    <FilterDeleteDialog
      :show="showFilterDelete"
      :initial-filters="filters"
      :groups="groups"
      :preview="deletePreview"
      :previewing="loading.previewing"
      :deleting="loading.deleting"
      @close="closeFilterDelete"
      @preview="runFilterDeletePreview"
      @confirm="confirmFilterDelete"
      @criteria-change="clearDeletePreview"
    />
    <EventDetailDialog :show="showEventDetail" :event="activeEvent" :loading="loading.detail" @close="closeEventDetail" />
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import Toggle from '@/components/common/Toggle.vue'
import Icon from '@/components/icons/Icon.vue'
import { useAppStore } from '@/stores/app'
import { extractApiErrorCode, extractApiErrorMessage } from '@/utils/apiError'
import RuntimeOverview from './components/RuntimeOverview.vue'
import EndpointPool from './components/EndpointPool.vue'
import PromptTemplatePanel from './components/PromptTemplatePanel.vue'
import GroupPolicyWorkspace from './components/GroupPolicyWorkspace.vue'
import ProbeGovernanceWorkspace from './components/ProbeGovernanceWorkspace.vue'
import EventWorkspace from './components/EventWorkspace.vue'
import EventDetailDialog from './components/EventDetailDialog.vue'
import FilterDeleteDialog from './components/FilterDeleteDialog.vue'
import CyberLearningWorkspace from './components/CyberLearningWorkspace.vue'
import promptAuditAPI from './api'
import type {
  PromptAuditDraft,
  PromptAuditEndpointDraft,
  PromptAuditEvent,
  PromptAuditGroup,
  PromptAuditAccount,
  PromptAuditRuntime,
  PromptDeletePreview,
  PromptEventFilters,
  PromptEventPage,
  PromptLoadErrors,
  PromptProbeResult,
} from './types'
import { buildUpdateRequest, cloneData, configToDraft, draftFingerprint, emptyEventFilters } from './viewModel'

const { t, locale } = useI18n()
const appStore = useAppStore()
type PromptAuditPageTab = 'config' | 'events' | 'cyber'
const initialQuery = new URLSearchParams(window.location.search)
const parsedCyberFeedbackId = Number(initialQuery.get('cyber_feedback_id'))
const initialCyberFeedbackId = Number.isSafeInteger(parsedCyberFeedbackId) && parsedCyberFeedbackId > 0 ? parsedCyberFeedbackId : null
const activeTab = ref<PromptAuditPageTab>(initialQuery.get('tab') === 'cyber' || initialCyberFeedbackId ? 'cyber' : 'events')
const pageTabs = computed(() => [
  { id: 'events' as const, label: t('admin.promptAudit.tabs.events') },
  { id: 'cyber' as const, label: t('admin.promptAudit.tabs.cyber') },
  { id: 'config' as const, label: t('admin.promptAudit.tabs.config') },
])
const serverConfig = ref<PromptAuditDraft | null>(null)
const draft = ref<PromptAuditDraft | null>(null)
const runtime = ref<PromptAuditRuntime | null>(null)
const groups = ref<PromptAuditGroup[]>([])
const riskRouteAccounts = ref<PromptAuditAccount[]>([])
const riskRouteAccountsLoaded = ref(false)
const events = reactive<PromptEventPage>({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
const filters = ref<PromptEventFilters>(emptyEventFilters())
const appliedFilters = ref<PromptEventFilters>(emptyEventFilters())
const selectedEventIds = ref<number[]>([])
const activeEvent = ref<PromptAuditEvent | null>(null)
const showEventDetail = ref(false)
const probeResults = reactive<Record<string, PromptProbeResult>>({})
const probingIds = ref<string[]>([])
const showFilterDelete = ref(false)
const deletePreview = ref<PromptDeletePreview | null>(null)
const deletePreviewFilters = ref<PromptEventFilters | null>(null)
const showBlockingConfirmation = ref(false)
const deleteRequest = reactive<{ mode: '' | 'single' | 'batch'; ids: number[] }>({ mode: '', ids: [] })
const loading = reactive({ config: false, runtime: false, groups: false, accounts: false, events: false, saving: false, detail: false, deleting: false, previewing: false })
const loadErrors = reactive<PromptLoadErrors>({ config: '', runtime: '', groups: '', accounts: '', events: '' })
const dirty = computed(() => draftFingerprint(draft.value) !== draftFingerprint(serverConfig.value))

function errorMessage(error: unknown, fallbackKey: string): string {
  const code = extractApiErrorCode(error)
  if (code) {
    const key = `admin.promptAudit.errors.${code}`
    const translated = t(key)
    if (translated !== key) return translated
  }
  return extractApiErrorMessage(error, t(fallbackKey))
}

async function loadConfig() {
  loading.config = true
  loadErrors.config = ''
  try {
    const config = await promptAuditAPI.getConfig()
    serverConfig.value = configToDraft(config)
    draft.value = configToDraft(config)
  } catch (error) {
    loadErrors.config = errorMessage(error, 'admin.promptAudit.errors.loadConfig')
  } finally {
    loading.config = false
  }
}
async function loadRuntime() {
  loading.runtime = true
  loadErrors.runtime = ''
  try { runtime.value = await promptAuditAPI.getRuntime() }
  catch (error) { loadErrors.runtime = errorMessage(error, 'admin.promptAudit.errors.loadRuntime') }
  finally { loading.runtime = false }
}
async function loadGroups() {
  loading.groups = true
  loadErrors.groups = ''
  try { groups.value = await promptAuditAPI.listGroups() }
  catch (error) { loadErrors.groups = errorMessage(error, 'admin.promptAudit.errors.loadGroups') }
  finally { loading.groups = false }
}
async function loadRiskRouteAccounts() {
  loading.accounts = true
  loadErrors.accounts = ''
  try {
    riskRouteAccounts.value = await promptAuditAPI.listRiskRouteAccounts()
    riskRouteAccountsLoaded.value = true
  } catch (error) {
    loadErrors.accounts = errorMessage(error, 'admin.promptAudit.errors.loadAccounts')
  } finally {
    loading.accounts = false
  }
}
async function loadEvents() {
  loading.events = true
  loadErrors.events = ''
  try {
    const result = await promptAuditAPI.listEvents(appliedFilters.value, events.page, events.page_size)
    Object.assign(events, result)
    selectedEventIds.value = []
  } catch (error) {
    loadErrors.events = errorMessage(error, 'admin.promptAudit.errors.loadEvents')
  } finally {
    loading.events = false
  }
}
async function loadInitial() {
  await Promise.allSettled([loadConfig(), loadRuntime(), loadGroups(), loadRiskRouteAccounts(), loadEvents()])
}

function replaceDraft(value: PromptAuditDraft) { draft.value = cloneData(value) }
function updateEndpoints(value: PromptAuditEndpointDraft[]) {
  if (!draft.value) return
  replaceDraft({ ...draft.value, endpoints: value })
}
function setEnabled(value: boolean) {
  if (!draft.value) return
  replaceDraft({ ...draft.value, enabled: value, blocking_enabled: value ? draft.value.blocking_enabled : false })
}
function setBlocking(value: boolean) {
  if (!draft.value || !draft.value.enabled) return
  if (value && !draft.value.blocking_enabled) { showBlockingConfirmation.value = true; return }
  replaceDraft({ ...draft.value, blocking_enabled: value })
}
function confirmBlocking() {
  showBlockingConfirmation.value = false
  if (draft.value) replaceDraft({ ...draft.value, blocking_enabled: true })
}
function resetDraft() {
  if (serverConfig.value) draft.value = cloneData(serverConfig.value)
}
async function saveConfig() {
  if (!draft.value || !dirty.value) return
  loading.saving = true
  try {
    const saved = await promptAuditAPI.updateConfig(buildUpdateRequest(draft.value))
    serverConfig.value = configToDraft(saved)
    draft.value = configToDraft(saved)
    appStore.showSuccess(t('admin.promptAudit.messages.saved'))
    await loadRuntime()
  } catch (error) {
    const code = extractApiErrorCode(error)
    appStore.showError(errorMessage(error, code === 'prompt_audit_config_conflict' ? 'admin.promptAudit.errors.prompt_audit_config_conflict' : 'admin.promptAudit.errors.saveConfig'))
  } finally {
    loading.saving = false
  }
}
async function runProbe(endpoint: PromptAuditEndpointDraft) {
  if (probingIds.value.includes(endpoint.id)) return
  probingIds.value = [...probingIds.value, endpoint.id]
  try {
    const result = await promptAuditAPI.probeEndpoint(endpoint)
    probeResults[endpoint.id] = result
    if (result.ok) appStore.showSuccess(t('admin.promptAudit.messages.probeSucceeded'))
    else appStore.showError(`${result.error_code || result.status}: ${result.message}`)
  } catch (error) {
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.probe'))
  } finally {
    probingIds.value = probingIds.value.filter((id) => id !== endpoint.id)
  }
}

function handleFiltersChanged(value: PromptEventFilters) {
  filters.value = cloneData(value)
  clearDeletePreview()
}
function applyEventFilters(value: PromptEventFilters) {
  filters.value = cloneData(value)
  appliedFilters.value = cloneData(value)
  events.page = 1
  clearDeletePreview()
  void loadEvents()
}
function changePage(value: number) { events.page = value; void loadEvents() }
function changePageSize(value: number) { events.page_size = value; events.page = 1; void loadEvents() }
async function openEvent(id: number) {
  showEventDetail.value = true
  loading.detail = true
  activeEvent.value = null
  try { activeEvent.value = await promptAuditAPI.getEvent(id) }
  catch (error) { appStore.showError(errorMessage(error, 'admin.promptAudit.errors.loadDetail')); showEventDetail.value = false }
  finally { loading.detail = false }
}
function closeEventDetail() { showEventDetail.value = false; activeEvent.value = null }
function requestSingleDelete(id: number) { deleteRequest.mode = 'single'; deleteRequest.ids = [id] }
function requestBatchDelete() { if (selectedEventIds.value.length) { deleteRequest.mode = 'batch'; deleteRequest.ids = [...selectedEventIds.value] } }
function clearDeleteRequest() { deleteRequest.mode = ''; deleteRequest.ids = [] }
async function confirmIDDelete() {
  const mode = deleteRequest.mode
  const ids = [...deleteRequest.ids]
  clearDeleteRequest()
  if (!mode || ids.length === 0) return
  loading.deleting = true
  try {
    const result = mode === 'single' ? await promptAuditAPI.deleteEvent(ids[0]) : await promptAuditAPI.batchDeleteEvents(ids)
    appStore.showSuccess(t('admin.promptAudit.messages.deleted', { count: result.deleted_events }))
    await Promise.allSettled([loadEvents(), loadRuntime()])
  } catch (error) { appStore.showError(errorMessage(error, 'admin.promptAudit.errors.delete')) }
  finally { loading.deleting = false }
}
function clearDeletePreview() {
  deletePreview.value = null
  deletePreviewFilters.value = null
}
function requestFilterDeletePreview() {
  clearDeletePreview()
  showFilterDelete.value = true
}
function closeFilterDelete() {
  showFilterDelete.value = false
  clearDeletePreview()
}
async function runFilterDeletePreview(value: PromptEventFilters) {
  loading.previewing = true
  try {
    deletePreview.value = await promptAuditAPI.previewDelete(value)
    deletePreviewFilters.value = cloneData(value)
  } catch (error) {
    clearDeletePreview()
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.previewDelete'))
  } finally { loading.previewing = false }
}
async function confirmFilterDelete(filters?: PromptEventFilters) {
  if (loading.deleting) return
  loading.deleting = true
  try {
    let preview = deletePreview.value
    let previewFilters = deletePreviewFilters.value ? cloneData(deletePreviewFilters.value) : null
    // One-click path: no fresh preview (never requested, or cleared by a
    // criteria change) — mint the confirmation token on the fly from the
    // criteria the dialog just emitted, then delete in the same action.
    if ((!preview || !previewFilters) && filters) {
      preview = await promptAuditAPI.previewDelete(filters)
      previewFilters = cloneData(filters)
    }
    if (!preview || !previewFilters) return
    const result = await promptAuditAPI.deleteEventsByFilter(previewFilters, preview)
    closeFilterDelete()
    appStore.showSuccess(t('admin.promptAudit.messages.deleted', { count: result.deleted_events }))
    await Promise.allSettled([loadEvents(), loadRuntime()])
  } catch (error) {
    clearDeletePreview()
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.deleteConfirmation'))
  } finally { loading.deleting = false }
}
function formatDate(value: string): string {
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value))
}

onMounted(loadInitial)
</script>

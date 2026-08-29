<template>
  <section aria-labelledby="prompt-risk-route-title" class="border-b border-gray-200 py-6 dark:border-dark-700/60">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="prompt-risk-route-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.riskRoute.title') }}</h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.riskRoute.description') }}</p>
      </div>
      <span class="rounded-full px-2.5 py-1 text-xs font-semibold" :class="selectedIDs.length ? 'bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-200' : 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-dark-200'">
        {{ selectedIDs.length ? t('admin.promptAudit.riskRoute.selectedCount', { count: selectedIDs.length }) : t('admin.promptAudit.riskRoute.off') }}
      </span>
    </div>

    <div class="mt-5 rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5">
      <div v-if="!editable" data-test="risk-route-blocking-required" class="mb-4 rounded-lg bg-gray-50 px-3 py-2 text-sm text-gray-600 dark:bg-dark-900/50 dark:text-dark-300">
        {{ t('admin.promptAudit.riskRoute.blockingRequired') }}
      </div>

      <div v-if="selectedRows.length" class="mb-4">
        <p class="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.riskRoute.selected') }}</p>
        <div class="mt-2 flex flex-wrap gap-2">
          <div
            v-for="row in selectedRows"
            :key="row.id"
            :data-test="`risk-route-selected-${row.id}`"
            class="flex max-w-full items-center gap-2 rounded-lg border px-2.5 py-1.5 text-sm"
            :class="row.invalid ? 'border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/30 dark:text-red-200' : 'border-gray-200 bg-white text-gray-800 dark:border-dark-700 dark:bg-dark-900 dark:text-dark-100'"
          >
            <span class="min-w-0 max-w-full">
              <span class="block truncate font-medium">{{ row.account?.name || missingAccountLabel(row.id) }}</span>
              <span v-if="row.account" class="block truncate text-[11px] text-gray-500 dark:text-dark-400">#{{ row.id }} · {{ row.account.platform }} / {{ row.account.type }}</span>
              <span v-if="row.account" class="mt-1 flex max-w-full flex-wrap gap-1" :aria-label="t('admin.promptAudit.riskRoute.groups')">
                <span
                  v-for="group in row.account.groups"
                  :key="group.id"
                  class="max-w-full truncate rounded bg-gray-100 px-1.5 py-0.5 text-[10px] font-medium text-gray-600 dark:bg-dark-700 dark:text-dark-200"
                  :title="groupLabel(group)"
                >{{ groupLabel(group) }}</span>
                <span v-if="row.account.groups.length === 0" class="text-[10px] text-gray-400 dark:text-dark-500">{{ t('admin.promptAudit.riskRoute.noGroup') }}</span>
              </span>
            </span>
            <button
              type="button"
              class="ml-1 rounded p-1 leading-none hover:bg-black/5 disabled:cursor-not-allowed disabled:opacity-40 dark:hover:bg-white/10"
              :disabled="!editable"
              :aria-label="t('admin.promptAudit.riskRoute.remove', { id: row.id })"
              @click="remove(row.id)"
            >
              ×
            </button>
          </div>
        </div>
      </div>

      <label class="block">
        <span class="input-label">{{ t('admin.promptAudit.riskRoute.search') }}</span>
        <input v-model="search" type="search" class="input w-full" :disabled="!editable || loading" :aria-label="t('admin.promptAudit.riskRoute.search')" />
      </label>

      <div v-if="error" role="alert" class="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-200">
        <span>{{ error }}</span>
        <button type="button" class="btn btn-secondary btn-sm" @click="$emit('retry')">{{ t('admin.promptAudit.actions.retry') }}</button>
      </div>
      <div v-else-if="loading" class="mt-3 rounded-lg border border-gray-200 px-3 py-6 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-300" aria-busy="true">
        {{ t('admin.promptAudit.riskRoute.loading') }}
      </div>
      <div v-else class="mt-3 max-h-64 overflow-y-auto rounded-lg border border-gray-200 p-2 dark:border-dark-700" data-test="risk-route-account-list">
        <label
          v-for="account in visibleAccounts"
          :key="account.id"
          class="flex items-center justify-between gap-3 rounded-md px-2 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-800"
          :class="editable ? 'cursor-pointer' : 'cursor-not-allowed opacity-60'"
        >
          <span class="flex min-w-0 flex-1 items-start gap-2">
            <input type="checkbox" class="mt-0.5 h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500 disabled:cursor-not-allowed disabled:opacity-50 dark:border-dark-600 dark:bg-dark-800" :checked="selectedIDSet.has(account.id)" :disabled="!editable" :aria-label="account.name" @change="toggle(account.id)" />
            <span class="min-w-0 flex-1">
              <span class="block truncate font-medium text-gray-800 dark:text-dark-100">{{ account.name }}</span>
              <span class="block truncate text-[11px] text-gray-500 dark:text-dark-400">#{{ account.id }} · {{ account.platform }} / {{ account.type }}</span>
              <span class="mt-1.5 flex min-w-0 flex-wrap gap-1" :aria-label="t('admin.promptAudit.riskRoute.groups')">
                <span
                  v-for="group in account.groups"
                  :key="group.id"
                  class="max-w-full truncate rounded bg-primary-50 px-1.5 py-0.5 text-[10px] font-medium text-primary-700 dark:bg-primary-950/40 dark:text-primary-300"
                  :title="groupLabel(group)"
                >{{ groupLabel(group) }}</span>
                <span v-if="account.groups.length === 0" class="text-[10px] text-gray-400 dark:text-dark-500">{{ t('admin.promptAudit.riskRoute.noGroup') }}</span>
              </span>
            </span>
          </span>
          <span class="shrink-0 text-xs text-gray-400">{{ account.status }}</span>
        </label>
        <p v-if="visibleAccounts.length === 0" class="px-2 py-5 text-center text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.riskRoute.noAccounts') }}</p>
      </div>

      <div v-if="selectedIDs.length" data-test="risk-route-hard-warning" class="mt-4 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm leading-6 text-amber-900 dark:border-amber-900/70 dark:bg-amber-950/30 dark:text-amber-200">
        {{ t('admin.promptAudit.riskRoute.hardPoolWarning', { flag: draft.flag_threshold, block: draft.block_threshold }) }}
      </div>
      <p v-else class="mt-3 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.riskRoute.emptyHint') }}</p>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { PromptAuditAccount, PromptAuditDraft } from '../types'
import { cloneData } from '../viewModel'

const props = defineProps<{
  draft: PromptAuditDraft
  accounts: PromptAuditAccount[]
  loaded: boolean
  loading: boolean
  error: string
}>()
const emit = defineEmits<{
  (event: 'update:draft', value: PromptAuditDraft): void
  (event: 'retry'): void
}>()
const { t } = useI18n()
const search = ref('')

const editable = computed(() => props.draft.enabled && props.draft.blocking_enabled)
const selectedIDs = computed(() => props.draft.risk_route_account_ids)
const selectedIDSet = computed(() => new Set(selectedIDs.value))
const accountByID = computed(() => new Map(props.accounts.map((account) => [account.id, account])))
const selectedRows = computed(() => selectedIDs.value.map((id) => {
  const account = accountByID.value.get(id)
  return { id, account, invalid: props.loaded && !props.error && !account }
}))
const visibleAccounts = computed(() => {
  const query = search.value.trim().toLowerCase()
  const filtered = query
    ? props.accounts.filter((account) => `${account.name} ${account.id} ${account.platform} ${account.type} ${account.status} ${account.groups.map(groupLabel).join(' ')}`.toLowerCase().includes(query))
    : props.accounts
  return [...filtered].sort((left, right) => {
    const selectedOrder = Number(selectedIDSet.value.has(right.id)) - Number(selectedIDSet.value.has(left.id))
    return selectedOrder || left.id - right.id
  })
})

function patchIDs(values: number[]) {
  const ids = Array.from(new Set(values)).sort((left, right) => left - right)
  emit('update:draft', { ...cloneData(props.draft), risk_route_account_ids: ids })
}
function toggle(id: number) {
  if (!editable.value) return
  patchIDs(selectedIDSet.value.has(id)
    ? selectedIDs.value.filter((value) => value !== id)
    : [...selectedIDs.value, id])
}
function remove(id: number) {
  if (!editable.value) return
  patchIDs(selectedIDs.value.filter((value) => value !== id))
}
function missingAccountLabel(id: number): string {
  if (props.loaded && !props.error) return t('admin.promptAudit.riskRoute.invalidAccount', { id })
  return t('admin.promptAudit.riskRoute.unresolvedAccount', { id })
}
function groupLabel(group: PromptAuditAccount['groups'][number]): string {
  return group.name.trim() || t('admin.promptAudit.riskRoute.unknownGroup', { id: group.id })
}
</script>

<template>
  <section aria-labelledby="cyber-feedback-scope-title" class="border-b border-gray-200 py-6 dark:border-dark-700/60">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="cyber-feedback-scope-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.cyberScope.title') }}</h2>
        <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.cyberScope.description') }}</p>
      </div>
      <span class="rounded-full bg-primary-50 px-2.5 py-1 text-xs font-semibold text-primary-700 dark:bg-primary-950/40 dark:text-primary-300">
        {{ t('admin.promptAudit.cyberScope.selectedSummary', { accounts: draft.cyber_feedback_account_ids.length }) }}
      </span>
    </div>

    <div class="mt-5 rounded-xl border border-primary-100 bg-primary-50/60 px-4 py-3 text-sm leading-6 text-primary-900 dark:border-primary-900/60 dark:bg-primary-950/20 dark:text-primary-200" data-test="cyber-scope-independent-hint">
      {{ t('admin.promptAudit.cyberScope.independentHint') }}
    </div>

    <div class="mt-4">
      <div class="rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20">
        <h3 class="text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.cyberScope.accountsTitle') }}</h3>
        <p class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.cyberScope.accountsHint') }}</p>
        <input v-model="accountSearch" type="search" class="input mt-3 w-full" :disabled="loading" :placeholder="t('admin.promptAudit.cyberScope.searchAccounts')" />
        <div v-if="error" role="alert" class="mt-2 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700 dark:bg-red-950/30 dark:text-red-200">
          {{ error }} <button type="button" class="ml-2 underline" @click="$emit('retry')">{{ t('admin.promptAudit.actions.retry') }}</button>
        </div>
        <div v-else-if="loading" class="mt-2 rounded-lg border border-gray-200 px-3 py-8 text-center text-sm text-gray-500 dark:border-dark-700">{{ t('admin.promptAudit.cyberScope.loadingAccounts') }}</div>
        <div v-else class="mt-2 max-h-64 overflow-y-auto rounded-lg border border-gray-200 p-1.5 dark:border-dark-700" data-test="cyber-scope-accounts">
          <label v-for="account in filteredAccounts" :key="account.id" class="flex cursor-pointer items-center justify-between gap-2 rounded-md px-2 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-800">
            <span class="flex min-w-0 items-center gap-2 text-gray-800 dark:text-dark-100">
              <input type="checkbox" :checked="draft.cyber_feedback_account_ids.includes(account.id)" @change="toggleAccount(account.id)" />
              <span class="min-w-0">
                <span class="block truncate">{{ account.name }}</span>
                <span class="block truncate text-[11px] text-gray-400">#{{ account.id }} · {{ account.platform }} / {{ account.type }}</span>
              </span>
            </span>
          </label>
          <p v-if="filteredAccounts.length === 0" class="px-2 py-5 text-center text-sm text-gray-500">{{ t('admin.promptAudit.cyberScope.noAccounts') }}</p>
        </div>
        <p v-if="missingAccountIDs.length" class="mt-2 text-xs text-amber-700 dark:text-amber-300">{{ t('admin.promptAudit.cyberScope.missingAccounts', { ids: missingAccountIDs.join(', ') }) }}</p>
      </div>
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
  accountsLoaded: boolean
  loading: boolean
  error: string
}>()
const emit = defineEmits<{
  (event: 'update:draft', value: PromptAuditDraft): void
  (event: 'retry'): void
}>()
const { t } = useI18n()
const accountSearch = ref('')

const filteredAccounts = computed(() => {
  const query = accountSearch.value.trim().toLowerCase()
  return (query ? props.accounts.filter((account) => `${account.name} ${account.id} ${account.platform} ${account.type}`.toLowerCase().includes(query)) : props.accounts)
    .slice().sort((left, right) => Number(props.draft.cyber_feedback_account_ids.includes(right.id)) - Number(props.draft.cyber_feedback_account_ids.includes(left.id)) || left.id - right.id)
})
const knownAccountIDs = computed(() => new Set(props.accounts.map((account) => account.id)))
const missingAccountIDs = computed(() => props.accountsLoaded && !props.error ? props.draft.cyber_feedback_account_ids.filter((id) => !knownAccountIDs.value.has(id)) : [])

function patch(value: Partial<PromptAuditDraft>) {
  emit('update:draft', { ...cloneData(props.draft), ...value })
}
function toggleAccount(id: number) {
  const selected = new Set(props.draft.cyber_feedback_account_ids)
  if (selected.has(id)) selected.delete(id)
  else selected.add(id)
  patch({ cyber_feedback_account_ids: [...selected].sort((left, right) => left - right) })
}
</script>

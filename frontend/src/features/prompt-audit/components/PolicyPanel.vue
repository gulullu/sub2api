<template>
  <section aria-labelledby="prompt-policy-title" class="py-6">
    <div>
      <h2 id="prompt-policy-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.policy.title') }}</h2>
      <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.policy.description') }}</p>
    </div>

    <div class="mt-5 grid gap-4 2xl:grid-cols-[minmax(0,1fr)_minmax(260px,0.45fr)]">
      <div class="rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5">
        <fieldset>
          <legend class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.policy.scope') }}</legend>
          <div class="mt-3 flex flex-wrap gap-5 text-sm text-gray-700 dark:text-dark-200">
            <label class="flex items-center gap-2">
              <input type="radio" name="prompt-audit-scope" :checked="draft.all_groups" @change="patch({ all_groups: true, group_ids: [] })" />
              {{ t('admin.promptAudit.policy.allGroups') }}
            </label>
            <label class="flex items-center gap-2">
              <input type="radio" name="prompt-audit-scope" :checked="!draft.all_groups" @change="patch({ all_groups: false })" />
              {{ t('admin.promptAudit.policy.selectedGroups') }}
            </label>
          </div>
        </fieldset>

        <div v-if="!draft.all_groups" class="mt-4">
          <label class="block text-sm text-gray-700 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.policy.searchGroups') }}</span>
            <input v-model="groupSearch" type="search" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.searchGroups')" />
          </label>
          <div data-test="prompt-audit-group-results" class="mt-3 max-h-52 overflow-y-auto rounded-lg border border-gray-200 p-2 dark:border-dark-700">
            <label v-for="group in filteredGroups" :key="group.id" class="flex cursor-pointer items-center justify-between gap-3 rounded-md px-2 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-800">
              <span class="flex items-center gap-2 text-gray-800 dark:text-dark-100">
                <input type="checkbox" :checked="draft.group_ids.includes(group.id)" @change="toggleGroup(group.id)" />
                {{ group.name }}
              </span>
              <span class="text-xs text-gray-500 dark:text-dark-400">{{ group.platform }} · {{ group.status }}</span>
            </label>
            <p v-if="filteredGroups.length === 0" class="px-2 py-4 text-center text-sm text-gray-500">{{ t('admin.promptAudit.policy.noGroups') }}</p>
          </div>
          <div v-if="missingGroupIds.length" class="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
            {{ t('admin.promptAudit.policy.missingGroups') }}: {{ missingGroupIds.join(', ') }}
          </div>
          <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.selectedCount', { count: draft.group_ids.length }) }}</p>
        </div>

        <fieldset class="mt-5 border-t border-gray-100 pt-5 dark:border-dark-800">
          <legend class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.policy.scanners') }}</legend>
          <div class="mt-3 grid gap-2 sm:grid-cols-2">
            <label v-for="scanner in SCANNER_CATALOG" :key="scanner.id" class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-gray-700 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-800">
              <input type="checkbox" :checked="draft.scanners.includes(scanner.id)" :aria-label="scannerLabel(scanner.id)" @change="toggleScanner(scanner.id)" />
              <span>{{ scannerLabel(scanner.id) }}</span>
            </label>
          </div>
        </fieldset>
      </div>

      <div class="space-y-4 rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5">
        <label class="block text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.policy.workerCount') }}</span>
          <input :value="draft.worker_count" type="number" min="1" max="32" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.workerCount')" @input="patch({ worker_count: Number(($event.target as HTMLInputElement).value) })" />
        </label>
        <label class="block text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.policy.queueCapacity') }}</span>
          <input :value="draft.queue_capacity" type="number" min="1" max="100000" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.queueCapacity')" @input="patch({ queue_capacity: Number(($event.target as HTMLInputElement).value) })" />
        </label>
        <div class="rounded-lg bg-gray-50 px-4 py-3 text-sm text-gray-600 dark:bg-dark-900/50 dark:text-dark-300">
          <p class="font-medium text-gray-800 dark:text-dark-100">{{ t('admin.promptAudit.policy.strategy') }}</p>
          <p class="mt-1">priority · {{ t('admin.promptAudit.policy.strategyHint') }}</p>
        </div>
      </div>
    </div>

    <div class="mt-6 border-t border-gray-200 pt-6 dark:border-dark-700/60">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 class="text-sm font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.policy.profiles.title') }}</h3>
          <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.policy.profiles.description') }}</p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <button type="button" class="btn btn-secondary btn-sm" :disabled="profileLoading || bulkSelecting" @click="reloadProfiles">{{ profileLoading ? t('common.loading') : t('admin.promptAudit.policy.profiles.refresh') }}</button>
          <button type="button" class="btn btn-secondary btn-sm" :disabled="profileLoading || bulkSelecting || !profilePage.items.length" @click="selectVisible(true)">{{ t('admin.promptAudit.policy.profiles.selectPage') }}</button>
          <button type="button" class="btn btn-secondary btn-sm" :disabled="profileLoading || bulkSelecting || !selectedOnPageCount" @click="selectVisible(false)">{{ t('admin.promptAudit.policy.profiles.clearPage') }}</button>
          <button type="button" class="btn btn-primary btn-sm" :disabled="profileLoading || bulkSelecting" @click="selectFiltered(true)">{{ t('admin.promptAudit.policy.profiles.selectFiltered') }}</button>
          <button type="button" class="btn btn-secondary btn-sm" :disabled="profileLoading || bulkSelecting || !selectedExcludedIds.length" @click="selectFiltered(false)">{{ t('admin.promptAudit.policy.profiles.clearFiltered') }}</button>
        </div>
      </div>

      <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.profiles.selectFilteredHint', { limit: formatCount(PROFILE_BULK_SELECT_LIMIT) }) }}</p>
      <div class="mt-4 rounded-lg bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
        {{ t('admin.promptAudit.policy.profiles.guardWarning') }}
      </div>
      <div v-if="profileNotice" role="status" class="mt-3 rounded-lg bg-sky-50 px-3 py-2 text-xs leading-5 text-sky-800 dark:bg-sky-950/30 dark:text-sky-200">
        {{ profileNotice }}
      </div>
      <div v-if="profileError" role="alert" class="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-200">
        {{ profileError }}
      </div>

      <div class="mt-4 grid gap-3 2xl:grid-cols-[minmax(0,1fr)_320px]">
        <div class="rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5">
          <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
            <label class="block text-sm text-gray-700 dark:text-dark-200 sm:col-span-2 xl:col-span-2">
              <span>{{ t('admin.promptAudit.policy.profiles.searchUser') }}</span>
              <div class="mt-1.5 flex gap-2">
                <input
                  :value="profileFilters.search"
                  type="search"
                  class="input min-w-0 w-full"
                  :placeholder="t('admin.promptAudit.policy.profiles.searchPlaceholder')"
                  :aria-label="t('admin.promptAudit.policy.profiles.searchUser')"
                  @input="setProfileSearch(($event.target as HTMLInputElement).value)"
                  @keyup.enter="applyProfileFilters"
                />
                <button type="button" class="btn btn-primary btn-sm shrink-0 whitespace-nowrap" @click="applyProfileFilters">{{ t('admin.promptAudit.policy.profiles.searchAction') }}</button>
              </div>
            </label>
            <label class="block text-sm text-gray-700 dark:text-dark-200">
              <span>{{ t('admin.promptAudit.policy.profiles.userId') }}</span>
              <input
                :value="profileFilters.user_id ?? ''"
                type="number"
                min="1"
                class="input mt-1.5 w-full"
                :aria-label="t('admin.promptAudit.policy.profiles.userId')"
                @change="setProfileUserId(($event.target as HTMLInputElement).value)"
              />
            </label>
            <label class="block text-sm text-gray-700 dark:text-dark-200">
              <span>{{ t('admin.promptAudit.policy.profiles.days') }}</span>
              <input :value="profileFilters.days" type="number" min="1" max="180" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.profiles.days')" @change="setProfileDays(($event.target as HTMLInputElement).value)" />
            </label>
            <label class="block text-sm text-gray-700 dark:text-dark-200">
              <span>{{ t('admin.promptAudit.policy.profiles.group') }}</span>
              <select :value="profileFilters.group_id ?? ''" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.profiles.group')" @change="setProfileGroupId(($event.target as HTMLSelectElement).value)">
                <option value="">{{ t('admin.promptAudit.policy.profiles.allGroups') }}</option>
                <option v-for="group in groups" :key="group.id" :value="group.id">#{{ group.id }} · {{ group.name }}</option>
              </select>
            </label>
            <label class="block text-sm text-gray-700 dark:text-dark-200">
              <span>{{ t('admin.promptAudit.policy.profiles.minSamples') }}</span>
              <input :value="profileFilters.min_samples" type="number" min="0" max="100000" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.profiles.minSamples')" @change="setProfileMinSamples(($event.target as HTMLInputElement).value)" />
            </label>
          </div>

          <div v-if="profileLoading || bulkSelecting" class="mt-4 rounded-lg border border-dashed border-gray-200 px-4 py-10 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-300">
            {{ bulkSelecting ? t('admin.promptAudit.policy.profiles.loadingBulk') : t('common.loading') }}
          </div>

          <div v-else class="mt-4 overflow-hidden rounded-lg border border-gray-200 dark:border-dark-700">
            <div class="max-h-[34rem] overflow-auto">
              <table class="min-w-[900px] divide-y divide-gray-200 text-sm dark:divide-dark-700">
                <thead class="sticky top-0 bg-gray-50 text-left text-xs font-semibold uppercase tracking-wide text-gray-500 dark:bg-dark-900 dark:text-dark-400">
                  <tr>
                    <th class="px-4 py-3 w-10">
                      <input type="checkbox" :checked="allVisibleSelected" :indeterminate="someVisibleSelected" @change="selectVisible(($event.target as HTMLInputElement).checked)" />
                    </th>
                    <th class="px-4 py-3">{{ t('admin.promptAudit.policy.profiles.user') }}</th>
                    <th class="px-4 py-3">{{ t('admin.promptAudit.policy.profiles.risk') }}</th>
                    <th class="px-4 py-3">{{ t('admin.promptAudit.policy.profiles.guard') }}</th>
                    <th class="px-4 py-3">{{ t('admin.promptAudit.policy.profiles.sample') }}</th>
                    <th class="px-4 py-3">{{ t('admin.promptAudit.policy.profiles.recent') }}</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 bg-white dark:divide-dark-800 dark:bg-dark-900/10">
                  <tr v-for="profile in profilePage.items" :key="profile.user_id" :class="profile.deleted ? 'bg-amber-50/50 dark:bg-amber-950/10' : ''">
                    <td class="px-4 py-3 align-top">
                      <input type="checkbox" :checked="isExcluded(profile.user_id)" @change="toggleExcluded(profile.user_id)" />
                    </td>
                    <td class="px-4 py-3 align-top">
                      <div class="flex flex-col gap-1">
                        <div class="flex flex-wrap items-center gap-2">
                          <span class="font-semibold text-gray-900 dark:text-white">{{ profile.username || profile.email || `#${profile.user_id}` }}</span>
                          <span v-if="profile.deleted" class="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:bg-amber-900/40 dark:text-amber-200">{{ t('admin.promptAudit.policy.profiles.deletedBadge') }}</span>
                          <span v-if="isExcluded(profile.user_id)" class="rounded-full bg-primary-100 px-2 py-0.5 text-[10px] font-semibold text-primary-700 dark:bg-primary-900/40 dark:text-primary-200">{{ t('admin.promptAudit.policy.profiles.excludedBadge') }}</span>
                        </div>
                        <div class="text-xs text-gray-500 dark:text-dark-400">#{{ profile.user_id }} · {{ profile.email || t('admin.promptAudit.policy.profiles.noEmail') }} · {{ profile.status || t('admin.promptAudit.policy.profiles.unknownStatus') }}</div>
                      </div>
                    </td>
                    <td class="px-4 py-3 align-top">
                      <div class="flex flex-col gap-1">
                        <span class="font-medium text-gray-900 dark:text-white">{{ riskText(profile) }}</span>
                        <span v-if="profile.system_exception_jobs" class="text-xs text-amber-600 dark:text-amber-300">{{ t('admin.promptAudit.policy.profiles.systemExceptions', { count: formatCount(profile.system_exception_jobs) }) }}</span>
                      </div>
                    </td>
                    <td class="px-4 py-3 align-top">
                      <div class="flex flex-col gap-1">
                        <span class="font-medium text-gray-900 dark:text-white">{{ guardText(profile) }}</span>
                        <span class="text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.profiles.cyberRatio', { ratio: formatPercent(profile.cyber_ratio), usage: formatCount(profile.usage_total) }) }}</span>
                      </div>
                    </td>
                    <td class="px-4 py-3 align-top">
                      <div class="flex flex-col gap-1">
                        <span class="font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.policy.profiles.auditSamples', { count: formatCount(profile.audit_jobs) }) }}</span>
                        <span class="text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.profiles.usageSamples', { count: formatCount(profile.usage_total) }) }}</span>
                      </div>
                    </td>
                    <td class="px-4 py-3 align-top text-xs text-gray-500 dark:text-dark-400">
                      <div>{{ t('admin.promptAudit.policy.profiles.recentAudit', { time: formatDate(profile.last_audit_at) }) }}</div>
                      <div>{{ t('admin.promptAudit.policy.profiles.recentUsage', { time: formatDate(profile.last_usage_at) }) }}</div>
                      <div>{{ t('admin.promptAudit.policy.profiles.recentCyber', { time: formatDate(profile.last_cyber_at) }) }}</div>
                    </td>
                  </tr>
                  <tr v-if="!profilePage.items.length">
                    <td colspan="6" class="px-4 py-10 text-center text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.profiles.noProfiles') }}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div class="flex flex-wrap items-center justify-between gap-3 border-t border-gray-200 bg-gray-50 px-4 py-3 text-sm dark:border-dark-700 dark:bg-dark-900/40">
              <span class="text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.profiles.pageSummary', { total: formatCount(profilePage.total), page: profilePage.page, pages: Math.max(profilePage.pages, 1) }) }}</span>
              <div class="flex items-center gap-2">
                <button type="button" class="btn btn-secondary btn-sm" :disabled="profilePage.page <= 1" @click="changeProfilePage(profilePage.page - 1)">{{ t('admin.promptAudit.policy.profiles.previous') }}</button>
                <button type="button" class="btn btn-secondary btn-sm" :disabled="profilePage.page >= profilePage.pages" @click="changeProfilePage(profilePage.page + 1)">{{ t('admin.promptAudit.policy.profiles.next') }}</button>
                <select :value="profileFilters.page_size" class="input h-8 w-24 py-0 text-sm" @change="setProfilePageSize(($event.target as HTMLSelectElement).value)">
                  <option :value="10">10</option>
                  <option :value="20">20</option>
                  <option :value="50">50</option>
                  <option :value="100">100</option>
                </select>
              </div>
            </div>
          </div>
        </div>

        <aside class="rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5">
          <div class="flex items-center justify-between gap-3">
            <h4 class="text-sm font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.policy.profiles.excludedTitle') }}</h4>
            <span class="rounded-full bg-primary-50 px-2.5 py-1 text-xs font-semibold text-primary-700 dark:bg-primary-950/40 dark:text-primary-300">
              {{ formatCount(selectedExcludedIds.length) }}
            </span>
          </div>

          <div v-if="selectedExcludedIds.length === 0" class="mt-4 rounded-lg border border-dashed border-gray-200 px-3 py-6 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400">
            {{ t('admin.promptAudit.policy.profiles.excludedEmpty') }}
          </div>

          <div v-else class="mt-4 max-h-[26rem] overflow-auto rounded-lg border border-gray-200 p-2 dark:border-dark-700">
            <div class="flex flex-wrap gap-2">
              <button
                v-for="item in selectedExcludedUsers"
                :key="item.id"
                data-test="prompt-audit-excluded-preview"
                type="button"
                class="inline-flex max-w-full items-center gap-2 rounded-full bg-primary-50 px-3 py-1.5 text-left text-xs font-medium text-primary-800 dark:bg-primary-950/40 dark:text-primary-200"
                @click="toggleExcluded(item.id)"
              >
                <span class="truncate">{{ item.label }}</span>
                <span class="shrink-0 opacity-70">×</span>
              </button>
            </div>
            <p v-if="hiddenExcludedUsersCount" class="mt-2 px-1 text-xs text-gray-500 dark:text-dark-400">
              {{ t('admin.promptAudit.policy.profiles.excludedPreviewMore', { count: formatCount(hiddenExcludedUsersCount) }) }}
            </p>
          </div>

          <div v-if="missingSelectedIds.length" class="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
            {{ t('admin.promptAudit.policy.profiles.excludedMissing', { count: formatCount(missingSelectedIds.length), ids: missingSelectedIds.join(', ') }) }}
          </div>

          <div class="mt-4 rounded-lg bg-gray-50 px-3 py-3 text-xs leading-5 text-gray-600 dark:bg-dark-900/50 dark:text-dark-300">
            <p>{{ t('admin.promptAudit.policy.profiles.saveHint') }}</p>
            <p class="mt-1">{{ t('admin.promptAudit.policy.profiles.cybPersistence') }}</p>
          </div>
        </aside>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { extractApiErrorMessage } from '@/utils/apiError'
import type { PromptAuditDraft, PromptAuditGroup, PromptAuditUserProfile, PromptAuditUserProfileFilter, PromptAuditUserProfilePage } from '../types'
import { cloneData, SCANNER_CATALOG } from '../viewModel'
import promptAuditAPI from '../api'

const props = defineProps<{ draft: PromptAuditDraft; groups: PromptAuditGroup[] }>()
const emit = defineEmits<{ (event: 'update:draft', value: PromptAuditDraft): void }>()
const { t, locale } = useI18n()
const PROFILE_BULK_SELECT_LIMIT = 1000
// Keep the exclusion summary responsive when a large bulk selection is saved.
// The full ID list remains in the draft; only its removable preview is bounded.
const PROFILE_SELECTED_PREVIEW_LIMIT = 200
const PROFILE_MAX_DAYS = 180
const PROFILE_DEFAULT_MIN_SAMPLES = 20
const groupSearch = ref('')
const profileLoading = ref(false)
const bulkSelecting = ref(false)
const profileError = ref('')
const profileNotice = ref('')
const profilePage = reactive<PromptAuditUserProfilePage>({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
const profileFilters = reactive<PromptAuditUserProfileFilter & { page_size: number }>({
  days: 30,
  search: '',
  user_id: undefined,
  group_id: undefined,
  min_samples: PROFILE_DEFAULT_MIN_SAMPLES,
  page_size: 20,
})
const profileCache = reactive(new Map<number, PromptAuditUserProfile>())
let profileRequestId = 0
const numberFormatter = computed(() => new Intl.NumberFormat(locale.value))
const dateFormatter = computed(() => new Intl.DateTimeFormat(locale.value, { dateStyle: 'short', timeStyle: 'medium', hour12: false }))

const filteredGroups = computed(() => {
  const query = groupSearch.value.trim().toLowerCase()
  if (!query) return props.groups
  return props.groups.filter((group) => `${group.name} ${group.id} ${group.platform}`.toLowerCase().includes(query))
})
const knownGroupIds = computed(() => new Set(props.groups.map((group) => group.id)))
const missingGroupIds = computed(() => props.draft.group_ids.filter((id) => !knownGroupIds.value.has(id)))
const selectedExcludedIds = computed(() => [...new Set(props.draft.excluded_user_ids ?? [])].sort((a, b) => a - b))
const excludedIdSet = computed(() => new Set(selectedExcludedIds.value))
const selectedExcludedUsers = computed(() => selectedExcludedIds.value.slice(0, PROFILE_SELECTED_PREVIEW_LIMIT).map((id) => {
  const profile = profileCache.get(id)
  const label = profile ? `${profile.username || profile.email || `#${id}`} · ${profile.email || t('admin.promptAudit.policy.profiles.noEmail')}` : `#${id}`
  return { id, label, profile }
}))
const hiddenExcludedUsersCount = computed(() => Math.max(0, selectedExcludedIds.value.length - PROFILE_SELECTED_PREVIEW_LIMIT))
const missingSelectedIds = computed(() => selectedExcludedIds.value.filter((id) => !profileCache.has(id)))
const currentPageSelectedIds = computed(() => profilePage.items.filter((profile) => isExcluded(profile.user_id)).map((profile) => profile.user_id))
const selectedOnPageCount = computed(() => currentPageSelectedIds.value.length)
const allVisibleSelected = computed(() => profilePage.items.length > 0 && selectedOnPageCount.value === profilePage.items.length)
const someVisibleSelected = computed(() => selectedOnPageCount.value > 0 && selectedOnPageCount.value < profilePage.items.length)

function patch(value: Partial<PromptAuditDraft>) {
  emit('update:draft', { ...cloneData(props.draft), ...value })
}

function toggleGroup(id: number) {
  const selected = new Set(props.draft.group_ids)
  if (selected.has(id)) selected.delete(id)
  else selected.add(id)
  patch({ group_ids: [...selected].sort((a, b) => a - b) })
}

function toggleScanner(id: string) {
  const selected = new Set(props.draft.scanners)
  if (selected.has(id)) selected.delete(id)
  else selected.add(id)
  patch({ scanners: SCANNER_CATALOG.map((item) => item.id).filter((item) => selected.has(item)) })
}

function scannerLabel(id: string): string {
  return t(`admin.promptAudit.scanners.${id}`)
}

function setProfileSearch(value: string) {
  profileFilters.search = value
}

function setProfileUserId(value: string) {
  const parsed = Number(value)
  profileFilters.user_id = Number.isInteger(parsed) && parsed > 0 ? parsed : undefined
}

function setProfileDays(value: string) {
	const parsed = Number(value)
	profileFilters.days = Number.isInteger(parsed) && parsed > 0 ? Math.min(PROFILE_MAX_DAYS, parsed) : 30
}

function setProfileGroupId(value: string) {
  const parsed = Number(value)
  profileFilters.group_id = Number.isInteger(parsed) && parsed > 0 ? parsed : undefined
}

function setProfileMinSamples(value: string) {
	const parsed = Number(value)
	profileFilters.min_samples = Number.isInteger(parsed) && parsed >= 0 ? parsed : PROFILE_DEFAULT_MIN_SAMPLES
}

function setProfilePageSize(value: string) {
  const parsed = Number(value)
  profileFilters.page_size = Number.isInteger(parsed) && parsed > 0 ? parsed : 20
  applyProfileFilters()
}

function isExcluded(userID: number): boolean {
  return excludedIdSet.value.has(userID)
}

function toggleExcluded(userID: number) {
  const selected = new Set(selectedExcludedIds.value)
  if (selected.has(userID)) selected.delete(userID)
  else selected.add(userID)
  patch({ excluded_user_ids: [...selected].sort((a, b) => a - b) })
}

function selectVisible(selected: boolean) {
  const next = new Set(selectedExcludedIds.value)
  for (const profile of profilePage.items) {
    if (selected) next.add(profile.user_id)
    else next.delete(profile.user_id)
  }
  patch({ excluded_user_ids: [...next].sort((a, b) => a - b) })
}

function buildFilter(): PromptAuditUserProfileFilter {
  return {
    days: Math.max(1, Math.min(PROFILE_MAX_DAYS, Number(profileFilters.days) || 30)),
    search: profileFilters.search.trim(),
    user_id: typeof profileFilters.user_id === 'number' && profileFilters.user_id > 0 ? profileFilters.user_id : undefined,
    group_id: typeof profileFilters.group_id === 'number' && profileFilters.group_id > 0 ? profileFilters.group_id : undefined,
    min_samples: Math.max(0, Number(profileFilters.min_samples) || 0),
  }
}

async function loadProfiles(page = profilePage.page) {
  const requestId = ++profileRequestId
  profileLoading.value = true
  profileError.value = ''
  profileNotice.value = ''
  try {
    const data = await promptAuditAPI.listUserProfiles(buildFilter(), page, profileFilters.page_size)
    if (requestId !== profileRequestId) return
    profilePage.items = data.items ?? []
    profilePage.total = data.total ?? 0
    profilePage.page = data.page ?? page
    profilePage.page_size = data.page_size ?? profileFilters.page_size
    profilePage.pages = data.pages ?? 0
    profileFilters.page_size = profilePage.page_size
    for (const profile of profilePage.items) {
      profileCache.set(profile.user_id, profile)
    }
  } catch (error) {
    if (requestId !== profileRequestId) return
    profileError.value = extractApiErrorMessage(error) || (error instanceof Error ? error.message : String(error))
  } finally {
    if (requestId === profileRequestId) profileLoading.value = false
  }
}

async function loadFilteredProfiles(limit = PROFILE_BULK_SELECT_LIMIT): Promise<PromptAuditUserProfile[]> {
  const filter = buildFilter()
  const pageSize = Math.min(limit, 1000)
  const firstPage = await promptAuditAPI.listUserProfiles(filter, 1, pageSize)
  profilePage.total = firstPage.total ?? 0
  profilePage.pages = firstPage.pages ?? 0
  for (const profile of firstPage.items ?? []) {
    profileCache.set(profile.user_id, profile)
  }
  const items = [...(firstPage.items ?? [])]
  const pageCount = firstPage.pages ?? 0
  for (let page = 2; page <= pageCount && items.length < limit; page += 1) {
    const nextPage = await promptAuditAPI.listUserProfiles(filter, page, pageSize)
    for (const profile of nextPage.items ?? []) {
      profileCache.set(profile.user_id, profile)
      items.push(profile)
      if (items.length >= limit) break
    }
  }
  return items.slice(0, limit)
}

async function selectFiltered(selected: boolean) {
  bulkSelecting.value = true
  profileError.value = ''
  profileNotice.value = ''
  try {
    const profiles = await loadFilteredProfiles()
    const next = new Set(selectedExcludedIds.value)
    for (const profile of profiles) {
      if (selected) next.add(profile.user_id)
      else next.delete(profile.user_id)
    }
    patch({ excluded_user_ids: [...next].sort((a, b) => a - b) })
    if (profilePage.total > PROFILE_BULK_SELECT_LIMIT) {
      profileNotice.value = t('admin.promptAudit.policy.profiles.bulkCapped', { total: formatCount(profilePage.total), limit: formatCount(PROFILE_BULK_SELECT_LIMIT) })
    }
  } catch (error) {
    profileError.value = extractApiErrorMessage(error) || (error instanceof Error ? error.message : String(error))
  } finally {
    bulkSelecting.value = false
  }
}

function applyProfileFilters() {
  profilePage.page = 1
  void loadProfiles(1)
}

function changeProfilePage(page: number) {
  profilePage.page = page
  void loadProfiles(page)
}

function reloadProfiles() {
  void loadProfiles(profilePage.page)
}

function formatCount(value: number | null | undefined): string {
  return numberFormatter.value.format(Number(value ?? 0))
}

function formatPercent(value: number | null | undefined): string {
  return `${Math.round(Number(value ?? 0) * 1000) / 10}%`
}

function formatDate(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return dateFormatter.value.format(date)
}

function riskText(profile: PromptAuditUserProfile): string {
  return t('admin.promptAudit.policy.profiles.riskSummary', {
    high: formatCount(profile.high_risk_jobs),
    highRatio: formatPercent(profile.high_risk_ratio),
    critical: formatCount(profile.critical_risk_jobs),
    criticalRatio: formatPercent(profile.critical_risk_ratio),
    combined: formatCount(profile.high_or_critical_jobs),
    combinedRatio: formatPercent(profile.high_or_critical_ratio),
    audit: formatCount(profile.audit_jobs),
  })
}

function guardText(profile: PromptAuditUserProfile): string {
  return t('admin.promptAudit.policy.profiles.guardSummary', {
    blocked: formatCount(profile.cyber_blocked_total),
    recorded: formatCount(profile.cyber_recorded_total),
  })
}

onMounted(() => {
  void loadProfiles()
})
</script>

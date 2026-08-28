<template>
  <section aria-labelledby="prompt-audit-groups-title" class="border-b border-gray-200 py-6 dark:border-dark-700/60" data-test="prompt-audit-group-workspace">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="prompt-audit-groups-title" class="text-base font-semibold text-gray-950 dark:text-white">
          {{ t('admin.promptAudit.groups.title') }}
        </h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.groups.description') }}</p>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <span class="rounded-full bg-primary-50 px-2.5 py-1 text-xs font-semibold text-primary-700 dark:bg-primary-950/40 dark:text-primary-300">
          {{ t('admin.promptAudit.groups.summary', { count: filteredRows.length }) }}
        </span>
        <button type="button" class="btn btn-secondary btn-sm" data-test="prompt-audit-group-refresh" @click="$emit('retry-accounts')">
          {{ t('admin.promptAudit.actions.refresh') }}
        </button>
      </div>
    </div>

    <div class="mt-5 rounded-xl border border-gray-200 bg-gray-50/70 p-4 dark:border-dark-700/60 dark:bg-dark-900/30 sm:p-5" data-test="prompt-audit-global-settings">
      <div class="flex flex-wrap items-end gap-4">
        <label class="min-w-[10rem] flex-1 text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.groups.workerCount') }}</span>
          <input
            :value="draft.worker_count"
            type="number"
            min="1"
            max="32"
            class="input mt-1.5 w-full"
            :aria-label="t('admin.promptAudit.groups.workerCount')"
            @change="patchDraft({ worker_count: boundedNumber(($event.target as HTMLInputElement).value, 1, 32, draft.worker_count) })"
          />
        </label>
        <label class="min-w-[10rem] flex-1 text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.groups.queueCapacity') }}</span>
          <input
            :value="draft.queue_capacity"
            type="number"
            min="1"
            max="100000"
            class="input mt-1.5 w-full"
            :aria-label="t('admin.promptAudit.groups.queueCapacity')"
            @change="patchDraft({ queue_capacity: boundedNumber(($event.target as HTMLInputElement).value, 1, 100000, draft.queue_capacity) })"
          />
        </label>
        <label class="flex items-center gap-2 pb-2 text-sm text-gray-700 dark:text-dark-200">
          <input type="checkbox" :checked="draft.all_groups" data-test="prompt-audit-all-groups" @change="toggleAllGroups(($event.target as HTMLInputElement).checked)" />
          {{ t('admin.promptAudit.groups.allGroups') }}
        </label>
        <div class="rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs text-gray-500 dark:border-dark-700 dark:bg-dark-900 dark:text-dark-300">
          <span class="font-medium text-gray-700 dark:text-dark-200">{{ t('admin.promptAudit.groups.strategy') }}</span>
          <span class="ml-2 font-mono">priority</span>
        </div>
      </div>
    </div>

    <div class="mt-4 flex flex-wrap items-end gap-3">
      <label class="min-w-[14rem] flex-1 text-sm text-gray-700 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.groups.search') }}</span>
        <input
          v-model="search"
          type="search"
          class="input mt-1.5 w-full"
          :placeholder="t('admin.promptAudit.groups.searchPlaceholder')"
          :aria-label="t('admin.promptAudit.groups.search')"
          data-test="prompt-audit-group-search"
        />
      </label>
      <label class="w-full sm:w-44 text-sm text-gray-700 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.groups.platform') }}</span>
        <select v-model="platformFilter" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.groups.platform')" data-test="prompt-audit-group-platform-filter">
          <option value="">{{ t('admin.promptAudit.groups.allPlatforms') }}</option>
          <option v-for="platform in platforms" :key="platform" :value="platform">{{ platform }}</option>
        </select>
      </label>
      <label class="w-full sm:w-44 text-sm text-gray-700 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.groups.status') }}</span>
        <select v-model="statusFilter" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.groups.status')" data-test="prompt-audit-group-status-filter">
          <option value="">{{ t('admin.promptAudit.groups.allStatuses') }}</option>
          <option value="active">{{ t('admin.promptAudit.groups.active') }}</option>
          <option value="inactive">{{ t('admin.promptAudit.groups.inactive') }}</option>
          <option value="unassigned">{{ t('admin.promptAudit.groups.unassigned') }}</option>
        </select>
      </label>
      <div class="relative">
        <button type="button" class="btn btn-secondary btn-sm" data-test="prompt-audit-group-column-settings" :aria-expanded="columnMenuOpen" @click="columnMenuOpen = !columnMenuOpen">
          {{ t('admin.promptAudit.groups.columns') }}
        </button>
        <div v-if="columnMenuOpen" class="absolute right-0 z-20 mt-2 w-56 rounded-xl border border-gray-200 bg-white p-2 shadow-lg dark:border-dark-700 dark:bg-dark-800" data-test="prompt-audit-group-column-menu">
          <label v-for="column in configurableColumns" :key="column.key" class="flex cursor-pointer items-center gap-2 rounded-lg px-2 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-700">
            <input type="checkbox" :checked="isColumnVisible(column.key)" @change="toggleColumn(column.key)" />
            <span>{{ column.label }}</span>
          </label>
          <p class="px-2 pb-1 pt-2 text-[11px] text-gray-400 dark:text-dark-500">{{ t('admin.promptAudit.groups.fixedColumns') }}</p>
        </div>
      </div>
    </div>

    <div v-if="missingPolicyGroupIDs.length" class="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200" data-test="prompt-audit-missing-policy-groups">
      {{ t('admin.promptAudit.groups.missingGroups', { ids: missingPolicyGroupIDs.join(', ') }) }}
    </div>

    <div class="mt-4 overflow-hidden rounded-xl border border-gray-200 bg-white dark:border-dark-700/60 dark:bg-dark-900/20">
      <DataTable
        :columns="visibleColumns"
        :data="filteredRows"
        :row-key="'row_key'"
        :clickable-rows="true"
        :sticky-first-column="true"
        :sticky-actions-column="true"
        :sort-storage-key="'prompt-audit-groups-sort'"
        default-sort-key="name"
        :default-sort-order="'asc'"
        data-test="prompt-audit-groups-table"
        @row-click="openEditor"
      >
        <template #cell-name="{ row }">
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <span class="truncate font-semibold text-gray-900 dark:text-white">{{ row.name }}</span>
              <span v-if="row.group_id === null" class="badge badge-gray">{{ t('admin.promptAudit.groups.defaultBadge') }}</span>
            </div>
            <p class="mt-0.5 text-xs text-gray-500 dark:text-dark-400">{{ row.group_id === null ? '—' : `#${row.group_id}` }}</p>
          </div>
        </template>
        <template #cell-platform="{ row }">
          <span class="text-sm text-gray-700 dark:text-dark-200">{{ row.platform }}</span>
        </template>
        <template #cell-scope="{ row }">
          <button
            v-if="row.group_id !== null"
            type="button"
            class="badge cursor-pointer border-0"
            :class="row.in_scope ? 'badge-success' : 'badge-gray'"
            :aria-label="t('admin.promptAudit.groups.toggleScope', { name: row.name })"
            @click.stop="toggleGroupScope(row.group_id)"
          >
            {{ row.in_scope ? t('admin.promptAudit.groups.inScope') : t('admin.promptAudit.groups.outOfScope') }}
          </button>
          <span v-else class="badge badge-gray">{{ t('admin.promptAudit.groups.unassigned') }}</span>
        </template>
        <template #cell-status="{ row }">
          <div class="flex flex-wrap items-center gap-1.5">
            <span class="badge" :class="row.enabled ? 'badge-success' : 'badge-gray'">{{ row.enabled ? t('admin.promptAudit.groups.enabled') : t('admin.promptAudit.groups.disabled') }}</span>
            <span v-if="row.blocking_enabled" class="badge badge-warning">{{ t('admin.promptAudit.groups.blocking') }}</span>
          </div>
        </template>
        <template #cell-mode="{ row }">
          <span class="text-sm text-gray-700 dark:text-dark-200">{{ row.mode }}</span>
        </template>
        <template #cell-threshold="{ row }">
          <span class="font-mono text-xs text-gray-700 dark:text-dark-200">{{ row.threshold }}</span>
        </template>
        <template #cell-fallback="{ row }">
          <span class="text-sm text-gray-700 dark:text-dark-200">{{ row.fallback }}</span>
        </template>
        <template #cell-accounts="{ row }">
          <span class="tabular-nums text-sm text-gray-700 dark:text-dark-200">{{ row.account_count }}</span>
        </template>
        <template #cell-risk="{ row }">
          <span class="tabular-nums text-sm text-gray-700 dark:text-dark-200">{{ row.risk_count }}</span>
        </template>
        <template #cell-extra="{ row }">
          <span class="tabular-nums text-sm text-gray-700 dark:text-dark-200">{{ row.extra_count }}</span>
        </template>
        <template #cell-updated="{ row }">
          <span class="text-xs text-gray-500 dark:text-dark-400">{{ formatDate(row.updated_at) }}</span>
        </template>
        <template #cell-actions="{ row }">
          <div class="flex flex-wrap items-center justify-end gap-1">
            <button type="button" class="btn btn-primary btn-sm" :data-test="`prompt-audit-edit-group-${row.row_key}`" @click.stop="openEditor(row)">{{ t('common.edit') }}</button>
            <button type="button" class="btn btn-ghost btn-sm" :data-test="`prompt-audit-copy-policy-${row.row_key}`" @click.stop="copyPolicy(row)">{{ copiedPolicyKey === row.row_key ? t('admin.promptAudit.groups.copied') : t('admin.promptAudit.groups.copy') }}</button>
          </div>
        </template>
        <template #empty>
          <div class="px-4 py-10 text-center text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.groups.empty') }}</div>
        </template>
      </DataTable>
    </div>

    <BaseDialog
      :show="Boolean(selectedPolicy)"
      :title="selectedPolicy ? t('admin.promptAudit.groups.editTitle', { name: selectedGroupName }) : ''"
      width="full"
      :close-on-click-outside="false"
      @close="closeEditor"
    >
      <div v-if="selectedPolicy" class="min-w-0">
        <div class="mb-4 flex flex-wrap items-center gap-2">
          <span class="badge" :class="selectedPolicy.enabled ? 'badge-success' : 'badge-gray'">{{ selectedPolicy.enabled ? t('admin.promptAudit.groups.enabled') : t('admin.promptAudit.groups.disabled') }}</span>
          <span v-if="selectedPolicy.group_id === null" class="badge badge-gray">{{ t('admin.promptAudit.groups.unassigned') }}</span>
          <span class="text-xs text-gray-500 dark:text-dark-400">{{ selectedPolicy.group_id === null ? '—' : `#${selectedPolicy.group_id}` }}</span>
        </div>

        <div class="border-b border-gray-200 dark:border-dark-700">
          <div class="flex flex-wrap gap-1" role="tablist" :aria-label="t('admin.promptAudit.groups.editorTabsLabel')">
            <button v-for="tab in editorTabs" :key="tab.id" type="button" role="tab" class="tab" :class="{ 'tab-active': editorTab === tab.id }" :aria-selected="editorTab === tab.id" :data-test="`prompt-audit-group-tab-${tab.id}`" @click="editorTab = tab.id">{{ tab.label }}</button>
          </div>
        </div>

        <div v-if="editorTab === 'policy'" class="mt-5 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(320px,.65fr)]">
          <div class="space-y-5 rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 sm:p-5">
            <div class="grid gap-4 sm:grid-cols-2">
              <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200">
                <input type="checkbox" :checked="selectedPolicy.enabled" data-test="prompt-audit-group-enabled" @change="patchPolicy({ enabled: ($event.target as HTMLInputElement).checked })" />
                {{ t('admin.promptAudit.groups.enabled') }}
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200">
                <input type="checkbox" :checked="selectedPolicy.blocking_enabled" :disabled="!selectedPolicy.enabled" data-test="prompt-audit-group-blocking" @change="patchPolicy({ blocking_enabled: ($event.target as HTMLInputElement).checked })" />
                {{ t('admin.promptAudit.groups.blocking') }}
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200">
                <input type="checkbox" :checked="selectedPolicy.blocking_latest_turn_only" :disabled="!selectedPolicy.enabled || !selectedPolicy.blocking_enabled" @change="patchPolicy({ blocking_latest_turn_only: ($event.target as HTMLInputElement).checked })" />
                {{ t('admin.promptAudit.groups.latestTurnOnly') }}
              </label>
              <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200">
                <input type="checkbox" :checked="selectedPolicy.store_pass_events" @change="patchPolicy({ store_pass_events: ($event.target as HTMLInputElement).checked })" />
                {{ t('admin.promptAudit.groups.storePass') }}
              </label>
            </div>

            <div class="grid gap-4 sm:grid-cols-2">
              <label class="block text-sm text-gray-700 dark:text-dark-200">
                <span>{{ t('admin.promptAudit.groups.flagThreshold') }}</span>
                <input :value="selectedPolicy.flag_threshold" type="number" min="0" max="0.99" step="0.01" class="input mt-1.5 w-full" data-test="prompt-audit-group-flag-threshold" @change="patchPolicy({ flag_threshold: threshold(($event.target as HTMLInputElement).value, 0, Math.max(0, selectedPolicy.block_threshold - 0.01), selectedPolicy.flag_threshold) })" />
              </label>
              <label class="block text-sm text-gray-700 dark:text-dark-200">
                <span>{{ t('admin.promptAudit.groups.blockThreshold') }}</span>
                <input :value="selectedPolicy.block_threshold" type="number" min="0.01" max="1" step="0.01" class="input mt-1.5 w-full" data-test="prompt-audit-group-block-threshold" @change="patchPolicy({ block_threshold: threshold(($event.target as HTMLInputElement).value, Math.min(1, selectedPolicy.flag_threshold + 0.01), 1, selectedPolicy.block_threshold) })" />
              </label>
              <label class="block text-sm text-gray-700 dark:text-dark-200">
                <span>{{ t('admin.promptAudit.groups.blockStatus') }}</span>
                <input :value="selectedPolicy.block_http_status" type="number" min="400" max="499" step="1" class="input mt-1.5 w-full" @change="patchPolicy({ block_http_status: boundedNumber(($event.target as HTMLInputElement).value, 400, 499, selectedPolicy.block_http_status) })" />
              </label>
              <label class="block text-sm text-gray-700 dark:text-dark-200">
                <span>{{ t('admin.promptAudit.groups.maxInput') }}</span>
                <input :value="selectedPolicy.max_total_input_chars" type="number" min="128" max="400000" step="1" class="input mt-1.5 w-full" @change="patchPolicy({ max_total_input_chars: boundedNumber(($event.target as HTMLInputElement).value, 128, 400000, selectedPolicy.max_total_input_chars) })" />
              </label>
            </div>

            <label class="block text-sm text-gray-700 dark:text-dark-200">
              <span>{{ t('admin.promptAudit.groups.blockMessage') }}</span>
              <textarea :value="selectedPolicy.block_message" maxlength="1000" class="input mt-1.5 min-h-24 w-full resize-y" @input="patchPolicy({ block_message: ($event.target as HTMLTextAreaElement).value.slice(0, 1000) })" />
            </label>

            <div class="grid gap-4 sm:grid-cols-2">
              <label class="block text-sm text-gray-700 dark:text-dark-200">
                <span>{{ t('admin.promptAudit.groups.noRouteFallback') }}</span>
                <select :value="selectedPolicy.no_route_fallback_mode" class="input mt-1.5 w-full" data-test="prompt-audit-group-no-route-fallback" @change="patchPolicy({ no_route_fallback_mode: ($event.target as HTMLSelectElement).value as PromptAuditNoRouteFallbackMode })">
                  <option value="allow">{{ t('admin.promptAudit.groups.fallbackAllow') }}</option>
                  <option value="block">{{ t('admin.promptAudit.groups.fallbackBlock') }}</option>
                </select>
              </label>
              <label class="block text-sm text-gray-700 dark:text-dark-200">
                <span>{{ t('admin.promptAudit.groups.template') }}</span>
                <select :value="selectedPolicy.active_prompt_template_id" class="input mt-1.5 w-full" @change="patchPolicy({ active_prompt_template_id: ($event.target as HTMLSelectElement).value })">
                  <option v-for="template in draft.prompt_templates" :key="template.id" :value="template.id">{{ template.name }}</option>
                </select>
              </label>
            </div>
          </div>

          <div class="rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 sm:p-5">
            <h3 class="text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.groups.scanners') }}</h3>
            <div class="mt-3 grid gap-2 sm:grid-cols-2">
              <label v-for="scanner in SCANNER_CATALOG" :key="scanner.id" class="flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-gray-700 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-800">
                <input type="checkbox" :checked="selectedPolicy.scanners.includes(scanner.id)" :aria-label="t(`admin.promptAudit.scanners.${scanner.id}`)" @change="toggleScanner(scanner.id)" />
                <span>{{ t(`admin.promptAudit.scanners.${scanner.id}`) }}</span>
              </label>
            </div>
          </div>
        </div>

        <div v-else-if="editorTab === 'risk'" class="mt-5 space-y-4">
          <div class="flex flex-wrap items-end gap-3">
            <label class="min-w-[16rem] flex-1 text-sm text-gray-700 dark:text-dark-200">
              <span>{{ t('admin.promptAudit.groups.accountSearch') }}</span>
              <input v-model="accountSearch" type="search" class="input mt-1.5 w-full" :placeholder="t('admin.promptAudit.groups.accountSearchPlaceholder')" data-test="prompt-audit-group-risk-search" />
            </label>
            <span class="badge badge-warning">{{ t('admin.promptAudit.groups.selectedCount', { count: selectedPolicy.risk_route_account_ids.length }) }}</span>
            <div class="relative">
              <button type="button" class="btn btn-secondary btn-sm" data-test="prompt-audit-account-column-settings" :aria-expanded="accountColumnMenuOpen" @click="accountColumnMenuOpen = !accountColumnMenuOpen">{{ t('admin.promptAudit.groups.columns') }}</button>
              <div v-if="accountColumnMenuOpen" class="absolute right-0 z-20 mt-2 w-56 rounded-xl border border-gray-200 bg-white p-2 shadow-lg dark:border-dark-700 dark:bg-dark-800" data-test="prompt-audit-account-column-menu">
                <label v-for="column in accountConfigurableColumns" :key="column.key" class="flex cursor-pointer items-center gap-2 rounded-lg px-2 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-700">
                  <input type="checkbox" :checked="isAccountColumnVisible(column.key)" @change="toggleAccountColumn(column.key)" />
                  <span>{{ column.label }}</span>
                </label>
                <p class="px-2 pb-1 pt-2 text-[11px] text-gray-400 dark:text-dark-500">{{ t('admin.promptAudit.groups.accountFixedColumns') }}</p>
              </div>
            </div>
          </div>
          <div v-if="accountsError" role="alert" class="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-200">
            {{ accountsError }} <button type="button" class="ml-2 underline" @click="$emit('retry-accounts')">{{ t('admin.promptAudit.actions.retry') }}</button>
          </div>
          <div v-else-if="accountsLoading" class="rounded-lg border border-dashed border-gray-200 px-4 py-10 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-300" aria-busy="true">{{ t('admin.promptAudit.groups.loadingAccounts') }}</div>
          <DataTable
            v-else
            :columns="visibleAccountColumns"
            :data="riskAccounts"
            :selectable="true"
            :selected-keys="selectedPolicy.risk_route_account_ids"
            row-key="id"
            :sticky-first-column="true"
            :sticky-actions-column="true"
            :virtualize-threshold="1000"
            data-test="prompt-audit-group-risk-table"
            @update:selected-keys="updateAccountIDs('risk', $event)"
          >
            <template #cell-name="{ row }"><AccountCell :account="row" /></template>
            <template #cell-platform="{ row }"><span>{{ row.platform }}</span></template>
            <template #cell-type="{ row }"><span>{{ row.type }}</span></template>
            <template #cell-status="{ row }"><span class="badge" :class="row.status === 'active' ? 'badge-success' : 'badge-gray'">{{ row.status }}</span></template>
            <template #cell-groups="{ row }"><span class="max-w-[16rem] truncate text-xs text-gray-500 dark:text-dark-400">{{ accountGroups(row) }}</span></template>
            <template #cell-actions="{ row }"><button type="button" class="btn btn-ghost btn-sm text-red-600 disabled:cursor-not-allowed disabled:opacity-40 dark:text-red-300" :disabled="!selectedPolicy!.risk_route_account_ids.includes(row.id)" @click.stop="removeAccount('risk', row.id)">{{ t('common.remove') }}</button></template>
            <template #empty><div class="px-4 py-10 text-center text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.groups.noAccounts') }}</div></template>
          </DataTable>
          <p v-if="riskOutsideScopeIDs.length" class="text-xs text-amber-700 dark:text-amber-300">{{ t('admin.promptAudit.groups.outsideScopeWarning', { ids: riskOutsideScopeIDs.join(', ') }) }}</p>
        </div>

        <div v-else-if="editorTab === 'cyber'" class="mt-5 space-y-4">
          <div class="flex flex-wrap items-end gap-3">
            <label class="min-w-[16rem] flex-1 text-sm text-gray-700 dark:text-dark-200">
              <span>{{ t('admin.promptAudit.groups.accountSearch') }}</span>
              <input v-model="accountSearch" type="search" class="input mt-1.5 w-full" :placeholder="t('admin.promptAudit.groups.accountSearchPlaceholder')" data-test="prompt-audit-group-cyber-search" />
            </label>
            <span class="badge badge-primary">{{ t('admin.promptAudit.groups.selectedCount', { count: selectedPolicy.cyber_feedback_account_ids.length }) }}</span>
            <div class="relative">
              <button type="button" class="btn btn-secondary btn-sm" data-test="prompt-audit-account-column-settings-cyber" :aria-expanded="accountColumnMenuOpen" @click="accountColumnMenuOpen = !accountColumnMenuOpen">{{ t('admin.promptAudit.groups.columns') }}</button>
              <div v-if="accountColumnMenuOpen" class="absolute right-0 z-20 mt-2 w-56 rounded-xl border border-gray-200 bg-white p-2 shadow-lg dark:border-dark-700 dark:bg-dark-800" data-test="prompt-audit-account-column-menu-cyber">
                <label v-for="column in accountConfigurableColumns" :key="column.key" class="flex cursor-pointer items-center gap-2 rounded-lg px-2 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-700">
                  <input type="checkbox" :checked="isAccountColumnVisible(column.key)" @change="toggleAccountColumn(column.key)" />
                  <span>{{ column.label }}</span>
                </label>
                <p class="px-2 pb-1 pt-2 text-[11px] text-gray-400 dark:text-dark-500">{{ t('admin.promptAudit.groups.accountFixedColumns') }}</p>
              </div>
            </div>
          </div>
          <div v-if="accountsError" role="alert" class="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-200">{{ accountsError }} <button type="button" class="ml-2 underline" @click="$emit('retry-accounts')">{{ t('admin.promptAudit.actions.retry') }}</button></div>
          <div v-else-if="accountsLoading" class="rounded-lg border border-dashed border-gray-200 px-4 py-10 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-300" aria-busy="true">{{ t('admin.promptAudit.groups.loadingAccounts') }}</div>
          <DataTable
            v-else
            :columns="visibleAccountColumns"
            :data="cyberAccounts"
            :selectable="true"
            :selected-keys="selectedPolicy.cyber_feedback_account_ids"
            row-key="id"
            :sticky-first-column="true"
            :sticky-actions-column="true"
            :virtualize-threshold="1000"
            data-test="prompt-audit-group-cyber-table"
            @update:selected-keys="updateAccountIDs('cyber', $event)"
          >
            <template #cell-name="{ row }"><AccountCell :account="row" /></template>
            <template #cell-platform="{ row }"><span>{{ row.platform }}</span></template>
            <template #cell-type="{ row }"><span>{{ row.type }}</span></template>
            <template #cell-status="{ row }"><span class="badge" :class="row.status === 'active' ? 'badge-success' : 'badge-gray'">{{ row.status }}</span></template>
            <template #cell-groups="{ row }"><span class="max-w-[16rem] truncate text-xs text-gray-500 dark:text-dark-400">{{ accountGroups(row) }}</span></template>
            <template #cell-actions="{ row }"><button type="button" class="btn btn-ghost btn-sm text-red-600 disabled:cursor-not-allowed disabled:opacity-40 dark:text-red-300" :disabled="!selectedPolicy!.cyber_feedback_account_ids.includes(row.id)" @click.stop="removeAccount('cyber', row.id)">{{ t('common.remove') }}</button></template>
            <template #empty><div class="px-4 py-10 text-center text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.groups.noAccounts') }}</div></template>
          </DataTable>
          <p v-if="cyberOutsideScopeIDs.length" class="text-xs text-amber-700 dark:text-amber-300">{{ t('admin.promptAudit.groups.outsideScopeWarning', { ids: cyberOutsideScopeIDs.join(', ') }) }}</p>
        </div>

        <div v-else class="mt-5 space-y-4">
          <div class="flex flex-wrap items-end gap-3">
            <label class="min-w-[16rem] flex-1 text-sm text-gray-700 dark:text-dark-200">
              <span>{{ t('admin.promptAudit.groups.profileSearch') }}</span>
              <input v-model="profileSearch" type="search" class="input mt-1.5 w-full" :placeholder="t('admin.promptAudit.groups.profileSearchPlaceholder')" data-test="prompt-audit-group-profile-search" @keyup.enter="applyProfileFilters" />
            </label>
            <label class="w-32 text-sm text-gray-700 dark:text-dark-200"><span>{{ t('admin.promptAudit.groups.profileDays') }}</span><input v-model.number="profileDays" type="number" min="1" max="180" class="input mt-1.5 w-full" @change="applyProfileFilters" /></label>
            <div class="relative">
              <button type="button" class="btn btn-secondary btn-sm" data-test="prompt-audit-profile-column-settings" :aria-expanded="profileColumnMenuOpen" @click="profileColumnMenuOpen = !profileColumnMenuOpen">{{ t('admin.promptAudit.groups.profileColumns') }}</button>
              <div v-if="profileColumnMenuOpen" class="absolute right-0 z-20 mt-2 w-56 rounded-xl border border-gray-200 bg-white p-2 shadow-lg dark:border-dark-700 dark:bg-dark-800" data-test="prompt-audit-profile-column-menu">
                <label v-for="column in profileConfigurableColumns" :key="column.key" class="flex cursor-pointer items-center gap-2 rounded-lg px-2 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-700">
                  <input type="checkbox" :checked="isProfileColumnVisible(column.key)" @change="toggleProfileColumn(column.key)" />
                  <span>{{ column.label }}</span>
                </label>
                <p class="px-2 pb-1 pt-2 text-[11px] text-gray-400 dark:text-dark-500">{{ t('admin.promptAudit.groups.profileFixedColumns') }}</p>
              </div>
            </div>
            <button type="button" class="btn btn-secondary btn-sm" :disabled="profilesLoading" @click="applyProfileFilters">{{ profilesLoading ? t('common.loading') : t('admin.promptAudit.groups.profileRefresh') }}</button>
            <button type="button" class="btn btn-secondary btn-sm" :disabled="profilesLoading || !profilePage.items.length" @click="selectProfilePage(true)">{{ t('admin.promptAudit.groups.selectPage') }}</button>
            <button type="button" class="btn btn-ghost btn-sm" :disabled="profilesLoading || !profilePage.items.length" @click="selectProfilePage(false)">{{ t('admin.promptAudit.groups.clearPage') }}</button>
          </div>
          <div v-if="profileError" role="alert" class="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-200">{{ profileError }}</div>
          <div v-else-if="profilesLoading" class="rounded-lg border border-dashed border-gray-200 px-4 py-10 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-300" aria-busy="true">{{ t('admin.promptAudit.groups.loadingProfiles') }}</div>
          <DataTable
            v-else
            :columns="visibleProfileColumns"
            :data="profilePage.items"
            :selectable="true"
            :selected-keys="selectedPolicy.excluded_user_ids"
            row-key="user_id"
            :sticky-first-column="true"
            :sticky-actions-column="false"
            :virtualize-threshold="1000"
            data-test="prompt-audit-group-profile-table"
            @update:selected-keys="updateExcludedIDs"
          >
            <template #cell-user="{ row }"><div class="min-w-0"><span class="block truncate font-medium">{{ row.username || `#${row.user_id}` }}</span><span class="block text-xs text-gray-500 dark:text-dark-400">#{{ row.user_id }}</span></div></template>
            <template #cell-email="{ row }"><span class="block max-w-[16rem] truncate text-sm" :title="row.email || undefined">{{ row.email || t('admin.promptAudit.groups.noEmail') }}</span></template>
            <template #cell-status="{ row }"><span class="badge" :class="row.deleted ? 'badge-gray' : row.status === 'active' ? 'badge-success' : 'badge-gray'">{{ row.deleted ? t('admin.promptAudit.groups.deleted') : row.status || t('admin.promptAudit.groups.unknownStatus') }}</span></template>
            <template #cell-risk="{ row }"><span class="text-xs">{{ formatRisk(row) }}</span></template>
            <template #cell-cyber="{ row }"><span class="text-xs">{{ formatCyber(row) }}</span></template>
            <template #cell-samples="{ row }"><span class="tabular-nums text-xs">{{ row.sample_total }}</span></template>
            <template #cell-coverage="{ row }"><span class="tabular-nums text-xs">{{ formatCoverage(row) }}</span></template>
            <template #cell-recent="{ row }"><span class="text-xs text-gray-500 dark:text-dark-400">{{ formatDate(row.last_audit_at || row.last_usage_at) }}</span></template>
            <template #cell-excluded="{ row }"><span class="badge" :class="selectedPolicy!.excluded_user_ids.includes(row.user_id) || row.excluded ? 'badge-warning' : 'badge-gray'">{{ selectedPolicy!.excluded_user_ids.includes(row.user_id) || row.excluded ? t('admin.promptAudit.groups.excluded') : t('admin.promptAudit.groups.included') }}</span></template>
            <template #empty><div class="px-4 py-10 text-center text-sm text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.groups.noProfiles') }}</div></template>
          </DataTable>
          <div class="flex flex-wrap items-center justify-between gap-2 text-xs text-gray-500 dark:text-dark-400">
            <span>{{ t('admin.promptAudit.groups.profileSummary', { total: profilePage.total, page: profilePage.page, pages: Math.max(profilePage.pages, 1) }) }}</span>
            <div class="flex gap-2">
              <button type="button" class="btn btn-secondary btn-sm" :disabled="profilePage.page <= 1 || profilesLoading" @click="changeProfilePage(profilePage.page - 1)">{{ t('admin.promptAudit.groups.previous') }}</button>
              <button type="button" class="btn btn-secondary btn-sm" :disabled="profilePage.page >= profilePage.pages || profilesLoading" @click="changeProfilePage(profilePage.page + 1)">{{ t('admin.promptAudit.groups.next') }}</button>
            </div>
          </div>
          <p v-if="selectedPolicy.excluded_user_ids.length" class="text-xs text-amber-700 dark:text-amber-300">{{ t('admin.promptAudit.groups.excludedCount', { count: selectedPolicy.excluded_user_ids.length }) }}</p>
        </div>
      </div>
      <template #footer>
        <div class="flex w-full items-center justify-between gap-3">
          <span class="text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.groups.saveHint') }}</span>
          <button type="button" class="btn btn-primary" @click="closeEditor">{{ t('common.close') }}</button>
        </div>
      </template>
    </BaseDialog>
  </section>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import DataTable from '@/components/common/DataTable.vue'
import type { Column } from '@/components/common/types'
import promptAuditAPI from '../api'
import type {
  PromptAuditAccount,
  PromptAuditDraft,
  PromptAuditGroup,
  PromptAuditGroupPolicy,
  PromptAuditNoRouteFallbackMode,
  PromptAuditUserProfile,
  PromptAuditUserProfilePage,
} from '../types'
import { cloneData, createGroupPolicyFromConfig, SCANNER_CATALOG } from '../viewModel'

const props = defineProps<{
  draft: PromptAuditDraft
  groups: PromptAuditGroup[]
  accounts: PromptAuditAccount[]
  accountsLoaded: boolean
  accountsLoading: boolean
  accountsError: string
}>()
const emit = defineEmits<{
  (event: 'update:draft', value: PromptAuditDraft): void
  (event: 'retry-accounts'): void
}>()
const { t, locale } = useI18n()

type EditorTab = 'policy' | 'risk' | 'cyber' | 'profiles'
type GroupRow = {
  row_key: string
  group_id: number | null
  name: string
  platform: string
  group_status: string
  in_scope: boolean
  enabled: boolean
  blocking_enabled: boolean
  mode: string
  threshold: string
  fallback: string
  account_count: number
  risk_count: number
  extra_count: number
  excluded_count: number
  updated_at: string
  policy: PromptAuditGroupPolicy
}

const search = ref('')
const platformFilter = ref('')
const statusFilter = ref('')
const columnMenuOpen = ref(false)
const accountColumnMenuOpen = ref(false)
const profileColumnMenuOpen = ref(false)
const copiedPolicyKey = ref('')
const hiddenColumns = ref<string[]>([])
const hiddenAccountColumns = ref<string[]>([])
const hiddenProfileColumns = ref<string[]>([])
const selectedPolicy = ref<PromptAuditGroupPolicy | null>(null)
const editorTab = ref<EditorTab>('policy')
const accountSearch = ref('')
const profileSearch = ref('')
const profileDays = ref(7)
const profilePage = ref<PromptAuditUserProfilePage>({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
const profilesLoading = ref(false)
const profileError = ref('')
const profilePageSize = 20

const editorTabs = computed(() => [
  { id: 'policy' as const, label: t('admin.promptAudit.groups.tabs.policy') },
  { id: 'risk' as const, label: t('admin.promptAudit.groups.tabs.risk') },
  { id: 'cyber' as const, label: t('admin.promptAudit.groups.tabs.cyber') },
  { id: 'profiles' as const, label: t('admin.promptAudit.groups.tabs.profiles') },
])

const allColumns = computed<Column[]>(() => [
  { key: 'name', label: t('admin.promptAudit.groups.name'), sortable: true, class: 'min-w-[220px]' },
  { key: 'platform', label: t('admin.promptAudit.groups.platform'), sortable: true, class: 'min-w-[120px]' },
  { key: 'scope', label: t('admin.promptAudit.groups.scope'), sortable: true, class: 'min-w-[130px]' },
  { key: 'status', label: t('admin.promptAudit.groups.status'), sortable: true, class: 'min-w-[150px]' },
  { key: 'mode', label: t('admin.promptAudit.groups.mode'), sortable: true, class: 'min-w-[130px]' },
  { key: 'threshold', label: t('admin.promptAudit.groups.threshold'), sortable: true, class: 'min-w-[130px]' },
  { key: 'fallback', label: t('admin.promptAudit.groups.fallback'), sortable: true, class: 'min-w-[150px]' },
  { key: 'accounts', label: t('admin.promptAudit.groups.accountCount'), sortable: true, class: 'min-w-[100px] text-right' },
  { key: 'risk', label: t('admin.promptAudit.groups.riskCount'), sortable: true, class: 'min-w-[110px] text-right' },
  { key: 'extra', label: t('admin.promptAudit.groups.extraCount'), sortable: true, class: 'min-w-[110px] text-right' },
  { key: 'updated', label: t('admin.promptAudit.groups.updated'), sortable: true, class: 'min-w-[160px]' },
  { key: 'actions', label: t('admin.promptAudit.common.actions'), class: 'min-w-[150px] text-right' },
])
const configurableColumns = computed(() => allColumns.value.filter((column) => !['name', 'actions'].includes(column.key)))
const visibleColumns = computed(() => allColumns.value.filter((column) => !hiddenColumns.value.includes(column.key) || ['name', 'actions'].includes(column.key)))

const accountColumns = computed<Column[]>(() => [
  { key: 'name', label: t('admin.promptAudit.groups.accountName'), sortable: true, class: 'min-w-[220px]' },
  { key: 'platform', label: t('admin.promptAudit.groups.platform'), sortable: true, class: 'min-w-[120px]' },
  { key: 'type', label: t('admin.promptAudit.groups.accountType'), sortable: true, class: 'min-w-[120px]' },
  { key: 'status', label: t('admin.promptAudit.groups.accountStatus'), sortable: true, class: 'min-w-[120px]' },
  { key: 'groups', label: t('admin.promptAudit.groups.accountGroups'), class: 'min-w-[180px]' },
  { key: 'actions', label: t('admin.promptAudit.common.actions'), class: 'min-w-[100px] text-right' },
])
const accountConfigurableColumns = computed(() => accountColumns.value.filter((column) => !['name', 'actions'].includes(column.key)))
const visibleAccountColumns = computed(() => accountColumns.value.filter((column) => !hiddenAccountColumns.value.includes(column.key) || ['name', 'actions'].includes(column.key)))
const allProfileColumns = computed<Column[]>(() => [
  { key: 'user', label: t('admin.promptAudit.groups.user'), sortable: true, class: 'min-w-[220px]' },
  { key: 'email', label: t('admin.promptAudit.groups.userEmail'), sortable: true, class: 'min-w-[220px]' },
  { key: 'status', label: t('admin.promptAudit.groups.userStatus'), sortable: true, class: 'min-w-[120px]' },
  { key: 'samples', label: t('admin.promptAudit.groups.userSamples'), sortable: true, class: 'min-w-[100px] text-right' },
  { key: 'risk', label: t('admin.promptAudit.groups.userRisk'), sortable: true, class: 'min-w-[180px]' },
  { key: 'cyber', label: t('admin.promptAudit.groups.userCyber'), sortable: true, class: 'min-w-[160px]' },
  { key: 'coverage', label: t('admin.promptAudit.groups.userCoverage'), sortable: true, class: 'min-w-[120px]' },
  { key: 'recent', label: t('admin.promptAudit.groups.userRecent'), sortable: true, class: 'min-w-[160px]' },
  { key: 'excluded', label: t('admin.promptAudit.groups.userExcluded'), sortable: true, class: 'min-w-[130px]' },
])
const profileConfigurableColumns = computed(() => allProfileColumns.value.filter((column) => column.key !== 'user'))
const visibleProfileColumns = computed(() => allProfileColumns.value.filter((column) => !hiddenProfileColumns.value.includes(column.key) || column.key === 'user'))

function groupKey(groupID: number | null): string { return groupID === null ? 'default' : String(groupID) }
function policyFor(groupID: number | null): PromptAuditGroupPolicy {
  const existing = (props.draft.group_policies ?? []).find((policy) => groupKey(normalizeGroupID(policy.group_id)) === groupKey(groupID))
  return createGroupPolicyFromConfig(props.draft, groupID, existing)
}
function normalizeGroupID(value: unknown): number | null {
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null
}
function groupInfo(groupID: number | null): PromptAuditGroup | undefined {
  return groupID === null ? undefined : props.groups.find((group) => group.id === groupID)
}
function accountsForGroup(groupID: number | null): PromptAuditAccount[] {
  return props.accounts.filter((account) => groupID === null
    ? account.groups.length === 0
    : account.groups.some((group) => group.id === groupID))
}
function policyModeLabel(policy: PromptAuditGroupPolicy): string {
  if (!policy.enabled) return t('admin.promptAudit.mode.off')
  return policy.blocking_enabled ? t('admin.promptAudit.mode.blocking') : t('admin.promptAudit.mode.async_audit')
}
function policyThresholdLabel(policy: PromptAuditGroupPolicy): string {
  return `${Math.round(policy.flag_threshold * 100)}% / ${Math.round(policy.block_threshold * 100)}%`
}
function policyFallbackLabel(policy: PromptAuditGroupPolicy): string {
  return policy.no_route_fallback_mode === 'allow'
    ? t('admin.promptAudit.groups.fallbackAllow')
    : t('admin.promptAudit.groups.fallbackBlock')
}

const rows = computed<GroupRow[]>(() => {
  const knownIDs = new Set(props.groups.map((group) => group.id))
  const ids = new Set<number | null>([null, ...props.groups.map((group) => group.id)])
  for (const policy of props.draft.group_policies ?? []) {
    const id = normalizeGroupID(policy.group_id)
    if (id === null || !knownIDs.has(id)) ids.add(id)
  }
  return [...ids].map((groupID) => {
    const group = groupInfo(groupID)
    const policy = policyFor(groupID)
    const hasPolicy = (props.draft.group_policies ?? []).some((item) => groupKey(normalizeGroupID(item.group_id)) === groupKey(groupID))
    const groupAccounts = accountsForGroup(groupID)
    return {
      row_key: groupKey(groupID),
      group_id: groupID,
      name: group?.name?.trim() || (groupID === null ? t('admin.promptAudit.groups.unassigned') : t('admin.promptAudit.groups.unknownGroup', { id: groupID })),
      platform: group?.platform || (groupID === null ? '—' : t('admin.promptAudit.groups.unknownPlatform')),
      group_status: group?.status || (groupID === null ? 'unassigned' : 'unknown'),
      in_scope: props.draft.all_groups || (hasPolicy || (groupID !== null && props.draft.group_ids.includes(groupID))),
      enabled: policy.enabled,
      blocking_enabled: policy.enabled && policy.blocking_enabled,
      mode: policyModeLabel(policy),
      threshold: policyThresholdLabel(policy),
      fallback: policyFallbackLabel(policy),
      account_count: groupAccounts.length,
      risk_count: policy.risk_route_account_ids.length,
      extra_count: policy.cyber_feedback_account_ids.length,
      excluded_count: policy.excluded_user_ids.length,
      updated_at: policy.updated_at || props.draft.updated_at || '',
      policy,
    }
  })
})

const platforms = computed(() => Array.from(new Set(rows.value.map((row) => row.platform).filter((value) => value && value !== '—'))).sort())
const filteredRows = computed(() => {
  const query = search.value.trim().toLowerCase()
  return rows.value.filter((row) => {
    if (query && !`${row.name} ${row.group_id ?? ''} ${row.platform}`.toLowerCase().includes(query)) return false
    if (platformFilter.value && row.platform !== platformFilter.value) return false
    if (statusFilter.value === 'unassigned' && row.group_id !== null) return false
    if (statusFilter.value === 'active' && (row.group_id === null || row.group_status !== 'active')) return false
    if (statusFilter.value === 'inactive' && (row.group_id === null || row.group_status !== 'inactive')) return false
    return true
  })
})
const missingPolicyGroupIDs = computed(() => (props.draft.group_policies ?? []).map((policy) => normalizeGroupID(policy.group_id)).filter((id): id is number => id !== null && !props.groups.some((group) => group.id === id)))

const selectedGroupName = computed(() => {
  if (!selectedPolicy.value) return ''
  return groupInfo(selectedPolicy.value.group_id)?.name || (selectedPolicy.value.group_id === null ? t('admin.promptAudit.groups.unassigned') : t('admin.promptAudit.groups.unknownGroup', { id: selectedPolicy.value.group_id }))
})

const scopedAccountRows = computed(() => {
  if (!selectedPolicy.value) return []
  const groupAccounts = accountsForGroup(selectedPolicy.value.group_id)
  const selectedIDs = new Set([...selectedPolicy.value.risk_route_account_ids, ...selectedPolicy.value.cyber_feedback_account_ids])
  const selectedOutside = props.accounts.filter((account) => selectedIDs.has(account.id) && !groupAccounts.some((candidate) => candidate.id === account.id))
  return [...groupAccounts, ...selectedOutside.filter((account) => !groupAccounts.some((candidate) => candidate.id === account.id))]
})
const filteredScopedAccounts = computed(() => {
  const query = accountSearch.value.trim().toLowerCase()
  return (query
    ? scopedAccountRows.value.filter((account) => `${account.name} ${account.id} ${account.platform} ${account.type} ${account.status} ${accountGroups(account)}`.toLowerCase().includes(query))
    : scopedAccountRows.value
  ).sort((left, right) => left.id - right.id)
})
const riskAccounts = computed(() => filteredScopedAccounts.value.filter((account) => {
  if (!selectedPolicy.value) return false
  return selectedPolicy.value.risk_route_account_ids.includes(account.id) || accountsForGroup(selectedPolicy.value.group_id).some((candidate) => candidate.id === account.id)
}))
const cyberAccounts = computed(() => filteredScopedAccounts.value.filter((account) => {
  if (!selectedPolicy.value) return false
  return selectedPolicy.value.cyber_feedback_account_ids.includes(account.id) || accountsForGroup(selectedPolicy.value.group_id).some((candidate) => candidate.id === account.id)
}))
const riskOutsideScopeIDs = computed(() => selectedPolicy.value ? selectedPolicy.value.risk_route_account_ids.filter((id) => !accountsForGroup(selectedPolicy.value!.group_id).some((account) => account.id === id)) : [])
const cyberOutsideScopeIDs = computed(() => selectedPolicy.value ? selectedPolicy.value.cyber_feedback_account_ids.filter((id) => !accountsForGroup(selectedPolicy.value!.group_id).some((account) => account.id === id)) : [])

function loadColumns() {
  try {
    const raw = localStorage.getItem('prompt-audit-group-hidden-columns')
    const parsed = raw ? JSON.parse(raw) : []
    if (Array.isArray(parsed)) hiddenColumns.value = parsed.filter((item): item is string => typeof item === 'string' && configurableColumns.value.some((column) => column.key === item))
  } catch { hiddenColumns.value = [] }
  try {
    const raw = localStorage.getItem('prompt-audit-account-hidden-columns')
    const parsed = raw ? JSON.parse(raw) : []
    if (Array.isArray(parsed)) hiddenAccountColumns.value = parsed.filter((item): item is string => typeof item === 'string' && accountConfigurableColumns.value.some((column) => column.key === item))
  } catch { hiddenAccountColumns.value = [] }
  try {
    const raw = localStorage.getItem('prompt-audit-profile-hidden-columns')
    const parsed = raw ? JSON.parse(raw) : []
    if (Array.isArray(parsed)) hiddenProfileColumns.value = parsed.filter((item): item is string => typeof item === 'string' && profileConfigurableColumns.value.some((column) => column.key === item))
  } catch { hiddenProfileColumns.value = [] }
}
function persistColumns() {
  try { localStorage.setItem('prompt-audit-group-hidden-columns', JSON.stringify(hiddenColumns.value)) } catch { /* storage is optional */ }
}
function isColumnVisible(key: string): boolean { return !hiddenColumns.value.includes(key) }
function toggleColumn(key: string) {
  if (['name', 'actions'].includes(key)) return
  hiddenColumns.value = hiddenColumns.value.includes(key) ? hiddenColumns.value.filter((item) => item !== key) : [...hiddenColumns.value, key]
  persistColumns()
}
function isAccountColumnVisible(key: string): boolean { return !hiddenAccountColumns.value.includes(key) || ['name', 'actions'].includes(key) }
function toggleAccountColumn(key: string) {
  if (['name', 'actions'].includes(key)) return
  hiddenAccountColumns.value = hiddenAccountColumns.value.includes(key)
    ? hiddenAccountColumns.value.filter((item) => item !== key)
    : [...hiddenAccountColumns.value, key]
  try { localStorage.setItem('prompt-audit-account-hidden-columns', JSON.stringify(hiddenAccountColumns.value)) } catch { /* storage is optional */ }
}
function isProfileColumnVisible(key: string): boolean { return !hiddenProfileColumns.value.includes(key) || key === 'user' }
function toggleProfileColumn(key: string) {
  if (key === 'user') return
  hiddenProfileColumns.value = hiddenProfileColumns.value.includes(key)
    ? hiddenProfileColumns.value.filter((item) => item !== key)
    : [...hiddenProfileColumns.value, key]
  try { localStorage.setItem('prompt-audit-profile-hidden-columns', JSON.stringify(hiddenProfileColumns.value)) } catch { /* storage is optional */ }
}

function boundedNumber(raw: string, min: number, max: number, fallback: number): number {
  const value = Number(raw)
  return Number.isFinite(value) ? Math.min(max, Math.max(min, Math.round(value))) : fallback
}
function threshold(raw: string, min: number, max: number, fallback: number): number {
  const value = Number(raw)
  return Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : fallback
}
function patchDraft(value: Partial<PromptAuditDraft>) { emit('update:draft', { ...cloneData(props.draft), ...value }) }
function toggleAllGroups(value: boolean) {
  patchDraft({ all_groups: value, group_ids: value ? [] : [...props.draft.group_ids] })
}
function toggleGroupScope(groupID: number) {
  const ids = new Set(props.draft.group_ids)
  if (ids.has(groupID)) ids.delete(groupID)
  else ids.add(groupID)
  patchDraft({ all_groups: false, group_ids: [...ids].sort((left, right) => left - right) })
}
function openEditor(row: GroupRow) {
  selectedPolicy.value = cloneData(row.policy)
  editorTab.value = 'policy'
  accountSearch.value = ''
  profileSearch.value = ''
  profileError.value = ''
  profilePage.value = { items: [], total: 0, page: 1, page_size: profilePageSize, pages: 0 }
}
function closeEditor() {
  selectedPolicy.value = null
  editorTab.value = 'policy'
}
function commitPolicy(policy: PromptAuditGroupPolicy) {
  const nextPolicies = (props.draft.group_policies ?? []).map((item) => cloneData(item))
  const index = nextPolicies.findIndex((item) => groupKey(normalizeGroupID(item.group_id)) === groupKey(policy.group_id))
  if (index < 0) nextPolicies.push(cloneData(policy))
  else nextPolicies.splice(index, 1, cloneData(policy))
  selectedPolicy.value = cloneData(policy)
  emit('update:draft', { ...cloneData(props.draft), group_policies: nextPolicies })
}
function patchPolicy(value: Partial<PromptAuditGroupPolicy>) {
  if (!selectedPolicy.value) return
  const next = { ...cloneData(selectedPolicy.value), ...value }
  if (!next.enabled) {
    next.blocking_enabled = false
    next.blocking_latest_turn_only = false
  }
  if (!next.blocking_enabled) next.blocking_latest_turn_only = false
  if (next.block_threshold <= next.flag_threshold) next.block_threshold = Math.min(1, next.flag_threshold + 0.01)
  commitPolicy(next)
}
function toggleScanner(scannerID: string) {
  if (!selectedPolicy.value) return
  const scanners = selectedPolicy.value.scanners.includes(scannerID)
    ? selectedPolicy.value.scanners.filter((item) => item !== scannerID)
    : [...selectedPolicy.value.scanners, scannerID]
  patchPolicy({ scanners })
}
function updateAccountIDs(kind: 'risk' | 'cyber', values: Array<string | number>) {
  if (!selectedPolicy.value) return
  const ids = Array.from(new Set(values.map((value) => Number(value)).filter((value) => Number.isSafeInteger(value) && value > 0))).sort((left, right) => left - right)
  patchPolicy(kind === 'risk' ? { risk_route_account_ids: ids } : { cyber_feedback_account_ids: ids })
}
function removeAccount(kind: 'risk' | 'cyber', id: number) {
  if (!selectedPolicy.value) return
  const current = kind === 'risk' ? selectedPolicy.value.risk_route_account_ids : selectedPolicy.value.cyber_feedback_account_ids
  updateAccountIDs(kind, current.filter((value) => value !== id))
}
function accountGroups(account: PromptAuditAccount): string {
  return account.groups.length ? account.groups.map((group) => group.name || `#${group.id}`).join(', ') : t('admin.promptAudit.groups.unassigned')
}
function copyPolicy(row: GroupRow) {
  const safe = { ...cloneData(row.policy), risk_route_account_ids: [...row.policy.risk_route_account_ids], cyber_feedback_account_ids: [...row.policy.cyber_feedback_account_ids], excluded_user_ids: [...row.policy.excluded_user_ids] }
  delete (safe as Partial<PromptAuditGroupPolicy>).updated_at
  const text = JSON.stringify(safe, null, 2)
  copiedPolicyKey.value = row.row_key
  void navigator.clipboard?.writeText(text)
  window.setTimeout(() => { if (copiedPolicyKey.value === row.row_key) copiedPolicyKey.value = '' }, 1600)
}
function formatDate(value?: string): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}
function formatRisk(profile: PromptAuditUserProfile): string { return `${profile.high_or_critical_jobs}/${profile.audit_jobs} · ${(profile.high_or_critical_ratio * 100).toFixed(1)}%` }
function formatCyber(profile: PromptAuditUserProfile): string { return `${profile.cyber_blocked_total} · ${(profile.cyber_ratio * 100).toFixed(1)}%` }
function formatCoverage(profile: PromptAuditUserProfile): string { return `${(profile.audit_coverage * 100).toFixed(1)}%` }

function updateExcludedIDs(values: Array<string | number>) {
  const ids = Array.from(new Set(values.map((value) => Number(value)).filter((value) => Number.isSafeInteger(value) && value > 0))).sort((left, right) => left - right)
  patchPolicy({ excluded_user_ids: ids })
}
function selectProfilePage(selected: boolean) {
  if (!selectedPolicy.value) return
  const pageIDs = profilePage.value.items.map((profile) => profile.user_id)
  const current = new Set(selectedPolicy.value.excluded_user_ids)
  pageIDs.forEach((id) => selected ? current.add(id) : current.delete(id))
  updateExcludedIDs([...current])
}
async function loadProfiles() {
  if (!selectedPolicy.value || editorTab.value !== 'profiles') return
  profilesLoading.value = true
  profileError.value = ''
  try {
    profilePage.value = await promptAuditAPI.listUserProfiles({
      days: boundedNumber(String(profileDays.value), 1, 180, 7),
      search: profileSearch.value.trim(),
      min_samples: 0,
        // The API treats zero as the explicit unassigned/default bucket;
        // omitting group_id would query every group and make exclusions look
        // unrelated to the row currently being edited.
        group_id: selectedPolicy.value.group_id ?? 0,
    }, profilePage.value.page, profilePageSize)
  } catch (error) {
    profileError.value = error instanceof Error ? error.message : t('admin.promptAudit.groups.profileLoadError')
  } finally { profilesLoading.value = false }
}
function applyProfileFilters() {
  profilePage.value = { ...profilePage.value, page: 1 }
  void loadProfiles()
}
function changeProfilePage(page: number) {
  profilePage.value = { ...profilePage.value, page: Math.max(1, page) }
  void loadProfiles()
}

watch(editorTab, () => { if (editorTab.value === 'profiles') void loadProfiles() })
watch(() => selectedPolicy.value?.group_id, () => { if (editorTab.value === 'profiles') void loadProfiles() })
onMounted(loadColumns)

const AccountCell = defineComponent({
  props: { account: { type: Object as () => PromptAuditAccount, required: true } },
  setup(accountProps) {
    return () => h('div', { class: 'min-w-0' }, [
      h('span', { class: 'block truncate font-medium text-gray-800 dark:text-dark-100' }, accountProps.account.name || `#${accountProps.account.id}`),
      h('span', { class: 'block text-xs text-gray-500 dark:text-dark-400' }, `#${accountProps.account.id}`),
    ])
  },
})
</script>

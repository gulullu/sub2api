<template>
  <section aria-labelledby="prompt-decision-title" class="border-b border-gray-200 py-6 dark:border-dark-700/60">
    <div>
      <h2 id="prompt-decision-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.decisionPolicy.title') }}</h2>
      <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.decisionPolicy.description') }}</p>
    </div>

    <div class="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(300px,.8fr)]">
      <div class="rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5">
        <div class="grid gap-4 sm:grid-cols-2">
          <label class="block text-sm text-gray-700 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.decisionPolicy.flagThreshold') }}</span>
            <input :value="draft.flag_threshold" class="input mt-1.5 w-full" type="number" min="0" max="0.99" step="0.01" data-test="flag-threshold" :aria-label="t('admin.promptAudit.decisionPolicy.flagThreshold')" @change="setFlagThreshold(($event.target as HTMLInputElement).value)" />
          </label>
          <label class="block text-sm text-gray-700 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.decisionPolicy.blockThreshold') }}</span>
            <input :value="draft.block_threshold" class="input mt-1.5 w-full" type="number" min="0.01" max="1" step="0.01" data-test="block-threshold" :aria-label="t('admin.promptAudit.decisionPolicy.blockThreshold')" @change="setBlockThreshold(($event.target as HTMLInputElement).value)" />
          </label>
        </div>

        <div class="mt-4 grid overflow-hidden rounded-lg border border-gray-200 text-sm dark:border-dark-700 sm:grid-cols-3">
          <div class="bg-emerald-50 px-3 py-3 text-emerald-800 dark:bg-emerald-950/25 dark:text-emerald-200">
            <p class="font-semibold">{{ t('admin.promptAudit.decisionPolicy.allow') }}</p>
            <p class="mt-1 font-mono text-xs">confidence &lt; {{ draft.flag_threshold }}</p>
          </div>
          <div class="border-y border-gray-200 bg-amber-50 px-3 py-3 text-amber-800 dark:border-dark-700 dark:bg-amber-950/25 dark:text-amber-200 sm:border-x sm:border-y-0">
            <p class="font-semibold">{{ t('admin.promptAudit.decisionPolicy.flag') }}</p>
            <p class="mt-1 font-mono text-xs">{{ draft.flag_threshold }} ≤ confidence &lt; {{ draft.block_threshold }}</p>
          </div>
          <div class="bg-red-50 px-3 py-3 text-red-800 dark:bg-red-950/25 dark:text-red-200">
            <p class="font-semibold">{{ t('admin.promptAudit.decisionPolicy.block') }}</p>
            <p class="mt-1 font-mono text-xs">confidence ≥ {{ draft.block_threshold }}</p>
          </div>
        </div>

        <div class="mt-4 rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-dark-700 dark:bg-dark-900/50">
          <label class="block text-sm text-gray-700 dark:text-dark-200">
            <span class="font-medium">{{ t('admin.promptAudit.decisionPolicy.maxTotalInputChars') }}</span>
            <input :value="draft.max_total_input_chars" class="input mt-1.5 w-full" type="number" min="128" max="400000" step="1" data-test="max-total-input-chars" :aria-label="t('admin.promptAudit.decisionPolicy.maxTotalInputChars')" @change="setMaxTotalInputChars(($event.target as HTMLInputElement).value)" />
          </label>
          <p class="mt-2 text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.decisionPolicy.maxTotalInputCharsHint') }}</p>
          <p class="mt-1 text-xs font-medium leading-5" :class="!draft.enabled || !draft.blocking_enabled ? 'text-gray-600 dark:text-dark-300' : draft.risk_route_account_ids.length ? 'text-amber-700 dark:text-amber-300' : 'text-red-700 dark:text-red-300'">
            {{ !draft.enabled ? t('admin.promptAudit.decisionPolicy.overLimitOff') : !draft.blocking_enabled ? t('admin.promptAudit.decisionPolicy.overLimitAsync') : draft.risk_route_account_ids.length ? t('admin.promptAudit.decisionPolicy.overLimitRoute') : t('admin.promptAudit.decisionPolicy.overLimitClosed') }}
          </p>
        </div>
      </div>

      <div class="space-y-4 rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5">
        <label class="block text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.decisionPolicy.httpStatus') }}</span>
          <input :value="draft.block_http_status" class="input mt-1.5 w-full" type="number" min="400" max="499" step="1" data-test="block-http-status" :aria-label="t('admin.promptAudit.decisionPolicy.httpStatus')" @change="setHTTPStatus(($event.target as HTMLInputElement).value)" />
        </label>
        <label class="block text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.decisionPolicy.blockMessage') }}</span>
          <textarea :value="draft.block_message" class="input mt-1.5 min-h-28 w-full resize-y" maxlength="1000" data-test="block-message" :aria-label="t('admin.promptAudit.decisionPolicy.blockMessage')" @input="setBlockMessage(($event.target as HTMLTextAreaElement).value)" />
          <span class="mt-1 block text-right text-xs tabular-nums text-gray-500 dark:text-dark-400">{{ draft.block_message.length }} / 1,000</span>
        </label>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { PromptAuditDraft } from '../types'
import { cloneData, DEFAULT_BLOCK_HTTP_STATUS } from '../viewModel'

const props = defineProps<{ draft: PromptAuditDraft }>()
const emit = defineEmits<{ (event: 'update:draft', value: PromptAuditDraft): void }>()
const { t } = useI18n()

function patch(value: Partial<PromptAuditDraft>) {
  emit('update:draft', { ...cloneData(props.draft), ...value })
}
function numberInRange(raw: string, min: number, max: number, fallback: number): number {
  const parsed = Number(raw)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, parsed))
}
function setFlagThreshold(raw: string) {
  patch({ flag_threshold: numberInRange(raw, 0, Math.max(0, props.draft.block_threshold - 0.01), props.draft.flag_threshold) })
}
function setBlockThreshold(raw: string) {
  patch({ block_threshold: numberInRange(raw, Math.min(1, props.draft.flag_threshold + 0.01), 1, props.draft.block_threshold) })
}
function setHTTPStatus(raw: string) {
  patch({ block_http_status: Math.round(numberInRange(raw, 400, 499, DEFAULT_BLOCK_HTTP_STATUS)) })
}
function setBlockMessage(value: string) {
  patch({ block_message: value.slice(0, 1000) })
}
function setMaxTotalInputChars(raw: string) {
  patch({ max_total_input_chars: Math.round(numberInRange(raw, 128, 400000, props.draft.max_total_input_chars)) })
}
</script>

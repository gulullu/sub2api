<template>
  <section aria-labelledby="prompt-template-title" class="border-b border-gray-200 py-6 dark:border-dark-700/60">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="prompt-template-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.templates.title') }}</h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.templates.description') }}</p>
      </div>
      <button type="button" class="btn btn-primary btn-sm" data-test="add-template" :disabled="draft.prompt_templates.length >= 32" @click="openCreate">
        {{ t('admin.promptAudit.templates.add') }}
      </button>
    </div>

    <div class="mt-5 grid gap-3 lg:grid-cols-2">
      <article
        v-for="template in draft.prompt_templates"
        :key="template.id"
        :data-test="`prompt-template-${template.id}`"
        class="rounded-xl border p-4 transition-colors"
        :class="template.id === draft.active_prompt_template_id ? 'border-primary-400 bg-primary-50/50 dark:border-primary-700 dark:bg-primary-950/20' : 'border-gray-200 dark:border-dark-700/60 dark:bg-dark-900/20'"
      >
        <div class="flex items-start justify-between gap-3">
          <label class="flex min-w-0 cursor-pointer items-start gap-3">
            <input
              type="radio"
              name="prompt-audit-template"
              class="mt-1 h-4 w-4 border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-dark-600 dark:bg-dark-800"
              :checked="template.id === draft.active_prompt_template_id"
              :aria-label="t('admin.promptAudit.templates.activate', { name: template.name })"
              @change="activate(template.id)"
            />
            <span class="min-w-0">
              <span class="flex flex-wrap items-center gap-2">
                <span class="truncate text-sm font-semibold text-gray-950 dark:text-white">{{ template.name }}</span>
                <span v-if="template.builtin" class="rounded bg-gray-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-600 dark:bg-dark-700 dark:text-dark-200">{{ t('admin.promptAudit.templates.builtin') }}</span>
                <span v-if="template.id === draft.active_prompt_template_id" class="rounded bg-primary-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary-700 dark:bg-primary-900/50 dark:text-primary-200">{{ t('admin.promptAudit.templates.active') }}</span>
              </span>
              <span class="mt-1 block font-mono text-[10px] text-gray-400">{{ template.id }}</span>
            </span>
          </label>
          <div class="flex shrink-0 flex-wrap justify-end gap-1">
            <button type="button" class="btn btn-ghost btn-sm" :disabled="draft.prompt_templates.length >= 32" @click="openCopy(template)">{{ t('admin.promptAudit.templates.copy') }}</button>
            <button v-if="!template.builtin" type="button" class="btn btn-ghost btn-sm" @click="openEdit(template)">{{ t('common.edit') }}</button>
            <button v-if="!template.builtin" type="button" class="btn btn-ghost btn-sm text-red-600 dark:text-red-300" @click="removeTemplate(template)">{{ t('common.delete') }}</button>
          </div>
        </div>
        <pre class="mt-3 max-h-28 overflow-hidden whitespace-pre-wrap break-words rounded-lg bg-white/70 px-3 py-2 text-xs leading-5 text-gray-600 dark:bg-dark-900/60 dark:text-dark-300">{{ template.system_prompt }}</pre>
      </article>
    </div>

    <BaseDialog :show="Boolean(editing)" :title="editorTitle" width="wide" @close="closeEditor">
      <form v-if="editing" class="space-y-4" @submit.prevent="saveEditor">
        <label class="block">
          <span class="input-label">{{ t('admin.promptAudit.templates.name') }}</span>
          <input v-model="editing.name" class="input w-full" maxlength="80" required :aria-label="t('admin.promptAudit.templates.name')" />
        </label>
        <label class="block">
          <span class="input-label">{{ t('admin.promptAudit.templates.systemPrompt') }}</span>
          <textarea v-model="editing.system_prompt" class="input min-h-[22rem] w-full resize-y font-mono text-xs leading-5" maxlength="100000" required :aria-label="t('admin.promptAudit.templates.systemPrompt')" />
          <span class="mt-1 block text-right text-xs tabular-nums text-gray-500 dark:text-dark-400">{{ editing.system_prompt.length.toLocaleString() }} / 100,000</span>
        </label>
      </form>
      <template #footer>
        <div class="flex justify-end gap-3">
          <button type="button" class="btn btn-secondary" @click="closeEditor">{{ t('common.cancel') }}</button>
          <button type="button" class="btn btn-primary" data-test="save-template" :disabled="!canSave" @click="saveEditor">{{ t('common.save') }}</button>
        </div>
      </template>
    </BaseDialog>
    <ConfirmDialog
      :show="Boolean(pendingDelete)"
      :title="t('common.delete')"
      :message="pendingDelete ? t('admin.promptAudit.templates.deleteConfirm', { name: pendingDelete.name }) : ''"
      :confirm-text="t('common.delete')"
      danger
      @confirm="confirmRemoveTemplate"
      @cancel="pendingDelete = null"
    />
  </section>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import type { PromptAuditDraft, PromptAuditTemplate } from '../types'
import { cloneData, DEFAULT_PROMPT_TEMPLATE_ID } from '../viewModel'

const props = defineProps<{ draft: PromptAuditDraft }>()
const emit = defineEmits<{ (event: 'update:draft', value: PromptAuditDraft): void }>()
const { t } = useI18n()
const editing = ref<PromptAuditTemplate | null>(null)
const editingOriginalID = ref('')
const pendingDelete = ref<PromptAuditTemplate | null>(null)

const editorTitle = computed(() => editingOriginalID.value
  ? t('admin.promptAudit.templates.edit')
  : t('admin.promptAudit.templates.add'))
const canSave = computed(() => {
  if (!editing.value) return false
  const nameLength = [...editing.value.name.trim()].length
  const promptLength = [...editing.value.system_prompt.trim()].length
  return nameLength >= 1 && nameLength <= 80 && promptLength >= 1 && promptLength <= 100000
})

function emitDraft(patch: Partial<PromptAuditDraft>) {
  emit('update:draft', { ...cloneData(props.draft), ...patch })
}
function activate(id: string) {
  emitDraft({ active_prompt_template_id: id })
}
function newTemplateID(): string {
  const existing = new Set(props.draft.prompt_templates.map((template) => template.id))
  let sequence = props.draft.prompt_templates.length + 1
  let id = `custom-${Date.now().toString(36)}-${sequence}`
  while (existing.has(id)) id = `custom-${Date.now().toString(36)}-${++sequence}`
  return id.slice(0, 64)
}
function openCreate() {
  if (props.draft.prompt_templates.length >= 32) return
  editingOriginalID.value = ''
  editing.value = { id: newTemplateID(), name: '', system_prompt: '', builtin: false }
}
function openCopy(template: PromptAuditTemplate) {
  if (props.draft.prompt_templates.length >= 32) return
  editingOriginalID.value = ''
  editing.value = {
    id: newTemplateID(),
    name: t('admin.promptAudit.templates.copyName', { name: template.name }),
    system_prompt: template.system_prompt,
    builtin: false,
  }
}
function openEdit(template: PromptAuditTemplate) {
  if (template.builtin) return
  editingOriginalID.value = template.id
  editing.value = cloneData(template)
}
function closeEditor() {
  editing.value = null
  editingOriginalID.value = ''
}
function saveEditor() {
  if (!editing.value || !canSave.value) return
  const saved: PromptAuditTemplate = {
    ...cloneData(editing.value),
    name: editing.value.name.trim(),
    system_prompt: editing.value.system_prompt.trim(),
    builtin: false,
  }
  const templates = props.draft.prompt_templates.map((template) => cloneData(template))
  const index = editingOriginalID.value
    ? templates.findIndex((template) => template.id === editingOriginalID.value)
    : -1
  if (index >= 0) templates.splice(index, 1, saved)
  else templates.push(saved)
  emitDraft({ prompt_templates: templates, active_prompt_template_id: saved.id })
  closeEditor()
}
function removeTemplate(template: PromptAuditTemplate) {
  if (template.builtin) return
  pendingDelete.value = cloneData(template)
}
function confirmRemoveTemplate() {
  const template = pendingDelete.value
  if (!template) return
  const templates = props.draft.prompt_templates.filter((item) => item.id !== template.id).map((item) => cloneData(item))
  const fallback = templates.find((item) => item.id === DEFAULT_PROMPT_TEMPLATE_ID)?.id ?? templates[0]?.id ?? ''
  emitDraft({
    prompt_templates: templates,
    active_prompt_template_id: props.draft.active_prompt_template_id === template.id ? fallback : props.draft.active_prompt_template_id,
  })
  pendingDelete.value = null
}
</script>

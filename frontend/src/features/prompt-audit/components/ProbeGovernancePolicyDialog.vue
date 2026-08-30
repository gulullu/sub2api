<template>
  <BaseDialog
    :show="show"
    :title="t('admin.promptAudit.probeGovernance.policy.title', { name: policy?.group_name || '' })"
    width="wide"
    :close-on-click-outside="false"
    @close="close"
  >
    <form v-if="form" class="space-y-6" data-test="probe-governance-policy-form" @submit.prevent="save">
      <div class="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-gray-200 bg-gray-50/60 px-4 py-3 dark:border-dark-700 dark:bg-dark-900/40">
        <div>
          <p class="text-sm font-semibold text-gray-900 dark:text-white">{{ form.group_name }}</p>
          <p class="mt-0.5 text-xs text-gray-500 dark:text-dark-400">#{{ form.group_id }}</p>
        </div>
        <div class="flex items-center gap-3">
          <span class="text-sm text-gray-700 dark:text-dark-200">{{ t('admin.promptAudit.probeGovernance.policy.enabled') }}</span>
          <Toggle
            v-model="form.enabled"
            :aria-label="t('admin.promptAudit.probeGovernance.policy.enabled')"
            data-test="probe-governance-policy-enabled"
          />
        </div>
      </div>

      <section class="space-y-4">
        <div>
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.probeGovernance.policy.requestPolicy') }}</h3>
          <p class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.probeGovernance.policy.requestPolicyHint') }}</p>
        </div>

        <div class="grid gap-4 md:grid-cols-2">
          <Input
            v-model="intervalInput"
            type="number"
            :label="t('admin.promptAudit.probeGovernance.policy.interval')"
            :hint="t('admin.promptAudit.probeGovernance.policy.intervalHint')"
            :error="intervalError"
            :min="60"
            :max="86400"
            :step="1"
            required
            data-test="probe-governance-policy-interval"
          />
          <div>
            <label class="input-label mb-1.5 block">{{ t('admin.promptAudit.probeGovernance.policy.healthScope') }}</label>
            <Select
              v-model="form.health_scope"
              :options="healthScopeOptions"
              :aria-label="t('admin.promptAudit.probeGovernance.policy.healthScope')"
              data-test="probe-governance-policy-health-scope"
            />
            <p class="input-hint mt-1.5">{{ t('admin.promptAudit.probeGovernance.policy.healthScopeHint') }}</p>
          </div>
        </div>

        <div class="grid gap-3 md:grid-cols-3">
          <PolicyToggle
            :label="t('admin.promptAudit.probeGovernance.policy.allowFirstReal')"
            :hint="t('admin.promptAudit.probeGovernance.policy.allowFirstRealHint')"
            :model-value="form.allow_first_real_probe"
            data-test="probe-governance-policy-first-real"
            @update:model-value="form.allow_first_real_probe = $event"
          />
          <PolicyToggle
            :label="t('admin.promptAudit.probeGovernance.policy.skipRepeatAudit')"
            :hint="t('admin.promptAudit.probeGovernance.policy.skipRepeatAuditHint')"
            :model-value="form.skip_repeat_audit"
            data-test="probe-governance-policy-skip-audit"
            @update:model-value="form.skip_repeat_audit = $event"
          />
          <PolicyToggle
            :label="t('admin.promptAudit.probeGovernance.policy.skipRepeatUpstream')"
            :hint="t('admin.promptAudit.probeGovernance.policy.skipRepeatUpstreamHint')"
            :model-value="form.skip_repeat_upstream"
            data-test="probe-governance-policy-skip-upstream"
            @update:model-value="form.skip_repeat_upstream = $event"
          />
        </div>
      </section>

      <section class="space-y-4 border-t border-gray-200 pt-5 dark:border-dark-700">
        <div>
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.probeGovernance.policy.localResponses') }}</h3>
          <p class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.probeGovernance.policy.localResponsesHint') }}</p>
        </div>
        <TextArea
          v-model="form.healthy_response"
          :label="t('admin.promptAudit.probeGovernance.policy.healthyResponse')"
          :error="responseError(form.healthy_response)"
          required
          :rows="3"
          data-test="probe-governance-policy-healthy-response"
        />
        <TextArea
          v-model="form.violation_response"
          :label="t('admin.promptAudit.probeGovernance.policy.violationResponse')"
          :error="responseError(form.violation_response)"
          required
          :rows="3"
          data-test="probe-governance-policy-violation-response"
        />
        <TextArea
          v-model="form.unknown_response"
          :label="t('admin.promptAudit.probeGovernance.policy.unknownResponse')"
          :error="responseError(form.unknown_response)"
          required
          :rows="3"
          data-test="probe-governance-policy-unknown-response"
        />
      </section>
    </form>

    <template #footer>
      <button type="button" class="btn btn-secondary" :disabled="saving" @click="close">{{ t('common.cancel') }}</button>
      <button type="button" class="btn btn-primary" :disabled="saving || !valid" data-test="probe-governance-policy-save" @click="save">
        {{ saving ? t('common.saving') : t('common.save') }}
      </button>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Input from '@/components/common/Input.vue'
import Select, { type SelectOption } from '@/components/common/Select.vue'
import TextArea from '@/components/common/TextArea.vue'
import Toggle from '@/components/common/Toggle.vue'
import type { ProbeGovernancePolicy, ProbeGovernancePolicyUpdate } from '../types'

const props = defineProps<{ show: boolean; policy: ProbeGovernancePolicy | null; saving: boolean }>()
const emit = defineEmits<{
  (event: 'close'): void
  (event: 'save', groupID: number, value: ProbeGovernancePolicyUpdate): void
}>()
const { t } = useI18n()

type PolicyForm = ProbeGovernancePolicy
const form = ref<PolicyForm | null>(null)
const intervalInput = ref('300')

watch(() => [props.show, props.policy] as const, ([show, policy]) => {
  if (!show || !policy) return
  form.value = JSON.parse(JSON.stringify({ ...policy, health_scope: policy.health_scope || 'group_model_protocol' })) as PolicyForm
  intervalInput.value = String(policy.interval_seconds || 300)
}, { immediate: true, deep: true })

const healthScopeOptions = computed<SelectOption[]>(() => [{
  value: 'group_model_protocol',
  label: t('admin.promptAudit.probeGovernance.policy.healthScopeGroupModelProtocol'),
}])
const intervalValue = computed(() => Number(intervalInput.value))
const intervalError = computed(() => {
  if (!Number.isInteger(intervalValue.value) || intervalValue.value < 60 || intervalValue.value > 86400) {
    return t('admin.promptAudit.probeGovernance.policy.intervalError')
  }
  return ''
})
function responseError(value: string): string {
  const length = value.trim().length
  return length < 1 || length > 1000 ? t('admin.promptAudit.probeGovernance.policy.responseError') : ''
}
const valid = computed(() => Boolean(
  form.value
  && !intervalError.value
  && !responseError(form.value.healthy_response)
  && !responseError(form.value.violation_response)
  && !responseError(form.value.unknown_response),
))

function close() {
  if (!props.saving) emit('close')
}
function save() {
  if (!form.value || !valid.value || props.saving) return
  emit('save', form.value.group_id, {
    enabled: form.value.enabled,
    interval_seconds: intervalValue.value,
    health_scope: form.value.health_scope,
    allow_first_real_probe: form.value.allow_first_real_probe,
    skip_repeat_audit: form.value.skip_repeat_audit,
    skip_repeat_upstream: form.value.skip_repeat_upstream,
    healthy_response: form.value.healthy_response.trim(),
    violation_response: form.value.violation_response.trim(),
    unknown_response: form.value.unknown_response.trim(),
  })
}

const PolicyToggle = defineComponent({
  inheritAttrs: false,
  props: {
    modelValue: { type: Boolean, required: true },
    label: { type: String, required: true },
    hint: { type: String, required: true },
  },
  emits: ['update:modelValue'],
  setup(componentProps, { attrs, emit: componentEmit }) {
    return () => h('div', {
      class: 'flex min-h-28 items-start justify-between gap-3 rounded-xl border border-gray-200 bg-gray-50/60 px-4 py-3 dark:border-dark-700 dark:bg-dark-900/40',
      ...attrs,
    }, [
      h('div', { class: 'min-w-0' }, [
        h('p', { class: 'text-sm font-medium text-gray-800 dark:text-dark-100' }, componentProps.label),
        h('p', { class: 'mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400' }, componentProps.hint),
      ]),
      h(Toggle, {
        modelValue: componentProps.modelValue,
        'aria-label': componentProps.label,
        'onUpdate:modelValue': (value: boolean) => componentEmit('update:modelValue', value),
      }),
    ])
  },
})
</script>

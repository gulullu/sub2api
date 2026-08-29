<template>
  <div ref="dropdownRef" class="relative">
    <button
      type="button"
      class="btn btn-secondary px-2 md:px-3"
      :title="label"
      :aria-expanded="open"
      :data-test="buttonTest"
      @click="open = !open"
    >
      <svg class="h-4 w-4 md:mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5" aria-hidden="true">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 4.5v15m6-15v15m-10.875 0h15.75c.621 0 1.125-.504 1.125-1.125V5.625c0-.621-.504-1.125-1.125-1.125H4.125C3.504 4.5 3 5.004 3 5.625v12.75c0 .621.504 1.125 1.125 1.125z" />
      </svg>
      <span class="hidden md:inline">{{ label }}</span>
    </button>
    <div
      v-if="open"
      class="absolute right-0 top-full z-50 mt-1 max-h-80 w-48 overflow-y-auto rounded-lg border border-gray-200 bg-white py-1 shadow-lg dark:border-dark-600 dark:bg-dark-800"
      :data-test="menuTest"
    >
      <button
        v-for="column in columns"
        :key="column.key"
        type="button"
        class="flex w-full items-center justify-between px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-dark-700"
        @click="$emit('toggle', column.key)"
      >
        <span>{{ column.label }}</span>
        <Icon
          v-if="isVisible(column.key)"
          name="check"
          size="sm"
          class="text-primary-500"
          :stroke-width="2"
        />
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import Icon from '@/components/icons/Icon.vue'

defineProps<{
  label: string
  columns: Array<{ key: string; label: string }>
  isVisible: (key: string) => boolean
  buttonTest?: string
  menuTest?: string
}>()

defineEmits<{
  (event: 'toggle', key: string): void
}>()

const open = ref(false)
const dropdownRef = ref<HTMLElement | null>(null)

function handleClickOutside(event: MouseEvent) {
  if (dropdownRef.value && !dropdownRef.value.contains(event.target as Node)) {
    open.value = false
  }
}

onMounted(() => document.addEventListener('click', handleClickOutside))
onUnmounted(() => document.removeEventListener('click', handleClickOutside))
</script>

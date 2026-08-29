import { nextTick } from 'vue'
import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import Icon from '@/components/icons/Icon.vue'
import ColumnSettingsDropdown from '../components/ColumnSettingsDropdown.vue'

describe('ColumnSettingsDropdown', () => {
  it('matches the Usage column menu and closes when clicking outside', async () => {
    const visibleKeys = new Set(['name'])
    const wrapper = mount(ColumnSettingsDropdown, {
      attachTo: document.body,
      props: {
        label: '列设置',
        columns: [
          { key: 'name', label: '名称' },
          { key: 'status', label: '状态' },
        ],
        isVisible: (key: string) => visibleKeys.has(key),
        buttonTest: 'columns-button',
        menuTest: 'columns-menu',
      },
    })

    const trigger = wrapper.get('[data-test="columns-button"]')
    expect(trigger.classes()).toEqual(expect.arrayContaining(['btn', 'btn-secondary', 'px-2', 'md:px-3']))
    expect(trigger.classes()).not.toContain('btn-sm')
    expect(trigger.attributes('title')).toBe('列设置')
    expect(trigger.find('svg[aria-hidden="true"]').exists()).toBe(true)

    await trigger.trigger('click')
    const menu = wrapper.get('[data-test="columns-menu"]')
    expect(menu.classes()).toEqual(expect.arrayContaining(['top-full', 'z-50', 'mt-1', 'max-h-80', 'w-48', 'overflow-y-auto', 'rounded-lg', 'py-1']))
    expect(menu.find('input[type="checkbox"]').exists()).toBe(false)

    const items = menu.findAll('button')
    expect(items).toHaveLength(2)
    expect(items[0].findComponent(Icon).exists()).toBe(true)
    expect(items[1].findComponent(Icon).exists()).toBe(false)

    await items[1].trigger('click')
    expect(wrapper.emitted('toggle')).toEqual([['status']])
    expect(wrapper.find('[data-test="columns-menu"]').exists()).toBe(true)

    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await nextTick()
    expect(wrapper.find('[data-test="columns-menu"]').exists()).toBe(false)
    expect(trigger.attributes('aria-expanded')).toBe('false')

    wrapper.unmount()
  })
})

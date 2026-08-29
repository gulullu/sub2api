import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import en from '@/i18n/locales/en'
import zh from '@/i18n/locales/zh'

const here = dirname(fileURLToPath(import.meta.url))
const read = (path: string) => readFileSync(resolve(here, path), 'utf8')

describe('Prompt Audit integration surface', () => {
  it('registers an admin and risk-control guarded route', () => {
    const router = read('../../../router/index.ts')
    expect(router).toContain("path: '/admin/prompt-audit'")
    const route = router.slice(router.indexOf("path: '/admin/prompt-audit'"), router.indexOf("path: '/admin/usage'"))
    expect(route).toContain('requiresAuth: true')
    expect(route).toContain('requiresAdmin: true')
    expect(route).toContain('requiresRiskControl: true')
  })

  it('keeps the legacy content moderation route and adds both pages under an expand-only security group', () => {
    const sidebar = read('../../../components/layout/AppSidebar.vue')
    const group = sidebar.slice(sidebar.indexOf("path: '/admin/security-audit'"), sidebar.indexOf("path: '/admin/redeem'"))
    expect(group).toContain('expandOnly: true')
    expect(group).toContain("path: '/admin/risk-control'")
    expect(group).toContain("path: '/admin/prompt-audit'")
  })

  it('keeps Prompt Audit locale trees symmetric and all operational controls named', () => {
    expect(Object.keys(zh.admin.promptAudit)).toEqual(Object.keys(en.admin.promptAudit))
    expect(zh.nav.securityAudit).toBeTruthy()
    expect(en.nav.securityAudit).toBeTruthy()
    const endpoint = read('../components/EndpointPool.vue')
    const runtime = read('../components/RuntimeOverview.vue')
    const riskRoute = read('../components/RiskRouteAccountSelector.vue')
    const events = read('../components/EventWorkspace.vue')
    const dataTable = read('../../../components/common/DataTable.vue')
    expect(endpoint).toContain('aria-label')
    expect(riskRoute).toContain('aria-label')
    expect(zh.admin.promptAudit.riskRoute.hardPoolWarning).toContain('503')
    expect(en.admin.promptAudit.riskRoute.hardPoolWarning).toContain('503')
    expect(zh.admin.promptAudit.riskRoute.hardPoolWarning).toContain('所有审计节点')
    expect(en.admin.promptAudit.riskRoute.hardPoolWarning).toContain('every audit node')
    expect(zh.admin.promptAudit.scanners.audit_unavailable).toBeTruthy()
    expect(en.admin.promptAudit.scannerDescriptions.audit_unavailable).toBeTruthy()
    expect(zh.admin.promptAudit.pool.failoverHint).toContain('相同优先级')
    expect(en.admin.promptAudit.pool.failoverHint).toContain('Equal priorities')
    expect(zh.admin.promptAudit.pool.timeoutWarning).toContain('没有自动修改')
    expect(en.admin.promptAudit.pool.timeoutWarning).toContain('not changed automatically')
    expect(runtime).toContain('metrics.circuitOpen')
    expect(runtime).toContain('metrics.circuitSkip')
    expect(runtime).toContain('metrics.circuitReset')
    expect(zh.admin.promptAudit.metrics.circuitOpen).toBeTruthy()
    expect(en.admin.promptAudit.metrics.circuitReset).toBeTruthy()
    expect(events).toContain('aria-label')
    expect(events).toContain("import DataTable from '@/components/common/DataTable.vue'")
    expect(events).toContain('<DataTable')
    expect(events).not.toContain('<table')
    expect(dataTable).toMatch(/overflow-x:\s*auto/)
    expect(events).toContain('flex flex-1 flex-wrap items-end gap-4')
    expect(events).toContain('sm:min-w-[240px]')
    expect(events).not.toContain('sm:grid-cols-2')
  })
})

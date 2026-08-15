import { apiClient } from '@/api/client'
import { accountsAPI } from '@/api/admin/accounts'
import type {
  PromptAuditAccount,
  PromptAuditConfig,
  PromptAuditEvent,
  PromptAuditGroup,
  PromptAuditRuntime,
  PromptAuditUpdateRequest,
  PromptDeletePreview,
  PromptDeleteResult,
  PromptEventFilters,
  PromptEventPage,
  PromptProbeResult,
  PromptAuditEndpointDraft,
} from './types'
import { eventFilterPayload, eventQueryParams } from './viewModel'

const basePath = '/admin/prompt-audit'
const accountPageSize = 1000

export async function getConfig(): Promise<PromptAuditConfig> {
  const { data } = await apiClient.get<PromptAuditConfig>(`${basePath}/config`)
  return data
}

export async function updateConfig(payload: PromptAuditUpdateRequest): Promise<PromptAuditConfig> {
  const { data } = await apiClient.put<PromptAuditConfig>(`${basePath}/config`, payload)
  return data
}

export async function probeEndpoint(endpoint: PromptAuditEndpointDraft): Promise<PromptProbeResult> {
  const { data } = await apiClient.post<PromptProbeResult>(`${basePath}/endpoints/probe`, {
    endpoint: {
      id: endpoint.id,
      name: endpoint.name,
      protocol: 'openai_compatible',
      adapter: endpoint.adapter,
      base_url: endpoint.base_url,
      model: endpoint.model,
      token: endpoint.token || undefined,
      timeout_ms: endpoint.timeout_ms,
      input_limit: endpoint.input_limit,
      enabled: endpoint.enabled,
    },
  })
  return data
}

export async function getRuntime(): Promise<PromptAuditRuntime> {
  const { data } = await apiClient.get<PromptAuditRuntime>(`${basePath}/runtime`)
  return data
}

export async function listEvents(
  filters: PromptEventFilters,
  page: number,
  pageSize: number,
): Promise<PromptEventPage> {
  const { data } = await apiClient.get<PromptEventPage>(`${basePath}/events`, {
    params: { page, page_size: pageSize, ...eventQueryParams(filters) },
  })
  return data
}

export async function getEvent(id: number): Promise<PromptAuditEvent> {
  const { data } = await apiClient.get<PromptAuditEvent>(`${basePath}/events/${id}`)
  return data
}

export async function deleteEvent(id: number): Promise<PromptDeleteResult> {
  const { data } = await apiClient.delete<PromptDeleteResult>(`${basePath}/events/${id}`)
  return data
}

export async function batchDeleteEvents(ids: number[]): Promise<PromptDeleteResult> {
  const { data } = await apiClient.post<PromptDeleteResult>(`${basePath}/events/batch-delete`, { ids })
  return data
}

export async function previewDelete(filters: PromptEventFilters): Promise<PromptDeletePreview> {
  const { data } = await apiClient.post<PromptDeletePreview>(
    `${basePath}/events/delete-preview`,
    eventFilterPayload(filters),
  )
  return data
}

export async function deleteEventsByFilter(
  filters: PromptEventFilters,
  preview: PromptDeletePreview,
): Promise<PromptDeleteResult> {
  const { data } = await apiClient.post<PromptDeleteResult>(`${basePath}/events/delete-by-filter`, {
    filter: eventFilterPayload(filters),
    snapshot_max_id: preview.snapshot_max_id,
    filter_hash: preview.filter_hash,
    confirmation_token: preview.confirmation_token,
    confirm: true,
  })
  return data
}

export async function listGroups(): Promise<PromptAuditGroup[]> {
  const { data } = await apiClient.get<PromptAuditGroup[]>('/admin/groups/all', {
    params: { include_inactive: true },
  })
  return data
}

export async function listRiskRouteAccounts(): Promise<PromptAuditAccount[]> {
  const accounts = new Map<number, PromptAuditAccount>()
  let page = 1
  let pageCount = 1
  let expectedTotal = 0
  do {
    const result = await accountsAPI.list(page, accountPageSize, {
      lite: '1',
      include_scheduler_score: '0',
      sort_by: 'id',
      sort_order: 'asc',
    })
    expectedTotal = Math.max(expectedTotal, result.total)
    pageCount = Math.max(pageCount, result.pages || Math.ceil(result.total / accountPageSize))
    for (const account of result.items) {
      const groupNames = new Map((account.groups ?? []).map((group) => [group.id, group.name]))
      const groupIDs = new Set([
        ...(account.group_ids ?? []),
        ...(account.groups ?? []).map((group) => group.id),
      ])
      accounts.set(account.id, {
        id: account.id,
        name: account.name,
        platform: account.platform,
        type: account.type,
        status: account.status,
        groups: [...groupIDs]
          .sort((left, right) => left - right)
          .map((id) => ({ id, name: groupNames.get(id) ?? '' })),
      })
    }
    page += 1
  } while (page <= pageCount)

  // A partial list could make a valid persisted ID look deleted. Refuse that
  // state instead of silently replacing it with a stale-account placeholder.
  if (accounts.size < expectedTotal) throw new Error('prompt audit account list is incomplete')
  return [...accounts.values()].sort((left, right) => left.id - right.id)
}

export const promptAuditAPI = {
  getConfig,
  updateConfig,
  probeEndpoint,
  getRuntime,
  listEvents,
  getEvent,
  deleteEvent,
  batchDeleteEvents,
  previewDelete,
  deleteEventsByFilter,
  listGroups,
  listRiskRouteAccounts,
}

export default promptAuditAPI

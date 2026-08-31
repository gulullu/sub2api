import { apiClient } from '@/api/client'
import { accountsAPI } from '@/api/admin/accounts'
import type {
  PromptAuditAccount,
  PromptAuditConfig,
  PromptAuditEndpointDraft,
  PromptAuditEvent,
  PromptAuditGroup,
  PromptAuditRuntime,
  PromptAuditUpdateRequest,
  PromptAuditUserProfileFilter,
  PromptAuditUserProfilePage,
  PromptDeletePreview,
  PromptDeleteResult,
  PromptEventFilters,
  PromptEventPage,
  PromptProbeResult,
  CyberFeedbackActionResult,
  CyberFeedbackDetail,
  CyberFeedbackEvidence,
  CyberFeedbackEvent,
  CyberFeedbackListFilter,
  CyberFeedbackPage,
  CyberFeedbackStatus,
  CyberPolicyRule,
  ProbeGovernanceEventDetail,
  ProbeGovernanceEventEvidence,
  ProbeGovernanceEventFilters,
  ProbeGovernanceEventPage,
  ProbeGovernanceExemption,
  ProbeGovernanceExemptionCreate,
  ProbeGovernanceExemptionPage,
  ProbeGovernancePolicy,
  ProbeGovernancePolicyPage,
  ProbeGovernancePolicyUpdate,
} from './types'
import { eventFilterPayload, eventQueryParams } from './viewModel'

const basePath = '/admin/prompt-audit'
const probeGovernancePath = `${basePath}/probe-governance`
const accountPageSize = 1000

type CyberPolicyRuleWire = CyberPolicyRule & { text_source?: string }

type CyberFeedbackPageWire = Omit<Partial<CyberFeedbackPage>, 'items' | 'active_rules' | 'rules'> & {
  items?: CyberFeedbackEvent[] | null
  active_rules?: CyberPolicyRuleWire[] | null
  rules?: CyberPolicyRuleWire[] | null
}

type CyberFeedbackEvidenceWire = Partial<CyberFeedbackEvidence> | null | undefined

function normalizeCyberPolicyRule(rule: CyberPolicyRuleWire): CyberPolicyRule {
  const { text_source: legacyTextSource, ...normalized } = rule
  const ruleTextSource = rule.rule_text_source || legacyTextSource || ''
  return {
    ...normalized,
    rule_text_source: ruleTextSource,
    recovered_candidate: rule.recovered_candidate === true || ruleTextSource === 'recovered_candidate',
  }
}

function normalizeCyberFeedbackPage(data: CyberFeedbackPageWire | null | undefined): CyberFeedbackPage {
  return {
    items: Array.isArray(data?.items) ? data.items : [],
    total: typeof data?.total === 'number' ? data.total : 0,
    page: typeof data?.page === 'number' ? data.page : 1,
    page_size: typeof data?.page_size === 'number' ? data.page_size : 20,
    active_rules: Array.isArray(data?.active_rules) ? data.active_rules.map(normalizeCyberPolicyRule) : [],
    rules: Array.isArray(data?.rules) ? data.rules.map(normalizeCyberPolicyRule) : undefined,
    config_version: typeof data?.config_version === 'number' ? data.config_version : 0,
  }
}

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
      credential_source: endpoint.credential_source || undefined,
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

export async function listUserProfiles(
  filter: PromptAuditUserProfileFilter,
  page: number,
  pageSize: number,
): Promise<PromptAuditUserProfilePage> {
  const { data } = await apiClient.get<PromptAuditUserProfilePage>(`${basePath}/user-profiles`, {
    params: {
      page,
      page_size: pageSize,
      days: filter.days,
      search: filter.search,
      ...(typeof filter.user_id === 'number' && filter.user_id > 0 ? { user_id: filter.user_id } : {}),
      min_samples: filter.min_samples ?? 0,
      // `0` is the explicit unassigned/default bucket; omitted remains all
      // groups. Keep the distinction so a group-level exclusion editor never
      // silently falls back to the global profile list.
      ...(typeof filter.group_id === 'number' && filter.group_id >= 0 ? { group_id: filter.group_id } : {}),
    },
  })
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

export async function listCyberEvents(
  status: CyberFeedbackStatus,
  page: number,
  pageSize: number,
  filter: CyberFeedbackListFilter = {},
): Promise<CyberFeedbackPage> {
  const { data } = await apiClient.get<CyberFeedbackPageWire>(`${basePath}/cyber/events`, {
    params: {
      status,
      page,
      page_size: pageSize,
      ...(typeof filter.group_id === 'number' && filter.group_id >= 0 ? { group_id: filter.group_id } : {}),
      ...(typeof filter.account_id === 'number' && filter.account_id > 0 ? { account_id: filter.account_id } : {}),
    },
  })
  return normalizeCyberFeedbackPage(data)
}

export async function getCyberEvent(id: number): Promise<CyberFeedbackActionResult> {
  const { data } = await apiClient.get<CyberFeedbackActionResult | CyberFeedbackDetail>(`${basePath}/cyber/events/${id}`)
  return 'id' in data ? { event: data } : data
}

export async function getCyberEvidence(id: number): Promise<CyberFeedbackEvidence> {
  const { data } = await apiClient.get<CyberFeedbackEvidenceWire | { evidence?: CyberFeedbackEvidenceWire }>(`${basePath}/cyber/events/${id}/evidence`)
  let wire: CyberFeedbackEvidenceWire
  if (data && typeof data === 'object' && 'evidence' in data) wire = data.evidence
  else wire = data as CyberFeedbackEvidenceWire
  return {
    available: wire?.available === true,
    full_prompt: typeof wire?.full_prompt === 'string' ? wire.full_prompt : '',
    prompt_length: typeof wire?.prompt_length === 'number' ? wire.prompt_length : 0,
    message_count: typeof wire?.message_count === 'number' ? wire.message_count : 0,
    truncated: wire?.truncated === true,
    user_id: typeof wire?.user_id === 'number' ? wire.user_id : null,
    username: typeof wire?.username === 'string' ? wire.username : '',
    user_email: typeof wire?.user_email === 'string' ? wire.user_email : '',
    api_key_id: typeof wire?.api_key_id === 'number' ? wire.api_key_id : null,
    api_key_name: typeof wire?.api_key_name === 'string' ? wire.api_key_name : '',
    api_key_prefix: typeof wire?.api_key_prefix === 'string' ? wire.api_key_prefix : '',
    group_id: typeof wire?.group_id === 'number' ? wire.group_id : null,
    group_name: typeof wire?.group_name === 'string' ? wire.group_name : '',
    selected_account_id: typeof wire?.selected_account_id === 'number' ? wire.selected_account_id : null,
    selected_account_name: typeof wire?.selected_account_name === 'string' ? wire.selected_account_name : '',
    credential_account_id: typeof wire?.credential_account_id === 'number' ? wire.credential_account_id : null,
    credential_account_name: typeof wire?.credential_account_name === 'string' ? wire.credential_account_name : '',
    credential_account_email: typeof wire?.credential_account_email === 'string' ? wire.credential_account_email : '',
    credential_account_email_source: typeof wire?.credential_account_email_source === 'string' ? wire.credential_account_email_source : 'unavailable',
    identity_source: typeof wire?.identity_source === 'string' ? wire.identity_source : 'unavailable',
    client_ip: typeof wire?.client_ip === 'string' ? wire.client_ip : '',
    user_agent: typeof wire?.user_agent === 'string' ? wire.user_agent : '',
    client_request_id: typeof wire?.client_request_id === 'string' ? wire.client_request_id : '',
  }
}

export async function adoptCyberEvent(
  id: number,
  ruleText: string,
  expectedConfigVersion: number,
): Promise<CyberFeedbackActionResult> {
  const { data } = await apiClient.post<CyberFeedbackActionResult>(`${basePath}/cyber/events/${id}/adopt`, {
    rule_text: ruleText,
    expected_config_version: expectedConfigVersion,
  })
  return data
}

export async function rejectCyberEvent(id: number, reason: string): Promise<CyberFeedbackActionResult> {
  const { data } = await apiClient.post<CyberFeedbackActionResult>(`${basePath}/cyber/events/${id}/reject`, { reason })
  return data
}

export async function regenerateCyberCandidate(id: number): Promise<CyberFeedbackActionResult> {
  const { data } = await apiClient.post<CyberFeedbackActionResult>(`${basePath}/cyber/events/${id}/regenerate`)
  return data
}

export async function revokeCyberRule(id: string, expectedConfigVersion: number): Promise<CyberFeedbackActionResult> {
  const { data } = await apiClient.post<CyberFeedbackActionResult>(`${basePath}/cyber/rules/${encodeURIComponent(id)}/revoke`, {
    expected_config_version: expectedConfigVersion,
  })
  return data
}

export async function restoreCyberRule(id: string, expectedConfigVersion: number): Promise<CyberFeedbackActionResult> {
  const { data } = await apiClient.post<CyberFeedbackActionResult>(`${basePath}/cyber/rules/${encodeURIComponent(id)}/restore`, {
    expected_config_version: expectedConfigVersion,
  })
  return data
}

export async function deleteCyberRule(id: string, expectedConfigVersion: number): Promise<CyberFeedbackActionResult> {
  const { data } = await apiClient.delete<CyberFeedbackActionResult>(`${basePath}/cyber/rules/${encodeURIComponent(id)}`, {
    data: {
      expected_config_version: expectedConfigVersion,
      confirm_rule_id: id,
    },
  })
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

export async function listProbeGovernancePolicies(params: {
  page: number
  page_size: number
  keyword?: string
  status?: string
}): Promise<ProbeGovernancePolicyPage> {
  const { data } = await apiClient.get<ProbeGovernancePolicyPage>(`${probeGovernancePath}/groups`, { params })
  return data
}

export async function updateProbeGovernancePolicy(
  groupID: number,
  payload: ProbeGovernancePolicyUpdate,
): Promise<ProbeGovernancePolicy> {
  const { data } = await apiClient.put<ProbeGovernancePolicy>(`${probeGovernancePath}/groups/${groupID}`, payload)
  return data
}

export async function listProbeGovernanceEvents(
  groupID: number,
  filters: ProbeGovernanceEventFilters,
  page: number,
  pageSize: number,
): Promise<ProbeGovernanceEventPage> {
  const { data } = await apiClient.get<ProbeGovernanceEventPage>(`${probeGovernancePath}/groups/${groupID}/events`, {
    params: {
      page,
      page_size: pageSize,
      ...Object.fromEntries(Object.entries(filters).filter(([, value]) => value !== '' && value != null)),
    },
  })
  return data
}

export async function getProbeGovernanceEvent(id: number): Promise<ProbeGovernanceEventDetail> {
  const { data } = await apiClient.get<ProbeGovernanceEventDetail>(`${probeGovernancePath}/events/${id}`)
  return data
}

export async function getProbeGovernanceEventEvidence(id: number): Promise<ProbeGovernanceEventEvidence> {
  const { data } = await apiClient.get<Partial<ProbeGovernanceEventEvidence> | null>(`${probeGovernancePath}/events/${id}/evidence`)
  return {
    available: data?.available === true,
    full_prompt: typeof data?.full_prompt === 'string' ? data.full_prompt : '',
    prompt_length: typeof data?.prompt_length === 'number' ? data.prompt_length : 0,
    request_id: typeof data?.request_id === 'string' ? data.request_id : '',
    source: typeof data?.source === 'string' ? data.source : 'unavailable',
  }
}

export async function clearProbeGovernanceEvent(id: number, reason: string): Promise<{ cleared: boolean }> {
  const { data } = await apiClient.post<{ cleared: boolean }>(`${probeGovernancePath}/events/${id}/clear`, { reason })
  return data
}

export async function listProbeGovernanceExemptions(
  groupID: number,
  page: number,
  pageSize: number,
  keyword = '',
): Promise<ProbeGovernanceExemptionPage> {
  const { data } = await apiClient.get<ProbeGovernanceExemptionPage>(`${probeGovernancePath}/groups/${groupID}/exemptions`, {
    params: { page, page_size: pageSize, ...(keyword.trim() ? { keyword: keyword.trim() } : {}) },
  })
  return data
}

export async function createProbeGovernanceExemption(
  groupID: number,
  payload: ProbeGovernanceExemptionCreate,
): Promise<ProbeGovernanceExemption> {
  const { data } = await apiClient.post<ProbeGovernanceExemption>(`${probeGovernancePath}/groups/${groupID}/exemptions`, payload)
  return data
}

export async function deleteProbeGovernanceExemption(groupID: number, exemptionID: number): Promise<{ deleted: boolean }> {
  const { data } = await apiClient.delete<{ deleted: boolean }>(`${probeGovernancePath}/groups/${groupID}/exemptions/${exemptionID}`)
  return data
}

export const promptAuditAPI = {
  getConfig,
  updateConfig,
  probeEndpoint,
  getRuntime,
  listUserProfiles,
  listEvents,
  getEvent,
  listCyberEvents,
  getCyberEvent,
  getCyberEvidence,
  adoptCyberEvent,
  rejectCyberEvent,
  regenerateCyberCandidate,
  revokeCyberRule,
  restoreCyberRule,
  deleteCyberRule,
  deleteEvent,
  batchDeleteEvents,
  previewDelete,
  deleteEventsByFilter,
  listGroups,
  listRiskRouteAccounts,
  listProbeGovernancePolicies,
  updateProbeGovernancePolicy,
  listProbeGovernanceEvents,
  getProbeGovernanceEvent,
  getProbeGovernanceEventEvidence,
  clearProbeGovernanceEvent,
  listProbeGovernanceExemptions,
  createProbeGovernanceExemption,
  deleteProbeGovernanceExemption,
}

export default promptAuditAPI

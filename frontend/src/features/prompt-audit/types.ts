export type PromptAuditMode = 'off' | 'async_audit' | 'blocking'
export type PromptDecision = 'pass' | 'flag' | 'critical'
export type PromptRiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type PromptAuditAdapter = 'qwen3guard' | 'confidence_json' | 'openai_moderation'
export type PromptAuditCredentialSource = '' | 'content_moderation'
export type PromptAuditNoRouteFallbackMode = 'allow' | 'block'

export interface PromptAuditTemplate {
  id: string
  name: string
  system_prompt: string
  builtin: boolean
}

export interface PromptAuditAccount {
  id: number
  name: string
  platform: string
  type: string
  status: string
  groups: Array<{
    id: number
    name: string
  }>
}

/**
 * A policy boundary for one real audit group. Older servers may return the
 * former unassigned bucket as group_id 0/null; the draft normalizer drops it
 * because unassigned credentials are never part of local Prompt Audit scope.
 */
export interface PromptAuditGroupPolicy {
  group_id: number | null
  /** Whether this policy's group is currently part of the local audit scope. */
  in_scope: boolean
  enabled: boolean
  blocking_enabled: boolean
  blocking_latest_turn_only: boolean
  store_pass_events: boolean
  strategy: string
  scanners: string[]
  max_total_input_chars: number
  active_prompt_template_id: string
  flag_threshold: number
  block_threshold: number
  block_http_status: number
  block_message: string
  risk_route_account_ids: number[]
  cyber_feedback_account_ids: number[]
  excluded_user_ids: number[]
  no_route_fallback_mode: PromptAuditNoRouteFallbackMode
  updated_at?: string
}

export interface PromptAuditEndpoint {
  id: string
  name: string
  protocol: 'openai_compatible'
  // Optional on the wire for compatibility with configs saved before adapters
  // existed. Drafts always normalize this to qwen3guard.
  adapter?: PromptAuditAdapter
  base_url: string
  model: string
  // Optional on the wire for configs saved before explicit failover priority.
  // Drafts always normalize this to a positive integer.
  priority?: number
  timeout_ms: number
  input_limit: number
  enabled: boolean
  has_token: boolean
  token_status: 'configured' | 'missing' | 'invalid' | string
}

export interface PromptAuditEndpointDraft extends Omit<PromptAuditEndpoint, 'adapter' | 'priority'> {
  adapter: PromptAuditAdapter
  priority: number
  token: string
  credential_source?: PromptAuditCredentialSource
  clear_token: boolean
}

export interface PromptAuditConfig {
  enabled: boolean
  blocking_enabled: boolean
  blocking_latest_turn_only: boolean
  store_pass_events: boolean
  effective_mode: PromptAuditMode
  strategy: 'priority'
  worker_count: number
  queue_capacity: number
  scanners: string[]
  all_groups: boolean
  group_ids: number[]
  risk_route_account_ids?: number[]
  cyber_feedback_account_ids?: number[]
  excluded_user_ids?: number[]
  /** Per-group overrides; omitted by pre-group-policy servers. */
  group_policies?: PromptAuditGroupPolicy[]
  /** Optional legacy/default fallback mode exposed by newer servers. */
  no_route_fallback_mode?: PromptAuditNoRouteFallbackMode
  prompt_templates?: PromptAuditTemplate[]
  active_prompt_template_id?: string
  flag_threshold?: number
  block_threshold?: number
  block_http_status?: number
  block_message?: string
  max_total_input_chars?: number
  endpoints: PromptAuditEndpoint[]
  config_version: number
  updated_at: string
  updated_by: number
  change_summary: string
}

export interface PromptAuditDraft extends Omit<
  PromptAuditConfig,
  | 'endpoints'
  | 'prompt_templates'
  | 'active_prompt_template_id'
  | 'flag_threshold'
  | 'block_threshold'
  | 'block_http_status'
  | 'block_message'
  | 'max_total_input_chars'
  | 'risk_route_account_ids'
  | 'cyber_feedback_account_ids'
  | 'excluded_user_ids'
  | 'group_policies'
> {
  endpoints: PromptAuditEndpointDraft[]
  prompt_templates: PromptAuditTemplate[]
  active_prompt_template_id: string
  flag_threshold: number
  block_threshold: number
  block_http_status: number
  block_message: string
  max_total_input_chars: number
  risk_route_account_ids: number[]
  cyber_feedback_account_ids: number[]
  excluded_user_ids: number[]
  group_policies?: PromptAuditGroupPolicy[]
  /** Legacy/default behavior when no eligible audit route remains. */
  no_route_fallback_mode?: PromptAuditNoRouteFallbackMode
}

export interface PromptAuditUpdateRequest {
  expected_config_version: number
  enabled: boolean
  blocking_enabled: boolean
  blocking_latest_turn_only: boolean
  store_pass_events: boolean
  strategy: 'priority'
  worker_count: number
  queue_capacity: number
  scanners: string[]
  all_groups: boolean
  group_ids: number[]
  risk_route_account_ids: number[]
  cyber_feedback_account_ids: number[]
  excluded_user_ids: number[]
  /** Default behavior for groups without an eligible route. */
  no_route_fallback_mode: PromptAuditNoRouteFallbackMode
  group_policies?: PromptAuditGroupPolicy[]
  prompt_templates: PromptAuditTemplate[]
  active_prompt_template_id: string
  flag_threshold: number
  block_threshold: number
  block_http_status: number
  block_message: string
  max_total_input_chars: number
  endpoints: Array<{
    id: string
    name: string
    protocol: 'openai_compatible'
    adapter: PromptAuditAdapter
    base_url: string
    model: string
    priority: number
    token?: string
    credential_source?: Exclude<PromptAuditCredentialSource, ''>
    clear_token: boolean
    timeout_ms: number
    input_limit: number
    enabled: boolean
  }>
}

export interface PromptAuditUserProfileFilter {
  days: number
  search: string
  user_id?: number
  group_id?: number
  min_samples?: number
}

export interface PromptAuditUserProfile {
  user_id: number
  username: string
  email: string
  status: string
  deleted: boolean
  excluded: boolean
  has_profile: boolean
  audit_jobs: number
  high_risk_jobs: number
  critical_risk_jobs: number
  high_or_critical_jobs: number
  system_exception_jobs: number
  unclassified_jobs: number
  usage_total: number
  cyber_blocked_total: number
  cyber_recorded_total: number
  sample_total: number
  audit_coverage: number
  cyber_ratio: number
  high_risk_ratio: number
  critical_risk_ratio: number
  high_or_critical_ratio: number
  score: number
  last_audit_at?: string
  last_usage_at?: string
  last_cyber_at?: string
  last_recorded_at?: string
}

export interface PromptAuditUserProfilePage {
  items: PromptAuditUserProfile[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface PromptProbeResult {
  ok: boolean
  status: string
  error_code?: string
  message: string
  latency_ms: number
  http_status: number
  retryable: boolean
  checked_at: string
  token_applied: boolean
}

export interface PromptQueueStats {
  staging: number
  queued: number
  processing: number
  retry: number
  done: number
  failed: number
  active: number
}

export interface PromptGuardMetrics {
  total: number
  allowed: number
  flagged: number
  blocked: number
  unavailable: number
  invalid: number
  timeouts: number
  failovers: number
  bulkhead_full: number
  circuit_open?: number
  circuit_skip?: number
  circuit_reset?: number
  record_failed: number
  latency_avg_ms?: number
  latency_p50_ms?: number
  latency_p95_ms?: number
  latency_p99_ms?: number
  latency_max_ms?: number
}

export interface PromptAuditRuntime {
  process_status: 'disabled' | 'running' | 'degraded' | 'error' | string
  effective_mode: PromptAuditMode
  expected_config_version: number
  active_config_version: number
  config_loaded_at?: string
  config_load_error?: string
  worker_total: number
  worker_active: number
  worker_heartbeat_at?: string
  queue_capacity: number
  queue: PromptQueueStats
  processed_total: number
  failed_total: number
  enqueued_total: number
  dropped_total: number
  last_processed_at?: string
  last_error_code?: string
  last_error_message?: string
  database_status: string
  redis_status: string
  endpoints: Record<string, PromptProbeResult>
  guard_metrics: PromptGuardMetrics
}

export interface PromptSnapshot {
  request_id: string
  user_id: number
  username: string
  user_email: string
  api_key_id: number
  api_key_name: string
  group_id?: number
  group_name: string
  provider: string
  endpoint: string
  protocol: string
  model: string
  prompt_hash: string
  redacted_preview: string
  full_prompt: string
  prompt_length: number
  message_count: number
  stage: string
}

export interface PromptIssueSummary {
  category: string
  scanner_id: string
  title: string
  description: string
  severity: string
  severity_label: string
  action: string
  action_label: string
  code: string
  score: number
  evidence: string
  evidence_hash: string
  start_rune?: number
  end_rune?: number
}

export interface PromptAuditEvent {
  id: number
  job_id: number
  snapshot: PromptSnapshot
  decision: PromptDecision
  risk_level: PromptRiskLevel
  action: 'Allow' | 'Warn' | 'Block' | string
  categories: string[]
  matched_scanners: string[]
  scanner_scores: Record<string, number>
  scanner_evidence: Record<string, string>
  scanner_backend: string
  scanner_version: string
  guard_endpoint_id: string
  guard_endpoint_name?: string
  policy_id: string
  policy_version: number
  config_version: number
  chunk_total: number
  latency_ms: number
  issue_summaries: PromptIssueSummary[]
  created_at: string
}

export interface PromptEventFilters {
  decision: string
  risk_level: string
  endpoint: string
  /** Guard/audit node ID; kept separate from the requested upstream endpoint. */
  guard_endpoint_id?: string
  group_id: string
  user_id: string
  api_key_id: string
  request_id: string
  prompt_hash: string
  keyword: string
  start_at: string
  end_at: string
}

export interface PromptEventPage {
  items: PromptAuditEvent[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface PromptDeleteResult {
  deleted_events: number
  deleted_jobs: number
}

export interface PromptDeletePreview {
  matched_count: number
  filter_summary: Record<string, unknown>
  snapshot_max_id: number
  filter_hash: string
  confirmation_token: string
  expires_at: string
}

export interface PromptAuditGroup {
  id: number
  name: string
  status: 'active' | 'inactive'
  platform: string
}

export type ProbeGovernanceHealthScope = 'group_model_protocol'
export type ProbeGovernanceStatusFilter = '' | 'enabled' | 'disabled'
export type ProbeVerdict = 'healthy' | 'confirmed_violation' | 'unknown'
export type ProbeClassification = 'known_health' | 'candidate' | 'healthy' | 'confirmed_violation' | 'unknown' | 'cleared'
export type ProbeProtocol = 'openai_responses' | 'openai_chat_completions' | 'anthropic_messages'
export type ProbeResponseKind = 'upstream' | 'healthy' | 'violation' | 'unknown'

export interface ProbeGovernancePolicy {
  group_id: number
  group_name: string
  enabled: boolean
  interval_seconds: number
  health_scope: ProbeGovernanceHealthScope
  allow_first_real_probe: boolean
  skip_repeat_audit: boolean
  skip_repeat_upstream: boolean
  healthy_response: string
  violation_response: string
  unknown_response: string
  local_responses_24h: number
  skipped_audits_24h: number
  skipped_upstream_24h: number
  last_probe_at?: string
  created_at?: string
  updated_at?: string
  updated_by?: number
}

export interface ProbeGovernancePolicyUpdate {
  enabled?: boolean
  interval_seconds?: number
  health_scope?: ProbeGovernanceHealthScope
  allow_first_real_probe?: boolean
  skip_repeat_audit?: boolean
  skip_repeat_upstream?: boolean
  healthy_response?: string
  violation_response?: string
  unknown_response?: string
}

export interface ProbeGovernancePolicyPage {
  items: ProbeGovernancePolicy[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface ProbeGovernanceEvent {
  id: number
  group_id: number
  group_name: string
  family_fingerprint: string
  family_preview: string
  classification: ProbeClassification
  verdict: ProbeVerdict
  user_id: number | null
  user_email: string
  api_key_id: number | null
  api_key_name: string
  model: string
  protocol: ProbeProtocol
  stream: boolean
  max_tokens: number | null
  first_seen_at: string
  last_seen_at: string
  total_count: number
  local_response_count: number
  audit_skipped_count: number
  upstream_skipped_count: number
  audit_call_count: number
  upstream_call_count: number
  handling: string
  last_real_health_at?: string
  linked_audit_event_id?: number | null
}

export interface ProbeGovernanceEventDetail extends ProbeGovernanceEvent {
  audit_config_version: number
  probe_config_version: number
  evidence: Record<string, unknown>
  risk_source: string
  window_expires_at?: string
  next_real_probe_at?: string
  response_kind: ProbeResponseKind
  prompt_snapshot: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface ProbeGovernanceEventEvidence {
  available: boolean
  full_prompt: string
  prompt_length: number
  request_id: string
  source: 'probe_event' | 'linked_audit_event' | 'unavailable' | string
}

export interface ProbeGovernanceEventFilters {
  verdict: string
  user_id?: number
  user_email: string
  api_key_id?: number
  api_key_name: string
  model: string
  protocol: string
  start_at: string
  end_at: string
}

export interface ProbeGovernanceEventPage {
  items: ProbeGovernanceEvent[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface ProbeGovernanceExemption {
  id: number
  group_id: number
  user_id: number | null
  user_email: string
  api_key_id: number | null
  api_key_name: string
  reason: string
  expires_at?: string | null
  created_at: string
  created_by: number | null
}

export interface ProbeGovernanceExemptionPage {
  items: ProbeGovernanceExemption[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface ProbeGovernanceExemptionCreate {
  user_id?: number
  api_key_id?: number
  reason: string
  expires_at?: string
}

export type CyberFeedbackStatus = 'pending' | 'approved' | 'rejected'
export type CyberPolicyRuleStatus = 'active' | 'disabled' | 'deleted' | 'revoked' | string

/** Optional server-side filters for the CYB feedback list. */
export interface CyberFeedbackListFilter {
  /** Group ID 0 is the explicit unassigned/default bucket. */
  group_id?: number
  account_id?: number
}

// List responses deliberately expose only compact metadata. Administrator-only
// detail and evidence are loaded from separate endpoints when the review dialog
// is opened, so raw evidence can never leak into the event list.
export interface CyberFeedbackEvent {
  id: number
  request_id: string
  turn_number?: number
  account_id: number | null
  group_id: number | null
  model: string
  endpoint: string
  protocol: string
  stage: string
  transport: string
  upstream_status: number | null
  redacted_preview: string
  candidate_rule_text: string
  generation_status: 'pending' | 'generated' | 'failed' | string
  generation_error_code: string
  status: CyberFeedbackStatus
  confirm_count: number
  similar_count?: number
  first_confirmed_at?: string
  last_confirmed_at?: string
  created_at?: string
  updated_at?: string
  reviewed_at: string | null
  reviewed_by: number | null
  rule_id: string | null
  config_version: number
  admin_alert_status?: string
}

export interface CyberFeedbackDetail extends CyberFeedbackEvent {
  account_name?: string | null
  upstream_code?: string | null
  upstream_message?: string | null
}

export interface CyberFeedbackEvidence {
  available: boolean
  full_prompt: string
  prompt_length: number
  message_count: number
  truncated: boolean
  user_id: number | null
  username: string
  user_email: string
  api_key_id: number | null
  api_key_name: string
  api_key_prefix: string
  group_id: number | null
  group_name: string
  selected_account_id: number | null
  selected_account_name: string
  credential_account_id: number | null
  credential_account_name: string
  credential_account_email: string
  credential_account_email_source: 'snapshot' | 'current' | 'unavailable' | string
  identity_source: 'snapshot' | 'current' | 'unavailable' | string
  client_ip: string
  user_agent: string
  client_request_id: string
}

export interface CyberPolicyRule {
  id: string
  rule_text: string
  source_feedback_id: number
  status: CyberPolicyRuleStatus
  created_at: string
  created_by: number
  config_version: number
  rule_text_source?: 'reviewed' | 'recovered_candidate' | 'unavailable' | string
  recovered_candidate?: boolean
}

export interface CyberFeedbackPage {
  items: CyberFeedbackEvent[]
  total: number
  page: number
  page_size: number
  active_rules: CyberPolicyRule[]
  rules?: CyberPolicyRule[]
  config_version: number
}

export interface CyberFeedbackActionResult {
  event?: CyberFeedbackDetail
  rule?: CyberPolicyRule
  config_version?: number
}

export interface PromptLoadErrors {
  config: string
  runtime: string
  groups: string
  accounts: string
  events: string
}

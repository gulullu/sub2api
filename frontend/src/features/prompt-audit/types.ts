export type PromptAuditMode = 'off' | 'async_audit' | 'blocking'
export type PromptDecision = 'pass' | 'flag' | 'critical'
export type PromptRiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type PromptAuditAdapter = 'qwen3guard' | 'confidence_json'

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
    clear_token: boolean
    timeout_ms: number
    input_limit: number
    enabled: boolean
  }>
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

export type CyberFeedbackStatus = 'pending' | 'approved' | 'rejected'
export type CyberPolicyRuleStatus = 'active' | 'revoked' | string

// CYB feedback deliberately exposes only the minimum metadata needed for
// administrator review. Raw prompts, hashes, user/key identity, and account
// names are not part of this frontend contract.
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

export interface CyberPolicyRule {
  id: string
  rule_text: string
  source_feedback_id: number
  status: CyberPolicyRuleStatus
  created_at: string
  created_by: number
  config_version: number
}

export interface CyberFeedbackPage {
  items: CyberFeedbackEvent[]
  total: number
  page: number
  page_size: number
  active_rules: CyberPolicyRule[]
  config_version: number
}

export interface CyberFeedbackActionResult {
  event?: CyberFeedbackEvent
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

package securityaudit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

const (
	probeRedisPrefix        = "sub2api:prompt_probe:"
	probeConfigCacheTTL     = 15 * time.Second
	probeFamilyHealthyTTL   = 24 * time.Hour
	probeFamilyViolationTTL = 7 * 24 * time.Hour
	probeClaimTTL           = 2 * time.Minute
	maxProbeCandidateRunes  = 128
)

var compareDeleteProbeLock = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0`)

var compareExpireProbeLock = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 0`)

type ProbeGovernanceResult struct {
	Enabled        bool
	Applied        bool
	Local          *ProbeLocalResponse
	Claim          *ProbeForwardClaim
	PromptDecision *PromptDecision
	AuditDecision  *Decision
}

type ProbeForwardClaim struct {
	request        Request
	shape          probeRequestShape
	config         ProbeGroupConfig
	policyVersion  int64
	classification string
	riskSource     string
	auditCalled    bool
	linkedEventID  *int64
	behaviorKey    string
	claimKeys      []probeLockClaim
	healthKey      string
	renewCancel    context.CancelFunc
	finishOnce     sync.Once
}

type probeLockClaim struct {
	key   string
	token string
}

type probeFamilyState struct {
	Classification  string       `json:"classification"`
	Verdict         string       `json:"verdict"`
	AuditKind       DecisionKind `json:"audit_kind,omitempty"`
	RouteAccountIDs []int64      `json:"route_account_ids,omitempty"`
}

func promptDecisionFromProbeFamilyState(state probeFamilyState) *PromptDecision {
	kind := state.AuditKind
	if kind != DecisionFlag {
		kind = DecisionAllow
	}
	return &PromptDecision{
		Kind:            kind,
		AllowNextStage:  true,
		RouteAccountIDs: append([]int64(nil), state.RouteAccountIDs...),
	}
}

func (s *PromptService) ProbeGovernanceEnabled(ctx context.Context, req Request) bool {
	if s == nil || s.payload == nil || s.payload.client == nil || req.GroupID == nil || *req.GroupID <= 0 {
		return false
	}
	if !supportedProbeRequest(req) {
		return false
	}
	if _, ok := s.probeAuditConfigForRequest(req); !ok {
		return false
	}
	cfg, err := s.loadProbeGroupConfig(ctx, *req.GroupID)
	return err == nil && cfg.Enabled
}

func (s *PromptService) GovernProbe(ctx context.Context, req Request) ProbeGovernanceResult {
	return s.governProbe(ctx, req, false, false)
}

func (s *PromptService) GovernConfirmedProbe(ctx context.Context, req Request) ProbeGovernanceResult {
	return s.governProbe(ctx, req, true, true)
}

func (s *PromptService) governProbe(ctx context.Context, req Request, confirmedViolation, forceCandidate bool) ProbeGovernanceResult {
	if s == nil || s.repo == nil || s.payload == nil || s.payload.client == nil ||
		req.GroupID == nil || *req.GroupID <= 0 || ctx == nil || ctx.Err() != nil {
		return ProbeGovernanceResult{}
	}
	if !supportedProbeRequest(req) {
		return ProbeGovernanceResult{}
	}
	active, ok := s.probeAuditConfigForRequest(req)
	if !ok {
		return ProbeGovernanceResult{}
	}
	probeConfig, err := s.loadProbeGroupConfig(ctx, *req.GroupID)
	if err != nil || !probeConfig.Enabled {
		return ProbeGovernanceResult{}
	}
	result := ProbeGovernanceResult{Enabled: true}
	shape, ok := analyzeProbeRequest(req)
	if forceCandidate {
		if !ok {
			shape = fallbackProbeShape(req)
		}
		shape.Candidate = true
	} else if !ok || !shape.Candidate {
		return result
	}
	policyVersion := combinedProbePolicyVersion(active.ConfigVersion, probeConfig.PolicyVersion)
	behaviorKey := probeBehaviorKey(*req.GroupID, req.UserID, policyVersion, shape.Fingerprint)
	if confirmedViolation {
		state := probeFamilyState{Classification: ProbeClassificationConfirmedViolation, Verdict: ProbeVerdictConfirmedViolation}
		// Durable CYB evidence is already authoritative. Redis is only an
		// optimization here; a transient cache write failure must not fall back to
		// the historical 403 path or allow the request to reach an upstream.
		_ = s.setProbeFamilyState(ctx, behaviorKey, state, probeFamilyViolationTTL)
		delta := probeEventDelta{Request: req, Shape: shape, Classification: state.Classification,
			Verdict: state.Verdict, RiskSource: "cyber_policy", Handling: "local_violation",
			ResponseKind: "violation", PolicyVersion: policyVersion, LocalResponse: true,
			AuditSkipped: true, UpstreamSkipped: true}
		s.recordProbeEventAsync(delta)
		return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, probeConfig.ViolationResponse, "violation")}
	}

	state, exists, stateErr := s.getProbeFamilyState(ctx, behaviorKey)
	if stateErr != nil {
		return result // Redis failures preserve the pre-feature request path.
	}
	if exists && state.Verdict == ProbeVerdictConfirmedViolation {
		// Repeated confirmed probes refresh the rolling suppression period. Only a
		// family that stays silent for the full violation TTL is eligible for a new
		// audit after the cached evidence expires.
		_ = s.setProbeFamilyState(ctx, behaviorKey, state, probeFamilyViolationTTL)
		delta := probeEventDelta{Request: req, Shape: shape, Classification: ProbeClassificationConfirmedViolation,
			Verdict: ProbeVerdictConfirmedViolation, RiskSource: "cached_confirmed_violation",
			Handling: "local_violation", ResponseKind: "violation", PolicyVersion: policyVersion,
			LocalResponse: true, AuditSkipped: true, UpstreamSkipped: true}
		s.recordProbeEventAsync(delta)
		return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, probeConfig.ViolationResponse, "violation")}
	}

	if shape.KnownHealth {
		exempt, exemptionErr := s.isProbeExempt(ctx, *req.GroupID, req.UserID, req.APIKeyID)
		if exemptionErr != nil {
			return result
		}
		return s.activateProbeClaim(s.handleSafeProbe(ctx, req, shape, probeConfig, policyVersion, behaviorKey,
			ProbeClassificationKnownHealth, "known_health_fingerprint", false, nil, exempt))
	}
	// User exclusions govern Prompt Audit admission, not the stronger known
	// health/CYB replay controls. A weak candidate for an excluded user follows
	// the pre-feature path without a Luna call or synthetic response.
	if !active.IncludesUser(req.UserID) {
		return result
	}
	exempt, exemptionErr := s.isProbeExempt(ctx, *req.GroupID, req.UserID, req.APIKeyID)
	if exemptionErr != nil {
		return result
	}
	if exists && state.Verdict == ProbeVerdictHealthy && probeConfig.SkipRepeatAudit {
		// Keep the original allow/flag decision (including its hard-route pool)
		// alive while the probe family remains active. A full quiet TTL is required
		// before Luna may classify the family again.
		_ = s.setProbeFamilyState(ctx, behaviorKey, state, probeFamilyHealthyTTL)
		safe := s.handleSafeProbe(ctx, req, shape, probeConfig, policyVersion, behaviorKey,
			ProbeClassificationHealthy, "cached_audit_allow", false, nil, exempt)
		if safe.Claim != nil {
			safe.PromptDecision = promptDecisionFromProbeFamilyState(state)
		}
		return s.activateProbeClaim(safe)
	}
	if exists && state.Verdict == ProbeVerdictUnknown && probeConfig.SkipRepeatAudit {
		delta := probeEventDelta{Request: req, Shape: shape, Classification: ProbeClassificationUnknown,
			Verdict: ProbeVerdictUnknown, RiskSource: "cached_audit_unavailable", Handling: "local_unknown",
			ResponseKind: "unknown", PolicyVersion: policyVersion, LocalResponse: true,
			AuditSkipped: true, UpstreamSkipped: true}
		s.recordProbeEventAsync(delta)
		return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, probeConfig.UnknownResponse, "unknown")}
	}

	auditLock := probeAuditLockKey(*req.GroupID, req.UserID, policyVersion, shape.Fingerprint)
	auditToken := newProbeLockToken()
	locked, lockErr := s.payload.client.SetNX(ctx, auditLock, auditToken, probeClaimTTL).Result()
	if lockErr != nil {
		return result
	}
	if !locked {
		delta := probeEventDelta{Request: req, Shape: shape, Classification: ProbeClassificationCandidate,
			Verdict: ProbeVerdictUnknown, RiskSource: "audit_singleflight_pending", Handling: "pending_coalesced",
			ResponseKind: "unknown", PolicyVersion: policyVersion, LocalResponse: true,
			AuditSkipped: true, UpstreamSkipped: true}
		s.recordProbeEventAsync(delta)
		return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, probeConfig.UnknownResponse, "unknown")}
	}
	claim := probeLockClaim{key: auditLock, token: auditToken}
	releaseAudit := true
	defer func() {
		if releaseAudit {
			s.releaseProbeLocks(context.Background(), []probeLockClaim{claim})
		}
	}()

	snapshot, snapshotErr := ExtractBlockingPromptSnapshot(req, true)
	if snapshotErr != nil {
		return result
	}
	decision, evaluateErr := s.evaluator.Evaluate(ctx, active, snapshot)
	if evaluateErr != nil || decision == nil {
		_ = s.setProbeFamilyState(ctx, behaviorKey, probeFamilyState{
			Classification: ProbeClassificationUnknown, Verdict: ProbeVerdictUnknown,
		}, time.Duration(probeConfig.IntervalSeconds)*time.Second)
		delta := probeEventDelta{Request: req, Shape: shape, Classification: ProbeClassificationUnknown,
			Verdict: ProbeVerdictUnknown, RiskSource: "audit_unavailable", Handling: "audit_unavailable",
			ResponseKind: "unknown", PolicyVersion: policyVersion, LocalResponse: true,
			AuditCalled: true, UpstreamSkipped: true}
		s.recordProbeEventAsync(delta)
		return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, probeConfig.UnknownResponse, "unknown")}
	}
	linkedID, _ := s.repo.FindLatestPromptAuditEventID(ctx, *req.GroupID, snapshot.PromptHash)
	if decision.Kind == DecisionBlock {
		_ = s.setProbeFamilyState(ctx, behaviorKey, probeFamilyState{
			Classification: ProbeClassificationConfirmedViolation, Verdict: ProbeVerdictConfirmedViolation,
		}, probeFamilyViolationTTL)
		delta := probeEventDelta{Request: req, Shape: shape, Classification: ProbeClassificationConfirmedViolation,
			Verdict: ProbeVerdictConfirmedViolation, RiskSource: "group_policy_block", Handling: "audit_blocked",
			ResponseKind: "violation", PolicyVersion: policyVersion, LocalResponse: true,
			AuditCalled: true, UpstreamSkipped: true, LinkedAuditEventID: linkedID}
		s.recordProbeEventAsync(delta)
		return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, probeConfig.ViolationResponse, "violation")}
	}
	if decision.Kind == DecisionInvalid || decision.Kind == DecisionUnavailable {
		_ = s.setProbeFamilyState(ctx, behaviorKey, probeFamilyState{
			Classification: ProbeClassificationUnknown, Verdict: ProbeVerdictUnknown,
		}, time.Duration(probeConfig.IntervalSeconds)*time.Second)
		delta := probeEventDelta{Request: req, Shape: shape, Classification: ProbeClassificationUnknown,
			Verdict: ProbeVerdictUnknown, RiskSource: "audit_unavailable", Handling: "audit_unavailable",
			ResponseKind: "unknown", PolicyVersion: policyVersion, LocalResponse: true,
			AuditCalled: true, UpstreamSkipped: true, LinkedAuditEventID: linkedID}
		s.recordProbeEventAsync(delta)
		return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, probeConfig.UnknownResponse, "unknown")}
	}

	// Persist the prompt decision separately from upstream health. This prevents
	// repeated Luna calls when the first real forward is disabled, coalesced,
	// unavailable before dispatch, or reaches an unhealthy upstream. A cached
	// flag also retains its hard-route pool for the next real forward.
	_ = s.setProbeFamilyState(ctx, behaviorKey, probeFamilyState{
		Classification:  ProbeClassificationHealthy,
		Verdict:         ProbeVerdictHealthy,
		AuditKind:       decision.Kind,
		RouteAccountIDs: append([]int64(nil), decision.RouteAccountIDs...),
	}, probeFamilyHealthyTTL)

	// Audit allow/flag is not health. It only authorizes one real request. The
	// handler will call FinalizeProbeForward after the actual upstream response.
	safe := s.handleSafeProbe(ctx, req, shape, probeConfig, policyVersion, behaviorKey,
		ProbeClassificationCandidate, "audit_allow", true, linkedID, exempt)
	if safe.Claim != nil {
		safe.Claim.claimKeys = append(safe.Claim.claimKeys, claim)
		releaseAudit = false
		safe.PromptDecision = decision
	}
	return s.activateProbeClaim(safe)
}

func (s *PromptService) activateProbeClaim(result ProbeGovernanceResult) ProbeGovernanceResult {
	if s == nil || result.Claim == nil || len(result.Claim.claimKeys) == 0 || s.payload == nil || s.payload.client == nil {
		return result
	}
	ctx, cancel := context.WithCancel(context.Background())
	result.Claim.renewCancel = cancel
	claim := result.Claim
	go func() {
		ticker := time.NewTicker(probeClaimTTL / 3)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.renewProbeLocks(ctx, claim.claimKeys)
			}
		}
	}()
	return result
}

func beginProbeClaimFinish(claim *ProbeForwardClaim) bool {
	if claim == nil {
		return false
	}
	started := false
	claim.finishOnce.Do(func() { started = true })
	if started && claim.renewCancel != nil {
		claim.renewCancel()
	}
	return started
}

func (s *PromptService) handleSafeProbe(
	ctx context.Context,
	req Request,
	shape probeRequestShape,
	cfg ProbeGroupConfig,
	policyVersion int64,
	behaviorKey, classification, riskSource string,
	auditCalled bool,
	linkedID *int64,
	exempt bool,
) ProbeGovernanceResult {
	groupID := *req.GroupID
	healthKey := probeHealthKey(groupID, policyVersion, canonicalProbeModel(req.Model), req.Protocol)
	bypassWindow := exempt || !cfg.SkipRepeatUpstream
	if !bypassWindow {
		value, err := s.payload.client.Get(ctx, healthKey).Result()
		if err == nil && value == "healthy" {
			next := s.now().Add(time.Duration(cfg.IntervalSeconds) * time.Second)
			delta := probeEventDelta{Request: req, Shape: shape, Classification: classification,
				Verdict: ProbeVerdictHealthy, RiskSource: riskSource, Handling: "local_healthy", ResponseKind: "healthy",
				PolicyVersion: policyVersion, LocalResponse: true, AuditSkipped: !auditCalled,
				UpstreamSkipped: true, AuditCalled: auditCalled, LinkedAuditEventID: linkedID, NextRealProbeAt: &next}
			s.recordProbeEventAsync(delta)
			return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, cfg.HealthyResponse, "healthy")}
		}
		if err == nil && value == "unknown" {
			delta := probeEventDelta{Request: req, Shape: shape, Classification: ProbeClassificationUnknown,
				Verdict: ProbeVerdictUnknown, RiskSource: "upstream_cooldown", Handling: "local_unknown",
				ResponseKind: "unknown", PolicyVersion: policyVersion, LocalResponse: true,
				AuditSkipped: !auditCalled, UpstreamSkipped: true, AuditCalled: auditCalled,
				LinkedAuditEventID: linkedID}
			s.recordProbeEventAsync(delta)
			return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, cfg.UnknownResponse, "unknown")}
		}
		if err != nil && !errors.Is(err, redis.Nil) {
			if auditCalled {
				return s.localUnknownProbe(req, shape, cfg, policyVersion, classification,
					"redis_unavailable_after_audit", auditCalled, linkedID)
			}
			return ProbeGovernanceResult{Enabled: true}
		}
	}
	if !cfg.AllowFirstRealProbe && !bypassWindow {
		return s.localUnknownProbe(req, shape, cfg, policyVersion, classification,
			riskSource+"_first_probe_disabled", auditCalled, linkedID)
	}
	pendingKey := probeHealthPendingKey(groupID, policyVersion, canonicalProbeModel(req.Model), req.Protocol)
	pendingToken := newProbeLockToken()
	locked, err := s.payload.client.SetNX(ctx, pendingKey, pendingToken, probeClaimTTL).Result()
	if err != nil {
		if auditCalled {
			return s.localUnknownProbe(req, shape, cfg, policyVersion, classification,
				"redis_unavailable_after_audit", auditCalled, linkedID)
		}
		return ProbeGovernanceResult{Enabled: true}
	}
	if !locked {
		delta := probeEventDelta{Request: req, Shape: shape, Classification: classification,
			Verdict: ProbeVerdictUnknown, RiskSource: "health_singleflight_pending", Handling: "pending_coalesced",
			ResponseKind: "unknown", PolicyVersion: policyVersion, LocalResponse: true,
			AuditSkipped: !auditCalled, UpstreamSkipped: true, AuditCalled: auditCalled, LinkedAuditEventID: linkedID}
		s.recordProbeEventAsync(delta)
		return ProbeGovernanceResult{Enabled: true, Applied: true, Local: probeLocalResponse(req, shape, cfg.UnknownResponse, "unknown")}
	}
	return ProbeGovernanceResult{Enabled: true, Applied: true, Claim: &ProbeForwardClaim{
		request: req.Clone(), shape: shape, config: cfg, policyVersion: policyVersion,
		classification: classification, riskSource: riskSource, auditCalled: auditCalled,
		linkedEventID: linkedID, behaviorKey: behaviorKey, healthKey: healthKey,
		claimKeys: []probeLockClaim{{key: pendingKey, token: pendingToken}},
	}}
}

func (s *PromptService) localUnknownProbe(
	req Request,
	shape probeRequestShape,
	cfg ProbeGroupConfig,
	policyVersion int64,
	classification, riskSource string,
	auditCalled bool,
	linkedID *int64,
) ProbeGovernanceResult {
	delta := probeEventDelta{Request: req, Shape: shape, Classification: classification,
		Verdict: ProbeVerdictUnknown, RiskSource: riskSource, Handling: "local_unknown",
		ResponseKind: "unknown", PolicyVersion: policyVersion, LocalResponse: true,
		AuditSkipped: !auditCalled, UpstreamSkipped: true, AuditCalled: auditCalled,
		LinkedAuditEventID: linkedID}
	s.recordProbeEventAsync(delta)
	return ProbeGovernanceResult{Enabled: true, Applied: true,
		Local: probeLocalResponse(req, shape, cfg.UnknownResponse, "unknown")}
}

func (s *PromptService) FinalizeProbeForward(claim *ProbeForwardClaim, upstreamAttempted, upstreamSucceeded bool) {
	if s == nil || claim == nil || s.payload == nil || s.payload.client == nil {
		return
	}
	if !beginProbeClaimFinish(claim) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if upstreamSucceeded {
		upstreamAttempted = true
	}
	now := s.now()
	delta := probeEventDelta{Request: claim.request, Shape: claim.shape, Classification: claim.classification,
		Verdict: ProbeVerdictUnknown, RiskSource: claim.riskSource, Handling: "audit_then_forward",
		ResponseKind: "upstream", PolicyVersion: claim.policyVersion, AuditCalled: claim.auditCalled,
		UpstreamCalled: upstreamAttempted, LinkedAuditEventID: claim.linkedEventID}
	if !claim.auditCalled {
		delta.Handling = "forwarded_real_probe"
		delta.AuditSkipped = true
	}
	if !upstreamAttempted {
		// Model availability, account selection, balance, or concurrency may stop
		// the normal request before any upstream dispatch. That is not evidence of
		// upstream health and must not create a group-wide unknown cooldown.
		delta.Handling = "forward_not_attempted"
		delta.ResponseKind = "unknown"
		delta.UpstreamSkipped = true
		s.recordProbeEventAsync(delta)
		s.releaseProbeLocks(ctx, claim.claimKeys)
		return
	}
	if upstreamSucceeded {
		delta.Verdict = ProbeVerdictHealthy
		delta.Classification = ProbeClassificationHealthy
		delta.LastRealHealthAt = &now
		expires := now.Add(time.Duration(claim.config.IntervalSeconds) * time.Second)
		delta.WindowExpiresAt = &expires
		delta.NextRealProbeAt = &expires
		_ = s.payload.client.Set(ctx, claim.healthKey, "healthy", time.Duration(claim.config.IntervalSeconds)*time.Second).Err()
	} else {
		delta.Classification = ProbeClassificationUnknown
		delta.RiskSource = "upstream_not_healthy"
		_ = s.payload.client.Set(ctx, claim.healthKey, "unknown", time.Duration(claim.config.IntervalSeconds)*time.Second).Err()
	}
	s.recordProbeEventAsync(delta)
	s.releaseProbeLocks(ctx, claim.claimKeys)
}

func (s *PromptService) ReleaseProbeForwardClaim(claim *ProbeForwardClaim) {
	if s == nil || claim == nil {
		return
	}
	if !beginProbeClaimFinish(claim) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.releaseProbeLocks(ctx, claim.claimKeys)
}

func (s *PromptService) RejectProbeForwardClaim(claim *ProbeForwardClaim, riskSource string) *ProbeLocalResponse {
	if s == nil || claim == nil {
		return nil
	}
	if !beginProbeClaimFinish(claim) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.setProbeFamilyState(ctx, claim.behaviorKey, probeFamilyState{
		Classification: ProbeClassificationConfirmedViolation, Verdict: ProbeVerdictConfirmedViolation,
	}, probeFamilyViolationTTL)
	s.releaseProbeLocks(ctx, claim.claimKeys)
	s.recordProbeEventAsync(probeEventDelta{
		Request: claim.request, Shape: claim.shape, Classification: ProbeClassificationConfirmedViolation,
		Verdict: ProbeVerdictConfirmedViolation, RiskSource: riskSource, Handling: "audit_blocked",
		ResponseKind: "violation", PolicyVersion: claim.policyVersion, LocalResponse: true,
		AuditCalled: claim.auditCalled, UpstreamSkipped: true, LinkedAuditEventID: claim.linkedEventID,
	})
	return probeLocalResponse(claim.request, claim.shape, claim.config.ViolationResponse, "violation")
}

func (s *PromptService) probeAuditConfigForRequest(req Request) (ActiveConfig, bool) {
	if s == nil || s.config == nil || req.GroupID == nil || *req.GroupID <= 0 {
		return ActiveConfig{}, false
	}
	cfg, ok := s.config.Active()
	if !ok || !cfg.RiskControlEnabled || !cfg.Enabled || !cfg.IncludesGroup(req.GroupID) {
		return ActiveConfig{}, false
	}
	effective := cfg.EffectiveForGroup(req.GroupID)
	if !effective.Enabled || effective.EffectiveMode() == ModeOff {
		return ActiveConfig{}, false
	}
	return effective, true
}

func supportedProbeRequest(req Request) bool {
	endpoint := strings.TrimSpace(req.Endpoint)
	rawPath := strings.ToLower(strings.TrimRight(strings.TrimSpace(req.RawEndpointPath), "/"))
	if rawPath == "" {
		return false
	}
	switch req.Protocol {
	case service.ContentModerationProtocolOpenAIChat:
		return endpoint == "/v1/chat/completions" && stringInProbeSet(rawPath,
			"/v1/chat/completions", "/chat/completions", "/openai/v1/chat/completions")
	case service.ContentModerationProtocolOpenAIResponses:
		return endpoint == "/v1/responses" && stringInProbeSet(rawPath,
			"/v1/responses", "/responses", "/openai/v1/responses", "/backend-api/codex/responses")
	case service.ContentModerationProtocolAnthropicMessages:
		return endpoint == "/v1/messages" && stringInProbeSet(rawPath,
			"/v1/messages", "/messages", "/openai/v1/messages", "/antigravity/v1/messages")
	default:
		return false
	}
}

func stringInProbeSet(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}

func (s *PromptService) loadProbeGroupConfig(ctx context.Context, groupID int64) (ProbeGroupConfig, error) {
	key := probeConfigKey(groupID)
	if s.payload != nil && s.payload.client != nil {
		if raw, err := s.payload.client.Get(ctx, key).Bytes(); err == nil {
			var cfg ProbeGroupConfig
			if json.Unmarshal(raw, &cfg) == nil {
				return cfg, nil
			}
		} else if !errors.Is(err, redis.Nil) {
			return ProbeGroupConfig{}, err
		}
	}
	cfg, err := s.repo.GetProbeGroupConfig(ctx, groupID)
	if err != nil {
		return ProbeGroupConfig{}, err
	}
	if s.payload != nil && s.payload.client != nil {
		if raw, marshalErr := json.Marshal(cfg); marshalErr == nil {
			_ = s.payload.client.Set(ctx, key, raw, probeConfigCacheTTL).Err()
		}
	}
	return cfg, nil
}

func (s *PromptService) getProbeFamilyState(ctx context.Context, key string) (probeFamilyState, bool, error) {
	raw, err := s.payload.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return probeFamilyState{}, false, nil
	}
	if err != nil {
		return probeFamilyState{}, false, err
	}
	var state probeFamilyState
	if err := json.Unmarshal(raw, &state); err != nil {
		return probeFamilyState{}, false, err
	}
	return state, true, nil
}

func (s *PromptService) setProbeFamilyState(ctx context.Context, key string, state probeFamilyState, ttl time.Duration) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.payload.client.Set(ctx, key, raw, ttl).Err()
}

func (s *PromptService) releaseProbeLocks(ctx context.Context, claims []probeLockClaim) {
	if s == nil || s.payload == nil || s.payload.client == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, claim := range claims {
		if claim.key == "" || claim.token == "" {
			continue
		}
		_, _ = compareDeleteProbeLock.Run(ctx, s.payload.client, []string{claim.key}, claim.token).Result()
	}
}

func (s *PromptService) renewProbeLocks(ctx context.Context, claims []probeLockClaim) {
	if s == nil || s.payload == nil || s.payload.client == nil {
		return
	}
	ttlMillis := strconv.FormatInt(probeClaimTTL.Milliseconds(), 10)
	for _, claim := range claims {
		if claim.key == "" || claim.token == "" {
			continue
		}
		_, _ = compareExpireProbeLock.Run(ctx, s.payload.client, []string{claim.key}, claim.token, ttlMillis).Result()
	}
}

func (s *PromptService) recordProbeEventAsync(delta probeEventDelta) {
	if s == nil || s.repo == nil || s.probeEventSlots == nil {
		return
	}
	if delta.ObservedAt.IsZero() {
		delta.ObservedAt = s.now()
	}
	select {
	case s.probeEventSlots <- struct{}{}:
	default:
		s.lifecycleMu.Lock()
		now := s.now()
		if !now.Before(s.probeEventDropLogAt) {
			s.probeEventDropLogAt = now.Add(time.Minute)
			slog.Warn("prompt probe event queue full; aggregate event dropped")
		}
		s.lifecycleMu.Unlock()
		return
	}
	s.lifecycleMu.Lock()
	background := s.background
	now := s.now()
	cleanup := s.probeStatsCleanupAt.IsZero() || !now.Before(s.probeStatsCleanupAt)
	if cleanup {
		s.probeStatsCleanupAt = now.Add(24 * time.Hour)
	}
	s.lifecycleMu.Unlock()
	if background == nil {
		background = context.Background()
	}
	s.enqueueWG.Add(1)
	go func() {
		defer s.enqueueWG.Done()
		defer func() { <-s.probeEventSlots }()
		ctx, cancel := context.WithTimeout(background, 2*time.Second)
		defer cancel()
		_, _ = s.repo.RecordProbeEvent(ctx, delta)
		if cleanup {
			_, _ = s.repo.DeleteOldProbeHourlyStats(ctx, 10_000)
		}
	}()
}

func (s *PromptService) isProbeExempt(ctx context.Context, groupID, userID, apiKeyID int64) (bool, error) {
	if s == nil || s.repo == nil {
		return false, errors.New("prompt probe repository unavailable")
	}
	// Exemptions are mutable and may carry sub-minute expiry. Read PostgreSQL
	// directly so create/delete/expiry semantics are immediate across instances;
	// caching true/false here creates unavoidable stale windows around mutations.
	return s.repo.IsProbeExempt(ctx, groupID, userID, apiKeyID)
}

func analyzeProbeRequest(req Request) (probeRequestShape, bool) {
	if req.Protocol != service.ContentModerationProtocolOpenAIChat &&
		req.Protocol != service.ContentModerationProtocolOpenAIResponses &&
		req.Protocol != service.ContentModerationProtocolAnthropicMessages {
		return probeRequestShape{}, false
	}
	var root map[string]any
	if json.Unmarshal(req.Body, &root) != nil || root == nil {
		return probeRequestShape{}, false
	}
	segments := extractProtocolSegments(req.Protocol, root)
	latest := ""
	userSegments := 0
	nonUserInstructions := 0
	for _, segment := range segments {
		text := strings.TrimSpace(segment.text)
		if text == "" {
			continue
		}
		if segment.user {
			latest = text
			userSegments++
		} else {
			nonUserInstructions++
		}
	}
	if latest == "" || utf8.RuneCountInString(latest) > maxProbeCandidateRunes {
		return probeRequestShape{}, false
	}
	normalized := normalizeProbeFamilyText(latest)
	if normalized == "" {
		return probeRequestShape{}, false
	}
	maxTokens := probeMaxTokens(root)
	stream, _ := root["stream"].(bool)
	richContext := userSegments != 1 || nonUserInstructions > 0 || probeHasRichContext(root)
	haikuHealthProbe := req.ClientIsClaudeCode && maxTokens == 1 && strings.Contains(strings.ToLower(req.Model), "haiku")
	known := haikuHealthProbe || (!richContext && knownHealthProbeText(normalized))
	candidate := haikuHealthProbe || (!richContext && (known || (maxTokens >= 1 && maxTokens <= 8)))
	if !candidate {
		return probeRequestShape{}, false
	}
	digest := sha256.Sum256([]byte("sub2api/prompt-probe-family/v1\x00" + normalized))
	return probeRequestShape{
		Fingerprint: hex.EncodeToString(digest[:]), Preview: BuildPromptPreview(latest, 96), ScanText: latest,
		Stream: stream, MaxTokens: maxTokens, KnownHealth: known, Candidate: candidate,
		Evidence: map[string]any{"short_single_turn": true, "tiny_output_limit": maxTokens > 0 && maxTokens <= 8,
			"known_health_fingerprint": known, "has_tools_or_files": false},
	}, true
}

func fallbackProbeShape(req Request) probeRequestShape {
	snapshot, err := ExtractBlockingPromptSnapshot(req, true)
	text := string(req.Body)
	preview := "[content withheld]"
	if err == nil {
		text, preview = snapshot.ScanText, snapshot.RedactedPreview
	}
	normalized := normalizeProbeFamilyText(text)
	digest := sha256.Sum256([]byte("sub2api/prompt-probe-family/v1\x00" + normalized))
	var root map[string]any
	_ = json.Unmarshal(req.Body, &root)
	stream, _ := root["stream"].(bool)
	return probeRequestShape{Fingerprint: hex.EncodeToString(digest[:]), Preview: preview, ScanText: text,
		Stream: stream, MaxTokens: probeMaxTokens(root), Candidate: true, Evidence: map[string]any{"confirmed_source": true}}
}

func normalizeProbeFamilyText(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func knownHealthProbeText(value string) bool {
	switch value {
	case "hi", "hello", "ping", "pong", "test", "ok", "health", "healthcheck", "areyoualive",
		"sayok", "respondok", "respondwithok", "replyok", "只回复ok", "回复ok", "测试", "健康检查", "服务正常吗":
		return true
	default:
		return false
	}
}

func probeMaxTokens(root map[string]any) int {
	for _, key := range []string{"max_output_tokens", "max_completion_tokens", "max_tokens"} {
		if value, ok := root[key].(float64); ok && value > 0 {
			return int(value)
		}
	}
	return 0
}

func probeHasRichContext(root map[string]any) bool {
	for _, key := range []string{"tools", "tool_choice", "attachments", "files", "previous_response_id"} {
		if value, exists := root[key]; exists && value != nil {
			switch typed := value.(type) {
			case []any:
				if len(typed) > 0 {
					return true
				}
			case string:
				if strings.TrimSpace(typed) != "" {
					return true
				}
			default:
				return true
			}
		}
	}
	raw, _ := json.Marshal(root)
	lower := strings.ToLower(string(raw))
	return strings.Contains(lower, "input_image") || strings.Contains(lower, "image_url") || strings.Contains(lower, "file_id") || strings.Contains(lower, "tool_call") || strings.Contains(lower, "tool_result")
}

func probeLocalResponse(req Request, shape probeRequestShape, message, kind string) *ProbeLocalResponse {
	return &ProbeLocalResponse{Protocol: req.Protocol, Model: req.Model, Stream: shape.Stream, Message: message, Kind: kind}
}

func combinedProbePolicyVersion(auditVersion, probeVersion int64) int64 {
	if auditVersion < 1 {
		auditVersion = 1
	}
	if probeVersion < 1 {
		probeVersion = 1
	}
	return auditVersion*1_000_000 + probeVersion
}

func splitCombinedProbePolicyVersion(version int64) (int64, int64) {
	if version < 1_000_000 {
		return 1, max(version, 1)
	}
	auditVersion := version / 1_000_000
	probeVersion := version % 1_000_000
	if probeVersion < 1 {
		probeVersion = 1
	}
	return auditVersion, probeVersion
}

func canonicalProbeModel(model string) string {
	model = strings.ToLower(strings.TrimSpace(service.NormalizeOpenAICompatRequestedModel(model)))
	if strings.HasPrefix(model, "claude-") {
		model = claude.DenormalizeModelID(claude.NormalizeModelID(model))
	}
	return model
}

func probeConfigKey(groupID int64) string {
	return probeRedisPrefix + "config:" + strconv.FormatInt(groupID, 10)
}
func probeBehaviorKey(groupID, userID, version int64, fingerprint string) string {
	return fmt.Sprintf("%sbehavior:%d:%d:%d:%s", probeRedisPrefix, groupID, userID, version, fingerprint)
}
func probeAuditLockKey(groupID, userID, version int64, fingerprint string) string {
	return fmt.Sprintf("%saudit-lock:%d:%d:%d:%s", probeRedisPrefix, groupID, userID, version, fingerprint)
}
func probeHealthKey(groupID, version int64, model, protocol string) string {
	digest := sha256.Sum256([]byte(model + "\x00" + strings.ToLower(strings.TrimSpace(protocol))))
	return fmt.Sprintf("%shealth:%d:%d:%x", probeRedisPrefix, groupID, version, digest[:12])
}
func probeHealthPendingKey(groupID, version int64, model, protocol string) string {
	return probeHealthKey(groupID, version, model, protocol) + ":pending"
}
func newProbeLockToken() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func (s *PromptService) ListProbeGroups(ctx context.Context, keyword, status string, page, pageSize int) (*ProbeGroupPage, error) {
	ids, err := s.inScopeProbeGroupIDs(ctx)
	if err != nil {
		return nil, err
	}
	return s.repo.ListProbeGroupConfigs(ctx, ids, keyword, status, page, pageSize)
}

func (s *PromptService) SaveProbeGroup(ctx context.Context, groupID int64, req UpdateProbeGroupConfigRequest, actorID int64) (ProbeGroupConfig, error) {
	if !s.isProbeGroupInScope(groupID) {
		return ProbeGroupConfig{}, infraerrors.BadRequest("prompt_probe_group_not_in_scope", "分组当前未纳入提示词审计范围")
	}
	cfg, err := s.repo.GetProbeGroupConfig(ctx, groupID)
	if err != nil {
		return ProbeGroupConfig{}, probeAdminError(err)
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.IntervalSeconds != nil {
		cfg.IntervalSeconds = *req.IntervalSeconds
	}
	if req.HealthScope != nil {
		cfg.HealthScope = strings.TrimSpace(*req.HealthScope)
	}
	if req.AllowFirstRealProbe != nil {
		cfg.AllowFirstRealProbe = *req.AllowFirstRealProbe
	}
	if req.SkipRepeatAudit != nil {
		cfg.SkipRepeatAudit = *req.SkipRepeatAudit
	}
	if req.SkipRepeatUpstream != nil {
		cfg.SkipRepeatUpstream = *req.SkipRepeatUpstream
	}
	if req.HealthyResponse != nil {
		cfg.HealthyResponse = strings.TrimSpace(*req.HealthyResponse)
	}
	if req.ViolationResponse != nil {
		cfg.ViolationResponse = strings.TrimSpace(*req.ViolationResponse)
	}
	if req.UnknownResponse != nil {
		cfg.UnknownResponse = strings.TrimSpace(*req.UnknownResponse)
	}
	if err := validateProbeGroupConfig(cfg); err != nil {
		return ProbeGroupConfig{}, err
	}
	saved, err := s.repo.SaveProbeGroupConfig(ctx, cfg, actorID)
	if err != nil {
		return ProbeGroupConfig{}, probeAdminError(err)
	}
	if s.payload != nil && s.payload.client != nil {
		raw, _ := json.Marshal(saved)
		if cacheErr := s.payload.client.Set(ctx, probeConfigKey(groupID), raw, probeConfigCacheTTL).Err(); cacheErr != nil {
			slog.Warn("prompt probe config cache refresh failed", "group_id", groupID, "error", cacheErr)
		}
	}
	return saved, nil
}

func validateProbeGroupConfig(cfg ProbeGroupConfig) error {
	if cfg.IntervalSeconds < MinProbeIntervalSeconds || cfg.IntervalSeconds > MaxProbeIntervalSeconds {
		return infraerrors.BadRequest("prompt_probe_invalid_interval", "探针最小间隔必须在 60 到 86400 秒之间")
	}
	if cfg.HealthScope != ProbeHealthScopeDefault {
		return infraerrors.BadRequest("prompt_probe_invalid_health_scope", "健康窗口范围无效")
	}
	for _, item := range []string{cfg.HealthyResponse, cfg.ViolationResponse, cfg.UnknownResponse} {
		length := utf8.RuneCountInString(strings.TrimSpace(item))
		if length < 1 || length > 1000 {
			return infraerrors.BadRequest("prompt_probe_invalid_response", "本地响应文案长度必须在 1 到 1000 个字符之间")
		}
	}
	return nil
}

func (s *PromptService) inScopeProbeGroupIDs(ctx context.Context) ([]int64, error) {
	if s == nil || s.config == nil {
		return []int64{}, nil
	}
	cfg, ok := s.config.Active()
	if !ok {
		return []int64{}, nil
	}
	var candidates []int64
	if cfg.AllGroups {
		all, err := s.repo.ListAllActiveProbeGroupIDs(ctx)
		if err != nil {
			return nil, err
		}
		candidates = all
	} else {
		candidates = append(candidates, cfg.GroupIDs...)
		for _, policy := range cfg.GroupPolicies {
			if policy.GroupID > 0 {
				candidates = append(candidates, policy.GroupID)
			}
		}
	}
	ids := make([]int64, 0, len(candidates))
	for _, groupID := range canonicalInt64s(candidates) {
		gid := groupID
		if cfg.IncludesGroup(&gid) {
			ids = append(ids, groupID)
		}
	}
	return ids, nil
}
func (s *PromptService) isProbeGroupInScope(groupID int64) bool {
	if s == nil || s.config == nil || groupID <= 0 {
		return false
	}
	cfg, ok := s.config.Active()
	if !ok {
		return false
	}
	gid := groupID
	return cfg.IncludesGroup(&gid)
}

func (s *PromptService) ListProbeEvents(ctx context.Context, groupID int64, filter ProbeEventFilter, page, pageSize int) (*ProbeEventPage, error) {
	if !s.isProbeGroupInScope(groupID) {
		return nil, infraerrors.BadRequest("prompt_probe_group_not_in_scope", "分组当前未纳入提示词审计范围")
	}
	return s.repo.ListProbeEvents(ctx, groupID, filter, page, pageSize)
}

func (s *PromptService) GetProbeEvent(ctx context.Context, id int64) (*ProbeEvent, error) {
	event, err := s.repo.GetProbeEvent(ctx, id)
	if err != nil {
		return nil, probeAdminError(err)
	}
	if !s.isProbeGroupInScope(event.GroupID) {
		return nil, infraerrors.BadRequest("prompt_probe_group_not_in_scope", "分组当前未纳入提示词审计范围")
	}
	return event, nil
}

func (s *PromptService) ClearProbeEvent(ctx context.Context, id, actorID int64, reason string) (*ProbeEvent, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > 500 {
		return nil, infraerrors.BadRequest("prompt_probe_clear_reason_required", "请填写清除原因")
	}
	before, err := s.repo.GetProbeEvent(ctx, id)
	if err != nil {
		return nil, probeAdminError(err)
	}
	if !s.isProbeGroupInScope(before.GroupID) {
		return nil, infraerrors.BadRequest("prompt_probe_group_not_in_scope", "分组当前未纳入提示词审计范围")
	}
	if s.payload != nil && s.payload.client != nil {
		userID := before.SubjectUserID
		keys := []string{
			probeBehaviorKey(before.GroupID, userID, before.PolicyVersion, before.FamilyFingerprint),
			probeAuditLockKey(before.GroupID, userID, before.PolicyVersion, before.FamilyFingerprint),
			probeHealthKey(before.GroupID, before.PolicyVersion, canonicalProbeModel(before.Model), before.Protocol),
			probeHealthPendingKey(before.GroupID, before.PolicyVersion, canonicalProbeModel(before.Model), before.Protocol),
		}
		if err := s.payload.client.Del(ctx, keys...).Err(); err != nil {
			return nil, infraerrors.ServiceUnavailable("prompt_probe_cache_clear_failed", "探针判定缓存清除失败，请重试")
		}
	}
	event, err := s.repo.ClearProbeEvent(ctx, id, actorID, reason)
	if err != nil {
		return nil, probeAdminError(err)
	}
	return event, nil
}

func (s *PromptService) ListProbeExemptions(ctx context.Context, groupID int64, keyword string, page, pageSize int) (*ProbeExemptionPage, error) {
	if !s.isProbeGroupInScope(groupID) {
		return nil, infraerrors.BadRequest("prompt_probe_group_not_in_scope", "分组当前未纳入提示词审计范围")
	}
	return s.repo.ListProbeExemptions(ctx, groupID, keyword, page, pageSize)
}

func (s *PromptService) CreateProbeExemption(ctx context.Context, groupID int64, req CreateProbeExemptionRequest, actorID int64) (*ProbeExemption, error) {
	if !s.isProbeGroupInScope(groupID) {
		return nil, infraerrors.BadRequest("prompt_probe_group_not_in_scope", "分组当前未纳入提示词审计范围")
	}
	if (req.UserID == nil) == (req.APIKeyID == nil) {
		return nil, infraerrors.BadRequest("prompt_probe_exemption_subject_required", "用户与 API Key 必须且只能选择一个")
	}
	if strings.TrimSpace(req.Reason) == "" || utf8.RuneCountInString(strings.TrimSpace(req.Reason)) > 500 {
		return nil, infraerrors.BadRequest("prompt_probe_exemption_reason_required", "请填写不超过 500 个字符的豁免原因")
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(s.now()) {
		return nil, infraerrors.BadRequest("prompt_probe_exemption_expired", "豁免到期时间必须晚于当前时间")
	}
	req.Reason = strings.TrimSpace(req.Reason)
	item, err := s.repo.CreateProbeExemption(ctx, groupID, req, actorID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, infraerrors.BadRequest("prompt_probe_exemption_subject_not_found", "用户或 API Key 不存在")
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PromptService) DeleteProbeExemption(ctx context.Context, groupID, id int64) error {
	if !s.isProbeGroupInScope(groupID) {
		return infraerrors.BadRequest("prompt_probe_group_not_in_scope", "分组当前未纳入提示词审计范围")
	}
	if err := s.repo.DeleteProbeExemption(ctx, groupID, id); err != nil {
		return probeAdminError(err)
	}
	return nil
}

func (r *PostgreSQLRepository) ListAllActiveProbeGroupIDs(ctx context.Context) ([]int64, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM groups WHERE deleted_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func probeAdminError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrProbeGroupNotFound):
		return infraerrors.NotFound("prompt_probe_group_not_found", "分组不存在")
	case errors.Is(err, ErrProbeEventNotFound):
		return infraerrors.NotFound("prompt_probe_event_not_found", "探针事件不存在")
	case errors.Is(err, ErrProbeExemptionNotFound):
		return infraerrors.NotFound("prompt_probe_exemption_not_found", "探针豁免不存在")
	default:
		return err
	}
}
func valueOrZero(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

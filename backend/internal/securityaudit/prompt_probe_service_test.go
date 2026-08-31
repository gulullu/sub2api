package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type failRedisCommandHook struct {
	command     string
	keyContains string
}

func (h failRedisCommandHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h failRedisCommandHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if strings.EqualFold(cmd.Name(), h.command) {
			args := cmd.Args()
			if h.keyContains == "" || (len(args) > 1 && strings.Contains(fmt.Sprint(args[1]), h.keyContains)) {
				return errors.New("injected redis failure")
			}
		}
		return next(ctx, cmd)
	}
}
func (h failRedisCommandHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error { return next(ctx, cmds) }
}

type probeMatrixScanner struct {
	calls  atomic.Int64
	action Action
	err    error
}

func (s *probeMatrixScanner) Scan(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	action := s.action
	if action == "" {
		action = ActionAllow
	}
	decision := EventPass
	risk := RiskLow
	safety := "Safe"
	if action == ActionWarn {
		decision = EventFlag
		risk = RiskMedium
		safety = "Controversial"
	} else if action == ActionBlock {
		decision = EventCritical
		risk = RiskCritical
		safety = "Unsafe"
	}
	result := &NormalizedResult{
		Decision: decision, RiskLevel: risk, Action: action, Safety: safety,
		GuardEndpointID: "probe-scanner", ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{},
	}
	if action == ActionWarn {
		result.MatchedScanners = []string{confidenceScoreKey}
		result.ScannerScores[confidenceScoreKey] = 0.7
		result.ScannerEvidence[confidenceScoreKey] = "probe risk"
	}
	return result, nil
}

func probeMatrixActiveConfig(excluded ...int64) ActiveConfig {
	return ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, BlockingLatestTurnOnly: true,
		AllGroups: true, ConfigVersion: 57, ExcludedUserIDs: excluded,
		Scanners: []string{"all"}, Endpoints: []ActiveEndpoint{{ID: "probe-scanner", Enabled: true, InputLimit: 4096, TimeoutMS: 1000}},
	}
}

func newProbeMatrixService(t *testing.T, active ActiveConfig, scanner *probeMatrixScanner) (*PromptService, sqlmock.Sqlmock, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 4, 2)
	now := time.Unix(1_900_000_000, 0).UTC()
	evaluator.clock = fixedClock{now: now}
	return &PromptService{
		config: &fakeConfigStore{active: true, cfg: active}, repo: NewPostgreSQLRepository(db),
		payload: NewRedisPayloadStore(client), evaluator: evaluator, metrics: metrics, clock: fixedClock{now: now},
	}, mock, mr, client
}

func cacheProbeMatrixGroupConfig(t *testing.T, client *redis.Client, enabled bool) ProbeGroupConfig {
	t.Helper()
	cfg := DefaultProbeGroupConfig(17, "claude-max")
	cfg.Enabled = enabled
	cfg.PolicyVersion = 4
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, client.Set(context.Background(), probeConfigKey(17), raw, time.Minute).Err())
	return cfg
}

func expectProbeMatrixExemption(mock sqlmock.Sqlmock, exempt bool) {
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM prompt_audit_probe_exemptions`).
		WithArgs(int64(17), int64(23), int64(29)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(exempt))
}

func expectProbeMatrixLinkedEventMiss(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT id FROM prompt_audit_events WHERE group_id=\$1 AND prompt_hash=\$2`).
		WithArgs(int64(17), sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)
}

func probeTestEventRows(eventID, groupID, subjectID, policyVersion, auditVersion, probeVersion int64, classification string) *sqlmock.Rows {
	now := time.Unix(1_900_000_000, 0).UTC()
	columns := strings.Split(strings.ReplaceAll(probeEventColumns(), "\n", ""), ",")
	for index := range columns {
		columns[index] = strings.TrimSpace(columns[index])
	}
	return sqlmock.NewRows(columns).AddRow(
		eventID, groupID, "claude-max", "family-a", "ping", classification, ProbeVerdictHealthy,
		subjectID, nil, "deleted@example.invalid", nil, "", "claude-haiku",
		service.ContentModerationProtocolAnthropicMessages, false, 1, policyVersion, auditVersion, probeVersion,
		[]byte(`{}`), "known", "local_healthy", "healthy", []byte(`{}`), int64(2), int64(1), int64(1),
		int64(1), int64(0), int64(1), nil, now, now, now, now.Add(5*time.Minute), now.Add(5*time.Minute), now, now,
	)
}

func probeTestRequest(protocol, endpoint, rawPath, model, body string) Request {
	groupID := int64(17)
	return Request{
		RequestID: "probe-test", UserID: 23, APIKeyID: 29, GroupID: &groupID,
		GroupName: "claude-max", Protocol: protocol, Endpoint: endpoint, RawEndpointPath: rawPath,
		Model: model, Body: []byte(body), Stage: "http",
	}
}

func TestAnalyzeProbeRequestRequiresClaudeCodeForHaikuCompatibilityProbe(t *testing.T) {
	req := probeTestRequest(
		service.ContentModerationProtocolAnthropicMessages,
		"/v1/messages", "/v1/messages", "claude-3-5-haiku-20241022",
		`{"model":"claude-3-5-haiku-20241022","max_tokens":1,"system":"You are Claude Code","tools":[{"name":"Read"}],"messages":[{"role":"user","content":"hello"}]}`,
	)

	_, ok := analyzeProbeRequest(req)
	require.False(t, ok, "a non-Claude-Code one-token request with real context must not be swallowed")

	req.ClientIsClaudeCode = true
	shape, ok := analyzeProbeRequest(req)
	require.True(t, ok)
	require.True(t, shape.Candidate)
	require.True(t, shape.KnownHealth)
	require.Contains(t, shape.FullPrompt, "You are Claude Code")
	require.Contains(t, shape.FullPrompt, "hello")
}

func TestProbeBehaviorKeyVersionsCachedDecisionSchema(t *testing.T) {
	require.Contains(t, probeBehaviorKey(17, 23, 57, "family"), "behavior:v2:")
}

func TestAnalyzeProbeRequestDoesNotTreatConversationEndingInHiAsProbe(t *testing.T) {
	req := probeTestRequest(
		service.ContentModerationProtocolOpenAIChat,
		"/v1/chat/completions", "/v1/chat/completions", "gpt-5.6-luna",
		`{"model":"gpt-5.6-luna","max_tokens":4,"messages":[{"role":"system","content":"real instructions"},{"role":"user","content":"work on this project"},{"role":"assistant","content":"ok"},{"role":"user","content":"hi"}]}`,
	)
	_, ok := analyzeProbeRequest(req)
	require.False(t, ok)
}

func TestSupportedProbeRequestOnlyAllowsBareGenerationRoutes(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		endpoint string
		path     string
		want     bool
	}{
		{"responses v1", service.ContentModerationProtocolOpenAIResponses, "/v1/responses", "/v1/responses", true},
		{"responses bare", service.ContentModerationProtocolOpenAIResponses, "/v1/responses", "/responses", true},
		{"responses codex", service.ContentModerationProtocolOpenAIResponses, "/v1/responses", "/backend-api/codex/responses", true},
		{"responses compact", service.ContentModerationProtocolOpenAIResponses, "/v1/responses/compact", "/v1/responses/compact", false},
		{"responses arbitrary subpath normalized root", service.ContentModerationProtocolOpenAIResponses, "/v1/responses", "/v1/responses/cancel", false},
		{"responses input tokens", service.ContentModerationProtocolOpenAIResponses, "/v1/responses/input_tokens", "/v1/responses/input_tokens", false},
		{"chat alias", service.ContentModerationProtocolOpenAIChat, "/v1/chat/completions", "/chat/completions", true},
		{"messages", service.ContentModerationProtocolAnthropicMessages, "/v1/messages", "/v1/messages", true},
		{"count tokens", service.ContentModerationProtocolAnthropicMessages, "/v1/messages", "/v1/messages/count_tokens", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := probeTestRequest(tt.protocol, tt.endpoint, tt.path, "model", `{}`)
			require.Equal(t, tt.want, supportedProbeRequest(req))
		})
	}
}

func TestGovernProbeCompatibilityAndCoreStateMatrix(t *testing.T) {
	knownRequest := func() Request {
		return probeTestRequest(
			service.ContentModerationProtocolAnthropicMessages, "/v1/messages", "/v1/messages", "claude-haiku",
			`{"model":"claude-haiku","max_tokens":1,"messages":[{"role":"user","content":"ping"}]}`,
		)
	}
	candidateRequest := func() Request {
		return probeTestRequest(
			service.ContentModerationProtocolAnthropicMessages, "/v1/messages", "/v1/messages", "claude-sonnet",
			`{"model":"claude-sonnet","max_tokens":4,"messages":[{"role":"user","content":"identify yourself"}]}`,
		)
	}

	t.Run("group switch off preserves original path", func(t *testing.T) {
		scanner := &probeMatrixScanner{}
		svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cacheProbeMatrixGroupConfig(t, client, false)
		result := svc.GovernProbe(context.Background(), knownRequest())
		require.False(t, result.Enabled)
		require.False(t, result.Applied)
		require.Zero(t, scanner.calls.Load())
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("group outside audit scope preserves original path", func(t *testing.T) {
		scanner := &probeMatrixScanner{}
		active := probeMatrixActiveConfig()
		active.AllGroups = false
		svc, mock, _, client := newProbeMatrixService(t, active, scanner)
		cacheProbeMatrixGroupConfig(t, client, true)
		result := svc.GovernProbe(context.Background(), knownRequest())
		require.False(t, result.Enabled)
		require.False(t, result.Applied)
		require.Zero(t, scanner.calls.Load())
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("missing policy row defaults off", func(t *testing.T) {
		scanner := &probeMatrixScanner{}
		svc, mock, _, _ := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		now := time.Unix(1_900_000_000, 0).UTC()
		mock.ExpectQuery(`SELECT g.id,g.name,COALESCE\(c.enabled,FALSE\)`).
			WithArgs(int64(17), DefaultProbeHealthyResponse, DefaultProbeViolationResponse, DefaultProbeUnknownResponse).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "name", "enabled", "interval", "scope", "allow_first", "skip_audit", "skip_upstream",
				"healthy", "violation", "unknown", "version", "created", "updated", "updated_by",
			}).AddRow(17, "claude-max", false, 300, ProbeHealthScopeDefault, true, true, true,
				DefaultProbeHealthyResponse, DefaultProbeViolationResponse, DefaultProbeUnknownResponse, 1, now, now, nil))
		result := svc.GovernProbe(context.Background(), knownRequest())
		require.False(t, result.Enabled)
		require.False(t, result.Applied)
		require.Zero(t, scanner.calls.Load())
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("known probe singleflight then successful window", func(t *testing.T) {
		scanner := &probeMatrixScanner{}
		svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cacheProbeMatrixGroupConfig(t, client, true)
		expectProbeMatrixExemption(mock, false)
		expectProbeMatrixExemption(mock, false)
		expectProbeMatrixExemption(mock, false)

		first := svc.GovernProbe(context.Background(), knownRequest())
		require.NotNil(t, first.Claim)
		coalesced := svc.GovernProbe(context.Background(), knownRequest())
		require.NotNil(t, coalesced.Local)
		require.Equal(t, "unknown", coalesced.Local.Kind)
		require.Zero(t, scanner.calls.Load())
		svc.FinalizeProbeForward(first.Claim, true, true)
		repeat := svc.GovernProbe(context.Background(), knownRequest())
		require.NotNil(t, repeat.Local)
		require.Equal(t, "healthy", repeat.Local.Kind)
		require.Zero(t, scanner.calls.Load())
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("excluded weak candidate skips audit while known probe remains governed", func(t *testing.T) {
		scanner := &probeMatrixScanner{}
		svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(23), scanner)
		cacheProbeMatrixGroupConfig(t, client, true)
		weak := svc.GovernProbe(context.Background(), candidateRequest())
		require.True(t, weak.Enabled)
		require.False(t, weak.Applied)
		require.Zero(t, scanner.calls.Load())

		expectProbeMatrixExemption(mock, false)
		known := svc.GovernProbe(context.Background(), knownRequest())
		require.NotNil(t, known.Claim)
		svc.ReleaseProbeForwardClaim(known.Claim)
		require.Zero(t, scanner.calls.Load())
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("candidate allow audits once and coalesces concurrent repeat", func(t *testing.T) {
		scanner := &probeMatrixScanner{action: ActionAllow}
		svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cacheProbeMatrixGroupConfig(t, client, true)
		expectProbeMatrixExemption(mock, false)
		expectProbeMatrixLinkedEventMiss(mock)
		expectProbeMatrixExemption(mock, false)
		expectProbeMatrixExemption(mock, false)

		first := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, first.Claim)
		require.NotNil(t, first.PromptDecision)
		second := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, second.Local)
		require.Equal(t, "unknown", second.Local.Kind)
		require.Equal(t, int64(1), scanner.calls.Load())
		svc.FinalizeProbeForward(first.Claim, true, true)
		repeat := svc.GovernProbe(context.Background(), candidateRequest())
		require.Nil(t, repeat.Claim)
		require.NotNil(t, repeat.Local)
		require.Equal(t, "healthy", repeat.Local.Kind)
		require.Equal(t, int64(1), scanner.calls.Load(), "a successful candidate must reuse its decision and health window")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("forward not dispatched reuses cached flag decision and route pool", func(t *testing.T) {
		scanner := &probeMatrixScanner{action: ActionWarn}
		active := probeMatrixActiveConfig()
		active.RiskRouteAccountIDs = []int64{701, 702}
		active.NoRouteFallbackMode = NoRouteFallbackAllow
		svc, mock, _, client := newProbeMatrixService(t, active, scanner)
		cacheProbeMatrixGroupConfig(t, client, true)
		expectProbeMatrixExemption(mock, false)
		expectProbeMatrixLinkedEventMiss(mock)
		expectProbeMatrixExemption(mock, false)

		first := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, first.Claim)
		require.NotNil(t, first.PromptDecision)
		require.Equal(t, DecisionFlag, first.PromptDecision.Kind)
		require.Equal(t, []int64{701, 702}, first.PromptDecision.RouteAccountIDs)
		require.True(t, first.PromptDecision.AllowRiskRouteFallback)
		svc.FinalizeProbeForward(first.Claim, false, false)

		repeat := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, repeat.Claim)
		require.NotNil(t, repeat.PromptDecision)
		require.Equal(t, DecisionFlag, repeat.PromptDecision.Kind)
		require.Equal(t, []int64{701, 702}, repeat.PromptDecision.RouteAccountIDs)
		require.True(t, repeat.PromptDecision.AllowRiskRouteFallback)
		require.Equal(t, int64(1), scanner.calls.Load(), "pre-dispatch failure must not cause another Luna audit")
		svc.ReleaseProbeForwardClaim(repeat.Claim)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	for _, upstreamSucceeded := range []bool{true, false} {
		name := "failure"
		if upstreamSucceeded {
			name = "success"
		}
		t.Run("cached flag survives upstream "+name+" window", func(t *testing.T) {
			scanner := &probeMatrixScanner{action: ActionWarn}
			active := probeMatrixActiveConfig()
			active.RiskRouteAccountIDs = []int64{801, 802}
			svc, mock, mr, client := newProbeMatrixService(t, active, scanner)
			cfg := cacheProbeMatrixGroupConfig(t, client, true)
			expectProbeMatrixExemption(mock, false)
			expectProbeMatrixLinkedEventMiss(mock)
			expectProbeMatrixExemption(mock, false)

			first := svc.GovernProbe(context.Background(), candidateRequest())
			require.NotNil(t, first.Claim)
			svc.FinalizeProbeForward(first.Claim, true, upstreamSucceeded)
			mr.FastForward(time.Duration(cfg.IntervalSeconds+1) * time.Second)
			cacheProbeMatrixGroupConfig(t, client, true)

			repeat := svc.GovernProbe(context.Background(), candidateRequest())
			require.NotNil(t, repeat.Claim)
			require.NotNil(t, repeat.PromptDecision)
			require.Equal(t, DecisionFlag, repeat.PromptDecision.Kind)
			require.Equal(t, []int64{801, 802}, repeat.PromptDecision.RouteAccountIDs)
			require.Equal(t, int64(1), scanner.calls.Load(), "upstream health must not overwrite the audit decision")
			shape, ok := analyzeProbeRequest(candidateRequest())
			require.True(t, ok)
			behaviorKey := probeBehaviorKey(17, 23, combinedProbePolicyVersion(57, cfg.PolicyVersion), shape.Fingerprint)
			require.Equal(t, probeFamilyHealthyTTL, mr.TTL(behaviorKey), "an active cached decision must refresh without losing flag metadata")
			svc.ReleaseProbeForwardClaim(repeat.Claim)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}

	t.Run("monitor exemption bypasses healthy suppression window", func(t *testing.T) {
		scanner := &probeMatrixScanner{}
		svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cfg := cacheProbeMatrixGroupConfig(t, client, true)
		expectProbeMatrixExemption(mock, true)
		version := combinedProbePolicyVersion(57, cfg.PolicyVersion)
		require.NoError(t, client.Set(context.Background(),
			probeHealthKey(17, version, canonicalProbeModel("claude-haiku"), service.ContentModerationProtocolAnthropicMessages),
			"healthy", time.Minute).Err())
		result := svc.GovernProbe(context.Background(), knownRequest())
		require.NotNil(t, result.Claim, "an exempt monitor still reaches the real upstream")
		require.Nil(t, result.Local)
		svc.ReleaseProbeForwardClaim(result.Claim)
		require.Zero(t, scanner.calls.Load())
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("candidate block becomes local confirmed violation", func(t *testing.T) {
		scanner := &probeMatrixScanner{action: ActionBlock}
		svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cacheProbeMatrixGroupConfig(t, client, true)
		expectProbeMatrixExemption(mock, false)
		expectProbeMatrixLinkedEventMiss(mock)
		result := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, result.Local)
		require.Equal(t, "violation", result.Local.Kind)
		require.Equal(t, int64(1), scanner.calls.Load())
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("audit unavailable becomes local unknown and repeat skips evaluator", func(t *testing.T) {
		scanner := &probeMatrixScanner{err: &GuardError{Code: ErrorCodeUnavailable, Retryable: true}}
		svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cacheProbeMatrixGroupConfig(t, client, true)
		expectProbeMatrixExemption(mock, false)
		expectProbeMatrixExemption(mock, false)
		first := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, first.Local)
		require.Equal(t, "unknown", first.Local.Kind)
		second := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, second.Local)
		require.Equal(t, "unknown", second.Local.Kind)
		require.Equal(t, int64(1), scanner.calls.Load())
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("disabled first real probe remembers audited candidate", func(t *testing.T) {
		scanner := &probeMatrixScanner{action: ActionAllow}
		svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cfg := DefaultProbeGroupConfig(17, "claude-max")
		cfg.Enabled = true
		cfg.PolicyVersion = 4
		cfg.AllowFirstRealProbe = false
		raw, err := json.Marshal(cfg)
		require.NoError(t, err)
		require.NoError(t, client.Set(context.Background(), probeConfigKey(17), raw, time.Minute).Err())
		expectProbeMatrixExemption(mock, false)
		expectProbeMatrixLinkedEventMiss(mock)
		expectProbeMatrixExemption(mock, false)

		first := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, first.Local)
		require.Equal(t, "unknown", first.Local.Kind)
		second := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, second.Local)
		require.Equal(t, "unknown", second.Local.Kind)
		require.Equal(t, int64(1), scanner.calls.Load(), "the same candidate must not be audited twice")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("preexisting unknown health window remembers audited candidate", func(t *testing.T) {
		scanner := &probeMatrixScanner{action: ActionAllow}
		svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cfg := cacheProbeMatrixGroupConfig(t, client, true)
		version := combinedProbePolicyVersion(57, cfg.PolicyVersion)
		require.NoError(t, client.Set(context.Background(),
			probeHealthKey(17, version, canonicalProbeModel("claude-sonnet"), service.ContentModerationProtocolAnthropicMessages),
			"unknown", time.Minute).Err())
		expectProbeMatrixExemption(mock, false)
		expectProbeMatrixLinkedEventMiss(mock)
		expectProbeMatrixExemption(mock, false)

		first := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, first.Local)
		require.Equal(t, "unknown", first.Local.Kind)
		second := svc.GovernProbe(context.Background(), candidateRequest())
		require.NotNil(t, second.Local)
		require.Equal(t, "unknown", second.Local.Kind)
		require.Equal(t, int64(1), scanner.calls.Load(), "the unknown health cooldown must suppress repeat audit")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("cached confirmed family never audits or forwards", func(t *testing.T) {
		scanner := &probeMatrixScanner{}
		svc, mock, mr, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cfg := cacheProbeMatrixGroupConfig(t, client, true)
		req := candidateRequest()
		shape, ok := analyzeProbeRequest(req)
		require.True(t, ok)
		version := combinedProbePolicyVersion(57, cfg.PolicyVersion)
		raw, err := json.Marshal(probeFamilyState{Classification: ProbeClassificationConfirmedViolation, Verdict: ProbeVerdictConfirmedViolation})
		require.NoError(t, err)
		behaviorKey := probeBehaviorKey(17, 23, version, shape.Fingerprint)
		require.NoError(t, client.Set(context.Background(), behaviorKey, raw, time.Hour).Err())
		result := svc.GovernProbe(context.Background(), req)
		require.NotNil(t, result.Local)
		require.Equal(t, "violation", result.Local.Kind)
		require.Zero(t, scanner.calls.Load())
		require.Equal(t, probeFamilyViolationTTL, mr.TTL(behaviorKey))
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("redis failure fails open to original path", func(t *testing.T) {
		scanner := &probeMatrixScanner{}
		svc, mock, mr, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
		cacheProbeMatrixGroupConfig(t, client, true)
		mr.Close()
		result := svc.GovernProbe(context.Background(), candidateRequest())
		require.False(t, result.Applied)
		require.Zero(t, scanner.calls.Load())
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestFinalizeProbeForwardWithoutDispatchDoesNotCreateUnknownCooldown(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	svc := &PromptService{payload: NewRedisPayloadStore(client), clock: fixedClock{now: time.Unix(1_900_000_000, 0)}}
	claim := &ProbeForwardClaim{
		config: DefaultProbeGroupConfig(17, "claude-max"), behaviorKey: "probe-behavior", healthKey: "probe-health",
		claimKeys: []probeLockClaim{{key: "probe-pending", token: "token"}},
	}
	require.NoError(t, client.Set(context.Background(), "probe-pending", "token", time.Minute).Err())
	svc.FinalizeProbeForward(claim, false, false)
	require.False(t, mr.Exists("probe-behavior"))
	require.False(t, mr.Exists("probe-health"))
	require.False(t, mr.Exists("probe-pending"))
}

func TestGovernConfirmedProbeRemainsLocalWhenRedisStateWriteFails(t *testing.T) {
	scanner := &probeMatrixScanner{}
	svc, mock, _, client := newProbeMatrixService(t, probeMatrixActiveConfig(), scanner)
	cacheProbeMatrixGroupConfig(t, client, true)
	client.AddHook(failRedisCommandHook{command: "set", keyContains: "behavior:"})
	req := probeTestRequest(
		service.ContentModerationProtocolAnthropicMessages, "/v1/messages", "/v1/messages", "claude-haiku",
		`{"model":"claude-haiku","max_tokens":1,"messages":[{"role":"user","content":"ping"}]}`,
	)
	result := svc.GovernConfirmedProbe(context.Background(), req)
	require.True(t, result.Enabled)
	require.True(t, result.Applied)
	require.NotNil(t, result.Local)
	require.Equal(t, "violation", result.Local.Kind)
	require.Zero(t, scanner.calls.Load())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProbeHealthSingleflightAndSuccessFailureCooldown(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	svc := &PromptService{payload: NewRedisPayloadStore(client), clock: fixedClock{now: time.Unix(1_900_000_000, 0)}}
	cfg := DefaultProbeGroupConfig(17, "claude-max")
	cfg.Enabled = true
	shape := probeRequestShape{Fingerprint: "family-a", Preview: "ping", ScanText: "ping", Candidate: true, KnownHealth: true}
	req := probeTestRequest(service.ContentModerationProtocolAnthropicMessages, "/v1/messages", "/v1/messages", "claude-haiku", `{}`)

	first := svc.handleSafeProbe(context.Background(), req, shape, cfg, 11, "behavior-a", ProbeClassificationKnownHealth, "known", false, nil, false)
	require.NotNil(t, first.Claim)
	coalesced := svc.handleSafeProbe(context.Background(), req, shape, cfg, 11, "behavior-b", ProbeClassificationKnownHealth, "known", false, nil, false)
	require.NotNil(t, coalesced.Local)
	require.Equal(t, "unknown", coalesced.Local.Kind)

	svc.FinalizeProbeForward(first.Claim, true, false)
	cooled := svc.handleSafeProbe(context.Background(), req, shape, cfg, 11, "behavior-c", ProbeClassificationKnownHealth, "known", false, nil, false)
	require.NotNil(t, cooled.Local)
	require.Equal(t, "unknown", cooled.Local.Kind, "a failed upstream must create a group/model/protocol cooldown")

	mr.FlushAll()
	success := svc.handleSafeProbe(context.Background(), req, shape, cfg, 11, "behavior-d", ProbeClassificationKnownHealth, "known", false, nil, false)
	require.NotNil(t, success.Claim)
	svc.FinalizeProbeForward(success.Claim, true, true)
	repeat := svc.handleSafeProbe(context.Background(), req, shape, cfg, 11, "behavior-e", ProbeClassificationKnownHealth, "known", false, nil, false)
	require.NotNil(t, repeat.Local)
	require.Equal(t, "healthy", repeat.Local.Kind)
}

func TestProbeLockReleaseAndRenewalAreTokenSafe(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	svc := &PromptService{payload: NewRedisPayloadStore(client)}
	ctx := context.Background()
	require.NoError(t, client.Set(ctx, "lock", "replacement", time.Minute).Err())
	svc.renewProbeLocks(ctx, []probeLockClaim{{key: "lock", token: "stale"}})
	svc.releaseProbeLocks(ctx, []probeLockClaim{{key: "lock", token: "stale"}})
	value, err := client.Get(ctx, "lock").Result()
	require.NoError(t, err)
	require.Equal(t, "replacement", value)

	svc.renewProbeLocks(ctx, []probeLockClaim{{key: "lock", token: "replacement"}})
	require.Equal(t, probeClaimTTL, mr.TTL("lock"))
	svc.releaseProbeLocks(ctx, []probeLockClaim{{key: "lock", token: "replacement"}})
	require.False(t, mr.Exists("lock"))
}

func TestCombinedProbePolicyVersionRoundTrip(t *testing.T) {
	combined := combinedProbePolicyVersion(57, 9)
	auditVersion, probeVersion := splitCombinedProbePolicyVersion(combined)
	require.Equal(t, int64(57), auditVersion)
	require.Equal(t, int64(9), probeVersion)
}

func TestClearProbeEventInvalidatesHealthAndUsesImmutableSubjectUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	const (
		eventID      = int64(91)
		groupID      = int64(17)
		subjectID    = int64(77)
		auditVersion = int64(57)
		probeVersion = int64(4)
	)
	policyVersion := combinedProbePolicyVersion(auditVersion, probeVersion)
	mock.ExpectQuery(`SELECT id,group_id.*FROM prompt_audit_probe_events WHERE id=\$1`).
		WithArgs(eventID).WillReturnRows(probeTestEventRows(eventID, groupID, subjectID, policyVersion, auditVersion, probeVersion, ProbeClassificationHealthy))
	mock.ExpectQuery(`UPDATE prompt_audit_probe_events SET classification='cleared'.*WHERE id=\$1 RETURNING`).
		WithArgs(eventID, int64(5), "重新评估").WillReturnRows(probeTestEventRows(eventID, groupID, subjectID, policyVersion, auditVersion, probeVersion, ProbeClassificationCleared))

	config := &fakeConfigStore{active: true, cfg: ActiveConfig{RiskControlEnabled: true, Enabled: true, AllGroups: true}}
	svc := &PromptService{config: config, repo: NewPostgreSQLRepository(db), payload: NewRedisPayloadStore(client)}
	keys := []string{
		probeBehaviorKey(groupID, subjectID, policyVersion, "family-a"),
		probeAuditLockKey(groupID, subjectID, policyVersion, "family-a"),
		probeHealthKey(groupID, policyVersion, canonicalProbeModel("claude-haiku"), service.ContentModerationProtocolAnthropicMessages),
		probeHealthPendingKey(groupID, policyVersion, canonicalProbeModel("claude-haiku"), service.ContentModerationProtocolAnthropicMessages),
	}
	for _, key := range keys {
		require.NoError(t, client.Set(context.Background(), key, "cached", time.Hour).Err())
	}
	wrongDeletedUserKey := probeBehaviorKey(groupID, 0, policyVersion, "family-a")
	require.NoError(t, client.Set(context.Background(), wrongDeletedUserKey, "keep", time.Hour).Err())

	cleared, err := svc.ClearProbeEvent(context.Background(), eventID, 5, "重新评估")
	require.NoError(t, err)
	require.Equal(t, ProbeClassificationCleared, cleared.Classification)
	for _, key := range keys {
		require.False(t, mr.Exists(key), key)
	}
	require.True(t, mr.Exists(wrongDeletedUserKey), "clear must use immutable subject_user_id rather than the nullable display FK")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestClearProbeEventRedisFailureDoesNotReportSuccessOrMutateDatabase(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	const eventID, groupID, subjectID = int64(92), int64(17), int64(77)
	const auditVersion, probeVersion = int64(57), int64(4)
	policyVersion := combinedProbePolicyVersion(auditVersion, probeVersion)
	mock.ExpectQuery(`SELECT id,group_id.*FROM prompt_audit_probe_events WHERE id=\$1`).
		WithArgs(eventID).WillReturnRows(probeTestEventRows(eventID, groupID, subjectID, policyVersion, auditVersion, probeVersion, ProbeClassificationHealthy))
	client.AddHook(failRedisCommandHook{command: "del"})
	svc := &PromptService{
		config: &fakeConfigStore{active: true, cfg: ActiveConfig{RiskControlEnabled: true, Enabled: true, AllGroups: true}},
		repo:   NewPostgreSQLRepository(db), payload: NewRedisPayloadStore(client),
	}
	cleared, err := svc.ClearProbeEvent(context.Background(), eventID, 5, "重新评估")
	require.Error(t, err)
	require.Nil(t, cleared)
	require.Contains(t, err.Error(), "缓存清除失败")
	require.NoError(t, mock.ExpectationsWereMet(), "the DB clear UPDATE must not run after Redis invalidation failed")
}

func TestRecordProbeEventSQLDoesNotReviveClearedRowFromOlderQueuedDelta(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)ON CONFLICT\(group_id,subject_user_id,audit_config_version,probe_config_version,family_fingerprint\).*WHERE prompt_audit_probe_events.cleared_at IS NULL OR prompt_audit_probe_events.cleared_at < \$33`).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	groupID := int64(17)
	_, err = NewPostgreSQLRepository(db).RecordProbeEvent(context.Background(), probeEventDelta{
		ObservedAt:     time.Unix(1_900_000_000, 0).UTC(),
		Request:        Request{GroupID: &groupID, UserID: 23, Model: "claude-haiku", Protocol: service.ContentModerationProtocolAnthropicMessages},
		Shape:          probeRequestShape{Fingerprint: "family-a", Preview: "ping", ScanText: "ping"},
		Classification: ProbeClassificationHealthy, Verdict: ProbeVerdictHealthy, PolicyVersion: combinedProbePolicyVersion(57, 4),
	})
	require.ErrorIs(t, err, sql.ErrNoRows)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProbeGovernanceMigrationUsesBoundedHourlyAggregation(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/232_prompt_audit_probe_governance.sql")
	require.NoError(t, err)
	sql := string(raw)
	require.Contains(t, sql, "prompt_audit_probe_hourly_stats")
	require.Contains(t, sql, "PRIMARY KEY (group_id, bucket_at)")
	require.NotContains(t, sql, "prompt_audit_probe_event_hits")
	require.NotContains(t, sql, " billed ")
	require.Contains(t, sql, "subject_user_id")
	require.Contains(t, sql, "audit_config_version")
	require.Contains(t, sql, "probe_config_version")
	require.Contains(t, strings.ReplaceAll(sql, "\n", " "), "(user_id IS NULL) <> (api_key_id IS NULL)")
}

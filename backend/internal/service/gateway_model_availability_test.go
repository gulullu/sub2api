//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/stretchr/testify/require"
)

type deadlineCapturingGroupRepo struct {
	GroupRepository
	group    *Group
	deadline time.Time
	block    bool
}

type panickingModelScopeGroupRepo struct {
	GroupRepository
}

func (r *panickingModelScopeGroupRepo) GetByIDLite(context.Context, int64) (*Group, error) {
	panic("model scope group lookup panic")
}

func (r *deadlineCapturingGroupRepo) GetByIDLite(ctx context.Context, _ int64) (*Group, error) {
	r.deadline, _ = ctx.Deadline()
	if r.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return r.group, nil
}

func TestDiagnoseModelAvailabilityForPlatform_NoModel_AlwaysAvailable(t *testing.T) {
	repo := &mockAccountRepoForPlatform{accounts: nil, accountsByID: map[int64]*Account{}}
	svc := &GatewayService{accountRepo: repo, cfg: testConfig()}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), nil, "", PlatformOpenAI)

	require.True(t, diag.HasAccountsInPool, "empty model must return HasAccountsInPool=true so caller stays on 503")
	require.True(t, diag.HasModelSupport, "empty model must return HasModelSupport=true so caller stays on 503")
}

func TestDiagnoseModelAvailabilityForPlatform_EmptyPlatform_AlwaysAvailable(t *testing.T) {
	repo := &mockAccountRepoForPlatform{accounts: nil, accountsByID: map[int64]*Account{}}
	svc := &GatewayService{accountRepo: repo, cfg: testConfig()}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), nil, "gpt-5", "")

	require.True(t, diag.HasAccountsInPool)
	require.True(t, diag.HasModelSupport, "empty platform must fall back to {true,true} so caller stays on 503")
}

func TestDiagnoseModelAvailabilityForPlatform_NilReceiver(t *testing.T) {
	var svc *GatewayService

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), nil, "gpt-5", PlatformOpenAI)

	require.True(t, diag.HasAccountsInPool)
	require.True(t, diag.HasModelSupport)
}

func TestDiagnoseModelAvailabilityForPlatform_NoAccountsInPool(t *testing.T) {
	repo := &mockAccountRepoForPlatform{accounts: nil, accountsByID: map[int64]*Account{}}
	svc := &GatewayService{accountRepo: repo, cfg: testConfig()}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), nil, "gpt-5", PlatformOpenAI)

	require.False(t, diag.HasAccountsInPool)
	require.False(t, diag.HasModelSupport, "no accounts means no support; caller stays on 503 (empty-pool branch)")
}

func TestDiagnoseModelAvailabilityForPlatform_ExplicitMappingMatches(t *testing.T) {
	repo := &mockAccountRepoForPlatform{
		accounts: []Account{
			{
				ID:          1,
				Platform:    PlatformOpenAI,
				Status:      StatusActive,
				Schedulable: true,
				Credentials: map[string]any{
					"model_mapping": map[string]any{"gpt-5.1-codex-mini": "gpt-5.1-codex-mini"},
				},
			},
		},
		accountsByID: map[int64]*Account{},
	}
	for i := range repo.accounts {
		repo.accountsByID[repo.accounts[i].ID] = &repo.accounts[i]
	}
	svc := &GatewayService{accountRepo: repo, cfg: testConfig()}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), nil, "gpt-5.1-codex-mini", PlatformOpenAI)

	require.True(t, diag.HasAccountsInPool)
	require.True(t, diag.HasModelSupport)
}

func TestDiagnoseModelAvailabilityForPlatform_EmptyMappingAllowsAll(t *testing.T) {
	repo := &mockAccountRepoForPlatform{
		accounts: []Account{
			{ID: 1, Platform: PlatformOpenAI, Status: StatusActive, Schedulable: true /* no ModelMapping = allow all */},
		},
		accountsByID: map[int64]*Account{},
	}
	for i := range repo.accounts {
		repo.accountsByID[repo.accounts[i].ID] = &repo.accounts[i]
	}
	svc := &GatewayService{accountRepo: repo, cfg: testConfig()}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), nil, "gpt-5.1-codex-mini", PlatformOpenAI)

	require.True(t, diag.HasModelSupport, "empty model_mapping must be treated as 'allow all' (Account.IsModelSupported semantics)")
}

func TestDiagnoseModelAvailabilityForPlatform_WildcardMappingMatches(t *testing.T) {
	repo := &mockAccountRepoForPlatform{
		accounts: []Account{
			{
				ID:          1,
				Platform:    PlatformOpenAI,
				Status:      StatusActive,
				Schedulable: true,
				Credentials: map[string]any{
					"model_mapping": map[string]any{"*": "gpt-5"},
				},
			},
		},
		accountsByID: map[int64]*Account{},
	}
	for i := range repo.accounts {
		repo.accountsByID[repo.accounts[i].ID] = &repo.accounts[i]
	}
	svc := &GatewayService{accountRepo: repo, cfg: testConfig()}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), nil, "gpt-5.1-codex-mini", PlatformOpenAI)

	require.True(t, diag.HasModelSupport, "wildcard mapping must classify the request as 'serviceable'")
}

func TestDiagnoseModelAvailabilityForPlatform_NoMatchingModel_ReturnsNotFoundSignal(t *testing.T) {
	groupID := int64(42)
	repo := &mockAccountRepoForPlatform{
		accounts: []Account{
			{
				ID:          1,
				Platform:    PlatformOpenAI,
				Status:      StatusActive,
				Schedulable: true,
				AccountGroups: []AccountGroup{
					{GroupID: groupID},
				},
				Credentials: map[string]any{"model_mapping": map[string]any{"gpt-5": "gpt-5"}},
			},
			{
				ID:          2,
				Platform:    PlatformOpenAI,
				Status:      StatusActive,
				Schedulable: true,
				AccountGroups: []AccountGroup{
					{GroupID: groupID},
				},
				Credentials: map[string]any{"model_mapping": map[string]any{"gpt-5-mini": "gpt-5-mini"}},
			},
		},
		accountsByID: map[int64]*Account{},
	}
	for i := range repo.accounts {
		repo.accountsByID[repo.accounts[i].ID] = &repo.accounts[i]
	}
	svc := &GatewayService{accountRepo: repo, cfg: testConfig()}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-5.1-codex-mini", PlatformOpenAI)

	require.True(t, diag.HasAccountsInPool, "group has OpenAI accounts")
	require.False(t, diag.HasModelSupport, "no account mapping admits the requested model — handler should return 404")
}

func TestDiagnoseModelAvailabilityForPlatform_RateLimitedSupportingAccountRemainsConfigured(t *testing.T) {
	groupID := int64(42)
	cooldownUntil := time.Now().Add(time.Hour)
	repo := &mockAccountRepoForPlatform{
		accounts: []Account{
			{
				ID:                     1,
				Platform:               PlatformAnthropic,
				Status:                 StatusActive,
				Schedulable:            true,
				RateLimitResetAt:       &cooldownUntil,
				OverloadUntil:          &cooldownUntil,
				TempUnschedulableUntil: &cooldownUntil,
				AccountGroups:          []AccountGroup{{GroupID: groupID}},
				Credentials: map[string]any{
					"model_mapping": map[string]any{"claude-opus-4-8": "claude-opus-4-8"},
				},
			},
		},
		accountsByID: map[int64]*Account{},
	}
	require.False(t, repo.accounts[0].IsSchedulable(), "test account must be excluded from normal scheduling while cooling down")
	svc := &GatewayService{
		accountRepo:       repo,
		cfg:               testConfig(),
		schedulerSnapshot: &SchedulerSnapshotService{}, // diagnosis must bypass the transient-only snapshot
	}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), &groupID, "claude-opus-4-8", PlatformAnthropic)

	require.True(t, diag.HasAccountsInPool)
	require.True(t, diag.HasModelSupport, "a configured model remains supported while every matching account is temporarily cooling down")
}

func TestOpenAIDiagnoseModelAvailabilityForPlatform_RateLimitedSupportingAccountRemainsConfigured(t *testing.T) {
	groupID := int64(43)
	cooldownUntil := time.Now().Add(time.Hour)
	repo := &mockAccountRepoForPlatform{
		accounts: []Account{
			{
				ID:                     2,
				Platform:               PlatformOpenAI,
				Status:                 StatusActive,
				Schedulable:            true,
				RateLimitResetAt:       &cooldownUntil,
				OverloadUntil:          &cooldownUntil,
				TempUnschedulableUntil: &cooldownUntil,
				AccountGroups:          []AccountGroup{{GroupID: groupID}},
				Credentials: map[string]any{
					"model_mapping": map[string]any{"claude-opus-4-8": "claude-opus-4-8"},
				},
			},
		},
		accountsByID: map[int64]*Account{},
	}
	require.False(t, repo.accounts[0].IsSchedulable(), "test account must be excluded from normal scheduling while cooling down")
	svc := &OpenAIGatewayService{
		accountRepo:       repo,
		cfg:               testConfig(),
		schedulerSnapshot: &SchedulerSnapshotService{}, // diagnosis must bypass the transient-only snapshot
	}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), &groupID, "claude-opus-4-8", PlatformOpenAI)

	require.True(t, diag.HasAccountsInPool)
	require.True(t, diag.HasModelSupport, "OpenAI-compatible diagnosis must keep transiently limited supporting accounts in the configured pool")
}

func TestDiagnoseModelAvailabilityForPlatform_WrongPlatformFiltersOut(t *testing.T) {
	// Group has only Anthropic accounts; user routes to OpenAI gateway.
	// Diagnosis must NOT see Anthropic accounts (listSchedulableAccounts filters
	// by platform), so HasAccountsInPool is false and the caller stays on 503.
	repo := &mockAccountRepoForPlatform{
		accounts: []Account{
			{
				ID:          1,
				Platform:    PlatformAnthropic,
				Status:      StatusActive,
				Schedulable: true,
				Credentials: map[string]any{"model_mapping": map[string]any{"claude-sonnet-4-5": "claude-sonnet-4-5"}},
			},
		},
		accountsByID: map[int64]*Account{},
	}
	for i := range repo.accounts {
		repo.accountsByID[repo.accounts[i].ID] = &repo.accounts[i]
	}
	svc := &GatewayService{accountRepo: repo, cfg: testConfig()}

	diag := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), nil, "gpt-5", PlatformOpenAI)

	require.False(t, diag.HasAccountsInPool, "OpenAI route must not see Anthropic accounts in pool")
	require.False(t, diag.HasModelSupport)
}

func TestGatewayModelAvailabilityPreflightSeparatesThinkingVariant(t *testing.T) {
	groupID := int64(42)
	repo := &mockAccountRepoForPlatform{
		accounts: []Account{{
			ID:            1,
			Platform:      PlatformAntigravity,
			Status:        StatusActive,
			Schedulable:   true,
			AccountGroups: []AccountGroup{{GroupID: groupID}},
			Extra:         map[string]any{"mixed_scheduling": true},
			Credentials: map[string]any{
				"model_mapping": map[string]any{"claude-sonnet-4-5": "claude-sonnet-4-5"},
			},
		}},
		accountsByID: map[int64]*Account{},
	}
	svc := &GatewayService{accountRepo: repo, cfg: testConfig()}

	withoutThinking := context.WithValue(context.Background(), ctxkey.ThinkingEnabled, false)
	withThinking := context.WithValue(context.Background(), ctxkey.ThinkingEnabled, true)
	plain := svc.PreflightModelAvailabilityForPlatform(withoutThinking, &groupID, "claude-sonnet-4-5", PlatformAnthropic)
	thinking := svc.PreflightModelAvailabilityForPlatform(withThinking, &groupID, "claude-sonnet-4-5", PlatformAnthropic)

	require.True(t, plain.HasModelSupport)
	require.False(t, thinking.HasModelSupport, "thinking mode changes the actual Antigravity scheduler model and must not reuse the plain cache entry")
}

func TestResolveModelAvailabilityScopeUsesClaudeCodeFallbackGroup(t *testing.T) {
	primaryID, fallbackID := int64(10), int64(11)
	svc := &GatewayService{groupRepo: &mockGroupRepoForGateway{groups: map[int64]*Group{
		primaryID: &Group{
			ID: primaryID, Platform: PlatformAnthropic, Status: StatusActive,
			ClaudeCodeOnly: true, FallbackGroupID: &fallbackID,
		},
		fallbackID: &Group{
			ID: fallbackID, Platform: PlatformGemini, Status: StatusActive,
		},
	}}}

	scope, err := svc.ResolveModelAvailabilityScope(context.Background(), &primaryID, "gemini-3.1-pro")
	require.NoError(t, err)
	require.NotNil(t, scope.GroupID)
	require.Equal(t, fallbackID, *scope.GroupID)
	require.Equal(t, PlatformGemini, scope.Platform)
	require.Equal(t, "gemini-3.1-pro", scope.RoutingModel)
}

func TestResolveModelAvailabilityScopeFallbackCompositeMirrorsSchedulerContext(t *testing.T) {
	primaryID, fallbackID := int64(20), int64(21)
	resolver := NewCompositeRouteResolver(compositeRouteRepoStub{routes: []CompositeModelRoute{{
		ID: 1, GroupID: fallbackID, PublicModel: "public-alias", MatchType: CompositeRouteMatchExact,
		TargetPlatform: PlatformGemini, UpstreamModel: "fallback-internal", Endpoint: CompositeRouteEndpointAny, Enabled: true,
	}}})
	svc := &GatewayService{
		groupRepo: &mockGroupRepoForGateway{groups: map[int64]*Group{
			primaryID: &Group{
				ID: primaryID, Platform: PlatformComposite, Status: StatusActive,
				ClaudeCodeOnly: true, FallbackGroupID: &fallbackID,
			},
			fallbackID: &Group{ID: fallbackID, Platform: PlatformComposite, Status: StatusActive},
		}},
		compositeResolver: resolver,
	}
	ctx := WithCompositeRouteDecision(context.Background(), CompositeRouteDecision{
		Matched: true, GroupID: primaryID, PublicModel: "public-alias",
		TargetPlatform: PlatformOpenAI, UpstreamModel: "original-internal",
	})

	scope, err := svc.ResolveModelAvailabilityScope(ctx, &primaryID, "original-internal")
	require.NoError(t, err)
	require.NotNil(t, scope.GroupID)
	require.Equal(t, fallbackID, *scope.GroupID)
	require.Equal(t, PlatformOpenAI, scope.Platform)
	require.Equal(t, "original-internal", scope.RoutingModel)
}

func TestResolveModelAvailabilityScopeFallbackOrdinaryMirrorsLegacyScheduler(t *testing.T) {
	primaryID, fallbackID := int64(30), int64(31)
	svc := &GatewayService{groupRepo: &mockGroupRepoForGateway{groups: map[int64]*Group{
		primaryID: &Group{
			ID: primaryID, Platform: PlatformComposite, Status: StatusActive,
			ClaudeCodeOnly: true, FallbackGroupID: &fallbackID,
		},
		fallbackID: &Group{ID: fallbackID, Platform: PlatformAnthropic, Status: StatusActive},
	}}}
	ctx := WithCompositeRouteDecision(context.Background(), CompositeRouteDecision{
		Matched: true, GroupID: primaryID, PublicModel: "public-alias",
		TargetPlatform: PlatformOpenAI, UpstreamModel: "original-internal",
	})

	scope, err := svc.ResolveModelAvailabilityScope(ctx, &primaryID, "original-internal")
	require.NoError(t, err)
	require.Equal(t, fallbackID, *scope.GroupID)
	require.Equal(t, PlatformAnthropic, scope.Platform)
	require.Equal(t, "original-internal", scope.RoutingModel)
}

func TestResolveModelAvailabilityScopeFallbackOrdinaryMirrorsLoadAwareScheduler(t *testing.T) {
	primaryID, fallbackID := int64(40), int64(41)
	svc := &GatewayService{
		groupRepo: &mockGroupRepoForGateway{groups: map[int64]*Group{
			primaryID: &Group{
				ID: primaryID, Platform: PlatformComposite, Status: StatusActive,
				ClaudeCodeOnly: true, FallbackGroupID: &fallbackID,
			},
			fallbackID: &Group{ID: fallbackID, Platform: PlatformAnthropic, Status: StatusActive},
		}},
		concurrencyService: NewConcurrencyService(nil),
	}
	ctx := WithCompositeRouteDecision(context.Background(), CompositeRouteDecision{
		Matched: true, GroupID: primaryID, PublicModel: "public-alias",
		TargetPlatform: PlatformOpenAI, UpstreamModel: "original-internal",
	})

	scope, err := svc.ResolveModelAvailabilityScope(ctx, &primaryID, "original-internal")
	require.NoError(t, err)
	require.Equal(t, fallbackID, *scope.GroupID)
	require.Equal(t, PlatformOpenAI, scope.Platform)
	require.Equal(t, "original-internal", scope.RoutingModel)
}

func TestResolveModelAvailabilityScopeFallbackCompositeMirrorsLegacySchedulerModel(t *testing.T) {
	primaryID, fallbackID := int64(50), int64(51)
	resolver := NewCompositeRouteResolver(compositeRouteRepoStub{routes: []CompositeModelRoute{{
		ID: 1, GroupID: fallbackID, PublicModel: "public-alias", MatchType: CompositeRouteMatchExact,
		TargetPlatform: PlatformGemini, UpstreamModel: "fallback-internal", Endpoint: CompositeRouteEndpointAny, Enabled: true,
	}}})
	svc := &GatewayService{
		groupRepo: &mockGroupRepoForGateway{groups: map[int64]*Group{
			primaryID: {
				ID: primaryID, Platform: PlatformAnthropic, Status: StatusActive,
				ClaudeCodeOnly: true, FallbackGroupID: &fallbackID,
			},
			fallbackID: {ID: fallbackID, Platform: PlatformComposite, Status: StatusActive},
		}},
		compositeResolver: resolver,
	}

	scope, err := svc.ResolveModelAvailabilityScope(context.Background(), &primaryID, "public-alias")
	require.NoError(t, err)
	require.Equal(t, fallbackID, *scope.GroupID)
	require.Equal(t, PlatformGemini, scope.Platform)
	require.Equal(t, "fallback-internal", scope.RoutingModel)
}

func TestResolveModelAvailabilityScopeFallbackCompositeMirrorsLoadAwareSchedulerModel(t *testing.T) {
	primaryID, fallbackID := int64(60), int64(61)
	resolver := NewCompositeRouteResolver(compositeRouteRepoStub{routes: []CompositeModelRoute{{
		ID: 1, GroupID: fallbackID, PublicModel: "public-alias", MatchType: CompositeRouteMatchExact,
		TargetPlatform: PlatformGemini, UpstreamModel: "fallback-internal", Endpoint: CompositeRouteEndpointAny, Enabled: true,
	}}})
	svc := &GatewayService{
		groupRepo: &mockGroupRepoForGateway{groups: map[int64]*Group{
			primaryID: {
				ID: primaryID, Platform: PlatformAnthropic, Status: StatusActive,
				ClaudeCodeOnly: true, FallbackGroupID: &fallbackID,
			},
			fallbackID: {ID: fallbackID, Platform: PlatformComposite, Status: StatusActive},
		}},
		compositeResolver:  resolver,
		concurrencyService: NewConcurrencyService(nil),
	}

	scope, err := svc.ResolveModelAvailabilityScope(context.Background(), &primaryID, "public-alias")
	require.NoError(t, err)
	require.Equal(t, fallbackID, *scope.GroupID)
	require.Equal(t, PlatformGemini, scope.Platform)
	require.Equal(t, "public-alias", scope.RoutingModel)
}

func TestResolveModelAvailabilityScopeBoundsGroupLookup(t *testing.T) {
	groupID := int64(70)
	repo := &deadlineCapturingGroupRepo{group: &Group{ID: groupID, Platform: PlatformAnthropic, Status: StatusActive}}
	svc := &GatewayService{groupRepo: repo}
	started := time.Now()

	_, err := svc.ResolveModelAvailabilityScope(context.Background(), &groupID, "claude-test")

	require.NoError(t, err)
	require.False(t, repo.deadline.IsZero())
	remaining := repo.deadline.Sub(started)
	require.Greater(t, remaining, 350*time.Millisecond)
	require.LessOrEqual(t, remaining, modelAvailabilityPreflightLoadTimeout+50*time.Millisecond)
}

func TestResolveModelAvailabilityScopePreservesShorterCallerDeadline(t *testing.T) {
	groupID := int64(71)
	repo := &deadlineCapturingGroupRepo{group: &Group{ID: groupID, Platform: PlatformAnthropic, Status: StatusActive}}
	svc := &GatewayService{groupRepo: repo}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()

	_, err := svc.ResolveModelAvailabilityScope(ctx, &groupID, "claude-test")

	require.NoError(t, err)
	require.False(t, repo.deadline.IsZero())
	require.LessOrEqual(t, repo.deadline.Sub(started), 50*time.Millisecond)
}

func TestResolveModelAvailabilityScopeTimeoutFailsPromptly(t *testing.T) {
	groupID := int64(72)
	repo := &deadlineCapturingGroupRepo{block: true}
	svc := &GatewayService{groupRepo: repo}
	started := time.Now()

	_, err := svc.ResolveModelAvailabilityScope(context.Background(), &groupID, "claude-test")

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 750*time.Millisecond)
}

func TestResolveModelAvailabilityScopePanicBecomesFailOpenError(t *testing.T) {
	groupID := int64(73)
	svc := &GatewayService{groupRepo: &panickingModelScopeGroupRepo{}}

	require.NotPanics(t, func() {
		_, err := svc.ResolveModelAvailabilityScope(context.Background(), &groupID, "claude-test")
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve model availability scope")
	})
}

func TestResolveModelAvailabilityScopeMissingCompositeResolverBecomesFailOpenError(t *testing.T) {
	groupID := int64(74)
	svc := &GatewayService{groupRepo: &deadlineCapturingGroupRepo{
		group: &Group{ID: groupID, Platform: PlatformComposite, Status: StatusActive},
	}}

	require.NotPanics(t, func() {
		_, err := svc.ResolveModelAvailabilityScope(context.Background(), &groupID, "unknown-public-model")
		require.Error(t, err)
		require.Contains(t, err.Error(), "composite target platform unknown")
	})
}

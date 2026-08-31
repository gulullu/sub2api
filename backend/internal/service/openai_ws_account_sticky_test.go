package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestOpenAIGatewayService_PreviousResponseOutsidePromptRiskPoolConflicts(t *testing.T) {
	groupID := int64(23)
	account := Account{
		ID: 2, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
		Status: StatusActive, Schedulable: true, Concurrency: 2,
		Extra: map[string]any{"openai_apikey_responses_websockets_v2_enabled": true},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	svc := &OpenAIGatewayService{
		accountRepo: stubOpenAIAccountRepo{accounts: []Account{account}}, cache: cache,
		cfg: newOpenAIWSV2TestConfig(), concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}
	require.NoError(t, store.BindResponseAccount(context.Background(), groupID, "resp_risk_conflict", account.ID, time.Hour))
	ctx := WithPromptRiskRoutePolicy(context.Background(), []int64{3}, true)

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_risk_conflict", "gpt-5.1", nil, false)

	require.Nil(t, selection)
	require.True(t, errors.Is(err, ErrPromptRiskRouteStateConflict))
	boundID, getErr := store.GetResponseAccount(context.Background(), groupID, "resp_risk_conflict")
	require.NoError(t, getErr)
	require.Equal(t, account.ID, boundID, "risk request must preserve the ordinary response binding")
}

func TestOpenAIGatewayService_PromptRiskNonMovablePreviousResponseFailsClosedWithoutVerifiedBinding(t *testing.T) {
	groupID := int64(23)
	ctx := WithPromptRiskRouteAccounts(context.Background(), []int64{2})

	t.Run("nil service state", func(t *testing.T) {
		var svc *OpenAIGatewayService
		selection, err := svc.selectAccountByPreviousResponseIDForCapability(ctx, &groupID, "resp_nil_store", "gpt-5.1", nil, "", false)
		require.Nil(t, selection)
		require.ErrorIs(t, err, ErrPromptRiskRouteStateConflict)
	})

	t.Run("binding missing", func(t *testing.T) {
		svc := &OpenAIGatewayService{openaiWSStateStore: NewOpenAIWSStateStore(nil)}
		selection, err := svc.selectAccountByPreviousResponseIDForCapability(ctx, &groupID, "resp_missing", "gpt-5.1", nil, "", false)
		require.Nil(t, selection)
		require.ErrorIs(t, err, ErrPromptRiskRouteStateConflict)
	})

	t.Run("binding lookup error", func(t *testing.T) {
		svc := &OpenAIGatewayService{openaiWSStateStore: promptRiskRouteFailingStateStore{
			OpenAIWSStateStore: NewOpenAIWSStateStore(nil),
		}}
		selection, err := svc.selectAccountByPreviousResponseIDForCapability(ctx, &groupID, "resp_lookup_error", "gpt-5.1", nil, "", false)
		require.Nil(t, selection)
		require.ErrorIs(t, err, ErrPromptRiskRouteStateConflict)
	})
}

func TestOpenAIGatewayService_PromptRiskNonMovablePreviousResponseUsesVerifiedPoolAccount(t *testing.T) {
	groupID := int64(23)
	account := Account{
		ID: 2, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
		Status: StatusActive, Schedulable: true, Concurrency: 2,
		Extra: map[string]any{"openai_apikey_responses_websockets_v2_enabled": true},
	}
	store := NewOpenAIWSStateStore(nil)
	svc := &OpenAIGatewayService{
		accountRepo: stubOpenAIAccountRepo{accounts: []Account{account}},
		cfg:         newOpenAIWSV2TestConfig(), concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}
	require.NoError(t, store.BindResponseAccount(context.Background(), groupID, "resp_verified", account.ID, time.Hour))
	ctx := WithPromptRiskRouteAccounts(context.Background(), []int64{account.ID})

	selection, decision, err := svc.SelectAccountWithSchedulerForCapability(
		ctx, &groupID, "resp_verified", "", "gpt-5.1", nil,
		OpenAIUpstreamTransportResponsesWebsocketV2, "", false, false, true,
	)

	require.NoError(t, err)
	require.NotNil(t, selection)
	require.Equal(t, account.ID, selection.Account.ID)
	require.True(t, decision.StickyPreviousHit)
	if selection.ReleaseFunc != nil {
		selection.ReleaseFunc()
	}
}

type promptRiskRouteFailingStateStore struct {
	OpenAIWSStateStore
}

func (promptRiskRouteFailingStateStore) GetResponseAccount(context.Context, int64, string) (int64, error) {
	return 0, errors.New("state store unavailable")
}

func TestOpenAIGatewayService_SelectAccountByPreviousResponseID_Hit(t *testing.T) {
	ctx := context.Background()
	groupID := int64(23)
	account := Account{
		ID:          2,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 2,
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_enabled": true,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	cfg := newOpenAIWSV2TestConfig()

	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{account}},
		cache:              cache,
		cfg:                cfg,
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}

	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_prev_1", account.ID, time.Hour))

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_prev_1", "gpt-5.1", nil, false)
	require.NoError(t, err)
	require.NotNil(t, selection)
	require.NotNil(t, selection.Account)
	require.Equal(t, account.ID, selection.Account.ID)
	require.True(t, selection.Acquired)
	if selection.ReleaseFunc != nil {
		selection.ReleaseFunc()
	}
}

func TestOpenAIGatewayService_SelectAccountByPreviousResponseID_QuotaAutoPausedMiss(t *testing.T) {
	ctx := context.Background()
	groupID := int64(23)
	account := Account{
		ID:          77,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 2,
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_enabled": true,
			"codex_5h_used_percent":                         96.0,
			"auto_pause_5h_threshold":                       0.95,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	cfg := newOpenAIWSV2TestConfig()
	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{account}},
		cache:              cache,
		cfg:                cfg,
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}

	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_prev_quota", account.ID, time.Hour))

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_prev_quota", "gpt-5.1", nil, false)
	require.NoError(t, err)
	require.Nil(t, selection, "超过 5h 配额阈值的账号不应继续命中 previous_response_id 粘连")

	// Auto-pause is transient, so the binding is preserved: the chain can resume on the
	// same account once the quota window resets.
	boundAccountID, getErr := store.GetResponseAccount(ctx, groupID, "resp_prev_quota")
	require.NoError(t, getErr)
	require.Equal(t, account.ID, boundAccountID)
}

func TestOpenAIGatewayService_SelectAccountByPreviousResponseID_RateLimitedMiss(t *testing.T) {
	ctx := context.Background()
	groupID := int64(23)
	rateLimitedUntil := time.Now().Add(30 * time.Minute)
	account := Account{
		ID:               12,
		Platform:         PlatformOpenAI,
		Type:             AccountTypeAPIKey,
		Status:           StatusActive,
		Schedulable:      true,
		Concurrency:      1,
		RateLimitResetAt: &rateLimitedUntil,
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_enabled": true,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	cfg := newOpenAIWSV2TestConfig()
	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{account}},
		cache:              cache,
		cfg:                cfg,
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}

	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_prev_rl", account.ID, time.Hour))

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_prev_rl", "gpt-5.1", nil, false)
	require.NoError(t, err)
	require.Nil(t, selection, "限额中的账号不应继续命中 previous_response_id 粘连")
	boundAccountID, getErr := store.GetResponseAccount(ctx, groupID, "resp_prev_rl")
	require.NoError(t, getErr)
	require.Zero(t, boundAccountID)
}

func TestOpenAIGatewayService_SelectAccountByPreviousResponseID_DBRuntimeRecheckRateLimitedMiss(t *testing.T) {
	ctx := context.Background()
	groupID := int64(24)
	rateLimitedUntil := time.Now().Add(30 * time.Minute)
	staleAccount := &Account{
		ID:          13,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_enabled": true,
		},
	}
	dbAccount := Account{
		ID:               13,
		Platform:         PlatformOpenAI,
		Type:             AccountTypeAPIKey,
		Status:           StatusActive,
		Schedulable:      true,
		Concurrency:      1,
		RateLimitResetAt: &rateLimitedUntil,
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_enabled": true,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	cfg := newOpenAIWSV2TestConfig()
	snapshotCache := &openAISnapshotCacheStub{
		accountsByID: map[int64]*Account{dbAccount.ID: staleAccount},
	}
	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{dbAccount}},
		cache:              cache,
		cfg:                cfg,
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
		schedulerSnapshot:  &SchedulerSnapshotService{cache: snapshotCache},
	}

	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_prev_db_rl", dbAccount.ID, time.Hour))

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_prev_db_rl", "gpt-5.1", nil, false)
	require.NoError(t, err)
	require.Nil(t, selection, "DB 中已限流的账号不应继续命中 previous_response_id 粘连")
	boundAccountID, getErr := store.GetResponseAccount(ctx, groupID, "resp_prev_db_rl")
	require.NoError(t, getErr)
	require.Zero(t, boundAccountID)
}

func TestOpenAIGatewayService_SelectAccountByPreviousResponseID_Excluded(t *testing.T) {
	ctx := context.Background()
	groupID := int64(23)
	account := Account{
		ID:          8,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_enabled": true,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	cfg := newOpenAIWSV2TestConfig()
	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{account}},
		cache:              cache,
		cfg:                cfg,
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}

	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_prev_2", account.ID, time.Hour))

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_prev_2", "gpt-5.1", map[int64]struct{}{account.ID: {}}, false)
	require.NoError(t, err)
	require.Nil(t, selection)
}

func TestOpenAIGatewayService_SelectAccountByPreviousResponseID_APIKeyForceHTTPHit(t *testing.T) {
	ctx := context.Background()
	groupID := int64(23)
	account := Account{
		ID:          11,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Extra: map[string]any{
			"openai_ws_force_http":            true,
			"responses_websockets_v2_enabled": true,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	cfg := newOpenAIWSV2TestConfig()
	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{account}},
		cache:              cache,
		cfg:                cfg,
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}

	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_prev_force_http", account.ID, time.Hour))

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_prev_force_http", "gpt-5.1", nil, false)
	require.NoError(t, err)
	require.NotNil(t, selection, "API-key HTTP continuation must retain the key/project that created the response")
	require.NotNil(t, selection.Account)
	require.Equal(t, account.ID, selection.Account.ID)
	if selection.ReleaseFunc != nil {
		selection.ReleaseFunc()
	}
}

func TestOpenAIGatewayService_SelectAccountByPreviousResponseID_OAuthForceHTTPIgnored(t *testing.T) {
	ctx := context.Background()
	groupID := int64(23)
	account := Account{
		ID:          12,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Extra: map[string]any{
			"openai_ws_force_http":            true,
			"responses_websockets_v2_enabled": true,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{account}},
		cache:              cache,
		cfg:                newOpenAIWSV2TestConfig(),
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}

	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_prev_oauth_force_http", account.ID, time.Hour))

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_prev_oauth_force_http", "gpt-5.1", nil, false)
	require.NoError(t, err)
	require.Nil(t, selection, "OAuth HTTP fallback cannot preserve WSv2 continuation state")
}

func TestOpenAIGatewayService_SelectAccountByPreviousResponseID_BusyKeepsSticky(t *testing.T) {
	ctx := context.Background()
	groupID := int64(23)
	accounts := []Account{
		{
			ID:          21,
			Platform:    PlatformOpenAI,
			Type:        AccountTypeAPIKey,
			Status:      StatusActive,
			Schedulable: true,
			Concurrency: 1,
			Priority:    0,
			Extra: map[string]any{
				"openai_apikey_responses_websockets_v2_enabled": true,
			},
		},
		{
			ID:          22,
			Platform:    PlatformOpenAI,
			Type:        AccountTypeAPIKey,
			Status:      StatusActive,
			Schedulable: true,
			Concurrency: 1,
			Priority:    9,
			Extra: map[string]any{
				"openai_apikey_responses_websockets_v2_enabled": true,
			},
		},
	}

	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	cfg := newOpenAIWSV2TestConfig()
	cfg.Gateway.Scheduling.StickySessionMaxWaiting = 2
	cfg.Gateway.Scheduling.StickySessionWaitTimeout = 30 * time.Second

	concurrencyCache := stubConcurrencyCache{
		acquireResults: map[int64]bool{
			21: false, // previous_response 命中的账号繁忙
			22: true,  // 次优账号可用（若回退会命中）
		},
		waitCounts: map[int64]int{
			21: 999,
		},
	}

	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: accounts},
		cache:              cache,
		cfg:                cfg,
		concurrencyService: NewConcurrencyService(concurrencyCache),
		openaiWSStateStore: store,
	}

	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_prev_busy", 21, time.Hour))

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_prev_busy", "gpt-5.1", nil, false)
	require.NoError(t, err)
	require.NotNil(t, selection)
	require.NotNil(t, selection.Account)
	require.Equal(t, int64(21), selection.Account.ID, "busy previous_response sticky account should remain selected")
	require.False(t, selection.Acquired)
	require.NotNil(t, selection.WaitPlan)
	require.Equal(t, int64(21), selection.WaitPlan.AccountID)
}

func TestOpenAIGatewayService_SelectAccountByPreviousResponseID_CapabilityMismatchKeepsSticky(t *testing.T) {
	ctx := context.Background()
	groupID := int64(25)
	account := Account{
		ID:          31,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"openai_capabilities": []any{"chat_completions"},
		},
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_enabled": true,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	cfg := newOpenAIWSV2TestConfig()
	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{account}},
		cache:              cache,
		cfg:                cfg,
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}

	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_prev_capability", account.ID, time.Hour))

	selection, err := svc.selectAccountByPreviousResponseIDForCapability(
		ctx,
		&groupID,
		"resp_prev_capability",
		"text-embedding-3-small",
		nil,
		OpenAIEndpointCapabilityEmbeddings,
		false,
	)
	require.NoError(t, err)
	require.Nil(t, selection)
	boundAccountID, getErr := store.GetResponseAccount(ctx, groupID, "resp_prev_capability")
	require.NoError(t, getErr)
	require.Equal(t, account.ID, boundAccountID)
}

func newOpenAIWSV2TestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.OAuthEnabled = true
	cfg.Gateway.OpenAIWS.APIKeyEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.StickyResponseIDTTLSeconds = 3600
	return cfg
}

//go:build unit

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type countingOpenAIModelAvailabilityRepo struct {
	AccountRepository

	mu       sync.Mutex
	calls    int
	accounts []Account
	errs     []error
}

type blockingOpenAIModelAvailabilityRepo struct {
	AccountRepository
	calls   atomic.Int64
	entered chan struct{}
	release chan struct{}
}

type contextAwareBlockingModelAvailabilityRepo struct {
	AccountRepository
	calls atomic.Int64
}

func (r *contextAwareBlockingModelAvailabilityRepo) ListModelAvailabilityCandidates(
	ctx context.Context,
	_ *int64,
	_ []string,
	_ bool,
) ([]Account, error) {
	r.calls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

type panickingModelAvailabilityRepo struct {
	AccountRepository
	calls atomic.Int64
}

func (r *panickingModelAvailabilityRepo) ListModelAvailabilityCandidates(
	context.Context,
	*int64,
	[]string,
	bool,
) ([]Account, error) {
	r.calls.Add(1)
	panic("repository panic")
}

func (r *blockingOpenAIModelAvailabilityRepo) ListModelAvailabilityCandidates(
	context.Context,
	*int64,
	[]string,
	bool,
) ([]Account, error) {
	r.calls.Add(1)
	r.entered <- struct{}{}
	<-r.release
	return []Account{explicitModelAvailabilityAccount("gpt-supported")}, nil
}

func (r *countingOpenAIModelAvailabilityRepo) ListModelAvailabilityCandidates(
	context.Context,
	*int64,
	[]string,
	bool,
) ([]Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if len(r.errs) > 0 {
		err := r.errs[0]
		r.errs = r.errs[1:]
		if err != nil {
			return nil, err
		}
	}
	return append([]Account(nil), r.accounts...), nil
}

func (r *countingOpenAIModelAvailabilityRepo) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *countingOpenAIModelAvailabilityRepo) setAccounts(accounts []Account) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts = append([]Account(nil), accounts...)
}

func explicitModelAvailabilityAccount(model string) Account {
	return Account{
		ID:          1,
		Platform:    PlatformOpenAI,
		Status:      StatusActive,
		Schedulable: true,
		Credentials: map[string]any{"model_mapping": map[string]any{model: model}},
	}
}

func TestOpenAIModelAvailabilityCacheReusesDiagnosisAndScopesKeys(t *testing.T) {
	repo := &countingOpenAIModelAvailabilityRepo{accounts: []Account{explicitModelAvailabilityAccount("gpt-supported")}}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupOne, groupTwo := int64(1), int64(2)

	first := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupOne, "gpt-supported", PlatformOpenAI)
	second := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupOne, "gpt-supported", PlatformOpenAI)
	require.True(t, first.HasModelSupport)
	require.Equal(t, first, second)
	require.Equal(t, 1, repo.callCount(), "same group/model/platform must use the five-second cache")

	svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupTwo, "gpt-supported", PlatformOpenAI)
	svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupOne, "gpt-other", PlatformOpenAI)
	svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupOne, "gpt-supported", PlatformGrok)
	require.Equal(t, 4, repo.callCount(), "group, model, and normalized platform must all scope cache entries")
}

func TestOpenAIModelAvailabilityCacheDoesNotCacheRepositoryFailure(t *testing.T) {
	repo := &countingOpenAIModelAvailabilityRepo{
		accounts: []Account{explicitModelAvailabilityAccount("gpt-supported")},
		errs:     []error{errors.New("temporary database failure")},
	}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)

	failedOpen := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-unsupported", PlatformOpenAI)
	require.True(t, failedOpen.HasAccountsInPool)
	require.True(t, failedOpen.HasModelSupport, "lookup errors must conservatively continue the request")

	retried := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-unsupported", PlatformOpenAI)
	require.True(t, retried.HasAccountsInPool)
	require.False(t, retried.HasModelSupport)
	require.Equal(t, 2, repo.callCount(), "a failed lookup must not poison the cache")
}

func TestOpenAIModelAvailabilityCacheDoesNotCacheEmptyPool(t *testing.T) {
	repo := &countingOpenAIModelAvailabilityRepo{}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)

	first := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-any", PlatformOpenAI)
	second := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-any", PlatformOpenAI)
	require.False(t, first.HasAccountsInPool)
	require.False(t, second.HasAccountsInPool)
	require.Equal(t, 2, repo.callCount(), "an empty provisioning pool must remain fail-open and uncached")
}

func TestOpenAIModelAvailabilityPreflightPreservesRawModel(t *testing.T) {
	repo := &countingOpenAIModelAvailabilityRepo{accounts: []Account{explicitModelAvailabilityAccount(" gpt-spaced ")}}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)

	raw := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, " gpt-spaced ", PlatformOpenAI)
	trimmed := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-spaced", PlatformOpenAI)
	require.True(t, raw.HasModelSupport, "preflight must query the exact scheduler model")
	require.False(t, trimmed.HasModelSupport, "distinct raw scheduler models must not share a cache key")
	require.Equal(t, 2, repo.callCount())
}

func TestOpenAIModelAvailabilityCacheExpiresAndReloads(t *testing.T) {
	repo := &countingOpenAIModelAvailabilityRepo{accounts: []Account{explicitModelAvailabilityAccount("gpt-supported")}}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)

	svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-unsupported", PlatformOpenAI)
	cache := svc.getModelAvailabilityPreflightCache()
	cache.mu.Lock()
	for key, entry := range cache.entries {
		entry.expiresAt = time.Now().Add(-time.Millisecond)
		cache.entries[key] = entry
	}
	cache.mu.Unlock()

	svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-unsupported", PlatformOpenAI)
	require.Equal(t, 2, repo.callCount())
}

func TestOpenAIModelAvailabilityNegativeCacheIsShortAndSharedDiagnoseStaysFresh(t *testing.T) {
	repo := &countingOpenAIModelAvailabilityRepo{accounts: []Account{explicitModelAvailabilityAccount("gpt-old")}}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)

	beforeUpdate := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-new", PlatformOpenAI)
	require.True(t, beforeUpdate.HasAccountsInPool)
	require.False(t, beforeUpdate.HasModelSupport)
	repo.setAccounts([]Account{explicitModelAvailabilityAccount("gpt-new")})

	stalePreflight := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-new", PlatformOpenAI)
	require.False(t, stalePreflight.HasModelSupport, "preflight configuration changes may take at most the five-second TTL to appear")
	require.Equal(t, 1, repo.callCount())

	authoritative := svc.DiagnoseModelAvailabilityForPlatform(context.Background(), &groupID, "gpt-new", PlatformOpenAI)
	require.True(t, authoritative.HasModelSupport, "shared post-selection classification must preserve a fresh repository lookup")
	require.Equal(t, 2, repo.callCount())
}

func TestOpenAIModelAvailabilityPreflightBoundsAttackerControlledMisses(t *testing.T) {
	repo := &countingOpenAIModelAvailabilityRepo{accounts: []Account{explicitModelAvailabilityAccount("gpt-supported")}}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)

	oversized := strings.Repeat("m", modelAvailabilityPreflightMaxModelBytes+1)
	diagnosis := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, oversized, PlatformOpenAI)
	require.True(t, diagnosis.HasModelSupport)
	require.Zero(t, repo.callCount(), "oversized model keys must not reach the repository")
	cache := svc.getModelAvailabilityPreflightCache()
	cache.mu.Lock()
	cache.loadWindowStart = time.Now().Add(time.Minute)
	cache.loadsInWindow = 0
	cache.mu.Unlock()

	for i := 0; i < modelAvailabilityPreflightLoadsPerWindow+50; i++ {
		svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, fmt.Sprintf("unique-model-%d", i), PlatformOpenAI)
	}
	require.Equal(t, modelAvailabilityPreflightLoadsPerWindow, repo.callCount(), "unique cache misses must be rate limited")
}

func TestOpenAIModelAvailabilityCacheIsBounded(t *testing.T) {
	cache := newModelAvailabilityPreflightCache()
	now := time.Now()
	for i := 0; i < modelAvailabilityPreflightMaxEntries+100; i++ {
		key := modelAvailabilityPreflightKey{hasGroup: true, groupID: 1, platform: PlatformOpenAI, model: fmt.Sprintf("model-%d", i)}
		cache.mu.Lock()
		if _, exists := cache.entries[key]; !exists && len(cache.entries) >= modelAvailabilityPreflightMaxEntries {
			clear(cache.entries)
		}
		cache.entries[key] = modelAvailabilityPreflightEntry{diagnosis: ModelAvailabilityDiagnosis{}, expiresAt: now.Add(time.Second)}
		cache.mu.Unlock()
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	require.LessOrEqual(t, len(cache.entries), modelAvailabilityPreflightMaxEntries)
}

func TestOpenAIModelAvailabilityPreflightCapsConcurrentRepositoryLoads(t *testing.T) {
	repo := &blockingOpenAIModelAvailabilityRepo{
		entered: make(chan struct{}, modelAvailabilityPreflightMaxInFlight),
		release: make(chan struct{}),
	}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)
	total := modelAvailabilityPreflightMaxInFlight + 20
	done := make(chan struct{}, total)
	for i := 0; i < total; i++ {
		go func(index int) {
			svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, fmt.Sprintf("concurrent-model-%d", index), PlatformOpenAI)
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < modelAvailabilityPreflightMaxInFlight; i++ {
		select {
		case <-repo.entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for bounded repository loads")
		}
	}
	for i := 0; i < total-modelAvailabilityPreflightMaxInFlight; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("saturated preflight callers did not fail open promptly")
		}
	}
	require.Equal(t, int64(modelAvailabilityPreflightMaxInFlight), repo.calls.Load())

	close(repo.release)
	for i := 0; i < modelAvailabilityPreflightMaxInFlight; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("repository-backed preflight callers did not finish")
		}
	}
}

func TestOpenAIModelAvailabilityPreflightCoalescesSameKey(t *testing.T) {
	repo := &blockingOpenAIModelAvailabilityRepo{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)
	const callers = 24
	done := make(chan struct{}, callers)
	for i := 0; i < callers; i++ {
		go func() {
			svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "same-model", PlatformOpenAI)
			done <- struct{}{}
		}()
	}
	select {
	case <-repo.entered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shared repository load")
	}
	require.Equal(t, int64(1), repo.calls.Load())
	close(repo.release)
	for i := 0; i < callers; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("same-key waiter did not finish")
		}
	}
	require.Equal(t, int64(1), repo.calls.Load(), "same-key callers must share one loader")
}

func TestOpenAIModelAvailabilityCanceledWaitersDoNotReleaseLoaderSlots(t *testing.T) {
	repo := &blockingOpenAIModelAvailabilityRepo{
		entered: make(chan struct{}, modelAvailabilityPreflightMaxInFlight),
		release: make(chan struct{}),
	}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)
	done := make(chan struct{}, modelAvailabilityPreflightMaxInFlight)
	cancels := make([]context.CancelFunc, 0, modelAvailabilityPreflightMaxInFlight)
	for i := 0; i < modelAvailabilityPreflightMaxInFlight; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		go func(index int) {
			svc.PreflightModelAvailabilityForPlatform(ctx, &groupID, fmt.Sprintf("cancel-model-%d", index), PlatformOpenAI)
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < modelAvailabilityPreflightMaxInFlight; i++ {
		select {
		case <-repo.entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for ignore-context repository loaders")
		}
	}
	for _, cancel := range cancels {
		cancel()
	}
	for i := 0; i < modelAvailabilityPreflightMaxInFlight; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("canceled caller did not fail open promptly")
		}
	}

	for i := 0; i < 20; i++ {
		svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, fmt.Sprintf("blocked-extra-%d", i), PlatformOpenAI)
	}
	require.Equal(t, int64(modelAvailabilityPreflightMaxInFlight), repo.calls.Load(), "caller cancellation must not admit replacement loaders")

	close(repo.release)
	require.Eventually(t, func() bool {
		return len(svc.getModelAvailabilityPreflightCache().loadSlots) == 0
	}, time.Second, 10*time.Millisecond)
	svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "after-release", PlatformOpenAI)
	require.Equal(t, int64(modelAvailabilityPreflightMaxInFlight+1), repo.calls.Load(), "completed loaders must release capacity")
}

func TestOpenAIModelAvailabilityPreflightUsesIndependentShortLoadDeadline(t *testing.T) {
	repo := &contextAwareBlockingModelAvailabilityRepo{}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)

	started := time.Now()
	diagnosis := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "timeout-model", PlatformOpenAI)
	require.Less(t, time.Since(started), 2*time.Second)
	require.True(t, diagnosis.HasModelSupport, "repository timeout must fail open")
	require.Equal(t, int64(1), repo.calls.Load())

	svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "timeout-model", PlatformOpenAI)
	require.Equal(t, int64(2), repo.calls.Load(), "timed-out loads must not be cached")
}

func TestOpenAIModelAvailabilityPreflightLoaderPanicFailsOpenAndReleasesSlot(t *testing.T) {
	repo := &panickingModelAvailabilityRepo{}
	svc := &OpenAIGatewayService{accountRepo: repo, cfg: testConfig()}
	groupID := int64(1)

	first := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "panic-model", PlatformOpenAI)
	second := svc.PreflightModelAvailabilityForPlatform(context.Background(), &groupID, "panic-model", PlatformOpenAI)
	require.True(t, first.HasModelSupport)
	require.True(t, second.HasModelSupport)
	require.Equal(t, int64(2), repo.calls.Load(), "panic results must not be cached or leave a stuck inflight key")
	require.Zero(t, len(svc.getModelAvailabilityPreflightCache().loadSlots))
}

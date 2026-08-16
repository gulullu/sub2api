package securityaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestCyberPrepareTurnFailOpenStillKeepsSafeMetadata(t *testing.T) {
	groupID := int64(12)
	req := Request{
		RequestID: "req-test", APIKeyID: 23, GroupID: &groupID, Provider: service.PlatformOpenAI,
		Endpoint: "/v1/responses", Protocol: "openai_responses", Model: "gpt-test",
		Body: []byte(`{"input":"confirmed test prompt"}`), Stage: "http",
	}

	withoutKey := NewCyberFeedbackService(nil, nil, &config.Config{}, nil, nil, nil)
	evidence, ok := withoutKey.PrepareTurn(req, 0)
	require.True(t, ok)
	require.Empty(t, evidence.Scope.PromptSignature)
	require.Equal(t, groupID, evidence.Scope.GroupID)
	require.NotEmpty(t, evidence.RedactedPreview)

	toolOnly := req
	toolOnly.Body = []byte(`{"tools":[{"type":"function","name":"noop"}]}`)
	evidence, ok = withoutKey.PrepareTurn(toolOnly, 0)
	require.True(t, ok)
	require.Empty(t, evidence.Scope.PromptSignature)
	require.Empty(t, evidence.RedactedPreview)

	nonOpenAI := req
	nonOpenAI.Provider = service.PlatformGrok
	_, ok = withoutKey.PrepareTurn(nonOpenAI, 0)
	require.False(t, ok)
}

type cyberFeedbackRepositoryStub struct {
	confirmed []CyberConfirmInput
}

func (r *cyberFeedbackRepositoryStub) Confirm(_ context.Context, input CyberConfirmInput) (CyberFeedback, bool, error) {
	r.confirmed = append(r.confirmed, input)
	apiKeyID := input.APIKeyID
	return CyberFeedback{
		ID: int64(len(r.confirmed)), RequestID: input.RequestID, APIKeyID: &apiKeyID,
		GroupID: input.GroupID, AccountID: input.AccountID, Protocol: input.Protocol,
		Stage: input.Stage, Transport: input.Transport, RedactedPreview: input.RedactedPreview, CreatedAt: time.Now().UTC(),
	}, true, nil
}
func (*cyberFeedbackRepositoryStub) MatchActiveSignature(context.Context, CyberFingerprintScope) (bool, error) {
	return false, nil
}
func (*cyberFeedbackRepositoryStub) ListActiveSignatures(context.Context, int64, string, int64, int) ([]CyberActiveSignature, error) {
	return nil, nil
}
func (*cyberFeedbackRepositoryStub) ListCyberFeedback(context.Context, CyberFeedbackFilter, int, int) ([]CyberFeedback, int64, error) {
	return nil, 0, nil
}
func (*cyberFeedbackRepositoryStub) GetCyberFeedback(context.Context, int64) (CyberFeedback, error) {
	return CyberFeedback{}, ErrCyberFeedbackNotFound
}
func (*cyberFeedbackRepositoryStub) ReviewCyberFeedback(context.Context, int64, string, int64, string, int64) (CyberFeedback, error) {
	return CyberFeedback{}, nil
}
func (*cyberFeedbackRepositoryStub) ResetCyberRuleGeneration(context.Context, int64) error {
	return nil
}
func (*cyberFeedbackRepositoryStub) CompleteCyberRuleGeneration(context.Context, int64, string, string) error {
	return nil
}

func TestConfirmRecordsMetadataWithoutFingerprint(t *testing.T) {
	repo := &cyberFeedbackRepositoryStub{}
	serviceUnderTest := NewCyberFeedbackService(repo, nil, &config.Config{}, nil, nil, nil)
	groupID := int64(12)
	evidence, ok := serviceUnderTest.PrepareTurn(Request{
		RequestID: "same-client-visible-id", APIKeyID: 7, GroupID: &groupID,
		Provider: service.PlatformOpenAI, Protocol: "openai_responses", Stage: "http",
		Body: []byte(`{"tools":[{"type":"function","name":"noop"}]}`),
	}, 0)
	require.True(t, ok)
	require.Empty(t, evidence.Scope.PromptSignature)

	feedback, inserted, err := serviceUnderTest.ConfirmOpenAIOAuthCYB(context.Background(), evidence, 88, 400)
	require.NoError(t, err)
	require.True(t, inserted)
	require.Equal(t, int64(1), feedback.ID)
	require.Len(t, repo.confirmed, 1)
	require.Empty(t, repo.confirmed[0].Scope.PromptSignature)
}

func TestResetCyberRuleGenerationUsesSingleWinnerCAS(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := NewPostgreSQLRepository(db)

	mock.ExpectExec(`UPDATE prompt_audit_cyber_feedback`).WithArgs(int64(41)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, repo.ResetCyberRuleGeneration(context.Background(), 41))

	// A concurrent caller observes that the winner already changed the row to
	// pending, so the same CAS updates zero rows and reports a conflict.
	mock.ExpectExec(`UPDATE prompt_audit_cyber_feedback`).WithArgs(int64(41)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(int64(41)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	err = repo.ResetCyberRuleGeneration(context.Background(), 41)
	require.True(t, errors.Is(err, ErrCyberFeedbackGenerationConflict))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCyberSignatureScopesByGroupAndKeyVersionOnly(t *testing.T) {
	groupID := int64(12)
	req := Request{
		GroupID: &groupID, Provider: service.PlatformOpenAI, Protocol: "openai_responses",
		Body: []byte(`{"input":"same normalized prompt"}`), Stage: "http",
	}
	first := NewCyberFeedbackService(nil, nil, &config.Config{JWT: config.JWTConfig{Secret: "stable-key-one"}}, nil, nil, nil)
	second := NewCyberFeedbackService(nil, nil, &config.Config{JWT: config.JWTConfig{Secret: "stable-key-two"}}, nil, nil, nil)

	httpEvidence, ok := first.PrepareTurn(req, 0)
	require.True(t, ok)
	require.Len(t, httpEvidence.Scope.PromptSignature, 32)
	require.Contains(t, httpEvidence.Scope.SignatureVersion, CyberSignatureVersion+":")

	wsReq := req
	wsReq.Stage = "first_turn"
	wsEvidence, ok := first.PrepareTurn(wsReq, 1)
	require.True(t, ok)
	require.True(t, bytes.Equal(httpEvidence.Scope.PromptSignature, wsEvidence.Scope.PromptSignature))
	require.Equal(t, cyberSignatureCacheKey(httpEvidence.Scope), cyberSignatureCacheKey(wsEvidence.Scope))

	rotated, ok := second.PrepareTurn(req, 0)
	require.True(t, ok)
	require.NotEqual(t, httpEvidence.Scope.SignatureVersion, rotated.Scope.SignatureVersion)
	require.False(t, bytes.Equal(httpEvidence.Scope.PromptSignature, rotated.Scope.PromptSignature))

	secondPrompt := req
	secondPrompt.RequestID = req.RequestID
	secondPrompt.Body = []byte(`{"input":"different normalized prompt"}`)
	secondEvidence, ok := first.PrepareTurn(secondPrompt, 0)
	require.True(t, ok)
	require.NotEqual(t, cyberEventKey(httpEvidence, 99), cyberEventKey(secondEvidence, 99))

	noKey := NewCyberFeedbackService(nil, nil, &config.Config{}, nil, nil, nil)
	withoutFingerprintA, ok := noKey.PrepareTurn(req, 0)
	require.True(t, ok)
	withoutFingerprintB, ok := noKey.PrepareTurn(req, 0)
	require.True(t, ok)
	require.NotEqual(t, cyberEventKey(withoutFingerprintA, 99), cyberEventKey(withoutFingerprintB, 99))
}

func TestBoundedCyberRuleSource(t *testing.T) {
	short := "short"
	require.Equal(t, short, boundedCyberRuleSource(short))

	input := make([]rune, maxCyberRuleSourceRunes+5000)
	for index := range input {
		input[index] = rune('a' + index%26)
	}
	bounded := []rune(boundedCyberRuleSource(string(input)))
	require.LessOrEqual(t, len(bounded), maxCyberRuleSourceRunes)
	require.Equal(t, input[:4096], bounded[:4096])
	require.Equal(t, input[len(input)-1024:], bounded[len(bounded)-1024:])

	groupID := int64(12)
	svc := NewCyberFeedbackService(nil, nil, &config.Config{JWT: config.JWTConfig{Secret: "stable-key"}}, nil, nil, nil)
	evidence, ok := svc.PrepareTurn(Request{
		GroupID: &groupID, Provider: service.PlatformOpenAI, Protocol: "openai_responses",
		Body: []byte(fmt.Sprintf(`{"input":%q}`, strings.Repeat("large-sensitive-source", 5000))),
	}, 0)
	require.True(t, ok)
	require.LessOrEqual(t, len([]rune(evidence.snapshot.ScanText)), maxCyberRuleSourceRunes)
	require.Empty(t, evidence.snapshot.FullPrompt)
	require.Empty(t, evidence.snapshot.PromptHash)
	require.Empty(t, evidence.snapshot.UsernameSnapshot)
	require.Empty(t, evidence.snapshot.UserEmailSnapshot)
	require.Zero(t, evidence.snapshot.APIKeyID)
}

type cyberReplayRepositoryStub struct {
	cyberFeedbackRepositoryStub
	mu        sync.Mutex
	items     []CyberActiveSignature
	listCalls int
	listErr   error
	wait      bool
	release   <-chan struct{}
}

func (r *cyberReplayRepositoryStub) ListActiveSignatures(ctx context.Context, groupID int64, signatureVersion string, afterID int64, limit int) ([]CyberActiveSignature, error) {
	r.mu.Lock()
	r.listCalls++
	wait, release, listErr := r.wait, r.release, r.listErr
	items := append([]CyberActiveSignature(nil), r.items...)
	r.mu.Unlock()
	if wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if listErr != nil {
		return nil, listErr
	}
	result := make([]CyberActiveSignature, 0, limit)
	for _, item := range items {
		if item.GroupID != groupID || item.SignatureVersion != signatureVersion || item.ID <= afterID {
			continue
		}
		result = append(result, item)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func (r *cyberReplayRepositoryStub) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listCalls
}

func newCyberReplayRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func cyberTestScope(groupID int64, version string, signature []byte) CyberFingerprintScope {
	return CyberFingerprintScope{GroupID: groupID, SignatureVersion: version, PromptSignature: append([]byte(nil), signature...)}
}

func TestCyberReplayWarmUsesReadyZSetAndIsGroupIsolated(t *testing.T) {
	_, client := newCyberReplayRedis(t)
	now := time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)
	version := "hmac-sha256-v1:test"
	groupOne := cyberTestScope(1, version, []byte("confirmed"))
	groupTwo := cyberTestScope(2, version, []byte("confirmed"))
	repo := &cyberReplayRepositoryStub{items: []CyberActiveSignature{{
		ID: 1, GroupID: 1, SignatureVersion: version, PromptSignature: groupOne.PromptSignature, ExpiresAt: now.Add(24 * time.Hour),
	}}}
	svc := NewCyberFeedbackService(repo, client, &config.Config{}, nil, nil, nil)
	svc.clock = fixedClock{now: now}

	require.True(t, svc.IsReplay(context.Background(), CyberTurnEvidence{Scope: groupOne}))
	require.False(t, svc.IsReplay(context.Background(), CyberTurnEvidence{Scope: groupTwo}))
	require.Equal(t, 2, repo.calls(), "each group owns an independently warmed index")
	require.NoError(t, client.ZScore(context.Background(), cyberSignatureZSetKey(1, version), cyberReplayReadyMember).Err())
	require.NoError(t, client.ZScore(context.Background(), cyberSignatureZSetKey(2, version), cyberReplayReadyMember).Err())

	unknown := cyberTestScope(1, version, []byte("unique-miss"))
	require.False(t, svc.IsReplay(context.Background(), CyberTurnEvidence{Scope: unknown}))
	require.Equal(t, 2, repo.calls(), "healthy ready miss must remain Redis-only")
}

func TestCyberReplayWarmCompletesMultiplePages(t *testing.T) {
	_, client := newCyberReplayRedis(t)
	now := time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)
	version := "hmac-sha256-v1:many"
	items := make([]CyberActiveSignature, cyberReplayWarmPageSize+1)
	for i := range items {
		items[i] = CyberActiveSignature{
			ID: int64(i + 1), GroupID: 7, SignatureVersion: version,
			PromptSignature: []byte(fmt.Sprintf("signature-%04d", i)), ExpiresAt: now.Add(time.Hour),
		}
	}
	repo := &cyberReplayRepositoryStub{items: items}
	svc := NewCyberFeedbackService(repo, client, &config.Config{}, nil, nil, nil)
	svc.clock = fixedClock{now: now}
	scope := cyberTestScope(7, version, items[len(items)-1].PromptSignature)
	require.True(t, svc.IsReplay(context.Background(), CyberTurnEvidence{Scope: scope}))
	require.Equal(t, 2, repo.calls())
}

func TestCyberReplayWarmTimeoutDoesNotPublishReadyMarker(t *testing.T) {
	_, client := newCyberReplayRedis(t)
	version := "hmac-sha256-v1:timeout"
	repo := &cyberReplayRepositoryStub{wait: true}
	svc := NewCyberFeedbackService(repo, client, &config.Config{}, nil, nil, nil)
	scope := cyberTestScope(8, version, []byte("signature"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.False(t, svc.IsReplay(ctx, CyberTurnEvidence{Scope: scope}))
	require.ErrorIs(t, client.ZScore(context.Background(), cyberSignatureZSetKey(8, version), cyberReplayReadyMember).Err(), redis.Nil)
}

func TestCyberReplayWarmSurvivesFirstCallerCancellation(t *testing.T) {
	_, client := newCyberReplayRedis(t)
	version := "hmac-sha256-v1:detached"
	scope := cyberTestScope(18, version, []byte("signature"))
	release := make(chan struct{})
	repo := &cyberReplayRepositoryStub{
		release: release,
		items: []CyberActiveSignature{{
			ID: 1, GroupID: 18, SignatureVersion: version,
			PromptSignature: scope.PromptSignature, ExpiresAt: time.Now().Add(time.Hour),
		}},
	}
	svc := NewCyberFeedbackService(repo, client, &config.Config{}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan bool, 1)
	go func() { returned <- svc.IsReplay(ctx, CyberTurnEvidence{Scope: scope}) }()
	require.Eventually(t, func() bool { return repo.calls() == 1 }, time.Second, 5*time.Millisecond)
	cancel()
	require.False(t, <-returned)
	close(release)
	require.Eventually(t, func() bool {
		return client.ZScore(context.Background(), cyberSignatureZSetKey(18, version), cyberReplayReadyMember).Err() == nil
	}, time.Second, 5*time.Millisecond)
	require.True(t, svc.IsReplay(context.Background(), CyberTurnEvidence{Scope: scope}))
	require.Equal(t, 1, repo.calls(), "the second caller must consume the completed shared warmup")
}

func TestCyberReplayWarmCannotShortenConcurrentConfirmation(t *testing.T) {
	_, client := newCyberReplayRedis(t)
	now := time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)
	version := "hmac-sha256-v1:race"
	scope := cyberTestScope(9, version, []byte("signature"))
	oldExpiry, newExpiry := now.Add(time.Hour), now.Add(6*24*time.Hour)
	repo := &cyberReplayRepositoryStub{items: []CyberActiveSignature{{
		ID: 1, GroupID: 9, SignatureVersion: version, PromptSignature: scope.PromptSignature, ExpiresAt: oldExpiry,
	}}}
	svc := NewCyberFeedbackService(repo, client, &config.Config{}, nil, nil, nil)
	svc.clock = fixedClock{now: now}
	zsetKey := cyberSignatureZSetKey(9, version)
	require.NoError(t, client.ZAdd(context.Background(), zsetKey, redis.Z{
		Score: float64(newExpiry.UnixMilli()), Member: cyberSignatureCacheMember(scope),
	}).Err())
	require.NoError(t, svc.loadReplayIndex(context.Background(), 9, version))
	score, err := client.ZScore(context.Background(), zsetKey, cyberSignatureCacheMember(scope)).Result()
	require.NoError(t, err)
	require.Equal(t, newExpiry.UnixMilli(), int64(score))
}

func TestCyberReplayNeverExtendsPersistedExpiryOnRead(t *testing.T) {
	_, client := newCyberReplayRedis(t)
	now := time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)
	version := "hmac-sha256-v1:ttl"
	scope := cyberTestScope(10, version, []byte("signature"))
	svc := NewCyberFeedbackService(&cyberReplayRepositoryStub{}, client, &config.Config{}, nil, nil, nil)
	clock := &advancingClock{now: now}
	svc.clock = clock
	zsetKey := cyberSignatureZSetKey(10, version)
	expiresAt := now.Add(time.Second)
	require.NoError(t, client.ZAdd(context.Background(), zsetKey,
		redis.Z{Score: 0, Member: cyberReplayReadyMember},
		redis.Z{Score: float64(expiresAt.UnixMilli()), Member: cyberSignatureCacheMember(scope)},
	).Err())
	require.True(t, svc.IsReplay(context.Background(), CyberTurnEvidence{Scope: scope}))
	svc.replayCacheMu.Lock()
	require.Equal(t, expiresAt, svc.positiveReplay[cyberSignatureCacheMember(scope)])
	svc.replayCacheMu.Unlock()
	clock.mu.Lock()
	clock.now = now.Add(2 * time.Second)
	clock.mu.Unlock()
	require.False(t, svc.IsReplay(context.Background(), CyberTurnEvidence{Scope: scope}))
	require.ErrorIs(t, client.ZScore(context.Background(), zsetKey, cyberSignatureCacheMember(scope)).Err(), redis.Nil)
}

func TestCyberReplayRedisFailureKeepsBoundedLocalPositive(t *testing.T) {
	dead := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 10 * time.Millisecond,
		ReadTimeout: 10 * time.Millisecond, WriteTimeout: 10 * time.Millisecond,
	})
	t.Cleanup(func() { _ = dead.Close() })
	now := time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)
	svc := NewCyberFeedbackService(&cyberReplayRepositoryStub{}, dead, &config.Config{}, nil, nil, nil)
	svc.clock = fixedClock{now: now}
	scope := cyberTestScope(11, "hmac-sha256-v1:dead", []byte("signature"))
	svc.cacheConfirmedSignature(context.Background(), scope, now.Add(6*24*time.Hour))
	require.True(t, svc.IsReplay(context.Background(), CyberTurnEvidence{Scope: scope}))
	svc.replayCacheMu.Lock()
	require.Equal(t, now.Add(cyberReplayLocalPositiveTTL), svc.positiveReplay[cyberSignatureCacheMember(scope)])
	svc.replayCacheMu.Unlock()
}

func TestCyberCanonicalFingerprintPreservesRolesAndSegmentBoundaries(t *testing.T) {
	groupID := int64(12)
	svc := NewCyberFeedbackService(nil, nil, &config.Config{JWT: config.JWTConfig{Secret: "stable-key"}}, nil, nil, nil)
	prepare := func(protocol, stage, body string) CyberTurnEvidence {
		evidence, ok := svc.PrepareTurn(Request{
			GroupID: &groupID, Provider: service.PlatformOpenAI, Protocol: protocol, Stage: stage, Body: []byte(body),
		}, 0)
		require.True(t, ok)
		require.NotEmpty(t, evidence.Scope.PromptSignature)
		return evidence
	}
	rolesA := prepare("openai_chat_completions", "http", `{"messages":[{"role":"user","content":"alpha"},{"role":"assistant","content":"beta"}]}`)
	rolesB := prepare("openai_chat_completions", "http", `{"messages":[{"role":"assistant","content":"alpha"},{"role":"user","content":"beta"}]}`)
	require.NotEqual(t, rolesA.Scope.PromptSignature, rolesB.Scope.PromptSignature)

	oneSegment := prepare("openai_responses", "http", `{"input":[{"role":"user","content":"alpha\n\nbeta"}]}`)
	twoSegments := prepare("openai_responses", "http", `{"input":[{"role":"user","content":[{"type":"input_text","text":"alpha"},{"type":"input_text","text":"beta"}]}]}`)
	require.NotEqual(t, oneSegment.Scope.PromptSignature, twoSegments.Scope.PromptSignature)

	httpEvidence := prepare("openai_responses", "http", `{"input":[{"role":"user","content":[{"type":"input_text","text":"same semantic turn"}]}]}`)
	wsEvidence := prepare("responses_websocket", "first_turn", `{"type":"response.create","input":[{"role":"user","content":[{"type":"input_text","text":"same semantic turn"}]}]}`)
	require.Equal(t, httpEvidence.Scope.PromptSignature, wsEvidence.Scope.PromptSignature)
}

func TestCyberEventNonceFallbackAndFeedbackJSONStaySafe(t *testing.T) {
	original := cyberRandomRead
	cyberRandomRead = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	t.Cleanup(func() { cyberRandomRead = original })
	first, second := newCyberEventNonce(), newCyberEventNonce()
	require.Len(t, first, 16)
	require.Len(t, second, 16)
	require.NotEqual(t, first, second)

	apiKeyID := int64(44)
	payload, err := json.Marshal(CyberFeedback{APIKeyID: &apiKeyID, SignatureVersion: "secret", PromptSignature: []byte("secret")})
	require.NoError(t, err)
	require.NotContains(t, string(payload), "api_key_id")
	require.NotContains(t, string(payload), "signature_version")
	require.NotContains(t, string(payload), "prompt_signature")
	require.NotContains(t, string(payload), "secret")
}

func TestCyberFeedbackPreviewWithholdsAllPromptText(t *testing.T) {
	groupID := int64(12)
	repo := &cyberFeedbackRepositoryStub{}
	svc := NewCyberFeedbackService(repo, nil, &config.Config{JWT: config.JWTConfig{Secret: "stable-key"}}, nil, nil, nil)
	evidence, ok := svc.PrepareTurn(Request{
		RequestID: "request-safe-preview", GroupID: &groupID, Provider: service.PlatformOpenAI,
		Protocol: "openai_responses", Body: []byte(`{"input":"Alice_INTERNAL asked about abcd1234"}`),
	}, 0)
	require.True(t, ok)
	require.Contains(t, evidence.RedactedPreview, "content withheld")
	for _, forbidden := range []string{"Alice", "INTERNAL", "abcd1234"} {
		require.NotContains(t, evidence.RedactedPreview, forbidden)
	}
	feedback, inserted, err := svc.ConfirmOpenAIOAuthCYB(context.Background(), evidence, 77, 400)
	require.NoError(t, err)
	require.True(t, inserted)
	payload, err := json.Marshal(feedback)
	require.NoError(t, err)
	for _, forbidden := range []string{"Alice", "INTERNAL", "abcd1234"} {
		require.NotContains(t, string(payload), forbidden)
	}
}

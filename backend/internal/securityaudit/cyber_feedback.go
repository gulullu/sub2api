package securityaudit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

const (
	CyberSignatureVersion = "hmac-sha256-v1"
	CyberSignatureTTL     = 7 * 24 * time.Hour

	CyberReviewPending  = "pending"
	CyberReviewApproved = "approved"
	CyberReviewRejected = "rejected"

	CyberGenerationPending   = "pending"
	CyberGenerationGenerated = "generated"
	CyberGenerationFailed    = "failed"

	OpenAIOAuthCYBAdminRecipient = "gulullu@gmail.com"
	cyberReplayLocalPositiveTTL  = time.Minute
	cyberReplayLocalCacheCap     = 4096
	cyberReplayWarmTTL           = 10 * time.Minute
	cyberReplayWarmTimeout       = 500 * time.Millisecond
	cyberReplayWarmFailureTTL    = 5 * time.Second
	cyberReplayWarmPageSize      = 500
	cyberReplayReadyMember       = "__ready__"
)

var (
	ErrCyberFeedbackNotFound           = errors.New("cyber feedback not found")
	ErrCyberFeedbackReviewConflict     = errors.New("cyber feedback review conflict")
	ErrCyberFeedbackGenerationConflict = errors.New("cyber feedback generation conflict")
)

type CyberFingerprintScope struct {
	GroupID          int64  `json:"-"`
	Protocol         string `json:"-"`
	Stage            string `json:"-"`
	SignatureVersion string `json:"-"`
	PromptSignature  []byte `json:"-"`
}

type CyberTurnEvidence struct {
	Scope           CyberFingerprintScope `json:"-"`
	RequestID       string                `json:"-"`
	APIKeyID        int64                 `json:"-"`
	Model           string                `json:"-"`
	Endpoint        string                `json:"-"`
	Transport       string                `json:"-"`
	Stage           string                `json:"-"`
	TurnNumber      int                   `json:"-"`
	RedactedPreview string                `json:"-"`
	EventNonce      []byte                `json:"-"`
	snapshot        PromptSnapshot
}

type CyberConfirmInput struct {
	Scope           CyberFingerprintScope
	EventKey        string
	RequestID       string
	TurnNumber      int
	APIKeyID        int64
	GroupID         int64
	AccountID       int64
	Model           string
	Endpoint        string
	Protocol        string
	Transport       string
	Stage           string
	UpstreamStatus  int
	RedactedPreview string
	ExpiresAt       time.Time
}

// CyberFeedback is safe for admin APIs. The HMAC and its version are repository
// internals and are deliberately excluded from JSON.
type CyberFeedback struct {
	ID                    int64      `json:"id"`
	SignatureID           int64      `json:"-"`
	SignatureVersion      string     `json:"-"`
	PromptSignature       []byte     `json:"-"`
	RequestID             string     `json:"request_id"`
	TurnNumber            int        `json:"turn_number"`
	APIKeyID              *int64     `json:"-"`
	GroupID               int64      `json:"group_id"`
	AccountID             int64      `json:"account_id"`
	Model                 string     `json:"model"`
	Endpoint              string     `json:"endpoint"`
	Protocol              string     `json:"protocol"`
	Transport             string     `json:"transport"`
	Stage                 string     `json:"stage"`
	UpstreamStatus        int        `json:"upstream_status"`
	RedactedPreview       string     `json:"redacted_preview"`
	SignatureConfirmCount int64      `json:"signature_confirm_count"`
	FirstConfirmedAt      *time.Time `json:"first_confirmed_at,omitempty"`
	LastConfirmedAt       *time.Time `json:"last_confirmed_at,omitempty"`
	GenerationStatus      string     `json:"generation_status"`
	GenerationErrorCode   string     `json:"generation_error_code,omitempty"`
	CandidateRuleText     string     `json:"candidate_rule_text,omitempty"`
	ReviewStatus          string     `json:"review_status"`
	ReviewedBy            *int64     `json:"reviewed_by,omitempty"`
	ReviewedAt            *time.Time `json:"reviewed_at,omitempty"`
	RuleID                string     `json:"rule_id,omitempty"`
	ConfigVersion         int64      `json:"config_version"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// CyberActiveSignature is the bounded database-to-Redis warmup projection.
// It never leaves the backend and contains no raw prompt material.
type CyberActiveSignature struct {
	ID               int64
	GroupID          int64
	SignatureVersion string
	PromptSignature  []byte
	ExpiresAt        time.Time
}

type CyberFeedbackFilter struct {
	GroupID          *int64
	ReviewStatus     string
	GenerationStatus string
}

type CyberFeedbackRepository interface {
	Confirm(ctx context.Context, input CyberConfirmInput) (CyberFeedback, bool, error)
	MatchActiveSignature(ctx context.Context, scope CyberFingerprintScope) (bool, error)
	ListActiveSignatures(ctx context.Context, groupID int64, signatureVersion string, afterID int64, limit int) ([]CyberActiveSignature, error)
	ListCyberFeedback(ctx context.Context, filter CyberFeedbackFilter, page, pageSize int) ([]CyberFeedback, int64, error)
	GetCyberFeedback(ctx context.Context, id int64) (CyberFeedback, error)
	ReviewCyberFeedback(ctx context.Context, id int64, status string, actorID int64, ruleID string, configVersion int64) (CyberFeedback, error)
	ResetCyberRuleGeneration(ctx context.Context, id int64) error
	CompleteCyberRuleGeneration(ctx context.Context, id int64, candidateRuleText, errorCode string) error
}

type CyberRuleDraftGenerator interface {
	GenerateCyberRuleDraft(ctx context.Context, snapshot PromptSnapshot) (string, error)
}

type CyberFeedbackService struct {
	repo             CyberFeedbackRepository
	redis            *redis.Client
	notification     *service.NotificationEmailService
	settings         service.SettingRepository
	generator        CyberRuleDraftGenerator
	hmacKey          []byte
	signatureVersion string
	clock            Clock
	generationSlots  chan struct{}
	warmSlots        chan struct{}
	warmLookup       singleflight.Group
	replayCacheMu    sync.Mutex
	positiveReplay   map[string]time.Time
	warmFailureMu    sync.Mutex
	warmFailures     map[string]time.Time
}

var (
	cyberEventNonceFallback atomic.Uint64
	cyberRandomRead         = rand.Read
)

func NewCyberFeedbackService(
	repo CyberFeedbackRepository,
	redisClient *redis.Client,
	cfg *config.Config,
	notification *service.NotificationEmailService,
	settings service.SettingRepository,
	generator CyberRuleDraftGenerator,
) *CyberFeedbackService {
	var key []byte
	if cfg != nil && strings.TrimSpace(cfg.JWT.Secret) != "" {
		key = []byte(strings.TrimSpace(cfg.JWT.Secret))
	}
	signatureVersion := ""
	if len(key) > 0 {
		digest := sha256.Sum256(key)
		signatureVersion = CyberSignatureVersion + ":" + hex.EncodeToString(digest[:6])
	}
	return &CyberFeedbackService{
		repo: repo, redis: redisClient, notification: notification, settings: settings,
		generator: generator, hmacKey: key, signatureVersion: signatureVersion,
		clock: realClock{}, generationSlots: make(chan struct{}, 4), warmSlots: make(chan struct{}, 2),
		positiveReplay: make(map[string]time.Time), warmFailures: make(map[string]time.Time),
	}
}

// PrepareTurn always retains safe event metadata for OpenAI turns. When the
// stable HMAC key or prompt text is unavailable, replay blocking fails open but
// a real upstream confirmation can still create an event and administrator alert.
func (s *CyberFeedbackService) PrepareTurn(req Request, turnNumber int) (CyberTurnEvidence, bool) {
	if s == nil || !strings.EqualFold(strings.TrimSpace(req.Provider), service.PlatformOpenAI) {
		return CyberTurnEvidence{}, false
	}
	stage := strings.TrimSpace(req.Stage)
	if stage == "" {
		stage = "http"
	}
	transport := "http"
	if stage == "first_turn" || stage == "subsequent_turn" {
		transport = "websocket"
	}
	if turnNumber < 0 {
		turnNumber = 0
	}
	groupID := int64(0)
	if req.GroupID != nil {
		groupID = *req.GroupID
	}
	evidence := CyberTurnEvidence{
		Scope:     CyberFingerprintScope{GroupID: groupID, Protocol: strings.TrimSpace(req.Protocol), Stage: stage},
		RequestID: req.RequestID, APIKeyID: req.APIKeyID, Model: req.Model,
		Endpoint: req.Endpoint, Transport: transport, Stage: stage, TurnNumber: turnNumber,
		EventNonce: newCyberEventNonce(),
	}
	snapshot, err := ExtractPromptSnapshot(req)
	if err != nil {
		return evidence, true
	}
	evidence.RedactedPreview = cyberContentWithheldSummary(snapshot)
	evidence.snapshot = minimalCyberGenerationSnapshot(snapshot)
	if len(s.hmacKey) == 0 || groupID <= 0 {
		return evidence, true
	}
	digest := snapshot.cyberCanonicalDigest
	if len(digest) != sha256.Size {
		return evidence, true
	}
	mac := hmac.New(sha256.New, s.hmacKey)
	_, _ = mac.Write([]byte("sub2api/openai-oauth-cyb-prompt/v1\x00"))
	_, _ = mac.Write(digest)
	evidence.Scope.SignatureVersion = s.signatureVersion
	evidence.Scope.PromptSignature = mac.Sum(nil)
	return evidence, true
}

// IsReplay uses a versioned Redis ZSET warmed in bounded batches from the
// authoritative database. A healthy ready ZSET makes unique-prompt misses a
// Redis-only fast path; storage failures and warmup overload always fail open.
func (s *CyberFeedbackService) IsReplay(ctx context.Context, evidence CyberTurnEvidence) bool {
	if s == nil || s.repo == nil || len(evidence.Scope.PromptSignature) == 0 {
		return false
	}
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	member := cyberSignatureCacheMember(evidence.Scope)
	if s.localPositiveReplayHit(member) {
		return true
	}
	if s.redis == nil || strings.TrimSpace(evidence.Scope.SignatureVersion) == "" {
		return false
	}
	zsetKey := cyberSignatureZSetKey(evidence.Scope.GroupID, evidence.Scope.SignatureVersion)
	ready, err := s.redis.ZScore(ctx, zsetKey, cyberReplayReadyMember).Result()
	_ = ready
	if errors.Is(err, redis.Nil) {
		if !s.warmReplayIndex(ctx, evidence.Scope.GroupID, evidence.Scope.SignatureVersion) {
			return false
		}
	} else if err != nil {
		return false
	}
	return s.replayMemberActive(ctx, zsetKey, member)
}

func (s *CyberFeedbackService) ConfirmOpenAIOAuthCYB(ctx context.Context, evidence CyberTurnEvidence, accountID int64, upstreamStatus int) (CyberFeedback, bool, error) {
	if s == nil || s.repo == nil || accountID <= 0 {
		return CyberFeedback{}, false, errors.New("cyber feedback service unavailable")
	}
	now := s.clock.Now()
	input := CyberConfirmInput{
		Scope: evidence.Scope, EventKey: cyberEventKey(evidence, accountID), RequestID: evidence.RequestID,
		TurnNumber: evidence.TurnNumber, APIKeyID: evidence.APIKeyID, GroupID: evidence.Scope.GroupID,
		AccountID: accountID, Model: evidence.Model, Endpoint: evidence.Endpoint, Protocol: evidence.Scope.Protocol,
		Transport: evidence.Transport, Stage: evidence.Scope.Stage, UpstreamStatus: upstreamStatus,
		RedactedPreview: evidence.RedactedPreview, ExpiresAt: now.Add(CyberSignatureTTL),
	}
	feedback, inserted, err := s.repo.Confirm(ctx, input)
	if err != nil {
		return CyberFeedback{}, false, err
	}
	if !inserted {
		return feedback, false, nil
	}
	if len(evidence.Scope.PromptSignature) > 0 {
		s.cacheConfirmedSignature(ctx, evidence.Scope, input.ExpiresAt)
	}
	s.sendAdminAlert(ctx, feedback)
	if s.generator != nil && len(evidence.Scope.PromptSignature) > 0 && evidence.snapshot.ScanText != "" {
		select {
		case s.generationSlots <- struct{}{}:
			snapshot := evidence.snapshot
			feedbackID := feedback.ID
			go func() {
				defer func() { <-s.generationSlots }()
				s.generateRuleDraft(feedbackID, snapshot)
			}()
		default:
			if updateErr := s.repo.CompleteCyberRuleGeneration(ctx, feedback.ID, "", "generation_busy"); updateErr != nil {
				slog.Warn("cyber feedback busy generation update failed", "feedback_id", feedback.ID, "error", updateErr)
			}
		}
	}
	return feedback, true, nil
}

func (s *CyberFeedbackService) generateRuleDraft(feedbackID int64, snapshot PromptSnapshot) {
	generationCtx, cancelGeneration := context.WithTimeout(context.Background(), 90*time.Second)
	rule, err := s.generator.GenerateCyberRuleDraft(generationCtx, snapshot)
	cancelGeneration()
	errorCode := ""
	if err != nil {
		rule = ""
		errorCode = cyberGenerationErrorCode(err)
	}
	updateCtx, cancelUpdate := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelUpdate()
	if updateErr := s.repo.CompleteCyberRuleGeneration(updateCtx, feedbackID, rule, errorCode); updateErr != nil {
		slog.Warn("cyber feedback rule draft result update failed", "feedback_id", feedbackID, "error", updateErr)
	}
}

func (s *CyberFeedbackService) sendAdminAlert(ctx context.Context, feedback CyberFeedback) {
	if s.notification == nil {
		return
	}
	variables := map[string]string{
		"event_id": strconv.FormatInt(feedback.ID, 10),
		"group_id": strconv.FormatInt(feedback.GroupID, 10), "account_id": strconv.FormatInt(feedback.AccountID, 10),
		"model": feedback.Model, "endpoint": feedback.Endpoint, "protocol": feedback.Protocol,
		"transport": feedback.Transport, "stage": feedback.Stage, "upstream_status": strconv.Itoa(feedback.UpstreamStatus),
		"admin_link": s.adminLink(ctx, feedback.ID), "triggered_at": feedback.CreatedAt.UTC().Format(time.RFC3339),
	}
	if err := s.notification.Send(ctx, service.NotificationEmailSendInput{
		Event: service.NotificationEmailEventOpenAIOAuthCYBAdminAlert, Locale: "zh",
		RecipientEmail: OpenAIOAuthCYBAdminRecipient, RecipientName: "Administrator",
		SourceType: "prompt_audit_cyber_feedback", SourceID: strconv.FormatInt(feedback.ID, 10), Variables: variables,
	}); err != nil {
		slog.Warn("cyber feedback admin email failed", "feedback_id", feedback.ID, "error", err)
	}
}

func (s *CyberFeedbackService) adminLink(ctx context.Context, feedbackID int64) string {
	baseURL := ""
	if s.settings != nil {
		for _, key := range []string{service.SettingKeyFrontendURL, service.SettingKeyAPIBaseURL} {
			if value, err := s.settings.GetValue(ctx, key); err == nil && strings.TrimSpace(value) != "" {
				baseURL = strings.TrimRight(strings.TrimSpace(value), "/")
				break
			}
		}
	}
	return fmt.Sprintf("%s/admin/prompt-audit?tab=cyber&cyber_feedback_id=%d", baseURL, feedbackID)
}

func cyberSignatureCacheMember(scope CyberFingerprintScope) string {
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "%d\x00%s\x00", scope.GroupID, scope.SignatureVersion)
	_, _ = digest.Write(scope.PromptSignature)
	return hex.EncodeToString(digest.Sum(nil))
}

func cyberSignatureCacheKey(scope CyberFingerprintScope) string {
	return cyberSignatureZSetKey(scope.GroupID, scope.SignatureVersion) + ":" + cyberSignatureCacheMember(scope)
}

func cyberSignatureZSetKey(groupID int64, signatureVersion string) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s", groupID, strings.TrimSpace(signatureVersion))))
	return "sub2api:prompt_audit:cyber_active:" + hex.EncodeToString(digest[:])
}

func (s *CyberFeedbackService) localPositiveReplayHit(key string) bool {
	if s == nil || key == "" {
		return false
	}
	now := s.clock.Now()
	s.replayCacheMu.Lock()
	defer s.replayCacheMu.Unlock()
	expiresAt, ok := s.positiveReplay[key]
	if !ok {
		return false
	}
	if !now.Before(expiresAt) {
		delete(s.positiveReplay, key)
		return false
	}
	return true
}

func (s *CyberFeedbackService) setLocalPositiveReplay(key string, persistentExpiresAt time.Time) {
	if s == nil || key == "" {
		return
	}
	now := s.clock.Now()
	if !persistentExpiresAt.After(now) {
		return
	}
	localExpiresAt := persistentExpiresAt
	if capAt := now.Add(cyberReplayLocalPositiveTTL); localExpiresAt.After(capAt) {
		localExpiresAt = capAt
	}
	s.replayCacheMu.Lock()
	defer s.replayCacheMu.Unlock()
	if len(s.positiveReplay) >= cyberReplayLocalCacheCap {
		for candidate := range s.positiveReplay {
			delete(s.positiveReplay, candidate)
			break
		}
	}
	s.positiveReplay[key] = localExpiresAt
}

func (s *CyberFeedbackService) clearLocalPositiveReplay(key string) {
	if s == nil || key == "" {
		return
	}
	s.replayCacheMu.Lock()
	defer s.replayCacheMu.Unlock()
	delete(s.positiveReplay, key)
}

func (s *CyberFeedbackService) replayMemberActive(ctx context.Context, zsetKey, member string) bool {
	score, err := s.redis.ZScore(ctx, zsetKey, member).Result()
	if errors.Is(err, redis.Nil) {
		return false
	}
	if err != nil {
		return false
	}
	expiresAt := time.UnixMilli(int64(score)).UTC()
	if !expiresAt.After(s.clock.Now()) {
		_ = s.redis.ZRem(ctx, zsetKey, member).Err()
		s.clearLocalPositiveReplay(member)
		return false
	}
	s.setLocalPositiveReplay(member, expiresAt)
	return true
}

func (s *CyberFeedbackService) warmReplayIndex(ctx context.Context, groupID int64, signatureVersion string) bool {
	if s == nil || s.repo == nil || s.redis == nil || groupID <= 0 || strings.TrimSpace(signatureVersion) == "" {
		return false
	}
	warmKey := cyberSignatureWarmKey(groupID, signatureVersion)
	if s.recentWarmFailure(warmKey) {
		return false
	}
	warmBaseCtx := context.WithoutCancel(ctx)
	result := s.warmLookup.DoChan(warmKey, func() (any, error) {
		warmCtx, cancel := context.WithTimeout(warmBaseCtx, cyberReplayWarmTimeout)
		defer cancel()
		if _, err := s.redis.ZScore(warmCtx, cyberSignatureZSetKey(groupID, signatureVersion), cyberReplayReadyMember).Result(); err == nil {
			return true, nil
		} else if !errors.Is(err, redis.Nil) {
			return false, err
		}
		select {
		case s.warmSlots <- struct{}{}:
			defer func() { <-s.warmSlots }()
		default:
			return false, errors.New("cyber replay warmup busy")
		}
		return true, s.loadReplayIndex(warmCtx, groupID, signatureVersion)
	})
	select {
	case <-ctx.Done():
		return false
	case outcome := <-result:
		if outcome.Err != nil {
			s.noteWarmFailure(warmKey)
			slog.Warn("cyber feedback replay index warmup failed open", "error", outcome.Err)
			return false
		}
		ready, _ := outcome.Val.(bool)
		return ready
	}
}

func (s *CyberFeedbackService) loadReplayIndex(ctx context.Context, groupID int64, signatureVersion string) error {
	zsetKey := cyberSignatureZSetKey(groupID, signatureVersion)
	afterID := int64(0)
	for {
		items, err := s.repo.ListActiveSignatures(ctx, groupID, signatureVersion, afterID, cyberReplayWarmPageSize)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			break
		}
		members := make([]redis.Z, 0, len(items))
		for _, item := range items {
			if item.ID <= afterID || item.GroupID != groupID || item.SignatureVersion != signatureVersion || len(item.PromptSignature) == 0 {
				return errors.New("cyber replay warmup returned invalid signature")
			}
			afterID = item.ID
			if !item.ExpiresAt.After(s.clock.Now()) {
				continue
			}
			members = append(members, redis.Z{
				Score: float64(item.ExpiresAt.UnixMilli()),
				Member: cyberSignatureCacheMember(CyberFingerprintScope{
					GroupID: item.GroupID, SignatureVersion: item.SignatureVersion, PromptSignature: item.PromptSignature,
				}),
			})
		}
		if len(members) > 0 {
			if err := s.redis.ZAddArgs(ctx, zsetKey, redis.ZAddArgs{GT: true, Members: members}).Err(); err != nil {
				return err
			}
		}
		if len(items) < cyberReplayWarmPageSize {
			break
		}
	}
	pipe := s.redis.TxPipeline()
	pipe.ZRemRangeByScore(ctx, zsetKey, "-inf", strconv.FormatInt(s.clock.Now().UnixMilli(), 10))
	pipe.ZAdd(ctx, zsetKey, redis.Z{Score: 0, Member: cyberReplayReadyMember})
	pipe.Expire(ctx, zsetKey, cyberReplayWarmTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		_ = s.redis.ZRem(context.Background(), zsetKey, cyberReplayReadyMember).Err()
		return err
	}
	s.clearWarmFailure(cyberSignatureWarmKey(groupID, signatureVersion))
	return nil
}

func (s *CyberFeedbackService) cacheConfirmedSignature(ctx context.Context, scope CyberFingerprintScope, persistentExpiresAt time.Time) {
	member := cyberSignatureCacheMember(scope)
	s.setLocalPositiveReplay(member, persistentExpiresAt)
	if s.redis == nil || strings.TrimSpace(scope.SignatureVersion) == "" {
		return
	}
	zsetKey := cyberSignatureZSetKey(scope.GroupID, scope.SignatureVersion)
	ready, err := s.redis.ZScore(ctx, zsetKey, cyberReplayReadyMember).Result()
	_ = ready
	if err != nil && !errors.Is(err, redis.Nil) {
		slog.Warn("cyber feedback cache update failed", "error", err)
		return
	}
	pipe := s.redis.TxPipeline()
	pipe.ZAddArgs(ctx, zsetKey, redis.ZAddArgs{GT: true, Members: []redis.Z{{Score: float64(persistentExpiresAt.UnixMilli()), Member: member}}})
	if err == nil {
		pipe.ZAdd(ctx, zsetKey, redis.Z{Score: 0, Member: cyberReplayReadyMember})
		pipe.Expire(ctx, zsetKey, cyberReplayWarmTTL)
	}
	if _, execErr := pipe.Exec(ctx); execErr != nil {
		if err == nil {
			_ = s.redis.ZRem(context.Background(), zsetKey, cyberReplayReadyMember).Err()
		}
		slog.Warn("cyber feedback cache update failed", "error", execErr)
	}
}

func cyberSignatureWarmKey(groupID int64, signatureVersion string) string {
	return strconv.FormatInt(groupID, 10) + "\x00" + strings.TrimSpace(signatureVersion)
}

func (s *CyberFeedbackService) recentWarmFailure(signatureVersion string) bool {
	now := s.clock.Now()
	s.warmFailureMu.Lock()
	defer s.warmFailureMu.Unlock()
	expiresAt, ok := s.warmFailures[signatureVersion]
	if !ok {
		return false
	}
	if !now.Before(expiresAt) {
		delete(s.warmFailures, signatureVersion)
		return false
	}
	return true
}

func (s *CyberFeedbackService) noteWarmFailure(signatureVersion string) {
	s.warmFailureMu.Lock()
	defer s.warmFailureMu.Unlock()
	if len(s.warmFailures) >= 16 {
		for version := range s.warmFailures {
			delete(s.warmFailures, version)
			break
		}
	}
	s.warmFailures[signatureVersion] = s.clock.Now().Add(cyberReplayWarmFailureTTL)
}

func (s *CyberFeedbackService) clearWarmFailure(signatureVersion string) {
	s.warmFailureMu.Lock()
	delete(s.warmFailures, signatureVersion)
	s.warmFailureMu.Unlock()
}

func minimalCyberGenerationSnapshot(snapshot PromptSnapshot) PromptSnapshot {
	return PromptSnapshot{
		RequestID: snapshot.RequestID, GroupID: cloneInt64Ptr(snapshot.GroupID),
		Provider: snapshot.Provider, Endpoint: snapshot.Endpoint, Protocol: snapshot.Protocol,
		Model: snapshot.Model, RedactedPreview: cyberContentWithheldSummary(snapshot), Stage: snapshot.Stage,
		ScanText: boundedCyberRuleSource(snapshot.ScanText),
	}
}

func cyberContentWithheldSummary(snapshot PromptSnapshot) string {
	return fmt.Sprintf("[content withheld; characters=%d; messages=%d]", snapshot.PromptLength, snapshot.MessageCount)
}

func cyberEventKey(evidence CyberTurnEvidence, accountID int64) string {
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "%s\x00%s\x00%d\x00%d", evidence.RequestID, evidence.Stage, evidence.TurnNumber, accountID)
	if len(evidence.Scope.PromptSignature) > 0 {
		_, _ = digest.Write([]byte("\x00signature\x00" + evidence.Scope.SignatureVersion + "\x00"))
		_, _ = digest.Write(evidence.Scope.PromptSignature)
	} else {
		nonce := evidence.EventNonce
		if len(nonce) == 0 {
			nonce = newCyberEventNonce()
		}
		_, _ = digest.Write([]byte("\x00nonce\x00"))
		_, _ = digest.Write(nonce)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func newCyberEventNonce() []byte {
	nonce := make([]byte, 16)
	if _, err := cyberRandomRead(nonce); err == nil {
		return nonce
	}
	counter := cyberEventNonceFallback.Add(1)
	fallback := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", time.Now().UnixNano(), counter)))
	return append([]byte(nil), fallback[:16]...)
}

func cyberGenerationErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var guardErr *GuardError
	if errors.As(err, &guardErr) && strings.TrimSpace(guardErr.Code) != "" {
		return strings.TrimSpace(guardErr.Code)
	}
	return "generation_failed"
}

package securityaudit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type prefixEncryptor struct{}

func (prefixEncryptor) Encrypt(value string) (string, error) { return "enc:" + value, nil }
func (prefixEncryptor) Decrypt(value string) (string, error) {
	if !strings.HasPrefix(value, "enc:") {
		return "", errors.New("cipher: message authentication failed")
	}
	return value[4:], nil
}

type opaqueTestEncryptor struct{}

func (opaqueTestEncryptor) Encrypt(value string) (string, error) {
	encoded := []byte(value)
	for index := range encoded {
		encoded[index] ^= 0x5a
	}
	return base64.RawStdEncoding.EncodeToString(encoded), nil
}

func (opaqueTestEncryptor) Decrypt(value string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	for index := range decoded {
		decoded[index] ^= 0x5a
	}
	return string(decoded), nil
}

// testTotpKeyConfig mirrors a deployment with a fixed TOTP_ENCRYPTION_KEY so
// unit tests may persist endpoint tokens.
func testTotpKeyConfig() *config.Config {
	return &config.Config{Totp: config.TotpConfig{EncryptionKeyConfigured: true}}
}

func TestDefaultConfigIsOff(t *testing.T) {
	storage, err := ParseStorageConfig("")
	require.NoError(t, err)
	require.False(t, storage.Enabled)
	require.False(t, storage.BlockingLatestTurnOnly)
	active, err := ActiveFromStorage(storage, true, prefixEncryptor{})
	require.NoError(t, err)
	require.Equal(t, ModeOff, active.EffectiveMode())
	require.Equal(t, AllScannerIDs, storage.Scanners)
	require.Equal(t, DefaultPromptTemplateID, storage.ActivePromptTemplateID)
	require.Equal(t, DefaultFlagThreshold, thresholdValue(storage.FlagThreshold, -1))
	require.Equal(t, DefaultBlockThreshold, thresholdValue(storage.BlockThreshold, -1))
	require.Equal(t, DefaultBlockHTTPStatus, storage.BlockHTTPStatus)
	require.Equal(t, DefaultBlockMessage, storage.BlockMessage)
	require.Equal(t, DefaultMaxTotalInputChars, storage.MaxTotalInputChars)
	require.Equal(t, DefaultNoRouteFallbackMode, storage.NoRouteFallbackMode)
	require.Empty(t, storage.CyberFeedbackAccountIDs)
	require.Equal(t, []PromptTemplate{DefaultPromptTemplate()}, storage.PromptTemplates)
	publicJSON, err := json.Marshal(PublicFromStorage(storage, true, nil))
	require.NoError(t, err)
	require.Contains(t, string(publicJSON), `"group_ids":[]`)
	require.Contains(t, string(publicJSON), `"risk_route_account_ids":[]`)
	require.Contains(t, string(publicJSON), `"cyber_feedback_account_ids":[]`)
	require.Contains(t, string(publicJSON), `"excluded_user_ids":[]`)
	require.Contains(t, string(publicJSON), `"no_route_fallback_mode":"block"`)
	require.Contains(t, string(publicJSON), `"endpoints":[]`)
}

func TestLegacyConfigDefaultsToQwenAdapterAndBuiltInPolicy(t *testing.T) {
	storage, err := ParseStorageConfig(`{"enabled":false,"strategy":"priority","worker_count":1,"queue_capacity":10,"scanners":["pii"],"all_groups":true,"endpoints":[{"id":"old","name":"Old","protocol":"openai_compatible","base_url":"http://127.0.0.1:8080","model":"guard","timeout_ms":1000,"input_limit":1000}]}`)
	require.NoError(t, err)
	require.Equal(t, AdapterQwen3Guard, storage.Endpoints[0].Adapter)
	require.Equal(t, DefaultPromptTemplateID, storage.ActivePromptTemplateID)
	require.Equal(t, DefaultFlagThreshold, thresholdValue(storage.FlagThreshold, -1))
	require.Equal(t, DefaultBlockThreshold, thresholdValue(storage.BlockThreshold, -1))
	require.Equal(t, 1, storage.Endpoints[0].Priority)
}

func TestEndpointPriorityBackwardCompatibilityRoundTripAndStableOrdering(t *testing.T) {
	legacy, err := ParseStorageConfig(`{"enabled":false,"strategy":"priority","worker_count":1,"queue_capacity":10,"scanners":["pii"],"all_groups":true,"endpoints":[{"id":"old-a","name":"Old A","protocol":"openai_compatible","base_url":"http://127.0.0.1:8080","model":"guard","timeout_ms":1000,"input_limit":1000},{"id":"old-b","name":"Old B","protocol":"openai_compatible","base_url":"http://127.0.0.1:8081","model":"guard","timeout_ms":1000,"input_limit":1000}]}`)
	require.NoError(t, err)
	require.Equal(t, []int{1, 2}, []int{legacy.Endpoints[0].Priority, legacy.Endpoints[1].Priority})

	public := PublicFromStorage(legacy, true, nil)
	require.Equal(t, []int{1, 2}, []int{public.Endpoints[0].Priority, public.Endpoints[1].Priority})
	raw, err := json.Marshal(public)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"priority":1`)

	cfg := ActiveConfig{Endpoints: []ActiveEndpoint{
		{ID: "later", Priority: 20, Enabled: true},
		{ID: "first-tie", Priority: 10, Enabled: true},
		{ID: "second-tie", Priority: 10, Enabled: true},
	}}
	ordered := cfg.EnabledEndpoints()
	require.Equal(t, []string{"first-tie", "second-tie", "later"}, []string{ordered[0].ID, ordered[1].ID, ordered[2].ID})
}

func TestEndpointPriorityUpdatePreservesOmittedAndRejectsOutOfRange(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	current := DefaultStorageConfig()
	current.Endpoints = []StorageEndpoint{{
		ID: "one", Name: "One", Priority: 7, Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080",
		Model: DefaultGuardModel, TimeoutMS: 1000, InputLimit: 1000,
	}}
	req := UpdateConfigRequest{
		ExpectedConfigVersion: 1, Strategy: "priority", WorkerCount: 1, QueueCapacity: 10,
		Scanners: []string{"pii"}, AllGroups: true,
		Endpoints: []UpdateEndpoint{{
			ID: "one", Name: "One", Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080",
			Model: DefaultGuardModel, TimeoutMS: 1000, InputLimit: 1000,
		}},
	}
	next, err := manager.buildNextStorage(current, req, 1)
	require.NoError(t, err)
	require.Equal(t, 7, next.Endpoints[0].Priority, "older PUT clients must not erase an existing priority")

	req.Endpoints[0].Priority = MaxEndpointPriority + 1
	_, err = manager.buildNextStorage(current, req, 1)
	require.Error(t, err)
	req.Endpoints[0].Priority = -1
	_, err = manager.buildNextStorage(current, req, 1)
	require.Error(t, err)
}

func TestOldUpdatePreservesNewPromptPolicyFields(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	current := DefaultStorageConfig()
	current.PromptTemplates = append(current.PromptTemplates, PromptTemplate{ID: "custom", Name: "Custom", SystemPrompt: "custom instructions"})
	current.ActivePromptTemplateID = "custom"
	current.FlagThreshold = float64Pointer(0.3)
	current.BlockThreshold = float64Pointer(0.8)
	current.BlockHTTPStatus = 422
	current.BlockMessage = "custom block"
	current.RiskRouteAccountIDs = []int64{9}
	current.CyberFeedbackAccountIDs = []int64{77}
	current.ExcludedUserIDs = []int64{88}
	current.Endpoints = []StorageEndpoint{{ID: "one", Name: "One", Protocol: "openai_compatible", Adapter: AdapterConfidenceJSON, BaseURL: "http://127.0.0.1:8080", Model: "deepseek-chat", TimeoutMS: 1000, InputLimit: 1000}}
	req := UpdateConfigRequest{ExpectedConfigVersion: 1, Strategy: "priority", WorkerCount: 1, QueueCapacity: 10, Scanners: []string{"pii"}, AllGroups: true,
		Endpoints: []UpdateEndpoint{{ID: "one", Name: "One", Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080", Model: "deepseek-chat", TimeoutMS: 1000, InputLimit: 1000}}}

	next, err := manager.buildNextStorage(current, req, 9)
	require.NoError(t, err)
	require.Equal(t, AdapterConfidenceJSON, next.Endpoints[0].Adapter)
	require.Equal(t, current.PromptTemplates, next.PromptTemplates)
	require.Equal(t, "custom", next.ActivePromptTemplateID)
	require.Equal(t, 0.3, thresholdValue(next.FlagThreshold, -1))
	require.Equal(t, 0.8, thresholdValue(next.BlockThreshold, -1))
	require.Equal(t, 422, next.BlockHTTPStatus)
	require.Equal(t, "custom block", next.BlockMessage)
	require.Equal(t, []int64{9}, next.RiskRouteAccountIDs)
	require.Equal(t, []int64{77}, next.CyberFeedbackAccountIDs)
	require.Equal(t, []int64{88}, next.ExcludedUserIDs)
	require.Equal(t, DefaultMaxTotalInputChars, next.MaxTotalInputChars)
}

func TestPromptAuditMaxTotalInputCharsConfigRoundTrip(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	limit := 12345
	req := promptAuditUpdateRequest(1, 1, "")
	req.MaxTotalInputChars = &limit

	next, err := manager.buildNextStorage(DefaultStorageConfig(), req, 5)
	require.NoError(t, err)
	require.Equal(t, limit, next.MaxTotalInputChars)
	active, err := ActiveFromStorage(next, true, prefixEncryptor{})
	require.NoError(t, err)
	require.Equal(t, limit, active.MaxTotalInputChars)
	require.Equal(t, limit, PublicFromStorage(next, true, nil).MaxTotalInputChars)
}

func TestPromptAuditRiskRouteConfigRoundTrip(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	routeIDs := []int64{102, 101, 102}
	req := promptAuditUpdateRequest(1, 1, "")
	req.RiskRouteAccountIDs = &routeIDs

	next, err := manager.buildNextStorage(DefaultStorageConfig(), req, 5)
	require.NoError(t, err)
	require.Equal(t, []int64{101, 102}, next.RiskRouteAccountIDs)

	active, err := ActiveFromStorage(next, true, prefixEncryptor{})
	require.NoError(t, err)
	require.Equal(t, next.RiskRouteAccountIDs, active.RiskRouteAccountIDs)
	public := PublicFromStorage(next, true, nil)
	require.Equal(t, next.RiskRouteAccountIDs, public.RiskRouteAccountIDs)
}

func TestPromptAuditGroupPoliciesRoundTripAndUngroupedBucket(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	req := promptAuditUpdateRequest(1, 1, "")
	// Group policies own their mode; use a blocking legacy default here so the
	// round-trip assertion also exercises the strict global configuration path.
	req.BlockingEnabled = true
	req.AllGroups = false
	req.GroupIDs = nil
	policies := []GroupPolicy{
		{GroupID: 0, Enabled: true, BlockingEnabled: true, BlockingLatestTurnOnly: true,
			StorePassEvents: true, Strategy: "priority", Scanners: []string{"jailbreak"},
			MaxTotalInputChars: 2048, ActivePromptTemplateID: DefaultPromptTemplateID,
			FlagThreshold: 0.25, BlockThreshold: 0.75, BlockHTTPStatus: 429,
			BlockMessage: "ungrouped blocked", RiskRouteAccountIDs: []int64{22},
			CyberFeedbackAccountIDs: []int64{33}, ExcludedUserIDs: []int64{44},
			NoRouteFallbackMode: NoRouteFallbackAllow},
		{GroupID: 9, Enabled: true, BlockingEnabled: false, Strategy: "priority", Scanners: []string{"pii"},
			MaxTotalInputChars: DefaultMaxTotalInputChars, ActivePromptTemplateID: DefaultPromptTemplateID,
			FlagThreshold: DefaultFlagThreshold, BlockThreshold: DefaultBlockThreshold,
			BlockHTTPStatus: DefaultBlockHTTPStatus, BlockMessage: DefaultBlockMessage,
			NoRouteFallbackMode: NoRouteFallbackBlock},
	}
	// A real HTTP request is decoded from JSON, which records explicit false/
	// zero-valued fields in GroupPolicy.present. Exercise that wire path here.
	encodedPolicies, err := json.Marshal(policies)
	require.NoError(t, err)
	var wirePolicies []GroupPolicy
	require.NoError(t, json.Unmarshal(encodedPolicies, &wirePolicies))
	req.GroupPolicies = &wirePolicies
	next, err := manager.buildNextStorage(DefaultStorageConfig(), req, 5)
	require.NoError(t, err)
	require.Len(t, next.GroupPolicies, 2)
	require.Equal(t, int64(0), next.GroupPolicies[0].GroupID)
	require.Equal(t, NoRouteFallbackAllow, next.GroupPolicies[0].NoRouteFallbackMode)

	active, err := ActiveFromStorage(next, true, prefixEncryptor{})
	require.NoError(t, err)
	var ungrouped *int64
	effective := active.EffectiveForGroup(ungrouped)
	require.Equal(t, ModeBlocking, effective.EffectiveMode())
	require.Equal(t, []string{"jailbreak"}, effective.Scanners)
	require.Equal(t, []int64{22}, effective.RiskRouteAccountIDs)
	require.True(t, effective.IncludesUser(1))
	require.False(t, effective.IncludesUser(44))
	require.Equal(t, NoRouteFallbackAllow, effective.NoRouteFallbackMode)
	require.True(t, active.IncludesGroup(nil))

	groupID := int64(9)
	groupCfg := active.EffectiveForGroup(&groupID)
	require.Equal(t, ModeAsync, groupCfg.EffectiveMode())
	require.Equal(t, []string{"pii"}, groupCfg.Scanners)
	require.Equal(t, NoRouteFallbackBlock, groupCfg.NoRouteFallbackMode)

	public := PublicFromStorage(next, true, nil)
	require.Len(t, public.GroupPolicies, 2)
	raw, err := json.Marshal(next)
	require.NoError(t, err)
	parsed, err := ParseStorageConfig(string(raw))
	require.NoError(t, err)
	require.Equal(t, next.GroupPolicies, parsed.GroupPolicies)
}

func TestPromptAuditLegacyUpdatePreservesNoRouteFallbackMode(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	current := DefaultStorageConfig()
	current.NoRouteFallbackMode = NoRouteFallbackAllow
	// Simulate an older admin bundle that does not know the new top-level field.
	req := promptAuditUpdateRequest(1, 1, "")
	req.NoRouteFallbackMode = ""

	next, err := manager.buildNextStorage(current, req, 5)

	require.NoError(t, err)
	require.Equal(t, NoRouteFallbackAllow, next.NoRouteFallbackMode)
}

func TestPromptAuditGroupPolicyMissingFieldsInheritLegacyValues(t *testing.T) {
	storage := DefaultStorageConfig()
	storage.Enabled = true
	storage.BlockingEnabled = true
	storage.Scanners = []string{"pii"}
	storage.GroupPolicies = []GroupPolicy{{GroupID: 7}}
	storage.Endpoints = []StorageEndpoint{{ID: "guard", Name: "Guard", Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080", Model: DefaultGuardModel, TimeoutMS: 1000, InputLimit: 1000, Enabled: true}}
	normalizeStorageConfig(&storage)
	require.NoError(t, validateStorageConfig(storage))
	require.Equal(t, storage.Enabled, storage.GroupPolicies[0].Enabled)
	require.Equal(t, storage.BlockingEnabled, storage.GroupPolicies[0].BlockingEnabled)
	require.Equal(t, storage.Scanners, storage.GroupPolicies[0].Scanners)
	require.Equal(t, DefaultNoRouteFallbackMode, storage.GroupPolicies[0].NoRouteFallbackMode)
}

func TestPromptAuditGroupPolicyRejectsDuplicateAndUnknownFallbackMode(t *testing.T) {
	storage := DefaultStorageConfig()
	storage.GroupPolicies = []GroupPolicy{
		{GroupID: 5, Enabled: true, Strategy: "priority", Scanners: []string{"pii"}, MaxTotalInputChars: DefaultMaxTotalInputChars,
			ActivePromptTemplateID: DefaultPromptTemplateID, FlagThreshold: DefaultFlagThreshold, BlockThreshold: DefaultBlockThreshold,
			BlockHTTPStatus: DefaultBlockHTTPStatus, BlockMessage: DefaultBlockMessage, NoRouteFallbackMode: NoRouteFallbackBlock},
		{GroupID: 5},
	}
	normalizeStorageConfig(&storage)
	require.Error(t, validateStorageConfig(storage))
	storage.GroupPolicies = storage.GroupPolicies[:1]
	storage.GroupPolicies[0].NoRouteFallbackMode = "drop"
	require.Error(t, validateStorageConfig(storage))
}

func TestPromptAuditExcludedUserIDsRoundTripAndAdmissionGate(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	req := promptAuditUpdateRequest(1, 1, "")
	excluded := []int64{19, 19, 7, 42}
	req.ExcludedUserIDs = &excluded

	next, err := manager.buildNextStorage(DefaultStorageConfig(), req, 5)
	require.NoError(t, err)
	require.Equal(t, []int64{7, 19, 42}, next.ExcludedUserIDs)

	active, err := ActiveFromStorage(next, true, prefixEncryptor{})
	require.NoError(t, err)
	require.True(t, active.IncludesUser(1))
	require.False(t, active.IncludesUser(19))
	require.True(t, active.IncludesUser(0))

	public := PublicFromStorage(next, true, nil)
	require.Equal(t, []int64{7, 19, 42}, public.ExcludedUserIDs)
}

func TestPromptAuditExcludedUserIDsRejectInvalidInput(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	req := promptAuditUpdateRequest(1, 1, "")
	excluded := []int64{19, 0, 42}
	req.ExcludedUserIDs = &excluded

	_, err := manager.buildNextStorage(DefaultStorageConfig(), req, 5)
	require.Error(t, err)
}

func TestContentModerationCredentialSourceIsOneShotEncryptedAndNeverPublic(t *testing.T) {
	const canary = "sk-content-moderation-canary"
	source, err := parseContentModerationCredentialSource(`{"api_key":"` + canary + `","base_url":"https://api.openai.com/v1","model":"omni-moderation-latest"}`)
	require.NoError(t, err)
	require.Equal(t, canary, source.credential)
	require.Equal(t, "https://api.openai.com", source.baseURL)
	require.Equal(t, DefaultOpenAIModerationModel, source.model)

	req := promptAuditUpdateRequest(1, 1, "")
	req.Endpoints[0].Adapter = AdapterOpenAIModeration
	req.Endpoints[0].BaseURL = "https://attacker.invalid"
	req.Endpoints[0].Model = "attacker-model"
	req.Endpoints[0].CredentialSource = CredentialSourceContentModeration
	resolved, err := applyEndpointCredentialSource(req, DefaultStorageConfig(), source)
	require.NoError(t, err)
	require.Equal(t, canary, resolved.Endpoints[0].Token)
	require.Equal(t, "https://api.openai.com", resolved.Endpoints[0].BaseURL)
	require.Equal(t, DefaultOpenAIModerationModel, resolved.Endpoints[0].Model)
	require.Empty(t, resolved.Endpoints[0].CredentialSource)

	manager := &ConfigManager{encryptor: opaqueTestEncryptor{}, encryptionKeyConfigured: true}
	next, err := manager.buildNextStorage(DefaultStorageConfig(), resolved, 5)
	require.NoError(t, err)
	require.NotEqual(t, canary, next.Endpoints[0].TokenCiphertext)
	decrypted, err := manager.encryptor.Decrypt(next.Endpoints[0].TokenCiphertext)
	require.NoError(t, err)
	require.Equal(t, canary, decrypted)
	rawStorage, err := json.Marshal(next)
	require.NoError(t, err)
	require.NotContains(t, string(rawStorage), canary)
	require.NotContains(t, string(rawStorage), "credential_source")
	next.CyberSupplementRules = []CyberSupplementRule{{ID: "reviewed-rule", RuleText: "抽象规则", Status: "active"}}
	active, err := ActiveFromStorage(next, true, manager.encryptor)
	require.NoError(t, err)
	require.Len(t, active.Endpoints, 1)
	require.False(t, active.Endpoints[0].SupportsSystemPrompt)
	require.False(t, active.Endpoints[0].CyberSupplementApplied)
	require.Empty(t, active.Endpoints[0].SystemPrompt)
	public := PublicFromStorage(next, true, nil)
	require.False(t, public.Endpoints[0].SupportsSystemPrompt)
	require.False(t, public.Endpoints[0].CyberSupplementApplied)
	publicJSON, err := json.Marshal(public)
	require.NoError(t, err)
	require.NotContains(t, string(publicJSON), canary)
	require.NotContains(t, string(publicJSON), "credential_source")
	require.Contains(t, string(publicJSON), `"has_token":true`)
}

func TestContentModerationCredentialSourceRejectsMissingAmbiguousAndConflictingValues(t *testing.T) {
	for _, raw := range []string{`{}`, `{"api_keys":[]}`, `{"api_keys":["key-one","key-two"],"base_url":"https://api.openai.com","model":"omni-moderation-latest"}`, `{invalid`} {
		_, err := parseContentModerationCredentialSource(raw)
		require.Error(t, err, raw)
	}
	source, err := parseContentModerationCredentialSource(`{"api_key":"same","api_keys":["same"," same "],"base_url":"https://api.openai.com/v1","model":"omni-moderation-latest"}`)
	require.NoError(t, err)
	require.Equal(t, "same", source.credential)

	defaulted, err := parseContentModerationCredentialSource(`{"api_key":"same"}`)
	require.NoError(t, err)
	require.Equal(t, "https://api.openai.com", defaulted.baseURL)
	require.Equal(t, DefaultOpenAIModerationModel, defaulted.model)

	base := promptAuditUpdateRequest(1, 1, "")
	base.Endpoints[0].CredentialSource = CredentialSourceContentModeration
	_, err = applyEndpointCredentialSource(base, DefaultStorageConfig(), source)
	require.Error(t, err, "only the moderation adapter may import this credential")

	base.Endpoints[0].Adapter = AdapterOpenAIModeration
	base.Endpoints[0].Token = "explicit"
	_, err = applyEndpointCredentialSource(base, DefaultStorageConfig(), source)
	require.Error(t, err, "explicit token and imported token are ambiguous")
}

func TestCyberFeedbackScopeIsIndependentFromPromptAuditScope(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	accountIDs := []int64{77, 77}
	req := promptAuditUpdateRequest(1, 1, "")
	req.Enabled = false
	req.AllGroups = false
	req.GroupIDs = []int64{12}
	req.CyberFeedbackAccountIDs = &accountIDs

	next, err := manager.buildNextStorage(DefaultStorageConfig(), req, 5)
	require.NoError(t, err)
	require.Equal(t, []int64{77}, next.CyberFeedbackAccountIDs)

	active, err := ActiveFromStorage(next, false, prefixEncryptor{})
	require.NoError(t, err)
	require.Equal(t, ModeOff, active.EffectiveMode())
	require.True(t, active.IncludesCyberFeedbackSource(70, service.PlatformOpenAI, service.AccountTypeOAuth))
	require.True(t, active.IncludesCyberFeedbackSource(77, service.PlatformOpenAI, service.AccountTypeUpstream))
	require.False(t, active.IncludesCyberFeedbackSource(70, service.PlatformOpenAI, service.AccountTypeAPIKey))
	require.False(t, active.IncludesCyberFeedbackSource(70, service.PlatformOpenAI, service.AccountTypeUpstream))

	public := PublicFromStorage(next, false, nil)
	require.Equal(t, []int64{77}, public.CyberFeedbackAccountIDs)
}

func TestLegacyCyberFeedbackScopePreservesOpenAIOAuthBehavior(t *testing.T) {
	storage, err := ParseStorageConfig(`{"enabled":false,"strategy":"priority","worker_count":1,"queue_capacity":10,"scanners":["pii"],"all_groups":true,"endpoints":[]}`)
	require.NoError(t, err)
	active, err := ActiveFromStorage(storage, false, prefixEncryptor{})
	require.NoError(t, err)
	require.True(t, active.IncludesCyberFeedbackSource(91, service.PlatformOpenAI, service.AccountTypeOAuth))
	require.False(t, active.IncludesCyberFeedbackSource(92, service.PlatformOpenAI, service.AccountTypeAPIKey))
	require.False(t, active.IncludesCyberFeedbackSource(93, service.PlatformGrok, service.AccountTypeOAuth))
}

func TestBlockingLatestTurnOnlyConfigRoundTrip(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	request := UpdateConfigRequest{
		ExpectedConfigVersion: 1, Enabled: true, BlockingEnabled: true, BlockingLatestTurnOnly: true,
		Strategy: "priority", WorkerCount: 1, QueueCapacity: 10, Scanners: []string{"pii"}, AllGroups: true,
		Endpoints: []UpdateEndpoint{{
			ID: "guard-1", Name: "Guard", Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080",
			Model: DefaultGuardModel, TimeoutMS: 1000, InputLimit: 1000, Enabled: true,
		}},
	}
	next, err := manager.buildNextStorage(DefaultStorageConfig(), request, 9)
	require.NoError(t, err)
	require.True(t, next.BlockingLatestTurnOnly)
	require.Contains(t, changeSummary(next), `"blocking_latest_turn_only":true`)

	active, err := ActiveFromStorage(next, true, prefixEncryptor{})
	require.NoError(t, err)
	require.True(t, active.BlockingLatestTurnOnly)
	public := PublicFromStorage(next, true, nil)
	require.True(t, public.BlockingLatestTurnOnly)
}

func TestConfigRejectsBlockingWithoutAudit(t *testing.T) {
	storage := DefaultStorageConfig()
	storage.BlockingEnabled = true
	require.Error(t, validateStorageConfig(storage))
}

func TestPublicConfigNeverMarshalsToken(t *testing.T) {
	storage := DefaultStorageConfig()
	storage.Endpoints = []StorageEndpoint{{ID: "one", Name: "One", Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080", Model: DefaultGuardModel, TokenCiphertext: "GUARD_TOKEN_CANARY_SECRET", TimeoutMS: 1000, InputLimit: 1000, Enabled: true}}
	public := PublicFromStorage(storage, true, nil)
	raw, err := json.Marshal(public)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "GUARD_TOKEN_CANARY_SECRET")
	require.NotContains(t, string(raw), "ciphertext")
	require.True(t, public.Endpoints[0].HasToken)
}

func TestConfigRuntimeLoadErrorIsStableBoundedAndSecretFree(t *testing.T) {
	const canary = "CONFIG_LOAD_CANARY_SECRET"
	manager := &ConfigManager{clock: fixedClock{}}
	manager.recordLoadError(errors.New("decrypt failed for token " + canary + " Authorization: Bearer " + canary))
	_, _, _, message := manager.RuntimeState()
	require.Equal(t, stableErrorMessage("config_load_failed"), message)
	require.NotContains(t, message, canary)
	require.LessOrEqual(t, len([]rune(message)), 160)
}

func TestConfigManagerPublicRequiresSuccessfullyLoadedSnapshot(t *testing.T) {
	t.Run("absent persisted setting is legitimate default", func(t *testing.T) {
		manager := NewConfigManager(nil, staticSettingRepository{values: map[string]string{
			SettingKeyPromptAuditConfig: "",
			SettingKeyRiskControl:       "false",
		}}, nil, prefixEncryptor{}, testTotpKeyConfig())
		require.NoError(t, manager.Reload(context.Background()))

		public, err := manager.Public()
		require.NoError(t, err)
		require.Equal(t, int64(1), public.ConfigVersion)
		require.False(t, public.Enabled)
	})

	t.Run("unparseable persisted config is unavailable", func(t *testing.T) {
		const canary = "persisted-token-canary"
		manager := NewConfigManager(nil, staticSettingRepository{values: map[string]string{
			// Endpoint without id/name fails validation, so no trustworthy
			// snapshot can be installed from this raw value.
			SettingKeyPromptAuditConfig: `{"enabled":true,"config_version":9,"endpoints":[{"token_ciphertext":"` + canary + `"}]}`,
			SettingKeyRiskControl:       "true",
		}}, nil, prefixEncryptor{}, testTotpKeyConfig())
		require.Error(t, manager.Reload(context.Background()))

		public, err := manager.Public()
		require.Error(t, err)
		require.Empty(t, public)
		require.Equal(t, ErrorCodeConfigUnavailable, infraerrors.Reason(err))
		require.NotContains(t, err.Error(), canary)
	})

	t.Run("reload failure preserves last successfully loaded snapshot", func(t *testing.T) {
		storage := DefaultStorageConfig()
		storage.ConfigVersion = 4
		storage.ChangeSummary = "trusted snapshot"
		raw, err := json.Marshal(storage)
		require.NoError(t, err)
		repository := &switchableSettingRepository{staticSettingRepository: staticSettingRepository{values: map[string]string{
			SettingKeyPromptAuditConfig: string(raw),
			SettingKeyRiskControl:       "false",
		}}}
		manager := NewConfigManager(nil, repository, nil, prefixEncryptor{}, testTotpKeyConfig())
		require.NoError(t, manager.Reload(context.Background()))
		repository.loadErr = errors.New("settings unavailable")
		require.Error(t, manager.Reload(context.Background()))

		public, err := manager.Public()
		require.NoError(t, err)
		require.Equal(t, int64(4), public.ConfigVersion)
		require.Equal(t, "trusted snapshot", public.ChangeSummary)
	})
}

// Regression coverage for issue #4887: a persisted config whose endpoint token
// can no longer be decrypted (encryption key changed or auto-generated per
// boot) must stay visible and editable for admins instead of falling back to a
// default v1 config that makes every save fail the CAS version check.
func TestConfigManagerUndecryptableTokenKeepsConfigVisibleAndRecoverable(t *testing.T) {
	const canary = "persisted-token-canary"
	persisted := `{"enabled":true,"blocking_enabled":false,"config_version":9,"endpoints":[{"id":"g1","name":"Guard","protocol":"openai_compatible","base_url":"http://127.0.0.1:8080","model":"m","token_ciphertext":"` + canary + `","timeout_ms":1000,"input_limit":1000,"enabled":true}]}`
	manager := NewConfigManager(nil, staticSettingRepository{values: map[string]string{
		SettingKeyPromptAuditConfig: persisted,
		SettingKeyRiskControl:       "true",
	}}, nil, prefixEncryptor{}, testTotpKeyConfig())
	require.NoError(t, manager.Reload(context.Background()), "an undecryptable token must not fail the whole config load")

	public, err := manager.Public()
	require.NoError(t, err)
	require.Equal(t, int64(9), public.ConfigVersion, "admins must see the real persisted version so CAS saves can succeed")
	require.Len(t, public.Endpoints, 1)
	require.True(t, public.Endpoints[0].HasToken)
	require.Equal(t, "invalid", public.Endpoints[0].TokenStatus)
	raw, err := json.Marshal(public)
	require.NoError(t, err)
	require.NotContains(t, string(raw), canary)

	active, ok := manager.Active()
	require.True(t, ok)
	require.Len(t, active.Endpoints, 1)
	require.False(t, active.Endpoints[0].Enabled, "an endpoint with an undecryptable token must not be used at runtime")
	require.True(t, active.Endpoints[0].TokenInvalid)
	require.Empty(t, active.Endpoints[0].Token)
	require.Empty(t, active.EnabledEndpoints())
	require.Equal(t, []string{"g1"}, active.InvalidTokenEndpointIDs())

	expected, activeVersion, _, _ := manager.RuntimeState()
	require.Equal(t, int64(9), expected)
	require.Equal(t, int64(9), activeVersion)
}

func TestConfigManagerUndecryptableTokenStillFailsClosedForBlockingIntent(t *testing.T) {
	persisted := `{"enabled":true,"blocking_enabled":true,"config_version":9,"endpoints":[{"id":"g1","name":"Guard","protocol":"openai_compatible","base_url":"http://127.0.0.1:8080","model":"m","token_ciphertext":"undecryptable","timeout_ms":1000,"input_limit":1000,"enabled":true}]}`
	manager := NewConfigManager(nil, staticSettingRepository{values: map[string]string{
		SettingKeyPromptAuditConfig: persisted,
		SettingKeyRiskControl:       "true",
	}}, nil, prefixEncryptor{}, testTotpKeyConfig())
	require.NoError(t, manager.Reload(context.Background()))
	require.Equal(t, ModeBlocking, manager.EffectiveMode())

	service := &PromptService{config: manager, evaluator: NewGuardEvaluator(NewOpenAICompatibleScanner(), nil, nil)}
	decision, err := service.Evaluate(context.Background(), Request{
		Protocol: "openai_chat_completions",
		Body:     []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	})
	require.Error(t, err, "blocking intent with no usable endpoint must not let requests pass unaudited")
	require.Nil(t, decision)
	var guardErr *GuardError
	require.ErrorAs(t, err, &guardErr)
	require.Equal(t, ErrorCodeUnavailable, guardErr.Code)
}

func TestBuildNextStoragePreserveReplaceAndClearToken(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	current := DefaultStorageConfig()
	current.Endpoints = []StorageEndpoint{{ID: "one", Name: "One", Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080", Model: DefaultGuardModel, TokenCiphertext: "enc:old", TimeoutMS: 1000, InputLimit: 1000}}
	base := UpdateConfigRequest{ExpectedConfigVersion: 1, Strategy: "priority", WorkerCount: 1, QueueCapacity: 10, Scanners: []string{"PII"}, AllGroups: true,
		Endpoints: []UpdateEndpoint{{ID: "one", Name: "One", Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080", TimeoutMS: 1000, InputLimit: 1000}}}
	preserved, err := manager.buildNextStorage(current, base, 9)
	require.NoError(t, err)
	require.Equal(t, "enc:old", preserved.Endpoints[0].TokenCiphertext)
	replacedReq := base
	replacedReq.Endpoints = append([]UpdateEndpoint(nil), base.Endpoints...)
	replacedReq.Endpoints[0].Token = "new"
	replaced, err := manager.buildNextStorage(current, replacedReq, 9)
	require.NoError(t, err)
	require.Equal(t, "enc:new", replaced.Endpoints[0].TokenCiphertext)
	clearedReq := base
	clearedReq.Endpoints = append([]UpdateEndpoint(nil), base.Endpoints...)
	clearedReq.Endpoints[0].ClearToken = true
	cleared, err := manager.buildNextStorage(current, clearedReq, 9)
	require.NoError(t, err)
	require.Empty(t, cleared.Endpoints[0].TokenCiphertext)
}

// Without a fixed encryption key the per-boot auto-generated key would make a
// freshly saved token undecryptable after the next restart (issue #4887), so
// saving a new token must be rejected with an actionable error. Preserving or
// clearing an existing ciphertext stays allowed so admins can still edit or
// disable the feature.
func TestBuildNextStorageRejectsNewTokenWithoutConfiguredEncryptionKey(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: false}
	current := DefaultStorageConfig()
	current.Endpoints = []StorageEndpoint{{ID: "one", Name: "One", Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080", Model: DefaultGuardModel, TokenCiphertext: "enc:old", TimeoutMS: 1000, InputLimit: 1000}}
	base := UpdateConfigRequest{ExpectedConfigVersion: 1, Strategy: "priority", WorkerCount: 1, QueueCapacity: 10, Scanners: []string{"PII"}, AllGroups: true,
		Endpoints: []UpdateEndpoint{{ID: "one", Name: "One", Protocol: "openai_compatible", BaseURL: "http://127.0.0.1:8080", TimeoutMS: 1000, InputLimit: 1000}}}

	newTokenReq := base
	newTokenReq.Endpoints = append([]UpdateEndpoint(nil), base.Endpoints...)
	newTokenReq.Endpoints[0].Token = "fresh-token"
	_, err := manager.buildNextStorage(current, newTokenReq, 9)
	require.Error(t, err)
	require.Equal(t, ErrorCodeEncryptionKeyRequired, infraerrors.Reason(err))

	preserved, err := manager.buildNextStorage(current, base, 9)
	require.NoError(t, err)
	require.Equal(t, "enc:old", preserved.Endpoints[0].TokenCiphertext)

	clearedReq := base
	clearedReq.Endpoints = append([]UpdateEndpoint(nil), base.Endpoints...)
	clearedReq.Endpoints[0].ClearToken = true
	cleared, err := manager.buildNextStorage(current, clearedReq, 9)
	require.NoError(t, err)
	require.Empty(t, cleared.Endpoints[0].TokenCiphertext)
}

func TestEffectiveModeTruthTable(t *testing.T) {
	tests := []struct {
		risk, enabled, blocking bool
		want                    Mode
	}{
		{false, false, false, ModeOff}, {false, true, true, ModeOff}, {true, false, false, ModeOff},
		{true, true, false, ModeAsync}, {true, true, true, ModeBlocking},
	}
	for _, tt := range tests {
		cfg := ActiveConfig{RiskControlEnabled: tt.risk, Enabled: tt.enabled, BlockingEnabled: tt.blocking}
		require.Equal(t, tt.want, cfg.EffectiveMode())
	}
}

func TestConfigManagerColdStartOnlyFailsClosedForExplicitBlockingIntent(t *testing.T) {
	manager := &ConfigManager{}

	manager.observeExpectedState(`{"enabled":true,"blocking_enabled":false,"config_version":42}`, true)
	require.Equal(t, int64(42), manager.expected.Load())
	require.Equal(t, ModeOff, manager.EffectiveMode(), "an async config version must not imply blocking")
	require.False(t, manager.BlockingActivationDegraded())

	manager.observeExpectedState(`{"enabled":true,"blocking_enabled":true,"config_version":43}`, false)
	require.Equal(t, ModeOff, manager.EffectiveMode(), "the global risk-control switch still gates blocking")

	manager.observeExpectedState(`{"enabled":true,"blocking_enabled":true,"config_version":44}`, true)
	require.Equal(t, ModeBlocking, manager.EffectiveMode())
	require.True(t, manager.BlockingActivationDegraded())

	manager.observeExpectedState(`{"enabled":true`, true)
	require.Equal(t, ModeBlocking, manager.EffectiveMode(), "undecodable storage must not erase the last known strict intent")
}

func TestConfigManagerExpectedBlockingNormalizesPartialGroupPolicyIntent(t *testing.T) {
	manager := &ConfigManager{}
	// A reload can observe the raw JSON before the full config is decoded. A
	// partial group entry inherits the top-level blocking flag and must keep the
	// fail-closed guard armed while activation is being retried.
	manager.observeExpectedState(`{"enabled":true,"blocking_enabled":true,"all_groups":false,"group_ids":[7],"group_policies":[{"group_id":7}],"config_version":45}`, true)
	require.True(t, manager.expectedBlocking.Load())
	require.True(t, manager.BlockingActivationDegraded())
	require.Equal(t, ModeBlocking, manager.EffectiveMode())
}

func TestEffectiveGroupPoliciesCanMixBlockingAndAsyncModes(t *testing.T) {
	groupBlocking := int64(7)
	groupAsync := int64(8)
	cfg := ActiveConfig{
		RiskControlEnabled: true,
		Enabled:            true,
		BlockingEnabled:    false,
		AllGroups:          false,
		GroupPolicies: []GroupPolicy{
			{GroupID: groupBlocking, Enabled: true, BlockingEnabled: true},
			{GroupID: groupAsync, Enabled: true, BlockingEnabled: false},
		},
	}
	require.True(t, cfg.RequiresBlockingActivation())
	require.Equal(t, ModeBlocking, cfg.EffectiveForGroup(&groupBlocking).EffectiveMode())
	require.Equal(t, ModeAsync, cfg.EffectiveForGroup(&groupAsync).EffectiveMode())
}

func TestConfigManagerStaleWeakerSnapshotFailsClosedWhenBlockingExpected(t *testing.T) {
	manager := &ConfigManager{}
	async := ActiveConfig{RiskControlEnabled: true, Enabled: true, BlockingEnabled: false, ConfigVersion: 1}
	manager.snapshot.Store(&activeConfigSnapshot{active: async, storage: DefaultStorageConfig(), loadedAt: fixedClock{}.Now()})
	manager.expected.Store(2)
	manager.expectedBlocking.Store(true)

	require.True(t, manager.BlockingActivationDegraded())
	require.Equal(t, ModeBlocking, manager.EffectiveMode())

	service := &PromptService{config: manager, evaluator: NewGuardEvaluator(nil, nil, nil)}
	decision, err := service.Evaluate(context.Background(), Request{Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"user","content":"hi"}]}`)})
	require.Error(t, err)
	require.Nil(t, decision)
	var guardErr *GuardError
	require.ErrorAs(t, err, &guardErr)
	require.Equal(t, ErrorCodeUnavailable, guardErr.Code)
}

type errorSettingRepository struct{ staticSettingRepository }

func (errorSettingRepository) GetMultiple(context.Context, []string) (map[string]string, error) {
	return nil, errors.New("settings unavailable")
}

type switchableSettingRepository struct {
	staticSettingRepository
	loadErr error
}

func (r *switchableSettingRepository) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	if r.loadErr != nil {
		return nil, r.loadErr
	}
	return r.staticSettingRepository.GetMultiple(ctx, keys)
}

func TestConfigManagerStartupLoadFailureDoesNotBlockWhenBlockingNotIntended(t *testing.T) {
	// Settings unavailable and no prior blocking intent: stay ModeOff so the
	// gateway remains usable and admins can still disable/configure Prompt Audit.
	manager := NewConfigManager(nil, errorSettingRepository{}, nil, prefixEncryptor{}, testTotpKeyConfig())
	err := manager.Start(context.Background())
	require.Error(t, err)
	require.True(t, manager.configUntrusted.Load())
	require.False(t, manager.BlockingActivationDegraded())
	require.Equal(t, ModeOff, manager.EffectiveMode())

	service := &PromptService{config: manager, evaluator: NewGuardEvaluator(nil, nil, nil)}
	decision, evalErr := service.Evaluate(context.Background(), Request{
		Protocol: "openai_chat_completions",
		Body:     []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	})
	require.NoError(t, evalErr)
	require.NotNil(t, decision)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.NoError(t, manager.Shutdown(context.Background()))
}

func TestConfigManagerStartupLoadFailureFailsClosedWhenBlockingIntended(t *testing.T) {
	manager := NewConfigManager(nil, errorSettingRepository{}, nil, prefixEncryptor{}, testTotpKeyConfig())
	// Simulate intent observed before a later load failure (e.g. decrypt error).
	manager.observeExpectedState(`{"enabled":true,"blocking_enabled":true,"config_version":3}`, true)
	manager.markConfigUntrusted()
	require.True(t, manager.BlockingActivationDegraded())
	require.Equal(t, ModeBlocking, manager.EffectiveMode())

	service := &PromptService{config: manager, evaluator: NewGuardEvaluator(nil, nil, nil)}
	decision, err := service.Evaluate(context.Background(), Request{
		Protocol: "openai_chat_completions",
		Body:     []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	})
	require.Error(t, err)
	require.Nil(t, decision)
	var guardErr *GuardError
	require.ErrorAs(t, err, &guardErr)
	require.Equal(t, ErrorCodeUnavailable, guardErr.Code)
}

func TestConfigManagerUntrustedClearsOnSuccessfulDisable(t *testing.T) {
	// After a degraded fail-closed period, saving disabled config must restore ModeOff.
	manager := &ConfigManager{encryptor: prefixEncryptor{}, clock: fixedClock{}}
	manager.observeExpectedState(`{"enabled":true,"blocking_enabled":true,"config_version":5}`, true)
	manager.markConfigUntrusted()
	require.Equal(t, ModeBlocking, manager.EffectiveMode())

	// Install a trusted disabled snapshot the same way Save does after commit.
	disabled := DefaultStorageConfig()
	disabled.ConfigVersion = 6
	disabled.Enabled = false
	disabled.BlockingEnabled = false
	active, err := ActiveFromStorage(disabled, true, manager.encryptor)
	require.NoError(t, err)
	manager.expected.Store(disabled.ConfigVersion)
	manager.expectedBlocking.Store(false)
	manager.snapshot.Store(&activeConfigSnapshot{storage: disabled, active: active, loadedAt: manager.clock.Now()})
	manager.configUntrusted.Store(false)

	require.False(t, manager.BlockingActivationDegraded())
	require.Equal(t, ModeOff, manager.EffectiveMode())

	service := &PromptService{config: manager, evaluator: NewGuardEvaluator(nil, nil, nil)}
	decision, evalErr := service.Evaluate(context.Background(), Request{
		Protocol: "openai_chat_completions",
		Body:     []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	})
	require.NoError(t, evalErr)
	require.Equal(t, DecisionAllow, decision.Kind)
}

func TestConfigManagerUntrustedWithoutBlockingDoesNotForceBlockingMode(t *testing.T) {
	manager := &ConfigManager{}
	manager.observeExpectedState(`{"enabled":true,"blocking_enabled":false,"config_version":2}`, true)
	manager.markConfigUntrusted()
	require.False(t, manager.expectedBlocking.Load())
	require.False(t, manager.BlockingActivationDegraded())
	require.Equal(t, ModeOff, manager.EffectiveMode(), "async intent + untrusted must not force blocking unavailable")
}

func TestParseLegacyConfigDefaultsMissingFieldsWithoutEnablingBlocking(t *testing.T) {
	storage, err := ParseStorageConfig(`{"enabled":false,"config_version":9}`)
	require.NoError(t, err)
	require.False(t, storage.BlockingEnabled)
	require.Equal(t, "priority", storage.Strategy)
	require.Equal(t, DefaultWorkerCount, storage.WorkerCount)
	require.Equal(t, DefaultQueueCapacity, storage.QueueCapacity)
	require.Equal(t, AllScannerIDs, storage.Scanners)
	require.True(t, storage.AllGroups)
}

func TestUpdateConfigStrictBoundsAndKnownValues(t *testing.T) {
	valid := promptAuditUpdateRequest(1, 1, "")
	require.NoError(t, validateUpdateConfigRequest(valid))

	tests := []struct {
		name   string
		mutate func(*UpdateConfigRequest)
		reason string
	}{
		{name: "strategy", mutate: func(req *UpdateConfigRequest) { req.Strategy = "round_robin" }, reason: "prompt_audit_invalid_strategy"},
		{name: "worker low", mutate: func(req *UpdateConfigRequest) { req.WorkerCount = 0 }, reason: "prompt_audit_invalid_worker_count"},
		{name: "worker high", mutate: func(req *UpdateConfigRequest) { req.WorkerCount = MaxWorkerCount + 1 }, reason: "prompt_audit_invalid_worker_count"},
		{name: "capacity low", mutate: func(req *UpdateConfigRequest) { req.QueueCapacity = 0 }, reason: "prompt_audit_invalid_queue_capacity"},
		{name: "capacity high", mutate: func(req *UpdateConfigRequest) { req.QueueCapacity = MaxQueueCapacity + 1 }, reason: "prompt_audit_invalid_queue_capacity"},
		{name: "unknown scanner", mutate: func(req *UpdateConfigRequest) { req.Scanners = []string{"made_up"} }, reason: "prompt_audit_invalid_scanner"},
		{name: "group required", mutate: func(req *UpdateConfigRequest) { req.AllGroups = false; req.GroupIDs = nil }, reason: "prompt_audit_groups_required"},
		{name: "group positive", mutate: func(req *UpdateConfigRequest) { req.AllGroups = false; req.GroupIDs = []int64{0} }, reason: "prompt_audit_invalid_group"},
		{name: "route account positive", mutate: func(req *UpdateConfigRequest) { values := []int64{0}; req.RiskRouteAccountIDs = &values }, reason: "prompt_audit_invalid_risk_route_account"},
		{name: "total input low", mutate: func(req *UpdateConfigRequest) { value := MinMaxTotalInputChars - 1; req.MaxTotalInputChars = &value }, reason: "prompt_audit_invalid_max_total_input_chars"},
		{name: "total input high", mutate: func(req *UpdateConfigRequest) { value := MaxMaxTotalInputChars + 1; req.MaxTotalInputChars = &value }, reason: "prompt_audit_invalid_max_total_input_chars"},
		{name: "timeout low", mutate: func(req *UpdateConfigRequest) { req.Endpoints[0].TimeoutMS = MinTimeoutMS - 1 }, reason: "prompt_audit_invalid_timeout"},
		{name: "timeout high", mutate: func(req *UpdateConfigRequest) { req.Endpoints[0].TimeoutMS = MaxTimeoutMS + 1 }, reason: "prompt_audit_invalid_timeout"},
		{name: "input low", mutate: func(req *UpdateConfigRequest) { req.Endpoints[0].InputLimit = MinInputLimit - 1 }, reason: "prompt_audit_invalid_input_limit"},
		{name: "input high", mutate: func(req *UpdateConfigRequest) { req.Endpoints[0].InputLimit = MaxInputLimit + 1 }, reason: "prompt_audit_invalid_input_limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := valid
			req.Scanners = append([]string(nil), valid.Scanners...)
			req.GroupIDs = append([]int64(nil), valid.GroupIDs...)
			req.Endpoints = append([]UpdateEndpoint(nil), valid.Endpoints...)
			tt.mutate(&req)
			err := validateUpdateConfigRequest(req)
			require.Error(t, err)
			require.Equal(t, tt.reason, infraerrors.Reason(err))
		})
	}
}

func TestUpdateConfigAcceptsMaximumEndpointLimits(t *testing.T) {
	req := promptAuditUpdateRequest(1, 1, "")
	req.Endpoints[0].TimeoutMS = 40000
	req.Endpoints[0].InputLimit = 400000

	require.Equal(t, 40000, MaxTimeoutMS)
	require.Equal(t, 400000, MaxInputLimit)
	require.NoError(t, validateUpdateConfigRequest(req))
}

// Regression coverage for issue #5732: refreshLoop reloads every 5s, so
// config_loaded must stay a change signal instead of ~17k identical lines a
// day, while still reporting the first load, real config changes and a
// recovery from a failed reload.
func TestConfigLoadedIsLoggedOnlyWhenSomethingChanged(t *testing.T) {
	storage := DefaultStorageConfig()
	storage.ConfigVersion = 4
	raw, err := json.Marshal(storage)
	require.NoError(t, err)
	repository := &switchableSettingRepository{staticSettingRepository: staticSettingRepository{values: map[string]string{
		SettingKeyPromptAuditConfig: string(raw),
		SettingKeyRiskControl:       "false",
	}}}
	manager := NewConfigManager(nil, repository, nil, prefixEncryptor{}, testTotpKeyConfig())

	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	loadedCount := func() int { return strings.Count(output.String(), EventConfigLoaded) }

	require.NoError(t, manager.Reload(context.Background()))
	require.Equal(t, 1, loadedCount(), "the first successful load must be logged")

	require.NoError(t, manager.Reload(context.Background()))
	require.NoError(t, manager.Reload(context.Background()))
	require.Equal(t, 1, loadedCount(), "TTL refreshes of an unchanged config must stay silent")

	repository.values[SettingKeyRiskControl] = "true"
	require.NoError(t, manager.Reload(context.Background()))
	require.Equal(t, 2, loadedCount(), "flipping the global risk control gate must be logged")

	storage.ConfigVersion = 5
	raw, err = json.Marshal(storage)
	require.NoError(t, err)
	repository.values[SettingKeyPromptAuditConfig] = string(raw)
	require.NoError(t, manager.Reload(context.Background()))
	require.Equal(t, 3, loadedCount(), "a new config version must be logged")

	repository.loadErr = errors.New("settings unavailable")
	require.Error(t, manager.Reload(context.Background()))
	require.Equal(t, 3, loadedCount(), "a failed reload must not claim a load")

	repository.loadErr = nil
	require.NoError(t, manager.Reload(context.Background()))
	require.Equal(t, 4, loadedCount(), "recovering from a failed reload must be visible")
}

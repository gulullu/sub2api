package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

const (
	defaultEndpointCircuitCapacity = 2048
	transientCircuitCooldown       = 5 * time.Second
	rateLimitCircuitCooldown       = 10 * time.Second
	configurationCircuitCooldown   = 30 * time.Second
	authPaymentCircuitCooldown     = time.Minute
)

type endpointCircuitPermit struct {
	key        string
	generation uint64
	owner      uint64
	halfOpen   bool
}

type endpointCircuitState struct {
	generation    uint64
	openUntil     time.Time
	halfOpenOwner uint64
	permits       map[uint64]uint64
}

// Every admitted call owns a generation-scoped permit. Completion from an
// older generation may release only its own permit; it cannot close, reopen,
// or release a newer half-open probe.
type endpointCircuitBreaker struct {
	mu         sync.Mutex
	states     map[string]*endpointCircuitState
	maxEntries int
	nextOwner  uint64
}

func newEndpointCircuitBreaker(maxEntries int) *endpointCircuitBreaker {
	if maxEntries < 1 {
		maxEntries = defaultEndpointCircuitCapacity
	}
	return &endpointCircuitBreaker{states: make(map[string]*endpointCircuitState), maxEntries: maxEntries}
}

func (b *endpointCircuitBreaker) allow(key string, now time.Time) (permit endpointCircuitPermit, allowed bool, state string, remaining time.Duration) {
	if b == nil || key == "" {
		return endpointCircuitPermit{}, true, "closed", 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	current := b.states[key]
	if current == nil {
		b.ensureCapacityLocked()
		current = &endpointCircuitState{generation: 1, permits: make(map[uint64]uint64)}
		b.states[key] = current
	}
	if now.Before(current.openUntil) {
		return endpointCircuitPermit{}, false, "open", current.openUntil.Sub(now)
	}
	if !current.openUntil.IsZero() {
		if current.halfOpenOwner != 0 || current.hasCurrentGenerationPermit() {
			return endpointCircuitPermit{}, false, "half_open_busy", 0
		}
		owner := b.nextOwnerLocked()
		current.halfOpenOwner = owner
		current.permits[owner] = current.generation
		return endpointCircuitPermit{key: key, generation: current.generation, owner: owner, halfOpen: true}, true, "half_open", 0
	}
	owner := b.nextOwnerLocked()
	current.permits[owner] = current.generation
	return endpointCircuitPermit{key: key, generation: current.generation, owner: owner}, true, "closed", 0
}

func (s *endpointCircuitState) hasCurrentGenerationPermit() bool {
	if s == nil {
		return false
	}
	for _, generation := range s.permits {
		if generation == s.generation {
			return true
		}
	}
	return false
}

func (b *endpointCircuitBreaker) fail(permit endpointCircuitPermit, now time.Time, cooldown time.Duration) bool {
	if b == nil || permit.key == "" || permit.owner == 0 {
		return false
	}
	if cooldown <= 0 {
		cooldown = transientCircuitCooldown
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	current := b.states[permit.key]
	if current == nil || current.permits[permit.owner] != permit.generation {
		return false
	}
	delete(current.permits, permit.owner)
	if current.halfOpenOwner == permit.owner {
		current.halfOpenOwner = 0
	}
	if current.generation != permit.generation {
		b.cleanupClosedLocked(permit.key, current)
		return false
	}
	current.generation++
	current.openUntil = now.Add(cooldown)
	current.halfOpenOwner = 0
	return true
}

func (b *endpointCircuitBreaker) succeed(permit endpointCircuitPermit) bool {
	if b == nil || permit.key == "" || permit.owner == 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	current := b.states[permit.key]
	if current == nil || current.permits[permit.owner] != permit.generation {
		return false
	}
	delete(current.permits, permit.owner)
	recovered := permit.halfOpen && current.generation == permit.generation && current.halfOpenOwner == permit.owner
	if current.halfOpenOwner == permit.owner {
		current.halfOpenOwner = 0
	}
	if recovered {
		current.generation++
		current.openUntil = time.Time{}
	}
	b.cleanupClosedLocked(permit.key, current)
	return recovered
}

// release is for caller cancellation or local bulkhead pressure, neither of
// which is an endpoint-health signal.
func (b *endpointCircuitBreaker) release(permit endpointCircuitPermit) {
	if b == nil || permit.key == "" || permit.owner == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	current := b.states[permit.key]
	if current == nil || current.permits[permit.owner] != permit.generation {
		return
	}
	delete(current.permits, permit.owner)
	if current.halfOpenOwner == permit.owner {
		current.halfOpenOwner = 0
	}
	b.cleanupClosedLocked(permit.key, current)
}

// reset is used only after an exact-identity successful probe. Generation
// bumping makes all older in-flight completions harmless.
func (b *endpointCircuitBreaker) reset(key string, _ time.Time) bool {
	if b == nil || key == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	current := b.states[key]
	if current == nil {
		return false
	}
	current.generation++
	current.openUntil = time.Time{}
	current.halfOpenOwner = 0
	b.cleanupClosedLocked(key, current)
	return true
}

func (b *endpointCircuitBreaker) cleanupClosedLocked(key string, current *endpointCircuitState) {
	if current != nil && current.openUntil.IsZero() && current.halfOpenOwner == 0 && len(current.permits) == 0 {
		delete(b.states, key)
	}
}

func (b *endpointCircuitBreaker) nextOwnerLocked() uint64 {
	b.nextOwner++
	if b.nextOwner == 0 {
		b.nextOwner++
	}
	return b.nextOwner
}

// Capacity is soft while every candidate still carries circuit semantics.
// In practice closed/quiescent states are removed eagerly, so both cooling
// and expired-but-unprobed open states must remain: evicting the latter would
// bypass the single half-open probe and create a recovery thundering herd.
func (b *endpointCircuitBreaker) ensureCapacityLocked() {
	if len(b.states) < b.maxEntries {
		return
	}
	for key, current := range b.states {
		if current.openUntil.IsZero() && len(current.permits) == 0 && current.halfOpenOwner == 0 {
			delete(b.states, key)
			return
		}
	}
}

func endpointCircuitKey(configVersion int64, endpoint ActiveEndpoint) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(strconv.FormatInt(configVersion, 10)))
	for _, value := range []string{
		endpoint.ID, endpoint.Name, strconv.Itoa(endpoint.Priority), endpoint.Protocol,
		endpoint.Adapter, endpoint.BaseURL, endpoint.Model, strconv.Itoa(endpoint.TimeoutMS),
		strconv.Itoa(endpoint.InputLimit), endpoint.PromptTemplateID, endpoint.SystemPrompt,
		fmt.Sprintf("%.12g", endpoint.FlagThreshold), fmt.Sprintf("%.12g", endpoint.BlockThreshold),
	} {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(value))
	}
	tokenDigest := sha256.Sum256([]byte(endpoint.Token))
	_, _ = digest.Write(tokenDigest[:])
	return hex.EncodeToString(digest.Sum(nil))
}

// Invalid output and ordinary 4xx responses stay local to a request.
// Auth/payment/permission (401/402/403), 404, 429, 5xx, transport, and timeout
// open the shared health circuit.
func endpointFailurePolicy(err error) (class string, cooldown time.Duration, openCircuit bool) {
	var guardErr *GuardError
	if errors.As(err, &guardErr) {
		switch guardErr.HTTPStatus {
		case 401, 402, 403:
			return "auth_payment", authPaymentCircuitCooldown, true
		case 404:
			return "configuration", configurationCircuitCooldown, true
		case 429:
			return "rate_limit", rateLimitCircuitCooldown, true
		}
		if guardErr.HTTPStatus >= 400 && guardErr.HTTPStatus < 500 {
			return "http_client", 0, false
		}
		if guardErr.HTTPStatus >= 500 {
			return "http_upstream", transientCircuitCooldown, true
		}
		if guardErr.Timeout {
			return "timeout", transientCircuitCooldown, true
		}
		if guardErr.Code == ErrorCodeInvalidResponse {
			return "invalid_response", 0, false
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", transientCircuitCooldown, true
	}
	return "transport", transientCircuitCooldown, true
}

func safeGuardErrorFields(err error) map[string]any {
	fields := map[string]any{"error_code": guardErrorCode(err)}
	var guardErr *GuardError
	if errors.As(err, &guardErr) {
		fields["http_status"] = guardErr.HTTPStatus
		fields["retryable"] = guardErr.Retryable
	}
	return fields
}

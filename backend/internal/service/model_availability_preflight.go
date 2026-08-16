package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	modelAvailabilityPreflightTTL            = 5 * time.Second
	modelAvailabilityPreflightMaxEntries     = 1024
	modelAvailabilityPreflightMaxModelBytes  = 512
	modelAvailabilityPreflightLoadTimeout    = 500 * time.Millisecond
	modelAvailabilityPreflightLoadWindow     = time.Second
	modelAvailabilityPreflightLoadsPerWindow = 64
	modelAvailabilityPreflightMaxInFlight    = 16
)

// ModelAvailabilityPreflighter is implemented by both gateway schedulers.
// It is intentionally separate from ModelAvailabilityDiagnoser: preflight is
// a bounded, short-lived, fail-open optimization on the request hot path,
// while DiagnoseModelAvailabilityForPlatform remains an authoritative fresh
// lookup used after account selection fails.
type ModelAvailabilityPreflighter interface {
	PreflightModelAvailabilityForPlatform(
		ctx context.Context,
		groupID *int64,
		requestedModel string,
		platform string,
	) ModelAvailabilityDiagnosis
}

type modelAvailabilityPreflightKey struct {
	hasGroup       bool
	groupID        int64
	includeGrouped bool
	model          string
	platform       string
	variant        string
}

type modelAvailabilityPreflightEntry struct {
	diagnosis ModelAvailabilityDiagnosis
	expiresAt time.Time
}

type modelAvailabilityPreflightCall struct {
	done      chan struct{}
	diagnosis ModelAvailabilityDiagnosis
	valid     bool
}

// modelAvailabilityPreflightCache bounds both retained client-controlled keys
// and concurrent repository work. The inflight map is a keyed promise rather
// than singleflight: only the loader owns an in-flight slot, and that slot is
// released only after the repository call actually finishes. A canceled
// waiter therefore cannot accidentally admit another loader while an
// ignore-context repository implementation is still blocked.
type modelAvailabilityPreflightCache struct {
	mu              sync.Mutex
	entries         map[modelAvailabilityPreflightKey]modelAvailabilityPreflightEntry
	inflight        map[modelAvailabilityPreflightKey]*modelAvailabilityPreflightCall
	loadSlots       chan struct{}
	loadWindowStart time.Time
	loadsInWindow   int
}

func newModelAvailabilityPreflightCache() *modelAvailabilityPreflightCache {
	return &modelAvailabilityPreflightCache{
		entries:   make(map[modelAvailabilityPreflightKey]modelAvailabilityPreflightEntry),
		inflight:  make(map[modelAvailabilityPreflightKey]*modelAvailabilityPreflightCall),
		loadSlots: make(chan struct{}, modelAvailabilityPreflightMaxInFlight),
	}
}

func modelAvailabilitySafeDiagnosis() ModelAvailabilityDiagnosis {
	return ModelAvailabilityDiagnosis{HasAccountsInPool: true, HasModelSupport: true}
}

func modelAvailabilityPreflightKeyFor(
	groupID *int64,
	includeGrouped bool,
	requestedModel string,
	platform string,
) modelAvailabilityPreflightKey {
	key := modelAvailabilityPreflightKey{
		includeGrouped: includeGrouped,
		model:          requestedModel,
		platform:       platform,
	}
	if groupID != nil {
		key.hasGroup = true
		key.groupID = *groupID
	}
	return key
}

func (c *modelAvailabilityPreflightCache) diagnose(
	ctx context.Context,
	key modelAvailabilityPreflightKey,
	loader func(context.Context) (ModelAvailabilityDiagnosis, error),
) ModelAvailabilityDiagnosis {
	if c == nil || loader == nil || strings.TrimSpace(key.model) == "" || len(key.model) > modelAvailabilityPreflightMaxModelBytes {
		return modelAvailabilitySafeDiagnosis()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return modelAvailabilitySafeDiagnosis()
	}

	now := time.Now()
	c.mu.Lock()
	if diagnosis, ok := c.getLocked(key, now); ok {
		c.mu.Unlock()
		return diagnosis
	}
	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		return waitForModelAvailabilityPreflight(ctx, call)
	}

	select {
	case c.loadSlots <- struct{}{}:
		// The loader owns this token until it actually completes. Waiters never
		// own or release loader capacity.
	default:
		c.mu.Unlock()
		return modelAvailabilitySafeDiagnosis()
	}
	if !c.allowLoadLocked(now) {
		<-c.loadSlots
		c.mu.Unlock()
		return modelAvailabilitySafeDiagnosis()
	}

	call := &modelAvailabilityPreflightCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	go c.runLoader(ctx, key, call, loader)
	return waitForModelAvailabilityPreflight(ctx, call)
}

func (c *modelAvailabilityPreflightCache) getLocked(
	key modelAvailabilityPreflightKey,
	now time.Time,
) (ModelAvailabilityDiagnosis, bool) {
	entry, ok := c.entries[key]
	if !ok {
		return ModelAvailabilityDiagnosis{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(c.entries, key)
		return ModelAvailabilityDiagnosis{}, false
	}
	return entry.diagnosis, true
}

func (c *modelAvailabilityPreflightCache) allowLoadLocked(now time.Time) bool {
	if c.loadWindowStart.IsZero() || now.Sub(c.loadWindowStart) >= modelAvailabilityPreflightLoadWindow {
		c.loadWindowStart = now
		c.loadsInWindow = 0
	}
	if c.loadsInWindow >= modelAvailabilityPreflightLoadsPerWindow {
		return false
	}
	c.loadsInWindow++
	return true
}

func (c *modelAvailabilityPreflightCache) runLoader(
	callerCtx context.Context,
	key modelAvailabilityPreflightKey,
	call *modelAvailabilityPreflightCall,
	loader func(context.Context) (ModelAvailabilityDiagnosis, error),
) {
	// Preserve request-scoped routing values, but never let the first caller's
	// disconnect cancel a shared load needed by healthy waiters. The dedicated
	// short deadline prevents preflight from consuming the prompt-audit budget.
	var diagnosis ModelAvailabilityDiagnosis
	var err error
	func() {
		defer func() {
			if recover() != nil {
				err = errors.New("model availability preflight loader panic")
			}
		}()
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(callerCtx), modelAvailabilityPreflightLoadTimeout)
		defer cancel()
		diagnosis, err = loader(loadCtx)
	}()

	c.mu.Lock()
	call.valid = err == nil
	if call.valid {
		call.diagnosis = diagnosis
		// An empty persistent pool is inconclusive and can change while an
		// operator is provisioning accounts, so do not retain it.
		if diagnosis.HasAccountsInPool {
			if _, exists := c.entries[key]; !exists && len(c.entries) >= modelAvailabilityPreflightMaxEntries {
				// A bounded wholesale reset avoids an attacker-controlled O(n)
				// oldest-entry scan on every unique-model insertion.
				clear(c.entries)
			}
			c.entries[key] = modelAvailabilityPreflightEntry{
				diagnosis: diagnosis,
				expiresAt: time.Now().Add(modelAvailabilityPreflightTTL),
			}
		}
	}
	delete(c.inflight, key)
	close(call.done)
	<-c.loadSlots
	c.mu.Unlock()
}

func waitForModelAvailabilityPreflight(
	ctx context.Context,
	call *modelAvailabilityPreflightCall,
) ModelAvailabilityDiagnosis {
	select {
	case <-ctx.Done():
		return modelAvailabilitySafeDiagnosis()
	case <-call.done:
		if !call.valid {
			return modelAvailabilitySafeDiagnosis()
		}
		return call.diagnosis
	}
}

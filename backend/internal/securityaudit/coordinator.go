package securityaudit

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

type LegacyEngine interface {
	Check(ctx context.Context, req Request) (*LegacyDecision, error)
}

type PromptEngine interface {
	EffectiveMode() Mode
	Enqueue(ctx context.Context, req Request) error
	Evaluate(ctx context.Context, req Request) (*PromptDecision, error)
}

// PromptModeResolver is optional so existing PromptEngine implementations and
// test doubles remain source-compatible. Implementations that support
// per-group policies return the mode for this request's group; the coordinator
// falls back to the historical global EffectiveMode otherwise.
type PromptModeResolver interface {
	ModeForRequest(req Request) Mode
}

type ProbeGovernanceEngine interface {
	ProbeGovernanceEnabled(context.Context, Request) bool
	GovernProbe(context.Context, Request) ProbeGovernanceResult
	GovernConfirmedProbe(context.Context, Request) ProbeGovernanceResult
	FinalizeProbeForward(*ProbeForwardClaim, bool, bool)
	ReleaseProbeForwardClaim(*ProbeForwardClaim)
	RejectProbeForwardClaim(*ProbeForwardClaim, string) *ProbeLocalResponse
}

func (c *Coordinator) ProbeGovernanceEnabled(ctx context.Context, req Request) bool {
	if c == nil || c.prompt == nil {
		return false
	}
	governor, ok := c.prompt.(ProbeGovernanceEngine)
	return ok && governor.ProbeGovernanceEnabled(ctx, req)
}

type Coordinator struct {
	legacy LegacyEngine
	prompt PromptEngine
}

func NewCoordinator(legacy LegacyEngine, prompt PromptEngine) *Coordinator {
	return &Coordinator{legacy: legacy, prompt: prompt}
}

func (c *Coordinator) GovernProbe(ctx context.Context, req Request) ProbeGovernanceResult {
	if c == nil || c.prompt == nil {
		return ProbeGovernanceResult{}
	}
	governor, ok := c.prompt.(ProbeGovernanceEngine)
	if !ok {
		return ProbeGovernanceResult{}
	}
	return c.mergeProbeAuditDecision(ctx, req, governor, governor.GovernProbe(ctx, req))
}

func (c *Coordinator) mergeProbeAuditDecision(ctx context.Context, req Request, governor ProbeGovernanceEngine, result ProbeGovernanceResult) ProbeGovernanceResult {
	if result.Claim == nil || result.PromptDecision == nil {
		return result
	}
	legacy, _ := c.checkLegacy(ctx, req)
	decision := prioritize(legacy, result.PromptDecision)
	result.AuditDecision = &decision
	if !decision.AllowNextStage {
		result.Local = governor.RejectProbeForwardClaim(result.Claim, "legacy_policy_block")
		result.Claim = nil
		result.AuditDecision = nil
	}
	return result
}

func (c *Coordinator) GovernConfirmedProbe(ctx context.Context, req Request) ProbeGovernanceResult {
	if c == nil || c.prompt == nil {
		return ProbeGovernanceResult{}
	}
	governor, ok := c.prompt.(ProbeGovernanceEngine)
	if !ok {
		return ProbeGovernanceResult{}
	}
	return governor.GovernConfirmedProbe(ctx, req)
}

func (c *Coordinator) FinalizeProbeForward(claim *ProbeForwardClaim, upstreamAttempted, upstreamSucceeded bool) {
	if c == nil || c.prompt == nil || claim == nil {
		return
	}
	if governor, ok := c.prompt.(ProbeGovernanceEngine); ok {
		governor.FinalizeProbeForward(claim, upstreamAttempted, upstreamSucceeded)
	}
}

func (c *Coordinator) Check(ctx context.Context, req Request) Decision {
	if c == nil {
		return allowDecision(nil, nil)
	}
	mode := ModeOff
	if c.prompt != nil {
		mode = c.prompt.EffectiveMode()
		if resolver, ok := c.prompt.(PromptModeResolver); ok {
			mode = resolver.ModeForRequest(req)
		}
	}
	switch mode {
	case ModeAsync:
		// Enqueue is deliberately best-effort. The implementation owns a bounded
		// context and copies request memory before it can outlive the Handler.
		_ = c.prompt.Enqueue(ctx, req.Clone())
		legacy, _ := c.checkLegacy(ctx, req)
		return prioritize(legacy, nil)
	case ModeBlocking:
		return c.checkBlocking(ctx, req)
	default:
		legacy, _ := c.checkLegacy(ctx, req)
		return prioritize(legacy, nil)
	}
}

func (c *Coordinator) checkBlocking(ctx context.Context, req Request) Decision {
	var wg sync.WaitGroup
	wg.Add(2)
	var legacy *LegacyDecision
	var prompt *PromptDecision
	go func() {
		defer wg.Done()
		legacy, _ = c.checkLegacy(ctx, req)
	}()
	go func() {
		defer wg.Done()
		if c.prompt == nil {
			prompt = unavailablePromptDecision(ErrorCodeUnavailable)
			return
		}
		result, err := c.prompt.Evaluate(ctx, req.Clone())
		if err != nil {
			var guardErr *GuardError
			if errors.As(err, &guardErr) && guardErr.Code == ErrorCodeInvalidResponse {
				prompt = unavailablePromptDecision(ErrorCodeInvalidResponse)
				return
			}
			prompt = unavailablePromptDecision(ErrorCodeUnavailable)
			return
		}
		if result == nil {
			prompt = unavailablePromptDecision(ErrorCodeUnavailable)
			return
		}
		prompt = result
	}()
	wg.Wait()
	return prioritize(legacy, prompt)
}

func (c *Coordinator) checkLegacy(ctx context.Context, req Request) (*LegacyDecision, error) {
	if c.legacy == nil {
		return nil, nil
	}
	return c.legacy.Check(ctx, req)
}

func prioritize(legacy *LegacyDecision, prompt *PromptDecision) Decision {
	if legacy != nil && legacy.Blocked {
		status := legacy.StatusCode
		if status < 400 || status > 599 {
			status = http.StatusForbidden
		}
		code := legacy.ErrorCode
		if code == "" {
			code = "content_policy_violation"
		}
		return Decision{
			Kind: DecisionBlock, HTTPStatus: status, ErrorCode: code, ClientMessage: legacy.Message,
			Legacy: legacy, Prompt: prompt, AllowNextStage: false,
		}
	}
	if prompt == nil {
		return allowDecision(legacy, nil)
	}
	switch prompt.Kind {
	case DecisionBlock:
		status := prompt.BlockHTTPStatus
		if status < 400 || status > 499 {
			status = DefaultBlockHTTPStatus
		}
		message := prompt.BlockMessage
		if message == "" {
			message = DefaultBlockMessage
		}
		code := prompt.ErrorCode
		if code == "" {
			code = ErrorCodeBlocked
		}
		return Decision{Kind: DecisionBlock, HTTPStatus: status, ErrorCode: code,
			ClientMessage: message, Legacy: legacy, Prompt: prompt}
	case DecisionInvalid:
		return Decision{Kind: DecisionInvalid, HTTPStatus: http.StatusServiceUnavailable, ErrorCode: ErrorCodeInvalidResponse,
			ClientMessage: "提示词安全审计暂时不可用，请稍后重试", Legacy: legacy, Prompt: prompt}
	case DecisionUnavailable:
		return Decision{Kind: DecisionUnavailable, HTTPStatus: http.StatusServiceUnavailable, ErrorCode: ErrorCodeUnavailable,
			ClientMessage: "提示词安全审计暂时不可用，请稍后重试", Legacy: legacy, Prompt: prompt}
	case DecisionFlag:
		return Decision{Kind: DecisionFlag, HTTPStatus: http.StatusOK, ErrorCode: prompt.ErrorCode, Legacy: legacy, Prompt: prompt, AllowNextStage: true}
	default:
		return allowDecision(legacy, prompt)
	}
}

func allowDecision(legacy *LegacyDecision, prompt *PromptDecision) Decision {
	return Decision{Kind: DecisionAllow, HTTPStatus: http.StatusOK, Legacy: legacy, Prompt: prompt, AllowNextStage: true}
}

func unavailablePromptDecision(code string) *PromptDecision {
	kind := DecisionUnavailable
	if code == ErrorCodeInvalidResponse {
		kind = DecisionInvalid
	}
	return &PromptDecision{Kind: kind, ErrorCode: code, AllowNextStage: false}
}

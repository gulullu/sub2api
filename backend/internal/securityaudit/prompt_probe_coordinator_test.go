package securityaudit

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeProbeGovernanceEngine struct {
	result        ProbeGovernanceResult
	rejectResult  *ProbeLocalResponse
	evaluateCalls atomic.Int64
	rejectCalls   atomic.Int64
}

func (f *fakeProbeGovernanceEngine) EffectiveMode() Mode                    { return ModeBlocking }
func (f *fakeProbeGovernanceEngine) Enqueue(context.Context, Request) error { return nil }
func (f *fakeProbeGovernanceEngine) Evaluate(context.Context, Request) (*PromptDecision, error) {
	f.evaluateCalls.Add(1)
	return nil, nil
}
func (f *fakeProbeGovernanceEngine) ProbeGovernanceEnabled(context.Context, Request) bool {
	return true
}
func (f *fakeProbeGovernanceEngine) GovernProbe(context.Context, Request) ProbeGovernanceResult {
	return f.result
}
func (f *fakeProbeGovernanceEngine) GovernConfirmedProbe(context.Context, Request) ProbeGovernanceResult {
	return f.result
}
func (f *fakeProbeGovernanceEngine) FinalizeProbeForward(*ProbeForwardClaim, bool, bool) {}
func (f *fakeProbeGovernanceEngine) ReleaseProbeForwardClaim(*ProbeForwardClaim)         {}
func (f *fakeProbeGovernanceEngine) RejectProbeForwardClaim(*ProbeForwardClaim, string) *ProbeLocalResponse {
	f.rejectCalls.Add(1)
	return f.rejectResult
}

func TestCoordinatorReusesProbePromptDecisionRunsLegacyAndPreservesRiskRoute(t *testing.T) {
	claim := &ProbeForwardClaim{}
	promptDecision := &PromptDecision{Kind: DecisionFlag, AllowNextStage: true, RouteAccountIDs: []int64{101, 202}}
	engine := &fakeProbeGovernanceEngine{result: ProbeGovernanceResult{
		Enabled: true, Applied: true, Claim: claim, PromptDecision: promptDecision,
	}}
	legacy := &fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}
	result := NewCoordinator(legacy, engine).GovernProbe(context.Background(), Request{})

	require.Same(t, claim, result.Claim)
	require.NotNil(t, result.AuditDecision)
	require.Equal(t, DecisionFlag, result.AuditDecision.Kind)
	require.Equal(t, []int64{101, 202}, result.AuditDecision.Prompt.RouteAccountIDs)
	require.Equal(t, int64(1), legacy.calls.Load())
	require.Zero(t, engine.evaluateCalls.Load(), "the already obtained Luna decision must not be evaluated twice")
}

func TestCoordinatorTurnsLegacyBlockedProbeClaimIntoLocalViolation(t *testing.T) {
	local := &ProbeLocalResponse{Kind: "violation"}
	engine := &fakeProbeGovernanceEngine{result: ProbeGovernanceResult{
		Enabled: true, Applied: true, Claim: &ProbeForwardClaim{},
		PromptDecision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true},
	}, rejectResult: local}
	legacy := &fakeLegacyEngine{decision: &LegacyDecision{Blocked: true}}
	result := NewCoordinator(legacy, engine).GovernProbe(context.Background(), Request{})

	require.Nil(t, result.Claim)
	require.Same(t, local, result.Local)
	require.Equal(t, int64(1), engine.rejectCalls.Load())
	require.Zero(t, engine.evaluateCalls.Load())
}

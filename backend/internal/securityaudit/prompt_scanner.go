package securityaudit

import (
	"errors"
	"sort"
	"strings"
	"time"
)

func SplitRunes(value string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	segments := strings.Split(value, promptAuditPrioritySeparator)
	chunks := make([]string, 0, len(segments))
	for _, segment := range segments {
		runes := []rune(segment)
		for start := 0; start < len(runes); start += limit {
			end := start + limit
			if end > len(runes) {
				end = len(runes)
			}
			chunks = append(chunks, string(runes[start:end]))
		}
	}
	return chunks
}

func AggregateResults(results []*NormalizedResult, latency time.Duration) (*NormalizedResult, error) {
	if len(results) == 0 {
		return nil, errors.New("prompt guard produced no complete result")
	}
	aggregated := &NormalizedResult{
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow,
		Categories: []string{}, MatchedScanners: []string{},
		ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}, ChunkTotal: len(results),
		LatencyMS: int(latency.Milliseconds()),
	}
	categories := map[string]struct{}{}
	matched := map[string]struct{}{}
	unknown := map[string]struct{}{}
	selectedResult := false
	selectedConfidence := 0.0
	confidenceResult := false
	confidenceReason := ""
	for _, result := range results {
		if result == nil {
			return nil, errors.New("prompt guard partial result is not allowed")
		}
		candidateDecisionSeverity := resultSeverity(result.Decision)
		selectedDecisionSeverity := resultSeverity(aggregated.Decision)
		moreSevere := candidateDecisionSeverity > selectedDecisionSeverity
		sameDecisionSeverity := candidateDecisionSeverity == selectedDecisionSeverity
		higherRisk := sameDecisionSeverity && riskSeverity(result.RiskLevel) > riskSeverity(aggregated.RiskLevel)
		sameRisk := riskSeverity(result.RiskLevel) == riskSeverity(aggregated.RiskLevel)
		higherConfidence := sameDecisionSeverity && sameRisk && result.Confidence > selectedConfidence
		if moreSevere {
			aggregated.Decision = result.Decision
			aggregated.Action = result.Action
		}
		if moreSevere || higherRisk {
			aggregated.RiskLevel = result.RiskLevel
		}
		if moreSevere || higherRisk || higherConfidence || !selectedResult {
			aggregated.Safety = result.Safety
			aggregated.GuardEndpointID = result.GuardEndpointID
			aggregated.GuardEndpointName = result.GuardEndpointName
			aggregated.ScannerBackend = result.ScannerBackend
			aggregated.ScannerVersion = result.ScannerVersion
			aggregated.PolicyID = result.PolicyID
			aggregated.PolicyVersion = result.PolicyVersion
			selectedConfidence = result.Confidence
			selectedResult = true
		}
		for _, category := range result.Categories {
			categories[category] = struct{}{}
		}
		for _, scanner := range result.MatchedScanners {
			matched[scanner] = struct{}{}
		}
		for scanner, score := range result.ScannerScores {
			currentScore, hasScore := aggregated.ScannerScores[scanner]
			if !hasScore || score > currentScore {
				aggregated.ScannerScores[scanner] = score
			}
			if scanner == confidenceScoreKey && (!confidenceResult || score > aggregated.Confidence) {
				aggregated.Confidence = score
				confidenceReason = result.ScannerEvidence[confidenceScoreKey]
				if strings.TrimSpace(confidenceReason) == "" {
					confidenceReason = result.Reason
				}
				confidenceResult = true
			}
		}
		for scanner, evidence := range result.ScannerEvidence {
			if _, exists := aggregated.ScannerEvidence[scanner]; !exists {
				aggregated.ScannerEvidence[scanner] = RedactSensitiveText(evidence)
			}
		}
		for _, category := range result.UnknownCategories {
			unknown[category] = struct{}{}
		}
	}
	aggregated.Categories = orderedScannerKeys(categories)
	aggregated.MatchedScanners = orderedScannerKeys(matched)
	aggregated.UnknownCategories = sortedKeys(unknown)
	if confidenceResult {
		aggregated.Reason = RedactSensitiveText(confidenceReason)
		aggregated.ScannerEvidence[confidenceScoreKey] = aggregated.Reason
	}
	return aggregated, nil
}

func resultSeverity(decision EventDecision) int {
	switch decision {
	case EventCritical:
		return 3
	case EventFlag:
		return 2
	default:
		return 1
	}
}

func riskSeverity(risk RiskLevel) int {
	switch risk {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	default:
		return 1
	}
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func orderedScannerKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	remaining := make(map[string]struct{}, len(values))
	for key := range values {
		remaining[key] = struct{}{}
	}
	for _, scannerID := range AllScannerIDs {
		if _, ok := remaining[scannerID]; ok {
			result = append(result, scannerID)
			delete(remaining, scannerID)
		}
	}
	result = append(result, sortedKeys(remaining)...)
	return result
}

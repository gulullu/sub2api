package securityaudit

import (
	"crypto/sha256"
	"encoding/hex"
)

func BuildIssueSummaries(result NormalizedResult) []IssueSummary {
	resultCategories := result.Categories
	if len(resultCategories) == 0 {
		resultCategories = result.MatchedScanners
	}
	summaries := make([]IssueSummary, 0, len(resultCategories)+len(result.UnknownCategories))
	for _, category := range resultCategories {
		if category == auditUnavailableScannerID {
			evidence := result.ScannerEvidence[category]
			if evidence == "" {
				evidence = "prompt audit dependency unavailable"
			}
			digest := sha256.Sum256([]byte(evidence))
			summaries = append(summaries, IssueSummary{
				Category: category, ScannerID: category, Title: "审计节点暂不可用",
				Description: "远程审计节点全部不可用；请求已限制到配置的高风险账号池", Severity: string(result.RiskLevel),
				SeverityLabel: riskLabelZH(result.RiskLevel), Action: string(result.Action),
				ActionLabel: actionLabelZH(result.Action), Code: "prompt_audit_unavailable",
				Score: result.ScannerScores[category], Evidence: evidence, EvidenceHash: hex.EncodeToString(digest[:]),
			})
			continue
		}
		if category == inputTooLargeScannerID {
			evidence := RedactPreview(result.ScannerEvidence[category], 160)
			if evidence == "" {
				evidence = "prompt exceeds total audit limit"
			}
			digest := sha256.Sum256([]byte(evidence))
			summaries = append(summaries, IssueSummary{
				Category: category, ScannerID: category, Title: "审计输入超过总量上限",
				Description: "请求未交给远程审核模型；同步模式会按配置分流或拒绝，异步模式仅记录", Severity: string(result.RiskLevel),
				SeverityLabel: riskLabelZH(result.RiskLevel), Action: string(result.Action),
				ActionLabel: actionLabelZH(result.Action), Code: "prompt_audit_input_too_large",
				Score: result.ScannerScores[category], Evidence: evidence, EvidenceHash: hex.EncodeToString(digest[:]),
			})
			continue
		}
		definition, ok := ScannerCatalog[category]
		if !ok {
			continue
		}
		evidence := RedactPreview(result.ScannerEvidence[category], 160)
		if evidence == "" {
			evidence = definition.Label
		}
		digest := sha256.Sum256([]byte(evidence))
		summaries = append(summaries, IssueSummary{
			Category: category, ScannerID: category, Title: definition.LabelZH,
			Description: definition.Description, Severity: string(result.RiskLevel),
			SeverityLabel: riskLabelZH(result.RiskLevel), Action: string(result.Action),
			ActionLabel: actionLabelZH(result.Action), Code: "prompt_audit_" + category,
			Score: result.ScannerScores[category], Evidence: evidence,
			EvidenceHash: hex.EncodeToString(digest[:]),
		})
	}
	confidenceMatched := false
	for _, scannerID := range result.MatchedScanners {
		if scannerID == confidenceScoreKey {
			confidenceMatched = true
			break
		}
	}
	if score, ok := result.ScannerScores[confidenceScoreKey]; ok && confidenceMatched {
		evidence := RedactPreview(result.ScannerEvidence[confidenceScoreKey], 160)
		if evidence == "" {
			evidence = "模型置信度超过配置阈值"
		}
		digest := sha256.Sum256([]byte(evidence))
		summaries = append(summaries, IssueSummary{
			Category: confidenceScoreKey, ScannerID: confidenceScoreKey, Title: "模型置信度判定",
			Description: "通用审核模型按配置的置信度阈值标记了风险", Severity: string(result.RiskLevel),
			SeverityLabel: riskLabelZH(result.RiskLevel), Action: string(result.Action),
			ActionLabel: actionLabelZH(result.Action), Code: "prompt_audit_confidence_json",
			Score: score, Evidence: evidence, EvidenceHash: hex.EncodeToString(digest[:]),
		})
	}
	for _, category := range result.UnknownCategories {
		evidence := "unknown_unsafe"
		digest := sha256.Sum256([]byte(evidence + ":" + category))
		summaries = append(summaries, IssueSummary{
			Category: category, ScannerID: "unknown_unsafe", Title: "未知高风险分类",
			Description: "审计节点返回了未知但不可忽略的高风险分类", Severity: string(RiskCritical),
			SeverityLabel: riskLabelZH(RiskCritical), Action: string(ActionBlock),
			ActionLabel: actionLabelZH(ActionBlock), Code: "prompt_audit_unknown_unsafe",
			Score: 1, Evidence: evidence, EvidenceHash: hex.EncodeToString(digest[:]),
		})
	}
	return summaries
}

func riskLabelZH(risk RiskLevel) string {
	switch risk {
	case RiskCritical:
		return "严重"
	case RiskHigh:
		return "高"
	case RiskMedium:
		return "中"
	default:
		return "低"
	}
}

func actionLabelZH(action Action) string {
	switch action {
	case ActionBlock:
		return "阻止"
	case ActionWarn:
		return "警告"
	default:
		return "允许"
	}
}

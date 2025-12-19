package policy

import (
	"context"
	"fmt"
	"mcp-gateway/internal/policy/config"
	"mcp-gateway/internal/policy/core"
	"mcp-gateway/internal/policy/detection"
	"mcp-gateway/internal/policy/ml/client"
	"mcp-gateway/internal/policy/processing"
	"mcp-gateway/internal/policy/utils"
	"time"
)

// New: 새로운 Policy 인스턴스 생성
func New(opts core.Options) *core.Policy {
	return core.New(opts)
}

// DetectSensitiveInfo: 전체 민감정보 탐지 (HIGH + MEDIUM 확실성)
func DetectSensitiveInfo(text string) []core.SensitiveInfo {
	return detection.DetectSensitiveInfo(text)
}

// DetectSensitiveInfoWithML: ML 모델을 포함한 민감정보 탐지
func DetectSensitiveInfoWithML(text, userID, sessionID, policyID string) ([]core.SensitiveInfo, error) {
	// ML 설정 로드 (LoadConfig 사용)
	mlConfig, _, _, _ := config.LoadConfig()
	// Timeout을 60초로 오버라이드 (ML 추론 시간 고려)
	mlConfig.Timeout = 60 * time.Second
	
	// gRPC 클라이언트 생성
	grpcClient, err := client.NewGRPCClient(mlConfig)
	if err != nil {
		return nil, err
	}
	
	// ML 탐지기 초기화
	mlDetector := detection.NewMLDetector(grpcClient, nil, nil, true)
	
	// ML 기반 탐지 실행
	result, err := detection.DetectSensitiveInfoWithML(
		context.Background(),
		text,
		userID,
		sessionID,
		policyID,
		mlDetector,
	)
	return result, err
}

// ProcessSensitiveInfo: 민감정보 처리 (탐지 + 마스킹) - ML 서버 사용
func ProcessSensitiveInfo(text string) (string, []core.SensitiveInfo) {
	// ML 서버를 사용한 탐지
	detected, err := DetectSensitiveInfoWithML(text, "system", fmt.Sprintf("session_%d", time.Now().UnixNano()), "default")
	if err != nil {
		// ML 서버 실패 시 기본 탐지 사용
		detected = DetectSensitiveInfo(text)
	}
	
	maskedText := text
	
	// HIGH 확실성 민감정보만 마스킹 처리
	for _, info := range detected {
		if info.Level == core.High {
			switch info.Category {
			case core.CategoryPersonalInfo:
				// 개인정보 마스킹
				maskedText = processing.MaskPersonalInfo(maskedText)
			case core.CategoryFinancial:
				// 재무/결제 정보 마스킹
				maskedText = processing.MaskFinancialInfo(maskedText)
			case core.CategoryAuth:
				// 인증/보안 정보 마스킹
				maskedText = processing.MaskAuthInfo(maskedText)
			case core.CategorySystem:
				// 내부 시스템 정보 마스킹
				maskedText = processing.MaskSystemInfo(maskedText)
			}
		}
	}
	
	return maskedText, detected
}

// ProcessSensitiveInfoWithLogging: 민감정보 처리 + 로깅 (사용자 정보 포함) - ML 서버 사용
func ProcessSensitiveInfoWithLogging(user, sessionID, text string) (string, []core.SensitiveInfo) {
	// ML 서버를 사용한 탐지
	detected, err := DetectSensitiveInfoWithML(text, user, sessionID, "default")
	if err != nil {
		// ML 서버 실패 시 기본 탐지 사용
		detected = DetectSensitiveInfo(text)
	}
	
	maskedText := text
	
	// HIGH 확실성 민감정보만 마스킹 처리
	for _, info := range detected {
		if info.Level == core.High {
			switch info.Category {
			case core.CategoryPersonalInfo:
				// 개인정보 마스킹
				maskedText = processing.MaskPersonalInfo(maskedText)
			case core.CategoryFinancial:
				// 재무/결제 정보 마스킹
				maskedText = processing.MaskFinancialInfo(maskedText)
			case core.CategoryAuth:
				// 인증/보안 정보 마스킹
				maskedText = processing.MaskAuthInfo(maskedText)
			case core.CategorySystem:
				// 내부 시스템 정보 마스킹
				maskedText = processing.MaskSystemInfo(maskedText)
			}
		}
	}
	
	// DLP 탐지 결과 로깅
	if len(detected) > 0 {
		utils.LogDLPDetection(user, sessionID, text, maskedText, detected)
		utils.LogDLPSummary(user, sessionID, detected)
	}
	
	return maskedText, detected
}

// GetSensitivitySummary: 민감정보 탐지 결과 요약 (확실성 수준별)
func GetSensitivitySummary(text string) map[string]interface{} {
	detected := DetectSensitiveInfo(text)
	
	summary := map[string]interface{}{
		"total_count":       len(detected),
		"high_confidence":   0, // 🔴 확실함 - Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		"medium_confidence": 0, // 🟠 판단 필요 - Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		"low_confidence":    0, // 🟢 안전함 - Regex 불일치/민감정보 관련 없음 → 그대로 통과 → 모델 X
		"categories":        make(map[string]int),
		"details":           detected,
	}
	
	for _, info := range detected {
		// 확실성 수준별 카운트
		switch info.Level {
		case core.High:
			summary["high_confidence"] = summary["high_confidence"].(int) + 1
		case core.Medium:
			summary["medium_confidence"] = summary["medium_confidence"].(int) + 1
		case core.Low:
			summary["low_confidence"] = summary["low_confidence"].(int) + 1
		}
		
		// 카테고리별 카운트
		categories := summary["categories"].(map[string]int)
		categories[string(info.Category)]++
	}
	
	return summary
}

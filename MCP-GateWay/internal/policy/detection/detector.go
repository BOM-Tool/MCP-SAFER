package detection

import (
	"context"
	"fmt"
	"mcp-gateway/internal/policy/core"
	"mcp-gateway/internal/policy/metrics"
	"time"
)

// DetectSensitiveInfo: 전체 민감정보 탐지 (HIGH + MEDIUM 확실성)
func DetectSensitiveInfo(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo
	
	// HIGH 확실성 탐지
	// 개인정보 탐지
	personalInfo := DetectPersonalInfo(text)
	detected = append(detected, personalInfo...)
	
	// 재무/결제 정보 탐지
	financialInfo := DetectFinancialInfo(text)
	detected = append(detected, financialInfo...)
	
	// 인증/보안 정보 탐지
	authInfo := DetectAuthInfo(text)
	detected = append(detected, authInfo...)
	
	// 내부 시스템 정보 탐지
	systemInfo := DetectSystemInfo(text)
	detected = append(detected, systemInfo...)
	
	// HIGH 확실성으로 탐지된 위치들을 추출하여 제외 영역 생성
	excludedPositions := make(map[int]int)
	for _, detection := range detected {
		if detection.Level == core.High {
			// HIGH 탐지된 전체 범위를 제외 영역으로 설정
			for i := detection.Position; i < detection.Position+len(detection.Value); i++ {
				excludedPositions[i] = 1
			}
		}
	}
	
	// MEDIUM 확실성 탐지 (HIGH와 겹치지 않는 부분만)
	mediumInfo := DetectMediumConfidenceInfoWithExclusion(text, excludedPositions)
	detected = append(detected, mediumInfo...)
	
	// 최종 중복 제거 (HIGH 우선, 겹치는 부분 제거)
	detected = removeDuplicatesWithHighPriority(detected)
	
	return detected
}

// DetectSensitiveInfoWithML: ML 기반 하이브리드 탐지
func DetectSensitiveInfoWithML(ctx context.Context, text, userID, sessionID, policyID string, mlDetector *MLDetector) ([]core.SensitiveInfo, error) {
	start := time.Now()
	defer func() {
		metrics.RecordDetectionLatency("hybrid", time.Since(start))
	}()

	// 1. Regex 탐지 (HIGH + MEDIUM)
	regexDetections := DetectSensitiveInfo(text)
	
	// HIGH 확실성 탐지 결과는 그대로 유지
	var highDetections []core.SensitiveInfo
	var mediumDetections []core.SensitiveInfo
	
	for _, detection := range regexDetections {
		if detection.Level == core.High {
			highDetections = append(highDetections, detection)
		} else {
			mediumDetections = append(mediumDetections, detection)
		}
	}
	
	// 2. ML 서버에 전송 (HIGH 또는 MEDIUM 탐지가 있을 때)
	var mlDetections []core.SensitiveInfo
	if len(highDetections) > 0 || len(mediumDetections) > 0 {
		// 전체 텍스트를 ML 서버에 전송 (HIGH 또는 MEDIUM 탐지가 있을 때)
		var err error
		mlDetections, err = mlDetector.DetectSensitiveInfoWithML(ctx, text, userID, sessionID, policyID)
		if err != nil {
			// ML 실패 시 기존 탐지 결과 유지
			metrics.RecordError("ml_detection_failed", "ml_detector")
			// HIGH는 그대로 유지, MEDIUM만 ML 결과로 대체
			mlDetections = mediumDetections
		}
	}
	
	// 3. 결과 병합: HIGH + ML 결과
	var finalDetections []core.SensitiveInfo
	finalDetections = append(finalDetections, highDetections...)
	finalDetections = append(finalDetections, mlDetections...)
	
	// 4. 메트릭 기록
	for _, detection := range finalDetections {
		metrics.RecordMLDetection(
			string(detection.Category),
			string(detection.Level),
			string(detection.Source),
			time.Since(start),
		)
	}

	return finalDetections, nil
}

// extractHighPositions: HIGH 확실성으로 탐지된 위치들을 추출
func extractHighPositions(detections []core.SensitiveInfo) map[int]int {
	positions := make(map[int]int)
	for _, det := range detections {
		if det.Level == core.High {
			// 시작 위치부터 끝 위치까지
			for i := det.Position; i < det.Position+len(det.Value); i++ {
				positions[i] = 1
			}
		}
	}
	return positions
}

// mergeDetections 중복 제거하여 탐지 결과 병합
func mergeDetections(regexDetections, mlDetections []core.SensitiveInfo) []core.SensitiveInfo {
	// ML 탐지 결과를 우선으로 하고, 겹치는 부분 제거
	var merged []core.SensitiveInfo
	
	// ML 탐지 결과 추가 (우선순위 높음)
	for _, mlDetection := range mlDetections {
		merged = append(merged, mlDetection)
	}
	
	// ML 탐지된 위치들을 추출하여 제외 영역 생성
	excludedPositions := make(map[int]bool)
	for _, mlDetection := range mlDetections {
		// ML 탐지된 전체 범위를 제외 영역으로 설정
		for i := mlDetection.Position; i < mlDetection.Position+len(mlDetection.Value); i++ {
			excludedPositions[i] = true
		}
	}
	
	// Regex 탐지 결과 추가 (ML과 겹치지 않는 경우만)
	for _, regexDetection := range regexDetections {
		// 겹치는지 확인
		overlaps := false
		for i := regexDetection.Position; i < regexDetection.Position+len(regexDetection.Value); i++ {
			if excludedPositions[i] {
				overlaps = true
				break
			}
		}
		
		if !overlaps {
			merged = append(merged, regexDetection)
		}
	}
	
	return merged
}

// removeDuplicates: 중복된 탐지 결과 제거 (위치와 값 기준)
func removeDuplicates(detections []core.SensitiveInfo) []core.SensitiveInfo {
	// 위치와 값의 조합으로 중복 제거
	seen := make(map[string]core.SensitiveInfo)
	
	for _, detection := range detections {
		key := fmt.Sprintf("%d-%s-%s", detection.Position, detection.Value, detection.Category)
		
		if existing, exists := seen[key]; exists {
			// 이미 존재하는 경우, HIGH 확실성이 우선
			if detection.Level == core.High && existing.Level != core.High {
				seen[key] = detection
			}
		} else {
			seen[key] = detection
		}
	}
	
	// 결과를 슬라이스로 변환
	var result []core.SensitiveInfo
	for _, detection := range seen {
		result = append(result, detection)
	}
	
	return result
}

// removeDuplicatesWithHighPriority: HIGH 우선순위로 중복 제거
func removeDuplicatesWithHighPriority(detections []core.SensitiveInfo) []core.SensitiveInfo {
	// HIGH 확실성 탐지들을 먼저 수집
	var highDetections []core.SensitiveInfo
	var otherDetections []core.SensitiveInfo
	
	for _, detection := range detections {
		if detection.Level == core.High {
			highDetections = append(highDetections, detection)
		} else {
			otherDetections = append(otherDetections, detection)
		}
	}
	
	// HIGH 탐지된 위치들을 제외 영역으로 설정
	excludedPositions := make(map[int]bool)
	for _, highDetection := range highDetections {
		for i := highDetection.Position; i < highDetection.Position+len(highDetection.Value); i++ {
			excludedPositions[i] = true
		}
	}
	
	// HIGH 탐지 결과는 모두 포함
	var result []core.SensitiveInfo
	result = append(result, highDetections...)
	
	// 다른 탐지들은 HIGH와 겹치지 않는 경우만 포함
	for _, detection := range otherDetections {
		overlaps := false
		for i := detection.Position; i < detection.Position+len(detection.Value); i++ {
			if excludedPositions[i] {
				overlaps = true
				break
			}
		}
		
		if !overlaps {
			result = append(result, detection)
		}
	}
	
	return result
}

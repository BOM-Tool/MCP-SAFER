package detection

import (
	"mcp-gateway/internal/policy/core"
	"mcp-gateway/internal/policy/processing"
	"regexp"
)

// DetectPersonalInfo: 개인정보 탐지 (주민등록번호, 여권번호, 전화번호, 이메일)
func DetectPersonalInfo(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo
	
	// patterns.go에서 정의된 패턴 사용
	patterns := core.InitSensitivePatterns()
	personalPatterns := patterns[core.CategoryPersonalInfo]
	
	for _, pattern := range personalPatterns {
		matches := pattern.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				value := text[match[0]:match[1]]
				level := processing.GetConfidenceLevel(core.CategoryPersonalInfo, value)
				sensitiveType := processing.GetSensitiveType(core.CategoryPersonalInfo, value)
				
				// MEDIUM 확실성은 "불명확"으로 통일
				if level == core.Medium {
					sensitiveType = "불명확"
				}
				
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    level,
					Type:     sensitiveType,
					Value:    value,
					Position: match[0],
				})
			}
		}
	}
	
	return removeDuplicates(detected)
}

// DetectFinancialInfo: 재무/결제 정보 탐지
func DetectFinancialInfo(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo
	
	// patterns.go에서 정의된 패턴 사용
	patterns := core.InitSensitivePatterns()
	financialPatterns := patterns[core.CategoryFinancial]
	
	for _, pattern := range financialPatterns {
		matches := pattern.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				value := text[match[0]:match[1]]
				level := processing.GetConfidenceLevel(core.CategoryFinancial, value)
				sensitiveType := processing.GetSensitiveType(core.CategoryFinancial, value)
				
				// MEDIUM 확실성은 "불명확"으로 통일
				if level == core.Medium {
					sensitiveType = "불명확"
				}
				
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryFinancial,
					Level:    level,
					Type:     sensitiveType,
					Value:    value,
					Position: match[0],
				})
			}
		}
	}
	
	return removeDuplicates(detected)
}

// DetectAuthInfo: 인증/보안 정보 탐지
func DetectAuthInfo(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo
	
	// patterns.go에서 정의된 패턴 사용
	patterns := core.InitSensitivePatterns()
	authPatterns := patterns[core.CategoryAuth]
	
	for _, pattern := range authPatterns {
		matches := pattern.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				value := text[match[0]:match[1]]
				level := processing.GetConfidenceLevel(core.CategoryAuth, value)
				sensitiveType := processing.GetSensitiveType(core.CategoryAuth, value)
				
				// MEDIUM 확실성은 "불명확"으로 통일
				if level == core.Medium {
					sensitiveType = "불명확"
				}
				
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryAuth,
					Level:    level,
					Type:     sensitiveType,
					Value:    value,
					Position: match[0],
				})
			}
		}
	}
	
	return removeDuplicates(detected)
}

// DetectSystemInfo: 내부 시스템 정보 탐지
func DetectSystemInfo(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo
	
	// patterns.go에서 정의된 패턴 사용
	patterns := core.InitSensitivePatterns()
	systemPatterns := patterns[core.CategorySystem]
	
	for _, pattern := range systemPatterns {
		matches := pattern.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				value := text[match[0]:match[1]]
				level := processing.GetConfidenceLevel(core.CategorySystem, value)
				sensitiveType := processing.GetSensitiveType(core.CategorySystem, value)
				
				// MEDIUM 확실성은 "불명확"으로 통일
				if level == core.Medium {
					sensitiveType = "불명확"
				}
				
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategorySystem,
					Level:    level,
					Type:     sensitiveType,
					Value:    value,
					Position: match[0],
				})
			}
		}
	}
	
	return removeDuplicates(detected)
}

// initSensitivePatterns: 민감정보 패턴 초기화 (core 패키지에서 가져옴)
func initSensitivePatterns() map[core.SensitiveCategory][]*regexp.Regexp {
	// core 패키지의 initSensitivePatterns 함수를 호출
	return core.InitSensitivePatterns()
}

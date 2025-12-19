package core

import (
	"path"
	"regexp"
	"strings"
)

type Options struct {
	Allowlist  []string
	ScrubEmail bool
	ScrubPhone bool
	// 민감정보 필터링 옵션
	EnableSensitiveFilter bool
	LogSensitiveInfo      bool
}

type Policy struct {
	allowGlobs        []string
	emailRx           *regexp.Regexp
	phoneRx           *regexp.Regexp
	sensitivePatterns map[SensitiveCategory][]*regexp.Regexp
}

func New(opts Options) *Policy {
	p := &Policy{allowGlobs: opts.Allowlist}
	
	// 기존 이메일/전화번호 패턴
	if opts.ScrubEmail {
		p.emailRx = regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	}
	if opts.ScrubPhone {
		p.phoneRx = regexp.MustCompile(`(?i)\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`)
	}
	
	// 민감정보 패턴 초기화
	p.sensitivePatterns = InitSensitivePatterns()
	
	return p
}

// AllowTool: 툴 이름이 allowlist 글롭과 매칭되는지
func (p *Policy) AllowTool(name string) bool {
	for _, g := range p.allowGlobs {
		if matched, _ := path.Match(g, name); matched {
			return true
		}
	}
	return false
}

// Scrub: 기존 스크러빙 로직
func (p *Policy) Scrub(data any) any {
	switch v := data.(type) {
	case string:
		scrubbed := v
		if p.emailRx != nil {
			scrubbed = p.emailRx.ReplaceAllString(scrubbed, "[EMAIL]")
		}
		if p.phoneRx != nil {
			scrubbed = p.phoneRx.ReplaceAllString(scrubbed, "[PHONE]")
		}
		return scrubbed
	case map[string]any:
		scrubbed := make(map[string]any)
		for k, val := range v {
			scrubbed[k] = p.Scrub(val)
		}
		return scrubbed
	case []any:
		scrubbed := make([]any, len(v))
		for i, val := range v {
			scrubbed[i] = p.Scrub(val)
		}
		return scrubbed
	default:
		return v
	}
}

// GetSensitivitySummary: 민감정보 탐지 결과 요약 (확실성 수준별)
func (p *Policy) GetSensitivitySummary(text string) map[string]interface{} {
	// 이 함수는 상위 레벨에서 구현됨
	detected := []SensitiveInfo{}
	
	summary := map[string]interface{}{
		"total_count": len(detected),
		"high_confidence":  0,    // 🔴 확실함 - Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		"medium_confidence": 0,   // 🟠 판단 필요 - Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		"low_confidence":   0,    // 🟢 안전함 - Regex 불일치/민감정보 관련 없음 → 그대로 통과 → 모델 X
		"categories":  make(map[string]int),
		"details":     detected,
	}
	
	for _, info := range detected {
		// 확실성 수준별 카운트
		switch info.Level {
		case High:
			summary["high_confidence"] = summary["high_confidence"].(int) + 1
		case Medium:
			summary["medium_confidence"] = summary["medium_confidence"].(int) + 1
		case Low:
			summary["low_confidence"] = summary["low_confidence"].(int) + 1
		}
		
		// 카테고리별 카운트
		categories := summary["categories"].(map[string]int)
		categories[string(info.Category)]++
	}
	
	return summary
}

// containsAny: 문자열이 주어진 문자열들 중 하나라도 포함하는지 확인
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

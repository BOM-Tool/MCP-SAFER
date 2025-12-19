package core

import (
	"time"
)

// ConfidenceLevel 확실성 수준
type ConfidenceLevel int

const (
	Low ConfidenceLevel = iota    // 🟢 안전함 - Regex 불일치/민감정보 관련 없음 → 그대로 통과 → 모델 X
	Medium                        // 🟠 판단 필요 - Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
	High                          // 🔴 확실함 - Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
)

// 민감정보 카테고리
type SensitiveCategory string

const (
	CategoryPersonalInfo SensitiveCategory = "personal_info" // 개인정보
	CategoryFinancial    SensitiveCategory = "financial"     // 재무/결제 정보
	CategoryAuth        SensitiveCategory = "auth"          // 인증/보안 정보
	CategorySystem      SensitiveCategory = "system"        // 내부 시스템 정보
)

// 탐지 소스
type DetectionSource int

const (
	SourceRegex DetectionSource = iota // Regex 탐지
	SourceML                          // ML 탐지
	SourceHybrid                      // 하이브리드 탐지
)

// 민감정보 탐지 결과
type SensitiveInfo struct {
	Category SensitiveCategory `json:"category"`
	Level    ConfidenceLevel   `json:"confidence_level"` // 확실성 수준
	Type     string            `json:"type"`             // 민감정보 유형
	Value    string            `json:"value"`            // 탐지된 값
	Position int               `json:"position"`         // 위치
	Source   DetectionSource   `json:"source"`           // 탐지 소스
	MLConfidence float64      `json:"ml_confidence"`     // ML 신뢰도
	Reasoning   string         `json:"reasoning"`       // AI 추론 과정
}

// DLP 탐지 로그 구조체
type DLPLog struct {
	Timestamp     time.Time       `json:"timestamp"`      // 탐지 시간
	User          string          `json:"user"`          // 사용자 ID
	SessionID     string          `json:"session_id"`    // 세션 ID
	Detections    []SensitiveInfo `json:"detections"`    // 탐지 결과 목록
	OriginalText  string          `json:"original_text"` // 사용자가 입력한 프롬프트
	MaskedText    string          `json:"masked_text"`   // 마스킹 처리 완료된 프롬프트
	HighCount     int             `json:"high_count"`    // HIGH 확실성 탐지 개수
	MediumCount   int             `json:"medium_count"`  // MEDIUM 확실성 탐지 개수
	LowCount      int             `json:"low_count"`     // LOW 확실성 탐지 개수
	TotalCount    int             `json:"total_count"`   // 전체 탐지 개수
	Categories    []string        `json:"categories"`    // 탐지된 카테고리 목록
	Types         []string        `json:"types"`         // 탐지된 유형 목록
}

// Policy 정책 구조체는 policy.go에서 정의됨

package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mcp-gateway/internal/policy/core"
)

// LogDLPDetection: DLP 탐지 결과를 로그로 기록
func LogDLPDetection(user, sessionID, originalText, maskedText string, detections []core.SensitiveInfo) {
	// 로그 디렉토리 생성
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("로그 디렉토리 생성 실패: %v", err)
		return
	}

	// 통계 계산
	highCount := 0
	mediumCount := 0
	lowCount := 0
	categories := make(map[string]bool)
	types := make(map[string]bool)

	for _, detection := range detections {
		switch detection.Level {
		case core.High:
			highCount++
		case core.Medium:
			mediumCount++
		case core.Low:
			lowCount++
		}
		categories[string(detection.Category)] = true
		types[detection.Type] = true
	}

	// 카테고리와 타입을 슬라이스로 변환
	var categoryList []string
	var typeList []string
	for cat := range categories {
		categoryList = append(categoryList, cat)
	}
	for typ := range types {
		typeList = append(typeList, typ)
	}

	// DLP 로그 구조체 생성
	dlpLog := core.DLPLog{
		Timestamp:     time.Now(),
		User:          user,
		SessionID:     sessionID,
		Detections:    detections,
		OriginalText:  originalText,
		MaskedText:    maskedText,
		HighCount:     highCount,
		MediumCount:   mediumCount,
		LowCount:      lowCount,
		TotalCount:    len(detections),
		Categories:    categoryList,
		Types:         typeList,
	}

	// JSON 형식으로 로그 기록
	logFileName := filepath.Join(logDir, fmt.Sprintf("dlp_%s.log", time.Now().Format("2006-01-02")))
	file, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("로그 파일 열기 실패: %v", err)
		return
	}
	defer file.Close()

	logEntry, err := json.Marshal(dlpLog)
	if err != nil {
		log.Printf("JSON 마샬링 실패: %v", err)
		return
	}

	if _, err := file.WriteString(string(logEntry) + "\n"); err != nil {
		log.Printf("로그 파일 쓰기 실패: %v", err)
	}
}

// LogDLPSummary: DLP 탐지 요약 정보를 로그로 기록 (콘솔 출력용)
func LogDLPSummary(user, sessionID string, detections []core.SensitiveInfo) {
	if len(detections) == 0 {
		return
	}

	var summary []string
	for _, det := range detections {
		levelStr := ""
		switch det.Level {
		case core.High:
			levelStr = "HIGH"
		case core.Medium:
			levelStr = "MEDIUM"
		case core.Low:
			levelStr = "LOW"
		}
		summary = append(summary, fmt.Sprintf("%s (%s, %s)", det.Type, det.Category, levelStr))
	}

	log.Printf("[DLP Summary] User: %s, Session: %s, Detections: %s, Total: %d",
		user, sessionID, strings.Join(summary, "; "), len(detections))
}

// GetDLPLogStats: 로그 파일에서 DLP 탐지 통계 조회 (예시)
func GetDLPLogStats(logFilePath string) (map[string]int, error) {
	file, err := os.Open(logFilePath)
	if err != nil {
		return nil, fmt.Errorf("로그 파일 열기 실패: %w", err)
	}
	defer file.Close()

	stats := make(map[string]int)
	// 실제 구현에서는 파일을 읽고 각 DLPLog 엔트리를 파싱하여 통계를 집계해야 합니다.
	// 이 부분은 DB 연동 시 더 효율적으로 처리될 수 있습니다.
	stats["TotalDetections"] = 0
	stats["HighConfidence"] = 0
	stats["MediumConfidence"] = 0
	stats["LowConfidence"] = 0

	return stats, nil
}


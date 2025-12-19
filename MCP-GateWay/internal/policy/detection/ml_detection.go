package detection

import (
	"context"
	"fmt"
	"mcp-gateway/internal/policy/cache"
	"mcp-gateway/internal/policy/core"
	"mcp-gateway/internal/policy/metrics"
	"mcp-gateway/internal/policy/ml/client"
	"time"
)

type MLDetector struct {
	grpcClient *client.GRPCClient
	redisCache *cache.RedisCache
	memCache   *cache.MemoryCache
	enabled    bool
}

// NewMLDetector ML 탐지기 생성
func NewMLDetector(grpcClient *client.GRPCClient, redisCache *cache.RedisCache, memCache *cache.MemoryCache, enabled bool) *MLDetector {
	return &MLDetector{
		grpcClient: grpcClient,
		redisCache: redisCache,
		memCache:   memCache,
		enabled:    enabled,
	}
}

// DetectSensitiveInfoWithML ML 기반 민감정보 탐지
func (m *MLDetector) DetectSensitiveInfoWithML(ctx context.Context, text, userID, sessionID, policyID string) ([]core.SensitiveInfo, error) {
	if !m.enabled {
		return []core.SensitiveInfo{}, nil
	}

	start := time.Now()
	defer func() {
		metrics.RecordDetectionLatency("ml", time.Since(start))
	}()

	// 1. 메모리 캐시 확인
	if m.memCache != nil {
	if detections, found := m.memCache.Get(ctx, policyID, text); found {
		metrics.RecordCacheHit("memory")
		return detections, nil
		}
	}

	// 2. Redis 캐시 확인
	if m.redisCache != nil {
	if detections, found := m.redisCache.Get(ctx, policyID, text); found {
		metrics.RecordCacheHit("redis")
		// 메모리 캐시에도 저장
			if m.memCache != nil {
		m.memCache.Set(ctx, policyID, text, detections)
			}
		return detections, nil
		}
	}

	// 3. ML 서버 호출 (캐시 미스 시에만)
	metrics.RecordMLServerCall()
	detections, err := m.grpcClient.DetectSensitiveInfo(ctx, text, userID, sessionID)
	if err != nil {
		metrics.RecordError("ml_server_error", "grpc_client")
		metrics.RecordMLServerCallFailure()
		return nil, fmt.Errorf("ML detection failed: %w", err)
	}

	// 4. 결과 캐싱
	if len(detections) > 0 {
		// Redis 캐시에 저장
		if m.redisCache != nil {
		if err := m.redisCache.Set(ctx, policyID, text, detections); err != nil {
			metrics.RecordError("cache_set_error", "redis")
			}
		}
		
		// 메모리 캐시에 저장
		if m.memCache != nil {
		m.memCache.Set(ctx, policyID, text, detections)
		}
	}

	// 5. 메트릭 기록
	for _, detection := range detections {
		metrics.RecordMLDetection(
			string(detection.Category),
			string(detection.Level),
			string(detection.Source),
			time.Since(start),
		)
	}

	return detections, nil
}

// BatchDetectSensitiveInfoWithML ML 기반 배치 탐지
func (m *MLDetector) BatchDetectSensitiveInfoWithML(ctx context.Context, requests []BatchMLRequest) ([]BatchMLResponse, error) {
	if !m.enabled {
		return []BatchMLResponse{}, nil
	}

	start := time.Now()
	defer func() {
		metrics.RecordBatchProcessing(time.Since(start), len(requests))
	}()

	// 배치 요청 변환
	var batchRequests []client.BatchRequest
	for _, req := range requests {
		batchRequests = append(batchRequests, client.BatchRequest{
			Text:       req.Text,
			UserID:     req.UserID,
			SessionID:  req.SessionID,
			Categories: req.Categories,
		})
	}

	// ML 서버 배치 호출
	metrics.RecordMLServerCall()
	responses, err := m.grpcClient.BatchDetectSensitiveInfo(ctx, batchRequests)
	if err != nil {
		metrics.RecordError("ml_batch_error", "grpc_client")
		metrics.RecordMLServerCallFailure()
		return nil, fmt.Errorf("batch ML detection failed: %w", err)
	}

	// 응답 변환
	var result []BatchMLResponse
	for i, resp := range responses {
		result = append(result, BatchMLResponse{
			Detections: resp.Detections,
			RequestID:  resp.RequestID,
			FromCache:  resp.FromCache,
			Index:      i,
		})
	}

	return result, nil
}

	// HealthCheck ML 서버 상태 확인
func (m *MLDetector) HealthCheck(ctx context.Context) error {
	if !m.enabled {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	err := m.grpcClient.HealthCheck(ctx)
	if err != nil {
		metrics.SetMLServerHealth(false)
		metrics.RecordError("ml_health_check_failed", "health_check")
		return fmt.Errorf("ML server health check failed: %w", err)
	}

	metrics.SetMLServerHealth(true)
	return nil
}

// BatchMLRequest 배치 ML 요청
type BatchMLRequest struct {
	Text       string
	UserID     string
	SessionID  string
	Categories []string
}

// BatchMLResponse 배치 ML 응답
type BatchMLResponse struct {
	Detections []core.SensitiveInfo
	RequestID  string
	FromCache  bool
	Index      int
}

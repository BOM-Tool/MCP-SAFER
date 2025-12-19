package client

import (
	"context"
	"fmt"
	"mcp-gateway/internal/policy/config"
	"mcp-gateway/internal/policy/core"
	"mcp-gateway/internal/policy/ml/proto"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type GRPCClient struct {
	client proto.DLPInferenceClient
	conn   *grpc.ClientConn
	config *config.MLConfig
}

// NewGRPCClient gRPC 클라이언트 생성
func NewGRPCClient(mlConfig *config.MLConfig) (*GRPCClient, error) {
	// Connection Pooling 설정
	serviceConfig := `{
		"loadBalancingConfig": [{"round_robin":{}}],
		"methodConfig": [{
			"name": [{"service": "dlp_inference.DLPInference"}],
			"retryPolicy": {
				"maxAttempts": 3,
				"initialBackoff": "0.1s",
				"maxBackoff": "1s",
			"backoffMultiplier": 2,
			"retryableStatusCodes": ["UNAVAILABLE", "DEADLINE_EXCEEDED"]
			}
		}]
	}`

	// Keep-alive 설정
	keepAliveParams := keepalive.ClientParameters{
		Time:                mlConfig.KeepAlive,
		Timeout:             time.Second * 5,
		PermitWithoutStream: true,
	}

	// gRPC 연결
	conn, err := grpc.Dial(mlConfig.ServerAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(serviceConfig),
		grpc.WithKeepaliveParams(keepAliveParams),
		grpc.WithMaxMsgSize(mlConfig.MaxMessageSize), // Send message size
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ML server: %w", err)
	}

	return &GRPCClient{
		client: proto.NewDLPInferenceClient(conn),
		conn:   conn,
		config: mlConfig,
	}, nil
}

// cleanUTF8 UTF-8로 정리 (잘못된 UTF-8 바이트 제거)
func cleanUTF8(text string) string {
	// 잘못된 UTF-8 바이트를 제거하고 유효한 UTF-8로 변환
	return strings.ToValidUTF8(text, "")
}

// DetectSensitiveInfo 단일 텍스트 탐지
func (c *GRPCClient) DetectSensitiveInfo(ctx context.Context, text string, userID, sessionID string) ([]core.SensitiveInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// UTF-8로 정리된 텍스트 사용
	cleanText := cleanUTF8(text)

	req := &proto.SensitiveInfoRequest{
		Text:                cleanText,
		UserId:              userID,
		SessionId:           sessionID,
		Categories:          []string{"personal_info", "financial", "auth", "system"},
		IncludeReasoning:    true,
		ConfidenceThreshold: 0.5,
	}

	// gRPC 호출 시 메시지 크기 제한 설정
	callOptions := []grpc.CallOption{
		grpc.MaxCallRecvMsgSize(c.config.MaxMessageSize),
		grpc.MaxCallSendMsgSize(c.config.MaxMessageSize),
	}

	resp, err := c.client.DetectSensitiveInfo(ctx, req, callOptions...)
	if err != nil {
		return nil, fmt.Errorf("ML detection failed: %w", err)
	}

	result := convertToSensitiveInfo(resp)
	return result, nil
}

// BatchDetectSensitiveInfo 배치 탐지
func (c *GRPCClient) BatchDetectSensitiveInfo(ctx context.Context, requests []BatchRequest) ([]BatchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout*2) // 배치는 더 긴 타임아웃
	defer cancel()

	var protoRequests []*proto.SensitiveInfoRequest
	for _, req := range requests {
		protoRequests = append(protoRequests, &proto.SensitiveInfoRequest{
			Text:                req.Text,
			UserId:              req.UserID,
			SessionId:           req.SessionID,
			Categories:          req.Categories,
			IncludeReasoning:    true,
			ConfidenceThreshold: 0.5,
		})
	}

	batchReq := &proto.BatchSensitiveInfoRequest{
		Requests:       protoRequests,
		BatchTimeoutMs: int32(c.config.Timeout.Milliseconds()),
	}

	resp, err := c.client.BatchDetectSensitiveInfo(ctx, batchReq)
	if err != nil {
		return nil, fmt.Errorf("batch ML detection failed: %w", err)
	}

	return convertBatchResponse(resp), nil
}

// HealthCheck 서버 상태 확인
func (c *GRPCClient) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	req := &proto.HealthCheckRequest{
		Service: "dlp_inference",
	}

	_, err := c.client.HealthCheck(ctx, req)
	return err
}

// Close 연결 종료
func (c *GRPCClient) Close() error {
	return c.conn.Close()
}

// BatchRequest 배치 요청 구조체
type BatchRequest struct {
	Text       string
	UserID     string
	SessionID  string
	Categories []string
}

// BatchResponse 배치 응답 구조체
type BatchResponse struct {
	Detections []core.SensitiveInfo
	RequestID  string
	FromCache  bool
}

// convertToSensitiveInfo proto 응답을 core.SensitiveInfo로 변환
func convertToSensitiveInfo(resp *proto.SensitiveInfoResponse) []core.SensitiveInfo {
	var detections []core.SensitiveInfo

	for _, detection := range resp.Detections {
		// 카테고리 매핑
		var category core.SensitiveCategory
		switch detection.Category {
		case "personal_info":
			category = core.CategoryPersonalInfo
		case "financial":
			category = core.CategoryFinancial
		case "auth":
			category = core.CategoryAuth
		case "system":
			category = core.CategorySystem
		default:
			category = core.CategoryPersonalInfo
		}

		// 신뢰도 수준 결정
		var level core.ConfidenceLevel
		if detection.Confidence >= 0.8 {
			level = core.High
		} else if detection.Confidence >= 0.5 {
			level = core.Medium
		} else {
			level = core.Low
		}

		// 탐지 소스 결정
		var source core.DetectionSource
		switch detection.Source {
		case "regex":
			source = core.SourceRegex
		case "ml":
			source = core.SourceML
		case "hybrid":
			source = core.SourceHybrid
		default:
			source = core.SourceML
		}

		detections = append(detections, core.SensitiveInfo{
			Category:     category,
			Level:        level,
			Type:         detection.Type,
			Value:        detection.Value,
			Position:     int(detection.StartPosition),
			Source:       source,
			MLConfidence: float64(detection.Confidence),
			Reasoning:    detection.Reasoning,
		})
	}

	return detections
}

// convertBatchResponse 배치 응답 변환
func convertBatchResponse(resp *proto.BatchSensitiveInfoResponse) []BatchResponse {
	var responses []BatchResponse

	for _, respItem := range resp.Responses {
		responses = append(responses, BatchResponse{
			Detections: convertToSensitiveInfo(respItem),
			RequestID:  respItem.RequestId,
			FromCache:  respItem.FromCache,
		})
	}

	return responses
}

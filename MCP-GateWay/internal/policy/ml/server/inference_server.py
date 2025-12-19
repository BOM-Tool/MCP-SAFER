#!/usr/bin/env python3
"""
간단한 DLP Inference 서버 (Mock)
실제 DistilBERT 모델 없이도 작동하는 테스트 서버
"""

import json
import logging
import time
import re
from typing import List, Dict, Any
from concurrent import futures
from threading import Thread
import http.server
import socketserver

import grpc

# Proto 파일 import
import dlp_inference_pb2
import dlp_inference_pb2_grpc

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 간단한 메트릭 카운터
class SimpleMetrics:
    def __init__(self):
        self.request_count = 0
        self.error_count = 0
        self.detection_count = 0
        self.start_time = time.time()
    
    def inc_request(self):
        self.request_count += 1
    
    def inc_error(self):
        self.error_count += 1
    
    def inc_detection(self):
        self.detection_count += 1
    
    def get_metrics(self):
        uptime = time.time() - self.start_time
        return f"""# HELP ml_request_total Number of ML inference requests
# TYPE ml_request_total counter
ml_request_total {self.request_count}

# HELP ml_request_errors_total Number of failed ML requests
# TYPE ml_request_errors_total counter
ml_request_errors_total {self.error_count}

# HELP ml_detections_total Number of sensitive info detections
# TYPE ml_detections_total counter
ml_detections_total {self.detection_count}

# HELP ml_uptime_seconds ML server uptime in seconds
# TYPE ml_uptime_seconds gauge
ml_uptime_seconds {uptime}

# HELP ml_model_version ML model version
# TYPE ml_model_version gauge
ml_model_version{{version="Mock_v1.0"}} 1
"""

metrics = SimpleMetrics()

# HTTP 메트릭 핸들러
class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(metrics.get_metrics().encode())
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "service": "ml-server"}')
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # 로그 메시지 억제
        pass

class MockDLPInferenceService(dlp_inference_pb2_grpc.DLPInferenceServicer):
    """Mock DLP Inference 서비스"""
    
    def __init__(self):
        self.model_version = "Mock_v1.0"
        
        # 간단한 패턴 매칭 규칙
        self.patterns = {
            "personal_info": [
                (r'\d{3}-\d{4}-\d{4}', "전화번호", 0.9),
                (r'\d{6}-\d{7}', "주민등록번호", 0.95),
                (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "이메일", 0.9),
                (r'[AM]\d{8,9}', "여권번호", 0.85),
            ],
            "financial": [
                (r'\d{4}-\d{4}-\d{4}-\d{4}', "카드번호", 0.9),
                (r'\d{3}-\d{2,4}-\d{6}', "계좌번호", 0.8),
                (r'CVV[:]\s*\d{3,4}', "CVV", 0.95),
            ],
            "auth": [
                (r'비밀번호[:]\s*[^\s]{6,}', "비밀번호", 0.8),
                (r'API[_-]?KEY[:]\s*[a-zA-Z0-9_-]{20,}', "API키", 0.9),
                (r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', "JWT토큰", 0.95),
            ],
            "system": [
                (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "IP주소", 0.8),
                (r':\d{1,5}', "포트번호", 0.7),
                (r'server[_-]?\d+', "서버명", 0.6),
            ]
        }
    
    def DetectSensitiveInfo(self, request, context):
        """민감정보 탐지"""
        logger.info(f"ML 서버 호출됨: {request.text[:50]}...")
        
        # 메트릭 증가
        metrics.inc_request()
        
        try:
            start_time = time.time()
            detections = []
            
            # 패턴 매칭으로 민감정보 탐지
            for category, patterns in self.patterns.items():
                for pattern, type_name, confidence in patterns:
                    matches = re.finditer(pattern, request.text)
                    for match in matches:
                        detection = dlp_inference_pb2.SensitiveDetection(
                            category=category,
                            type=type_name,
                            value=match.group(),
                            start_position=match.start(),
                            end_position=match.end(),
                            confidence=confidence,
                            reasoning=f"패턴 매칭: {pattern}",
                            source="ML_MODEL"
                        )
                        detections.append(detection)
                        # 탐지 메트릭 증가
                        metrics.inc_detection()
            
            processing_time = int((time.time() - start_time) * 1000)
            
            response = dlp_inference_pb2.SensitiveInfoResponse(
                detections=detections,
                confidence_score=0.85,
                processing_time_ms=processing_time,
                model_version=self.model_version,
                request_id=f"req_{int(time.time())}",
                from_cache=False
            )
            
            logger.info(f"ML 서버 응답: {len(detections)}개 탐지, {processing_time}ms")
            return response
            
        except Exception as e:
            metrics.inc_error()
            logger.error(f"ML 탐지 오류: {e}")
            raise
    
    def BatchDetectSensitiveInfo(self, request, context):
        """배치 민감정보 탐지"""
        responses = []
        total_start = time.time()
        successful = 0
        failed = 0
        
        for req in request.requests:
            try:
                response = self.DetectSensitiveInfo(req, context)
                responses.append(response)
                successful += 1
            except Exception as e:
                logger.error(f"배치 처리 실패: {e}")
                failed += 1
        
        total_time = int((time.time() - total_start) * 1000)
        
        return dlp_inference_pb2.BatchSensitiveInfoResponse(
            responses=responses,
            total_processing_time_ms=total_time,
            successful_requests=successful,
            failed_requests=failed
        )
    
    def HealthCheck(self, request, context):
        """헬스체크"""
        return dlp_inference_pb2.HealthCheckResponse(
            status=dlp_inference_pb2.HealthCheckResponse.SERVING,
            message="ML 서버 정상 작동 중",
            timestamp=int(time.time())
        )

def serve():
    """gRPC 서버 시작"""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    
    # 서비스 등록
    dlp_inference_pb2_grpc.add_DLPInferenceServicer_to_server(
        MockDLPInferenceService(), server
    )
    
    # 포트 바인딩
    listen_addr = '[::]:50051'
    server.add_insecure_port(listen_addr)
    
    logger.info(f"ML 서버 시작: {listen_addr}")
    server.start()
    
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("서버 종료 중...")
        server.stop(0)

if __name__ == '__main__':
    serve()
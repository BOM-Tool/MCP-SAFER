#!/usr/bin/env python3
"""
간단한 DLP Mock 서버
실제 DistilBERT 없이도 작동하는 테스트용 서버
"""

import json
import logging
import time
import re
from typing import List, Dict, Any
from concurrent import futures
import grpc

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MockDLPServer:
    """Mock DLP 서버"""
    
    def __init__(self):
        self.model_version = "Mock_v1"
        
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
    
    def detect_sensitive_info(self, text: str, categories: List[str] = None) -> List[Dict]:
        """민감정보 탐지"""
        detections = []
        
        if not categories:
            categories = list(self.patterns.keys())
        
        for category in categories:
            if category not in self.patterns:
                continue
                
            for pattern, sensitive_type, confidence in self.patterns[category]:
                matches = re.finditer(pattern, text)
                
                for match in matches:
                    detection = {
                        "category": category,
                        "type": sensitive_type,
                        "value": match.group(),
                        "start_position": match.start(),
                        "end_position": match.end(),
                        "confidence": confidence,
                        "reasoning": f"패턴 매칭으로 {sensitive_type} 탐지 (신뢰도: {confidence:.2f})",
                        "source": "mock"
                    }
                    detections.append(detection)
        
        return detections
    
    def health_check(self) -> Dict:
        """헬스체크"""
        return {
            "status": "SERVING",
            "message": "Mock DLP Server is healthy",
            "timestamp": int(time.time())
        }

# gRPC 서비스 구현 (간단한 HTTP 서버로 대체)
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class DLPHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.dlp_server = MockDLPServer()
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        """POST 요청 처리"""
        if self.path == '/detect':
            self.handle_detect()
        else:
            self.send_error(404)
    
    def do_GET(self):
        """GET 요청 처리"""
        if self.path == '/health':
            self.handle_health()
        else:
            self.send_error(404)
    
    def handle_detect(self):
        """민감정보 탐지 처리"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            text = data.get('text', '')
            categories = data.get('categories', [])
            
            logger.info(f"🔍 ML 모델 호출됨 - 텍스트: {text[:50]}...")
            logger.info(f"📊 요청 카테고리: {categories}")
            
            # 탐지 수행
            detections = self.dlp_server.detect_sensitive_info(text, categories)
            
            logger.info(f"✅ 탐지 완료 - {len(detections)}개 민감정보 발견")
            for detection in detections:
                logger.info(f"  - {detection['type']}: {detection['value']} (신뢰도: {detection['confidence']:.2f})")
            
            # 응답 생성
            response = {
                "detections": detections,
                "confidence_score": max([d["confidence"] for d in detections]) if detections else 0.0,
                "processing_time_ms": 50,  # Mock 처리 시간
                "model_version": self.dlp_server.model_version,
                "request_id": f"mock_{int(time.time())}",
                "from_cache": False
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Detection error: {e}")
            self.send_error(500)
    
    def handle_health(self):
        """헬스체크 처리"""
        health = self.dlp_server.health_check()
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(health, ensure_ascii=False).encode('utf-8'))
    
    def log_message(self, format, *args):
        """로그 메시지 무시"""
        pass

def serve():
    """서버 시작"""
    server_address = ('0.0.0.0', 50051)
    httpd = HTTPServer(server_address, DLPHandler)
    
    logger.info(f"Mock DLP Server starting on {server_address}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        httpd.shutdown()

if __name__ == '__main__':
    serve()

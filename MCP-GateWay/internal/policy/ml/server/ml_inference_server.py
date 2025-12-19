#!/usr/bin/env python3
"""
실제 DistilBERT 모델을 사용한 DLP Inference 서버
Medium 탐지된 텍스트를 ML로 재검증
"""

import json
import logging
import time
import re
import sys
from typing import List, Dict, Any
from concurrent import futures
import os

import grpc
import torch
from transformers import DistilBertForTokenClassification, DistilBertTokenizerFast

# Python 출력 버퍼링 비활성화 (즉시 출력)
# Python 3.7+ 호환성 체크
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass  # 재구성이 안되면 그냥 넘어감

# Proto 파일 import
import dlp_inference_pb2
import dlp_inference_pb2_grpc

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DistilBERTDLPService(dlp_inference_pb2_grpc.DLPInferenceServicer):
    """실제 DistilBERT 모델을 사용한 DLP 서비스"""
    
    def __init__(self, model_path: str):
        print(f"🔧 [PYTHON SERVER] DistilBERTDLPService.__init__ called with model_path: {model_path}", flush=True)
        sys.stdout.flush()
        self.model_path = model_path
        self.model_version = "DistilBERT_v1"
        
        # 모델과 토크나이저 로드
        logger.info(f"DistilBERT 모델 로딩 중: {model_path}")
        print(f"🔧 [PYTHON SERVER] Loading DistilBERT model from: {model_path}", flush=True)
        sys.stdout.flush()
        
        try:
            # 토크나이저 로드
            self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_path)
            
            # 모델 로드 (Token Classification)
            self.model = DistilBertForTokenClassification.from_pretrained(
                model_path,
                local_files_only=True,
                trust_remote_code=True
            )
            
            # GPU 사용 가능하면 GPU로 이동
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)
            self.model.eval()
            
            # 라벨 매핑 로드
            with open(os.path.join(model_path, "label_mapping.json"), "r", encoding="utf-8") as f:
                self.label_mapping = json.load(f)
            
            logger.info(f"모델 로딩 완료. Device: {self.device}")
            logger.info(f"토큰 레벨 라벨: {len(self.label_mapping['id2label'])}개")
            logger.info(f"민감정보 타입: {len(self.label_mapping['type2id'])}개")
            
        except Exception as e:
            logger.error(f"모델 로딩 실패: {e}")
            # 폴백: 간단한 패턴 매칭으로 대체
            self.model = None
            self.tokenizer = None
            self.device = None
            self.label_mapping = {"id2label": {"0": "0", "1": "1"}, "type2id": {}}
            logger.warning("패턴 매칭 모드로 폴백")
    
    def DetectSensitiveInfo(self, request, context):
        """민감정보 탐지 - 실제 ML 모델 사용"""
        import sys
        print(f"🚀 [PYTHON ML SERVER] 요청 받음: {request.text[:50] if len(request.text) > 50 else request.text}...", flush=True)
        print(f"📥 [PYTHON ML SERVER] 전체 텍스트 길이: {len(request.text)}", flush=True)
        logger.info(f"ML 서버 호출됨: {request.text[:50]}...")
        sys.stdout.flush()
        sys.stderr.flush()
        
        start_time = time.time()
        detections = []
        
        try:
            # ML 모델이 로드된 경우
            if self.model is not None and self.tokenizer is not None:
                # 텍스트를 토큰화하고 모델로 예측
                inputs = self.tokenizer(
                    request.text,
                    return_tensors="pt",
                    truncation=True,
                    padding=True,
                    max_length=256  # 모델이 256으로 훈련됨
                )
                
                # GPU로 이동
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                # 모델 추론 (Token Classification)
                with torch.no_grad():
                    outputs = self.model(**inputs)
                    predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
                    
                    # 토큰별 예측 결과 처리
                    token_predictions = torch.argmax(predictions, dim=-1)
                    token_confidences = torch.max(predictions, dim=-1)[0]
                    
                    # 입력 토큰들 디코딩
                    input_ids = inputs['input_ids'][0]
                    tokens = self.tokenizer.convert_ids_to_tokens(input_ids)
                    
                    # 민감한 토큰들 찾기 (라벨 1 = 민감)
                    sensitive_tokens = []
                    for i, (token_pred, token_conf) in enumerate(zip(token_predictions[0], token_confidences[0])):
                        if token_pred.item() == 1 and token_conf.item() >= 0.5:
                            sensitive_tokens.append({
                                'token': tokens[i],
                                'confidence': token_conf.item(),
                                'position': i
                            })
                    
                    # 민감한 토큰이 있으면 민감정보로 분류
                    if sensitive_tokens:
                        # 텍스트에서 민감정보 패턴 찾기
                        sensitive_patterns = self._get_sensitive_patterns()
                        
                        for pattern_name, pattern in sensitive_patterns.items():
                            matches = re.finditer(pattern, request.text)
                            for match in matches:
                                # 민감한 토큰들의 평균 신뢰도 계산
                                avg_confidence = sum(t['confidence'] for t in sensitive_tokens) / len(sensitive_tokens)
                                
                                detection = dlp_inference_pb2.SensitiveDetection(
                                    category=self._get_category(pattern_name),
                                    type=pattern_name,
                                    value=match.group(),
                                    start_position=match.start(),
                                    end_position=match.end(),
                                    confidence=avg_confidence,
                                    reasoning=f"ML Token Classification: 민감한 토큰 {len(sensitive_tokens)}개 탐지 (평균 신뢰도: {avg_confidence:.3f})",
                                    source="ML_MODEL"
                                )
                                detections.append(detection)
            else:
                # 폴백: 패턴 매칭 사용
                logger.info("패턴 매칭 모드로 탐지")
                sensitive_patterns = self._get_sensitive_patterns()
                
                for pattern_name, pattern in sensitive_patterns.items():
                    matches = re.finditer(pattern, request.text)
                    for match in matches:
                        detection = dlp_inference_pb2.SensitiveDetection(
                            category=self._get_category(pattern_name),
                            type=pattern_name,
                            value=match.group(),
                            start_position=match.start(),
                            end_position=match.end(),
                            confidence=0.8,  # 패턴 매칭 기본 신뢰도
                            reasoning=f"패턴 매칭: {pattern}",
                            source="PATTERN_MATCH"
                        )
                        detections.append(detection)
            
            processing_time = int((time.time() - start_time) * 1000)
            confidence_score = 0.85 if detections else 0.0
            
            response = dlp_inference_pb2.SensitiveInfoResponse(
                detections=detections,
                confidence_score=confidence_score,
                processing_time_ms=processing_time,
                model_version=self.model_version,
                request_id=f"req_{int(time.time())}",
                from_cache=False
            )
            
            logger.info(f"ML 서버 응답: {len(detections)}개 탐지, {processing_time}ms")
            print(f"✅ [PYTHON ML SERVER] 응답 전송: {len(detections)}개 탐지, {processing_time}ms", flush=True)
            sys.stdout.flush()
            return response
            
        except Exception as e:
            logger.error(f"ML 탐지 오류: {e}")
            print(f"❌ [PYTHON ML SERVER] 에러 발생: {e}", flush=True)
            sys.stderr.flush()
            raise
    
    def BatchDetectSensitiveInfo(self, request, context):
        """배치 민감정보 탐지"""
        responses = []
        total_start = time.time()
        
        for text_request in request.requests:
            # 개별 요청 처리
            single_request = dlp_inference_pb2.SensitiveInfoRequest(
                text=text_request.text,
                user_id=text_request.user_id,
                session_id=text_request.session_id,
                categories=text_request.categories,
                include_reasoning=text_request.include_reasoning,
                confidence_threshold=text_request.confidence_threshold
            )
            
            try:
                response = self.DetectSensitiveInfo(single_request, context)
                responses.append(response)
            except Exception as e:
                logger.error(f"배치 처리 중 오류: {e}")
                # 오류 응답 생성
                error_response = dlp_inference_pb2.SensitiveInfoResponse(
                    detections=[],
                    confidence_score=0.0,
                    processing_time_ms=0,
                    model_version=self.model_version,
                    request_id=f"error_{int(time.time())}",
                    from_cache=False
                )
                responses.append(error_response)
        
        total_time = int((time.time() - total_start) * 1000)
        
        return dlp_inference_pb2.BatchSensitiveInfoResponse(
            responses=responses,
            total_processing_time_ms=total_time,
            successful_requests=len([r for r in responses if r.detections]),
            failed_requests=len([r for r in responses if not r.detections])
        )
    
    def HealthCheck(self, request, context):
        """헬스체크"""
        return dlp_inference_pb2.HealthCheckResponse(
            status=dlp_inference_pb2.HealthCheckResponse.SERVING,
            message=f"ML 서버 정상 작동 중 (모델: {self.model_version})",
            timestamp=int(time.time())
        )
    
    def _get_sensitive_patterns(self):
        """민감정보 패턴 정의"""
        return {
            "전화번호": r'\d{3}-\d{4}-\d{4}',
            "주민등록번호": r'\d{6}-\d{7}',
            "이메일": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "카드번호": r'\d{4}-\d{4}-\d{4}-\d{4}',
            "계좌번호": r'\d{3}-\d{2,4}-\d{6}',
        }
    
    def _get_category(self, pattern_name):
        """패턴명을 카테고리로 변환"""
        category_map = {
            "전화번호": "personal_info",
            "주민등록번호": "personal_info", 
            "이메일": "personal_info",
            "카드번호": "financial",
            "계좌번호": "financial",
        }
        return category_map.get(pattern_name, "unknown")

def serve():
    """gRPC 서버 시작"""
    # 모델 경로 설정
    model_path = "../../../../models/DistilBERT_v1"
    
    # 모델 파일 존재 확인
    if not os.path.exists(model_path):
        logger.error(f"모델 경로가 존재하지 않습니다: {model_path}")
        return
    
    # gRPC 서버 옵션 설정 (메시지 크기 제한)
    options = [
        ('grpc.max_send_message_length', 4 * 1024 * 1024),  # 4MB (클라이언트와 일치)
        ('grpc.max_receive_message_length', 4 * 1024 * 1024),  # 4MB (클라이언트와 일치)
    ]
    
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), options=options)
    
    # 서비스 등록
    print(f"🔧 [PYTHON SERVER] Creating DistilBERTDLPService instance...", flush=True)
    sys.stdout.flush()
    service = DistilBERTDLPService(model_path)
    print(f"🔧 [PYTHON SERVER] Registering service to gRPC server...", flush=True)
    sys.stdout.flush()
    dlp_inference_pb2_grpc.add_DLPInferenceServicer_to_server(service, server)
    print(f"✅ [PYTHON SERVER] Service registered successfully", flush=True)
    sys.stdout.flush()
    
    # 포트 바인딩 (IPv4 + IPv6 모두 지원)
    listen_addr = '0.0.0.0:50051'
    server.add_insecure_port(listen_addr)
    
    logger.info(f"ML 서버 시작: {listen_addr}")
    logger.info(f"모델 경로: {model_path}")
    print(f"🚀 [PYTHON SERVER] Starting gRPC server on {listen_addr}", flush=True)
    sys.stdout.flush()
    
    server.start()
    print(f"✅ [PYTHON SERVER] gRPC server started successfully on {listen_addr}", flush=True)
    print(f"✅ [PYTHON SERVER] Server is listening for requests...", flush=True)
    sys.stdout.flush()
    
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("서버 종료 중...")
        print(f"🛑 [PYTHON SERVER] Shutting down...", flush=True)
        sys.stdout.flush()
        server.stop(0)

if __name__ == '__main__':
    serve()

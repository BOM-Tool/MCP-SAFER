#!/usr/bin/env python3
"""
gRPC 서버 헬스체크 스크립트
"""

import sys
import os
import grpc

try:
    import dlp_inference_pb2
    import dlp_inference_pb2_grpc
    
    # gRPC 채널 생성
    channel = grpc.insecure_channel('localhost:50051')
    stub = dlp_inference_pb2_grpc.DLPInferenceStub(channel)
    
    # 헬스체크 요청
    request = dlp_inference_pb2.HealthCheckRequest(service='dlp_inference')
    response = stub.HealthCheck(request, timeout=5)
    
    if response.status == dlp_inference_pb2.HealthCheckResponse.SERVING:
        print("Health check passed")
        sys.exit(0)
    else:
        print("Health check failed")
        sys.exit(1)
        
except Exception as e:
    print(f"Health check error: {e}")
    sys.exit(1)

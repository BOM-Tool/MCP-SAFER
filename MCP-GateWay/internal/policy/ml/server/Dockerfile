FROM python:3.9-slim

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 업데이트 및 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python 의존성 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 서버 코드 복사
COPY ml_inference_server.py .
COPY health_check.py .

# 생성된 Proto 파일들 복사
COPY dlp_inference_pb2.py .
COPY dlp_inference_pb2_grpc.py .

# 포트 노출
EXPOSE 50051

# 서버 실행
CMD ["python", "ml_inference_server.py"]

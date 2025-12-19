# MCP Gateway 리눅스 서버 배포 가이드

## 📋 사전 준비

### 1. 로컬 빌드 (macOS/Linux)

```bash
# 리눅스용 바이너리 빌드
chmod +x build-linux.sh
./build-linux.sh
```

### 2. EC2 서버 준비

#### 필요한 소프트웨어 설치:

```bash
# Python 3.11+ 및 pip
sudo yum install python3 python3-pip -y  # Amazon Linux 2
# 또는
sudo apt-get install python3 python3-pip -y  # Ubuntu

# Python ML 서버 의존성
cd /opt/mcp-gateway/ml-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 모델 파일 배포 (models/DistilBERT_v1)
# S3나 직접 복사
```

## 🚀 배포 방법

### 방법 1: 자동 배포 스크립트 사용

```bash
# 환경 변수 설정
export EC2_HOST="ec2-user@your-instance.com"
export SSH_KEY="~/.ssh/your-key.pem"
export EC2_PATH="/opt/mcp-gateway"

# 배포 실행
chmod +x deploy/ec2-deploy.sh
./deploy/ec2-deploy.sh
```

### 방법 2: 수동 배포

```bash
# 1. 로컬에서 빌드
./build-linux.sh

# 2. 파일을 EC2에 복사
scp -i ~/.ssh/your-key.pem \
    bin/mcp-gateway-linux \
    config-cursor-mitm.yaml \
    ec2-user@your-instance.com:/opt/mcp-gateway/

# 3. EC2에 SSH 접속
ssh -i ~/.ssh/your-key.pem ec2-user@your-instance.com

# 4. 실행 권한 부여
chmod +x /opt/mcp-gateway/mcp-gateway-linux
```

## ⚙️ 서비스 설정 (systemd)

### 1. 서비스 파일 설치

```bash
# EC2 서버에서
sudo cp deploy/mcp-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 2. 서비스 시작

```bash
# 시작
sudo systemctl start mcp-gateway

# 자동 시작 설정
sudo systemctl enable mcp-gateway

# 상태 확인
sudo systemctl status mcp-gateway

# 로그 확인
sudo journalctl -u mcp-gateway -f
```

## 🔧 Python ML 서버 실행

### 방법 1: systemd 서비스로 실행

`deploy/ml-server.service` 파일 생성 (예시):

```ini
[Unit]
Description=ML Inference Server
After=network.target

[Service]
Type=simple
User=mcp
WorkingDirectory=/opt/mcp-gateway/ml-server
ExecStart=/opt/mcp-gateway/ml-server/venv/bin/python ml_inference_server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 방법 2: 직접 실행

```bash
cd /opt/mcp-gateway/ml-server
source venv/bin/activate
python ml_inference_server.py
```

### 방법 3: screen/tmux 사용

```bash
screen -S ml-server
cd /opt/mcp-gateway/ml-server
source venv/bin/activate
python ml_inference_server.py
# Ctrl+A, D로 detach
```

## 📁 디렉토리 구조 (EC2)

```
/opt/mcp-gateway/
├── mcp-gateway              # 메인 바이너리
├── config-cursor-mitm.yaml # 설정 파일
├── certs/                   # SSL 인증서
├── logs/                    # 로그 디렉토리
├── ml-server/               # Python ML 서버
│   ├── ml_inference_server.py
│   ├── venv/
│   └── requirements.txt
└── models/                  # ML 모델 (별도 배포)
    └── DistilBERT_v1/
```

## 🔐 보안 설정

### 1. 사용자 생성 (권장)

```bash
sudo useradd -r -s /bin/false mcp
sudo chown -R mcp:mcp /opt/mcp-gateway
```

### 2. 방화벽 설정

```bash
# HTTP Gateway 포트 (8081)
sudo firewall-cmd --permanent --add-port=8081/tcp

# HTTP Proxy 포트 (8082)
sudo firewall-cmd --permanent --add-port=8082/tcp

# ML 서버 gRPC 포트 (50051)
sudo firewall-cmd --permanent --add-port=50051/tcp

sudo firewall-cmd --reload
```

## 🐛 문제 해결

### 바이너리가 실행되지 않을 때

```bash
# 파일 권한 확인
ls -la /opt/mcp-gateway/mcp-gateway
chmod +x /opt/mcp-gateway/mcp-gateway

# 의존성 확인
ldd /opt/mcp-gateway/mcp-gateway  # 동적 링크 확인 (정적 링크면 필요 없음)
```

### Python ML 서버 연결 실패

```bash
# 포트 확인
netstat -tlnp | grep 50051

# 로그 확인
tail -f /opt/mcp-gateway/logs/*.log
```

### 설정 파일 오류

```bash
# YAML 문법 검증
yamllint config-cursor-mitm.yaml
```

## 📊 모니터링

### 서비스 상태 확인

```bash
# Gateway 상태
sudo systemctl status mcp-gateway

# ML 서버 상태
sudo systemctl status ml-server  # 또는 프로세스 확인
ps aux | grep ml_inference_server
```

### 로그 모니터링

```bash
# 실시간 로그
tail -f /opt/mcp-gateway/logs/*.ndjson

# Journal 로그
sudo journalctl -u mcp-gateway -f
```

## 🔄 업데이트 프로세스

```bash
# 1. 새 버전 빌드
./build-linux.sh

# 2. 서비스 중지
sudo systemctl stop mcp-gateway

# 3. 바이너리 교체
scp bin/mcp-gateway-linux ec2-user@instance:/opt/mcp-gateway/mcp-gateway

# 4. 서비스 재시작
sudo systemctl start mcp-gateway
```


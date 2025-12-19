#!/bin/bash
# EC2 배포 스크립트

set -e

# 설정 (환경에 맞게 수정)
EC2_HOST="${EC2_HOST:-ec2-user@your-ec2-instance.com}"
EC2_PATH="${EC2_PATH:-/opt/mcp-gateway}"
SSH_KEY="${SSH_KEY:-~/.ssh/your-key.pem}"

echo "🚀 Deploying MCP Gateway to EC2..."

# 1. 로컬에서 리눅스 바이너리 빌드
echo "📦 Building Linux binaries..."
./build-linux.sh

# 2. 필수 파일 준비
echo "📁 Preparing deployment package..."
mkdir -p deploy/package
cp bin/mcp-gateway-linux deploy/package/mcp-gateway
cp bin/http-proxy-linux deploy/package/http-proxy
cp config-cursor-mitm.yaml deploy/package/ 2>/dev/null || true
cp -r certs deploy/package/ 2>/dev/null || true

# 3. Python ML 서버 파일 준비
if [ -d "internal/policy/ml/server" ]; then
    echo "📦 Packaging ML server..."
    mkdir -p deploy/package/ml-server
    cp -r internal/policy/ml/server/* deploy/package/ml-server/
    # models 디렉토리는 별도로 배포 필요 (너무 큼)
    echo "⚠️  Note: models/ directory must be deployed separately"
fi

# 4. EC2에 업로드
echo "📤 Uploading to EC2..."
ssh -i "$SSH_KEY" "$EC2_HOST" "mkdir -p $EC2_PATH"
scp -i "$SSH_KEY" -r deploy/package/* "$EC2_HOST:$EC2_PATH/"

# 5. 실행 권한 부여
echo "🔧 Setting permissions..."
ssh -i "$SSH_KEY" "$EC2_HOST" "chmod +x $EC2_PATH/mcp-gateway $EC2_PATH/http-proxy"

# 6. systemd 서비스 파일 배포
echo "⚙️  Installing systemd services..."
if [ -f "deploy/mcp-gateway.service" ]; then
    scp -i "$SSH_KEY" deploy/mcp-gateway.service "$EC2_HOST:/tmp/"
    ssh -i "$SSH_KEY" "$EC2_HOST" "sudo mv /tmp/mcp-gateway.service /etc/systemd/system/"
fi
if [ -f "deploy/http-proxy.service" ]; then
    scp -i "$SSH_KEY" deploy/http-proxy.service "$EC2_HOST:/tmp/"
    ssh -i "$SSH_KEY" "$EC2_HOST" "sudo mv /tmp/http-proxy.service /etc/systemd/system/"
fi
ssh -i "$SSH_KEY" "$EC2_HOST" "sudo systemctl daemon-reload"

echo "✅ Deployment complete!"
echo "📝 Next steps:"
echo "   1. SSH to EC2: ssh -i $SSH_KEY $EC2_HOST"
echo "   2. Start services: sudo systemctl start mcp-gateway http-proxy"
echo "   3. Enable auto-start: sudo systemctl enable mcp-gateway http-proxy"


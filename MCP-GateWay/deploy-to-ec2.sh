#!/bin/bash
# EC2에 파일 전송 스크립트

set -e

# EC2 접속 정보
EC2_HOST="ubuntu@52.78.65.106"
EC2_PATH="/opt/mcp-gateway"
SSH_KEY="/Users/iminhyeog/Desktop/pem/MCP-Gateway.pem"

echo "🚀 Deploying MCP Gateway to EC2..."

# EC2에 디렉토리 생성
echo "📁 Creating directories on EC2..."
ssh -i "$SSH_KEY" "$EC2_HOST" "sudo mkdir -p $EC2_PATH/{certs,pem,logs,models,ml-server} && sudo chown -R ubuntu:ubuntu $EC2_PATH"

# 1. 바이너리 파일 전송
echo "📦 Uploading binaries..."
scp -i "$SSH_KEY" bin/mcp-gateway-linux "$EC2_HOST:/tmp/mcp-gateway"
scp -i "$SSH_KEY" bin/http-proxy-linux "$EC2_HOST:/tmp/http-proxy"
ssh -i "$SSH_KEY" "$EC2_HOST" "sudo mv /tmp/mcp-gateway /tmp/http-proxy $EC2_PATH/ && sudo chmod +x $EC2_PATH/mcp-gateway $EC2_PATH/http-proxy"

# 2. 설정 파일 전송
echo "📝 Uploading config files..."
scp -i "$SSH_KEY" config-cursor-mitm.yaml "$EC2_HOST:$EC2_PATH/"
scp -i "$SSH_KEY" config-http-proxy.yaml "$EC2_HOST:$EC2_PATH/"

# 3. certs 폴더 전송 (있는 경우)
if [ -d "certs" ] && [ "$(ls -A certs 2>/dev/null)" ]; then
    echo "🔐 Uploading certs..."
    scp -i "$SSH_KEY" -r certs/* "$EC2_HOST:$EC2_PATH/certs/" 2>/dev/null || true
fi

# 4. pem 폴더 전송 (MCP-Server.pem 파일)
if [ -f "pem/MCP-Server.pem" ]; then
    echo "🔑 Uploading SSH key..."
    scp -i "$SSH_KEY" pem/MCP-Server.pem "$EC2_HOST:$EC2_PATH/pem/"
    ssh -i "$SSH_KEY" "$EC2_HOST" "chmod 600 $EC2_PATH/pem/MCP-Server.pem"
else
    echo "⚠️  Warning: pem/MCP-Server.pem not found. Please upload manually."
fi

# 5. systemd 서비스 파일 전송
echo "⚙️  Uploading systemd service files..."
scp -i "$SSH_KEY" deploy/mcp-gateway.service "$EC2_HOST:/tmp/"
scp -i "$SSH_KEY" deploy/http-proxy.service "$EC2_HOST:/tmp/"
ssh -i "$SSH_KEY" "$EC2_HOST" "sudo mv /tmp/mcp-gateway.service /tmp/http-proxy.service /etc/systemd/system/ && sudo systemctl daemon-reload"

# 6. models 폴더 전송 (선택적, 크기가 클 수 있음 - 주석 처리)
# models 폴더는 크기가 클 수 있어 별도로 전송하는 것을 권장합니다
# if [ -d "models" ] && [ "$(ls -A models 2>/dev/null)" ]; then
#     echo "🤖 Uploading ML models (this may take a while)..."
#     scp -i "$SSH_KEY" -r models "$EC2_HOST:$EC2_PATH/"
# fi

# 7. ml-server 폴더 전송 (선택적)
if [ -d "internal/policy/ml/server" ]; then
    echo "🐍 Uploading ML server files..."
    ssh -i "$SSH_KEY" "$EC2_HOST" "mkdir -p $EC2_PATH/ml-server"
    scp -i "$SSH_KEY" -r internal/policy/ml/server/*.py "$EC2_HOST:$EC2_PATH/ml-server/" 2>/dev/null || true
    scp -i "$SSH_KEY" -r internal/policy/ml/server/*.txt "$EC2_HOST:$EC2_PATH/ml-server/" 2>/dev/null || true
    scp -i "$SSH_KEY" -r internal/policy/ml/server/*.proto "$EC2_HOST:$EC2_PATH/ml-server/" 2>/dev/null || true
    scp -i "$SSH_KEY" -r internal/policy/ml/server/Dockerfile "$EC2_HOST:$EC2_PATH/ml-server/" 2>/dev/null || true
    # venv는 제외 (EC2에서 새로 생성)
fi

echo "✅ Deployment complete!"
echo ""
echo "📝 Next steps:"
echo "   1. SSH to EC2: ssh -i $SSH_KEY $EC2_HOST"
echo "   2. Edit config files if needed (webserver_url, backend_api_url)"
echo "   3. Start services: sudo systemctl start mcp-gateway http-proxy"
echo "   4. Enable auto-start: sudo systemctl enable mcp-gateway http-proxy"
echo "   5. Check status: sudo systemctl status mcp-gateway http-proxy"


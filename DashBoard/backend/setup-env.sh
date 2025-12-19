#!/bin/bash

# EC2 환경 변수 설정 스크립트
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

echo "=== EC2 환경 변수 설정 ==="
echo ""

# 1. PEM 파일 위치 확인
echo "1. PEM 파일 위치 확인 중..."
PEM_PATHS=(
  "$SCRIPT_DIR/../pem/MCP-Server.pem"
  "$HOME/mcp-safer/DashBoard/pem/MCP-Server.pem"
  "$HOME/test-mcp/DashBoard/pem/MCP-Server.pem"
)

FOUND_PEM=""
for pem_path in "${PEM_PATHS[@]}"; do
  if [ -f "$pem_path" ]; then
    FOUND_PEM="$pem_path"
    echo "  ✓ PEM 파일 발견: $pem_path"
    break
  fi
done

if [ -z "$FOUND_PEM" ]; then
  echo "  ✗ PEM 파일을 찾을 수 없습니다."
  echo "  다음 경로 중 하나에 MCP-Server.pem 파일이 있어야 합니다:"
  for pem_path in "${PEM_PATHS[@]}"; do
    echo "    - $pem_path"
  done
  exit 1
fi

# 2. .env 파일 생성
echo ""
echo "2. .env 파일 생성 중..."

cat > "$ENV_FILE" << EOF
# Backend Server Configuration
PORT=3001

# MCP Registry SSH Configuration
# 중앙 레지스트리 서버 (MCP Registry)
MCP_REGISTRY_SSH_HOST=13.125.27.16
MCP_REGISTRY_SSH_USER=ubuntu
# EC2 환경에서는 절대 경로 사용
MCP_REGISTRY_SSH_KEY=$FOUND_PEM

# Slack Webhook URL (선택사항)
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
EOF

echo "  ✓ .env 파일 생성 완료: $ENV_FILE"
echo ""
echo "3. 생성된 설정 확인:"
grep MCP_REGISTRY_SSH_KEY "$ENV_FILE"
echo ""
echo "설정 완료! 웹서버를 재시작하면 적용됩니다."


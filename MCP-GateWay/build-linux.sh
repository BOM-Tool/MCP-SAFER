#!/bin/bash
# 리눅스용 바이너리 빌드 스크립트

set -e

echo "🔨 Building MCP Gateway for Linux..."

# 빌드 환경 설정
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0  # 정적 링크 (의존성 최소화)

# 바이너리 빌드
echo "📦 Building mcp-gateway..."
go build -ldflags="-s -w" -o bin/mcp-gateway-linux cmd/mcp-proxy/main.go

# http-proxy도 빌드 (필요한 경우)
if [ -f "cmd/http-proxy/main.go" ]; then
    echo "📦 Building http-proxy..."
    go build -ldflags="-s -w" -o bin/http-proxy-linux cmd/http-proxy/main.go
fi

echo "✅ Build complete!"
echo "📁 Output: bin/mcp-gateway-linux"
ls -lh bin/mcp-gateway-linux






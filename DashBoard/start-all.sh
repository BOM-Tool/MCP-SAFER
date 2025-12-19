#!/bin/bash

# 현재 스크립트가 있는 디렉토리로 이동
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "MCP-Safer 전체 서비스 시작 스크립트"
echo "=========================================="

# 프로젝트 루트 디렉토리 (mcp-safer)
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
echo "프로젝트 루트: $PROJECT_ROOT"

# ========== 0. Docker 네트워크 확인 및 생성 ==========
echo ""
echo "0. Docker 네트워크 확인 및 생성 중..."
if ! docker network ls --format '{{.Name}}' | grep -q "^mcp-network$"; then
  echo "  mcp-network 네트워크가 없습니다. 생성 중..."
  docker network create mcp-network 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "  mcp-network 네트워크 생성 완료"
  else
    echo "  [경고] mcp-network 네트워크 생성 실패 (이미 존재할 수 있음)"
  fi
else
  echo "  mcp-network 네트워크 확인 완료"
fi

# docker-compose vs docker compose 확인
if command -v docker-compose &> /dev/null; then
  DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
  DOCKER_COMPOSE_CMD="docker compose"
else
  echo "  [오류] docker-compose 또는 docker compose를 찾을 수 없습니다."
  exit 1
fi
echo "  사용할 명령: $DOCKER_COMPOSE_CMD"

# ========== 1. Docker 컨테이너 확인 및 시작 ==========
echo ""
echo "1. Docker 컨테이너 확인 및 시작 중..."

# MCP-SCAN (bomtool-scanner)
MCP_SCAN_DIR="$PROJECT_ROOT/MCP-SCAN"
if [ -d "$MCP_SCAN_DIR" ]; then
  echo "  [MCP-SCAN] 컨테이너 확인 중..."
  # output 디렉토리 생성 및 권한 설정
  mkdir -p "$MCP_SCAN_DIR/output"
  chmod 777 "$MCP_SCAN_DIR/output"
  if ! docker ps --format '{{.Names}}' | grep -q "^bomtool-scanner$"; then
    echo "  [MCP-SCAN] 컨테이너가 실행 중이 아닙니다. 시작 중..."
    cd "$MCP_SCAN_DIR"
    $DOCKER_COMPOSE_CMD up -d --build
    if [ $? -eq 0 ]; then
      echo "  [MCP-SCAN] 컨테이너 시작 완료: bomtool-scanner"
    else
      echo "  [MCP-SCAN] 컨테이너 시작 실패"
    fi
    cd "$SCRIPT_DIR"
  else
    echo "  [MCP-SCAN] 컨테이너 이미 실행 중: bomtool-scanner"
  fi
else
  echo "  [MCP-SCAN] 디렉토리를 찾을 수 없습니다: $MCP_SCAN_DIR"
fi

# SBOM-SCA (bomtori)
SBOM_SCA_DIR="$PROJECT_ROOT/SBOM-SCA"
if [ -d "$SBOM_SCA_DIR" ]; then
  echo "  [SBOM-SCA] 컨테이너 확인 중..."
  # output 디렉토리 생성 및 권한 설정
  mkdir -p "$SBOM_SCA_DIR/output"
  chmod 777 "$SBOM_SCA_DIR/output"
  if ! docker ps --format '{{.Names}}' | grep -q "^bomtori$"; then
    echo "  [SBOM-SCA] 컨테이너가 실행 중이 아닙니다. 시작 중..."
    cd "$SBOM_SCA_DIR"
    $DOCKER_COMPOSE_CMD up -d --build
    if [ $? -eq 0 ]; then
      echo "  [SBOM-SCA] 컨테이너 시작 완료: bomtori"
      # 컨테이너가 실제로 실행 중인지 확인
      sleep 2
      if docker ps --format '{{.Names}}' | grep -q "^bomtori$"; then
        echo "  [SBOM-SCA] 컨테이너 실행 확인됨"
      else
        echo "  [SBOM-SCA] 경고: 컨테이너가 시작되었지만 실행 중이 아닙니다. 로그 확인: docker logs bomtori"
      fi
    else
      echo "  [SBOM-SCA] 컨테이너 시작 실패"
      echo "  [SBOM-SCA] 오류 상세 정보 확인: cd $SBOM_SCA_DIR && $DOCKER_COMPOSE_CMD logs"
    fi
    cd "$SCRIPT_DIR"
  else
    echo "  [SBOM-SCA] 컨테이너 이미 실행 중: bomtori"
  fi
else
  echo "  [SBOM-SCA] 디렉토리를 찾을 수 없습니다: $SBOM_SCA_DIR"
fi

# TOOL-VET (mcp-vetting)
TOOL_VET_DIR="$PROJECT_ROOT/TOOL-VET"
if [ -d "$TOOL_VET_DIR" ]; then
  echo "  [TOOL-VET] 컨테이너 확인 중..."
  # output 디렉토리 생성 및 권한 설정
  mkdir -p "$TOOL_VET_DIR/output" "$TOOL_VET_DIR/temp_env"
  chmod 777 "$TOOL_VET_DIR/output" "$TOOL_VET_DIR/temp_env"
  # temp_env 디렉토리 소유권을 ubuntu로 변경 (root 소유 문제 해결)
  sudo chown -R ubuntu:ubuntu "$TOOL_VET_DIR/temp_env" 2>/dev/null || chown -R ubuntu:ubuntu "$TOOL_VET_DIR/temp_env" 2>/dev/null || true
  if ! docker ps --format '{{.Names}}' | grep -q "^mcp-vetting$"; then
    echo "  [TOOL-VET] 컨테이너가 실행 중이 아닙니다. 시작 중..."
    cd "$TOOL_VET_DIR"
    $DOCKER_COMPOSE_CMD up -d --build
    if [ $? -eq 0 ]; then
      echo "  [TOOL-VET] 컨테이너 시작 완료: mcp-vetting"
    else
      echo "  [TOOL-VET] 컨테이너 시작 실패"
    fi
    cd "$SCRIPT_DIR"
  else
    echo "  [TOOL-VET] 컨테이너 이미 실행 중: mcp-vetting"
  fi
else
  echo "  [TOOL-VET] 디렉토리를 찾을 수 없습니다: $TOOL_VET_DIR"
fi

# Docker 컨테이너 상태 확인
echo ""
echo "실행 중인 Docker 컨테이너:"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "bomtool-scanner|bomtori|mcp-vetting" || echo "  (없음)"

# ========== 2. 환경 변수 설정 확인 ==========
echo ""
echo "2. 환경 변수 설정 확인 중..."
if [ ! -f "backend/.env" ]; then
  echo "  .env 파일이 없습니다. 자동 생성 중..."
  if [ -f "backend/setup-env.sh" ]; then
    cd backend
    bash setup-env.sh
    cd ..
  else
    echo "  [경고] setup-env.sh를 찾을 수 없습니다. 수동으로 .env를 생성해주세요."
  fi
else
  echo "  .env 파일 확인 완료"
fi

# ========== 3. 기존 웹서버 프로세스 종료 ==========
echo ""
echo "3. 기존 웹서버 프로세스 종료 중..."
pkill -f "nodemon app.js" || pkill -f "node app.js" || true
pkill -f "vite" || true
sleep 2

# ========== 4. 의존성 설치 확인 ==========
echo ""
echo "3. 의존성 설치 확인 중..."

# concurrently 모듈 오류 확인 및 수정
check_concurrently() {
  if [ -d "node_modules/.bin" ] && [ -f "node_modules/.bin/concurrently" ]; then
    # concurrently 실행 테스트
    if ! node node_modules/.bin/concurrently --version >/dev/null 2>&1; then
      return 1
    fi
    # 모듈 require 테스트
    if ! node -e "require('concurrently')" >/dev/null 2>&1; then
      return 1
    fi
  fi
  return 0
}

# 루트 package.json 확인
if [ -f "package.json" ]; then
  if [ ! -d "node_modules" ] || ! check_concurrently; then
    if [ -d "node_modules" ]; then
      echo "  concurrently 모듈 오류 감지. node_modules 정리 중..."
      rm -rf node_modules package-lock.json
    else
      echo "  루트 node_modules 없음."
    fi
    echo "  루트 node_modules 설치 중..."
    npm install
    if [ $? -ne 0 ]; then
      echo "  [오류] npm install 실패. 수동으로 'npm install'을 실행해주세요."
      exit 1
    fi
  else
    echo "  루트 node_modules 확인 완료"
  fi
fi

# 백엔드 의존성 확인
if [ -d "backend" ] && [ -f "backend/package.json" ]; then
  if [ ! -d "backend/node_modules" ]; then
    echo "  백엔드 node_modules 없음. 설치 중..."
    cd backend
    npm install
    cd ..
  else
    echo "  백엔드 node_modules 확인 완료"
  fi
fi

# 프론트엔드 의존성 확인
if [ -d "frontend" ] && [ -f "frontend/package.json" ]; then
  if [ ! -d "frontend/node_modules" ]; then
    echo "  프론트엔드 node_modules 없음. 설치 중..."
    cd frontend
    npm install
    cd ..
  else
    echo "  프론트엔드 node_modules 확인 완료"
  fi
fi

# ========== 5. 웹서버 시작 ==========
echo ""
echo "4. 웹서버 시작 중..."
echo "  프론트엔드와 백엔드를 동시에 실행합니다."
echo "  종료하려면 Ctrl+C를 누르세요."
echo ""

# npm run dev 실행 (concurrently 사용)
npm run dev


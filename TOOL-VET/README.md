# TOOL-VET

MCP 서버의 Tool(도구)을 동적으로 분석하여 MCP 특화 보안 취약점을 검증하는 도구입니다.

## 주요 기능

- **동적 분석 (DAST)**: MCP 서버를 실제로 실행하여 Tool의 동작을 분석
- **Sandbox 환경 실행**: 격리된 환경에서 MCP 서버를 실행하여 안전하게 분석
- **런타임 자동 감지**: Go 또는 npm 프로젝트를 자동으로 감지하고 실행
- **프록시 기반 HTTP 캡처**: mitmproxy를 통해 Tool이 호출하는 외부 API 요청 캡처
- **MCP 특화 취약점 탐지**:
  - **MCP-01: AI Tool Selection Risk**: AI가 위험한 도구를 선택할 위험성
  - **MCP-02: Context Injection Risk**: AI가 주입한 컨텍스트가 검증 없이 사용되는 위험성
  - **MCP-03: Autonomous Execution Risk**: AI가 사용자 확인 없이 자율적으로 실행하는 위험성
  - **MCP-04: Tool Combination Risk**: 여러 도구를 조합할 때 발생하는 위험성
- **취약점 검증**: 실제 HTTP 요청을 통해 발견된 취약점을 검증

## 요구사항

### Docker 실행
- Docker
- Docker Compose

### 로컬 실행
- Python 3.12+
- Go 1.23+ (Go 프로젝트 분석 시)
- Node.js 및 npm (npm 프로젝트 분석 시)
- mitmproxy

## Docker로 실행하기

### 1. docker-compose 사용

```bash
# 컨테이너 빌드 및 실행
docker-compose up -d

# 컨테이너에 접속
docker exec -it mcp-vetting bash

# 컨테이너 내에서 분석 실행
python main.py --git-url https://github.com/user/repo.git --output-dir ./output
```

### 2. Docker 직접 사용

```bash
# 이미지 빌드
docker build -t tool-vet .

# 컨테이너 실행
docker run --rm -v "$(pwd)/output:/app/output" tool-vet \
  --git-url https://github.com/user/repo.git \
  --output-dir ./output
```

### 3. 환경 변수 설정 (필요 시)

분석하려는 MCP 서버가 인증 토큰 등 환경 변수가 필요한 경우:

```bash
# .env 파일 생성
echo "NOTION_TOKEN=your_token_here" > .env
echo "GITHUB_TOKEN=your_token_here" >> .env

# docker-compose.yml에서 environment 섹션 주석 해제 및 수정
# 또는 Docker run 시 환경 변수 전달
docker run --rm \
  -v "$(pwd)/output:/app/output" \
  -v "$(pwd)/.env:/app/.env" \
  tool-vet \
  --git-url https://github.com/user/repo.git \
  --output-dir ./output \
  --env-file .env
```

## 로컬에서 실행하기

### 1. 의존성 설치

```bash
# Python 패키지 설치
pip install mitmproxy requests pyyaml

# Go 설치 (Go 프로젝트 분석 시)
# https://go.dev/dl/ 에서 다운로드

# Node.js 및 npm 설치 (npm 프로젝트 분석 시)
# https://nodejs.org/ 에서 다운로드
```

### 2. 실행

```bash
# 기본 실행 (output 디렉토리에 결과 저장)
python main.py --git-url https://github.com/user/repo.git

# 출력 디렉토리 지정
python main.py --git-url https://github.com/user/repo.git --output-dir ./results

# 특정 브랜치 분석
python main.py --git-url https://github.com/user/repo.git --branch main

# 환경 변수 파일 지정
python main.py --git-url https://github.com/user/repo.git --env-file .env

# MCP 서버 실행 시 추가 인자 전달
python main.py --git-url https://github.com/user/repo.git --server-args "--toolsets all"
```

## 명령어 옵션

- `--git-url` (필수): 분석할 MCP 서버의 Git 저장소 URL
- `--branch`: Git 브랜치 또는 태그 (예: `main`, `v1.0.0`, `develop`)
- `--output-dir`: 분석 결과를 저장할 디렉터리 (기본값: `./output`)
- `--env-file`: 환경 변수 파일 경로 (기본값: `.env`)
- `--server-args`: MCP 서버 실행 시 추가할 인자 (예: `--toolsets all`)
- `--auto`: 런타임 자동 감지 및 실행 (기본값: `True`)

## 출력 파일

분석이 완료되면 다음 파일이 생성됩니다:

- `{repo-name}-report.json`: MCP 특화 취약점 리포트
  - 취약점 목록 (MCP-01 ~ MCP-04)
  - 각 취약점의 상세 설명 및 증거
  - API 엔드포인트 정보 및 호출 방법 (curl 명령어)
  - Tool과 API의 연관성 분석
  - 취약점별 수정 권장사항

## MCP 특화 취약점 상세

### MCP-01: AI Tool Selection Risk
AI가 위험한 도구(삭제, 관리자 기능 등)를 선택할 위험성을 탐지합니다.

### MCP-02: Context Injection Risk
AI가 주입한 컨텍스트가 검증 없이 API 경로나 파라미터로 직접 사용되는 위험성을 탐지합니다.

### MCP-03: Autonomous Execution Risk
AI가 사용자 확인 없이 자율적으로 수정/삭제 작업을 실행하는 위험성을 탐지합니다.

### MCP-04: Tool Combination Risk
여러 도구를 조합할 때 발생할 수 있는 위험성을 탐지합니다.

## 예제

```bash
# GitHub 저장소 분석
python main.py --git-url https://github.com/makenotion/notion-mcp-server.git

# 특정 브랜치 분석 및 출력 디렉토리 지정
python main.py \
  --git-url https://github.com/user/repo.git \
  --branch main \
  --output-dir ./my-results

# Docker 사용
docker run --rm \
  -v "$(pwd)/output:/app/output" \
  tool-vet \
  --git-url https://github.com/user/repo.git \
  --output-dir ./output
```

## 지원하는 프로젝트 타입

- **Go**: Go modules 사용 프로젝트
- **npm**: package.json이 있는 Node.js/TypeScript 프로젝트

## 라이선스

MIT License


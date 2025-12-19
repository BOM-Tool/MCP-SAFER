# SBOM-SCA

Software Bill of Materials (SBOM) 생성 및 오픈소스 취약점 분석 도구

## 주요 기능

- **SBOM 생성**: CycloneDX 형식의 SBOM 생성 (Go, npm 프로젝트 지원)
- **의존성 분석**: 직접 의존성 및 간접 의존성(transitive dependencies) 분석
- **취약점 분석**:
  - Go 프로젝트: `govulncheck`를 사용한 취약점 탐지
  - npm 프로젝트: `npm audit`을 사용한 취약점 탐지
- **Call Graph 분석**: SSA IR 기반 호출 그래프 분석으로 취약점 도달 가능성 확인
- **Reachability Analysis**: 취약점이 있는 패키지가 실제 코드에서 호출되는지 분석

## 요구사항

### Docker 실행
- Docker
- Docker Compose

### 로컬 실행
- Python 3.8+
- Go 1.18+
- Node.js 18+
- npm 또는 pnpm

## Docker로 실행하기

### 1. 이미지 빌드 및 컨테이너 실행

```bash
# docker-compose 사용
docker-compose up -d

# 또는 Docker 직접 사용
docker build -t sbom-sca .
docker run --rm -v "$(pwd)/output:/app/output" sbom-sca \
  https://github.com/user/repo.git \
  --output-dir ./output
```

### 2. 컨테이너 내에서 실행

```bash
# 컨테이너에 접속
docker exec -it sbom-sca bash

# 컨테이너 내에서 실행
python3 main.py https://github.com/user/repo.git --output-dir ./output
```

### 3. 컨테이너에서 직접 실행

```bash
docker exec -it sbom-sca python3 main.py \
  https://github.com/user/repo.git \
  --output-dir ./output
```

## 로컬에서 실행하기

### 1. 의존성 설치

```bash
# Python 패키지 설치
pip install -r SBOM/requirements.txt

# npm 패키지 설치 (Call Graph 분석용)
npm ci --prefix SCA/callGraph/npm

# Go 도구 설치 (Go 프로젝트 분석용)
go install golang.org/x/vuln/cmd/govulncheck@latest
```

### 2. 실행

```bash
# 기본 실행 (output 디렉토리에 결과 저장)
python3 main.py https://github.com/user/repo.git

# 출력 디렉토리 지정
python3 main.py https://github.com/user/repo.git --output-dir ./results
```

## 출력 파일

분석이 완료되면 다음 파일들이 생성됩니다:

- `{repo-name}-sbom.cdx.json`: CycloneDX 형식의 SBOM 파일
- `{repo-name}-metadata.json`: 프로젝트 메타데이터
- `{repo-name}-summary.json`: 분석 요약
- `{repo-name}-reachability.json`: 취약점 도달 가능성 정보
- `{repo-name}-dashboard.json`: 대시보드용 JSON 데이터

## 예제

```bash
# GitHub 저장소 분석
python3 main.py https://github.com/makenotion/notion-mcp-server.git

# 출력 디렉토리 지정
python3 main.py https://github.com/user/repo.git --output-dir ./my-results

# Docker 사용
docker run --rm -v "$(pwd)/output:/app/output" sbom-sca \
  https://github.com/user/repo.git \
  --output-dir ./output
```

## 지원하는 프로젝트 타입

- **Go**: Go modules 사용 프로젝트
- **npm**: package.json이 있는 Node.js/TypeScript 프로젝트

## 라이선스

MIT License


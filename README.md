# MCP-Safer

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![React](https://img.shields.io/badge/React-19.1.1-blue.svg)
![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Go](https://img.shields.io/badge/Go-1.18+-00ADD8.svg)

MCP AI Agent 위험관리 점검 도구

## ☁️ 클라우드 배포 (AWS EC2)

### 1. EC2 인스턴스 생성

- Ubuntu 22.04 LTS 인스턴스 생성 (최소 t3.medium 권장)
- 보안 그룹 설정: HTTP (80), HTTPS (443), SSH (22)

### 2. 서버 접속 및 배포

```bash
# SSH로 서버 접속
ssh -i your-key.pem ubuntu@your-ec2-ip

# Docker 및 Docker Compose 설치
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git nodejs npm
sudo usermod -aG docker $USER
newgrp docker

# 프로젝트 클론
git clone https://github.com/BOM-Tool/MCP-SAFER.git
cd MCP-SAFER

# PEM 키 파일 설정 (MCP Registry 서버 접속 기능 사용 시 필요)
# MCP Registry 서버에 서버를 등록하는 기능을 사용하려면 PEM 키가 필요합니다
mkdir -p DashBoard/pem
# PEM 키 파일을 DashBoard/pem/MCP-Server.pem에 복사 (scp 또는 직접 업로드)
# 예: scp -i your-key.pem MCP-Server.pem ubuntu@your-ec2-ip:/home/ubuntu/MCP-SAFER/DashBoard/pem/MCP-Server.pem
chmod 400 DashBoard/pem/MCP-Server.pem

# 배포 실행
cd DashBoard
chmod +x start-all.sh
./start-all.sh
```

### 3. 접속

- **Dashboard**: `http://your-ec2-ip:80` 또는 `http://your-ec2-ip:5173`
- **Backend API**: `http://your-ec2-ip:3001/api`

## 📦 모듈 구조

```
MCP-SAFER/
├── DashBoard/          # 웹 대시보드 (Frontend + Backend)
├── MCP-SCAN/          # 코드 스캔 모듈
├── SBOM-SCA/          # SBOM 생성 및 취약점 분석
├── TOOL-VET/          # 도구 검증 모듈
└── MCP-GateWay/       # 게이트웨이
```

## 🔧 주요 기능

### Dashboard
- MCP 서버 등록 및 관리
- 위험도 분석 결과 조회
- 취약점 리포트 확인

### MCP-SCAN (정적 코드 분석)

MCP-SCAN은 MCP 서버의 소스 코드를 정적 분석하여 보안 취약점을 탐지하는 도구입니다.

**주요 기능:**
- **정적 코드 분석 (SAST)**: 소스 코드를 실행하지 않고 코드 자체를 분석하여 취약점 탐지
- **다중 언어 지원**: Go, TypeScript, JavaScript 지원
- **일반 보안 취약점 탐지**: Command Injection, Path Traversal, SSRF (Server-Side Request Forgery), Open Redirect
- **MCP 특화 취약점 탐지**:
  - Config Poisoning: 악의적인 설정 값 주입 (데이터 유출, 인증 우회, 권한 상승 등)
  - Tool Poisoning: Tool의 입력값을 조작하여 공격
  - Tool Name Spoofing: Tool 이름을 위조하여 혼란 유도
  - Tool Shadowing: 동일한 이름의 Tool로 인한 충돌
  - Toxic Flow: 위험한 데이터 흐름 탐지
- **위험도 점수 산정**: 발견된 취약점을 기반으로 서버의 전체 위험도 점수 계산

**분석 결과:**
- 취약점 유형 및 심각도 (CWE 매핑)
- 취약점 위치 (파일 경로, 라인 번호)
- 취약점 설명 및 수정 권장사항
- 서버 전체 위험도 점수

### SBOM-SCA (SBOM 생성 및 오픈소스 취약점 분석)

SBOM-SCA는 Software Bill of Materials (SBOM)를 생성하고 오픈소스 라이브러리의 취약점을 분석하는 도구입니다.

**주요 기능:**
- **SBOM 생성**: CycloneDX 형식의 SBOM 생성 (Go, npm 프로젝트 지원)
- **의존성 분석**: 직접 의존성 및 간접 의존성(transitive dependencies) 분석
- **취약점 분석**:
  - Go 프로젝트: `govulncheck`를 사용한 취약점 탐지
  - npm 프로젝트: `npm audit`을 사용한 취약점 탐지
- **Call Graph 분석**: 코드의 호출 그래프를 분석하여 취약점이 실제로 사용되는지 확인 (Reachability Analysis)
- **취약점 도달 가능성 분석**: 취약점이 있는 패키지가 실제 코드에서 호출되는지 분석
- **대시보드 데이터 생성**: 취약점 정보를 시각화하기 위한 대시보드 데이터 생성

**분석 결과:**
- CycloneDX 형식의 SBOM 파일
- 프로젝트 메타데이터 (총 컴포넌트 수, 직접/간접 의존성 수)
- 취약점 목록 (CVE ID, 심각도, 설명)
- 취약점 도달 가능성 정보 (Reachability)
- 대시보드용 JSON 데이터

### TOOL-VET (MCP Tool 보안 검증)

TOOL-VET은 MCP 서버의 Tool(도구)을 동적으로 분석하여 MCP 특화 보안 취약점을 검증하는 도구입니다.

**주요 기능:**
- **동적 분석 (DAST)**: MCP 서버를 실제로 실행하여 Tool의 동작을 분석
- **Sandbox 환경 실행**: 격리된 환경에서 MCP 서버를 실행하여 안전하게 분석
- **런타임 자동 감지**: Go 또는 npm 프로젝트를 자동으로 감지하고 실행
- **프록시 기반 HTTP 캡처**: mitmdump를 통해 Tool이 호출하는 외부 API 요청 캡처
- **MCP 특화 취약점 탐지**:
  - **MCP-01: AI Tool Selection Risk**: AI가 위험한 도구를 선택할 위험성
  - **MCP-02: Context Injection Risk**: AI가 주입한 컨텍스트가 검증 없이 사용되는 위험성
  - **MCP-03: Autonomous Execution Risk**: AI가 사용자 확인 없이 자율적으로 실행하는 위험성
  - **MCP-04: Tool Combination Risk**: 여러 도구를 조합할 때 발생하는 위험성
- **취약점 검증**: 실제 HTTP 요청을 통해 발견된 취약점을 검증

**분석 결과:**
- MCP 특화 취약점 목록 (MCP-01 ~ MCP-04)
- 각 취약점의 상세 설명 및 증거
- API 엔드포인트 정보 및 호출 방법 (curl 명령어)
- Tool과 API의 연관성 분석
- 취약점별 수정 권장사항

### MCP-GateWay (MCP 프록시 및 DLP)

MCP-GateWay는 MCP(Model Context Protocol)를 안전하게 이용하기 위한 HTTP Proxy와 MCP Proxy를 제공하는 게이트웨이입니다.

**주요 기능:**
- **MCP Proxy**: MCP 서버에 대한 프록시 및 라우팅 제공
  - SSE (Server-Sent Events) 연결 프록시
  - stdio 연결 프록시
  - HTTP 기반 MCP 통신 프록시
- **HTTP Proxy**: HTTPS 트래픽 복호화 및 DLP(Data Loss Prevention) 기능
  - MITM SSL Interception을 통한 HTTPS 트래픽 분석
  - 요청/응답 로깅 및 모니터링
- **DLP (Data Loss Prevention)**: AI 기반 민감 정보 탐지 및 마스킹
  - AI 기반 민감 정보 자동 탐지
  - 실시간 데이터 마스킹 처리
  - 정책 기반 필터링 및 차단

**주요 포트:**
- **MCP Proxy**: `:8081` - MCP 서버 프록시
- **HTTP Proxy**: `:8082` - HTTPS 트래픽 분석 및 DLP

## 📝 기본 계정

배포 후 다음 계정으로 로그인:

- **관리자**: `admin` / `admin`
- **일반 사용자**: `user` / `user`

> ⚠️ **보안**: 배포 후 반드시 기본 비밀번호를 변경하세요!

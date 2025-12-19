# MCP Gateway

MCP(Model Context Protocol)를 안전하게 이용하기 위한 HTTP Proxy와 MCP Proxy를 제공하는 Gateway입니다.

## 주요 기능

- **MCP Proxy**: MCP 서버에 대한 프록시 및 라우팅 제공
- **HTTP Proxy**: HTTPS 트래픽 복호화 및 DLP(Data Loss Prevention) 기능
- **DLP**: AI 기반 민감 정보 탐지 및 마스킹

## 아키텍처

```
┌─────────────┐
│   Client    │
│  (Cursor)   │
└──────┬──────┘
       │
       │ HTTP/SSE/stdio
       │
┌──────▼─────────────────────────────────────┐
│         MCP Proxy (:8081)                  │
│  - /sse/{server_id}                        │
│  - /stdio/{server_id}                      │
│  - /mcp/{server_id}                        │
└──────┬─────────────────────────────────────┘
       │
       │ SSH/HTTP/SSE
       │
┌──────▼─────────────────────────────────────┐
│         MCP Servers                         │
│  (GitHub, Database, etc.)                  │
└─────────────────────────────────────────────┘

┌─────────────┐
│   Client    │
│  (Browser)  │
└──────┬──────┘
       │
       │ HTTP/HTTPS
       │
┌──────▼─────────────────────────────────────┐
│      HTTP Proxy (:8082)                     │
│  - MITM SSL Interception                    │
│  - DLP Detection & Masking                 │
│  - Request/Response Logging                 │
└──────┬─────────────────────────────────────┘
       │
       │ Decrypted Traffic
       │
┌──────▼─────────────────────────────────────┐
│      Backend Services                       │
│  (AI APIs, Web Services)                   │
└─────────────────────────────────────────────┘
```

## 빌드

### 로컬 빌드

```bash
# MCP Proxy 빌드
go build -o bin/mcp-proxy cmd/mcp-proxy/main.go

# HTTP Proxy 빌드
go build -o bin/http-proxy cmd/http-proxy/main.go
```

### Linux 배포용 빌드

```bash
./build-linux.sh
```

빌드된 바이너리:
- `bin/mcp-gateway-linux` - MCP Proxy
- `bin/http-proxy-linux` - HTTP Proxy

## 설정

### MCP Proxy 설정 (`config-cursor-mitm.yaml`)

```yaml
# MCP Gateway 설정
gateway:
  listen: ":8081"
  log_dir: "./logs"

mcp_proxy:
  # 웹서버 URL (서버 정보 조회용)
  webserver_url: "http://localhost:3001"  # 로컬 개발용
  ip_auth_enabled: true                    # IP 기반 인증 활성화
  api_key: ""                              # 웹서버 API 키 (선택적)
  bypass_proxy: true                       # HTTP Proxy 우회 (직접 연결)

ssh:
  key_path: "key_path"
  user: "user"
```

### HTTP Proxy 설정 (`config-http-proxy.yaml`)

```yaml
# HTTP Proxy 설정 (8082)
http_proxy:
  enabled: true
  port: ":8082"
  log_dir: "./logs"
  enable_mitm: true                        # HTTPS 트래픽 복호화 활성화
  ca_cert_file: "ca_cert_file"
  ca_key_file: "ce_key_file"
  force_http_1_1: true                     # HTTP/1.1 강제
  verbose_logging: true                    # 상세 로깅
  ai_only: false                           # 모든 트래픽 로깅
  decode_protobuf: true                    # Protobuf에서 텍스트 추출
  backend_api_url: "http://localhost:3001" # DLP 로그 백엔드 URL
  dlp_api_key: "default-dlp-api-key-change-in-production"

# AI 모델 설정
ai_model:
  enabled: true
  model_path: "./models/DistilBERT_v1"
  fallback_to_patterns: true
  confidence_threshold: 0.7
```

## 사용법

### MCP Proxy 실행

```bash
# 기본 설정 파일 사용
./bin/mcp-proxy

# 커스텀 설정 파일 지정
./bin/mcp-proxy -config config-cursor-mitm.yaml
```

**엔드포인트:**
- `GET/POST /health` - 헬스 체크
- `GET /sse/{server_id}` - SSE 스트리밍
- `POST /stdio/{server_id}` - Streamable HTTP (stdio over HTTP)
- `POST /mcp/{server_id}` - JSON-RPC over HTTP

**예시 (Cursor `mcp.json` 설정):**
```json
{
  "mcpServers": {
    "github-central": {
      "url": "http://localhost:8081/stdio/github-central"
    }
  }
}
```

### HTTP Proxy 실행

```bash
# YAML 설정 파일 사용 (권장)
./bin/http-proxy -config config-http-proxy.yaml
```

**프록시 설정 (settings.json):**

```json
{
    "http.proxy": "http://127.0.0.1:8082",
    "https.proxy": "http://127.0.0.1:8082",
    "http.proxyStrictSSL": false,
    "http.proxySupport": "on",
    "http.proxyAuthorization": null,
    "cursor.general.disableHttp2": true,
}
```


**CA 인증서 설치:**
MITM 기능을 사용하려면 CA 인증서를 시스템에 설치해야 합니다:


## MCP 서버 등록

MCP 서버는 웹서버의 데이터베이스에 등록되어야 합니다.

**등록 API 예시:**
```bash
curl -X POST http://localhost:3001/api/mcp/servers \
  -H "Content-Type: application/json" \
  -d '{
    "server_id": "github-central",
    "name": "GitHub MCP Server",
    "type": "ssh",
    "ssh_host": "host_address",
    "ssh_user": "ubuntu",
    "ssh_key": "ssh_key",
    "command": "/host_address/github-mcp-server/cmd/github-mcp-server/mcp-server",
    "args": ["stdio"],
    "env": {
      "GITHUB_PERSONAL_ACCESS_TOKEN": "your-token"
    },
    "mcp_server_id": 1
  }'
```

## DLP (Data Loss Prevention)

HTTP Proxy는 AI 기반 DLP 기능을 제공합니다:

- **AI 모델**: DistilBERT 기반 민감 정보 탐지
- **패턴 매칭**: 정규식 기반 폴백 탐지
- **자동 마스킹**: 탐지된 민감 정보 자동 마스킹
- **로그 전송**: 백엔드 API로 DLP 이벤트 전송

**지원하는 민감 정보 유형:**
- 신용카드 번호
- 주민등록번호
- 이메일 주소
- 전화번호
- API 키/토큰
- 기타 사용자 정의 패턴



## 로그

로그는 `./logs/` 디렉토리에 저장됩니다:

- `mcp-proxy.ndjson` - MCP Proxy 로그
- `http-proxy-*.log` - HTTP Proxy 로그

## 문제 해결

### MCP Proxy 연결 실패

1. 웹서버가 실행 중인지 확인
2. `webserver_url` 설정 확인
3. 서버가 DB에 등록되어 있는지 확인
4. SSH 키 경로 및 권한 확인

### HTTP Proxy MITM 실패

1. CA 인증서가 설치되어 있는지 확인
2. 인증서 파일 경로 확인 (`ca_cert_file`, `ca_key_file`)
3. 브라우저/시스템 프록시 설정 확인



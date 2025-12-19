# github-central 서버 DB 등록 예시

## 현재 상황

- **중앙 MCP Server 저장소**: `15.164.213.161`
- **SSH 접속**: `ubuntu@15.164.213.161`
- **서버 경로**: `/home/ubuntu/github-mcp-server`
- **실행 파일**: `/home/ubuntu/github-mcp-server/cmd/github-mcp-server/mcp-server`
- **실행 인자**: `["stdio"]`
- **환경 변수**: `GITHUB_PERSONAL_ACCESS_TOKEN`

## DB에 저장할 데이터

### API: POST /api/mcp/servers (또는 웹 UI에서 등록)

**요청 본문:**
```json
{
  "server_id": "github-central",
  "name": "GitHub MCP Server",
  "type": "ssh",
  "ssh_host": "15.164.213.161",
  "ssh_user": "ubuntu",
  "ssh_key": "/path/to/MCP-Server.pem",
  "command": "/home/ubuntu/github-mcp-server/cmd/github-mcp-server/mcp-server",
  "args": ["stdio"],
  "env": {
    "GITHUB_PERSONAL_ACCESS_TOKEN": "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"
  },
  "mcp_server_id": 1
}
```

### 필드 설명

| 필드 | 값 | 설명 |
|------|-----|------|
| `server_id` | `"github-central"` | 개발자가 `mcp.json`에서 사용할 서버 ID |
| `name` | `"GitHub MCP Server"` | 서버 표시 이름 (선택적) |
| `type` | `"ssh"` | 서버 타입 (ssh, local, http, sse) |
| `ssh_host` | `"15.164.213.161"` | SSH 호스트 IP 또는 도메인 |
| `ssh_user` | `"ubuntu"` | SSH 사용자명 |
| `ssh_key` | `"/path/to/MCP-Server.pem"` | **Proxy 서버에 있는 SSH 키 파일 경로** | >> /Users/iminhyeog/Desktop/pem/MCP-Server.pem
| `command` | `"/home/ubuntu/github-mcp-server/cmd/github-mcp-server/mcp-server"` | 원격 서버에서 실행할 명령어 (절대 경로) |
| `args` | `["stdio"]` | 명령어 인자 배열 |
| `env` | `{ "GITHUB_PERSONAL_ACCESS_TOKEN": "..." }` | 환경 변수 (키-값 쌍) |
| `mcp_server_id` | `1` | 웹서버 DB의 `mcp_servers.id` (권한 체크용) |

## 중요 사항

### 1. SSH 키 경로 주의

**`ssh_key` 필드는 Proxy 서버에 있는 SSH 키 파일 경로입니다:**

- ❌ 원격 서버 경로 아님
- ✅ Proxy 서버 (중앙 서버)의 절대 경로

**예시:**
- 로컬 개발 환경: `/Users/iminhyeog/Desktop/pem/MCP-Server.pem`
- 운영 환경 (Proxy 서버): `/opt/mcp-gateway/keys/MCP-Server.pem` 또는 `/home/ubuntu/.ssh/mcp-server-key.pem`

**권장:** Proxy 서버에 SSH 키를 고정 위치에 배치하고 해당 경로를 DB에 저장

### 2. 환경 변수 보안

**민감한 정보 (토큰 등)는 환경 변수로 관리하는 것을 권장:**

```json
{
  "env": {
    "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"
  }
}
```

또는 웹서버에서 환경 변수를 읽어서 주입:

```json
{
  "env": {
    "GITHUB_PERSONAL_ACCESS_TOKEN": "#{read_from_secret_store('github_token')}"
  }
}
```

### 3. 전체 예시 (실제 사용 가능)

```json
{
  "server_id": "github-central",
  "name": "GitHub MCP Server",
  "type": "ssh",
  "ssh_host": "15.164.213.161",
  "ssh_user": "ubuntu",
  "ssh_key": "/opt/mcp-gateway/keys/MCP-Server.pem",
  "command": "/home/ubuntu/github-mcp-server/cmd/github-mcp-server/mcp-server",
  "args": ["stdio"],
  "env": {
    "GITHUB_PERSONAL_ACCESS_TOKEN": "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"
  },
  "mcp_server_id": 1
}
```

## 테스트

### 1. DB에 등록 후

**개발자 `mcp.json`:**
```json
{
  "mcpServers": {
    "github-central": {
      "url": "http://localhost:8081/stdio/github-central"
    }
  }
}
```

### 2. Proxy가 요청 처리

```
Client 요청: POST /stdio/github-central
  → Proxy가 server_id 추출: "github-central"
  → DB 조회: GET /api/mcp/servers/github-central
  → SSH 연결 정보 획득
  → SSH 명령어 실행:
     ssh -i /opt/mcp-gateway/keys/MCP-Server.pem \
         -T \
         ubuntu@15.164.213.161 \
         '/home/ubuntu/github-mcp-server/cmd/github-mcp-server/mcp-server stdio'
  → MCP 프로토콜 메시지 중계
```

## SQL 예시 (직접 DB에 삽입하는 경우)

```sql
INSERT INTO mcp_servers (
  server_id,
  name,
  type,
  ssh_host,
  ssh_user,
  ssh_key,
  command,
  args,
  env,
  mcp_server_id
) VALUES (
  'github-central',
  'GitHub MCP Server',
  'ssh',
  '15.164.213.161',
  'ubuntu',
  '/opt/mcp-gateway/keys/MCP-Server.pem',
  '/home/ubuntu/github-mcp-server/cmd/github-mcp-server/mcp-server',
  '["stdio"]'::jsonb,
  '{"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..."}'::jsonb,
  1
);
```

## 검증

등록 후 Proxy 로그에서 확인:
```
[DB Lookup] Fetching server config from http://localhost:3001/api/mcp/servers/github-central
[DB Lookup] Successfully fetched server config for github-central (type: ssh)
Created session stdio-http-github-central for server github-central
```

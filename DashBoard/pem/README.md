# PEM 키 폴더

이 폴더에 SSH 접속에 필요한 PEM 키 파일을 저장하세요.

## 필요한 파일

- `MCP-Server.pem`: MCP Registry 서버(15.164.213.161 또는 15.165.223.28) 접속용 키

## 파일 권한 설정

PEM 키 파일의 권한을 올바르게 설정해야 합니다:

```bash
chmod 400 pem/MCP-Server.pem
```

## 환경 변수로 오버라이드

`.env` 파일에서 환경 변수로 PEM 키 경로를 지정할 수 있습니다:

```bash
MCP_REGISTRY_SSH_KEY=/path/to/your/key.pem
```

환경 변수가 설정되지 않으면 기본적으로 `pem/MCP-Server.pem`을 사용합니다.

## 보안 주의사항

- PEM 키 파일은 절대 Git에 커밋하지 마세요
- `.gitignore`에 `pem/*.pem`을 추가하세요
- 프로덕션 환경에서는 환경 변수를 사용하는 것을 권장합니다


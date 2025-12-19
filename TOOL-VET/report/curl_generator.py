"""cURL 명령어 생성 유틸리티"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, quote


def generate_curl_command(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> str:
    """HTTP 요청을 cURL 명령어로 변환"""
    parts = ["curl"]
    
    # URL 인용 처리
    quoted_url = quote(url, safe=":/?#[]@!$&'()*+,;=")
    parts.append(f'"{quoted_url}"')
    
    # HTTP 메서드
    if method.upper() != "GET":
        parts.append(f"-X {method.upper()}")
    
    # 헤더
    if headers:
        for key, value in headers.items():
            # 헤더 값에 특수문자가 있으면 이스케이프
            escaped_value = value.replace('"', '\\"')
            parts.append(f'-H "{key}: {escaped_value}"')
    
    # 쿠키
    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        parts.append(f'-H "Cookie: {cookie_str}"')
    
    # 데이터 (POST, PUT, PATCH 등)
    if data and method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        if isinstance(data, str):
            # JSON 문자열인 경우
            try:
                import json
                json.loads(data)  # JSON 유효성 검사
                escaped_data = data.replace('"', '\\"').replace('$', '\\$')
                parts.append(f'-d "{escaped_data}"')
            except (json.JSONDecodeError, ValueError):
                # 일반 문자열인 경우
                escaped_data = data.replace('"', '\\"').replace('$', '\\$')
                parts.append(f'--data-raw "{escaped_data}"')
        elif isinstance(data, dict):
            # 딕셔너리인 경우 JSON으로 변환
            import json
            json_data = json.dumps(data, ensure_ascii=False)
            escaped_data = json_data.replace('"', '\\"').replace('$', '\\$')
            parts.append(f'-d "{escaped_data}"')
        else:
            # 기타 타입
            escaped_data = str(data).replace('"', '\\"').replace('$', '\\$')
            parts.append(f'--data-raw "{escaped_data}"')
    
    return " \\\n  ".join(parts)


def generate_curl_from_proxy_entry(entry: Dict[str, Any]) -> Optional[str]:
    """프록시 로그 엔트리에서 cURL 명령어 생성"""
    method = entry.get("method", "GET")
    url = entry.get("url", "")
    headers = entry.get("headers", {})
    request_body = entry.get("request_body")
    cookies = entry.get("cookies", {})
    
    if not url:
        return None
    
    return generate_curl_command(method, url, headers, request_body, cookies)


def generate_curl_from_api(
    method: str,
    host: str,
    path: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
) -> str:
    """API 정보에서 cURL 명령어 생성"""
    # URL 구성
    if not host.startswith(("http://", "https://")):
        url = f"https://{host}{path}"
    else:
        url = f"{host}{path}"
    
    return generate_curl_command(method, url, headers, data)


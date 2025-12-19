"""MCP 취약점 실제 검증 모듈

curl_command를 활용한 실제 HTTP 요청을 통한 취약점 검증
"""

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

try:
    import requests
except ImportError:
    requests = None


def parse_curl_command(curl_cmd: str) -> Dict[str, Any]:
    """curl 명령어를 파싱하여 HTTP 요청 정보 추출"""
    result = {
        "method": "GET",
        "url": "",
        "headers": {},
        "data": None,
        "cookies": {},
    }
    
    if not curl_cmd or not curl_cmd.strip().startswith("curl"):
        return result
    
    # curl_command는 \n으로 구분되어 있을 수 있음
    curl_cmd_normalized = curl_cmd.replace("\\\n", " ").replace("\n", " ")
    
    # URL 추출 (큰따옴표로 감싸진 부분)
    url_match = re.search(r'curl\s+"([^"]+)"', curl_cmd_normalized)
    if url_match:
        result["url"] = unquote(url_match.group(1))
    
    # HTTP 메서드 추출
    method_match = re.search(r'-X\s+(\w+)', curl_cmd_normalized)
    if method_match:
        result["method"] = method_match.group(1).upper()
    
    # 헤더 추출
    header_matches = re.findall(r'-H\s+"([^"]+)"', curl_cmd_normalized)
    for header in header_matches:
        if ":" in header:
            key, value = header.split(":", 1)
            result["headers"][key.strip()] = value.strip()
    
    # 데이터 추출 (-d 또는 --data-raw)
    data_match = re.search(r'(-d|--data-raw)\s+"([^"]+)"', curl_cmd_normalized)
    if data_match:
        data_str = data_match.group(2)
        # JSON인지 확인
        try:
            result["data"] = json.loads(data_str)
        except json.JSONDecodeError:
            result["data"] = data_str
    
    return result


def verify_context_injection(
    curl_cmd: str,
    tool_arguments: Optional[Dict[str, Any]] = None,
    api_path: str = "",
) -> Tuple[bool, str]:
    """MCP-02: Context Injection Risk 검증
    
    tool arguments가 API 경로나 파라미터에 직접 사용되는지 확인
    """
    if not requests:
        return False, "requests 라이브러리가 설치되지 않았습니다"
    
    parsed = parse_curl_command(curl_cmd)
    if not parsed["url"]:
        return False, "URL을 추출할 수 없습니다"
    
    # tool arguments가 API 경로에 직접 사용되는지 확인
    if tool_arguments and api_path:
        for arg_name, arg_value in tool_arguments.items():
            if isinstance(arg_value, str) and arg_value in api_path:
                # 실제 요청을 보내서 확인
                try:
                    response = requests.request(
                        parsed["method"],
                        parsed["url"],
                        headers=parsed["headers"],
                        json=parsed["data"],
                        timeout=5,
                        allow_redirects=False,
                    )
                    # 200 OK면 실제로 사용 가능
                    if response.status_code == 200:
                        return True, f"tool argument '{arg_name}' 값이 API 경로에 직접 사용됨 (실제 확인: {response.status_code})"
                except Exception as e:
                    return False, f"검증 중 오류: {str(e)}"
    
    return False, "안전 (tool arguments가 API 경로에 직접 사용되지 않음)"


def verify_autonomous_execution(
    curl_cmd: str,
    method: str = "GET",
) -> Tuple[bool, str]:
    """MCP-03: Autonomous Execution Risk 검증
    
    수정/삭제 작업이 실제로 사용자 확인 없이 실행 가능한지 확인
    """
    if not requests:
        return False, "requests 라이브러리가 설치되지 않았습니다"
    
    destructive_methods = {"DELETE", "PATCH", "PUT"}
    if method.upper() not in destructive_methods:
        return False, "수정/삭제 작업이 아님"
    
    parsed = parse_curl_command(curl_cmd)
    if not parsed["url"]:
        return False, "URL을 추출할 수 없습니다"
    
    # 실제 요청을 보내서 확인
    try:
        response = requests.request(
            parsed["method"],
            parsed["url"],
            headers=parsed["headers"],
            json=parsed["data"],
            timeout=5,
            allow_redirects=False,
        )
        
        # 200 OK 또는 204 No Content면 실제로 실행 가능
        if response.status_code in [200, 201, 204]:
            return True, f"수정/삭제 작업이 사용자 확인 없이 실행 가능 (실제 확인: {response.status_code})"
        elif response.status_code == 401:
            return False, "안전 (인증 필요)"
        elif response.status_code == 403:
            return False, "안전 (권한 없음)"
        elif response.status_code == 404:
            return False, "안전 (리소스 없음)"
        else:
            return False, f"확인 불가 (상태 코드: {response.status_code})"
    except Exception as e:
        return False, f"검증 중 오류: {str(e)}"


def verify_tool_api_correlation(
    tool_arguments: Dict[str, Any],
    api_request_body: Optional[Dict[str, Any]] = None,
    api_path: str = "",
) -> Tuple[bool, str, Dict[str, Any]]:
    """tool 호출 arguments와 API 요청의 실제 연관성 확인
    
    Returns:
        (is_correlated, evidence, correlation_map)
    """
    if not tool_arguments:
        return False, "tool arguments 없음", {}
    
    correlation_map = {}
    evidence_parts = []
    
    # API 경로에서 tool arguments 값 찾기
    for arg_name, arg_value in tool_arguments.items():
        if isinstance(arg_value, str) and arg_value:
            if arg_value in api_path:
                correlation_map[arg_name] = {
                    "type": "path",
                    "value": arg_value,
                    "location": "API 경로"
                }
                evidence_parts.append(f"'{arg_name}'={arg_value} (경로)")
    
    # API request body에서 tool arguments 값 찾기
    if api_request_body and isinstance(api_request_body, dict):
        for arg_name, arg_value in tool_arguments.items():
            if isinstance(arg_value, (str, int, float, bool)) and arg_value:
                # request body에서 값 찾기
                for key, value in api_request_body.items():
                    if value == arg_value:
                        if arg_name not in correlation_map:
                            correlation_map[arg_name] = {
                                "type": "body",
                                "value": arg_value,
                                "location": f"request body.{key}"
                            }
                            evidence_parts.append(f"'{arg_name}'={arg_value} (body.{key})")
    
    if correlation_map:
        evidence = f"tool arguments가 API 요청에 직접 사용됨: {', '.join(evidence_parts)}"
        return True, evidence, correlation_map
    
    return False, "tool arguments와 API 요청의 직접적 연관성 없음", {}


def verify_mcp_vulnerability(
    vulnerability_code: str,
    curl_cmd: str,
    tool_arguments: Optional[Dict[str, Any]] = None,
    api_path: str = "",
    api_method: str = "GET",
    api_request_body: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """MCP 취약점 실제 검증
    
    Returns:
        (is_vulnerable, evidence, verification_details)
    """
    verification_details = {
        "verified": False,
        "method": "pattern_based",
        "evidence": "",
    }
    
    if vulnerability_code == "MCP-02":
        # Context Injection 검증
        is_vuln, evidence = verify_context_injection(curl_cmd, tool_arguments, api_path)
        if is_vuln:
            verification_details["verified"] = True
            verification_details["method"] = "http_request"
            verification_details["evidence"] = evidence
        
        # tool-API 연관성 확인
        if tool_arguments:
            is_correlated, corr_evidence, corr_map = verify_tool_api_correlation(
                tool_arguments, api_request_body, api_path
            )
            if is_correlated:
                verification_details["tool_api_correlation"] = corr_map
                if verification_details["evidence"]:
                    verification_details["evidence"] += f"; {corr_evidence}"
                else:
                    verification_details["evidence"] = corr_evidence
        
        return is_vuln, verification_details.get("evidence", evidence), verification_details
    
    elif vulnerability_code == "MCP-03":
        # Autonomous Execution 검증
        is_vuln, evidence = verify_autonomous_execution(curl_cmd, api_method)
        if is_vuln:
            verification_details["verified"] = True
            verification_details["method"] = "http_request"
            verification_details["evidence"] = evidence
        
        return is_vuln, verification_details.get("evidence", evidence), verification_details
    
    return False, "검증 로직 없음", verification_details


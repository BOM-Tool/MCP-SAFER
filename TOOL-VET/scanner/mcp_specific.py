"""MCP 서버 특화 취약점 스캐너

MCP AI Agent의 핵심 특징에 기반한 취약점 탐지:
- MCP는 "User prompts AI → AI interprets intent → Chooses tools → Injects context → Executes autonomously" 흐름
- 일반 API와 달리, 사용자가 직접 제어하지 않으므로 AI의 의사결정 과정에서 발생하는 취약점에 집중

체크 항목 (4개):
1. MCP-01: AI Tool Selection Risk - AI가 도구를 선택하는 단계
2. MCP-02: Context Injection Risk - AI가 컨텍스트를 주입하는 단계
3. MCP-03: Autonomous Execution Risk - AI가 자율적으로 실행하는 단계
4. MCP-04: Tool Combination Risk - AI가 여러 도구를 조합하는 단계
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class MCPVulnerability:
    category_code: str  # "MCP-01", "MCP-02" 등
    category_name: str  # "AI Tool Selection Risk" 등
    title: str
    description: str
    tool_name: Optional[str] = None
    api_endpoint: Optional[str] = None
    evidence: str = ""
    recommendation: str = ""


@dataclass
class MCPScanResult:
    total_vulnerabilities: int = 0
    vulnerabilities: List[MCPVulnerability] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)


def scan_mcp_specific(
    tools_file: Optional[Path] = None,
    api_endpoints_file: Optional[Path] = None,
    proxy_entries: Optional[List[Dict[str, Any]]] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
    api_endpoints: Optional[List[Dict[str, Any]]] = None,
    tool_call_arguments_map: Optional[Dict[str, Dict[str, Any]]] = None,
) -> MCPScanResult:
    result = MCPScanResult()
    
    if tools is None:
        if not tools_file or not tools_file.exists():
            return result
        try:
            with tools_file.open("r", encoding="utf-8") as handle:
                tools = json.load(handle)
        except (json.JSONDecodeError, FileNotFoundError):
            return result
    
    if api_endpoints is None:
        api_endpoints = []
        if api_endpoints_file and api_endpoints_file.exists():
            try:
                with api_endpoints_file.open("r", encoding="utf-8") as handle:
                    api_endpoints = json.load(handle)
            except json.JSONDecodeError:
                pass
    
    proxy_entries = proxy_entries or []
    tool_call_arguments_map = tool_call_arguments_map or {}
    
    _check_ai_tool_selection_risk(tools, api_endpoints, result)
    _check_context_injection_risk(tools, api_endpoints, proxy_entries, result, tool_call_arguments_map)
    _check_autonomous_execution_risk(tools, api_endpoints, result)
    _check_tool_combination_risk(tools, api_endpoints, result)
    
    result.total_vulnerabilities = len(result.vulnerabilities)
    result.summary = _count_by_category(result.vulnerabilities)
    
    return result


def _check_ai_tool_selection_risk(
    tools: List[Dict[str, Any]],
    api_endpoints: List[Dict[str, Any]],
    result: MCPScanResult,
):
    """MCP-01: AI Tool Selection Risk - 강화된 탐지"""
    dangerous_keywords = [
        "delete", "remove", "destroy", "clear", "cleanup", "reset", "admin", "drop", "truncate",
        "terminate", "kill", "wipe", "erase", "purge", "revoke", "disable", "suspend",
        "ban", "block", "expire", "invalidate", "cancel", "abort", "stop", "shutdown",
        "uninstall", "deactivate", "lock", "freeze", "obliterate", "annihilate",
        "exec", "command"
    ]
    warning_keywords = ["warning", "dangerous", "irreversible", "permanent", "cannot undo", "destructive", "critical"]
    
    dangerous_tools = []
    for tool in tools:
        tool_name_lower = tool.get("name", "").lower()
        tool_desc_lower = tool.get("description", "").lower()
        
        # 키워드 기반 탐지
        is_dangerous = any(keyword in tool_name_lower for keyword in dangerous_keywords)
        
        if is_dangerous:
            # description에 경고가 있는지 확인
            has_warning = any(keyword in tool_desc_lower for keyword in warning_keywords)
            
            # 경고 여부 기록
            dangerous_tools.append({
                "tool": tool,
                "has_warning": has_warning
            })
    
    if dangerous_tools:
        dangerous_ratio = len(dangerous_tools) / len(tools) if tools else 0
        
        high_severity_tools = [d for d in dangerous_tools if not d["has_warning"]]
        medium_severity_tools = [d for d in dangerous_tools if d["has_warning"]]
        
        # 위험한 도구가 있으면 항상 탐지 (10% 미만 조건 제거)
        # 위험한 도구는 비율과 관계없이 항상 위험하므로 탐지 필요
        if high_severity_tools:
            # 위험한 도구가 소수일 때 (혼재 위험) vs 다수일 때 (위험 집중) 구분
            if dangerous_ratio < 0.1:
                title = "위험한 도구가 일반 도구와 혼재하며 경고 부재"
                description = f"위험한 도구({len(high_severity_tools)}개)가 일반 도구와 섞여있고, " \
                             f"도구 설명에 경고가 없어 AI가 실수로 선택할 위험이 높습니다."
            else:
                title = "위험한 도구 다수 존재 (경고 부재)"
                description = f"위험한 도구({len(high_severity_tools)}개, 전체의 {dangerous_ratio*100:.1f}%)가 많고, " \
                             f"도구 설명에 경고가 없어 AI가 실수로 선택할 위험이 높습니다."
            
            result.vulnerabilities.append(MCPVulnerability(
                category_code="MCP-01",
                category_name="AI Tool Selection Risk",
                title=title,
                description=description,
                evidence=f"경고 없는 위험 도구: {[d['tool'].get('name') for d in high_severity_tools[:5]]}",
                recommendation="위험한 도구는 별도 네임스페이스로 분리하거나, 도구 설명에 명확한 경고를 추가하세요."
            ))
        
        if medium_severity_tools and len(high_severity_tools) == 0:
            result.vulnerabilities.append(MCPVulnerability(
                category_code="MCP-01",
                category_name="AI Tool Selection Risk",
                title="위험한 도구가 일반 도구와 혼재 (경고 있음)",
                description=f"위험한 도구({len(medium_severity_tools)}개)가 일반 도구와 섞여있지만, "
                           f"도구 설명에 경고가 있어 상대적으로 안전합니다.",
                evidence=f"경고 있는 위험 도구: {[d['tool'].get('name') for d in medium_severity_tools[:5]]}",
                recommendation="위험한 도구는 별도 네임스페이스로 분리하는 것을 권장합니다."
            ))


def _check_context_injection_risk(
    tools: List[Dict[str, Any]],
    api_endpoints: List[Dict[str, Any]],
    proxy_entries: List[Dict[str, Any]],
    result: MCPScanResult,
    tool_call_arguments_map: Optional[Dict[str, Dict[str, Any]]] = None,
):
    """MCP-02: Context Injection Risk - 강화된 탐지"""
    # 1. inputSchema 부재 확인
    tools_without_schema = [
        tool for tool in tools
        if not tool.get("inputSchema")
    ]
    
    if tools_without_schema:
        result.vulnerabilities.append(MCPVulnerability(
            category_code="MCP-02",
            category_name="Context Injection Risk",
            title="AI 주입 컨텍스트 검증 불가",
            description=f"{len(tools_without_schema)}개 도구에 inputSchema가 없어 AI가 주입한 컨텍스트를 검증할 수 없습니다.",
            evidence=f"스키마 없는 도구: {[t.get('name') for t in tools_without_schema[:5]]}",
            recommendation="모든 도구에 inputSchema를 정의하여 AI가 주입한 컨텍스트를 엄격하게 검증하세요."
        ))
    
    # 2. inputSchema 검증 강도 분석
    weak_validation_tools = []
    for tool in tools:
        input_schema = tool.get("inputSchema", {})
        if not input_schema:
            continue
        
        properties = input_schema.get("properties", {})
        required = input_schema.get("required", [])
        
        # 검증 강도 평가
        has_enum = False
        has_pattern = False
        has_min_max = False
        weak_fields = []
        
        # Command injection 위험 필드 확인
        command_injection_risk_fields = []
        command_keywords = ["command", "cmd", "exec", "shell", "script", "execute"]
        
        for field_name, field_schema in properties.items():
            field_name_lower = field_name.lower()
            
            # enum 제약 확인
            if "enum" in field_schema:
                has_enum = True
            # pattern 제약 확인
            if "pattern" in field_schema:
                has_pattern = True
            # min/max 제약 확인
            if "minimum" in field_schema or "maximum" in field_schema:
                has_min_max = True
            
            # Command injection 위험 필드 확인
            # command, cmd, exec, shell 같은 필드명을 가진 string 타입 필드
            is_command_field = any(keyword in field_name_lower for keyword in command_keywords)
            field_type = field_schema.get("type", "")
            
            # anyOf 처리: anyOf 내부의 string 타입 확인
            if "anyOf" in field_schema:
                any_of_types = [item.get("type") for item in field_schema.get("anyOf", []) if isinstance(item, dict)]
                has_string_type = "string" in any_of_types
            else:
                has_string_type = field_type == "string"
            
            if is_command_field and has_string_type:
                # pattern 제약이 없으면 command injection 위험
                has_pattern_constraint = False
                if "pattern" in field_schema:
                    has_pattern_constraint = True
                elif "anyOf" in field_schema:
                    # anyOf 내부의 string 타입에 pattern이 있는지 확인
                    for item in field_schema.get("anyOf", []):
                        if isinstance(item, dict) and item.get("type") == "string":
                            if "pattern" in item:
                                has_pattern_constraint = True
                                break
                
                if not has_pattern_constraint:
                    command_injection_risk_fields.append(field_name)
            
            # required가 아니고 제약이 없는 필드
            if field_name not in required and not any([
                "enum" in field_schema,
                "pattern" in field_schema,
                "minimum" in field_schema,
                "maximum" in field_schema
            ]):
                # anyOf 내부의 제약도 확인
                if "anyOf" in field_schema:
                    has_any_constraint = False
                    for item in field_schema.get("anyOf", []):
                        if isinstance(item, dict):
                            if any(["enum" in item, "pattern" in item, "minimum" in item, "maximum" in item]):
                                has_any_constraint = True
                                break
                    if not has_any_constraint:
                        weak_fields.append(field_name)
                else:
                    weak_fields.append(field_name)
        
        # Command injection 위험 필드가 있으면 별도 취약점 추가
        if command_injection_risk_fields:
            result.vulnerabilities.append(MCPVulnerability(
                category_code="MCP-02",
                category_name="Context Injection Risk",
                title="Command Injection 위험 (Shell Metacharacters 검증 부재)",
                description=f"도구 '{tool.get('name')}'의 {len(command_injection_risk_fields)}개 필드({', '.join(command_injection_risk_fields)})가 " \
                          f"command/exec 관련 필드명을 가지고 있지만, shell metacharacters를 검증하는 pattern 제약이 없어 " \
                          f"command injection 공격에 취약할 수 있습니다.",
                tool_name=tool.get("name"),
                evidence=f"위험 필드: {', '.join(command_injection_risk_fields)} (pattern 제약 없음)",
                recommendation="command/exec 관련 필드에 shell metacharacters (;, &&, |, >, <, $ 등)를 차단하는 pattern 제약을 추가하거나, " \
                              "array 형식만 허용하도록 제한하세요."
            ))
        
        # 검증이 약한 경우 (required 필드가 적고, enum/pattern 제약이 없음)
        if len(required) < len(properties) * 0.5 and not (has_enum or has_pattern):
            weak_validation_tools.append({
                "tool": tool,
                "required_ratio": len(required) / len(properties) if properties else 0,
                "weak_fields": weak_fields[:3]
            })
    
    if weak_validation_tools:
        result.vulnerabilities.append(MCPVulnerability(
            category_code="MCP-02",
            category_name="Context Injection Risk",
            title="AI 주입 컨텍스트 검증 강도 부족",
            description=f"{len(weak_validation_tools)}개 도구의 inputSchema 검증이 약하여 AI가 주입한 컨텍스트를 충분히 검증하지 못할 수 있습니다.",
            evidence=f"약한 검증 도구: {[w['tool'].get('name') for w in weak_validation_tools[:5]]}",
            recommendation="inputSchema에 enum, pattern, minimum/maximum 등의 제약 조건을 추가하여 검증을 강화하세요."
        ))
    
    # 3. 동적 경로 사용 확인 (프록시 로그 기반) - tool arguments와 연관성 확인
    if proxy_entries:
        dynamic_path_requests = []
        tool_api_correlations = []  # tool arguments와 API 요청의 실제 연관성
        
        for entry in proxy_entries:
            path = entry.get("path", "")
            request_body = entry.get("request_body")
            
            # 동적 경로 패턴: {param}, {id} 등 (확장된 패턴)
            # 기본 패턴: {param}, {id}, {user_id} 등
            # UUID 패턴: 8-4-4-4-12 형식
            # 숫자 ID 패턴: /123, /456 등
            # 해시 패턴: /abc123def 등
            uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            numeric_id_pattern = r'/\d+'
            hash_pattern = r'/[a-f0-9]{20,}'
            
            is_dynamic = (
                re.search(r"/\{[^}]+\}", path) or  # {param}, {id} 등
                re.search(r"/[^/]+/[^/]+/[^/]+", path) or  # 3단계 이상 경로
                re.search(uuid_pattern, path, re.IGNORECASE) or  # UUID 패턴
                re.search(numeric_id_pattern, path) or  # 숫자 ID
                re.search(hash_pattern, path, re.IGNORECASE)  # 해시 패턴
            )
            
            if is_dynamic:
                dynamic_path_requests.append(f"{entry.get('method')} {path}")
                
                # tool arguments와 API 요청의 연관성 확인
                if tool_call_arguments_map:
                    for tool_name, tool_args in tool_call_arguments_map.items():
                        if tool_args:
                            # tool arguments 값이 API 경로나 body에 있는지 확인
                            for arg_name, arg_value in tool_args.items():
                                if isinstance(arg_value, str) and arg_value:
                                    if arg_value in path or (isinstance(request_body, str) and arg_value in request_body):
                                        tool_api_correlations.append({
                                            "tool": tool_name,
                                            "argument": arg_name,
                                            "value": arg_value[:50],  # 값이 길면 잘라냄
                                            "api": f"{entry.get('method')} {path}",
                                        })
        
        if dynamic_path_requests:
            # tool-API 연관성이 확인된 경우
            if tool_api_correlations:
                correlation_evidence = []
                for corr in tool_api_correlations[:5]:
                    correlation_evidence.append(f"{corr['tool']}.{corr['argument']} → {corr['api']}")
                
                result.vulnerabilities.append(MCPVulnerability(
                    category_code="MCP-02",
                    category_name="Context Injection Risk",
                    title="AI 주입 컨텍스트가 동적 경로로 직접 실행됨 (실제 확인)",
                    description=f"프록시 로그 및 tool arguments 분석 결과, tool 호출 arguments가 {len(tool_api_correlations)}개의 API 요청에 직접 사용되고 있습니다.",
                    evidence=f"tool-API 연관성: {', '.join(correlation_evidence)}",
                    recommendation="AI가 주입한 모든 컨텍스트를 화이트리스트 기반으로 검증하고, 동적 경로 사용을 최소화하세요.",
                    tool_name=None,  # 전역 취약점
                ))
            else:
                # 연관성 확인 안 됨 (패턴 기반만)
                result.vulnerabilities.append(MCPVulnerability(
                    category_code="MCP-02",
                    category_name="Context Injection Risk",
                    title="동적 경로 사용 (AI 주입 가능성)",
                    description=f"프록시 로그 분석 결과, {len(dynamic_path_requests)}개의 동적 경로가 사용되고 있습니다. tool arguments와의 직접적 연관성은 확인되지 않았습니다.",
                    evidence=f"동적 경로 사용: {', '.join(dynamic_path_requests[:5])}",
                    recommendation="AI가 주입한 모든 컨텍스트를 화이트리스트 기반으로 검증하고, 동적 경로 사용을 최소화하세요.",
                    tool_name=None,  # 전역 취약점
                ))


def _check_autonomous_execution_risk(
    tools: List[Dict[str, Any]],
    api_endpoints: List[Dict[str, Any]],
    result: MCPScanResult,
):
    """MCP-03: Autonomous Execution Risk - 강화된 탐지"""
    destructive_methods = {"DELETE", "PATCH", "PUT"}
    destructive_apis = [
        ep for ep in api_endpoints
        if ep.get("method") in destructive_methods
    ]
    
    if destructive_apis:
        destructive_ratio = len(destructive_apis) / len(api_endpoints) if api_endpoints else 0
        
        # 영향 범위 분석
        delete_apis = [ep for ep in destructive_apis if ep.get("method") == "DELETE"]
        modify_apis = [ep for ep in destructive_apis if ep.get("method") in {"PATCH", "PUT"}]
        
        # 경로 패턴 분석으로 리소스 타입 추정
        sensitive_resources = []
        resource_keywords = [
            "user", "account", "admin", "secret", "token", "key", "credential", "password",
            "auth", "authorization", "permission", "role", "privilege", "access",
            "personal", "private", "confidential", "sensitive", "internal", "protected",
            "session", "cookie", "api_key", "api_secret", "private_key", "ssh_key",
            "wallet", "payment", "billing", "subscription", "license", "certificate"
        ]
        
        for api in destructive_apis:
            path = api.get("path", "").lower()
            if any(keyword in path for keyword in resource_keywords):
                sensitive_resources.append(api.get("path", ""))
        
        # 제목 및 설명 결정
        if delete_apis:
            if sensitive_resources:
                title = "AI가 사용자 확인 없이 민감한 리소스 삭제 작업을 자율 실행 가능"
                description = f"삭제 작업({len(delete_apis)}개) 중 민감한 리소스({len(sensitive_resources)}개)가 포함되어 있어 " \
                            f"AI가 사용자 확인 없이 자율적으로 실행할 경우 심각한 피해가 발생할 수 있습니다."
            else:
                title = "AI가 사용자 확인 없이 삭제 작업을 자율 실행 가능"
                description = f"삭제 작업이 {len(delete_apis)}개로 많아 AI가 사용자 확인 없이 자율적으로 실행할 수 있습니다."
        elif modify_apis:
            title = "AI가 사용자 확인 없이 수정 작업을 자율 실행 가능"
            description = f"수정 작업이 {len(modify_apis)}개({destructive_ratio*100:.1f}%)로 많아 " \
                        f"AI가 사용자 확인 없이 자율적으로 실행할 수 있습니다."
        else:
            title = "AI가 사용자 확인 없이 수정/삭제 작업을 자율 실행 가능"
            description = f"수정/삭제 작업이 {len(destructive_apis)}개({destructive_ratio*100:.1f}%)로 많아 " \
                        f"AI가 사용자 확인 없이 자율적으로 실행할 수 있습니다."
        
        evidence_parts = []
        if delete_apis:
            evidence_parts.append(f"DELETE: {len(delete_apis)}개")
        if modify_apis:
            evidence_parts.append(f"PATCH/PUT: {len(modify_apis)}개")
        if sensitive_resources:
            evidence_parts.append(f"민감한 리소스: {len(sensitive_resources)}개")
        
        result.vulnerabilities.append(MCPVulnerability(
            category_code="MCP-03",
            category_name="Autonomous Execution Risk",
            title=title,
            description=description,
            evidence=f"수정/삭제 작업: {', '.join(evidence_parts)}",
            recommendation="위험한 작업은 사용자 확인을 요구하거나, 명시적인 승인 플래그를 필요로 하도록 설계하세요."
        ))


def _check_tool_combination_risk(
    tools: List[Dict[str, Any]],
    api_endpoints: List[Dict[str, Any]],
    result: MCPScanResult,
):
    """MCP-04: Tool Combination Risk - 강화된 탐지"""
    read_keywords = [
        "get", "read", "list", "fetch", "search", "query", "retrieve",
        "obtain", "extract", "download", "load", "access", "view", "show", "display",
        "enumerate", "scan", "inspect", "examine", "analyze", "review", "check"
    ]
    write_keywords = [
        "create", "update", "delete", "write", "modify", "edit", "remove", "destroy",
        "add", "insert", "append", "replace", "set", "change", "alter", "transform",
        "publish", "submit", "post", "send", "upload", "save", "store", "commit",
        "push", "deploy", "execute", "run", "trigger", "invoke", "call", "activate"
    ]
    
    read_tools = []
    write_tools = []
    
    for tool in tools:
        tool_name_lower = tool.get("name", "").lower()
        tool_desc_lower = tool.get("description", "").lower()
        
        # 읽기 도구 확인
        is_read = any(keyword in tool_name_lower or keyword in tool_desc_lower for keyword in read_keywords)
        # 쓰기 도구 확인
        is_write = any(keyword in tool_name_lower or keyword in tool_desc_lower for keyword in write_keywords)
        
        if is_read and not is_write:
            read_tools.append(tool)
        elif is_write:
            write_tools.append(tool)
    
    if read_tools and write_tools:
        write_ratio = len(write_tools) / len(tools) if tools else 0
        
        # 실제 공격 가능성 평가
        # 읽기 도구와 쓰기 도구가 모두 있고, 쓰기 비율이 높으면 위험
        if write_ratio > 0.2:
            # 민감한 정보를 읽을 수 있는 도구 확인
            sensitive_read_tools = []
            sensitive_keywords = [
                "user", "account", "secret", "token", "key", "credential", "password", "admin",
                "auth", "authorization", "permission", "role", "privilege", "access",
                "personal", "private", "confidential", "sensitive", "internal", "protected",
                "session", "cookie", "api_key", "api_secret", "private_key", "ssh_key",
                "wallet", "payment", "billing", "subscription", "license", "certificate"
            ]
            
            for tool in read_tools:
                tool_name_lower = tool.get("name", "").lower()
                tool_desc_lower = tool.get("description", "").lower()
                if any(keyword in tool_name_lower or keyword in tool_desc_lower for keyword in sensitive_keywords):
                    sensitive_read_tools.append(tool)
            
            if sensitive_read_tools:
                title = "AI가 민감한 정보를 읽은 후 쓰기 도구로 악용 가능"
                description = f"민감한 정보를 읽을 수 있는 도구({len(sensitive_read_tools)}개)와 " \
                            f"쓰기 도구({len(write_tools)}개)가 모두 있어 AI가 정보를 수집한 후 악용할 위험이 높습니다."
                evidence = f"민감 정보 읽기 도구: {len(sensitive_read_tools)}개, 쓰기 도구: {len(write_tools)}개"
            else:
                title = "AI가 읽기-쓰기 도구를 조합하여 정보 악용 가능"
                description = f"읽기 도구({len(read_tools)}개)와 쓰기 도구({len(write_tools)}개)가 모두 있어 " \
                            f"AI가 정보를 수집한 후 악용할 수 있습니다."
                evidence = f"읽기 도구: {len(read_tools)}개, 쓰기 도구: {len(write_tools)}개"
            
            result.vulnerabilities.append(MCPVulnerability(
                category_code="MCP-04",
                category_name="Tool Combination Risk",
                title=title,
                description=description,
                evidence=evidence,
                recommendation="읽기 도구와 쓰기 도구의 권한을 분리하고, 민감한 정보 접근 시 쓰기 작업을 제한하세요."
            ))


def _count_by_category(vulnerabilities: List[MCPVulnerability]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for vuln in vulnerabilities:
        category_code = vuln.category_code
        summary[category_code] = summary.get(category_code, 0) + 1
    return summary


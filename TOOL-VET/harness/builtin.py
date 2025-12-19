from __future__ import annotations

import json
import os
import select
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class ToolCallResult:
    name: str
    success: bool
    error: Optional[str] = None
    timestamp_start: Optional[float] = None
    timestamp_end: Optional[float] = None
    arguments: Optional[Dict[str, Any]] = None  # tool 호출 arguments 추적


@dataclass
class HarnessReport:
    tools: List[Dict[str, Any]]
    calls: List[ToolCallResult]


class MCPClient:
    def __init__(self, process, timeout: float = 30.0):  # 타임아웃을 30초로 복원 (성능 개선)
        self.process = process
        self.timeout = timeout
        self._next_id = 1
        if process.stdin is None or process.stdout is None:
            raise ValueError("프로세스 stdin/stdout 파이프가 필요합니다.")

    def initialize(self) -> None:
        params = {
            "clientInfo": {"name": "mcp-vetting", "version": "0.1.0"},
            "protocolVersion": "2025-06-18",
            "capabilities": {},
        }
        self._request("initialize", params)

    def list_tools(self) -> List[Dict[str, Any]]:
        response = self._request("tools/list", {})
        return response.get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        params = {"name": name, "arguments": arguments}
        return self._request("tools/call", params)

    def shutdown(self) -> None:
        try:
            self._request("shutdown", {})
        except TimeoutError:
            pass

    def _request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1

        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        
        # 프로세스가 종료되었는지 확인
        if self.process.poll() is not None:
            exit_code = self.process.poll()
            # stderr에서 오류 메시지 읽기 시도
            stderr_output = ""
            try:
                if self.process.stderr:
                    stderr_output = self.process.stderr.read()
            except:
                pass
            error_msg = f"MCP 서버 프로세스가 종료되었습니다 (종료 코드: {exit_code})"
            if stderr_output:
                error_msg += f"\n서버 오류 출력: {stderr_output[:500]}"
            raise RuntimeError(error_msg)
        
        self._send_json(message)
        
        # initialize의 경우 더 긴 타임아웃 사용
        original_timeout = self.timeout
        if method == "initialize":
            self.timeout = original_timeout * 2  # initialize는 2배 타임아웃
        
        try:
            # 최대 3번 재시도 (성능 개선: 10번 → 3번)
            max_attempts = 3
            attempts = 0
            while attempts < max_attempts:
                response = self._read_json()
                if response is None:
                    # 프로세스 상태 재확인
                    if self.process.poll() is not None:
                        exit_code = self.process.poll()
                        stderr_output = ""
                        try:
                            if self.process.stderr:
                                stderr_output = self.process.stderr.read()
                        except:
                            pass
                        error_msg = f"MCP 서버 프로세스가 응답 중 종료되었습니다 (종료 코드: {exit_code})"
                        if stderr_output:
                            error_msg += f"\n서버 오류 출력: {stderr_output[:500]}"
                        raise RuntimeError(error_msg)
                    
                    attempts += 1
                    if attempts >= max_attempts:
                        raise TimeoutError(f"응답을 받지 못했습니다: {method} (타임아웃: {self.timeout}초, 재시도: {attempts}회)")
                    continue
                if response.get("id") == request_id:
                    if "error" in response:
                        error_info = response["error"]
                        error_code = error_info.get("code", "unknown")
                        error_message = error_info.get("message", "알 수 없는 오류")
                        error_data = error_info.get("data", "")
                        full_error = f"JSON-RPC 오류 (코드: {error_code}): {error_message}"
                        if error_data:
                            full_error += f" | 데이터: {error_data}"
                        raise RuntimeError(full_error)
                    return response.get("result", {})
                # 다른 요청의 응답이면 계속 대기
                attempts += 1
            
            raise TimeoutError(f"응답을 받지 못했습니다: {method} (최대 재시도 횟수 초과)")
        finally:
            # 타임아웃 원래대로 복구
            self.timeout = original_timeout

    def _send_json(self, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False)
        self.process.stdin.write(data + "\n")
        self.process.stdin.flush()

    def _read_json(self) -> Optional[Dict[str, Any]]:
        deadline = time.time() + self.timeout
        stdout = self.process.stdout
        if stdout is None:
            return None

        buffer: List[str] = []
        # select 타임아웃을 짧게 설정하여 주기적으로 deadline 체크 (1초마다)
        select_timeout = 1.0

        while time.time() < deadline:
            if self.process.poll() is not None:
                remainder = stdout.read()
                if remainder:
                    buffer.append(remainder)
                break

            remaining_time = max(0, deadline - time.time())
            if remaining_time <= 0:
                break
                
            # select 타임아웃을 남은 시간과 select_timeout 중 작은 값으로 설정
            # 이렇게 하면 1초마다 deadline을 체크할 수 있음
            select_timeout_actual = min(select_timeout, remaining_time)
            ready, _, _ = select.select([stdout], [], [], select_timeout_actual)
            
            if ready:
                line = stdout.readline()
                if not line:
                    continue
                line = line.strip()
                if not line:
                    continue
                buffer.append(line)
                try:
                    return json.loads("".join(buffer))
                except json.JSONDecodeError:
                    continue
            # select가 타임아웃되면 (ready가 비어있으면) 다시 루프로 돌아가서 deadline 체크

        return None


def _sample_value(schema: Dict[str, Any], field_name: str = "", resources: Optional[Dict[str, Any]] = None) -> Any:
    if resources:
        field_lower = field_name.lower()
        if field_lower in ("owner", "repository_owner"):
            if "owner" in resources:
                return resources["owner"]
        if field_lower in ("repo", "repository", "repository_name"):
            if "repo" in resources:
                return resources["repo"]
        if field_lower in ("issue_number", "issue", "number"):
            if "issue_number" in resources:
                return resources["issue_number"]
    
    schema_type = schema.get("type")
    if schema_type == "string":
        # format 필드 처리 (UUID, email, date 등)
        format_type = schema.get("format", "")
        if format_type == "uuid":
            import uuid
            return str(uuid.uuid4())
        if format_type == "email":
            return "test@example.com"
        if format_type == "date" or format_type == "date-time":
            from datetime import datetime
            return datetime.now().isoformat()
        
        enum_values = schema.get("enum")
        if isinstance(enum_values, list) and enum_values:
            return enum_values[0]
        
        # pattern 필드 처리
        pattern = schema.get("pattern", "")
        if pattern:
            # 간단한 패턴 매칭 (예: 숫자만, 알파벳만 등)
            if r'\d+' in pattern or pattern == r'^[0-9]+$':
                return "12345"
            if r'[a-zA-Z]' in pattern:
                return "sample"
        
        field_lower = field_name.lower()
        # 필드명 기반 스마트 기본값 (보편화)
        # ID 필드 처리 (UUID 형식이 필요한 경우)
        if "id" in field_lower:
            import uuid
            return str(uuid.uuid4())
        # 사용자/소유자 관련
        if any(keyword in field_lower for keyword in ["owner", "user", "author", "creator"]):
            return "test-user"
        # 저장소/프로젝트 관련
        if any(keyword in field_lower for keyword in ["repo", "repository", "project", "workspace"]):
            return "test-repo"
        # 이슈/티켓 관련
        if any(keyword in field_lower for keyword in ["issue", "ticket", "task"]):
            return "1"
        # 브랜치/버전 관련
        if any(keyword in field_lower for keyword in ["branch", "ref", "version", "tag"]):
            return "main"
        # 파일/경로 관련
        if any(keyword in field_lower for keyword in ["path", "file", "filename", "filepath"]):
            return "README.md"
        # 페이지/문서 관련
        if any(keyword in field_lower for keyword in ["page", "document", "doc"]):
            import uuid
            return str(uuid.uuid4())
        # 데이터베이스/테이블 관련
        if any(keyword in field_lower for keyword in ["database", "db", "table", "collection"]):
            import uuid
            return str(uuid.uuid4())
        # 블록/컨텐츠 관련
        if any(keyword in field_lower for keyword in ["block", "content", "item"]):
            import uuid
            return str(uuid.uuid4())
        # 커서/페이지네이션 관련
        if any(keyword in field_lower for keyword in ["cursor", "offset", "skip"]):
            return None  # 선택적 필드
        # 쿼리/검색 관련
        if any(keyword in field_lower for keyword in ["query", "search", "filter", "q"]):
            return ""
        # 토큰/키 관련
        if any(keyword in field_lower for keyword in ["token", "key", "secret", "api_key"]):
            return "dummy-token"
        # URL 관련
        if any(keyword in field_lower for keyword in ["url", "uri", "endpoint", "link"]):
            return "https://example.com"
        # 기본값
        return "sample"
    if schema_type == "number" or schema_type == "integer":
        field_lower = field_name.lower()
        if "number" in field_lower:
            return 1
        return 0
    if schema_type == "boolean":
        return False
    if schema_type == "array":
        items = schema.get("items", {})
        return [_sample_value(items, "", resources)] if items else []
    if schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        result = {}
        for key in required:
            subschema = properties.get(key)
            if subschema is None:
                continue
            result[key] = _sample_value(subschema, key, resources)
        return result
    return ""


def _build_arguments(tool: Dict[str, Any], resources: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    input_schema = tool.get("inputSchema", {})
    schema_type = input_schema.get("type", "object")
    if schema_type != "object":
        return {}
    properties = input_schema.get("properties", {})
    required_fields: Iterable[str] = input_schema.get("required", [])

    args: Dict[str, Any] = {}
    # 필수 필드 먼저 처리
    for field in required_fields:
        schema = properties.get(field)
        if not schema:
            continue
        value = _sample_value(schema, field, resources)
        # None 값은 제외 (선택적 필드로 처리)
        if value is not None:
            args[field] = value
    
    # 선택적 필드도 일부 포함 (API 호출 성공률 향상)
    optional_fields = set(properties.keys()) - set(required_fields)
    for field in list(optional_fields)[:3]:  # 최대 3개만 추가
        schema = properties.get(field)
        if not schema:
            continue
        value = _sample_value(schema, field, resources)
        if value is not None:
            args[field] = value
    
    return args


def run_builtin_harness(
    process,
    max_tools: int = 0,
    resources: Optional[Dict[str, Any]] = None,
    predefined_tools: Optional[List[Dict[str, Any]]] = None,
) -> HarnessReport:
    client = MCPClient(process)
    tools: List[Dict[str, Any]] = []
    results: List[ToolCallResult] = []

    if resources is None:
        resources = {}

    try:
        client.initialize()
    except Exception as exc:
        error_msg = str(exc)
        print(f"❌ initialize 실패: {error_msg}", file=sys.stderr)
        return HarnessReport(tools=[], calls=[ToolCallResult(name="initialize", success=False, error=error_msg)])

    try:
        if predefined_tools:
            tools = predefined_tools
        else:
            tools = client.list_tools()
    except Exception as exc:
        error_msg = str(exc)
        print(f"❌ tools/list 실패: {error_msg}", file=sys.stderr)
        # 프로세스 상태 확인
        if process.poll() is not None:
            exit_code = process.poll()
            error_msg += f" (MCP 서버 프로세스 종료 코드: {exit_code})"
        return HarnessReport(tools=[], calls=[ToolCallResult(name="tools/list", success=False, error=error_msg)])

    tool_list = tools if max_tools == 0 else tools[:max_tools]
    
    print(f"총 {len(tool_list)}개 도구 호출 시작...")
    for i, tool in enumerate(tool_list, 1):
        name = tool.get("name", "unknown")
        timestamp_start = time.time()
        success = False
        error_msg = None
        
        # 첫 번째 시도: 필수 파라미터 포함
        args = None
        try:
            args = _build_arguments(tool, resources)
            client.call_tool(name, args)
            timestamp_end = time.time()
            results.append(ToolCallResult(name=name, success=True, timestamp_start=timestamp_start, timestamp_end=timestamp_end, arguments=args))
            success = True
        except TimeoutError:
            error_msg = "Timeout"
        except Exception as exc:  # pylint: disable=broad-except
            error_msg = str(exc)
            if len(error_msg) > 200:
                error_msg = error_msg[:200] + "..."
        
        # 실패한 경우 재시도: 빈 파라미터로 시도 (일부 tool은 파라미터가 선택적)
        # 단, TimeoutError나 명확한 필수 파라미터 오류가 아닌 경우에만 재시도
        if not success and error_msg and "required" not in error_msg.lower() and "missing" not in error_msg.lower() and "timeout" not in error_msg.lower():
            try:
                empty_args = {}
                client.call_tool(name, empty_args)
                timestamp_end = time.time()
                results.append(ToolCallResult(name=name, success=True, timestamp_start=timestamp_start, timestamp_end=timestamp_end, arguments=empty_args))
                success = True
                error_msg = None
                args = empty_args
            except (TimeoutError, Exception):
                # 재시도도 실패하면 바로 넘어감
                pass
        
        if not success:
            timestamp_end = time.time()
            results.append(ToolCallResult(name=name, success=False, error=error_msg, timestamp_start=timestamp_start, timestamp_end=timestamp_end, arguments=args))
        
        # timestamp_end가 설정되지 않은 경우 (이론적으로는 발생하지 않아야 함)
        if timestamp_end is None:
            timestamp_end = time.time()
        
        # 진행 상황 표시 (매 5개마다 또는 완료 시)
        if i % 5 == 0 or i == len(tool_list):
            elapsed = timestamp_end - timestamp_start
            print(f"   진행: {i}/{len(tool_list)} (성공: {sum(1 for r in results if r.success)}개, 현재: {name}, 소요: {elapsed:.1f}초)")

    try:
        client.shutdown()
    except Exception:
        pass

    return HarnessReport(tools=tools, calls=results)


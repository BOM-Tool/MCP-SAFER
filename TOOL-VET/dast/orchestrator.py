#!/usr/bin/env python3
"""MCP 서버 검증 오케스트레이터

1. tools/list로 tool 목록 및 관련 정보, API 추출
2. tools/call로 API 취약점 점검 수행
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

CommandType = Union[str, Sequence[str]]

from auto.runtime import RuntimePlan, detect_runtime
from dast.mitm import wait_for_mitmproxy_ca
from dast.utils import clone_repository, extract_repo_name
from harness import run_builtin_harness, run_http_harness
from harness.builtin import HarnessReport
from scanner.mcp_specific import scan_mcp_specific
from scanner.mcp_verifier import verify_mcp_vulnerability, verify_tool_api_correlation
from extractor.openapi_extractor import (
    find_openapi_files,
    extract_apis_from_openapi,
    match_api_patterns,
    normalize_path_pattern,
)
from extractor.graphql_extractor import (
    detect_graphql_endpoint,
    introspect_graphql_schema,
    extract_operations_from_schema,
    check_introspection_enabled,
)
from report.curl_generator import generate_curl_from_api


def parse_args():
    parser = argparse.ArgumentParser(description="MCP 서버 검증 도구")
    parser.add_argument("--git-url", required=True, help="MCP 서버 Git URL")
    parser.add_argument("--branch", default=None, help="Git 브랜치 또는 태그 (예: main, v1.0.0, develop)")
    parser.add_argument("--output-dir", default=str(Path.cwd() / "output"), help="결과 저장 디렉터리")
    parser.add_argument("--env-file", default=".env", help="환경변수 파일 경로")
    parser.add_argument("--server-args", default="", help="MCP 서버 실행 시 추가할 인자 (예: --toolsets all)")
    parser.add_argument("--auto", action="store_true", default=True, help="런타임 자동 감지 및 실행")
    return parser.parse_args()


def load_env_file(env_file: str) -> Dict[str, str]:
    env_vars = {}
    env_path = Path(env_file)
    print(f"[DEBUG] .env 파일 경로: {env_path} (절대 경로: {env_path.resolve()})")
    print(f"[DEBUG] .env 파일 존재 여부: {env_path.exists()}")
    
    if env_path.exists():
        with env_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        env_vars[key] = value
                        print(f"[DEBUG] 환경 변수 로드: {key}=*** (길이: {len(value)})")
    else:
        print(f"[DEBUG] .env 파일이 존재하지 않습니다: {env_path}")
    
    print(f"[DEBUG] 총 {len(env_vars)}개의 환경 변수가 로드되었습니다.")
    return env_vars


def save_env_to_file(env_file: str, env_vars: Dict[str, str]):
    with Path(env_file).open("w", encoding="utf-8") as f:
        for key, value in env_vars.items():
            f.write(f"{key}={value}\n")


def run_command(command: CommandType, cwd: Path, extra_env: Optional[Dict[str, str]] = None) -> int:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    if isinstance(command, str):
        proc = subprocess.run(command, shell=True, cwd=str(cwd), env=env, capture_output=True, text=True)
    else:
        proc = subprocess.run(command, cwd=str(cwd), env=env, capture_output=True, text=True)

    if proc.stdout:
        print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    return proc.returncode


def _normalize_command(command: CommandType) -> List[str]:
    if isinstance(command, str):
        return command.split()
    return list(command)


def _format_command(command: CommandType) -> str:
    if isinstance(command, str):
        return command
    return " ".join(command)


def kill_process(proc: subprocess.Popen):
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            proc.kill()


def start_mitmdump(mitmdump_path: str, host: str, port: int, output_file: Path, conf_dir: Path) -> subprocess.Popen:
    addon_path = Path(__file__).parent / "proxy_logger.py"
    cmd = [
        mitmdump_path,
        "--listen-host", host,
        "--listen-port", str(port),
        "-s", str(addon_path),
        "--set", f"logger_output={output_file}",
        "--set", f"confdir={conf_dir}",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)


def start_mcp_server(
    command: CommandType,
    cwd: Path,
    proxy_url: str,
    extra_env: Optional[Dict[str, str]] = None,
    background: bool = False,
) -> subprocess.Popen:
    env = os.environ.copy()
    env.update({
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
    })
    if extra_env:
        print(f"[DEBUG] MCP 서버에 환경 변수 전달: {list(extra_env.keys())}")
        env.update(extra_env)
        # 환경 변수가 실제로 설정되었는지 확인
        for key in extra_env.keys():
            if key in env:
                print(f"[DEBUG] 환경 변수 확인: {key} = *** (설정됨)")
            else:
                print(f"[DEBUG] 환경 변수 확인: {key} = (설정되지 않음!)", file=sys.stderr)
    
    if background:
        return subprocess.Popen(
            _normalize_command(command),
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid,
        )
    else:
        return subprocess.Popen(
            _normalize_command(command),
            cwd=str(cwd),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid,
        )


def extract_apis_from_tools(tools: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """tools/list 결과에서 각 tool의 API 정보 추출"""
    import re
    from urllib.parse import urlparse
    
    tool_api_map: Dict[str, List[Dict[str, Any]]] = {}
    url_pattern = r'https?://[^\s\)]+'
    
    for tool in tools:
        tool_name = tool.get("name", "")
        tool_apis = []
        
        # description에서 API URL 추출
        description = tool.get("description", "")
        if description:
            urls = re.findall(url_pattern, description)
            for url in urls:
                try:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        tool_apis.append({
                            "method": "GET",
                            "host": parsed.netloc,
                            "path": parsed.path or "/",
                        })
                except Exception:
                    pass
        
        # inputSchema의 필드명에서 API 패턴 추출
        input_schema = tool.get("inputSchema", {})
        properties = input_schema.get("properties", {})
        for field_name, field_schema in properties.items():
            field_lower = field_name.lower()
            if any(keyword in field_lower for keyword in ["url", "endpoint", "api", "path", "route"]):
                field_desc = field_schema.get("description", "")
                if field_desc:
                    urls = re.findall(url_pattern, field_desc)
                    for url in urls:
                        try:
                            parsed = urlparse(url)
                            if parsed.netloc:
                                tool_apis.append({
                                    "method": "GET",
                                    "host": parsed.netloc,
                                    "path": parsed.path or "/",
                                })
                        except Exception:
                            pass
        
        if tool_apis:
            tool_api_map[tool_name] = tool_apis
    
    return tool_api_map


def main():
    args = parse_args()
    
    output_dir = Path(args.output_dir).resolve()
    
    # 볼륨 마운트로 인해 stat()이 실패할 수 있으므로, 직접 파일 쓰기로 권한 확인
    try:
        # 디렉토리 생성 시도
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError) as mkdir_error:
            # 디렉토리 생성 실패 (이미 존재하거나 권한 문제)
            pass
        
        # 권한 설정 시도 (볼륨 마운트로 인해 실패할 수 있음)
        try:
            os.chmod(output_dir, 0o777)
        except (PermissionError, OSError):
            # 권한 설정 실패해도 계속 진행 (볼륨 마운트로 인한 제한일 수 있음)
            pass
        
        # 실제 파일 쓰기로 권한 확인
        test_file = output_dir / '.write_test'
        try:
            test_file.write_text('test')
            test_file.unlink()
            print(f"[INFO] output 디렉토리 쓰기 권한 확인 완료: {output_dir}")
        except (PermissionError, OSError) as write_error:
            print(f"[ERROR] output 디렉토리에 쓰기 권한이 없습니다: {write_error}")
            print(f"[ERROR] 경로: {output_dir}")
            print(f"[ERROR] 호스트에서 디렉토리 권한을 확인해주세요: chmod -R 777 {output_dir}")
            sys.exit(1)
    except Exception as e:
        # 예상치 못한 오류
        print(f"[ERROR] output 디렉토리 확인 중 오류 발생: {e}")
        print(f"[ERROR] 경로: {output_dir}")
        # 파일 쓰기로 최종 확인
        try:
            test_file = output_dir / '.write_test'
            test_file.write_text('test')
            test_file.unlink()
            print(f"[INFO] 파일 쓰기 테스트 성공, 계속 진행")
        except:
            print(f"[ERROR] 파일 쓰기 테스트 실패, 분석을 중단합니다")
            sys.exit(1)
    
    # proxy_url은 나중에 동적으로 할당된 포트로 업데이트됨
    proxy_url = "http://127.0.0.1:8081"  # 초기값, 나중에 업데이트됨
    print(f"[DEBUG] --env-file 인자: {args.env_file}")
    env_overrides = load_env_file(args.env_file)
    print(f"[DEBUG] env_overrides: {list(env_overrides.keys())}")

    with tempfile.TemporaryDirectory(prefix="mcp-vetting-") as temp_dir:
        temp_path = Path(temp_dir)
        temp_proxy_log = temp_path / "proxy-log.jsonl"
        mitm_conf_dir = temp_path / "mitmproxy"
        repo_root = temp_path / "repo"

        print(f"저장소 클론 중: {args.git_url}" + (f" (브랜치: {args.branch})" if args.branch else ""))
        repo_name = extract_repo_name(args.git_url)
        cloned_path = clone_repository(args.git_url, repo_root, branch=args.branch)
        if not cloned_path:
            sys.exit(1)
        print(f"클론 완료: {repo_name}")

        tools: List[Dict[str, Any]] = []
        vulnerabilities: List[Dict[str, Any]] = []
        vuln_summary: Dict[str, int] = {}
        harness_report = None
        proxy_entries: List[Dict[str, Any]] = []
        
        if not args.auto:
            print("--auto 옵션이 필요합니다.", file=sys.stderr)
            sys.exit(1)
        
        runtime_plan: Optional[RuntimePlan] = None
        server_command: Optional[CommandType] = None

        mitm_conf_dir.mkdir(parents=True, exist_ok=True)

        # 사용 가능한 포트 찾기 (8081부터 시작하여 10개 포트 시도)
        proxy_port = None
        for port in range(8081, 8091):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result != 0:  # 포트가 사용 가능함
                proxy_port = port
                break
        
        if proxy_port is None:
            print("사용 가능한 포트를 찾을 수 없습니다 (8081-8090)", file=sys.stderr)
            sys.exit(1)
        
        print(f"mitmdump 실행 중... (포트: {proxy_port})")
        proxy_proc = start_mitmdump("mitmdump", "127.0.0.1", proxy_port, temp_proxy_log, mitm_conf_dir)
        time.sleep(1)
        if proxy_proc.poll() is not None:
            stdout, stderr = proxy_proc.communicate()
            print("mitmdump 실행 실패", file=sys.stderr)
            if stdout:
                print(stdout)
            if stderr:
                print(stderr, file=sys.stderr)
            sys.exit(1)
        
        # proxy_url 업데이트
        proxy_url = f"http://127.0.0.1:{proxy_port}"

        ca_paths = wait_for_mitmproxy_ca(mitm_conf_dir)
        if ca_paths:
            cer_path = ca_paths.get("cer")
            if cer_path and cer_path.exists():
                try:
                    system_ca_dir = Path("/usr/local/share/ca-certificates")
                    if system_ca_dir.exists():
                        target_ca = system_ca_dir / "mitmproxy-runtime.crt"
                        shutil.copy(cer_path, target_ca)
                        try:
                            subprocess.run(["update-ca-certificates"], check=False, capture_output=True)
                        except (subprocess.SubprocessError, FileNotFoundError):
                            pass
                except Exception:
                    pass

        print("런타임 자동 감지 중...")
        try:
            runtime_plan = detect_runtime(repo_root)
        except Exception as exc:
            print(f"런타임 감지 실패: {exc}", file=sys.stderr)
            sys.exit(1)

        print(f"감지된 런타임: {runtime_plan.name}")

        for step in runtime_plan.install_steps:
            print(f"준비 명령 실행: {_format_command(step)}")
            rc = run_command(step, repo_root, env_overrides)
            if rc != 0:
                print(f"준비 명령 실패 (exit {rc})", file=sys.stderr)
                sys.exit(1)

        server_command = runtime_plan.server_command.copy() if isinstance(runtime_plan.server_command, list) else list(runtime_plan.server_command)
        
        # --server-args가 있으면 server_command에 추가
        if args.server_args:
            # 인자를 공백으로 분리하여 리스트에 추가
            import shlex
            try:
                additional_args = shlex.split(args.server_args)
                server_command.extend(additional_args)
                print(f"[DEBUG] 서버 실행 인자 추가: {additional_args}")
            except Exception as e:
                print(f"[WARNING] 서버 인자 파싱 실패: {e}, 원본 문자열 사용: {args.server_args}", file=sys.stderr)
                # 파싱 실패 시 공백으로 분리
                additional_args = args.server_args.split()
                server_command.extend(additional_args)
        if runtime_plan.env:
            env_overrides.update(runtime_plan.env)
        if runtime_plan.work_dir:
            repo_root = runtime_plan.work_dir

        if ca_paths:
            pem_path = ca_paths.get("pem")
            if pem_path:
                pem_path = str(pem_path)
                env_overrides.setdefault("SSL_CERT_FILE", pem_path)
                env_overrides.setdefault("REQUESTS_CA_BUNDLE", pem_path)
                env_overrides.setdefault("NODE_EXTRA_CA_CERTS", pem_path)
                env_overrides.setdefault("GIT_SSL_CAINFO", pem_path)
                env_overrides.setdefault("CURL_CA_BUNDLE", pem_path)

        if not server_command:
            print("서버 실행 명령이 지정되지 않았습니다.", file=sys.stderr)
            sys.exit(1)

        print(f"MCP 서버 실행 중: {_format_command(server_command)}")
        is_http = runtime_plan and runtime_plan.transport_type == "http"
        server_proc = start_mcp_server(server_command, repo_root, proxy_url, env_overrides, background=is_http)
        
        if is_http:
            print("HTTP 서버 시작 대기 중...")
            time.sleep(3)
            if server_proc.poll() is not None:
                stdout, stderr = server_proc.communicate()
                print("HTTP 서버 시작 실패", file=sys.stderr)
                if stdout:
                    print(stdout)
                if stderr:
                    print(stderr, file=sys.stderr)
                server_proc = None
            else:
                http_url = runtime_plan.http_url
                import requests
                max_retries = 15
                for i in range(max_retries):
                    try:
                        response = requests.get(f"{http_url}/health", timeout=2)
                        if response.status_code == 200:
                            print("HTTP 서버 시작 확인")
                            break
                    except Exception:
                        if i < max_retries - 1:
                            time.sleep(1)
                        else:
                            print("HTTP 서버 health check 실패, 계속 진행합니다.", file=sys.stderr)
        else:
            time.sleep(5)
            if server_proc.poll() is not None:
                exit_code = server_proc.poll()
                stdout, stderr = server_proc.communicate()
                print(f"[오류] MCP 서버 시작 실패 (종료 코드: {exit_code})", file=sys.stderr)
                if stdout:
                    print(f"   stdout: {stdout[:1000]}", file=sys.stderr)
                if stderr:
                    print(f"   stderr: {stderr[:1000]}", file=sys.stderr)
                print("   MCP 서버가 시작되지 않아 tools/list를 호출할 수 없습니다.", file=sys.stderr)
                server_proc = None
            else:
                print(f"[TOOL-VET] MCP 서버 프로세스 실행 중 (PID: {server_proc.pid})")

        # 1단계: tools/list로 tool 목록 및 관련 정보 추출
        print("\n=== 1단계: tools/list로 tool 목록 추출 ===")
        
        # MCP 서버 프로세스 상태 확인
        if not is_http and not server_proc:
            print("[오류] MCP 서버 프로세스가 시작되지 않았습니다.", file=sys.stderr)
            print("   MCP 서버 시작에 실패했거나 프로세스가 종료되었습니다.", file=sys.stderr)
            kill_process(proxy_proc)
            sys.exit(1)
        
        if is_http and runtime_plan.http_url:
            print("HTTP 하네스 실행 중...")
            print(f"   HTTP URL: {runtime_plan.http_url}")
            try:
                harness_report = run_http_harness(runtime_plan.http_url, predefined_tools=None)
            except Exception as exc:
                print(f"HTTP 하네스 실행 실패: {exc}", file=sys.stderr)
                harness_report = HarnessReport(tools=[], calls=[])
        elif server_proc:
            print("내장 하네스 실행 중...")
            print(f"   MCP 서버 프로세스 PID: {server_proc.pid}")
            # 프로세스가 여전히 실행 중인지 확인
            if server_proc.poll() is not None:
                exit_code = server_proc.poll()
                stdout, stderr = server_proc.communicate()
                print(f"[오류] MCP 서버 프로세스가 종료되었습니다 (종료 코드: {exit_code})", file=sys.stderr)
                if stdout:
                    print(f"   stdout: {stdout[:500]}", file=sys.stderr)
                if stderr:
                    print(f"   stderr: {stderr[:500]}", file=sys.stderr)
                kill_process(proxy_proc)
                sys.exit(1)
            try:
                harness_report = run_builtin_harness(server_proc, predefined_tools=None)
            except Exception as exc:
                print(f"내장 하네스 실행 실패: {exc}", file=sys.stderr)
                harness_report = HarnessReport(tools=[], calls=[])
        else:
            print("[오류] MCP 서버 프로세스가 없습니다.", file=sys.stderr)
            kill_process(proxy_proc)
            sys.exit(1)
        
        if harness_report and harness_report.tools:
            tools = harness_report.tools
            print(f"[TOOL-VET] tools/list로 가져온 tool: {len(tools)}개")
        else:
            print("[오류] tools/list로 tool을 가져오지 못했습니다.", file=sys.stderr)
            # 오류 상세 정보 출력
            if harness_report and harness_report.calls:
                for call in harness_report.calls:
                    if not call.success:
                        print(f"   오류: {call.name} - {call.error}", file=sys.stderr)
            else:
                print("   harness_report가 없거나 calls가 비어있습니다.", file=sys.stderr)
            if server_proc:
                kill_process(server_proc)
            kill_process(proxy_proc)
            sys.exit(1)
        
        # OpenAPI 스펙에서 예상 API 목록 추출 (먼저 로드)
        expected_apis: List[Dict[str, Any]] = []
        openapi_files = find_openapi_files(repo_root)
        if openapi_files:
            print(f"\n=== OpenAPI 스펙에서 예상 API 추출 ===")
            for openapi_file in openapi_files:
                print(f"   발견: {openapi_file.relative_to(repo_root)}")
                apis = extract_apis_from_openapi(openapi_file)
                expected_apis.extend(apis)
            if expected_apis:
                print(f"   [TOOL-VET] {len(expected_apis)}개 예상 API 추출됨")
        
        # OpenAPI 스펙에서 원본 경로 패턴 추출 (tool 이름과 매칭) - 우선 처리
        tool_api_map: Dict[str, List[Dict[str, Any]]] = {}
        if expected_apis:
            print("\n=== OpenAPI 스펙에서 원본 경로 패턴 매핑 ===")
            # 모든 tool에 대해 OpenAPI 스펙 매핑 시도
            for tool in tools:
                tool_name = tool.get("name", "")
                
                # tool 이름에서 operation_id 추출 (예: "API-get-user" → "get-user")
                operation_id = tool_name.replace("API-", "").replace("_", "-")
                
                # OpenAPI 스펙에서 해당 operation_id 찾기
                matched = False
                for api in expected_apis:
                    if api.get("operation_id", "").lower() == operation_id.lower():
                        # 원본 경로 패턴을 path로 직접 사용
                        original_api = {
                            "method": api.get("method", "GET"),
                            "host": api.get("host", ""),
                            "path": api.get("path", ""),  # 원본 패턴 (예: /v1/blocks/{block_id}/children)
                        }
                        
                        # OpenAPI 스펙에서 찾은 원본 패턴만 사용
                        if tool_name not in tool_api_map:
                            tool_api_map[tool_name] = []
                        tool_api_map[tool_name].append(original_api)
                        print(f"  {tool_name}: {original_api['method']} {original_api['path']}")
                        matched = True
                        break
                
                # 매칭되지 않은 경우에도 빈 리스트로 초기화 (나중에 프록시 로그나 누락된 API 추가 가능)
                if not matched and tool_name not in tool_api_map:
                    tool_api_map[tool_name] = []
            
            print(f"[TOOL-VET] {len(tool_api_map)}개 tool에 OpenAPI 원본 경로 패턴 매핑됨")
        
        # OpenAPI 스펙에 없는 경우에만 tools/list 결과에서 API 정보 추출 (보조)
        # extract_apis_from_tools는 메타데이터에서만 추출하므로 sample 값이 나올 가능성 없음
        print("\n=== tools/list 결과에서 추가 API 정보 추출 ===")
        extracted_from_tools = extract_apis_from_tools(tools)
        for tool_name, apis in extracted_from_tools.items():
            if tool_name not in tool_api_map:
                # OpenAPI에 없는 tool만 추가
                tool_api_map[tool_name] = apis
                print(f"  {tool_name}: {len(apis)}개 API (tools/list에서 추출)")
        
        # 프록시 로그에서 실제 호출된 API 수집
        if temp_proxy_log.exists():
            try:
                with temp_proxy_log.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entry = json.loads(line)
                                proxy_entries.append(entry)
                            except json.JSONDecodeError:
                                continue
                print(f"[TOOL-VET] 프록시 로그에서 {len(proxy_entries)}개 API 요청 발견")
            except Exception as e:
                print(f"프록시 로그 읽기 실패: {e}", file=sys.stderr)
        
        # 프록시 로그에서 tool-API 매핑 수행 (OpenAPI 스펙이 있어도 프록시 로그의 실제 호출된 API 포함)
        if proxy_entries and harness_report and harness_report.calls:
            print("\n=== 프록시 로그에서 tool-API 매핑 ===")
            # tool 호출 timestamp와 프록시 로그 timestamp 매칭
            for call_result in harness_report.calls:
                if not call_result.success or not call_result.timestamp_start or not call_result.timestamp_end:
                    continue
                
                tool_name = call_result.name
                # 해당 tool 호출 시간 범위 내의 프록시 로그 찾기
                matched_apis = []
                for entry in proxy_entries:
                    entry_start = entry.get("timestamp_start")
                    if entry_start is None:
                        continue
                    
                    # tool 호출 시간 범위 내에 있는 API 요청
                    if call_result.timestamp_start <= entry_start <= call_result.timestamp_end:
                        import re
                        from urllib.parse import urlparse, parse_qs, urlencode
                        
                        path = entry.get("path", "")
                        
                        # URL 파싱 (경로 + 쿼리 파라미터)
                        parsed = urlparse(path if path.startswith('/') else f'/{path}')
                        path_part = parsed.path
                        query_part = parsed.query
                        
                        # 경로 부분: test-user, test-owner, test-repo, sample, dummy를 {param}으로 변환
                        test_values = ["test-user", "test-owner", "test-repo", "sample", "dummy"]
                        for test_val in test_values:
                            # 경로 세그먼트 단위로 매칭하여 {param}으로 변환
                            path_part = re.sub(rf'/{re.escape(test_val)}/', '/{param}/', path_part, flags=re.IGNORECASE)
                            path_part = re.sub(rf'/{re.escape(test_val)}$', '/{param}', path_part, flags=re.IGNORECASE)
                            path_part = re.sub(rf'^{re.escape(test_val)}/', '{param}/', path_part, flags=re.IGNORECASE)
                        
                        # UUID 패턴을 {param}으로 변환
                        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
                        path_part = re.sub(uuid_pattern, '{param}', path_part, flags=re.IGNORECASE)
                        
                        # 숫자 ID도 {param}으로 변환 (예: /issues/1 -> /issues/{param})
                        path_part = re.sub(r'/\d+', '/{param}', path_part)
                        path_part = re.sub(r'/\d+$', '/{param}', path_part)
                        
                        # 쿼리 파라미터도 정규화
                        if query_part:
                            query_params = parse_qs(query_part, keep_blank_values=True)
                            normalized_params = {}
                            for key, values in query_params.items():
                                normalized_values = []
                                for value in values:
                                    # 테스트 값 정규화
                                    normalized_value = value
                                    for test_val in test_values:
                                        if test_val.lower() in normalized_value.lower():
                                            normalized_value = '{param}'
                                            break
                                    # UUID 정규화
                                    if re.match(uuid_pattern, normalized_value, re.IGNORECASE):
                                        normalized_value = '{param}'
                                    # 숫자 정규화
                                    if normalized_value.isdigit():
                                        normalized_value = '{param}'
                                    normalized_values.append(normalized_value)
                                normalized_params[key] = normalized_values
                            # urlencode 대신 수동으로 쿼리 문자열 생성 (URL 인코딩 방지)
                            query_parts = []
                            for key, values in normalized_params.items():
                                for value in values:
                                    if value == '{param}':
                                        query_parts.append(f"{key}={value}")
                                    else:
                                        # 일반 값은 URL 인코딩
                                        from urllib.parse import quote
                                        query_parts.append(f"{key}={quote(str(value))}")
                            query_part = '&'.join(query_parts)
                        
                        # 정규화된 경로 재구성
                        normalized_path = path_part
                        if query_part:
                            normalized_path = f"{path_part}?{query_part}"
                        
                        api_info = {
                            "method": entry.get("method", "GET"),
                            "host": entry.get("host", ""),
                            "path": normalized_path,
                            "original_path": entry.get("path", ""),  # 원본 경로 저장 (검증용)
                            "request_body": entry.get("request_body"),  # request body 저장 (검증용)
                        }
                        
                        # 중복 제거
                        api_key = (api_info["method"], api_info["host"], api_info["path"])
                        if api_key not in {((a.get("method", "GET"), a.get("host", ""), a.get("path", ""))) for a in matched_apis}:
                            matched_apis.append(api_info)
                
                if matched_apis:
                    # tool_api_map에 추가 (기존 항목이 있으면 병합)
                    if tool_name not in tool_api_map:
                        tool_api_map[tool_name] = []
                    # 중복 제거하면서 추가
                    existing_keys = {(a.get("method", "GET"), a.get("host", ""), a.get("path", "")) for a in tool_api_map[tool_name]}
                    for api in matched_apis:
                        api_key = (api.get("method", "GET"), api.get("host", ""), api.get("path", ""))
                        if api_key not in existing_keys:
                            # tool 호출 arguments와 원본 프록시 로그 정보도 함께 저장
                            api["tool_call_arguments"] = call_result.arguments
                            tool_api_map[tool_name].append(api)
                            existing_keys.add(api_key)
            
            mapped_count = sum(1 for apis in tool_api_map.values() if apis)
            print(f"[TOOL-VET] {mapped_count}개 tool에 API 매핑됨")
        
        # GraphQL 엔드포인트 감지 및 스키마 추출
        graphql_info: Dict[str, Any] = {}
        if proxy_entries:
            # 프록시 로그에서 호스트 추출
            hosts = set()
            for entry in proxy_entries:
                host = entry.get("host", "")
                if host:
                    hosts.add(host)
            
            for host in hosts:
                base_url = f"https://{host}"
                graphql_endpoint = detect_graphql_endpoint(base_url)
                if graphql_endpoint:
                    print(f"\n=== GraphQL 엔드포인트 감지 ===")
                    print(f"   발견: {graphql_endpoint}")
                    
                    # Introspection 활성화 여부 확인
                    introspection_enabled = check_introspection_enabled(graphql_endpoint)
                    graphql_info["endpoint"] = graphql_endpoint
                    graphql_info["introspection_enabled"] = introspection_enabled
                    
                    if introspection_enabled:
                        print(f"   [경고] Introspection 활성화됨 (보안 취약점 가능)")
                        schema = introspect_graphql_schema(graphql_endpoint)
                        if schema:
                            operations = extract_operations_from_schema(schema)
                            graphql_info["operations"] = operations
                            graphql_info["schema"] = schema
                            print(f"   [TOOL-VET] {len(operations)}개 operation 추출됨")
                    else:
                        print(f"   [TOOL-VET] Introspection 비활성화됨 (안전)")
                    break
        
        # 수집된 API와 예상 API 비교
        if expected_apis and proxy_entries:
            from extractor.openapi_extractor import normalize_path_pattern
            collected_apis = [
                {
                    "method": entry.get("method", "GET"),
                    "host": entry.get("host", ""),
                    "path": entry.get("path", ""),
                }
                for entry in proxy_entries
            ]
            matched, missing = match_api_patterns(expected_apis, collected_apis)
            if missing:
                print(f"\n   [경고] 누락된 API 패턴: {len(missing)}개")
                print(f"   [TOOL-VET] 매칭된 API 패턴: {len(matched)}개")
                if len(expected_apis) > 0:
                    collection_rate = (len(matched) / len(set(normalize_path_pattern(api.get("path", "")) for api in expected_apis))) * 100
                    print(f"   [TOOL-VET] 수집률: {collection_rate:.1f}%")
        
        if server_proc:
            kill_process(server_proc)
        kill_process(proxy_proc)

        # 2단계: 각 tool별로 API 취약점 점검
        print("\n=== 2단계: 각 tool별로 API 취약점 점검 ===")
        if tools:
            print(f"총 {len(tools)}개 tool에 대해 취약점 점검 시작...")
            
            # 전체 tools에 대한 구조적 취약점 스캔 (MCP-01, MCP-04) - 한 번만 수행
            # API 엔드포인트가 없는 도구들도 포함하여 스캔
            all_tool_apis = []
            for tool_name, apis in tool_api_map.items():
                all_tool_apis.extend(apis)
            
            # 전체 tool 호출 arguments 맵 생성
            all_tool_call_arguments_map = {}
            if harness_report and harness_report.calls:
                for call_result in harness_report.calls:
                    if call_result.arguments:
                        all_tool_call_arguments_map[call_result.name] = call_result.arguments
            
            # 전체 tools에 대한 구조적 취약점 스캔 (중복 방지를 위해 한 번만 수행)
            global_scan_result = scan_mcp_specific(
                None,
                None,
                proxy_entries,
                tools,  # 전체 tools 리스트
                all_tool_apis,  # 모든 tool의 API
                all_tool_call_arguments_map
            )
            
            # 전역 취약점 추가 (MCP-01, MCP-04 등)
            if global_scan_result and global_scan_result.vulnerabilities:
                for v in global_scan_result.vulnerabilities:
                    # tool_name이 None이면 전역 취약점
                    if v.tool_name is None:
                        # 중복 체크
                        existing = next((existing_v for existing_v in vulnerabilities 
                                        if existing_v.get("category_code") == v.category_code 
                                        and existing_v.get("title") == v.title), None)
                        if not existing:
                            vulnerabilities.append({
                                "category_code": v.category_code,
                                "category_name": v.category_name,
                                "title": v.title,
                                "description": v.description,
                                "tool_name": None,
                                "api_endpoint": v.api_endpoint,
                                "evidence": v.evidence,
                                "recommendation": v.recommendation,
                            })
                for cat, count in global_scan_result.summary.items():
                    vuln_summary[cat] = vuln_summary.get(cat, 0) + count
            
            # 각 tool별로 API 취약점 점검 (MCP-02, MCP-03)
            for tool in tools:
                tool_name = tool.get("name", "")
                tool_apis = tool_api_map.get(tool_name, [])
                
                # OpenAPI 스펙에서 예상 API가 있으면 누락된 API 확인
                if expected_apis:
                    # tool 이름에서 operation_id 추출 시도
                    operation_id = tool_name.replace("API-", "").replace("_", "-")
                    
                    # OpenAPI 스펙에서 해당 tool의 예상 API 찾기
                    tool_expected_apis = [
                        api for api in expected_apis
                        if api.get("operation_id", "").lower() == operation_id.lower()
                    ]
                    
                    # tool_expected_apis가 있으면 반드시 tool_api_map에 포함되어야 함
                    if tool_expected_apis:
                        # 현재 tool_apis에 있는 경로 패턴 정규화
                        from extractor.openapi_extractor import normalize_path_pattern
                        collected_paths = {normalize_path_pattern(api.get("path", "")) for api in tool_apis}
                        
                        # 예상 API 중 수집되지 않은 것 찾기
                        missing_apis = []
                        for expected_api in tool_expected_apis:
                            expected_path = normalize_path_pattern(expected_api.get("path", ""))
                            if expected_path not in collected_paths:
                                missing_apis.append(expected_api)
                        
                        if missing_apis:
                            # 누락된 API를 tool_api_map에 추가 (리포트에 포함되도록)
                            if tool_name not in tool_api_map:
                                tool_api_map[tool_name] = []
                            for missing_api in missing_apis:
                                # 원본 경로 패턴만 추가 (sample 값 없음)
                                tool_api_map[tool_name].append({
                                    "method": missing_api.get("method", "GET"),
                                    "host": missing_api.get("host", ""),
                                    "path": missing_api.get("path", ""),  # 원본 패턴 (예: /v1/blocks/{block_id}/children)
                                    "note": "예상 API (실제 호출되지 않음)"
                                })
                            tool_apis = tool_api_map.get(tool_name, [])
                    else:
                        # tool_expected_apis가 없으면 OpenAPI 스펙에 해당 operation_id가 없는 것
                        # 하지만 OpenAPI 스펙 매핑 단계에서 이미 처리되었을 수 있음
                        pass
                
                # tool_apis에서 중복 제거 (sample 값은 이미 추가되지 않았으므로 필터링 불필요)
                filtered_tool_apis = []
                seen_paths = set()
                for api in tool_apis:
                    path = api.get("path", "")
                    # 중복 제거만 수행
                    path_key = (api.get("method", "GET"), path)
                    if path_key not in seen_paths:
                        seen_paths.add(path_key)
                        filtered_tool_apis.append(api)
                
                tool_apis = filtered_tool_apis
                
                # curl_command를 먼저 생성 (검증에 필요)
                tool_apis_with_curl = []
                for api in tool_apis:
                    api_with_curl = api.copy()
                    curl_cmd = generate_curl_from_api(
                        api.get("method", "GET"),
                        api.get("host", ""),
                        api.get("path", ""),
                    )
                    if curl_cmd:
                        api_with_curl["curl_command"] = curl_cmd
                    tool_apis_with_curl.append(api_with_curl)
                
                # tool 호출 arguments 맵 생성
                tool_call_arguments_map = {}
                if harness_report and harness_report.calls:
                    for call_result in harness_report.calls:
                        if call_result.name == tool_name and call_result.arguments:
                            tool_call_arguments_map[tool_name] = call_result.arguments
                            break
                
                # tool별 취약점 스캔 (API가 없어도 실행 - Command Injection 등 구조적 취약점 탐지)
                # 해당 tool만 전달하여 tool별 취약점만 탐지 (성능 개선: 전체 tools 스캔 제거)
                # MCP-01, MCP-04는 이미 위에서 전체 스캔으로 처리됨
                # 하지만 tool별 구조적 취약점(예: Command Injection)은 여기서 탐지됨
                mcp_scan_result = scan_mcp_specific(
                    None,
                    None,
                    proxy_entries,
                    [tool],  # 해당 tool만 전달 (성능 개선)
                    tool_apis_with_curl,  # 해당 tool의 API만 전달 (비어있을 수 있음)
                    tool_call_arguments_map
                )
                
                if mcp_scan_result and mcp_scan_result.vulnerabilities:
                    for v in mcp_scan_result.vulnerabilities:
                        # tool_name이 있는 tool별 취약점만 추가 (전역 취약점은 이미 추가됨)
                        # 또는 해당 tool과 관련된 취약점만 추가
                        if v.tool_name is not None and v.tool_name == tool_name:
                            # 중복 체크
                            existing = next((existing_v for existing_v in vulnerabilities 
                                            if existing_v.get("category_code") == v.category_code 
                                            and existing_v.get("tool_name") == v.tool_name
                                            and existing_v.get("api_endpoint") == v.api_endpoint), None)
                            if not existing:
                                vulnerabilities.append({
                                    "category_code": v.category_code,
                                    "category_name": v.category_name,
                                    "title": v.title,
                                    "description": v.description,
                                    "tool_name": v.tool_name,
                                    "api_endpoint": v.api_endpoint,
                                    "evidence": v.evidence,
                                    "recommendation": v.recommendation,
                                })
                    for cat, count in mcp_scan_result.summary.items():
                        vuln_summary[cat] = vuln_summary.get(cat, 0) + count
                
                # tool_api_map 업데이트 (curl_command 포함)
                tool_api_map[tool_name] = tool_apis_with_curl
            
            if vulnerabilities:
                print(f"[TOOL-VET] 총 {len(vulnerabilities)}개 취약점 발견")
            else:
                print("[TOOL-VET] 취약점이 발견되지 않았습니다.")
        
        # 리포트 생성
        print("\n=== 리포트 생성 ===")
        integrated_tools = []
        for tool in tools:
            tool_name = tool.get("name", "")
            tool_apis = tool_api_map.get(tool_name, [])
            # tool별 취약점
            tool_vulns = [v for v in vulnerabilities if v.get("tool_name") == tool_name]
            
            # 전역 MCP 취약점 중에서 이 tool의 API와 관련된 것도 찾기
            # 모든 취약점은 api_endpoint와 함께 매핑되어 api_endpoints[].vulnerabilities에만 포함
            for vuln in vulnerabilities:
                if not vuln.get("tool_name") and vuln.get("category_code", "").startswith("MCP-"):
                    # MCP-02: 동적 경로 사용 취약점은 동적 경로가 있는 API에만 적용
                    if vuln.get("category_code") == "MCP-02":
                        for api in tool_apis:
                            # 동적 경로가 있는 API인지 확인
                            if "/{" in api.get("path", "") or "/{param}" in api.get("path", ""):
                                tool_vulns.append({
                                    **vuln,
                                    "api_endpoint": f"{api.get('method')} {api.get('host')}{api.get('path')}"
                                })
                    # MCP-03: 수정/삭제 작업 취약점은 해당 작업이 있는 API에만 적용
                    elif vuln.get("category_code") == "MCP-03":
                        for api in tool_apis:
                            method = api.get("method", "").upper()
                            if method in ["DELETE", "PATCH", "PUT", "POST"]:
                                tool_vulns.append({
                                    **vuln,
                                    "api_endpoint": f"{api.get('method')} {api.get('host')}{api.get('path')}"
                                })
                    # 기타: api_endpoint가 있으면 매칭
                    elif vuln.get("api_endpoint"):
                        vuln_api = vuln.get("api_endpoint", "")
                        for api in tool_apis:
                            api_key = f"{api.get('method')} {api.get('host')}{api.get('path')}"
                            if vuln_api in api_key or api_key in vuln_api or api.get('path') in vuln_api:
                                tool_vulns.append({
                                    **vuln,
                                    "api_endpoint": api_key
                                })
                                break
            
            # 하네스 실행 결과에서 해당 tool의 호출 결과 찾기
            tool_call_result = None
            if harness_report and harness_report.calls:
                for call_result in harness_report.calls:
                    if call_result.name == tool_name:
                        tool_call_result = {
                            "success": call_result.success,
                            "error": call_result.error if not call_result.success else None,
                        }
                        break
            
            # 각 API에 대해 cURL 명령어 확인 (이미 생성되어 있으면 재사용)
            api_endpoints_with_curl = []
            for api in tool_apis:
                api_with_curl = api.copy()
                # curl_command가 이미 있으면 재사용, 없으면 생성
                if "curl_command" not in api_with_curl:
                    curl_cmd = generate_curl_from_api(
                        api.get("method", "GET"),
                        api.get("host", ""),
                        api.get("path", ""),
                    )
                    if curl_cmd:
                        api_with_curl["curl_command"] = curl_cmd
                api_endpoints_with_curl.append(api_with_curl)
            
            # tool 호출 arguments 가져오기
            tool_call_arguments = None
            if harness_report and harness_report.calls:
                for call_result in harness_report.calls:
                    if call_result.name == tool_name and call_result.arguments:
                        tool_call_arguments = call_result.arguments
                        break
            
            # API별로 취약점 그룹화 및 실제 검증
            api_vulnerabilities = {}
            tool_level_vulnerabilities = []  # API가 없는 tool별 취약점 (예: Command Injection)
            seen_vulns = set()  # 중복 제거용 (전체 범위)
            for vuln in tool_vulns:
                api_endpoint = vuln.get("api_endpoint")
                if api_endpoint:
                    # 중복 제거: (api_endpoint, category_code, title) 조합으로
                    vuln_key = (api_endpoint, vuln.get("category_code"), vuln.get("title"))
                    if vuln_key not in seen_vulns:
                        seen_vulns.add(vuln_key)
                        if api_endpoint not in api_vulnerabilities:
                            api_vulnerabilities[api_endpoint] = []
                        
                        # 실제 검증 수행
                        vuln_data = {
                            "category_code": vuln.get("category_code"),
                            "category_name": vuln.get("category_name"),
                            "title": vuln.get("title"),
                            "description": vuln.get("description"),
                            "evidence": vuln.get("evidence"),
                            "recommendation": vuln.get("recommendation"),
                        }
                        
                        # 해당 API의 curl_command와 원본 정보 찾기
                        matching_api = None
                        for api in tool_apis_with_curl:
                            api_key_check = f"{api.get('method')} {api.get('host')}{api.get('path')}"
                            if api_key_check == api_endpoint:
                                matching_api = api
                                break
                        
                        if matching_api:
                            curl_cmd = matching_api.get("curl_command", "")
                            api_path = matching_api.get("path", "")
                            api_method = matching_api.get("method", "GET")
                            api_request_body = matching_api.get("request_body")
                            
                            # 실제 검증 수행 (MCP-02, MCP-03만)
                            if curl_cmd and vuln.get("category_code") in ["MCP-02", "MCP-03"]:
                                try:
                                    is_verified, verified_evidence, verification_details = verify_mcp_vulnerability(
                                        vuln.get("category_code"),
                                        curl_cmd,
                                        tool_call_arguments,
                                        api_path,
                                        api_method,
                                        api_request_body,
                                    )
                                    
                                    if is_verified:
                                        # 실제 검증된 경우 evidence 업데이트
                                        vuln_data["evidence"] = f"[실제 검증됨] {verified_evidence}"
                                        vuln_data["verification"] = verification_details
                                    else:
                                        # 검증 실패한 경우 패턴 기반임을 명시
                                        if "패턴 기반" not in vuln_data["evidence"]:
                                            vuln_data["evidence"] = f"[패턴 기반 탐지] {vuln.get('evidence', '')}"
                                        vuln_data["verification"] = verification_details
                                except Exception as e:
                                    # 검증 중 오류 발생 시 원본 evidence 유지
                                    vuln_data["evidence"] = f"[검증 오류] {vuln.get('evidence', '')} (오류: {str(e)})"
                        
                        api_vulnerabilities[api_endpoint].append(vuln_data)
                else:
                    # API 엔드포인트가 없는 tool별 취약점 (예: Command Injection)
                    vuln_key = (vuln.get("category_code"), vuln.get("title"))
                    if vuln_key not in seen_vulns:
                        seen_vulns.add(vuln_key)
                        tool_level_vulnerabilities.append({
                            "category_code": vuln.get("category_code"),
                            "category_name": vuln.get("category_name"),
                            "title": vuln.get("title"),
                            "description": vuln.get("description"),
                            "evidence": vuln.get("evidence"),
                            "recommendation": vuln.get("recommendation"),
                        })
            
            # API 엔드포인트에 취약점 정보 추가
            for api in api_endpoints_with_curl:
                api_key = f"{api.get('method')} {api.get('host')}{api.get('path')}"
                if api_key in api_vulnerabilities:
                    api["vulnerabilities"] = api_vulnerabilities[api_key]
                else:
                    api["vulnerabilities"] = []
            
            # API가 없는 tool별 취약점은 tool 레벨에 추가 (예: Command Injection)
            
            tool_data = {
                "name": tool_name,
                "description": tool.get("description", ""),
                "inputSchema": tool.get("inputSchema", {}),
                "api_endpoints": api_endpoints_with_curl,  # 각 API에 vulnerabilities 포함됨
            }
            if tool_level_vulnerabilities:
                tool_data["vulnerabilities"] = tool_level_vulnerabilities  # API가 없는 tool별 취약점
            if tool_call_result:
                tool_data["harness_result"] = tool_call_result
            integrated_tools.append(tool_data)
        
        # 전역 취약점 추출 및 중복 제거 (MCP 특화만)
        global_vulns_raw = [v for v in vulnerabilities if not v.get("tool_name") and v.get("category_code", "").startswith("MCP-")]
        # 카테고리와 제목으로 중복 제거
        seen_global = set()
        global_vulnerabilities = []
        for v in global_vulns_raw:
            key = (v.get("category_code"), v.get("title"))
            if key not in seen_global:
                seen_global.add(key)
                global_vulnerabilities.append(v)
        
        # 하네스 실행 통계
        harness_stats = {}
        if harness_report and harness_report.calls:
            total_calls = len(harness_report.calls)
            successful_calls = sum(1 for r in harness_report.calls if r.success)
            failed_calls = total_calls - successful_calls
            harness_stats = {
                "total_tool_calls": total_calls,
                "successful_calls": successful_calls,
                "failed_calls": failed_calls,
                "success_rate": (successful_calls / total_calls * 100) if total_calls > 0 else 0,
            }
        
        # GraphQL 정보 추가
        report_data = {
            "tools": integrated_tools,
            "global_vulnerabilities": global_vulnerabilities,
            "summary": {
                "total_tools": len(integrated_tools),
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerability_summary": vuln_summary,
                "harness_stats": harness_stats,
            }
        }
        
        if graphql_info:
            report_data["graphql"] = graphql_info
        
        report_file = output_dir / f"{repo_name}-report.json"
        with report_file.open("w", encoding="utf-8") as handle:
            json.dump(report_data, handle, indent=2, ensure_ascii=False)
        
        print(f"[TOOL-VET] 결과 저장: {report_file}")
        print(f"   - Tools: {len(integrated_tools)}개")
        print(f"   - 취약점: {len(vulnerabilities)}개")
        if vuln_summary:
            print(f"   - 카테고리별: {vuln_summary}")


if __name__ == "__main__":
    main()


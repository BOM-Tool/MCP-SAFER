"""OpenAPI 스펙에서 API 엔드포인트 추출"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


def find_openapi_files(repo_root: Path) -> List[Path]:
    """저장소에서 OpenAPI 스펙 파일 찾기"""
    candidates: List[Path] = []
    
    # 일반적인 OpenAPI 파일 이름 패턴
    common_names = [
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "swagger.json",
        "swagger.yaml",
        "api.json",
        "api.yaml",
        "*openapi*.json",
        "*openapi*.yaml",
        "*openapi*.yml",
        "*swagger*.json",
        "*swagger*.yaml",
    ]
    
    exclude_dirs = {"node_modules", ".git", "dist", "build", "vendor", ".venv", "__pycache__"}
    
    # 루트 디렉터리에서 찾기
    for name in common_names:
        if "*" in name:
            # 패턴 매칭
            import fnmatch
            for item in repo_root.iterdir():
                if item.is_file() and fnmatch.fnmatch(item.name, name):
                    candidates.append(item)
        else:
            candidate = repo_root / name
            if candidate.exists():
                candidates.append(candidate)
    
    # scripts/, docs/, spec/ 디렉터리에서 찾기
    for subdir in ["scripts", "docs", "spec", "api", "openapi"]:
        subdir_path = repo_root / subdir
        if subdir_path.is_dir():
            for name in common_names:
                if "*" in name:
                    import fnmatch
                    try:
                        for item in subdir_path.iterdir():
                            if item.is_file() and fnmatch.fnmatch(item.name, name):
                                candidates.append(item)
                    except PermissionError:
                        pass
                else:
                    candidate = subdir_path / name
                    if candidate.exists():
                        candidates.append(candidate)
    
    # 재귀적으로 찾기 (깊이 2까지만, 특정 디렉터리 제외)
    try:
        for item in repo_root.iterdir():
            if item.is_dir() and item.name not in exclude_dirs:
                for name in common_names:
                    if "*" in name:
                        import fnmatch
                        try:
                            for subitem in item.iterdir():
                                if subitem.is_file() and fnmatch.fnmatch(subitem.name, name):
                                    candidates.append(subitem)
                        except (PermissionError, OSError):
                            pass
                    else:
                        candidate = item / name
                        if candidate.exists():
                            candidates.append(candidate)
    except (PermissionError, OSError):
        pass
    
    # 중복 제거
    return list(set(candidates))


def extract_apis_from_openapi(openapi_path: Path) -> List[Dict[str, Any]]:
    """OpenAPI 스펙 파일에서 API 엔드포인트 추출"""
    try:
        content = openapi_path.read_text(encoding="utf-8")
        
        # YAML 파일인 경우
        if openapi_path.suffix in {".yaml", ".yml"}:
            try:
                import yaml
                spec = yaml.safe_load(content)
            except ImportError:
                return []
        else:
            # JSON 파일인 경우
            spec = json.loads(content)
        
        apis: List[Dict[str, Any]] = []
        paths = spec.get("paths", {})
        servers = spec.get("servers", [])
        base_url = servers[0].get("url", "") if servers else ""
        
        # base_url에서 호스트 추출
        host = ""
        if base_url:
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            host = parsed.netloc
        
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    apis.append({
                        "method": method.upper(),
                        "host": host,
                        "path": path,
                        "operation_id": operation.get("operationId", ""),
                    })
        
        return apis
    except Exception:
        return []


def normalize_path_pattern(path: str) -> str:
    """경로 패턴 정규화 (동적 파라미터를 {param}으로 통일)"""
    # 이미 {param} 형식인 경우
    normalized = re.sub(r'\{[^}]+\}', '{param}', path)
    return normalized


def match_api_patterns(
    expected_apis: List[Dict[str, Any]],
    collected_apis: List[Dict[str, Any]]
) -> Tuple[Set[Tuple[str, str, str]], Set[Tuple[str, str, str]]]:
    """예상 API와 수집된 API를 패턴으로 매칭"""
    expected_patterns = set()
    for api in expected_apis:
        pattern = normalize_path_pattern(api.get("path", ""))
        expected_patterns.add((
            api.get("method", "GET"),
            api.get("host", ""),
            pattern
        ))
    
    collected_patterns = set()
    for api in collected_apis:
        pattern = normalize_path_pattern(api.get("path", ""))
        collected_patterns.add((
            api.get("method", "GET"),
            api.get("host", ""),
            pattern
        ))
    
    missing = expected_patterns - collected_patterns
    matched = expected_patterns & collected_patterns
    
    return matched, missing


def get_missing_apis_for_tool(
    tool_name: str,
    tool_operation_id: Optional[str],
    expected_apis: List[Dict[str, Any]],
    collected_apis: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """특정 tool에 대해 누락된 API 목록 반환"""
    if not tool_operation_id:
        return []
    
    # operation_id로 예상 API 찾기
    tool_expected_apis = [
        api for api in expected_apis
        if api.get("operation_id", "").lower() == tool_operation_id.lower()
    ]
    
    if not tool_expected_apis:
        return []
    
    # 수집된 API와 비교
    collected_paths = {normalize_path_pattern(api.get("path", "")) for api in collected_apis}
    
    missing = []
    for expected_api in tool_expected_apis:
        pattern = normalize_path_pattern(expected_api.get("path", ""))
        if pattern not in collected_paths:
            missing.append(expected_api)
    
    return missing


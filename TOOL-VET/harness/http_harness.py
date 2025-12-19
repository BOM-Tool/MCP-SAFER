from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from harness.builtin import HarnessReport, ToolCallResult, _build_arguments
from harness.http_client import HTTPMCPClient


def run_http_harness(
    http_url: str,
    max_tools: int = 0,
    resources: Optional[Dict[str, Any]] = None,
    auth_token: Optional[str] = None,
    predefined_tools: Optional[List[Dict[str, Any]]] = None,
) -> HarnessReport:
    client = HTTPMCPClient(http_url, timeout=30.0, auth_token=auth_token)
    tools: List[Dict[str, Any]] = []
    results: List[ToolCallResult] = []

    if resources is None:
        resources = {}

    try:
        client.initialize()
    except Exception as exc:
        error_msg = str(exc)
        print(f"HTTP initialize 실패: {error_msg}", file=__import__("sys").stderr)
        return HarnessReport(tools=[], calls=[ToolCallResult(name="initialize", success=False, error=error_msg)])

    try:
        if predefined_tools:
            tools = predefined_tools
        else:
            tools = client.list_tools()
    except Exception as exc:
        error_msg = str(exc)
        print(f"HTTP tools/list 실패: {error_msg}", file=__import__("sys").stderr)
        return HarnessReport(tools=[], calls=[ToolCallResult(name="tools/list", success=False, error=error_msg)])

    tool_list = tools if max_tools == 0 else tools[:max_tools]
    
    print(f"총 {len(tool_list)}개 도구 호출 시작...")
    for i, tool in enumerate(tool_list, 1):
        name = tool.get("name", "unknown")
        timestamp_start = time.time()
        try:
            args = _build_arguments(tool, resources)
            client.call_tool(name, args)
            timestamp_end = time.time()
            results.append(ToolCallResult(name=name, success=True, timestamp_start=timestamp_start, timestamp_end=timestamp_end))
            if i % 10 == 0 or i == len(tool_list):
                print(f"   진행: {i}/{len(tool_list)} (성공: {sum(1 for r in results if r.success)}개)")
        except TimeoutError:
            timestamp_end = time.time()
            results.append(ToolCallResult(name=name, success=False, error="Timeout", timestamp_start=timestamp_start, timestamp_end=timestamp_end))
            if i % 10 == 0 or i == len(tool_list):
                print(f"   진행: {i}/{len(tool_list)} (성공: {sum(1 for r in results if r.success)}개)")
        except Exception as exc:
            timestamp_end = time.time()
            error_msg = str(exc)
            if len(error_msg) > 200:
                error_msg = error_msg[:200] + "..."
            results.append(ToolCallResult(name=name, success=False, error=error_msg, timestamp_start=timestamp_start, timestamp_end=timestamp_end))
            if i % 10 == 0 or i == len(tool_list):
                print(f"   진행: {i}/{len(tool_list)} (성공: {sum(1 for r in results if r.success)}개)")

    try:
        client.shutdown()
    except Exception:
        pass

    return HarnessReport(tools=tools, calls=results)


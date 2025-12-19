from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional

import requests


class HTTPMCPClient:
    def __init__(self, base_url: str, timeout: float = 30.0, auth_token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.auth_token = auth_token
        self.session_id: Optional[str] = None
        self._next_id = 1
        self._headers = {
            "Content-Type": "application/json",
        }
        if auth_token:
            self._headers["Authorization"] = f"Bearer {auth_token}"

    def initialize(self) -> None:
        params = {
            "clientInfo": {"name": "mcp-vetting", "version": "0.1.0"},
            "protocolVersion": "2025-06-18",
            "capabilities": {},
        }
        response = self._request("initialize", params)
        self.session_id = response.get("sessionId") or str(uuid.uuid4())

    def list_tools(self) -> List[Dict[str, Any]]:
        response = self._request("tools/list", {})
        return response.get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        params = {"name": name, "arguments": arguments}
        return self._request("tools/call", params)

    def shutdown(self) -> None:
        try:
            self._request("shutdown", {})
        except Exception:
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

        headers = self._headers.copy()
        if self.session_id:
            headers["mcp-session-id"] = self.session_id

        try:
            response = requests.post(
                f"{self.base_url}/mcp",
                json=message,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            result = response.json()

            if "error" in result:
                error_msg = result["error"].get("message", "알 수 없는 오류")
                error_code = result["error"].get("code", -1)
                raise RuntimeError(f"JSON-RPC 오류 (코드 {error_code}): {error_msg}")
            
            response_result = result.get("result", {})
            
            if method == "initialize" and "sessionId" in response_result:
                self.session_id = response_result["sessionId"]
            
            return response_result
        except requests.exceptions.Timeout:
            raise TimeoutError(f"HTTP 요청 타임아웃: {method}")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"HTTP 요청 실패: {e}")


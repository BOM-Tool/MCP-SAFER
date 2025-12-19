"""
mitmproxy 애드온: HTTP(S) 트래픽을 JSON 라인 포맷으로 기록.
"""

import json
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http


class JsonFlowLogger:
    def __init__(self):
        self.output_path: Optional[Path] = None

    def load(self, loader):
        loader.add_option(
            "logger_output",
            str,
            "",
            "트래픽 로그를 기록할 JSONL 파일 경로",
        )

    def configure(self, updated):
        if "logger_output" in updated:
            output = ctx.options.logger_output
            if output:
                self.output_path = Path(output).expanduser().resolve()
                self.output_path.parent.mkdir(parents=True, exist_ok=True)
                self.output_path.write_text("", encoding="utf-8")
            else:
                self.output_path = None

    def response(self, flow: http.HTTPFlow):
        if not self.output_path:
            return

        # request body 추출 (JSON인 경우 파싱)
        request_body = None
        if flow.request.content:
            try:
                request_body_str = flow.request.content.decode("utf-8")
                if request_body_str:
                    try:
                        request_body = json.loads(request_body_str)
                    except json.JSONDecodeError:
                        request_body = request_body_str
            except (UnicodeDecodeError, AttributeError):
                pass
        
        # request body를 문자열로도 저장 (비-JSON인 경우)
        request_body_raw = None
        if flow.request.content:
            try:
                request_body_raw = flow.request.content.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                pass
        
        entry = {
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": flow.request.host,
            "port": flow.request.port,
            "path": flow.request.path,
            "http_version": flow.request.http_version,
            "timestamp_start": flow.request.timestamp_start,
            "timestamp_end": flow.response.timestamp_end if flow.response else None,
            "status_code": flow.response.status_code if flow.response else None,
            "response_headers": dict(flow.response.headers) if flow.response else {},
            "request_headers": dict(flow.request.headers),
            "request_body": request_body,  # 파싱된 JSON 또는 문자열
            "request_body_raw": request_body_raw,  # 원본 문자열
        }

        with self.output_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


addons = [JsonFlowLogger()]


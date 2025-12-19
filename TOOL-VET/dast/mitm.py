from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, Optional

from dast.certs import collect_mitmproxy_ca


def wait_for_mitmproxy_ca(conf_dir: Path, timeout: float = 10.0, poll_interval: float = 0.5) -> Optional[Dict[str, Path]]:
    """지정된 conf_dir에서 mitmproxy CA 파일이 생성될 때까지 대기."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return collect_mitmproxy_ca(conf_dir)
        except FileNotFoundError:
            time.sleep(poll_interval)
    return None


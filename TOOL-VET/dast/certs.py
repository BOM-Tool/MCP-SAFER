from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional


def collect_mitmproxy_ca(conf_dir: Path) -> Dict[str, Path]:
    """mitmproxy CA 파일 경로를 수집합니다."""
    cer_path = conf_dir / "mitmproxy-ca-cert.cer"
    pem_path = conf_dir / "mitmproxy-ca-cert.pem"
    
    if not cer_path.exists():
        raise FileNotFoundError(f"mitmproxy CA cert not found: {cer_path}")
    if not pem_path.exists():
        raise FileNotFoundError(f"mitmproxy CA pem not found: {pem_path}")
    
    return {
        "cer": cer_path,
        "pem": pem_path,
    }


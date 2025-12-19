import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime


class ScanResultWriter:
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def save_json(self, results: Dict[str, Any], filename: str) -> Path:
        output_file = self.output_dir / filename
        output_file.write_text(
            json.dumps(results, indent=2, ensure_ascii=False), 
            encoding="utf-8"
        )
        return output_file
    
    def save_scan_result(self, results: Dict[str, Any], repo_name: str) -> Path:
        filename = self.generate_filename(repo_name)
        return self.save_json(results, filename)
    
    def save_mcp_scan_result(self, results: Dict[str, Any]) -> Path:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"mcp_scan_{timestamp}.json"
        return self.save_json(results, filename)
    
    @staticmethod
    def generate_filename(repo_name: str, prefix: str = "", suffix: str = "") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        parts = []
        if prefix:
            parts.append(prefix)
        parts.append(repo_name)
        parts.append(timestamp)
        if suffix:
            parts.append(suffix)
        
        return "_".join(parts) + ".json"
    
    def get_output_path(self, filename: str) -> Path:
        return self.output_dir / filename
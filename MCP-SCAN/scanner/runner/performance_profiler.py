import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class FileProfile:
    file_path: str
    language: str
    total_time: float = 0.0
    ast_parse_time: float = 0.0
    pattern_match_time: float = 0.0
    mcp_scan_time: float = 0.0
    cfg_build_time: float = 0.0
    taint_analysis_time: float = 0.0
    findings_count: int = 0
    file_size: int = 0
    lines_count: int = 0
    error: Optional[str] = None


@dataclass
class PerformanceProfile:
    total_duration: float = 0.0
    repository_prep_time: float = 0.0
    language_detection_time: float = 0.0
    file_scan_time: float = 0.0
    mcp_scan_time: float = 0.0
    file_profiles: List[FileProfile] = field(default_factory=list)
    language_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    total_files: int = 0
    total_findings: int = 0


class PerformanceProfiler:
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.profile = PerformanceProfile()
        self.file_profiles: Dict[str, FileProfile] = {}
        self.lock = threading.Lock()
        self.timers: Dict[str, float] = {}
    
    def start_timer(self, name: str) -> None:
        if not self.enabled:
            return
        self.timers[name] = time.time()
    
    def stop_timer(self, name: str) -> float:
        if not self.enabled:
            return 0.0
        if name not in self.timers:
            return 0.0
        elapsed = time.time() - self.timers[name]
        del self.timers[name]
        return elapsed
    
    def record_repository_prep(self, duration: float) -> None:
        if not self.enabled:
            return
        with self.lock:
            self.profile.repository_prep_time = duration
    
    def record_language_detection(self, duration: float) -> None:
        if not self.enabled:
            return
        with self.lock:
            self.profile.language_detection_time = duration
    
    def start_file_scan(self, file_path: str, language: str) -> None:
        if not self.enabled:
            return
        with self.lock:
            profile = FileProfile(
                file_path=str(file_path),
                language=language
            )
            self.file_profiles[str(file_path)] = profile
            self.timers[f"file_{file_path}"] = time.time()
            
            try:
                path = Path(file_path)
                if path.exists():
                    profile.file_size = path.stat().st_size
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            profile.lines_count = len(f.readlines())
                    except (IOError, OSError, PermissionError):
                        pass
            except (OSError, PermissionError):
                pass
    
    def record_ast_parse(self, file_path: str, duration: float) -> None:
        if not self.enabled:
            return
        with self.lock:
            if str(file_path) in self.file_profiles:
                self.file_profiles[str(file_path)].ast_parse_time = duration
    
    def record_pattern_match(self, file_path: str, duration: float) -> None:
        if not self.enabled:
            return
        with self.lock:
            if str(file_path) in self.file_profiles:
                self.file_profiles[str(file_path)].pattern_match_time = duration
    
    def record_mcp_scan(self, file_path: str, duration: float) -> None:
        if not self.enabled:
            return
        with self.lock:
            if str(file_path) in self.file_profiles:
                self.file_profiles[str(file_path)].mcp_scan_time = duration
    
    def record_cfg_build(self, file_path: str, duration: float) -> None:
        if not self.enabled:
            return
        with self.lock:
            if str(file_path) in self.file_profiles:
                self.file_profiles[str(file_path)].cfg_build_time = duration
    
    def record_taint_analysis(self, file_path: str, duration: float) -> None:
        if not self.enabled:
            return
        with self.lock:
            if str(file_path) in self.file_profiles:
                self.file_profiles[str(file_path)].taint_analysis_time = duration
    
    def finish_file_scan(self, file_path: str, findings_count: int, error: Optional[str] = None) -> None:
        if not self.enabled:
            return
        with self.lock:
            timer_key = f"file_{file_path}"
            if timer_key in self.timers:
                total_time = self.stop_timer(timer_key)
                if str(file_path) in self.file_profiles:
                    profile = self.file_profiles[str(file_path)]
                    profile.total_time = total_time
                    profile.findings_count = findings_count
                    if error:
                        profile.error = error
                    
                    self.profile.file_profiles.append(profile)
                    self.profile.total_files += 1
                    self.profile.total_findings += findings_count
    
    def record_total_duration(self, duration: float) -> None:
        if not self.enabled:
            return
        with self.lock:
            self.profile.total_duration = duration
            self.profile.file_scan_time = duration - self.profile.repository_prep_time - self.profile.language_detection_time
    
    def get_summary(self) -> Dict[str, Any]:
        if not self.enabled or not self.profile.file_profiles:
            return {}
        
        with self.lock:
            profiles = self.profile.file_profiles
            
            lang_stats = defaultdict(lambda: {
                'files': 0,
                'total_time': 0.0,
                'avg_time': 0.0,
                'total_ast_time': 0.0,
                'total_pattern_time': 0.0,
                'total_mcp_time': 0.0,
                'findings': 0
            })
            
            for profile in profiles:
                lang = profile.language
                lang_stats[lang]['files'] += 1
                lang_stats[lang]['total_time'] += profile.total_time
                lang_stats[lang]['total_ast_time'] += profile.ast_parse_time
                lang_stats[lang]['total_pattern_time'] += profile.pattern_match_time
                lang_stats[lang]['total_mcp_time'] += profile.mcp_scan_time
                lang_stats[lang]['findings'] += profile.findings_count
            
            for lang in lang_stats:
                if lang_stats[lang]['files'] > 0:
                    lang_stats[lang]['avg_time'] = lang_stats[lang]['total_time'] / lang_stats[lang]['files']
            
            total_files = len(profiles)
            total_time = sum(p.total_time for p in profiles)
            avg_time = total_time / total_files if total_files > 0 else 0.0
            
            total_ast_time = sum(p.ast_parse_time for p in profiles)
            total_pattern_time = sum(p.pattern_match_time for p in profiles)
            total_mcp_time = sum(p.mcp_scan_time for p in profiles)
            total_cfg_time = sum(p.cfg_build_time for p in profiles)
            total_taint_time = sum(p.taint_analysis_time for p in profiles)
            
            return {
                'total_duration': self.profile.total_duration,
                'repository_prep_time': self.profile.repository_prep_time,
                'language_detection_time': self.profile.language_detection_time,
                'file_scan_time': self.profile.file_scan_time,
                'mcp_scan_time': self.profile.mcp_scan_time,
                'total_files': total_files,
                'total_findings': self.profile.total_findings,
                'avg_file_scan_time': avg_time,
                'total_ast_parse_time': total_ast_time,
                'total_pattern_match_time': total_pattern_time,
                'total_mcp_scan_time': total_mcp_time,
                'total_cfg_build_time': total_cfg_time,
                'total_taint_analysis_time': total_taint_time,
                'language_stats': dict(lang_stats),
                'slowest_files': sorted(
                    [(p.file_path, p.total_time) for p in profiles],
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            }
    
    def get_file_profiles(self) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []
        
        with self.lock:
            return [
                {
                    'file_path': p.file_path,
                    'language': p.language,
                    'total_time': p.total_time,
                    'ast_parse_time': p.ast_parse_time,
                    'pattern_match_time': p.pattern_match_time,
                    'mcp_scan_time': p.mcp_scan_time,
                    'cfg_build_time': p.cfg_build_time,
                    'taint_analysis_time': p.taint_analysis_time,
                    'findings_count': p.findings_count,
                    'file_size': p.file_size,
                    'lines_count': p.lines_count,
                    'error': p.error
                }
                for p in self.profile.file_profiles
            ]
    
    def to_dict(self) -> Dict[str, Any]:
        if not self.enabled:
            return {}
        
        return {
            'summary': self.get_summary(),
            'file_profiles': self.get_file_profiles()
        }
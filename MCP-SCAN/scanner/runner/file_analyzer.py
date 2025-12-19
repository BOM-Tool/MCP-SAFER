import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Set, Tuple, Optional, Any


class FileAnalyzer:
    
    EXCLUDE_DIRS = {
        '.git', 'node_modules', 'vendor', '__pycache__', '.venv', 
        'venv', 'dist', 'build', '.next', 'target', '.gradle',
        'output', 'temp', 'tmp', '.idea', '.vscode'
    }
    
    TEXT_EXTENSIONS = {
        '.json', '.js', '.ts', '.jsx', '.tsx', '.go', '.py', '.java',
        '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.php', '.swift',
        '.kt', '.scala', '.rs', '.sh', '.bash', '.zsh', '.yaml', '.yml',
        '.toml', '.ini', '.conf', '.config', '.env', '.md', '.txt',
        '.xml', '.html', '.css', '.scss', '.less', '.vue', '.svelte',
        '.mjs', '.cjs', '.dart', '.lua', '.r', '.sql', '.pl', '.pm'
    }
    
    MAX_FILE_SIZE = 1024 * 1024
    
    def __init__(self, logger=None, max_workers: int = 4):
        self.logger = logger
        self.max_workers = max_workers
    
    def count_total_files(self, repo_path: Path) -> int:
        total_count = 0
        try:
            for file_path in repo_path.rglob('*'):
                if self._should_include_file(file_path):
                    total_count += 1
        except Exception as e:
            self._log(f"Error counting total files: {e}")
        
        return total_count
    
    def scan_files_for_mcp(
        self, 
        repo_path: Path, 
        security_scan_manager: Any,
        already_scanned_paths: Optional[Set[Path]] = None,
        progress_callback=None
    ) -> Tuple[List[Any], int]:
        findings = []
        scanned_files = 0
        
        try:
            if progress_callback:
                progress_callback.update(85, "Scanning all files for MCP vulnerabilities...")
            
            files_to_scan = self._get_files_to_scan(repo_path, already_scanned_paths)
            
            total_files = len(files_to_scan)
            if total_files == 0:
                return findings, scanned_files
            
            use_parallel = total_files > 10 and self.max_workers > 1
            
            if use_parallel:
                findings, scanned_files = self._scan_files_parallel(
                    files_to_scan, security_scan_manager, progress_callback
                )
            else:
                findings, scanned_files = self._scan_files_sequential(
                    files_to_scan, security_scan_manager
                )
            
            self._log(f"[MCP] Scanned {scanned_files} additional files for MCP vulnerabilities")
            
        except Exception as e:
            self._log(f"[MCP] Error in MCP file scan: {e}")
        
        return findings, scanned_files
    
    def get_already_scanned_paths(self, repo_path: Path) -> Set[Path]:
        scanned_paths = set()
        
        for lang in ['go', 'typescript', 'ts', 'javascript', 'js']:
            if lang in ['typescript', 'ts', 'javascript', 'js']:
                lang_extensions = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']
            elif lang == 'go':
                lang_extensions = ['.go']
            else:
                continue
            
            for ext in lang_extensions:
                for file_path in repo_path.rglob(f'*{ext}'):
                    if file_path.is_file():
                        scanned_paths.add(file_path.resolve())
        
        return scanned_paths
    
    def _should_include_file(self, file_path: Path) -> bool:
        if not file_path.is_file():
            return False
        
        if any(excluded in file_path.parts for excluded in self.EXCLUDE_DIRS):
            return False
        
        if file_path.suffix.lower() not in self.TEXT_EXTENSIONS and file_path.suffix:
            return False
        
        try:
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return False
        except (OSError, PermissionError) as e:
            self._log(f"Warning: Could not stat file {file_path}: {e}")
            return False
        
        return True
    
    def _get_files_to_scan(
        self, 
        repo_path: Path, 
        already_scanned: Optional[Set[Path]] = None
    ) -> List[Path]:
        if already_scanned is None:
            already_scanned = set()
        
        files_to_scan = []
        for file_path in repo_path.rglob('*'):
            if file_path.resolve() in already_scanned:
                continue
            
            if self._should_include_file(file_path):
                files_to_scan.append(file_path)
        
        return files_to_scan
    
    def _scan_files_parallel(
        self,
        files_to_scan: List[Path],
        security_scan_manager: Any,
        progress_callback=None
    ) -> Tuple[List[Any], int]:
        findings = []
        scanned_files = 0
        total_files = len(files_to_scan)
        
        def scan_mcp_file(file_path: Path) -> Tuple[Path, List[Any], Optional[Exception]]:
            try:
                mcp_findings = security_scan_manager.scan_file_for_mcp(file_path)
                return (file_path, mcp_findings, None)
            except Exception as e:
                return (file_path, [], e)
        
        completed_count = 0
        mcp_lock = threading.Lock()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(scan_mcp_file, file_path): file_path 
                for file_path in files_to_scan
            }
            
            for future in as_completed(future_to_file):
                file_path, mcp_findings, error = future.result()
                
                with mcp_lock:
                    completed_count += 1
                    
                    if error:
                        self._log(f"[MCP] Error scanning {file_path}: {error}")
                    else:
                        if mcp_findings:
                            findings.extend(mcp_findings)
                            self._log(f"[MCP] {file_path.name}: {len(mcp_findings)} MCP findings")
                    
                    scanned_files += 1
                    
                    if progress_callback and total_files > 0:
                        progress_pct = 85 + int((completed_count / total_files) * 5)
                        progress_callback.update(progress_pct, f"Scanning MCP files ({completed_count}/{total_files})")
        
        return findings, scanned_files
    
    def _scan_files_sequential(
        self,
        files_to_scan: List[Path],
        security_scan_manager: Any
    ) -> Tuple[List[Any], int]:
        findings = []
        scanned_files = 0
        
        for file_path in files_to_scan:
            try:
                mcp_findings = security_scan_manager.scan_file_for_mcp(file_path)
                if mcp_findings:
                    findings.extend(mcp_findings)
                    self._log(f"[MCP] {file_path.name}: {len(mcp_findings)} MCP findings")
                scanned_files += 1
            except Exception as e:
                self._log(f"[MCP] Error scanning {file_path}: {e}")
                scanned_files += 1
        
        return findings, scanned_files
    
    def _log(self, msg: str) -> None:
        if self.logger:
            self.logger(msg)


from __future__ import annotations
import json
import tempfile
import shutil
import time
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Dict, List, Optional, Any
from rich.console import Console
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn, ProgressColumn
from rich.progress import Task
from rich.text import Text
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich import box
from scanner.analyzers.language import LanguageDetector
from scanner.analyzers.common.scanner import SecurityScanManager, Finding
from scanner.analyzers.common.constants import (
    GITHUB_PREFIXES, CLONE_RETRIES, SUPPORTED_LANGUAGES, 
    PROGRESS_PREPARE_START, PROGRESS_DETECT_LANGS, PROGRESS_SCAN_START,
    PROGRESS_SCAN_END, PROGRESS_FINALIZING, PROGRESS_COMPLETE,
    SEVERITY_INFO, ARTIFACTS_DIR, SEVERITY_WEIGHTS
)
from scanner.analyzers.common.utils import (
    is_github_repo, extract_repo_name, filter_findings_by_severity, count_findings_by_category
)
from scanner.runner.file_analyzer import FileAnalyzer


class TimeElapsedColumnPrecise(ProgressColumn):
    
    def render(self, task: Task) -> Text:
        elapsed = task.elapsed
        if elapsed is None:
            return Text("--:--", style="progress.elapsed")
        
        if elapsed < 60:
            return Text(f"{elapsed:.3f}s", style="progress.elapsed")
        elif elapsed < 3600:
            minutes = int(elapsed // 60)
            seconds = elapsed % 60
            return Text(f"{minutes}:{seconds:05.2f}", style="progress.elapsed")
        else:
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = elapsed % 60
            return Text(f"{hours}:{minutes:02d}:{seconds:05.2f}", style="progress.elapsed")


class TimeRemainingColumnOrEmpty(ProgressColumn):
    
    def render(self, task: Task) -> Text:
        if task.completed >= task.total or task.total == 0:
            return Text("")
        else:
            remaining = task.time_remaining
            if remaining is None or remaining == 0:
                return Text("--:--", style="progress.remaining")
            from rich.progress import TimeRemainingColumn
            default_column = TimeRemainingColumn()
            return default_column.render(task)


class RepositoryCloner:

    def __init__(self, work_dir: Path, progress_callback=None, logger=None):
        self.work_dir = work_dir
        self.progress_callback = progress_callback
        self.logger = logger
    
    def _is_commit_hash(self, ref: str) -> bool:
        return (
            7 <= len(ref) <= 40 and 
            all(c in '0123456789abcdef' for c in ref.lower())
        )
    
    def clone(self, github_url: str, max_retries: int = CLONE_RETRIES) -> Path:
        from scanner.analyzers.common.utils import normalize_github_url
        
        base_url, branch_or_commit = normalize_github_url(github_url)
        repo_name = extract_repo_name(base_url)
        clone_path = self.work_dir / repo_name
        last_error = None
        
        for attempt in range(max_retries):
            try:
                if clone_path.exists():
                    shutil.rmtree(clone_path)
                
                self._log(f"Cloning repository: {base_url} (branch/commit: {branch_or_commit}) (attempt {attempt + 1}/{max_retries})")
                self._update_progress(26, f"Cloning {repo_name}... (attempt {attempt + 1})")
                
                is_commit_hash = self._is_commit_hash(branch_or_commit)
                
                if is_commit_hash:
                    clone_cmd = ['git', 'clone', '--progress', '--depth', '50', base_url, str(clone_path)]
                    process = subprocess.Popen(
                        clone_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )
                else:
                    clone_cmd = ['git', 'clone', '--progress', '--depth', '1', '--branch', branch_or_commit, base_url, str(clone_path)]
                    process = subprocess.Popen(
                        clone_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )
                
                output_lines = []
                for line in process.stdout:
                    output_lines.append(line)
                    if self.progress_callback:
                        if 'Receiving objects' in line or 'Resolving deltas' in line:
                            self.progress_callback.update(30, f"Downloading {repo_name}...")
                        elif 'Checking out files' in line:
                            self.progress_callback.update(34, f"Checking out {repo_name}...")
                
                return_code = process.wait()
                error_msg = ''.join(output_lines).strip()
                
                if return_code == 0:
                    if self._is_commit_hash(branch_or_commit):
                        checkout_process = subprocess.Popen(
                            ['git', 'checkout', branch_or_commit],
                            cwd=str(clone_path),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True
                        )
                        checkout_output = checkout_process.stdout.read()
                        checkout_return_code = checkout_process.wait()
                        if checkout_return_code != 0:
                            self._log(f"Warning: Failed to checkout commit {branch_or_commit}: {checkout_output}")
                        else:
                            self._log(f"Checked out commit: {branch_or_commit}")
                    
                    self._update_progress(35, f"Repository cloned: {repo_name}")
                    self._log(f"Repository cloned to: {clone_path}")
                    return clone_path
                else:
                    if not is_commit_hash and 'Remote branch' in error_msg and 'not found' in error_msg:
                        self._log(f"Branch '{branch_or_commit}' not found, trying default branch...")
                        if clone_path.exists():
                            shutil.rmtree(clone_path)
                        clone_cmd = ['git', 'clone', '--progress', '--depth', '1', base_url, str(clone_path)]
                        process = subprocess.Popen(
                            clone_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            bufsize=1
                        )
                        output_lines = []
                        for line in process.stdout:
                            output_lines.append(line)
                            if self.progress_callback:
                                if 'Receiving objects' in line or 'Resolving deltas' in line:
                                    self.progress_callback.update(30, f"Downloading {repo_name}...")
                                elif 'Checking out files' in line:
                                    self.progress_callback.update(34, f"Checking out {repo_name}...")
                        
                        return_code = process.wait()
                        if return_code == 0:
                            self._update_progress(35, f"Repository cloned: {repo_name}")
                            self._log(f"Repository cloned to: {clone_path} (using default branch)")
                            return clone_path
                        else:
                            error_msg = ''.join(output_lines).strip()
                            if not error_msg:
                                error_msg = f"Git clone failed with exit code {return_code}"
                    
                    if not error_msg:
                        error_msg = f"Git clone failed with exit code {return_code}"
                    last_error = error_msg
                    self._handle_clone_error(error_msg, github_url, attempt, max_retries)
                    
            except subprocess.CalledProcessError as e:
                last_error = str(e)
                if attempt < max_retries - 1:
                    self._retry_after_delay(attempt)
                else:
                    raise RuntimeError(f"Failed to clone after {max_retries} attempts: {last_error}")
            except Exception as e:
                last_error = str(e)
                if attempt < max_retries - 1:
                    self._retry_after_delay(attempt)
                else:
                    raise RuntimeError(f"Failed to clone after {max_retries} attempts: {last_error}")
        
        error_detail = f": {last_error}" if last_error else ""
        raise RuntimeError(f"Failed to clone repository after {max_retries} attempts{error_detail}")
    
    def _handle_clone_error(self, error_msg: str, github_url: str, attempt: int, max_retries: int):
        self._log(f"Git clone failed")
        self._log(f"Error details: {error_msg}")
        
        if 'Repository not found' in error_msg or 'not found' in error_msg.lower():
            raise RuntimeError(f"Repository not found: {github_url}. Please check the URL.")
        elif 'Permission denied' in error_msg or 'authentication failed' in error_msg.lower():
            raise RuntimeError(f"Authentication failed. The repository may be private: {github_url}")
        elif 'Could not resolve host' in error_msg:
            raise RuntimeError(f"Network error: Could not resolve host. Please check your internet connection.")
        
        if attempt < max_retries - 1:
            wait_time = (attempt + 1) * 2
            self._log(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
        else:
            raise subprocess.CalledProcessError(1, 'git clone', error_msg)
    
    def _retry_after_delay(self, attempt: int):
        wait_time = (attempt + 1) * 2
        self._log(f"Retrying in {wait_time} seconds...")
        time.sleep(wait_time)
    
    def _log(self, msg: str):
        if self.logger:
            self.logger(msg)
    
    def _update_progress(self, progress: int, msg: str):
        if self.progress_callback:
            self.progress_callback.update(progress, msg)


class ScanOrchestrator:
    
    def __init__(self, language_detector: LanguageDetector, security_scan_manager: SecurityScanManager, 
                 console: Console, progress_callback=None, logger=None, max_workers: int = 4):
        self.language_detector = language_detector
        self.security_scan_manager = security_scan_manager
        self.console = console
        self.progress_callback = progress_callback
        self.logger = logger
        self.max_workers = max_workers
        self.progress_lock = threading.Lock()
    
    def scan_language_files_with_progress(self, repo_path: Path, language: str, 
                                         progress: Progress, task_id: TaskID, 
                                         lang_index: int, total_langs: int) -> tuple[List[Finding], int, int]:
        if language not in SUPPORTED_LANGUAGES:
            self._log(f"Unsupported language: {language} (skipping)")
            return [], 0, 0
        
        files = self._get_file_list(repo_path, language)
        total_files = len(files)
        self._log(f"[{language}] Found {total_files} files")
        
        if self.progress_callback and total_files > 0:
            base_progress = 40 + int((lang_index / total_langs) * 45)
            base_progress = min(84, base_progress)
            self.progress_callback.update(base_progress, f"Starting {language.upper()} scan ({total_files} files)")
        
        if total_files == 0:
            return [], 0, 0
        
        use_parallel = total_files > 10 and self.max_workers > 1
        
        if use_parallel:
            return self._scan_files_parallel(files, language, progress, task_id, lang_index, total_langs)
        else:
            return self._scan_files_sequential(files, language, progress, task_id, lang_index, total_langs)
    
    def _scan_files_sequential(self, files: List[Path], language: str, 
                              progress: Progress, task_id: TaskID, 
                              lang_index: int, total_langs: int) -> tuple[List[Finding], int, int]:
        all_findings = []
        scanned_files = 0
        total_files = len(files)
        
        total_ast_time = 0.0
        total_cfg_time = 0.0
        total_taint_time = 0.0
        total_pattern_time = 0.0
        total_mcp_time = 0.0
        
        last_update_time = time.time()
        update_interval = 0.5
        
        for i, file_path in enumerate(files):
            try:
                findings, timing = self.security_scan_manager.scan_file(file_path, language)
                all_findings.extend(findings)
                scanned_files += 1
                
                total_ast_time += timing.get('ast_time', 0.0)
                total_cfg_time += timing.get('cfg_time', 0.0)
                total_taint_time += timing.get('taint_time', 0.0)
                total_pattern_time += timing.get('pattern_time', 0.0)
                total_mcp_time += timing.get('mcp_time', 0.0)
                
                if findings:
                    self.console.print(f" [yellow]{language.upper()}[/yellow] {file_path.name}: [red]{len(findings)} findings[/red]")
                    self._log(f"[{language}] {file_path.name}: {len(findings)} findings")
                else:
                    self.console.print(f" [yellow]{language.upper()}[/yellow] {file_path.name}: [green]No issues found[/green]")
                
                current_time = time.time()
                is_last_file = (i == total_files - 1)
                should_update = (current_time - last_update_time >= update_interval) or is_last_file
                
                if should_update:
                    time_parts = []
                    if total_ast_time > 0:
                        time_parts.append(f"AST: {total_ast_time:.3f}s")
                    if total_cfg_time > 0:
                        time_parts.append(f"CFG: {total_cfg_time:.3f}s")
                    if total_taint_time > 0:
                        time_parts.append(f"Taint: {total_taint_time:.3f}s")
                    if total_pattern_time > 0:
                        time_parts.append(f"Pattern: {total_pattern_time:.3f}s")
                    if total_mcp_time > 0:
                        time_parts.append(f"MCP: {total_mcp_time:.3f}s")
                    
                    if time_parts:
                        description = f"Scanning {language.upper()} files...\n  " + " | ".join(time_parts)
                        progress.update(task_id, description=description)
                    last_update_time = current_time
                
                self._update_scan_progress(i, total_files, lang_index, total_langs, language, progress, task_id)
                    
            except Exception as e:
                self.console.print(f" [yellow]{language.upper()}[/yellow] {file_path.name}: [red]Error - {e}[/red]")
                self._log(f"[{language}] Error scanning {file_path}: {e}")
                scanned_files += 1
        
        if lang_index == total_langs - 1:
            progress.update(task_id, completed=100)
        
        self._log(f"[{language}] Analysis completed - {len(all_findings)} total findings, {scanned_files}/{total_files} files scanned")
        return all_findings, total_files, scanned_files
    
    def _scan_files_parallel(self, files: List[Path], language: str, 
                            progress: Progress, task_id: TaskID, 
                            lang_index: int, total_langs: int) -> tuple[List[Finding], int, int]:
        all_findings = []
        scanned_files = 0
        total_files = len(files)
        completed_count = 0
        
        total_ast_time = 0.0
        total_cfg_time = 0.0
        total_taint_time = 0.0
        total_pattern_time = 0.0
        total_mcp_time = 0.0
        
        def scan_single_file(file_path: Path) -> tuple[Path, List[Finding], Dict[str, float], Optional[Exception]]:
            try:
                findings, timing = self.security_scan_manager.scan_file(file_path, language)
                return (file_path, findings, timing, None)
            except Exception as e:
                return (file_path, [], {}, e)
        
        last_update_time = time.time()
        update_interval = 0.5
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(scan_single_file, file_path): file_path 
                for file_path in files
            }
            
            for future in as_completed(future_to_file):
                file_path, findings, timing, error = future.result()
                
                if error:
                    with self.progress_lock:
                        completed_count += 1
                        self.console.print(f" [yellow]{language.upper()}[/yellow] {file_path.name}: [red]Error - {error}[/red]")
                        self._log(f"[{language}] Error scanning {file_path}: {error}")
                        self._update_scan_progress(completed_count - 1, total_files, lang_index, total_langs, language, progress, task_id)
                else:
                    with self.progress_lock:
                        completed_count += 1
                        all_findings.extend(findings)
                        
                        total_ast_time += timing.get('ast_time', 0.0)
                        total_cfg_time += timing.get('cfg_time', 0.0)
                        total_taint_time += timing.get('taint_time', 0.0)
                        total_pattern_time += timing.get('pattern_time', 0.0)
                        total_mcp_time += timing.get('mcp_time', 0.0)
                        
                        if findings:
                            self.console.print(f" [yellow]{language.upper()}[/yellow] {file_path.name}: [red]{len(findings)} findings[/red]")
                            self._log(f"[{language}] {file_path.name}: {len(findings)} findings")
                        else:
                            self.console.print(f" [yellow]{language.upper()}[/yellow] {file_path.name}: [green]No issues found[/green]")
                        
                        current_time = time.time()
                        is_last_file = (completed_count == total_files)
                        should_update = (current_time - last_update_time >= update_interval) or is_last_file
                        
                        if should_update:
                            time_parts = []
                            if total_ast_time > 0:
                                time_parts.append(f"AST: {total_ast_time:.3f}s")
                            if total_cfg_time > 0:
                                time_parts.append(f"CFG: {total_cfg_time:.3f}s")
                            if total_taint_time > 0:
                                time_parts.append(f"Taint: {total_taint_time:.3f}s")
                            if total_pattern_time > 0:
                                time_parts.append(f"Pattern: {total_pattern_time:.3f}s")
                            if total_mcp_time > 0:
                                time_parts.append(f"MCP: {total_mcp_time:.3f}s")
                            
                            if time_parts:
                                description = f"Scanning {language.upper()} files...\n  " + " | ".join(time_parts)
                                progress.update(task_id, description=description)
                            last_update_time = current_time
                        
                        self._update_scan_progress(completed_count - 1, total_files, lang_index, total_langs, language, progress, task_id)
        
        scanned_files = completed_count
        
        if lang_index == total_langs - 1:
            progress.update(task_id, completed=100)
        
        self._log(f"[{language}] Analysis completed (parallel) - {len(all_findings)} total findings, {scanned_files}/{total_files} files scanned")
        return all_findings, total_files, scanned_files
    
    def _get_file_list(self, repo_path: Path, language: str) -> List[Path]:
        if repo_path.is_file():
            self._log(f"[{language}] Single file: {repo_path.name}")
            return [repo_path]
        else:
            return self.language_detector.get_file_list(repo_path, language)
    
    def _update_scan_progress(self, current: int, total: int, lang_index: int, 
                             total_langs: int, language: str, progress: Progress, task_id: TaskID):
        file_progress = (current + 1) / total if total else 1.0
        lang_progress = (lang_index + file_progress) / total_langs * 100
        progress.update(task_id, completed=lang_progress)
        
        if self.progress_callback:
            current_lang_progress = (current + 1) / total
            web_progress = 40 + int((lang_index + current_lang_progress) / total_langs * 45)
            web_progress = min(85, max(40, web_progress))
            self.progress_callback.update(web_progress, f"Scanning {language.upper()} ({current+1}/{total} files)")
    
    def _log(self, msg: str):
        if self.logger:
            self.logger(msg)


class ResultFormatter:
    
    def __init__(self, console: Console, language_detector: LanguageDetector):
        self.console = console
        self.language_detector = language_detector
    
    def _calculate_risk_score(self, finding: Finding) -> float:
        severity_key = (finding.severity or "").lower()
        severity_weight = SEVERITY_WEIGHTS.get(severity_key, 0)
        confidence = finding.confidence or 0.0
        risk_score = severity_weight * confidence
        return round(risk_score, 3)
    
    def finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        risk_score = self._calculate_risk_score(finding)
        return {
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "message": finding.message,
            "cwe": finding.cwe,
            "file": finding.file,
            "line": finding.line,
            "column": finding.column,
            "code_snippet": finding.code_snippet,
            "pattern_type": finding.pattern_type,
            "pattern": finding.pattern,
            "confidence": finding.confidence,
            "risk_score": risk_score
        }
    
    def generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not findings:
            return {
                "total_findings": 0,
                "total_findings_excluding_info": 0,
                "mcp_findings": 0,
                "mcp_findings_excluding_info": 0,
                "general_findings": 0,
                "general_findings_excluding_info": 0,
                "by_severity": {},
                "by_rule": {},
                "by_language": {}
            }
        
        findings_excluding_info = filter_findings_by_severity(findings, [SEVERITY_INFO])
        
        mcp_findings = [f for f in findings if f.get("rule_id", "").startswith("mcp/")]
        general_findings = [f for f in findings if not f.get("rule_id", "").startswith("mcp/")]
        
        mcp_findings_excluding_info = filter_findings_by_severity(mcp_findings, [SEVERITY_INFO])
        general_findings_excluding_info = filter_findings_by_severity(general_findings, [SEVERITY_INFO])
        
        summary = {
            "total_findings": len(findings),
            "total_findings_excluding_info": len(findings_excluding_info),
            "mcp_findings": len(mcp_findings),
            "mcp_findings_excluding_info": len(mcp_findings_excluding_info),
            "general_findings": len(general_findings),
            "general_findings_excluding_info": len(general_findings_excluding_info),
            "by_severity": count_findings_by_category(findings, "severity"),
            "by_rule": count_findings_by_category(findings, "rule_id"),
            "by_language": count_findings_by_category(findings, "language")
        }
        
        return summary
    
    def display_scan_summary(self, findings: List[Dict[str, Any]], languages: List[str]):
        severity_stats = {}
        rule_stats = {}
        language_stats = {}
        
        for finding in findings:
            severity = finding.get("severity", "unknown")
            rule_id = finding.get("rule_id", "unknown")
            file_path = finding.get("file", "")

            lang = self.language_detector.detect_from_path(file_path)
            
            severity_stats[severity] = severity_stats.get(severity, 0) + 1
            rule_stats[rule_id] = rule_stats.get(rule_id, 0) + 1
            language_stats[lang] = language_stats.get(lang, 0) + 1
        
        table = Table(title="Security Scan Results Summary", box=box.ROUNDED)
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Details", style="white")
        
        total_findings = len(findings)
        findings_excluding_info = filter_findings_by_severity(findings, [SEVERITY_INFO])
        total_findings_excluding_info = len(findings_excluding_info)
        
        if total_findings == 0:
            table.add_row("Total Findings", "[green]No security issues found![/green]")
        else:
            table.add_row("Total Findings", f"[red]{total_findings_excluding_info}[/red] security issues detected (excluding info)")
            if severity_stats.get("info", 0) > 0:
                table.add_row("Info Findings", f"[blue]{severity_stats.get('info', 0)}[/blue] info-level findings")
        
        if severity_stats:
            severity_text = " | ".join([
                f"[red]{severity.upper()}: {count}[/red]" if severity == 'high' 
                else f"[yellow]{severity.upper()}: {count}[/yellow]" if severity == 'medium'
                else f"[blue]{severity.upper()}: {count}[/blue]"
                for severity, count in sorted(severity_stats.items())
            ])
            table.add_row("By Severity", severity_text)
        
        if language_stats:
            lang_text = " | ".join([
                f"[cyan]{lang}: {count}[/cyan]" 
                for lang, count in sorted(language_stats.items())
            ])
            table.add_row("By Language", lang_text)
        
        if rule_stats:
            top_rules = sorted(rule_stats.items(), key=lambda x: x[1], reverse=True)[:5]
            rules_text = " | ".join([
                f"[magenta]{rule}: {count}[/magenta]"
                for rule, count in top_rules
            ])
            table.add_row("Top Rules", rules_text)
        
        self.console.print(Panel(table, title="Scan Summary", border_style="blue"))


class MCPScannerManager:
    
    def __init__(self, temp_dir: Optional[str] = None, max_workers: int = 4, verbose: bool = False):
        self.work_dir = Path(temp_dir) if temp_dir else Path("output/temp")
        self.console = Console()
        self.max_workers = max_workers
        self.verbose = verbose

        self.file_analyzer = FileAnalyzer(logger=self.log_manager, max_workers=max_workers)
        
        self._cleanup_temp_directory(self.work_dir)

        self.language_detector = LanguageDetector()
        self.security_scan_manager = SecurityScanManager()
        self.progress_callback = None

        self.cloner = RepositoryCloner(self.work_dir, None, self.log_manager)
        self.orchestrator = ScanOrchestrator(
            self.language_detector, 
            self.security_scan_manager,
            self.console,
            None,
            self.log_manager,
            max_workers=self.max_workers
        )
        self.formatter = ResultFormatter(self.console, self.language_detector)
        
        self.log_manager(f"Manager initialized - work_dir: {self.work_dir}, max_workers: {self.max_workers}")
    
    def set_progress_callback(self, callback):
        self.progress_callback = callback
        self.cloner.progress_callback = callback
        self.orchestrator.progress_callback = callback
    
    def scan_repository_full(self, repo_path: str | Path) -> Dict[str, Any]:
        repo_path_str = str(repo_path)
        scan_start_time = time.time()
        kst = ZoneInfo('Asia/Seoul')
        scan_timestamp = datetime.now(kst).strftime("%Y-%m-%d %H:%M:%S")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumnPrecise(),
            TimeRemainingColumnOrEmpty(),
            console=self.console,
            expand=True,
        ) as progress:
            actual_repo_path = self._prepare_repository(repo_path_str, progress)
            
            total_files = self.file_analyzer.count_total_files(actual_repo_path)
            self.log_manager(f"Total text files in repository: {total_files}")
            
            languages = self._detect_languages(actual_repo_path, progress)
            
            if not languages:
                scan_end_time = time.time()
                scan_duration = round(scan_end_time - scan_start_time, 2)
                result = self._create_empty_result(repo_path_str, scan_duration, scan_timestamp)
                self._cleanup_artifacts_directory(Path(ARTIFACTS_DIR))
                return result
            
            all_findings, lang_total_files, lang_scanned_files = self._scan_all_languages(actual_repo_path, languages, progress)
            
            already_scanned = self.file_analyzer.get_already_scanned_paths(actual_repo_path)
            mcp_findings, mcp_scanned_files = self.file_analyzer.scan_files_for_mcp(
                actual_repo_path, 
                self.security_scan_manager,
                already_scanned,
                self.progress_callback
            )
            all_findings.extend(mcp_findings)
            
            scanned_files = lang_scanned_files + mcp_scanned_files
            
            if scanned_files == 0 and total_files > 0:
                scanned_files = total_files
                self.log_manager(f"Warning: No files were scanned but {total_files} files were counted. Setting scanned_files to total_files.")
            
            if scanned_files > total_files:
                scanned_files = total_files
            
            self.log_manager(f"Final count: {total_files} total files, {scanned_files} scanned files (lang: {lang_scanned_files}, mcp: {mcp_scanned_files})")
            
            findings_dict = [self.formatter.finding_to_dict(f) for f in all_findings]
            self.formatter.display_scan_summary(findings_dict, languages)
        
        scan_end_time = time.time()
        scan_duration = round(scan_end_time - scan_start_time, 2)
        
        findings_excluding_info = filter_findings_by_severity(findings_dict, [SEVERITY_INFO])
        
        from scanner.analyzers.common.utils import calculate_server_risk_score
        server_risk_score = calculate_server_risk_score(all_findings)
        
        result = {
            "scan_info": {
                "repository": repo_path_str,
                "languages": languages,
                "total_findings": len(findings_dict),
                "total_findings_excluding_info": len(findings_excluding_info),
                "scan_duration": scan_duration,
                "scan_timestamp": scan_timestamp,
                "server_risk_score": server_risk_score,
            },
            "findings": findings_dict,
            "summary": self.formatter.generate_summary(findings_dict),
        }
        
        self._cleanup_artifacts_directory(Path(ARTIFACTS_DIR))
        
        return result
    
    def _prepare_repository(self, repo_path_str: str, progress: Progress) -> Path:
        task_prepare = progress.add_task(" Preparing repository...", total=100)
        progress.update(task_prepare, completed=10)
        
        if self.progress_callback:
            self.progress_callback.update(20, "Preparing repository...")
        
        if is_github_repo(repo_path_str):
            self.log_manager(f"GitHub repository detected: {repo_path_str}")
            progress.update(task_prepare, description="Cloning GitHub repository...", completed=30)
            
            if self.progress_callback:
                self.progress_callback.update(22, "Starting clone...")
            
            actual_repo_path = self.cloner.clone(repo_path_str)
        else:
            actual_repo_path = Path(repo_path_str).resolve()
            if not actual_repo_path.exists():
                raise ValueError(f"Repository path does not exist: {actual_repo_path}")
            
            progress.update(task_prepare, description="Analyzing local repository...", completed=30)
            if self.progress_callback:
                self.progress_callback.update(25, "Analyzing local repository...")
        
        progress.update(task_prepare, completed=100)
        if self.progress_callback:
            self.progress_callback.update(36, "Repository ready")
        
        return actual_repo_path
    
    def _detect_languages(self, repo_path: Path, progress: Progress) -> List[str]:
        task_detect = progress.add_task("Detecting programming languages...", total=100)
        progress.update(task_detect, completed=20)
        
        if self.progress_callback:
            self.progress_callback.update(37, "Detecting languages...")
        
        self.log_manager(f"Starting repository analysis: {repo_path}")
        
        if repo_path.is_file():
            lang = self.language_detector.detect_from_file(repo_path)
            languages = [lang] if lang != 'unknown' else []
        else:
            languages = self.language_detector.detect(repo_path)
        
        progress.update(task_detect, completed=100)
        
        if self.progress_callback:
            self.progress_callback.update(39, f"Found: {', '.join(languages)}")
        
        if languages:
            self.log_manager(f"Detected languages: {', '.join(languages)}")
            self.console.print(f"\n [green]Detected languages:[/green] {', '.join(languages)}")
        else:
            self.log_manager("No supported languages detected (go/ts)")
            self.console.print("[red]No supported languages detected[/red]")
        
        return languages
    
    def _scan_all_languages(self, repo_path: Path, languages: List[str], progress: Progress) -> tuple[List[Finding], int, int]:
        task_scan = progress.add_task("Scanning files for vulnerabilities...", total=100)
        all_findings = []
        total_files = 0
        scanned_files = 0
        scan_start_time = time.time()
        
        for i, lang in enumerate(languages):
            lang_start_time = time.time()
            progress.update(task_scan, description=f"Scanning {lang.upper()} files...")
            
            if self.progress_callback:
                lang_progress = 40 + int((i / len(languages)) * 45)
                self.progress_callback.update(lang_progress, f"Starting {lang.upper()} scan...")
            
            lang_findings, lang_total_files, lang_scanned_files = self.orchestrator.scan_language_files_with_progress(
                repo_path, lang, progress, task_scan, i, len(languages)
            )
            lang_duration = time.time() - lang_start_time
            self.log_manager(f"[{lang.upper()}] Scanned {lang_scanned_files} files in {lang_duration:.2f}s")
            
            all_findings.extend(lang_findings)
            total_files += lang_total_files
            scanned_files += lang_scanned_files
        
        scan_duration = time.time() - scan_start_time
        progress.update(task_scan, completed=100)
        
        if self.progress_callback:
            self.progress_callback.update(90, "Scan completed")
        
        self.log_manager(f"Scan completed in {scan_duration:.2f} seconds - {scanned_files}/{total_files} files scanned")
        
        return all_findings, total_files, scanned_files
    
    def _create_empty_result(self, repo_path: str, scan_duration: float = 0.0, scan_timestamp: str = "") -> Dict[str, Any]:
        if not scan_timestamp:
            kst = ZoneInfo('Asia/Seoul')
            scan_timestamp = datetime.now(kst).strftime("%Y-%m-%d %H:%M:%S")
        return {
            "scan_info": {
                "repository": repo_path,
                "languages": [],
                "total_findings": 0,
                "total_findings_excluding_info": 0,
                "scan_duration": scan_duration,
                "scan_timestamp": scan_timestamp,
            },
            "findings": [],
            "summary": self.formatter.generate_summary([]),
        }
    
    def _cleanup_temp_directory(self, temp_dir: Path) -> None:
        if temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
                self.log_manager(f"Cleaned up existing temp directory: {temp_dir}")
            except Exception as e:
                self.log_manager(f"Warning: Failed to cleanup temp directory: {e}")
        
        temp_dir.mkdir(parents=True, exist_ok=True)
    
    def _cleanup_artifacts_directory(self, artifacts_dir: Path) -> None:
        if artifacts_dir.exists():
            try:
                shutil.rmtree(artifacts_dir)
                self.log_manager(f"Cleaned up artifacts directory: {artifacts_dir}")
            except Exception as e:
                self.log_manager(f"Warning: Failed to cleanup artifacts directory: {e}")
    
    def log_manager(self, msg: str):
        if self.verbose:
            print(f"[LOG] {msg}")
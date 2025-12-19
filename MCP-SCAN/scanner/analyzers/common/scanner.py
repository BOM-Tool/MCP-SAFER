import re
import ast
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS

@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    cwe: str
    file: str
    line: int
    column: int
    code_snippet: str
    pattern_type: str
    pattern: str
    confidence: float = 1.0
    
    @property
    def severity_weight(self) -> int:
        from scanner.analyzers.common.constants import SEVERITY_WEIGHTS
        return SEVERITY_WEIGHTS.get(self.severity, 1)

class CommonPatterns:
    SAFE_COMMENT_PATTERNS = [
        # TypeScript/JavaScript
        r'//\s*eslint-disable',
        r'//\s*@ts-ignore',
        # Go security suppression comments
        r'//nolint:gosec',
        r'//\s*nolint:gosec',
        r'//\s*nolint\s*:gosec',
        r'//\s*nolint:.*gosec',
        r'//#nosec',
        r'//\s*#nosec',
        r'//\s*#nosec\s+\w+',
        r'//\s*nosec',
        # General security comments
        r'//\s*safe',
        r'//\s*sanitized',
        r'//\s*trusted',
        r'//\s*validated',
        r'//\s*whitelisted',
        r'//\s*verified',
        r'//\s*controlled',
        # Block comments
        r'/\*\s*nosec\s*\*/',
        r'/\*\s*safe\s*\*/',
        r'/\*\s*security:\s*reviewed\s*\*/',
        r'/\*\s*nolint:gosec\s*\*/',
        r'/\*\s*#nosec\s*\*/',
    ]
    
    SHELL_METACHARACTERS = [
        ';', '&', '|', '||', '&&', '$(', '`', '$(',
        '>', '>>', '<', '\n', '\r\n', '2>&1', '2>',
    ]
    
    SHELL_FLAGS = ['-c', '/c', '/C', '-Command', '-EncodedCommand', '-File']
    
    SAFE_FILE_EXTENSIONS = ['.md', '.txt', '.json', '.log', '.tmp', '.dat', 
                           '.xml', '.yaml', '.yml', '.csv', '.ini', '.conf', '.git']
    
    CONFIDENCE_LEVELS = CONFIDENCE_LEVELS
    
    @staticmethod
    def is_test_file(file_path: str, language: str = "all") -> bool:
        config = ConfigLoader.get_instance()
        test_patterns = config.get_test_file_patterns(language)
        return any(pattern in file_path for pattern in test_patterns)
    
    @staticmethod
    def has_safe_comment(line_content: str) -> bool:
        for pattern in CommonPatterns.SAFE_COMMENT_PATTERNS:
            if re.search(pattern, line_content, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def is_safe_literal(value: str, language: str = "all") -> bool:
        config = ConfigLoader.get_instance()
        safe_keywords = config.get_safe_literals(language)
        if any(keyword in value for keyword in safe_keywords):
            return True
        
        safe_path_patterns = [
            r'README', r'LICENSE', r'CHANGELOG', r'CONTRIBUTING',
            r'\.md$', r'\.txt$', r'\.json$', r'\.yaml$', r'\.yml$',
            r'^docs/', r'^\.github/', r'^\.git/', r'^node_modules/',
            r'^dist/', r'^build/', r'^public/', r'^static/', r'^assets/'
        ]
        
        for pattern in safe_path_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def extract_base_var(var_name: str) -> str:
        if not var_name:
            return ""
        var_name = var_name.strip()
        if '.' in var_name:
            return var_name.split('.')[0].strip()
        return var_name
    
    @staticmethod
    def adjust_severity_down(severity: str, steps: int = 1) -> str:
        severity_levels = ["critical", "high", "medium", "low", "info"]
        try:
            current_index = severity_levels.index(severity.lower())
            new_index = min(current_index + steps, len(severity_levels) - 1)
            return severity_levels[new_index]
        except ValueError:
            return severity
    
    @staticmethod
    def adjust_severity_with_context(severity: str, context_type: str) -> tuple[str, float]:
        multiplier = 0.6
        if context_type == 'safe_var':
            multiplier = 0.5
        
        adjusted_severity = CommonPatterns.adjust_severity_down(severity, 1)
        return adjusted_severity, multiplier
    
    @staticmethod
    def is_arg_in_tainted_vars(arg: str, tainted_vars: set) -> bool:
        if arg in tainted_vars:
            return True
        base_var = CommonPatterns.extract_base_var(arg)
        return base_var in tainted_vars if base_var else False

class ConfigLoader:
    
    _instance: Optional['ConfigLoader'] = None
    _config: Dict[str, Any] = {}
    
    def __init__(self, config_path: Optional[str] = None):
        if ConfigLoader._instance is not None:
            return
        
        self.config_path = config_path or self._find_config_file()
        self._config = self._load_config()
        ConfigLoader._instance = self
    
    @classmethod
    def get_instance(cls, config_path: Optional[str] = None) -> 'ConfigLoader':
        if cls._instance is None:
            cls._instance = ConfigLoader(config_path)
        return cls._instance
    
    def _find_config_file(self) -> Path:
        current = Path(__file__).resolve().parent.parent.parent.parent
        for parent in [current] + list(current.parents):
            config_file = parent / "custom_config.json"
            if config_file.exists():
                return config_file
        return current / "custom_config.json"
    
    def _load_config(self) -> Dict[str, Any]:
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
        return {}
    
    def get_whitelisted_domains(self, language: str = "all") -> List[str]:
        default_domains = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'example.com', 'example.org', 'example.net']
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                domains = patterns[language].get('whitelisted_domains', [])
                return default_domains + domains
            if 'all' in patterns:
                domains = patterns['all'].get('whitelisted_domains', [])
                return default_domains + domains
        except Exception:
            pass
        return default_domains
    
    def get_safe_url_patterns(self, language: str = "all") -> List[str]:
        default_patterns = [
            r'localhost:\d+',
            r'127\.0\.0\.1:\d+',
            r'example\.com',
            r'example\.org',
        ]
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                url_patterns = patterns[language].get('safe_urls', [])
                return default_patterns + url_patterns
            if 'all' in patterns:
                url_patterns = patterns['all'].get('safe_urls', [])
                return default_patterns + url_patterns
        except Exception:
            pass
        return default_patterns
    
    def get_safe_comment_patterns(self, language: str = "all") -> List[str]:
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                return patterns[language].get('safe_comments', [])
            if 'all' in patterns:
                return patterns['all'].get('safe_comments', [])
        except Exception:
            pass
        return []
    
    def get_exclude_dirs(self, language: str = "all") -> List[str]:
        default_dirs = {
            'go': ['vendor', 'node_modules', '__pycache__'],
            'typescript': ['node_modules', 'dist', 'build', '__pycache__'],
            'ts': ['node_modules', 'dist', 'build', '__pycache__'],
            'all': []
        }
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                dirs = patterns[language].get('exclude_dirs', [])
                return default_dirs.get(language, []) + dirs if dirs else default_dirs.get(language, [])
            if 'all' in patterns:
                dirs = patterns['all'].get('exclude_dirs', [])
                return default_dirs.get(language, []) + dirs if dirs else default_dirs.get(language, [])
        except Exception:
            pass
        return default_dirs.get(language, default_dirs.get('all', []))
    
    def get_test_file_patterns(self, language: str = "all") -> List[str]:
        default_patterns = [
            '_test.', '.test.', '.spec.', '/test/', '/tests/', '/__tests__/',
            '/testdata/', 'test/', 'tests/'
        ]
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                test_patterns = patterns[language].get('test_file_patterns', [])
                return default_patterns + test_patterns if test_patterns else default_patterns
            if 'all' in patterns:
                test_patterns = patterns['all'].get('test_file_patterns', [])
                return default_patterns + test_patterns if test_patterns else default_patterns
        except Exception:
            pass
        return default_patterns
    
    def get_safe_literals(self, language: str = "all") -> List[str]:
        default_literals = [
            'README', 'LICENSE', 'CHANGELOG', 'CONTRIBUTING',
            'package.json', 'tsconfig.json', 'node_modules',
            'dist/', 'build/', 'public/', 'static/', 'assets/'
        ]
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                literals = patterns[language].get('safe_literals', [])
                return default_literals + literals if literals else default_literals
            if 'all' in patterns:
                literals = patterns['all'].get('safe_literals', [])
                return default_literals + literals if literals else default_literals
        except Exception:
            pass
        return default_literals
    
    def reload(self):
        self._config = self._load_config()

class SecurityScanManager:
    
    def __init__(self):
        self.general_detectors = []
        self.mcp_detectors = []
        self.config_detector = None
        self.taint_analyzer = None
        self.parser_paths = {}
        self._load_detectors()
        self._init_config_detector()
        self._init_taint_analyzer()
    
    def _init_config_detector(self):
        try:
            from scanner.analyzers.rules.mcp.config_poisoning import ConfigPoisoningDetector
            self.config_detector = ConfigPoisoningDetector()
        except ImportError:
            self.config_detector = None
    
    def _init_taint_analyzer(self):
        from scanner.analyzers.common.taint_engine import TaintPropagationEngine
        self.taint_analyzer = TaintPropagationEngine()
    
    def _load_detectors(self):
        parsers_dir = Path(__file__).parent.parent / "rules" / "parsers"
        self.parser_paths = {
            'go': parsers_dir / 'go_parser',
            'typescript': parsers_dir / 'ts_parser.js',
            'ts': parsers_dir / 'ts_parser.js',
            'javascript': parsers_dir / 'ts_parser.js',
            'js': parsers_dir / 'ts_parser.js'
        }
        
        try:
            from scanner.analyzers.rules.go.command_injection import CommandInjectionDetector as GoCI
            from scanner.analyzers.rules.go.path_traversal import PathTraversalDetector as GoPT
            from scanner.analyzers.rules.go.server_side_request_forgery import SSRFDetector as GoSSRF
            
            self.general_detectors.extend([
                ('go', GoCI()),
                ('go', GoPT()),
                ('go', GoSSRF())
            ])
            print(" Go general detectors loaded successfully")
        except ImportError as e:
            print(f"Warning: Could not load Go general detectors: {e}")
        
        try:
            from scanner.analyzers.rules.typescript.command_injection import CommandInjectionDetector as TsCI
            from scanner.analyzers.rules.typescript.path_traversal import PathTraversalDetector as TsPT
            from scanner.analyzers.rules.typescript.server_side_request_forgery import SSRFDetector as TsSSRF
            from scanner.analyzers.rules.typescript.open_redirect import OpenRedirectDetector as TsOR
            
            for lang in ['ts', 'typescript', 'javascript', 'js']:
                self.general_detectors.extend([
                    (lang, TsCI()),
                    (lang, TsPT()),
                    (lang, TsSSRF()),
                    (lang, TsOR())
                ])
            print(" TypeScript/JavaScript general detectors loaded successfully")
        except ImportError as e:
            print(f"Warning: Could not load TypeScript general detectors: {e}")
        
        try:
            from scanner.analyzers.rules.mcp import (
                ToxicFlowDetector,
                ToolPoisoningDetector,
                ToolNameSpoofingDetector,
                ToolShadowingDetector
            )
            
            for lang in ['go', 'ts', 'typescript', 'javascript', 'js']:
                self.mcp_detectors.extend([
                    (lang, ToxicFlowDetector()),
                    (lang, ToolPoisoningDetector()),
                    (lang, ToolNameSpoofingDetector()),
                    (lang, ToolShadowingDetector())
                ])
            print(" MCP detectors loaded successfully")
        except ImportError as e:
            print(f"Warning: Could not load MCP detectors: {e}")

    def scan_file(self, file_path: Path, language: str) -> Tuple[List[Finding], Dict[str, float]]:
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        findings = []
        timing = {'config_time': 0.0, 'ast_time': 0.0, 'cfg_time': 0.0, 'taint_time': 0.0, 
                  'pattern_time': 0.0, 'mcp_time': 0.0}
        
        lines = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except (IOError, OSError, PermissionError) as e:
            print(f"Warning: Could not read file {file_path}: {e}")
            return findings, timing
        except Exception as e:
            print(f"Warning: Unexpected error reading file {file_path}: {e}")
            return findings, timing
        
        if not lines:
            return findings, timing
        
        config_findings = []
        config_thread_result = [None]
        config_lock = threading.Lock()
        
        def run_config_detector():
            if self.config_detector:
                config_start = time.time()
                try:
                    result = self.config_detector.check(
                        calls=[],
                        tainted_vars=set(),
                        lines=lines,
                        file_path=str(file_path),
                        ast_result=None,
                        taint_result=None,
                        cfg=None
                    )
                    with config_lock:
                        config_findings.extend(result)
                        config_thread_result[0] = time.time() - config_start
                except Exception as e:
                    print(f"Config detector error: {e}")
        
        config_thread = threading.Thread(target=run_config_detector, daemon=True)
        config_thread.start()
        
        try:
            ast_start = time.time()
            ast_result = self._parse_ast(file_path, language)
            timing['ast_time'] = time.time() - ast_start
            
            if not ast_result:
                config_thread.join()
                findings.extend(config_findings)
                if config_thread_result[0]:
                    timing['config_time'] = config_thread_result[0]
                return findings, timing
            
            cfg_start = time.time()
            cfg = self._build_cfg(ast_result)
            timing['cfg_time'] = time.time() - cfg_start
            
            taint_start = time.time()
            dataflow_result = {'data_flows': ast_result.get('data_flows', [])}
            if hasattr(self.taint_analyzer, 'sanitization_recognizer'):
                self.taint_analyzer.sanitization_recognizer = self.taint_analyzer.sanitization_recognizer.__class__(language)
            taint_result = self.taint_analyzer.analyze(ast_result, cfg, dataflow_result)
            timing['taint_time'] = time.time() - taint_start
            
            all_tainted = set(taint_result.get('all_tainted', []))
            calls = ast_result.get('calls', [])
            
            pattern_start = time.time()
            general_detectors = [d for lang, d in self.general_detectors if lang == language]
            
            general_findings = []
            for detector in general_detectors:
                try:
                    detector_results = detector.check(
                        calls,
                        all_tainted,
                        lines,
                        str(file_path),
                        ast_result,
                        taint_result,
                        cfg=cfg
                    )
                    general_findings.extend(detector_results)
                except Exception as e:
                    print(f"Detector error ({detector.__class__.__name__}): {e}")
            
            findings.extend(general_findings)
            timing['pattern_time'] = time.time() - pattern_start
            
            mcp_start = time.time()
            mcp_detectors = [d for lang, d in self.mcp_detectors if lang == language]
            
            mcp_findings = []
            for detector in mcp_detectors:
                try:
                    detector_results = detector.check(
                        calls,
                        all_tainted,
                        lines,
                        str(file_path),
                        ast_result,
                        taint_result,
                        cfg=cfg
                    )
                    mcp_findings.extend(detector_results)
                except Exception as e:
                    print(f"MCP Detector error ({detector.__class__.__name__}): {e}")
            
            findings.extend(mcp_findings)
            timing['mcp_time'] = time.time() - mcp_start
            
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
        
        config_thread.join()
        findings.extend(config_findings)
        if config_thread_result[0]:
            timing['config_time'] = config_thread_result[0]
        
        return findings, timing
    
    def _get_detectors_for_language(self, language: str) -> List[Any]:
        detectors = []
        
        for lang, detector in self.general_detectors:
            if lang == language:
                detectors.append(detector)
        
        for lang, detector in self.mcp_detectors:
            if lang == language:
                detectors.append(detector)
        
        return detectors
    
    def _parse_ast(self, file_path: Path, language: str) -> Dict[str, Any]:
        import subprocess
        
        if language not in self.parser_paths:
            return {}
        
        parser_path = self.parser_paths[language]
        
        try:
            if language == 'go':
                cmd = [str(parser_path), str(file_path)]
            elif language in ['typescript', 'ts', 'javascript', 'js']:
                cmd = ['node', str(parser_path), str(file_path)]
            else:
                return {}
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return {}
            
            return json.loads(result.stdout)
            
        except Exception as e:
            print(f"Parser error: {e}")
            return {}
    
    def _extract_var_name_from_call(self, arg: str) -> str:
        from scanner.analyzers.common.utils import extract_var_name
        return extract_var_name(arg)
    
    def _build_cfg(self, ast_result: Dict[str, Any]) -> Any:
        from scanner.analyzers.common.control_flow import (
            ControlFlowGraph, ControlFlowEdge, ControlFlowNode, NodeType
        )
        
        cfg = ControlFlowGraph(ast_result.get('file_path', ''))
        
        all_statement_nodes = []
        
        functions = ast_result.get('functions', [])
        for func in functions:
            cfg.add_function(func)
            func_name = func.get('name', 'anonymous')
            node_id = f"func_{func_name}_{func.get('line', 0)}"
            all_statement_nodes.append((node_id, func.get('line', 0), 'function'))
        
        for call in ast_result.get('calls', []):
            cfg.add_call(call)
            call_name = f"{call.get('package', '')}.{call.get('function', '')}" if call.get('package') else call.get('function', '')
            node_id = f"call_{call_name}_{call.get('line', 0)}"
            all_statement_nodes.append((node_id, call.get('line', 0), 'call'))
        
        conditions = ast_result.get('conditions', [])
        condition_nodes = {}
        for cond in conditions:
            cond_expr = cond.get('condition', 'unknown')
            line = cond.get('line', 0)
            node_id = cfg.add_condition(cond_expr, line)
            all_statement_nodes.append((node_id, line, 'condition'))
            condition_nodes[node_id] = {
                'variables': cond.get('variables', []),
                'has_validation': cond.get('has_validation', False) or cond.get('HasValidation', False),
                'validation_type': cond.get('validation_type') or cond.get('ValidationType'),
                'is_negated': cond.get('is_negated', False) or cond.get('IsNegated', False)
            }
        
        loops = ast_result.get('loops', [])
        for loop in loops:
            loop_type = loop.get('type', 'for')
            condition = loop.get('condition', 'unknown')
            line = loop.get('line', 0)
            loop_node_id = cfg.add_loop(loop_type, condition, line)
            all_statement_nodes.append((loop_node_id, line, 'loop'))
        
        all_statement_nodes.sort(key=lambda x: x[1])
        
        node_info_map = {node_id: (line, node_type) for node_id, line, node_type in all_statement_nodes}
        
        condition_merge_map = {}  # cond_node_id -> merge_node_id
        for cond in conditions:
            cond_line = cond.get('line', 0)
            cond_node_id = f"cond_{cond_line}_0"
            then_line = cond.get('then_line', 0)
            else_line = cond.get('else_line', 0)
            end_line = cond.get('end_line', 0)
            
            then_node_id = None
            if then_line > 0:
                for node_id, node_line, node_type in all_statement_nodes:
                    if node_line >= then_line and node_id != cond_node_id:
                        then_node_id = node_id
                        break
            
            else_node_id = None
            if else_line > 0:
                for node_id, node_line, node_type in all_statement_nodes:
                    if node_line >= else_line and node_id != cond_node_id and node_id != then_node_id:
                        else_node_id = node_id
                        break
            
            merge_node_id = None
            if end_line > 0:
                for node_id, node_line, node_type in all_statement_nodes:
                    if node_line > end_line:
                        merge_node_id = node_id
                        break
            
            if then_node_id:
                cfg.add_conditional_branch(
                    condition_node=cond_node_id,
                    true_branch=then_node_id,
                    false_branch=else_node_id,
                    merge_node=merge_node_id
                )
                if merge_node_id:
                    condition_merge_map[cond_node_id] = merge_node_id
        
        loop_info_map = {}  # loop_node_id -> (body_node_id, exit_node_id, body_last_node_id)
        for loop in loops:
            loop_type = loop.get('type', 'for')
            loop_line = loop.get('line', 0)
            loop_node_id = f"loop_{loop_type}_{loop_line}_0"
            body_start = loop.get('body_start', 0)
            body_end = loop.get('body_end', 0)
            
            loop_body_node_id = None
            if body_start > 0:
                for node_id, node_line, node_type in all_statement_nodes:
                    if node_line >= body_start and node_id != loop_node_id:
                        loop_body_node_id = node_id
                        break
            
            loop_body_last_node_id = None
            if body_end > 0:
                for node_id, node_line, node_type in reversed(all_statement_nodes):
                    if body_start <= node_line <= body_end and node_id != loop_node_id:
                        loop_body_last_node_id = node_id
                        break
            
            loop_exit_node_id = None
            if body_end > 0:
                for node_id, node_line, node_type in all_statement_nodes:
                    if node_line > body_end:
                        loop_exit_node_id = node_id
                        break
            
            if loop_body_node_id:
                exit_node = loop_exit_node_id if loop_exit_node_id else (all_statement_nodes[-1][0] if all_statement_nodes else None)
                if exit_node:
                    cfg.add_loop_edges(
                        loop_entry=loop_node_id,
                        loop_body=loop_body_node_id,
                        loop_exit=exit_node,
                        back_edge_from=loop_body_last_node_id if loop_body_last_node_id else loop_body_node_id
                    )
                    loop_info_map[loop_node_id] = (loop_body_node_id, exit_node, loop_body_last_node_id)
        
        processed_control_nodes = set()
        for cond in conditions:
            processed_control_nodes.add(f"cond_{cond.get('line', 0)}_0")
        for loop in loops:
            processed_control_nodes.add(f"loop_{loop.get('type', 'for')}_{loop.get('line', 0)}_0")
        
        condition_ranges = {}  # cond_node_id -> (start_line, end_line)
        for cond in conditions:
            cond_line = cond.get('line', 0)
            cond_node_id = f"cond_{cond_line}_0"
            then_line = cond.get('then_line', 0)
            end_line = cond.get('end_line', 0)
            if then_line > 0 and end_line > 0:
                condition_ranges[cond_node_id] = (then_line, end_line)
        
        loop_ranges = {}  # loop_node_id -> (start_line, end_line)
        for loop in loops:
            loop_type = loop.get('type', 'for')
            loop_line = loop.get('line', 0)
            loop_node_id = f"loop_{loop_type}_{loop_line}_0"
            body_start = loop.get('body_start', 0)
            body_end = loop.get('body_end', 0)
            if body_start > 0 and body_end > 0:
                loop_ranges[loop_node_id] = (body_start, body_end)
        
        for i in range(len(all_statement_nodes) - 1):
            current_node_id = all_statement_nodes[i][0]
            next_node_id = all_statement_nodes[i + 1][0]
            current_line = node_info_map.get(current_node_id, (0, ''))[0]
            next_line = node_info_map.get(next_node_id, (0, ''))[0]
            
            if any(e.from_node == current_node_id and e.to_node == next_node_id for e in cfg.edges):
                continue
            
            if current_node_id in processed_control_nodes or next_node_id in processed_control_nodes:
                continue
            
            skip = False
            for cond_node_id, merge_node_id in condition_merge_map.items():
                if next_node_id == merge_node_id:
                    if cond_node_id in condition_ranges:
                        start_line, end_line = condition_ranges[cond_node_id]
                        if start_line <= current_line <= end_line:
                            skip = True
                            break
            
            if skip:
                continue
            
            for loop_node_id, (_, exit_node, _) in loop_info_map.items():
                if next_node_id == exit_node:
                    if loop_node_id in loop_ranges:
                        start_line, end_line = loop_ranges[loop_node_id]
                        if start_line <= current_line <= end_line:
                            skip = True
                            break
            
            if skip:
                continue
            
            edge = ControlFlowEdge(
                from_node=current_node_id,
                to_node=next_node_id,
                edge_type="sequential"
            )
            cfg.add_edge(edge)
        
        if all_statement_nodes:
            cfg.entry_node = all_statement_nodes[0][0]
            cfg.exit_nodes.add(all_statement_nodes[-1][0])
            for merge_node_id in condition_merge_map.values():
                if not cfg.get_successors(merge_node_id):
                    cfg.exit_nodes.add(merge_node_id)
            for loop_node_id, (_, exit_node, _) in loop_info_map.items():
                if exit_node and not cfg.get_successors(exit_node):
                    cfg.exit_nodes.add(exit_node)
        
        return cfg
    
    def scan_file_for_mcp(self, file_path: Path) -> List[Finding]:
        try:
            from scanner.analyzers.language import LanguageDetector
            detector = LanguageDetector()
            detected_lang = detector.detect_from_file(file_path)
            
            if detected_lang in ['go', 'typescript', 'ts', 'javascript', 'js']:
                findings, _ = self.scan_file(file_path, detected_lang)
                return findings
            
            findings = []
            if self.config_detector:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    
                    if lines:
                        config_findings = self.config_detector.check(
                            calls=[],
                            tainted_vars=set(),
                            lines=lines,
                            file_path=str(file_path),
                            ast_result=None,
                            taint_result=None,
                            cfg=None
                        )
                        findings.extend(config_findings)
                except (IOError, OSError, PermissionError) as e:
                    print(f"Warning: Could not read file {file_path}: {e}")
                except Exception as e:
                    print(f"Warning: Config detector failed for {file_path}: {e}")
            
            return findings
                
        except Exception as e:
            print(f"Error scanning file {file_path} for MCP: {e}")
            return []
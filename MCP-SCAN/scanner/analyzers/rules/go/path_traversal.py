import re
import ast
from typing import List, Dict, Set, Optional, Tuple, Any
from scanner.analyzers.common.scanner import Finding, CommonPatterns
from scanner.analyzers.common.base_detector import BaseDetector
from scanner.analyzers.common.utils import extract_var_name

class DataFlowAnalyzer:
    
    USER_INPUT_SOURCES = [
        'FormValue', 'Query', 'PostFormValue', 'Header.Get',
        'URL.Query', 'Request.', 'Args', 'Getenv', 'LookupEnv',
        'flag.String', 'flag.Parse', 'os.Args', 'ReadFile', 'ReadAll',
        'ReadDir', 'Scan', 'ReadString', 'ReadBytes', 'ReadFrom',
        'Parse', 'Unmarshal', 'Decode', 'Load', 'Import'
    ]
    
    USER_INPUT_PATTERNS = [
        r'.*\.FormValue\(', r'.*\.Query\(', r'.*\.PostFormValue\(', r'.*\.Header\.Get\(',
        r'.*\.URL\.Query\(', r'.*\.Request\.', r'.*\.Args\[', r'.*\.Getenv\(', r'.*\.LookupEnv\(',
        r'.*\.flag\.String\(', r'.*\.flag\.Parse\(', r'.*\.os\.Args\[',
        r'.*\.ReadFile\(', r'.*\.ReadAll\(', r'.*\.ReadDir\(', r'.*\.Scan\(',
        r'.*\.ReadString\(', r'.*\.ReadBytes\(', r'.*\.ReadFrom\(',
        r'.*\.Parse\(', r'.*\.Unmarshal\(', r'.*\.Decode\(',
        r'.*\.multipart\.', r'.*\.json\.', r'.*\.xml\.'
    ]
    
    SANITIZER_FUNCTIONS = [
        'filepath.Clean', 'filepath.Join', 'filepath.Abs', 'filepath.EvalSymlinks',
        'path.Join', 'path.Clean', 'path.Abs',
        'strings.TrimSpace', 'strings.Trim', 'strings.Replace', 'strings.TrimPrefix',
        'html.EscapeString', 'url.QueryEscape', 'regexp.MustCompile',
        'securejoin.SecureJoin', 'path/filepath.Join'
    ]
    
    def __init__(self):
        self.user_input_sources = self.USER_INPUT_SOURCES
        
        self.sanitizer_functions = self.SANITIZER_FUNCTIONS
        
        self.dangerous_sinks = {
            'critical': [
                ('os', 'Remove'), ('os', 'RemoveAll'), ('os', 'Rename'),
                ('os', 'Chmod'), ('os', 'Chown'), ('os', 'Symlink'),
                ('syscall', 'Unlink'), ('syscall', 'Rmdir'),
                ('os', 'Truncate'), ('os', 'Chmod'), ('os', 'Chown')
            ],
            'high': [
                ('os', 'WriteFile'), ('os', 'Create'), ('os', 'OpenFile'),
                ('os', 'MkdirAll'), ('os', 'Rename'), ('ioutil', 'WriteFile'),
                ('os', 'CreateTemp'), ('os', 'MkdirTemp'), ('os', 'TempDir'),
                ('os', 'CreateNamedPipe'), ('os', 'Pipe')
            ],
            'medium': [
                ('os', 'ReadFile'), ('os', 'Open'), ('os', 'Stat'),
                ('os', 'ReadDir'), ('ioutil', 'ReadFile'), ('ioutil', 'ReadAll'),
                ('os', 'Lstat'), ('os', 'Stat'), ('os', 'Readlink'),
                ('os', 'Walk'), ('os', 'WalkDir'), ('filepath', 'Walk'),
                ('os', 'LookPath'), ('os', 'Executable')
            ],
            'low': [
                ('os', 'Mkdir'), ('filepath', 'Join'), ('path', 'Join'),
                ('os', 'Getwd'), ('os', 'Chdir')
            ]
        }
        self.user_input_patterns_compiled = [re.compile(p) for p in self.USER_INPUT_PATTERNS]
    
    def analyze_data_flow(self, ast_result: Dict[str, Any], taint_result: Dict[str, Any]) -> List[Dict]:
        findings = []
        
        tainted_vars = set(taint_result.get('all_tainted', []))
        
        for call in ast_result.get('calls', []):
            pkg = call.get('package', '')
            fn = call.get('function', '')
            args = call.get('args', [])
            line = call.get('line', 0)
            
            is_dangerous = False
            severity = "medium"
            for sev, sinks in self.dangerous_sinks.items():
                if (pkg, fn) in sinks:
                    is_dangerous = True
                    severity = sev
                    break
            
            if not is_dangerous:
                continue
            
            for arg in args:
                arg_var = self._extract_var_name(arg)
                if arg_var and arg_var in tainted_vars:
                    findings.append({
                        'severity': severity,
                        'message': f"Data flow: Tainted variable '{arg_var}' reaches {pkg}.{fn}()",
                        'line': line,
                        'file': ast_result.get('file_path', ''),
                        'tainted_var': arg_var,
                        'sink': f"{pkg}.{fn}"
                    })
        
        return findings
    
    def _extract_var_name(self, arg: str) -> str:
        return extract_var_name(arg)
        
    def _fallback_regex_analysis(self, file_content: str, file_path: str) -> List[Dict]:
        findings = []
        lines = file_content.split('\n')
        
        variable_assignments = {}
        tainted_vars = set()
        
        for line_num, line in enumerate(lines, 1):
            for source in self.user_input_sources:
                if source in line:
                    var_match = re.search(r'(\w+)\s*[=:]\s*.*' + re.escape(source), line)
                    if var_match:
                        var_name = var_match.group(1)
                        tainted_vars.add(var_name)
                        variable_assignments[var_name] = {
                            'line': line_num,
                            'source': source,
                            'tainted': True
                        }
            
            for pattern in self.user_input_patterns_compiled:
                if pattern.search(line):
                    var_match = pattern.search(line)
                    if var_match:
                        var_name = var_match.group(1) if var_match.groups() else var_match.group(0)
                        tainted_vars.add(var_name)
                        variable_assignments[var_name] = {
                            'line': line_num,
                            'source': f'pattern:{pattern.pattern}',
                            'tainted': True
                        }
            
            for severity, sinks in self.dangerous_sinks.items():
                for pkg, fn in sinks:
                    pattern = rf'{pkg}\.{fn}\s*\('
                    if re.search(pattern, line):
                        args_match = re.search(rf'{pkg}\.{fn}\s*\(([^)]+)\)', line)
                        if args_match:
                            args = args_match.group(1)
                            for var in tainted_vars:
                                if var in args:
                                    findings.append({
                                        'severity': severity,
                                        'message': f"Data flow: User input '{var}' reaches {pkg}.{fn}()",
                                        'line': line_num,
                                        'file': file_path,
                                        'tainted_var': var,
                                        'sink': f"{pkg}.{fn}"
                                    })
        
        return findings

class PathTraversalDetector(BaseDetector):
    
    def _is_from_literal(self, var_name: str, data_flows: List[Dict], ast_result: Dict[str, Any] = None) -> bool:
        return super()._is_from_literal(var_name, data_flows, ast_result)
    
    SAFE_FUNCTIONS = [
        ('log', 'Printf'), ('log', 'Print'), ('log', 'Println'),
        ('fmt', 'Printf'), ('fmt', 'Print'), ('fmt', 'Println'),
        ('config', 'Get'), ('config', 'Set'), ('config', 'Load'),
        ('buffer', 'Write'), ('buffer', 'Read'), ('buffer', 'String'),
        ('strings', 'Builder'), ('bytes', 'Buffer'),
        ('os', 'Getenv'), ('os', 'Setenv'), ('os', 'Unsetenv'), ('os', 'Clearenv'),
        ('os', 'ExpandEnv'), ('os', 'Expand')
    ]
    
    def __init__(self, language: str = "go"):
        super().__init__()
        self.language = language
        self.analyzer = DataFlowAnalyzer()
        self.user_input_patterns_compiled = self.analyzer.user_input_patterns_compiled

    def get_name(self) -> str:
        return "path-traversal"

    def get_cwe(self) -> str:
        return "CWE-22"
    
    def get_rule_id(self, language: str = None) -> str:
        lang = language or self.language
        return f"{lang}/path-traversal"
    
    def is_dangerous_sink(self, pkg: str, fn: str) -> bool:
        for sinks in self.analyzer.dangerous_sinks.values():
            if (pkg, fn) in sinks:
                return True
        return False
    
    def get_sink_severity(self, pkg: str, fn: str) -> str:
        for sev, sinks in self.analyzer.dangerous_sinks.items():
            if (pkg, fn) in sinks:
                return sev
        return "medium"
    
    def is_safe_usage(self, call: Dict, line_content: str, args: List[str], 
                     file_path: str, lines: List[str]) -> bool:
        pkg = call.get('package', '')
        fn = call.get('function', '')
        
        if self._is_safe_function(pkg, fn):
            return True
        
        if self._is_hardcoded_path(args, line_content):
            return True
        
        if self._is_safe_path_usage(args, line_content, lines, call.get('line', 0)):
            return True
        
        for arg in args:
            arg_var = self.analyzer._extract_var_name(arg)
            if arg_var:
                line_num = call.get('line', 0)
                if line_num > 0 and lines:
                    if self._check_sanitizer_applied(arg_var, lines, line_num, [], None):
                        return True
                    ast_result_local = {'file_path': file_path} if file_path else {}
                    if self._is_path_from_literal_or_safe_pattern(arg_var, [], lines, line_num, ast_result_local):
                        return True
        
        return False
    
    def analyze_data_flow(self, ast_result: Dict[str, Any], 
                         taint_result: Dict[str, Any]) -> List[Dict]:
        findings = self.analyzer.analyze_data_flow(ast_result, taint_result)
        
        data_flows = ast_result.get('data_flows', [])
        filtered_findings = []
        
        file_path = ast_result.get('file_path', '')
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except (IOError, OSError, PermissionError) as e:
            print(f"Warning: Could not read file {file_path}: {e}")
            lines = []
        
        for finding in findings:
            tainted_var = finding.get('tainted_var', '')
            line_num = finding.get('line', 0)
            
            if tainted_var and self._is_from_literal(tainted_var, data_flows, taint_result):
                continue
            
            if tainted_var and self._is_path_from_literal_or_safe_pattern(tainted_var, data_flows, lines, line_num, ast_result):
                continue
            
            if tainted_var and self._check_sanitizer_applied(tainted_var, lines, line_num, data_flows, ast_result):
                continue
            
            filtered_findings.append(finding)
        
        return filtered_findings
    
    def build_finding_message(self, call: Dict, severity: str, 
                             base_var: str = None, data_flow_finding: Dict = None) -> str:
        pkg = call.get('package', '')
        fn = call.get('function', '')
        
        tainted_var = base_var
        if data_flow_finding and not base_var:
            tainted_var = data_flow_finding.get('tainted_var', '')
        
        if tainted_var:
            return f"Path traversal: User input '{tainted_var}' in {pkg}.{fn}() - verify input sanitization"
        
        return f"Path traversal: {pkg}.{fn}() - verify input sanitization"
    
    def _validate_data_flow_finding(self, call: Dict, args: List[str], 
                                    line_content: str, data_flow_finding: Dict,
                                    severity: str, confidence: float) -> Tuple[str, float]:
        if self._is_safe_path_usage(args, line_content, [], call.get('line', 0)):
            severity, multiplier = CommonPatterns.adjust_severity_with_context(severity, 'safe_path')
            if severity == "info":
                return None, 0.0
            confidence *= multiplier
        return severity, confidence


    def _is_safe_function(self, pkg: str, fn: str) -> bool:
        return (pkg, fn) in self.SAFE_FUNCTIONS

    def _is_hardcoded_path(self, args: List[str], line_content: str) -> bool:
        if not args:
            return False
        
        for pattern in self.user_input_patterns_compiled:
            if pattern.search(line_content):
                return False
        
        return all(
            arg.strip().startswith('"') and arg.strip().endswith('"')
            for arg in args
        )

    def _analyze_data_flow_advanced(self, file_content: str, file_path: str) -> List[Dict]:
        findings = []
        lines = file_content.split('\n')
        
        variable_chain = {}
        tainted_vars = set()
        
        for line_num, line in enumerate(lines, 1):
            user_input_match = re.search(r'(\w+)\s*[=:]\s*.*(?:FormValue|Query|Getenv|Args|ReadFile|ReadAll|ReadDir|Scan)', line)
            if user_input_match:
                var_name = user_input_match.group(1)
                tainted_vars.add(var_name)
                variable_chain[var_name] = [line_num, 'user_input', True]
            
            for pattern in self.analyzer.USER_INPUT_PATTERNS:
                pattern_match = re.search(rf'(\w+)\s*[=:]\s*.*{pattern}', line)
                if pattern_match:
                    var_name = pattern_match.group(1)
                    tainted_vars.add(var_name)
                    variable_chain[var_name] = [line_num, f'pattern:{pattern}', True]
            
            assignment_match = re.search(r'(\w+)\s*[=:]\s*(\w+)', line)
            if assignment_match:
                target_var = assignment_match.group(1)
                source_var = assignment_match.group(2)
                
                if source_var in tainted_vars:
                    tainted_vars.add(target_var)
                    variable_chain[target_var] = [line_num, f'from_{source_var}', True]
                elif source_var in variable_chain:
                    if variable_chain[source_var][2]:
                        tainted_vars.add(target_var)
                        variable_chain[target_var] = [line_num, f'from_{source_var}', True]
            
            for severity, sinks in self.analyzer.dangerous_sinks.items():
                for pkg, fn in sinks:
                    sink_pattern = rf'{pkg}\.{fn}\s*\(([^)]+)\)'
                    sink_match = re.search(sink_pattern, line)
                    if sink_match:
                        args = sink_match.group(1)
                        
                        for var in tainted_vars:
                            if var in args:
                                findings.append({
                                    'severity': severity,
                                    'message': f"Data flow: User input '{var}' → {pkg}.{fn}() (via {variable_chain.get(var, ['unknown'])[1]})",
                                    'line': line_num,
                                    'file': file_path,
                                    'tainted_var': var,
                                    'sink': f"{pkg}.{fn}",
                                    'data_flow': variable_chain.get(var, [])
                                })
        
        return findings

    def _is_safe_path_usage(self, args: List[str], line_content: str, lines: List[str], line: int) -> bool:
        safe_literals = [
            'README.md', 'LICENSE', 'CHANGELOG.md',
            '.gitignore', '.gitattributes',
            'go.mod', 'go.sum', 'Dockerfile',
            '/dev/null', '/dev/stdout', '/dev/stderr'
        ]

        for arg in args:
            if arg.startswith('"') and arg.endswith('"'):
                path_value = arg.strip('"')
                if any(safe in path_value for safe in safe_literals):
                    return True

        config_patterns = [
            r'cfg\.\w+', r'config\.\w+', r'settings\.\w+', r'conf\.\w+'
        ]

        for pattern in config_patterns:
            if re.search(pattern, line_content):
                return True

        return False
    
    def _is_path_from_literal_or_safe_pattern(self, var_name: str, data_flows: List[Dict], 
                                               lines: List[str], line_num: int, 
                                               ast_result: Dict[str, Any] = None) -> bool:
        if not var_name or not lines or line_num < 1:
            return False
        
        safe_patterns = [
            r'README\.md',
            r'__toolsnaps__',
            r'\.snap',
            r'docs/.*\.md',
            r'LICENSE',
            r'CHANGELOG\.md',
        ]
        
        file_path = ast_result.get('file_path', '') if ast_result else ''
        
        start_line = max(1, line_num - 50)
        end_line = min(len(lines), line_num + 5)
        
        for i in range(start_line - 1, end_line):
            line = lines[i]
            
            if re.search(rf'{re.escape(var_name)}\s*[:=]\s*["\']', line):
                path_match = re.search(rf'{re.escape(var_name)}\s*[:=]\s*["\']([^"\']+)["\']', line)
                if path_match:
                    path_value = path_match.group(1)
                    if any(re.search(pattern, path_value, re.IGNORECASE) for pattern in safe_patterns):
                        return True
            
            if re.search(rf'{re.escape(var_name)}\s*[:=]\s*fmt\.Sprintf\(', line):
                format_match = re.search(rf'{re.escape(var_name)}\s*[:=]\s*fmt\.Sprintf\(["\']([^"\']+)["\']', line)
                if format_match:
                    format_str = format_match.group(1)
                    if any(pattern in format_str for pattern in ['__toolsnaps__', '.snap', 'README', 'docs/']):
                        return True
            
            if re.search(rf'generate\w*Docs?\s*\(["\']', line, re.IGNORECASE):
                if 'README.md' in line or 'docs/' in line or var_name in line:
                    return True
            
            if re.search(rf'generate\w*Docs?\s*\(\s*{re.escape(var_name)}', line, re.IGNORECASE):
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    if any(pattern in next_line for pattern in ['README.md', 'docs/', '"README.md"', '"docs/']):
                        return True
        
        if data_flows:
            for flow in data_flows:
                to_var = flow.get('to', '').strip()
                if to_var == var_name:
                    from_var = flow.get('from', '').strip()
                    if from_var and self._is_literal_string(from_var):
                        if any(re.search(pattern, from_var, re.IGNORECASE) for pattern in safe_patterns):
                            return True
                    if from_var:
                        if self._is_path_from_literal_or_safe_pattern(from_var, data_flows, lines, max(1, line_num - 1), ast_result):
                            return True
        
        return False
    
    def _check_sanitizer_applied(self, var_name: str, lines: List[str], line_num: int, 
                                 data_flows: List[Dict], ast_result: Dict[str, Any] = None) -> bool:
        if not var_name or not lines or line_num < 1:
            return False
        
        sanitizer_patterns = [
            r'filepath\.Clean\s*\(',
            r'filepath\.Join\s*\(',
            r'filepath\.Abs\s*\(',
            r'filepath\.EvalSymlinks\s*\(',
            r'path\.Clean\s*\(',
            r'path\.Join\s*\(',
            r'path\.Abs\s*\(',
            r'securejoin\.SecureJoin\s*\(',
        ]
        
        var_patterns = [
            rf'{re.escape(var_name)}\s*[:=]\s*filepath\.Clean\s*\(',
            rf'{re.escape(var_name)}\s*[:=]\s*path\.Clean\s*\(',
            rf'filepath\.Clean\s*\(\s*[^)]*\b{re.escape(var_name)}\b',
            rf'path\.Clean\s*\(\s*[^)]*\b{re.escape(var_name)}\b',
        ]
        
        start_line = max(1, line_num - 20)
        end_line = min(len(lines), line_num + 1)
        
        for i in range(start_line - 1, end_line):
            line = lines[i]
            
            for pattern in var_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return True
            
            for sanitizer in sanitizer_patterns:
                if re.search(sanitizer, line, re.IGNORECASE):
                    if var_name in line:
                        return True
        
        if data_flows:
            for flow in data_flows:
                to_var = flow.get('to', '').strip()
                if to_var == var_name:
                    from_var = flow.get('from', '').strip()
                    if from_var and self._check_sanitizer_applied(from_var, lines, line_num - 1, data_flows, ast_result):
                        return True
        
        return False
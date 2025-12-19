import re
from typing import List, Dict, Set, Any
from scanner.analyzers.common.scanner import Finding, CommonPatterns
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS

class PathTraversalDetector:
    CRITICAL_SINKS = [
        ('fs', 'unlink'), ('', 'unlink'), ('fs', 'unlinkSync'), ('', 'unlinkSync'),
        ('fs', 'rm'), ('', 'rm'), ('fs', 'rmSync'), ('', 'rmSync'),
        ('fs', 'rmdir'), ('', 'rmdir'), ('fs', 'rmdirSync'), ('', 'rmdirSync'),
        ('fs', 'rename'), ('', 'rename'), ('fs', 'renameSync'), ('', 'renameSync'),
    ]
    HIGH_SINKS = [
        ('fs', 'writeFile'), ('', 'writeFile'), ('fs', 'writeFileSync'), ('', 'writeFileSync'),
        ('fs', 'appendFile'), ('', 'appendFile'), ('fs', 'appendFileSync'), ('', 'appendFileSync'),
        ('fs', 'createWriteStream'), ('', 'createWriteStream'),
        ('fs', 'chmod'), ('', 'chmod'), ('fs', 'chmodSync'), ('', 'chmodSync'),
        ('fs', 'chown'), ('', 'chown'), ('fs', 'chownSync'), ('', 'chownSync'),
        ('fs', 'symlink'), ('', 'symlink'), ('fs', 'symlinkSync'), ('', 'symlinkSync'),
        ('fs', 'link'), ('', 'link'), ('fs', 'linkSync'), ('', 'linkSync'),
    ]
    MEDIUM_SINKS = [
        ('fs', 'readFile'), ('', 'readFile'), ('fs', 'readFileSync'), ('', 'readFileSync'),
        ('fs', 'createReadStream'), ('', 'createReadStream'),
        ('fs', 'readdir'), ('', 'readdir'), ('fs', 'readdirSync'), ('', 'readdirSync'),
        ('fs', 'stat'), ('', 'stat'), ('fs', 'statSync'), ('', 'statSync'),
        ('fs', 'lstat'), ('', 'lstat'), ('fs', 'lstatSync'), ('', 'lstatSync'),
        ('fs', 'readlink'), ('', 'readlink'), ('fs', 'readlinkSync'), ('', 'readlinkSync'),
        ('fs', 'realpath'), ('', 'realpath'), ('fs', 'realpathSync'), ('', 'realpathSync'),
    ]
    LOW_SINKS = [
        ('fs', 'mkdir'), ('', 'mkdir'), ('fs', 'mkdirSync'), ('', 'mkdirSync'),
        ('fs', 'mkdtemp'), ('', 'mkdtemp'), ('fs', 'mkdtempSync'), ('', 'mkdtempSync'),
        ('fs', 'access'), ('', 'access'), ('fs', 'accessSync'), ('', 'accessSync'),
        ('fs', 'exists'), ('', 'exists'), ('fs', 'existsSync'), ('', 'existsSync'),
        ('path', 'join'), ('path', 'resolve'),
    ]
    
    SAFE_COMMENT_PATTERNS = [
        r'//\s*eslint-disable', r'//\s*@ts-ignore', r'//\s*safe',
        r'//\s*trusted', r'//\s*controlled',
    ]
    SAFE_PATH_PATTERNS = [
        r'README', r'LICENSE', r'CHANGELOG', r'\.gitignore', r'package\.json',
        r'tsconfig\.json', r'\.eslintrc', r'\.prettierrc', r'__tests__',
        r'__mocks__', r'\.test\.', r'\.spec\.', r'node_modules',
    ]
    CONTEXT_COMMENT_PATTERNS = [
        r'//\s*nosec', r'//\s*eslint-disable', r'//\s*safe', r'//\s*sanitized',
        r'/\*\s*nosec\s*\*/', r'/\*\s*safe\s*\*/',
    ]
    CONTEXT_PATH_PATTERNS = [
        r'path\.join\(', r'path\.resolve\(', r'path\.normalize\(',
        r'__dirname', r'__filename', r'process\.cwd\(',
        r'\.json', r'\.txt', r'\.md', r'\.log', r'\.conf',
        r'package\.json', r'README', r'LICENSE', r'CHANGELOG',
        r'node_modules/', r'\.git/', r'dist/', r'build/', r'public/', r'static/', r'assets/', r'images/',
    ]
    TEMPLATE_PATTERNS = [
        r'`[^`]*\$\{[^}]+\}[^`]*`', r'`[^`]*\$\{[^}]+\.[^}]+\}[^`]*`',
    ]
    USER_INPUT_PATTERNS = [
        r'filename', r'filepath', r'path', r'file', r'name', r'title',
        r'content', r'data', r'input', r'user', r'args', r'param',
    ]
    
    def __init__(self):
        self.critical_sinks = self.CRITICAL_SINKS
        self.high_sinks = self.HIGH_SINKS
        self.medium_sinks = self.MEDIUM_SINKS
        self.low_sinks = self.LOW_SINKS
        self.dangerous_sinks = self.CRITICAL_SINKS + self.HIGH_SINKS + self.MEDIUM_SINKS + self.LOW_SINKS
        
        self.safe_comment_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.SAFE_COMMENT_PATTERNS]
        self.safe_path_patterns_compiled = [re.compile(p) for p in self.SAFE_PATH_PATTERNS]
        self.context_comment_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.CONTEXT_COMMENT_PATTERNS]
        self.context_path_patterns_compiled = [re.compile(p) for p in self.CONTEXT_PATH_PATTERNS]
        self.template_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.TEMPLATE_PATTERNS]
        self.template_var_patterns_compiled = [re.compile(r'\$\{([^}]+)\}', re.IGNORECASE)]
        self.user_input_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.USER_INPUT_PATTERNS]
        self.var_patterns_compiled = [re.compile(r'\b(\w+)\s*\+'), re.compile(r'\+\s*(\w+)\b')]
    
    SAFE_LITERALS = [
        'README', 'LICENSE', 'CHANGELOG', 'CONTRIBUTING',
        '.git', 'docs/', '__', 'test', 'fixtures/',
        '.md', '.txt', '.yaml', '.yml', '.json', '.toml',
        'config', 'static/', 'public/', 'assets/',
        'package.json', 'node_modules/', 'dist/', 'build/',
    ]
    
    def get_name(self) -> str:
        return "path-traversal"
    
    def get_cwe(self) -> str:
        return "CWE-22"
    
    def _get_context_info(self, line_content: str, args: List[str], file_path: str) -> Dict[str, bool]:
        context = {
            'is_test_file': CommonPatterns.is_test_file(file_path, "typescript"),
            'has_safe_comment': any(p.search(line_content) for p in self.context_comment_patterns_compiled),
            'is_safe_path_pattern': any(p.search(line_content) for p in self.context_path_patterns_compiled),
            'is_literal_path': False
        }
        
        if args and args[0].startswith('"') and args[0].endswith('"'):
            path_value = args[0].strip('"')
            context['is_literal_path'] = (
                not path_value or
                any(safe in path_value for safe in self.SAFE_LITERALS) or
                (not path_value.startswith(('/','..', '~')) and '/' not in path_value and '\\' not in path_value)
            )
        
        return context
    
    def _check_test_file_context(self, file_path: str) -> bool:
        return CommonPatterns.is_test_file(file_path, "typescript")
    
    def _check_safe_patterns(self, line_content: str) -> bool:
        if any(pattern.search(line_content) for pattern in self.safe_comment_patterns_compiled):
            return True
        if re.search(r'\.git/', line_content):
            return True
        if 'process.cwd()' in line_content or '__dirname' in line_content:
            return True
        if any(pattern.search(line_content) for pattern in self.safe_path_patterns_compiled):
            return True
        if 'path.join(' in line_content or 'path.resolve(' in line_content:
            return True
        return False
    
    def _check_safe_arg_patterns(self, args: List[str], lines: List[str] = None) -> bool:
        if not args:
            return False
        
        if lines:
            file_content = ''.join(lines[:200])
            if 'process.cwd()' in file_content:
                return True
        
        return False
    
    def _check_template_literal_unsafe(self, line_content: str) -> bool:
        if '`' not in line_content:
            return False
        
        for pattern in self.template_patterns_compiled:
            matches = pattern.findall(line_content)
            for match in matches:
                for var_pattern in self.template_var_patterns_compiled:
                    var_matches = var_pattern.findall(match)
                    for var_expr in var_matches:
                        var_expr = var_expr.strip()
                        if any(user_pattern.search(var_expr) 
                              for user_pattern in self.user_input_patterns_compiled):
                            return True
                        if '.' in var_expr:
                            base_var = CommonPatterns.extract_base_var(var_expr)
                            if any(user_pattern.search(base_var) 
                                  for user_pattern in self.user_input_patterns_compiled):
                                return True
        return False
    
    def _check_string_concat_unsafe(self, line_content: str) -> bool:
        if '+' not in line_content:
            return False
        
        for pattern in self.var_patterns_compiled:
            matches = pattern.findall(line_content)
            for var_name in matches:
                if any(user_pattern.search(var_name) 
                      for user_pattern in self.user_input_patterns_compiled):
                    return True
        return False
    
    def _check_literal_path(self, args: List[str]) -> bool:
        if not args or not (args[0].startswith('"') or args[0].startswith("'") or args[0].startswith('`')):
            return False
        
        path_value = args[0].strip('"`\'')
        if not path_value:
            return True
        
        if any(safe in path_value for safe in self.SAFE_LITERALS):
            return True
        
        if not path_value.startswith(('/','..', '~')):
            if '/' not in path_value and '\\' not in path_value:
                if re.match(r'^[\w\-\.]+\.(md|txt|json|log|tmp|dat|xml|yaml|yml|csv|ini|conf)$', path_value):
                    return True
                return True
        
        return False
    
    def _is_safe_usage(self, line_content: str, args: List[str], file_path: str, lines: List[str] = None) -> bool:
        if self._check_test_file_context(file_path):
            return True
        
        if self._check_safe_patterns(line_content):
            return True
        
        if self._check_safe_arg_patterns(args, lines):
            return True
        
        if self._check_template_literal_unsafe(line_content):
            return False
        
        if self._check_string_concat_unsafe(line_content):
            return False
        
        if self._check_literal_path(args):
            return True
        
        return False
    
    def _has_complete_path_validation(self, lines: List[str], line: int, var_name: str = "") -> tuple[bool, bool, bool]:
        if not lines or line < 1 or line > len(lines):
            return False, False, False
        
        start = max(0, line - 30)
        end = min(len(lines), line + 5)
        context = '\n'.join(lines[start:end])
        
        has_normalize = False
        has_resolve = False
        has_expand_home = False
        
        normalize_patterns = [
            r'path\.normalize\s*\(',
            r'normalizePath\s*\(',
            r'\.normalize\s*\(',
        ]
        
        resolve_patterns = [
            r'path\.resolve\s*\(',
            r'resolvePath\s*\(',
            r'\.resolve\s*\(',
        ]
        
        expand_home_patterns = [
            r'expandHome\s*\(',
            r'expand.*home',
            r'os\.homedir\s*\(',
            r'process\.env\.HOME',
            r'~\s*[=:]',
            r'filepath\.startsWith\s*\(\s*[\'"]~',
            r'\.startsWith\s*\(\s*[\'"]~',
        ]
        
        for pattern in normalize_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                if not var_name or var_name.lower() in context.lower():
                    has_normalize = True
                    break
        
        for pattern in resolve_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                if not var_name or var_name.lower() in context.lower():
                    has_resolve = True
                    break
        
        for pattern in expand_home_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                if not var_name or var_name.lower() in context.lower():
                    has_expand_home = True
                    break
        
        return has_normalize, has_resolve, has_expand_home
    
    def _has_extension_validation(self, lines: List[str], line: int, var_name: str = "") -> bool:
        if not lines or line < 1 or line > len(lines):
            return False
        
        start = max(0, line - 30)
        end = min(len(lines), line + 5)
        context = '\n'.join(lines[start:end])
        
        extension_patterns = [
            r'path\.extname\s*\(',
            r'\.extname\s*\(',
            r'\.endsWith\s*\(\s*[\'"]\.',
            r'\.endsWith\s*\(\s*[\'"]\.md',
            r'\.endsWith\s*\(\s*[\'"]\.markdown',
            r'\.includes\s*\(\s*[\'"]\.md',
            r'\.includes\s*\(\s*[\'"]\.markdown',
            r'markdownExt\s*\.includes',
            r'\.ext\s*===?\s*[\'"]\.',
            r'Required file is not a Markdown file',
            r'not.*markdown.*file',
            r'extension.*not.*allowed',
        ]
        
        for pattern in extension_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                if not var_name or var_name.lower() in context.lower():
                    return True
        
        return False
    
    def _has_allowed_directory_validation(self, lines: List[str], line: int, var_name: str = "") -> bool:
        if not lines or line < 1 or line > len(lines):
            return False
        
        start = max(0, line - 30)
        end = min(len(lines), line + 5)
        context = '\n'.join(lines[start:end])
        
        allowed_dir_patterns = [
            r'process\.env\.[A-Z_]+.*SHARE.*DIR',
            r'process\.env\.[A-Z_]+.*ALLOWED.*DIR',
            r'process\.env\.[A-Z_]+.*BASE.*DIR',
            r'MD_SHARE_DIR',
            r'ALLOWED_DIR',
            r'SHARE_DIR',
            r'BASE_DIR',
            r'\.startsWith\s*\(\s*allowed',
            r'\.startsWith\s*\(\s*allowedShareDir',
            r'\.startsWith\s*\(\s*allowedDir',
            r'Only files in.*are allowed',
            r'files in.*allowed',
            r'allowed.*directory',
        ]
        
        for pattern in allowed_dir_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                if not var_name or var_name.lower() in context.lower():
                    return True
        
        return False
    
    def _analyze_data_flow(self, ast_result: Dict[str, Any], taint_result: Dict[str, Any], 
                           calls: List[Dict], dangerous_sinks: List[tuple]) -> List[Dict]:
        data_flow_findings = []
        
        if not ast_result or not taint_result:
            return data_flow_findings
        
        data_flows = ast_result.get('data_flows', [])
        tainted_vars = set(taint_result.get('all_tainted', []))
        
        actual_user_input_sources = set()
        for source in ast_result.get('taint_sources', []):
            var_name = source.get('var_name', '')
            source_type = source.get('source_type', '')
            if source_type in ['req_body', 'req_query', 'req_params', 'process_argv', 'tool_args']:
                actual_user_input_sources.add(var_name)
        
        flow_graph = {}
        for flow in data_flows:
            from_var = flow.get('from', '').strip()
            to_var = flow.get('to', '').strip()
            
            if from_var and to_var:
                if from_var not in flow_graph:
                    flow_graph[from_var] = set()
                flow_graph[from_var].add(to_var)
        
        for call in calls:
            pkg = call.get('package', '')
            fn = call.get('function', '')
            args = call.get('args', [])
            line = call.get('line', 0)
            
            if (pkg, fn) not in dangerous_sinks:
                continue
            
            for arg in args:
                arg_var = CommonPatterns.extract_base_var(arg)
                
                if arg_var and arg_var in tainted_vars:
                    flow_path = self._trace_data_flow_path(arg_var, flow_graph, actual_user_input_sources or tainted_vars)
                    
                    originates_from_user = False
                    if actual_user_input_sources:
                        for source in actual_user_input_sources:
                            if source in arg_var or source in flow_path or arg_var in flow_graph.get(source, set()):
                                originates_from_user = True
                                break
                    else:
                        user_input_indicators = ['req', 'request', 'query', 'body', 'params', 'args.', 'argv', 'user']
                        if any(indicator in arg_var.lower() for indicator in user_input_indicators):
                            originates_from_user = True
                        elif 'input' in arg_var.lower() and ('args' in arg_var.lower() or 'req' in arg_var.lower() or 'body' in arg_var.lower()):
                            originates_from_user = True
                                        
                    if not originates_from_user and not any(indicator in arg_var.lower() for indicator in ['input', 'user', 'req', 'args']):
                        continue
                    
                    severity = "medium"
                    if (pkg, fn) in self.critical_sinks:
                        severity = "critical"
                    elif (pkg, fn) in self.high_sinks:
                        severity = "high"
                    elif (pkg, fn) in self.low_sinks:
                        severity = "low"
                    
                    message = f"Path Traversal: User input '{arg_var}' reaches {pkg}.{fn}()"
                    if flow_path:
                        message += f" (via {flow_path})"
                    
                    data_flow_findings.append({
                        'severity': severity,
                        'message': message,
                        'line': line,
                        'tainted_var': arg_var,
                        'sink': f"{pkg}.{fn}",
                        'flow_path': flow_path
                    })
        
        return data_flow_findings
    
    def _trace_data_flow_path(self, var_name: str, flow_graph: Dict[str, Set[str]], 
                              tainted_vars: Set[str], max_depth: int = 5) -> str:
        if max_depth <= 0:
            return ""
        
        path = []
        visited = set()
        
        def trace(current_var: str, depth: int) -> bool:
            if depth > max_depth or current_var in visited:
                return False
            
            visited.add(current_var)
            
            if current_var in tainted_vars:
                path.append(current_var)
                return True
            
            for from_var, to_vars in flow_graph.items():
                if current_var in to_vars:
                    if trace(from_var, depth + 1):
                        path.append(f"{from_var} -> {current_var}")
                        return True
            
            return False
        
        trace(var_name, 0)
        return " -> ".join(reversed(path)) if path else ""
    
    def _is_connected_to_taint_source(self, var_name: str, taint_sources: Set[str], 
                                      data_flows: List[Dict], max_depth: int = 5) -> bool:
        if max_depth <= 0:
            return False
        
        if var_name in taint_sources:
            return True
        
        for flow in data_flows:
            to_var = flow.get('to', '').strip()
            if to_var == var_name:
                from_var = flow.get('from', '').strip()
                if self._is_connected_to_taint_source(from_var, taint_sources, data_flows, max_depth - 1):
                    return True
        
        return False
    
    def check(self, calls: List[Dict], tainted_vars: Set[str],
              lines: List[str], file_path: str, ast_result: Dict[str, Any] = None, 
              taint_result: Dict[str, Any] = None, cfg: Any = None) -> List[Finding]:
        findings = []
        
        if not ast_result:
            return findings
        
        data_flows = ast_result.get('data_flows', [])
        taint_sources = {s.get('var_name') for s in ast_result.get('taint_sources', [])}
        
        if taint_result:
            all_tainted = set(taint_result.get('all_tainted', []))
        else:
            all_tainted = set()
            taint_result = {'all_tainted': [], 'initial_tainted': []}
        
        data_flow_findings = self._analyze_data_flow(
            ast_result, taint_result, calls, self.dangerous_sinks
        )
        
        for call in calls:
            pkg = call.get('package', '')
            fn = call.get('function', '')
            args = call.get('args', [])
            line = call.get('line', 0)
            if (pkg, fn) not in self.dangerous_sinks:
                continue
            line_content = lines[line-1] if 0 < line <= len(lines) else ""
            
            context = self._get_context_info(line_content, args, file_path)
            is_vulnerable = False
            confidence = CONFIDENCE_LEVELS['MEDIUM']
            severity = "low"
            message = f"Path traversal vulnerability in {pkg}.{fn}()"
            if (pkg, fn) in self.critical_sinks:
                severity = "critical"
                message = f"Critical: File deletion/modification via {pkg}.{fn}() - system damage possible"
            elif (pkg, fn) in self.high_sinks:
                severity = "high"
                message = f"Path traversal: Unauthorized file write via {pkg}.{fn}()"
            elif (pkg, fn) in self.medium_sinks:
                severity = "medium"
                message = f"Path traversal: Sensitive file read via {pkg}.{fn}()"
            elif (pkg, fn) in self.low_sinks:
                severity = "low"
                message = f"Path traversal: Directory access via {pkg}.{fn}()"
            data_flow_finding = next(
                (f for f in data_flow_findings if f['line'] == line and f['sink'] == f"{pkg}.{fn}"), 
                None
            )
            
            tainted_found = False
            if data_flow_finding:
                is_vulnerable = True
                tainted_found = True
                severity = data_flow_finding['severity']
                message = data_flow_finding['message']
                confidence = CONFIDENCE_LEVELS['CRITICAL']
                if severity == "critical":
                    confidence = CONFIDENCE_LEVELS['CRITICAL']
            else:
                tainted_found = False
                base_var = None
                actual_user_input_sources = set()
                
                for source in ast_result.get('taint_sources', []):
                    var_name = source.get('var_name', '')
                    source_type = source.get('source_type', '')
                    if source_type in ['req_body', 'req_query', 'req_params', 'process_argv', 'tool_args']:
                        actual_user_input_sources.add(var_name)
                
                for arg in args:
                    arg_clean = CommonPatterns.extract_base_var(arg)
                    
                    if arg_clean in all_tainted:
                        if data_flows:
                            found_flow = False
                            for flow in data_flows:
                                from_var = flow.get('from', '').strip()
                                to_var = flow.get('to', '').strip()
                                if to_var == arg_clean and from_var in taint_sources:
                                    found_flow = True
                                    break
                                if to_var == arg_clean:
                                    if self._is_connected_to_taint_source(from_var, taint_sources, data_flows):
                                        found_flow = True
                                        break
                            if found_flow:
                                tainted_found = True
                                base_var = arg_clean
                                break
                        elif arg_clean in taint_sources:
                            tainted_found = True
                            base_var = arg_clean
                            break
                        elif data_flows:
                            for flow in data_flows:
                                to_var = flow.get('to', '').strip()
                                if to_var == arg_clean:
                                    from_var = flow.get('from', '').strip()
                                    if from_var in taint_sources:
                                        tainted_found = True
                                        base_var = arg_clean
                                        break
                            if tainted_found:
                                break
                
                if not tainted_found:
                    continue
                
                if not base_var:
                    for arg in args:
                        base_var = CommonPatterns.extract_base_var(arg)
                        break
                
                originates_from_user = False
                if actual_user_input_sources:
                    for source in actual_user_input_sources:
                        if source in base_var or base_var == source:
                            originates_from_user = True
                            break
                else:
                    user_input_indicators = ['req', 'request', 'query', 'body', 'params', 'args.', 'argv', 'user']
                    if any(indicator in base_var.lower() for indicator in user_input_indicators):
                        originates_from_user = True
                    elif 'input' in base_var.lower() and ('args' in base_var.lower() or 'req' in base_var.lower() or 'body' in base_var.lower()):
                        originates_from_user = True
                
                has_path_validation = False
                if line_content:
                    validation_patterns = [
                        r'path\.normalize\(',
                        r'path\.resolve\(',
                        r'path\.join\(',
                        r'\.replace\(.*\.\.',
                        r'\.includes\(.*\.\.',
                        r'\.startsWith\(.*\.\.',
                        r'\.indexOf\(.*\.\.',
                        r'\.substring\(.*\.\.',
                        r'path\.relative\(',
                        r'path\.basename\(',
                        r'path\.dirname\(',
                    ]
                    for pattern in validation_patterns:
                        if re.search(pattern, line_content, re.IGNORECASE):
                            if base_var.lower() in line_content.lower():
                                has_path_validation = True
                                break
                
                if not has_path_validation and lines and line > 1:
                    start_line = max(0, line - 10)
                    context_lines = '\n'.join(lines[start_line:line-1])
                    for pattern in validation_patterns:
                        if re.search(pattern, context_lines, re.IGNORECASE):
                            if base_var.lower() in context_lines.lower():
                                has_path_validation = True
                                break
                
                has_normalize, has_resolve, has_expand_home = self._has_complete_path_validation(lines, line, base_var)
                has_extension_check = self._has_extension_validation(lines, line, base_var)
                has_allowed_dir_check = self._has_allowed_directory_validation(lines, line, base_var)
                
                if not originates_from_user and not any(indicator in base_var.lower() for indicator in ['input', 'user', 'req', 'args']):
                    continue
                
                is_vulnerable = True
                tainted_found = True
                
                incomplete_validation_issues = []
                if not has_normalize:
                    incomplete_validation_issues.append("missing path.normalize()")
                if not has_resolve:
                    incomplete_validation_issues.append("missing path.resolve()")
                if not has_expand_home:
                    incomplete_validation_issues.append("missing home directory expansion check (~)")
                if not has_extension_check:
                    incomplete_validation_issues.append("missing file extension validation")
                if not has_allowed_dir_check:
                    incomplete_validation_issues.append("missing allowed directory validation")
                
                if has_path_validation and originates_from_user:
                    if incomplete_validation_issues:
                        severity = "high"
                        issues_str = ", ".join(incomplete_validation_issues)
                        message = f"Path Traversal (incomplete validation): User input '{base_var}' reaches {pkg}.{fn}() - validation present but incomplete: {issues_str}"
                        confidence = CONFIDENCE_LEVELS['HIGH']
                    else:
                        if (pkg, fn) in self.critical_sinks:
                            severity = "high"
                            message = f"Path Traversal (with validation): User input '{base_var}' reaches {pkg}.{fn}() - path validation present but may be incomplete"
                            confidence = CONFIDENCE_LEVELS['MEDIUM']
                        elif (pkg, fn) in self.high_sinks:
                            severity = "medium"
                            message = f"Path Traversal (with validation): User input '{base_var}' reaches {pkg}.{fn}() - path validation present but may be incomplete"
                            confidence = CONFIDENCE_LEVELS['MEDIUM']
                        else:
                            confidence = CONFIDENCE_LEVELS['MEDIUM']
                elif incomplete_validation_issues and originates_from_user:
                    issues_str = ", ".join(incomplete_validation_issues)
                    severity = "high"
                    message = f"Path Traversal (missing validation): User input '{base_var}' reaches {pkg}.{fn}() - missing validations: {issues_str}"
                    confidence = CONFIDENCE_LEVELS['CRITICAL']
                else:
                    confidence = CONFIDENCE_LEVELS['CRITICAL']
                    if (pkg, fn) in self.critical_sinks:
                        confidence = CONFIDENCE_LEVELS['CRITICAL']
                        message = f"Critical: User-controlled path (via {base_var}) in {pkg}.{fn}() - file deletion possible"
                    else:
                        message = f"Path traversal: {pkg}.{fn}() - verify input sanitization"
            
            if not tainted_found:
                continue
            
            is_completely_safe = (
                (context['is_safe_path_pattern'] or context['is_literal_path']) and
                not context['has_safe_comment'] and
                not context['is_test_file']
            )
            
            if is_completely_safe:
                continue
            
            if context['is_test_file']:
                severity = "info"
                message = f"Test file: {pkg}.{fn}() - in test environment"
                confidence = CONFIDENCE_LEVELS['LOW']
            
            if context['has_safe_comment']:
                severity = "info"
                message = f"Developer-marked safe: {pkg}.{fn}() - reviewed by developer"
                confidence = CONFIDENCE_LEVELS['LOW']
            
            if context['is_safe_path_pattern'] and not context['is_test_file'] and not context['has_safe_comment']:
                severity, multiplier = CommonPatterns.adjust_severity_with_context(severity, 'safe_path')
                if severity == "info":
                    continue
                message += " (safe path pattern)"
                confidence *= multiplier
            
            if context['is_literal_path'] and not context['is_test_file'] and not context['has_safe_comment']:
                severity, multiplier = CommonPatterns.adjust_severity_with_context(severity, 'literal_path')
                if severity == "info":
                    continue
                message += " (literal path)"
                confidence *= multiplier
            
            if is_vulnerable:
                pattern_type = "data_flow_analysis" if data_flow_finding else "ast_analysis"
                findings.append(Finding(
                    rule_id="typescript/path-traversal",
                    severity=severity,
                    message=message,
                    cwe=self.get_cwe(),
                    file=file_path,
                    line=line,
                    column=call.get('column', 0),
                    code_snippet=lines[line-1] if 0 < line <= len(lines) else "",
                    pattern_type=pattern_type,
                    pattern=f"{pkg}.{fn}",
                    confidence=confidence
                ))
        return findings
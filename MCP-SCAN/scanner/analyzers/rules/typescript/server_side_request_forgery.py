import re
from typing import List, Dict, Set, Any
from scanner.analyzers.common.scanner import Finding, CommonPatterns, ConfigLoader
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS

class SSRFDetector:
    def __init__(self):
        self.config = ConfigLoader.get_instance()
        
        self.metadata_urls = [
            '169.254.169.254',
            '169.254.170.2',
            'metadata.google.internal',
            '100.100.100.200',
        ]
        self.high_sinks = [
            ('axios', 'get'), ('', 'axios'),
            ('axios', 'post'),
            ('axios', 'put'),
            ('axios', 'delete'),
            ('axios', 'request'),
            ('fetch', ''), ('', 'fetch'),
            ('http', 'get'),
            ('http', 'request'),
            ('https', 'get'),
            ('https', 'request'),
            ('request', 'get'),
            ('request', 'post'),
            ('got', 'get'),
            ('got', 'post'),
            ('superagent', 'get'),
            ('superagent', 'post'),
        ]
        self.medium_sinks = [
            ('axios', 'create'),
            ('http', 'Agent'),
            ('https', 'Agent'),
        ]
        self.low_sinks = [
            ('net', 'connect'),
            ('net', 'createConnection'),
            ('dgram', 'createSocket'),
        ]
        self.dangerous_sinks = (
            self.high_sinks + 
            self.medium_sinks + 
            self.low_sinks
        )
        self.private_networks = [
            '127.0.0.1',
            'localhost',
            '10.',
            '172.16.',
            '192.168.',
            '0.0.0.0',
            '::1',
        ]
        
        trusted_patterns = self.config.get_safe_url_patterns('typescript')
        self.trusted_url_patterns = trusted_patterns
        self.trusted_url_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.trusted_url_patterns]
        
        custom_comments = self.config.get_safe_comment_patterns('typescript')
        self.safe_comment_patterns = CommonPatterns.SAFE_COMMENT_PATTERNS + custom_comments
        self.safe_comment_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.safe_comment_patterns]
        
        self.script_patterns_compiled = [
            re.compile(r'/scripts/'),
            re.compile(r'/utils/'),
        ]
        
        self.api_patterns_compiled = [
            re.compile(r'api\.'),
            re.compile(r'\.json'),
            re.compile(r'openapi'),
            re.compile(r'schema'),
            re.compile(r'docs'),
        ]
        self.template_patterns_compiled = [
            re.compile(r'`[^`]*\$\{[^}]+\}[^`]*`', re.IGNORECASE),
            re.compile(r'`[^`]*\$\{[^}]+\.[^}]+\}[^`]*`', re.IGNORECASE),
        ]
        self.template_var_patterns_compiled = [re.compile(r'\$\{([^}]+)\}', re.IGNORECASE)]
        self.user_input_patterns_compiled = [
            re.compile(r'url', re.IGNORECASE),
            re.compile(r'endpoint', re.IGNORECASE),
            re.compile(r'path', re.IGNORECASE),
            re.compile(r'uri', re.IGNORECASE),
            re.compile(r'link', re.IGNORECASE),
            re.compile(r'href', re.IGNORECASE),
            re.compile(r'src', re.IGNORECASE),
            re.compile(r'action', re.IGNORECASE),
            re.compile(r'redirect', re.IGNORECASE),
            re.compile(r'target', re.IGNORECASE),
            re.compile(r'destination', re.IGNORECASE),
        ]
        self.var_patterns_compiled = [
            re.compile(r'\b(\w+)\s*\+'),
            re.compile(r'\+\s*(\w+)\b'),
        ]
        
        self.external_service_api_patterns = [
            re.compile(r'slack\.com/api', re.IGNORECASE),
            re.compile(r'discord\.com/api', re.IGNORECASE),
            re.compile(r'teams\.microsoft\.com/api', re.IGNORECASE),
            re.compile(r'api\.slack\.com', re.IGNORECASE),
            re.compile(r'api\.discord\.com', re.IGNORECASE),
            re.compile(r'graph\.microsoft\.com', re.IGNORECASE),
            re.compile(r'api\.github\.com', re.IGNORECASE),
            re.compile(r'api\.gitlab\.com', re.IGNORECASE),
            re.compile(r'api\.atlassian\.com', re.IGNORECASE),
        ]
        
        self.auto_request_trigger_patterns = [
            re.compile(r'unfurl', re.IGNORECASE),
            re.compile(r'auto.*fetch', re.IGNORECASE),
            re.compile(r'auto.*request', re.IGNORECASE),
            re.compile(r'auto.*load', re.IGNORECASE),
            re.compile(r'preview', re.IGNORECASE),
            re.compile(r'expand', re.IGNORECASE),
        ]
        
        self.body_user_input_fields = [
            'text', 'message', 'content', 'body', 'data', 'payload',
            'input', 'userInput', 'user_input', 'value', 'url', 'link',
            'href', 'src', 'uri', 'endpoint', 'path',
        ]
    
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
    
    def get_name(self) -> str:
        return "ssrf"
    def get_cwe(self) -> str:
        return "CWE-918"
    def _has_url_validation(self, lines: List[str], line: int, file_path: str = "") -> bool:
        if not lines or line < 1 or line > len(lines):
            return False
        
        start = max(0, line - 30)
        end = line
        context = '\n'.join(lines[start:end])
        
        validation_patterns = [
            r'new\s+URL\s*\(',
            r'parsedUrl\s*=',
            r'parsed.*URL',
            r'validatedArgs\.url',
            r'\.protocol',
            r'\.hostname',
            r'is_ip_private',
            r'isIpPrivate',
            r'private.*network',
            r'localhost.*check',
            r'127\.0\.0\.1',
            r'metadata.*check',
            r'169\.254\.169\.254',
            r'Only\s+http.*https',
            r'http.*https.*schemes',
            r'schemes\s+are\s+allowed',
            r'potentially\s+dangerous',
            r'throw\s+new\s+Error.*Only',
            r'throw\s+new\s+Error.*http',
            r'throw\s+new\s+Error.*https',
            r'throw\s+new\s+Error.*schemes',
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        if file_path:
            from pathlib import Path
            file_name = Path(file_path).name.lower()
            parent_dir = Path(file_path).parent

            if 'server' not in file_name and ('markdownify' in file_name or 'utils' in file_name or 'helper' in file_name):
                server_files = [
                    'server.ts', 'server.js', 'index.ts', 'index.js',
                    'app.ts', 'app.js', 'main.ts', 'main.js',
                    '*server*.ts', '*server*.js'
                ]
                for pattern in server_files:
                    if '*' in pattern:
                        pattern = pattern.replace('*', '')
                    potential_server = parent_dir / pattern
                    if potential_server.exists():
                        try:
                            with open(potential_server, 'r', encoding='utf-8', errors='ignore') as f:
                                server_content = f.read()
                                for val_pattern in validation_patterns:
                                    if re.search(val_pattern, server_content, re.IGNORECASE):
                                        return True
                        except (IOError, OSError, PermissionError):
                            pass
            
            if parent_dir.exists():
                for server_file in parent_dir.glob('*server*.ts'):
                    if server_file.exists() and server_file.name != Path(file_path).name:
                        try:
                            with open(server_file, 'r', encoding='utf-8', errors='ignore') as f:
                                server_content = f.read()
                                for val_pattern in validation_patterns:
                                    if re.search(val_pattern, server_content, re.IGNORECASE):
                                        return True
                        except (IOError, OSError, PermissionError):
                            pass
        
        return False
    
    def _has_complete_url_validation(self, lines: List[str], line: int, file_path: str = "") -> tuple[bool, bool, bool]:
        if not lines or line < 1 or line > len(lines):
            return False, False, False
        
        start = max(0, line - 50)
        end = min(len(lines), line + 10)
        context = '\n'.join(lines[start:end])
        
        has_protocol_check = False
        has_private_ip_check = False
        has_metadata_check = False
        
        protocol_patterns = [
            r'\.protocol\s*[!=]',
            r'parsedUrl\.protocol',
            r'Only\s+http.*https',
            r'http.*https.*schemes',
            r'schemes\s+are\s+allowed',
            r'!\["http:",\s*"https:"\]\.includes\(.*\.protocol\)',
            r'\["http:",\s*"https:"\]\.includes\(.*\.protocol\)',
            r'\.protocol\s*===?\s*["\']http',
            r'\.protocol\s*!==?\s*["\']http',
        ]
        
        private_ip_patterns = [
            r'is_ip_private\s*\(',
            r'isIpPrivate\s*\(',
            r'private.*ip',
            r'private.*network',
            r'localhost.*check',
            r'127\.0\.0\.1',
            r'10\.',
            r'172\.16\.',
            r'192\.168\.',
            r'potentially\s+dangerous',
            r'private-ip',
        ]
        
        metadata_patterns = [
            r'169\.254\.169\.254',
            r'metadata.*check',
            r'metadata\.google\.internal',
            r'169\.254\.170\.2',
        ]
        
        for pattern in protocol_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                has_protocol_check = True
                break
        
        for pattern in private_ip_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                has_private_ip_check = True
                break
        
        for pattern in metadata_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                has_metadata_check = True
                break
        
        return has_protocol_check, has_private_ip_check, has_metadata_check
    
    def _check_url_parsing_validation(self, lines: List[str], line: int, file_path: str = "") -> tuple[bool, bool]:
        if not lines or line < 1 or line > len(lines):
            return False, False
        
        start = max(0, line - 50)
        end = min(len(lines), line + 10)
        context_lines = lines[start:end]
        context = '\n'.join(context_lines)
        
        has_url_parsing = False
        has_validation_after_parsing = False
        
        url_parsing_patterns = [
            r'new\s+URL\s*\(',
            r'parsedUrl\s*=\s*new\s+URL',
            r'const\s+parsedUrl\s*=\s*new\s+URL',
            r'let\s+parsedUrl\s*=\s*new\s+URL',
            r'var\s+parsedUrl\s*=\s*new\s+URL',
        ]
        
        for pattern in url_parsing_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                has_url_parsing = True
                break
        
        if not has_url_parsing:
            return False, False
        
        parsing_line_idx = -1
        for i, ctx_line in enumerate(context_lines):
            if re.search(r'new\s+URL\s*\(', ctx_line, re.IGNORECASE):
                parsing_line_idx = start + i
                break
        
        if parsing_line_idx == -1:
            return True, False
        
        validation_after_parsing = False
        for i in range(parsing_line_idx + 1, min(len(lines), parsing_line_idx + 20)):
            check_line = lines[i] if i < len(lines) else ""
            
            protocol_check = re.search(r'parsedUrl\.protocol', check_line, re.IGNORECASE)
            hostname_check = re.search(r'parsedUrl\.hostname', check_line, re.IGNORECASE)
            private_check = re.search(r'is_ip_private|isIpPrivate|private.*ip|private.*network', check_line, re.IGNORECASE)
            throw_check = re.search(r'throw\s+new\s+Error', check_line, re.IGNORECASE)
            
            if (protocol_check or hostname_check or private_check) and throw_check:
                validation_after_parsing = True
                break
            
            if protocol_check and (hostname_check or private_check):
                validation_after_parsing = True
                break
        
        return True, validation_after_parsing
    
    def _has_redirect_protection(self, lines: List[str], line: int) -> bool:
        if not lines or line < 1 or line > len(lines):
            return False
        
        start = max(0, line - 10)
        end = min(len(lines), line + 10)
        context = '\n'.join(lines[start:end])
        
        redirect_patterns = [
            r'redirect\s*:\s*[\'"]manual[\'"]',
            r'redirect\s*:\s*[\'"]error[\'"]',
            r'response\.redirected',
            r'response\.url',
            r'check.*redirect',
            r'validate.*redirect',
            r'is_ip_private.*response',
            r'parsedUrl.*hostname.*response',
            r'new URL\(.*response',
            r'if\s*\(.*response\.redirected',
            r'response\.headers\.get\([\'"]location[\'"]',
        ]
        
        for pattern in redirect_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _is_safe_usage(self, line_content: str, args: List[str], file_path: str, lines: List[str] = None) -> bool:
        if '.test.' in file_path or '.spec.' in file_path or '/test/' in file_path or '/__tests__/' in file_path:
            return True
        for pattern in self.safe_comment_patterns_compiled:
            if pattern.search(line_content):
                return True
        for pattern in self.trusted_url_patterns_compiled:
            if pattern.search(line_content):
                return True
        if args and (args[0].startswith('"') or args[0].startswith("'") or args[0].startswith('`')):
            url_value = args[0].strip('"`\'')
            if url_value.startswith('https://'):
                is_metadata = any(meta in url_value for meta in self.metadata_urls)
                if not is_metadata:
                    is_private = any(priv in url_value for priv in self.private_networks)
                    if not is_private:
                        return True
        if 'process.env.' in line_content or 'config.' in line_content:
            return True
        
        for pattern in self.script_patterns_compiled:
            if pattern.search(file_path):
                return True
        
        for pattern in self.api_patterns_compiled:
            if pattern.search(line_content):
                return True
        
        if '`' in line_content:
            for pattern in self.template_patterns_compiled:
                matches = pattern.findall(line_content)
                for match in matches:
                    for var_pattern in self.template_var_patterns_compiled:
                        var_matches = var_pattern.findall(match)
                        for var_expr in var_matches:
                            var_expr = var_expr.strip()
                            for user_pattern in self.user_input_patterns_compiled:
                                if user_pattern.search(var_expr):
                                    return False
                            if '.' in var_expr:
                                base_var = CommonPatterns.extract_base_var(var_expr)
                                for user_pattern in self.user_input_patterns_compiled:
                                    if user_pattern.search(base_var):
                                        return False
        
        if '+' in line_content:
            for pattern in self.var_patterns_compiled:
                matches = pattern.findall(line_content)
                for var_name in matches:
                    for user_pattern in self.user_input_patterns_compiled:
                        if user_pattern.search(var_name):
                            return False
        
        return False
    
    def _analyze_data_flow(self, ast_result: Dict[str, Any], taint_result: Dict[str, Any], 
                           calls: List[Dict], dangerous_sinks: List[tuple]) -> List[Dict]:
        data_flow_findings = []
        
        if not ast_result or not taint_result:
            return data_flow_findings
        
        data_flows = ast_result.get('data_flows', [])
        tainted_vars = set(taint_result.get('all_tainted', []))
        
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
            
            is_dangerous = False
            if pkg:
                is_dangerous = (pkg, fn) in dangerous_sinks
            else:
                is_dangerous = fn in ['fetch']
            
            if not is_dangerous:
                continue
            
            for arg in args:
                arg_var = CommonPatterns.extract_base_var(arg)
                
                if arg_var and arg_var in tainted_vars:
                    flow_path = self._trace_data_flow_path(arg_var, flow_graph, tainted_vars)
                    
                    severity = "medium"
                    if (pkg, fn) in self.high_sinks or fn == 'fetch':
                        severity = "high"
                    elif (pkg, fn) in self.medium_sinks:
                        severity = "medium"
                    elif (pkg, fn) in self.low_sinks:
                        severity = "low"
                    
                    message = f"SSRF: User-controlled URL '{arg_var}' reaches {pkg}.{fn}()" if pkg else f"SSRF: User-controlled URL '{arg_var}' reaches {fn}()"
                    if flow_path:
                        message += f" (via {flow_path})"
                    
                    data_flow_findings.append({
                        'severity': severity,
                        'message': message,
                        'line': line,
                        'tainted_var': arg_var,
                        'sink': f"{pkg}.{fn}" if pkg else fn,
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
    
    def check(self, calls: List[Dict], tainted_vars: Set[str],
              lines: List[str], file_path: str, ast_result: Dict[str, Any] = None, 
              taint_result: Dict[str, Any] = None, cfg: Any = None) -> List[Finding]:
        findings = []
        
        if not ast_result:
            return findings
        
        base64_parse_findings = self._check_base64_json_parse_ssrf(lines, file_path, ast_result, taint_result)
        findings.extend(base64_parse_findings)
        
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
            line_content = lines[line-1] if 0 < line <= len(lines) else ""
            
            is_dangerous = False
            if pkg:
                is_dangerous = (pkg, fn) in self.dangerous_sinks
            else:
                is_dangerous = fn in ['fetch'] or fn.lower() == 'fetch'
            
            if not is_dangerous and line_content:
                if 'fetch(' in line_content or 'await fetch' in line_content:
                    if re.search(r'\bfetch\s*\(', line_content, re.IGNORECASE):
                        is_dangerous = True
                        fn = 'fetch'
            
            if not is_dangerous:
                continue
            
            has_url_validation = self._has_url_validation(lines, line, file_path)
            has_redirect_protection = self._has_redirect_protection(lines, line)
            redirect_vulnerable = has_url_validation and not has_redirect_protection and fn == 'fetch'
            
            has_protocol_check, has_private_ip_check, has_metadata_check = self._has_complete_url_validation(lines, line, file_path)
            has_url_parsing, has_validation_after_parsing = self._check_url_parsing_validation(lines, line, file_path)
            
            if has_url_parsing and not has_validation_after_parsing:
                findings.append(Finding(
                    rule_id="typescript/ssrf",
                    severity="high",
                    message=f"SSRF: URL parsing detected (new URL()) but no validation found after parsing. Missing protocol/hostname/private IP validation.",
                    cwe=self.get_cwe(),
                    file=file_path,
                    line=line,
                    column=call.get('column', 0),
                    code_snippet=line_content,
                    pattern_type="missing_url_validation",
                    pattern=fn,
                    confidence=CONFIDENCE_LEVELS['HIGH']
                ))
            
            if has_protocol_check and not has_private_ip_check:
                findings.append(Finding(
                    rule_id="typescript/ssrf",
                    severity="high",
                    message=f"SSRF: Incomplete URL validation - protocol check exists but private IP check is missing. Private network access may be possible.",
                    cwe=self.get_cwe(),
                    file=file_path,
                    line=line,
                    column=call.get('column', 0),
                    code_snippet=line_content,
                    pattern_type="incomplete_validation",
                    pattern=fn,
                    confidence=CONFIDENCE_LEVELS['CRITICAL']
                ))
            
            if redirect_vulnerable:
                findings.append(Finding(
                    rule_id="typescript/ssrf",
                    severity="high",
                    message=f"SSRF via redirect: URL validation exists but fetch() automatically follows redirects without validation. Redirect target may be private/metadata IP.",
                    cwe=self.get_cwe(),
                    file=file_path,
                    line=line,
                    column=call.get('column', 0),
                    code_snippet=line_content,
                    pattern_type="redirect_vulnerability",
                    pattern=fn,
                    confidence=CONFIDENCE_LEVELS['CRITICAL']
                ))
                continue
            
            if self._is_safe_usage(line_content, args, file_path, lines):
                continue
            
            is_vulnerable = False
            confidence = CONFIDENCE_LEVELS['MEDIUM']
            severity = "low"
            message = f"SSRF vulnerability in {pkg}.{fn}()" if pkg else f"SSRF vulnerability in {fn}()"
            
            if (pkg, fn) in self.high_sinks or fn == 'fetch':
                severity = "high"
                message = f"SSRF: User-controlled URL in {pkg}.{fn}()" if pkg else f"SSRF: User-controlled URL in {fn}()"
            elif (pkg, fn) in self.medium_sinks:
                severity = "medium"
                message = f"Potential SSRF: HTTP request with user input in {pkg}.{fn}()"
            elif (pkg, fn) in self.low_sinks:
                severity = "low"
                message = f"Potential SSRF: Network connection in {pkg}.{fn}()"
            has_metadata_url = False
            has_private_network = False
            for arg in args:
                if any(metadata in arg for metadata in self.metadata_urls):
                    has_metadata_url = True
                    is_vulnerable = True
                    confidence = CONFIDENCE_LEVELS['CRITICAL']
                    severity = "critical"
                    message = f"Critical: Cloud metadata service access in {pkg}.{fn}() - credential theft possible" if pkg else f"Critical: Cloud metadata service access in {fn}()"
                    break
                if any(private in arg for private in self.private_networks):
                    has_private_network = True
                    is_vulnerable = True
                    confidence = CONFIDENCE_LEVELS['CRITICAL']
                    if severity in ["medium", "low"]:
                        severity = CommonPatterns.adjust_severity_down(severity, -1)
                        message = f"SSRF to internal network via {pkg}.{fn}()" if pkg else f"SSRF to internal network via {fn}()"
            data_flow_finding = next(
                (f for f in data_flow_findings 
                 if f['line'] == line and f['sink'] == (f"{pkg}.{fn}" if pkg else fn)), 
                None
            )
            
            tainted_found = False
            if data_flow_finding:
                is_vulnerable = True
                tainted_found = True
                severity = data_flow_finding['severity']
                message = data_flow_finding['message']
                confidence = CONFIDENCE_LEVELS['CRITICAL']
                
                if any(metadata in str(args) for metadata in self.metadata_urls):
                    severity = "critical"
                    confidence = CONFIDENCE_LEVELS['CRITICAL']
                    message = f"Critical: User-controlled URL to metadata service in {pkg}.{fn}()" if pkg else f"Critical: User-controlled URL to metadata service in {fn}()"
                elif any(private in str(args) for private in self.private_networks):
                    if severity in ["medium", "low"]:
                        severity = CommonPatterns.adjust_severity_down(severity, -1)
                        message = f"SSRF to internal network via {pkg}.{fn}()" if pkg else f"SSRF to internal network via {fn}()"
            elif not is_vulnerable:
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
                                is_vulnerable = True
                                tainted_found = True
                                confidence = CONFIDENCE_LEVELS['CRITICAL']
                                base_var = arg_clean
                                if has_metadata_url:
                                    severity = "critical"
                                    confidence = CONFIDENCE_LEVELS['CRITICAL']
                                    if base_var != arg:
                                        message = f"Critical: User-controlled URL (via {base_var}) to metadata service"
                                elif (pkg, fn) in self.high_sinks or fn == 'fetch':
                                    severity = "high"
                                    if base_var != arg:
                                        message = f"SSRF: User-controlled URL (via {base_var}) in {pkg}.{fn}()" if pkg else f"SSRF: User-controlled URL (via {base_var}) in {fn}()"
                                elif (pkg, fn) in self.medium_sinks:
                                    severity = "medium"
                                break
                        elif arg_clean in taint_sources:
                            is_vulnerable = True
                            tainted_found = True
                            confidence = CONFIDENCE_LEVELS['MEDIUM']
                            base_var = arg_clean
                            if (pkg, fn) in self.high_sinks or fn == 'fetch':
                                severity = "high"
                                message = f"SSRF: User input ({base_var}) in {pkg}.{fn}() - AST based detection" if pkg else f"SSRF: User input ({base_var}) in {fn}() - AST based detection"
                            elif (pkg, fn) in self.medium_sinks:
                                severity = "medium"
                                message = f"Potential SSRF: User input ({base_var}) in {pkg}.{fn}() - AST based detection"
                            break
                        elif data_flows:
                            for flow in data_flows:
                                to_var = flow.get('to', '').strip()
                                if to_var == arg_clean:
                                    from_var = flow.get('from', '').strip()
                                    if from_var in taint_sources:
                                        is_vulnerable = True
                                        tainted_found = True
                                        confidence = CONFIDENCE_LEVELS['MEDIUM']
                                        base_var = arg_clean
                                        if (pkg, fn) in self.high_sinks or fn == 'fetch':
                                            severity = "high"
                                            message = f"SSRF: Data flow from {from_var} to {pkg}.{fn}() - AST based detection" if pkg else f"SSRF: Data flow from {from_var} to {fn}() - AST based detection"
                                        elif (pkg, fn) in self.medium_sinks:
                                            severity = "medium"
                                            message = f"Potential SSRF: Data flow from {from_var} to {pkg}.{fn}() - AST based detection"
                                        break
                            if tainted_found:
                                break
            
            if not tainted_found and not is_vulnerable:
                continue
            
            if is_vulnerable:
                pattern_type = "data_flow_analysis" if data_flow_finding else "ast_analysis"
                findings.append(Finding(
                    rule_id="typescript/ssrf",
                    severity=severity,
                    message=message,
                    cwe=self.get_cwe(),
                    file=file_path,
                    line=line,
                    column=call.get('column', 0),
                    code_snippet=lines[line-1] if 0 < line <= len(lines) else "",
                    pattern_type=pattern_type,
                    pattern=f"{pkg}.{fn}" if pkg else fn,
                    confidence=confidence
                ))
        
        external_api_findings = self._check_external_service_api_ssrf(calls, tainted_vars, lines, file_path, ast_result, taint_result)
        findings.extend(external_api_findings)
        
        body_input_findings = self._check_body_user_input_ssrf(calls, tainted_vars, lines, file_path, ast_result, taint_result)
        findings.extend(body_input_findings)
        
        return findings
    
    def _check_base64_json_parse_ssrf(self, lines: List[str], file_path: str,
                                     ast_result: Dict[str, Any] = None,
                                     taint_result: Dict[str, Any] = None) -> List[Finding]:
        findings = []
        
        if not ast_result:
            return findings
        
        taint_sources = {s.get('var_name') for s in ast_result.get('taint_sources', [])}
        if taint_result:
            all_tainted = set(taint_result.get('all_tainted', []))
        else:
            all_tainted = set()
        
        data_flows = ast_result.get('data_flows', [])
        
        base64_parse_patterns = [
            r'JSON\.parse\s*\(\s*Buffer\.from\s*\([^,]+,\s*["\']base64["\']\s*\)\.toString\s*\(\)',
            r'JSON\.parse\s*\(\s*atob\s*\(',
            r'JSON\.parse\s*\(\s*Buffer\.from\s*\([^)]+["\']base64',
        ]
        
        config_param_patterns = [
            r'configParam',
            r'config.*param',
            r'config.*base64',
            r'base64.*config',
        ]
        
        url_property_patterns = [
            r'\.apiUrl',
            r'\.api_url',
            r'\.endpoint',
            r'\.url',
            r'\.baseUrl',
            r'\.base_url',
            r'\.callbackUrl',
            r'\.callback_url',
        ]
        
        allowed_check_patterns = [
            r'isAllowedApiUrl',
            r'isAllowedUrl',
            r'allowedUrls\.includes',
            r'allowedUrls\.indexOf',
            r'ALLOWED.*URLS',
            r'whitelist.*url',
        ]
        
        for line_num, line_content in enumerate(lines, 1):
            has_base64_parse = False
            parse_var_name = None
            
            for pattern in base64_parse_patterns:
                if re.search(pattern, line_content, re.IGNORECASE):
                    has_base64_parse = True
                    var_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*JSON\.parse', line_content, re.IGNORECASE)
                    if var_match:
                        parse_var_name = var_match.group(1)
                    else:
                        var_match = re.search(r'(\w+)\s*=\s*JSON\.parse', line_content, re.IGNORECASE)
                        if var_match:
                            parse_var_name = var_match.group(1)
                    break
            
            if not has_base64_parse:
                continue
            
            has_config_param = False
            for pattern in config_param_patterns:
                if re.search(pattern, line_content, re.IGNORECASE):
                    has_config_param = True
                    break
            
            if not has_config_param and not parse_var_name:
                continue
            
            has_user_input = False
            if has_config_param:
                has_user_input = True
            elif parse_var_name:
                if parse_var_name in all_tainted or parse_var_name in taint_sources:
                    has_user_input = True
                else:
                    for taint_source in taint_sources:
                        if taint_source.endswith('.') and parse_var_name.startswith(taint_source):
                            has_user_input = True
                            break
                        if parse_var_name.startswith(taint_source + '.'):
                            has_user_input = True
                            break
                    
                    if not has_user_input:
                        for flow in data_flows:
                            to_var = flow.get('to', '').strip()
                            if to_var == parse_var_name:
                                from_var = flow.get('from', '').strip()
                                if from_var in taint_sources or from_var in all_tainted:
                                    has_user_input = True
                                    break
            
            if not has_user_input:
                continue
            
            url_usage_found = False
            url_var_name = None
            fetch_line = None
            
            for i in range(line_num, min(len(lines), line_num + 50)):
                check_line = lines[i]
                
                for url_pattern in url_property_patterns:
                    if re.search(rf'{re.escape(parse_var_name) if parse_var_name else r"\w+"}{re.escape(url_pattern)}', check_line, re.IGNORECASE):
                        url_usage_found = True
                        var_match = re.search(r'(\w+)\s*=\s*.*' + re.escape(url_pattern), check_line, re.IGNORECASE)
                        if var_match:
                            url_var_name = var_match.group(1)
                        else:
                            url_var_name = parse_var_name + url_pattern
                        break
                
                if url_usage_found:
                    for j in range(i, min(len(lines), i + 20)):
                        fetch_check = lines[j]
                        if re.search(r'\bfetch\s*\(|axios\.(get|post|put|delete|request)\s*\(', fetch_check, re.IGNORECASE):
                            if url_var_name and url_var_name in fetch_check:
                                fetch_line = j + 1
                                break
                            elif parse_var_name and parse_var_name in fetch_check:
                                fetch_line = j + 1
                                break
                    break
            
            if not url_usage_found:
                continue
            
            has_allowed_check = False
            if fetch_line:
                check_start = max(0, line_num - 10)
                check_end = min(len(lines), fetch_line + 5)
                for i in range(check_start, check_end):
                    check_line = lines[i]
                    for allowed_pattern in allowed_check_patterns:
                        if re.search(allowed_pattern, check_line, re.IGNORECASE):
                            if url_var_name and url_var_name in check_line:
                                has_allowed_check = True
                                break
                            elif parse_var_name and parse_var_name in check_line:
                                has_allowed_check = True
                                break
                    if has_allowed_check:
                        break
            
            if not has_allowed_check:
                context_start = max(0, line_num - 3)
                context_end = min(len(lines), (fetch_line if fetch_line else line_num) + 3)
                context_lines = lines[context_start:context_end]
                code_snippet = '\n'.join(context_lines)
                
                message = f"[HIGH] SSRF: Base64-decoded and JSON-parsed user input used in HTTP request without URL validation - Parsed config contains URL property ({url_var_name if url_var_name else 'URL'}) that is used in fetch/axios without allowlist validation - Use isAllowedApiUrl() or similar allowlist check before making requests"
                severity = "high"
                confidence = CONFIDENCE_LEVELS['HIGH']
                
                findings.append(Finding(
                    rule_id="typescript/ssrf",
                    severity=severity,
                    message=message,
                    cwe="CWE-918",
                    file=file_path,
                    line=fetch_line if fetch_line else line_num,
                    column=0,
                    code_snippet=code_snippet,
                    pattern_type="base64_json_parse_ssrf",
                    pattern="base64_json_parse_ssrf",
                    confidence=confidence
                ))
        
        return findings
    
    def _check_external_service_api_ssrf(self, calls: List[Dict], tainted_vars: Set[str],
                                         lines: List[str], file_path: str,
                                         ast_result: Dict[str, Any] = None,
                                         taint_result: Dict[str, Any] = None) -> List[Finding]:
        findings = []
        
        if not ast_result or not taint_result:
            return findings
        
        data_flows = ast_result.get('data_flows', [])
        taint_sources = {s.get('var_name') for s in ast_result.get('taint_sources', [])}
        all_tainted = set(taint_result.get('all_tainted', []))
        
        for call in calls:
            pkg = call.get('package', '')
            fn = call.get('function', '')
            args = call.get('args', [])
            line = call.get('line', 0)
            
            if line < 1 or line > len(lines):
                continue
            
            line_content = lines[line - 1] if line <= len(lines) else ""
            
            is_fetch = False
            if fn == 'fetch' or (not pkg and fn.lower() == 'fetch'):
                is_fetch = True
            elif 'fetch(' in line_content or 'await fetch' in line_content:
                if re.search(r'\bfetch\s*\(', line_content, re.IGNORECASE):
                    is_fetch = True
            
            if not is_fetch:
                continue
            
            is_external_api = False
            external_api_name = None
            for pattern in self.external_service_api_patterns:
                if pattern.search(line_content):
                    is_external_api = True
                    match = pattern.search(line_content)
                    if match:
                        external_api_name = match.group(0)
                    break
            
            if not is_external_api:
                continue
            
            has_user_input_in_body = False
            user_input_vars = []
            
            json_stringify_pattern = re.compile(r'JSON\.stringify\s*\(', re.IGNORECASE)
            if json_stringify_pattern.search(line_content):
                start = max(0, line - 10)
                end = min(len(lines), line + 5)
                context = '\n'.join(lines[start:end])
                
                for field in self.body_user_input_fields:
                    field_pattern = re.compile(rf'\b{re.escape(field)}\s*:', re.IGNORECASE)
                    if field_pattern.search(context):
                        var_pattern = re.compile(rf'{re.escape(field)}\s*:\s*(\w+)', re.IGNORECASE)
                        matches = var_pattern.findall(context)
                        for match in matches:
                            var_name = match.strip()
                            if var_name in all_tainted or var_name in taint_sources:
                                has_user_input_in_body = True
                                user_input_vars.append(f"{field}: {var_name}")
                            else:
                                for taint_source in taint_sources:
                                    if taint_source.endswith('.') and var_name.startswith(taint_source):
                                        has_user_input_in_body = True
                                        user_input_vars.append(f"{field}: {var_name}")
                                        break
                                    if var_name.startswith(taint_source + '.'):
                                        has_user_input_in_body = True
                                        user_input_vars.append(f"{field}: {var_name}")
                                        break
                                
                                if not has_user_input_in_body:
                                    for flow in data_flows:
                                        to_var = flow.get('to', '').strip()
                                        if to_var == var_name:
                                            from_var = flow.get('from', '').strip()
                                            if from_var in taint_sources or from_var in all_tainted:
                                                has_user_input_in_body = True
                                                user_input_vars.append(f"{field}: {var_name}")
                                                break
            
            if has_user_input_in_body:
                user_input_str = ', '.join(user_input_vars[:3])
                if len(user_input_vars) > 3:
                    user_input_str += f', ... (+{len(user_input_vars) - 3} more)'
                
                code_snippet = line_content.strip()[:200]
                
                findings.append(Finding(
                    rule_id="typescript/ssrf",
                    severity="high",
                    message=f"[HIGH] SSRF: External service API call ({external_api_name}) with user input in body ({user_input_str}) - User-controlled data in API request body may trigger automatic requests or expose sensitive information - Validate and sanitize user input before sending to external APIs",
                    cwe="CWE-918",
                    file=file_path,
                    line=line,
                    column=call.get('column', 0),
                    code_snippet=code_snippet,
                    pattern_type="external_service_api_ssrf",
                    pattern=f"fetch({external_api_name})",
                    confidence=CONFIDENCE_LEVELS['HIGH']
                ))
        
        return findings
    
    def _check_body_user_input_ssrf(self, calls: List[Dict], tainted_vars: Set[str],
                                    lines: List[str], file_path: str,
                                    ast_result: Dict[str, Any] = None,
                                    taint_result: Dict[str, Any] = None) -> List[Finding]:
        findings = []
        
        if not ast_result or not taint_result:
            return findings
        
        data_flows = ast_result.get('data_flows', [])
        taint_sources = {s.get('var_name') for s in ast_result.get('taint_sources', [])}
        all_tainted = set(taint_result.get('all_tainted', []))
        
        for call in calls:
            pkg = call.get('package', '')
            fn = call.get('function', '')
            args = call.get('args', [])
            line = call.get('line', 0)
            
            if line < 1 or line > len(lines):
                continue
            
            line_content = lines[line - 1] if line <= len(lines) else ""
            
            is_fetch = False
            if fn == 'fetch' or (not pkg and fn.lower() == 'fetch'):
                is_fetch = True
            elif 'fetch(' in line_content or 'await fetch' in line_content:
                if re.search(r'\bfetch\s*\(', line_content, re.IGNORECASE):
                    is_fetch = True
            
            if not is_fetch:
                continue
            
            json_stringify_pattern = re.compile(r'JSON\.stringify\s*\(', re.IGNORECASE)
            if not json_stringify_pattern.search(line_content):
                continue
            
            start = max(0, line - 15)
            end = min(len(lines), line + 5)
            context_lines = lines[start:end]
            context = '\n'.join(context_lines)
            
            has_user_input_in_body = False
            user_input_vars = []
            body_fields_with_input = []
            
            for field in self.body_user_input_fields:
                field_pattern = re.compile(rf'\b{re.escape(field)}\s*:', re.IGNORECASE)
                if field_pattern.search(context):
                    var_pattern = re.compile(rf'{re.escape(field)}\s*:\s*(\w+)', re.IGNORECASE)
                    matches = var_pattern.findall(context)
                    for match in matches:
                        var_name = match.strip()
                        is_tainted = False
                        
                        if var_name in all_tainted or var_name in taint_sources:
                            is_tainted = True
                        else:
                            for taint_source in taint_sources:
                                if taint_source.endswith('.') and var_name.startswith(taint_source):
                                    is_tainted = True
                                    break
                                if var_name.startswith(taint_source + '.'):
                                    is_tainted = True
                                    break
                            
                            if not is_tainted:
                                for flow in data_flows:
                                    to_var = flow.get('to', '').strip()
                                    if to_var == var_name:
                                        from_var = flow.get('from', '').strip()
                                        if from_var in taint_sources or from_var in all_tainted:
                                            is_tainted = True
                                            break
                        
                        if is_tainted:
                            has_user_input_in_body = True
                            user_input_vars.append(var_name)
                            body_fields_with_input.append(field)
            
            if not has_user_input_in_body:
                continue
            
            has_auto_request_disabled = False
            for i in range(start, end):
                check_line = lines[i] if i < len(lines) else ""
                for pattern in self.auto_request_trigger_patterns:
                    if pattern.search(check_line):
                        false_pattern = re.compile(rf'{pattern.pattern}.*:\s*false', re.IGNORECASE)
                        if false_pattern.search(check_line):
                            has_auto_request_disabled = True
                            break
                if has_auto_request_disabled:
                    break
            
            if has_auto_request_disabled:
                continue
            
            user_input_str = ', '.join(user_input_vars[:3])
            if len(user_input_vars) > 3:
                user_input_str += f', ... (+{len(user_input_vars) - 3} more)'
            
            fields_str = ', '.join(set(body_fields_with_input[:3]))
            if len(set(body_fields_with_input)) > 3:
                fields_str += f', ... (+{len(set(body_fields_with_input)) - 3} more)'
            
            code_snippet = '\n'.join(context_lines[-5:])
            
            findings.append(Finding(
                rule_id="typescript/ssrf",
                severity="high",
                message=f"[HIGH] SSRF: User input in fetch body ({fields_str}: {user_input_str}) without auto-request trigger protection - User-controlled data in request body may trigger automatic requests (unfurl, auto-fetch, preview, etc.) to external URLs, potentially exposing sensitive information - Disable auto-request triggers (e.g., unfurl_links: false, unfurl_media: false) or validate/sanitize user input",
                cwe="CWE-918",
                file=file_path,
                line=line,
                column=call.get('column', 0),
                code_snippet=code_snippet,
                pattern_type="body_user_input_ssrf",
                pattern="fetch(JSON.stringify)",
                confidence=CONFIDENCE_LEVELS['HIGH']
            ))
        
        return findings
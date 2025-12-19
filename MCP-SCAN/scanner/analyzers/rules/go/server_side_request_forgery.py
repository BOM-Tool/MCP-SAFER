import re
from typing import List, Dict, Set, Optional, Tuple, Any
from scanner.analyzers.common.scanner import Finding, CommonPatterns, ConfigLoader
from scanner.analyzers.common.base_detector import BaseDetector
from scanner.analyzers.common.utils import extract_var_name

class SSRFDataFlowAnalyzer:
    
    def __init__(self):
        self.config = ConfigLoader.get_instance()
        
        self.user_input_sources = [
            'FormValue', 'Query', 'PostFormValue', 'Header.Get',
            'URL.Query', 'Request.', 'Args', 'Getenv', 'LookupEnv',
            'flag.String', 'flag.Parse', 'os.Args'
        ]
        
        self.sanitizer_functions = [
            'url.Parse', 'url.QueryEscape', 'strings.TrimSpace',
            'regexp.MustCompile', 'net.ParseIP'
        ]
        
        self.dangerous_sinks = {
            'critical': [
                ('http', 'Get'), ('http', 'Post'), ('http', 'PostForm'), ('http', 'Head'),
                ('http', 'Do'), ('http', 'NewRequest'), ('http', 'NewRequestWithContext')
            ],
            'high': [
                ('net', 'Dial'), ('net', 'DialTimeout'), ('net', 'DialTCP'), ('net', 'DialUDP'),
                ('http', 'Client'), ('http', 'Transport'), ('net/http', 'Get'),
                ('net/http', 'Post'), ('net/http', 'PostForm'), ('net/http', 'Head')
            ],
            'medium': [
                ('net', 'Listen'), ('net', 'ListenTCP'), ('net', 'ListenUDP'),
                ('net', 'ResolveTCPAddr'), ('net', 'ResolveUDPAddr'),
                ('net/http', 'ListenAndServe'), ('net/http', 'ListenAndServeTLS'),
                ('url', 'Parse'), ('url', 'ParseRequestURI')
            ],
            'low': [
                ('net', 'LookupHost'), ('net', 'LookupIP'), ('net', 'LookupCNAME'),
                ('net', 'LookupMX'), ('net', 'LookupNS'), ('net', 'LookupTXT'),
                ('net', 'LookupSRV'), ('net', 'LookupAddr')
            ]
        }
        
        self.metadata_urls = [
            '169.254.169.254', '169.254.170.2', 'metadata.google.internal', '100.100.100.200'
        ]
        
        self.private_networks = [
            '127.0.0.1', 'localhost', '10.', '172.16.', '192.168.', '0.0.0.0', '::1'
        ]
        
        trusted_patterns = self.config.get_safe_url_patterns('go')
        self.trusted_url_patterns = trusted_patterns + [
            r'testServer\.URL', r'httptest\.NewServer',
            r'test\.example\.com', r'staging\.example\.com', r'api\.example\.com'
        ]
        self.trusted_url_patterns_compiled = [re.compile(p) for p in self.trusted_url_patterns]
        
        self.whitelisted_domains = self.config.get_whitelisted_domains('go')
    
    def _extract_var_name(self, arg: str) -> str:
        return extract_var_name(arg)
    
    
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

class SSRFDetector(BaseDetector):
    
    def __init__(self, language: str = "go"):
        super().__init__()
        self.language = language
        self.analyzer = SSRFDataFlowAnalyzer()
        self.SAFE_URL_PATTERNS = [
            r'^https://[a-zA-Z0-9.-]+\.(com|org|net|edu|gov|io|co|uk|de|fr|jp|cn)/',
            r'^https://api\.[a-zA-Z0-9.-]+\.',
            r'^https://www\.[a-zA-Z0-9.-]+\.',
            r'^https://[a-zA-Z0-9-]+\.cloudfront\.net',
            r'^https://[a-zA-Z0-9-]+\.s3\.[a-zA-Z0-9-]+\.amazonaws\.com'
        ]
        self.safe_url_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.SAFE_URL_PATTERNS]
        
        self.CONTROLLED_URL_PATTERNS = [
            r'cfg\.\w+', r'config\.\w+', r'settings\.\w+', r'conf\.\w+',
            r'env\.\w+', r'os\.Getenv\(', r'flag\.String\('
        ]
        self.controlled_url_patterns_compiled = [re.compile(p) for p in self.CONTROLLED_URL_PATTERNS]
    
    def get_name(self) -> str:
        return "ssrf"
    
    def get_cwe(self) -> str:
        return "CWE-918"
    
    def get_rule_id(self, language: str = None) -> str:
        lang = language or self.language
        return f"{lang}/ssrf"
    
    def is_dangerous_sink(self, pkg: str, fn: str) -> bool:
        for sinks in self.analyzer.dangerous_sinks.values():
            if (pkg, fn) in sinks:
                return True
        return False
    
    def get_sink_severity(self, pkg: str, fn: str) -> str:
        url_severity, _ = self._analyze_url_risk_level([], "")
        
        for sev, sinks in self.analyzer.dangerous_sinks.items():
            if (pkg, fn) in sinks:
                if sev in ['critical', 'high'] or url_severity in ['critical', 'high']:
                    return 'critical' if (sev == 'critical' or url_severity == 'critical') else 'high'
                return sev if sev in ['medium', 'low'] else url_severity
        return "medium"
    
    def is_safe_usage(self, call: Dict, line_content: str, args: List[str], 
                     file_path: str, lines: List[str]) -> bool:
        if self._is_hardcoded_url(args, line_content):
            return True
        
        if self._is_safe_url_usage(args, line_content):
            return True
        
        if self._is_trusted_url(line_content):
            return True
        
        if self._is_unix_socket(line_content):
            return True
        
        if self._is_literal_url(args):
            return True
        
        return False
    
    def analyze_data_flow(self, ast_result: Dict[str, Any], 
                         taint_result: Dict[str, Any]) -> List[Dict]:
        findings = self.analyzer.analyze_data_flow(ast_result, taint_result)
        
        data_flows = ast_result.get('data_flows', [])
        filtered_findings = []
        
        for finding in findings:
            tainted_var = finding.get('tainted_var', '')
            if tainted_var and self._is_from_literal(tainted_var, data_flows, ast_result):
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
            return f"SSRF: User input '{tainted_var}' in {pkg}.{fn}() - verify input sanitization"
        
        return f"SSRF: {pkg}.{fn}() - verify input sanitization"
    
    def _calculate_confidence(self, call: Dict, args: List[str], base_var: str,
                              severity: str, data_flows: List[Dict],
                              taint_sources: Set[str]) -> float:
        line_content = call.get('line_content', '')
        if not line_content and args:
            line_content = str(args[0])
        
        url_severity, url_confidence = self._analyze_url_risk_level(args, line_content)
        base_confidence = max(self.CONFIDENCE_LEVELS['MEDIUM'], url_confidence)
        
        if severity == "critical":
            base_confidence = self.CONFIDENCE_LEVELS['CRITICAL']
        elif severity == "high":
            base_confidence = self.CONFIDENCE_LEVELS['HIGH']
        
        if data_flows and base_var:
            for flow in data_flows:
                to_var = flow.get('to', '').strip()
                if to_var == base_var:
                    from_var = flow.get('from', '').strip()
                    if from_var in taint_sources:
                        base_confidence = max(base_confidence, self.CONFIDENCE_LEVELS['HIGH'])
        
        return base_confidence
    
    def _detect_vulnerability(self, call: Dict, args: List[str], line: int,
                             line_content: str, file_path: str,
                             data_flow_findings: List[Dict],
                             data_flows: List[Dict],
                             taint_sources: Set[str],
                             all_tainted: Set[str]) -> Tuple[Optional[str], Optional[str], float]:
        pkg = call.get('package', '')
        fn = call.get('function', '')
        
        if self._is_metadata_url(args, line_content):
            return "critical", f"Metadata URL detected: {pkg}.{fn}() - potential cloud metadata access", self.CONFIDENCE_LEVELS['CRITICAL']
        
        if self._is_private_network_url(args, line_content):
            return "high", f"Private network URL: {pkg}.{fn}() - internal network access", self.CONFIDENCE_LEVELS['HIGH']
        
        return super()._detect_vulnerability(call, args, line, line_content, file_path,
                                            data_flow_findings, data_flows, taint_sources, all_tainted)
    def _get_context_info(self, line_content: str, args: List[str], file_path: str) -> Dict[str, bool]:
        context = {
            'is_test_file': False,
            'has_safe_comment': False,
            'is_trusted_url': False,
            'is_unix_socket': False,
            'is_literal_url': False
        }
        
        context['is_test_file'] = CommonPatterns.is_test_file(file_path, "go")
        context['has_safe_comment'] = CommonPatterns.has_safe_comment(line_content)
        
        if args and args[0].startswith('"') and args[0].endswith('"'):
            url_value = args[0].strip('"')
            context['is_trusted_url'] = any(pattern.search(url_value) for pattern in self.safe_url_patterns_compiled) or any(domain in url_value for domain in self.analyzer.whitelisted_domains)
            
            if url_value.startswith('https://'):
                is_metadata = any(meta in url_value for meta in self.analyzer.metadata_urls)
                if not is_metadata:
                    is_private = any(priv in url_value for priv in self.analyzer.private_networks)
                    if not is_private:
                        context['is_literal_url'] = True
        
        if 'net.Dial("unix"' in line_content or 'net.DialTimeout("unix"' in line_content:
            context['is_unix_socket'] = True
        
        return context

    def _is_trusted_url(self, line_content: str) -> bool:
        return any(pattern.search(line_content) 
                  for pattern in self.analyzer.trusted_url_patterns_compiled)

    def _is_unix_socket(self, line_content: str) -> bool:
        return 'net.Dial("unix"' in line_content or 'net.DialTimeout("unix"' in line_content

    def _is_literal_url(self, args: List[str]) -> bool:
        if args and args[0].startswith('"') and args[0].endswith('"'):
            url_value = args[0].strip('"')
            if url_value.startswith('https://'):
                is_metadata = any(meta in url_value for meta in self.analyzer.metadata_urls)
                if not is_metadata:
                    is_private = any(priv in url_value for priv in self.analyzer.private_networks)
                    if not is_private:
                        return True
        return False
    
    def _is_hardcoded_url(self, args: List[str], line_content: str) -> bool:
        if not args:
            return False
        
        for pattern in self.analyzer.user_input_sources:
            if re.search(pattern, line_content):
                return False
        
        return all(
            arg.strip().startswith('"') and arg.strip().endswith('"')
            for arg in args
        )
    
    def _is_safe_url_usage(self, args: List[str], line_content: str) -> bool:
        if not args:
            return False
        
        for arg in args:
            if arg.startswith('"') and arg.endswith('"'):
                url_value = arg.strip('"')
                
                for pattern in self.safe_url_patterns_compiled:
                    if pattern.search(url_value):
                        return True
                
                for domain in self.analyzer.whitelisted_domains:
                    if domain in url_value:
                        return True
        
        return False
    
    def _is_controlled_url(self, args: List[str], line_content: str) -> bool:
        for pattern in self.controlled_url_patterns_compiled:
            if pattern.search(line_content):
                return True
        return False
    
    def _is_metadata_url(self, args: List[str], line_content: str) -> bool:
        if not args:
            return False
        
        for arg in args:
            url_value = arg.strip('"\'')
            if any(meta in url_value for meta in self.analyzer.metadata_urls):
                return True
        
        for meta in self.analyzer.metadata_urls:
            if meta in line_content:
                return True
        
        return False
    
    def _is_private_network_url(self, args: List[str], line_content: str) -> bool:
        if not args:
            return False
        
        for arg in args:
            url_value = arg.strip('"\'')
            if any(priv in url_value for priv in self.analyzer.private_networks):
                return True
        
        for priv in self.analyzer.private_networks:
            if priv in line_content:
                return True
        
        return False
    
    def _analyze_url_risk_level(self, args: List[str], line_content: str) -> Tuple[str, float]:
        if self._is_metadata_url(args, line_content):
            return 'critical', self.CONFIDENCE_LEVELS['CRITICAL']
        
        if self._is_private_network_url(args, line_content):
            return 'high', self.CONFIDENCE_LEVELS['HIGH']
        
        if self._is_safe_url_usage(args, line_content):
            return 'low', self.CONFIDENCE_LEVELS['LOW']
        
        if self._is_controlled_url(args, line_content):
            return 'medium', self.CONFIDENCE_LEVELS['MEDIUM']
        
        return 'medium', self.CONFIDENCE_LEVELS['MEDIUM']

    def _validate_data_flow_finding(self, call: Dict, args: List[str], 
                                    line_content: str, data_flow_finding: Dict,
                                    severity: str, confidence: float) -> Tuple[str, float]:
        if self._is_metadata_url(args, line_content):
            return "critical", self.CONFIDENCE_LEVELS['CRITICAL']
        if self._is_private_network_url(args, line_content):
            return "high", self.CONFIDENCE_LEVELS['HIGH']
        return severity, confidence
import re
from typing import List, Dict, Set, Any
from scanner.analyzers.common.scanner import Finding, CommonPatterns

class OpenRedirectDetector:
    REDIRECT_SINKS = [
        ('', 'redirect'),
        ('res', 'redirect'),
        ('response', 'redirect'),
        ('Response', 'redirect'),
        ('ctx', 'redirect'),
        ('context', 'redirect'),
        ('reply', 'redirect'),
        ('h', 'redirect'),
        ('fastify', 'redirect'),
        ('koa', 'redirect'),
        ('express', 'redirect'),
        ('', 'writeHead'),
        ('res', 'writeHead'),
        ('response', 'writeHead'),
        ('', 'location'),
        ('window', 'location'),
        ('location', 'href'),
        ('location', 'replace'),
        ('location', 'assign'),
    ]
    
    REDIRECT_URI_SOURCES = [
        'redirect_uri', 'redirectUri', 'redirect_uri', 'redirect',
        'return_url', 'returnUrl', 'return_url', 'return',
        'callback_url', 'callbackUrl', 'callback_url', 'callback',
        'next', 'nextUrl', 'next_url', 'continue', 'continueUrl',
        'target', 'targetUrl', 'target_url', 'destination', 'dest',
        'url', 'uri', 'link', 'href', 'to', 'goto', 'go',
    ]
    
    VALIDATION_PATTERNS = [
        r'isRedirectUriAllowed',
        r'isRedirectUriValid',
        r'validateRedirectUri',
        r'validateRedirect',
        r'checkRedirectUri',
        r'checkRedirect',
        r'allowedRedirectUris',
        r'allowedRedirects',
        r'whitelist.*redirect',
        r'allowlist.*redirect',
        r'redirect.*whitelist',
        r'redirect.*allowlist',
        r'redirect.*allowed',
        r'redirect.*valid',
        r'client.*redirect',
        r'registered.*redirect',
        r'redirect.*register',
        r'redirect.*match',
        r'redirect.*equals',
        r'redirect.*startsWith',
        r'redirect.*includes',
        r'redirect.*indexOf',
    ]
    
    USER_INPUT_PATTERNS = [
        r'req\.query\.',
        r'request\.query\.',
        r'req\.params\.',
        r'request\.params\.',
        r'req\.body\.',
        r'request\.body\.',
        r'req\.headers\.',
        r'request\.headers\.',
        r'query\.',
        r'params\.',
        r'body\.',
        r'headers\.',
        r'input\.',
        r'args\.',
        r'data\.',
        r'payload\.',
    ]
    
    def __init__(self):
        self.redirect_sinks = self.REDIRECT_SINKS
        self.redirect_uri_sources = self.REDIRECT_URI_SOURCES
        self.validation_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.VALIDATION_PATTERNS]
        self.user_input_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.USER_INPUT_PATTERNS]
        self.redirect_uri_sources_compiled = [re.compile(r'\b' + re.escape(s) + r'\b', re.IGNORECASE) for s in self.redirect_uri_sources]
    
    def get_name(self) -> str:
        return "open-redirect"
    
    def get_cwe(self) -> str:
        return "CWE-601"
    
    def _has_redirect_validation(self, lines: List[str], line: int, var_name: str = "") -> bool:
        if not lines or line < 1 or line > len(lines):
            return False
        
        start = max(0, line - 30)
        end = min(len(lines), line + 5)
        context = '\n'.join(lines[start:end])
        
        for pattern in self.validation_patterns_compiled:
            if pattern.search(context):
                if var_name:
                    var_pattern = re.compile(r'\b' + re.escape(var_name) + r'\b', re.IGNORECASE)
                    if var_pattern.search(context):
                        return True
                else:
                    return True
        
        return False
    
    def _is_user_input_source(self, var_name: str, line_content: str) -> bool:
        for pattern in self.user_input_patterns_compiled:
            if pattern.search(line_content):
                for source in self.redirect_uri_sources_compiled:
                    if source.search(line_content):
                        return True
        
        for pattern in self.user_input_patterns_compiled:
            if pattern.search(var_name):
                return True
        
        return False
    
    def _extract_redirect_uri_vars(self, line_content: str) -> List[str]:
        vars_found = []
        
        for source in self.redirect_uri_sources:
            pattern = re.compile(r'\b' + re.escape(source) + r'\b', re.IGNORECASE)
            if pattern.search(line_content):
                for user_input_pattern in self.user_input_patterns_compiled:
                    matches = user_input_pattern.findall(line_content)
                    for match in matches:
                        if source.lower() in match.lower() or match.lower() in source.lower():
                            vars_found.append(match)
        
        template_var_pattern = re.compile(r'\$\{([^}]+)\}', re.IGNORECASE)
        template_vars = template_var_pattern.findall(line_content)
        for var in template_vars:
            var_clean = var.strip()
            for source in self.redirect_uri_sources:
                if source.lower() in var_clean.lower() or var_clean.lower() in source.lower():
                    if self._is_user_input_source(var_clean, line_content):
                        vars_found.append(var_clean)
        
        return list(set(vars_found))
    
    def check(self, calls: List[Dict], tainted_vars: Set[str], 
              lines: List[str], file_path: str, 
              ast_result: Dict = None, taint_result: Dict = None, cfg: Any = None) -> List[Finding]:
        findings = []
        
        if not calls:
            return findings
        
        for call in calls:
            pkg = call.get('package', '')
            fn = call.get('function', '')
            line = call.get('line', 0)
            args = call.get('args', [])
            
            if line < 1 or line > len(lines):
                continue
            
            line_content = lines[line - 1] if line <= len(lines) else ""
            
            is_redirect_sink = False
            for sink_pkg, sink_fn in self.redirect_sinks:
                if (pkg == sink_pkg or (not sink_pkg and not pkg)) and fn == sink_fn:
                    is_redirect_sink = True
                    break
            
            if not is_redirect_sink:
                continue
            
            redirect_uri_vars = self._extract_redirect_uri_vars(line_content)
            unsafe_vars = []
            
            for var in redirect_uri_vars:
                if self._is_user_input_source(var, line_content):
                    unsafe_vars.append(var)
            
            for arg in args:
                arg_str = str(arg) if arg else ""
                if self._is_user_input_source(arg_str, line_content):
                    for source in self.redirect_uri_sources:
                        if source.lower() in arg_str.lower() or arg_str.lower() in source.lower():
                            unsafe_vars.append(arg_str)
            
            for tainted_var in tainted_vars:
                for source in self.redirect_uri_sources:
                    if source.lower() in tainted_var.lower() or tainted_var.lower() in source.lower():
                        if tainted_var not in unsafe_vars:
                            unsafe_vars.append(tainted_var)
            
            if not unsafe_vars:
                continue
            
            unsafe_vars_str = ', '.join(unsafe_vars[:3])
            if len(unsafe_vars) > 3:
                unsafe_vars_str += f', ... (+{len(unsafe_vars) - 3} more)'
            
            has_validation = self._has_redirect_validation(lines, line, unsafe_vars_str)
            
            if has_validation:
                continue
            
            severity = "HIGH"
            if CommonPatterns.is_test_file(file_path, "typescript"):
                severity = "LOW"
            
            code_snippet = line_content.strip()[:200] if line_content else ""
            
            finding = Finding(
                rule_id=f"{self.get_name()}-{self.get_cwe()}",
                severity=severity.lower(),
                message=f"[{severity}] Open Redirect (CWE-601): External-controlled redirect URI ({unsafe_vars_str}) passed to {pkg}.{fn}() without validation - Redirect URI should be validated against an allowlist or registered client redirect URIs to prevent unauthorized redirects - OAuth redirect_uri must match registered values exactly",
                cwe=self.get_cwe(),
                file=file_path,
                line=line,
                column=0,
                code_snippet=code_snippet,
                pattern_type="open_redirect",
                pattern=f"{pkg}.{fn}" if pkg else fn,
            )
            findings.append(finding)
        
        return findings


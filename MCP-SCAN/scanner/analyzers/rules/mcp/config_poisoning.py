import re
from typing import List, Dict, Set, Optional, Any
from scanner.analyzers.common.scanner import Finding
from scanner.analyzers.common.mcp_utils import scan_lines_for_patterns, create_mcp_finding, scan_lines_with_custom_check
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS

class ConfigPoisoningDetector:
    
    def __init__(self):
        self.malicious_urls = [
            r'https?://[a-zA-Z0-9-]+\.(exe|bat|sh|ps1|vbs|jar)',
            r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
            r'https?://.*\.(onion|bit|tk|ml|ga|cf|gq)',
            r'file:///',
            r'ftp://.*',
            r'\\\\.*',
        ]
        
        self.external_data_exfiltration = [
            r'webhook',
            r'callback',
            r'http',
            r'https',
            r'api\.',
            r'analytics',
            r'tracking',
        ]
        
        self.dangerous_tool_enablements = [
            r'enableShell',
            r'allowExec',
            r'enableFileSystem',
            r'allowNetwork',
            r'enableDatabase',
            r'allowDelete',
            r'enableWrite',
            r'unsafeMode',
            r'disableSecurity',
            r'bypassAuth',
        ]
        
        self.auth_bypass_patterns = [
            r'auth\s*:\s*false',
            r'authentication\s*:\s*false',
            r'requireAuth\s*:\s*false',
            r'bypassAuth\s*:\s*true',
            r'skipVerification\s*:\s*true',
            r'trustAll\s*:\s*true',
            r'verifySSL\s*:\s*false',
            r'verifyTLS\s*:\s*false',
        ]
        
        self.privilege_escalation = [
            r'runAsRoot\s*:\s*true',
            r'sudo\s*:\s*true',
            r'elevatePrivileges\s*:\s*true',
            r'adminMode\s*:\s*true',
            r'systemAccess\s*:\s*true',
            r'fullPermissions\s*:\s*true',
        ]
        
        self.malicious_env_vars = [
            r'API_KEY\s*=\s*["\'].*["\']',
            r'SECRET\s*=\s*["\'].*["\']',
            r'PASSWORD\s*=\s*["\'].*["\']',
            r'TOKEN\s*=\s*["\'].*["\']',
            r'CREDENTIALS\s*=\s*["\'].*["\']',
        ]
        
        self.suspicious_paths = [
            r'/etc/passwd',
            r'/etc/shadow',
            r'/root/',
            r'C:\\Windows\\System32',
            r'~/.ssh/',
            r'/var/log/',
        ]
        
        self.config_file_patterns = [
            r'package\.json',
            r'tsconfig\.json',
            r'mcp\.config\.(js|ts|json)',
            r'\.env',
            r'config\.(js|ts|json)',
            r'settings\.(js|ts|json)',
        ]
        
        self.config_object_patterns = [
            r'const\s+config\s*=',
            r'export\s+const\s+config\s*=',
            r'module\.exports\s*=\s*\{',
            r'export\s+default\s+\{',
            r'const\s+settings\s*=',
            r'process\.env\.',
        ]
    
    def get_name(self) -> str:
        return "config-poisoning"
    
    def check(self, calls: List[Dict], tainted_vars: Set[str], 
              lines: List[str], file_path: str, 
              ast_result: Dict = None, taint_result: Dict = None, cfg: Any = None) -> List[Finding]:
        findings = []
        
        if not lines:
            return findings
        
        findings.extend(self._check_malicious_urls(lines, file_path))
        findings.extend(self._check_data_exfiltration(lines, file_path))
        findings.extend(self._check_dangerous_tools(lines, file_path))
        findings.extend(self._check_auth_bypass(lines, file_path))
        findings.extend(self._check_privilege_escalation(lines, file_path))
        findings.extend(self._check_malicious_env_vars(lines, file_path))
        findings.extend(self._check_suspicious_paths(lines, file_path))
        findings.extend(self._check_config_injection(lines, file_path))
        
        return findings
    
    def _check_malicious_urls(self, lines: List[str], file_path: str) -> List[Finding]:
        findings = []
        
        file_lower = file_path.lower()
        is_test_file = (
            file_lower.endswith('_test.go') or
            file_lower.endswith('.test.js') or
            file_lower.endswith('.test.ts') or
            file_lower.endswith('.test.py') or
            '/test/' in file_lower or
            'test_' in file_lower or
            '_test_' in file_lower
        )
        
        if is_test_file:
            return findings
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if not stripped:
                continue
            
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            if '/test/' in file_lower or 'tests/' in file_lower:
                if any(keyword in line.lower() for keyword in ['it(', 'describe(', 'test(', 'expect(', 'should ']):
                    continue
            
            if 'regexp.MustCompile' in line or 'regexp.Compile' in line or 'regexp.New' in line:
                continue
            
            if re.search(r'regexp\.(MustCompile|Compile|New)\s*\(', line, re.IGNORECASE):
                continue
            
            if re.search(r'const\s+\w+\s*=\s*`', line) or re.search(r'const\s+\w+\s*=\s*"', line):
                continue
            
            if re.search(r'var\s+\w+\s*=\s*`', line) or re.search(r'var\s+\w+\s*=\s*"', line):
                continue
            
            if re.search(r'\.replace\(', line, re.IGNORECASE):
                continue
            
            if re.search(r'/.*/', line) and ('g' in line or 'i' in line or 'm' in line):
                continue
            
            if re.search(r'\\\\x1b|\\\\\\[|\\\\\\]|\\\\n|\\\\t|\\\\r', line):
                continue
            
            if re.search(r'\\\\\$&|\\\\\$1|\\\\\$2', line):
                continue
            
            if re.search(r'str\.replace|string\.replace|\.replace\(/', line, re.IGNORECASE):
                continue
            
            if 'git grep' in line or 'git log' in line or 'git diff' in line:
                if '\\\\b' in line or '\\\\w' in line:
                    continue
            
            if 'createColor' in line and '\\\\x1b' in line:
                continue
            
            if re.search(r'\.regex\(|\.match\(|\.test\(|\.exec\(', line):
                continue
            
            example_indicators = [
                '# example', '# usage:', '# note:', '# explicit', '# sample',
                '// example', '// usage:', '// note:', '// explicit', '// sample',
                'example:', 'usage:', 'note:', 'sample:',
                '/path/to/', '/example/', 'example.com', 'example.org',
                '// Throws', '// throws', '// Throws error'
            ]
            
            line_lower = line.lower()
            if any(indicator in line_lower for indicator in example_indicators):
                continue
            
            if re.search(r'^\s*[{\[].*["\'](file://|ftp://|https?://)', stripped, re.IGNORECASE):
                continue
            
            if re.search(r'map\[.*\]\s*\{', stripped, re.IGNORECASE):
                continue
            
            if 'pipe\\' in line.lower() or 'named.pipe' in line.lower() or 'pipe/' in line.lower():
                if re.search(r'\\\\.*', line, re.IGNORECASE):
                    continue
            
            config_context = False
            
            if re.search(r'(ReadFile|readFile|loadConfig|readConfig|parseConfig|require\(|import\s+.*config)', line, re.IGNORECASE):
                config_context = True
            
            if re.search(r'(Getenv|process\.env|env\.|os\.Getenv|LookupEnv)', line, re.IGNORECASE):
                config_context = True
            
            if re.search(r'(FormValue|Query\(|PostForm|req\.(query|params|body))', line, re.IGNORECASE):
                config_context = True
            
            if re.search(r'["\']?(url|endpoint|host|server|webhook)["\']?\s*[:=]\s*["\']?(file://|ftp://|https?://)', line, re.IGNORECASE):
                config_context = True
            
            if not config_context:
                continue
            
            for pattern in self.malicious_urls:
                if pattern == r'\\\\.*':
                    if re.search(r'file://|ftp://', line, re.IGNORECASE):
                        if '\\x1b' not in line and '.replace(' not in line and '/.*/' not in line and '\\\\' not in line[:10]:
                            findings.append(create_mcp_finding(
                                rule_id="mcp/config-poisoning-malicious-url",
                                message=f"[CONFIG POISONING] Malicious URL pattern detected in configuration: Suspicious URL pattern '{pattern}'",
                                file_path=file_path,
                                line=i,
                                code_snippet=stripped[:200] if len(stripped) > 200 else stripped,
                                pattern_type="malicious-url",
                                pattern=f"malicious-url:{pattern}",
                                confidence=CONFIDENCE_LEVELS['CRITICAL']
                            ))
                            break
                elif re.search(pattern, line, re.IGNORECASE):
                    findings.append(create_mcp_finding(
                        rule_id="mcp/config-poisoning-malicious-url",
                        message=f"[CONFIG POISONING] Malicious URL pattern detected in configuration: Suspicious URL pattern '{pattern}'",
                        file_path=file_path,
                        line=i,
                        code_snippet=stripped[:200] if len(stripped) > 200 else stripped,
                        pattern_type="malicious-url",
                        pattern=f"malicious-url:{pattern}",
                        confidence=CONFIDENCE_LEVELS['HIGH']
                    ))
                    break
        
        return findings
    
    def _check_data_exfiltration(self, lines: List[str], file_path: str) -> List[Finding]:
        findings = []
        
        file_lower = file_path.lower()
        is_test_file = (
            file_lower.endswith('_test.go') or
            file_lower.endswith('.test.js') or
            file_lower.endswith('.test.ts') or
            file_lower.endswith('.test.py') or
            '/test/' in file_lower or
            'test_' in file_lower or
            '_test_' in file_lower
        )
        
        if is_test_file:
            return findings
        
        if 'package-lock.json' in file_lower or 'package.json' in file_lower:
            return findings
        
        if 'openapi.json' in file_lower or '-openapi.json' in file_lower or 'swagger.json' in file_lower:
            return findings
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            
            if re.search(r'^import\s+', line, re.IGNORECASE):
                continue
            
            if 'from \'http\'' in line or 'from "http"' in line or 'from \'https\'' in line or 'from "https"' in line:
                continue
            
            if '@module' in line or '@param' in line or '@return' in line or '@type' in line:
                continue
            
            if re.search(r'function\s+\w*[Hh]ttp|const\s+\w*[Hh]ttp|let\s+\w*[Hh]ttp|var\s+\w*[Hh]ttp', line):
                if 'baseURL' not in line and 'endpoint' not in line.lower() and 'url' not in line.lower():
                    continue
            
            if re.search(r'createHttp|startHttp|stopHttp|httpServer|httpTransport|httpApp', line, re.IGNORECASE):
                continue
            
            if 'http.createServer' in line or 'http.Server' in line or 'http.Request' in line or 'http.Response' in line:
                continue
            
            if re.search(r'mcpHttp|httpHost|httpEndpoint|httpTransport', line, re.IGNORECASE):
                continue
            
            if re.search(r'localhost|127\.0\.0\.1|::1|0\.0\.0\.0', line, re.IGNORECASE):
                continue
            
            if 'example.com' in line.lower() or 'example.org' in line.lower():
                continue
            
            if re.search(r'https?://static\.|https?://registry\.|https?://api\.(openai|elevenlabs|openrouter)\.', line, re.IGNORECASE):
                continue
            
            config_context = False
            
            if re.search(r'(ReadFile|readFile|loadConfig|readConfig|parseConfig|require\(|import\s+.*config)', line, re.IGNORECASE):
                config_context = True
            
            if re.search(r'(Getenv|process\.env|env\.|os\.Getenv|LookupEnv)', line, re.IGNORECASE):
                if not re.search(r'https?://', line):
                    continue
                config_context = True
            
            if re.search(r'(FormValue|Query\(|PostForm|req\.(query|params|body))', line, re.IGNORECASE):
                config_context = True
            
            if re.search(r'["\']?(url|endpoint|host|server|webhook)["\']?\s*[:=]\s*["\']?https?://', line, re.IGNORECASE):
                config_context = True
            
            if re.search(r'baseURL\s*[:=]|baseUrl\s*[:=]|apiUrl\s*[:=]|api_url\s*[:=]', line, re.IGNORECASE):
                if re.search(r'https?://', line):
                    if re.search(r'(openai|elevenlabs|openrouter|api\.)', line, re.IGNORECASE):
                        continue
                    config_context = True
            
            if not config_context:
                continue
            
            for pattern in self.external_data_exfiltration:
                if pattern in ['http', 'https']:
                    if not re.search(r'["\']https?://[^"\']+["\']', line):
                        continue
                    if re.search(r'https?://(localhost|127\.0\.0\.1|static\.|registry\.|api\.(openai|elevenlabs|openrouter))', line, re.IGNORECASE):
                        continue
                
                if pattern == r'api\.':
                    if re.search(r'["\']https?://api\.', line, re.IGNORECASE):
                        if not any(sus in line.lower() for sus in ['unknown', 'external', 'untrusted', 'user', 'config', 'env']):
                            continue
                
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(create_mcp_finding(
                        rule_id="mcp/config-poisoning-data-exfiltration",
                        message="[CONFIG POISONING] Data exfiltration configuration detected: External endpoint configured for potential data exfiltration",
                        file_path=file_path,
                        line=i,
                        code_snippet=stripped[:200] if len(stripped) > 200 else stripped,
                        pattern_type="config_poisoning",
                        pattern=f"data-exfiltration:{pattern}",
                        confidence=CONFIDENCE_LEVELS['HIGH']
                    ))
                    break
        
        return findings
    
    def _check_dangerous_tools(self, lines: List[str], file_path: str) -> List[Finding]:
        return scan_lines_for_patterns(
            lines=lines,
            patterns=self.dangerous_tool_enablements,
            file_path=file_path,
            rule_id_prefix="mcp/config-poisoning",
            message_template="[CONFIG POISONING] Dangerous tool enabled in configuration: '{pattern}' is set to true - May enable malicious operations",
            pattern_category="dangerous-tool",
            confidence=CONFIDENCE_LEVELS['CRITICAL'],
            condition=lambda line, pattern: bool(re.search(r':\s*(true|1|"true"|\'true\')', line, re.IGNORECASE))
        )
    
    def _check_auth_bypass(self, lines: List[str], file_path: str) -> List[Finding]:
        return scan_lines_for_patterns(
            lines=lines,
            patterns=self.auth_bypass_patterns,
            file_path=file_path,
            rule_id_prefix="mcp/config-poisoning",
            message_template="[CONFIG POISONING] Authentication bypass detected: Security mechanism disabled in configuration",
            pattern_category="auth-bypass",
            confidence=CONFIDENCE_LEVELS['CRITICAL']
        )
    
    def _check_privilege_escalation(self, lines: List[str], file_path: str) -> List[Finding]:
        return scan_lines_for_patterns(
            lines=lines,
            patterns=self.privilege_escalation,
            file_path=file_path,
            rule_id_prefix="mcp/config-poisoning",
            message_template="[CONFIG POISONING] Privilege escalation detected: Configuration allows elevated privileges",
            pattern_category="privilege-escalation",
            confidence=CONFIDENCE_LEVELS['CRITICAL']
        )
    
    def _check_malicious_env_vars(self, lines: List[str], file_path: str) -> List[Finding]:
        if '.env' not in file_path.lower() and 'env' not in file_path.lower():
            return []
        
        return scan_lines_for_patterns(
            lines=lines,
            patterns=self.malicious_env_vars,
            file_path=file_path,
            rule_id_prefix="mcp/config-poisoning",
            message_template="[CONFIG POISONING] Sensitive credentials in environment file: Credentials exposed in configuration file",
            pattern_category="malicious-env",
            confidence=CONFIDENCE_LEVELS['CRITICAL'],
            condition=lambda line, pattern: not line.strip().startswith('#'),
            code_snippet_transform=lambda line: (line.strip()[:50] + "...") if len(line.strip()) > 50 else line.strip()
        )
    
    def _check_suspicious_paths(self, lines: List[str], file_path: str) -> List[Finding]:
        findings = []
        
        file_lower = file_path.lower()
        is_test_file = (
            file_lower.endswith('_test.go') or
            file_lower.endswith('.test.js') or
            file_lower.endswith('.test.ts') or
            file_lower.endswith('.test.py') or
            '/test/' in file_lower or
            'test_' in file_lower or
            '_test_' in file_lower
        )
        
        if is_test_file:
            return findings
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('/*'):
                continue
            
            if '// Throws' in line or '// throws' in line or '// Throws error' in line:
                continue
            
            if 'example' in line.lower() or 'sample' in line.lower():
                if '/etc/passwd' in line or '/etc/shadow' in line:
                    continue
            
            if re.search(r'validateFilePath|validatePath|checkPath', line, re.IGNORECASE):
                if '/etc/passwd' in line:
                    continue
            
            if '--mount=type=cache' in line or '--mount=type=secret' in line or '--mount=type=ssh' in line:
                continue
            
            if stripped.startswith('RUN') and 'cache' in line.lower() and '/root/' in line:
                continue
            
            for pattern in self.suspicious_paths:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(create_mcp_finding(
                        rule_id="mcp/config-poisoning-suspicious-path",
                        message=f"[CONFIG POISONING] Suspicious system path in configuration: Access to sensitive system path '{pattern}'",
                        file_path=file_path,
                        line=i,
                        code_snippet=stripped[:200] if len(stripped) > 200 else stripped,
                        pattern_type="config_poisoning",
                        pattern=f"suspicious-path:{pattern}",
                        confidence=CONFIDENCE_LEVELS['HIGH']
                    ))
                    break
        
        return findings
    
    def _check_config_injection(self, lines: List[str], file_path: str) -> List[Finding]:
        findings = []
        
        file_lower = file_path.lower()
        is_test_file = (
            file_lower.endswith('_test.go') or
            file_lower.endswith('.test.js') or
            file_lower.endswith('.test.ts') or
            file_lower.endswith('.test.py') or
            '/test/' in file_lower or
            'test_' in file_lower or
            '_test_' in file_lower
        )
        
        if is_test_file:
            return findings
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('/*'):
                continue
            
            constructor_patterns = [
                r'func\s+(New|Create|Make|Build|Init|Setup)\w+',
                r'function\s+(new|create|make|build|init|setup)\w+',
                r'const\s+(new|create|make|build|init|setup)\w+',
                r'class\s+\w+.*(constructor|Factory|Builder)',
            ]
            
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in constructor_patterns):
                continue
            
            if re.search(r'container\.(register|bind|resolve)', line, re.IGNORECASE):
                continue
            
            if re.search(r'di\.(register|bind|resolve)', line, re.IGNORECASE):
                continue
            
            if re.search(r'inject\(|injection\(', line, re.IGNORECASE):
                if 'useValue' in line or 'useClass' in line or 'useFactory' in line:
                    continue
            
            if ('eval' in line.lower() or 'Function' in line) and ('config' in line.lower() or 'process.env' in line):
                if 'eval(' not in line and 'Function(' not in line:
                    continue
                findings.append(create_mcp_finding(
                    rule_id="mcp/config-poisoning-injection",
                    message="[CONFIG POISONING] Code injection in configuration: Dynamic code execution with configuration data",
                    file_path=file_path,
                    line=i,
                    code_snippet=stripped[:200] if len(stripped) > 200 else stripped,
                    pattern_type="config_poisoning",
                    pattern="config_injection",
                    confidence=CONFIDENCE_LEVELS['CRITICAL']
                ))
        
        return findings
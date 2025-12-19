import re
import unicodedata
from typing import List, Dict, Set, Tuple, Any
from scanner.analyzers.common.scanner import Finding
from scanner.analyzers.common.mcp_utils import create_mcp_finding
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS

class ToolNameSpoofingDetector:
    
    def __init__(self):
        self.system_keywords = [
            'system', 'admin', 'root', 'sudo', 'superuser',
            'administrator', 'sysadmin', 'kernel', 'os',
            'auth', 'login', 'password', 'credential', 'token',
            'key', 'certificate', 'security', 'encryption',
            'decrypt', 'authenticate', 'authorize',
            'network', 'firewall', 'proxy', 'vpn', 'ssh',
            'ftp', 'telnet', 'dns', 'dhcp', 'router',
            'process', 'service', 'daemon', 'kill', 'terminate',
            'restart', 'shutdown', 'reboot', 'startup',
            
            'drop_table', 'drop_database', 'grant_permission',
            'revoke_permission', 'create_user', 'delete_user',
            'format_drive', 'partition', 'mount', 'unmount',
            'chmod', 'chown', 'setuid', 'setgid',
        ]
        self.suspicious_actions = [
            'execute', 'run', 'launch', 'start', 'invoke',
            'call', 'trigger', 'activate', 'enable', 'disable',
            'install', 'uninstall', 'deploy', 'configure',
            'modify', 'change', 'alter', 'update', 'upgrade',
            'delete', 'remove', 'destroy', 'wipe', 'clean',
            'backup', 'restore', 'reset', 'initialize',
        ]
        self.unicode_confusables = {
            'а': 'a',
            'е': 'e',
            'о': 'o',
            'р': 'p',
            'с': 'c',
            'х': 'x',
            'у': 'y',
            'ѕ': 's',
            'і': 'i',
            'α': 'a',
            'ο': 'o',
            'ρ': 'p',
            'τ': 't',
            'υ': 'u',
            'χ': 'x',
            '𝐚': 'a',
            '𝐞': 'e',
            '𝐢': 'i',
            '𝐨': 'o',
            'ǝ': 'e',
            'ɑ': 'a',
            'ɵ': 'o',
        }
    
    def get_name(self) -> str:
        return "tool-name-spoofing"
    
    def check(self, calls: List[Dict], tainted_vars: Set[str],
              lines: List[str], file_path: str,
              ast_result: Dict = None, taint_result: Dict = None, cfg: Any = None) -> List[Finding]:
        
        findings = []
        
        if not ast_result:
            return findings
        
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
        
        functions = ast_result.get('functions', [])
        
        for func in functions:
            func_name = func.get('name', '')
            
            if re.match(r'^(Test|test_|_test)', func_name, re.IGNORECASE):
                continue
            
            if func_name.startswith('anonymous_') or re.match(r'^anonymous\d+', func_name, re.IGNORECASE):
                continue
            
            if ' callback' in func_name.lower() or '.callback' in func_name.lower():
                continue
            
            if re.search(r'\.(map|filter|reduce|forEach|some|every|find|sort|flatMap)\s+callback', func_name, re.IGNORECASE):
                continue
            
            if re.search(r'\.(catch|then|finally)\s+callback', func_name, re.IGNORECASE):
                continue
            
            if re.search(r'\.(preprocess|transform|validate)', func_name, re.IGNORECASE):
                continue
            
            if re.search(r'^[a-z]\.[a-z]', func_name):
                continue
            
            if func_name.startswith('find') and func_name.endswith('Root'):
                if func_name in ['findProjectRoot', 'findRepoRoot', 'findModuleRoot', 'findWorkspaceRoot']:
                    continue
            
            if func_name.startswith('get') and func_name.endswith('Root'):
                if func_name in ['getGitRoot', 'getProjectRoot', 'getRepoRoot', 'getModuleRoot']:
                    continue
            
            if func_name in ['getAllKeys', 'getAllItems', 'getAllValues']:
                if is_test_file:
                    continue
            
            if not self._is_exported(func):
                continue
            
            findings.extend(self._check_system_privilege_spoofing(
                func_name, file_path, func.get('line', 0)
            ))
            findings.extend(self._check_excessive_capabilities(
                func_name, file_path, func.get('line', 0)
            ))
        
        return findings
    
    def _is_exported(self, func: Dict) -> bool:
        is_exported = func.get('is_exported', False)
        func_name = func.get('name', '')
        is_public = not func_name.startswith('_')
        return is_exported or is_public
    
    def _check_system_privilege_spoofing(self, func_name: str,
                                        file_path: str, line: int) -> List[Finding]:
        findings = []
        
        func_lower = func_name.lower()
        normalized_name = func_lower.strip()
        
        suspicious_prefixes = ['malicious_', 'evil_', 'fake_', 'hijack_', 'backdoor_',
                              'bypass_', 'override_', 'shadow_', 'replace_', 'steal_']
        suspicious_suffixes = ['_hack', '_exploit', '_vulnerability', '_backdoor', '_bypass']
        
        dangerous_keywords = ['root', 'sudo', 'superuser', 'admin_all', 'god_mode',
                            'drop_table', 'drop_database', 'format_drive', 'chmod',
                            'setuid', 'setgid', 'kill_all', 'terminate_all']
        
        for keyword in self.system_keywords:
            if keyword in func_lower:
                has_suspicious_prefix = any(func_lower.startswith(prefix) for prefix in suspicious_prefixes)
                has_suspicious_suffix = any(func_lower.endswith(suffix) for suffix in suspicious_suffixes)
                is_dangerous_keyword = keyword in dangerous_keywords
                
                if has_suspicious_prefix or has_suspicious_suffix or is_dangerous_keyword:
                    findings.append(create_mcp_finding(
                        rule_id="mcp/tool-name-spoofing-system",
                        message=f"[TOOL NAME SPOOFING] Tool name '{func_name}' contains system keyword '{keyword}' "
                                f"with suspicious pattern - Possible attempt to impersonate system functionality",
                        file_path=file_path,
                        line=line,
                        code_snippet=f"function {func_name}()",
                        pattern_type="tool_name_spoofing",
                        pattern=f"system_keyword:{keyword}",
                        confidence=CONFIDENCE_LEVELS['HIGH']
                    ))
                    break
        
        for action in self.suspicious_actions:
            if action in func_lower:
                for keyword in self.system_keywords:
                    if keyword in func_lower:
                        if keyword in dangerous_keywords or action in ['destroy', 'wipe', 'kill', 'terminate']:
                            findings.append(create_mcp_finding(
                                rule_id="mcp/tool-name-spoofing-dangerous-combo",
                                message=f"[TOOL NAME SPOOFING] Tool name '{func_name}' combines dangerous action '{action}' "
                                        f"with system keyword '{keyword}' - High risk of privilege escalation",
                                file_path=file_path,
                                line=line,
                                code_snippet=f"function {func_name}()",
                                pattern_type="tool_name_spoofing",
                                pattern=f"dangerous_combo:{action}+{keyword}",
                                confidence=CONFIDENCE_LEVELS['CRITICAL'],
                                cwe="CWE-250"
                            ))
                            break
        
        return findings
    
    def _check_unicode_homograph(self, func_name: str,
                                file_path: str, line: int) -> List[Finding]:
        
        findings = []
        
        suspicious_chars = []
        normalized_name = ''
        
        for char in func_name:
            if char in self.unicode_confusables:
                suspicious_chars.append((char, self.unicode_confusables[char]))
                normalized_name += self.unicode_confusables[char]
            else:
                normalized_name += char
        
        if suspicious_chars:
            char_info = ', '.join([f"'{s}'→'{n}'" for s, n in suspicious_chars])
            
            findings.append(create_mcp_finding(
                rule_id="mcp/tool-name-spoofing-unicode",
                message=f"[TOOL NAME SPOOFING] Tool name '{func_name}' uses Unicode homograph attack - "
                        f"Confusable characters detected ({char_info})",
                file_path=file_path,
                line=line,
                code_snippet=f"function {func_name}()",
                pattern_type="tool_name_spoofing",
                pattern="unicode_homograph",
                confidence=CONFIDENCE_LEVELS['CRITICAL']
            ))
        
        return findings
    
    def _check_excessive_capabilities(self, func_name: str,
                                     file_path: str, line: int) -> List[Finding]:
        
        findings = []
        
        file_lower = file_path.lower()
        is_test_file = (
            file_lower.endswith('_test.go') or
            file_lower.endswith('.test.js') or
            file_lower.endswith('.test.ts') or
            file_lower.endswith('.test.py') or
            '/test/' in file_lower or
            'test_' in file_lower or
            '_test_' in file_lower or
            'mock' in file_lower or
            'helper' in file_lower
        )
        
        if is_test_file:
            return findings
        
        func_lower = func_name.lower()
        
        common_crud_patterns = [
            r'^(get|set|fetch|load|save|create|update|delete|remove|find|list|add|clear)all',
            r'^(get|set|fetch|load|save|create|update|delete|remove|find|list|add|clear)all(keys|items|values|entries|records|data)',
        ]
        
        if any(re.match(pattern, func_lower) for pattern in common_crud_patterns):
            return findings
        
        capability_words = ['all', 'any', 'every', 'unlimited', 'full', 'complete', 
                           'total', 'absolute', 'maximum', 'super', 'ultimate', 'master']
        
        capability_count = sum(1 for word in capability_words if word in func_lower)
        
        if capability_count >= 1:
            system_count = sum(1 for keyword in self.system_keywords if keyword in func_lower)
            
            if system_count >= 1:
                findings.append(create_mcp_finding(
                    rule_id="mcp/tool-name-spoofing-excessive-caps",
                    message=f"[TOOL NAME SPOOFING] Tool name '{func_name}' claims excessive capabilities - "
                            f"Combination of capability and system keywords suggests overreach",
                    file_path=file_path,
                    line=line,
                    code_snippet=f"function {func_name}()",
                    pattern_type="tool_name_spoofing",
                    pattern="excessive_capabilities",
                    confidence=CONFIDENCE_LEVELS['HIGH'],
                    cwe="CWE-1007"
                ))
        
        inflated_patterns = [
            r'god_?mode', r'admin_?all', r'super_?user', r'root_?access',
            r'full_?control', r'unlimited_?power', r'master_?key',
            r'backdoor', r'bypass', r'override_?all'
        ]
        
        for pattern in inflated_patterns:
            if re.search(pattern, func_lower):
                findings.append(create_mcp_finding(
                    rule_id="mcp/tool-name-spoofing-inflated",
                    message=f"[TOOL NAME SPOOFING] Tool name '{func_name}' contains inflated capability claim - "
                            f"Pattern '{pattern}' suggests malicious intent",
                    file_path=file_path,
                    line=line,
                    code_snippet=f"function {func_name}()",
                    pattern_type="tool_name_spoofing",
                    pattern=f"inflated:{pattern}",
                    confidence=CONFIDENCE_LEVELS['CRITICAL'],
                    cwe="CWE-1007"
                ))
        
        return findings
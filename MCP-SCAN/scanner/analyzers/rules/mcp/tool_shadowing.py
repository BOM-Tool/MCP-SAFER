import re
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict
from scanner.analyzers.common.scanner import Finding
from scanner.analyzers.common.mcp_utils import create_mcp_finding, get_line_snippet
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS

class ToolShadowingDetector:

    def __init__(self):
        
        self.shadowing_patterns = [
            r'override_(\w+)',
            r'replace_(\w+)',
            r'fake_(\w+)',
            r'mock_(\w+)',
            r'shadow_(\w+)',
            
            r'malicious_(\w+)',
            r'hijack_(\w+)',
            r'backdoor_(\w+)',
            r'evil_(\w+)',
            
            r'(\w+)_v2',
            r'(\w+)_new',
            r'(\w+)_updated',
            r'(\w+)_fixed',
            
            r'(\w+)_internal',
            r'(\w+)_private',
            r'(\w+)_admin',
            r'(\w+)_root',
        ]
        
        self.registration_patterns = [
            r'tools\.register\s*\(\s*["\'](\w+)["\']',
            r'addTool\s*\(\s*["\'](\w+)["\']',
            r'defineTool\s*\(\s*["\'](\w+)["\']',
            r'createTool\s*\(\s*["\'](\w+)["\']',
            
            r'"name"\s*:\s*["\'](\w+)["\']',
            r'toolName\s*:\s*["\'](\w+)["\']',
            r'function\s+(\w+)\s*\(',
            r'export\s+function\s+(\w+)',
            r'export\s+const\s+(\w+)',
        ]
        
        self.conflict_indicators = [
            r'overrideExisting\s*:\s*true',
            r'forceRegister\s*:\s*true',
            r'replaceTool\s*:\s*true',
            r'shadowMode\s*:\s*true',
            
            r'//\s*shadow\s+tool[:\s]+(\w+)',
            r'//\s*override\s+tool[:\s]+(\w+)',
            r'//\s*replace\s+tool[:\s]+(\w+)',
            r'/\*\s*shadow\s+tool[:\s]+(\w+)\s*\*/',
            
            r'eval\s*\(\s*["\']registerTool',
            r'Function\s*\(\s*["\']return\s+registerTool',
        ]
        
        self.tool_registrations = defaultdict(list)
        self.server_tools = defaultdict(set)
    
    def get_name(self) -> str:
        return "tool-shadowing"
    
    def check(self, calls: List[Dict], tainted_vars: Set[str], 
              lines: List[str], file_path: str, 
              ast_result: Dict = None, taint_result: Dict = None, cfg: Any = None) -> List[Finding]:
        
        findings = []
        
        if not ast_result:
            return findings
        
        file_tools = self._extract_tool_registrations(lines, file_path, ast_result)
        
        findings.extend(self._check_shadowing_patterns(
            file_tools, file_path, lines
        ))
        
        findings.extend(self._check_malicious_replacement(
            file_tools, file_path, lines
        ))
        
        findings.extend(self._check_namespace_pollution(
            file_tools, file_path, lines
        ))
        
        findings.extend(self._check_registration_manipulation(
            file_tools, file_path, lines
        ))
        
        findings.extend(self._check_cross_file_conflicts(
            file_tools, file_path, lines
        ))
        
        self._update_tool_registry(file_tools, file_path)
        
        return findings
    
    def _extract_tool_registrations(self, lines: List[str], file_path: str, 
                                   ast_result: Dict) -> List[Dict]:
        
        tools = []
        
        file_lower = file_path.lower()
        if (file_lower.endswith('_test.go') or 
            file_lower.endswith('.test.js') or 
            file_lower.endswith('.test.ts') or 
            file_lower.endswith('.test.py') or
            '/test/' in file_lower or
            'test_' in file_lower or
            '_test_' in file_lower):
            return tools
        
        builtin_functions = {
            'init', 'main', 'setup', 'teardown', 'beforeeach', 'aftereach',
            'beforeall', 'afterall', 'constructor', 'destructor',
            'getinstance', 'singleton', 'factory'
        }
        
        functions = ast_result.get('functions', [])
        for func in functions:
            func_name = func.get('name', '')
            
            if func_name.startswith('anonymous_') or re.match(r'^anonymous\d+', func_name, re.IGNORECASE):
                continue
            
            if func_name.lower() in builtin_functions:
                continue
            if self._is_exported(func):
                if self._is_valid_tool_name(func_name):
                    tools.append({
                        'name': func_name,
                        'line': func.get('line', 0),
                        'type': 'function',
                        'file': file_path
                    })
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            for pattern in self.registration_patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        tool_name = match[0] if match[0] else (match[1] if len(match) > 1 else None)
                    else:
                        tool_name = match
                    
                    if not tool_name:
                        continue
                    
                    if tool_name and self._is_valid_tool_name(tool_name):
                        tools.append({
                            'name': tool_name,
                            'line': line_num,
                            'type': 'registration',
                            'file': file_path,
                            'source_line': line.strip()
                        })
        
        return tools
    
    def _check_shadowing_patterns(self, tools: List[Dict], file_path: str, 
                                  lines: List[str]) -> List[Finding]:
        
        findings = []
        
        for tool in tools:
            tool_name = tool['name']
            line = tool['line']
            
            for pattern in self.shadowing_patterns:
                match = re.match(pattern, tool_name, re.IGNORECASE)
                if match and len(match.groups()) > 0:
                    base_tool = match.group(1)
                    findings.append(create_mcp_finding(
                        rule_id="mcp/tool-shadowing-pattern",
                        message=f"[TOOL SHADOWING] Tool '{tool_name}' uses suspicious shadowing pattern "
                                f"that may override existing tool '{base_tool}'",
                        file_path=file_path,
                        line=line,
                        code_snippet=get_line_snippet(lines, line),
                        pattern_type="tool_shadowing",
                        pattern=f"shadowing_pattern:{pattern}",
                        confidence=CONFIDENCE_LEVELS['HIGH']
                    ))
        
        return findings
    
    def _check_malicious_replacement(self, tools: List[Dict], file_path: str,
                                    lines: List[str]) -> List[Finding]:
        
        findings = []
        
        for tool in tools:
            tool_name = tool['name']
            line = tool['line']
            
            malicious_prefixes = ['malicious_', 'evil_', 'hijack_', 'backdoor_', 'trojan_']
            for prefix in malicious_prefixes:
                if tool_name.startswith(prefix):
                    base_tool = tool_name[len(prefix):]
                    findings.append(create_mcp_finding(
                        rule_id="mcp/tool-shadowing-malicious",
                        message=f"[TOOL SHADOWING] Tool '{tool_name}' uses malicious prefix '{prefix}' "
                                f"to replace '{base_tool}'",
                        file_path=file_path,
                        line=line,
                        code_snippet=get_line_snippet(lines, line),
                        pattern_type="tool_shadowing",
                        pattern=f"malicious_prefix:{prefix}",
                        confidence=CONFIDENCE_LEVELS['CRITICAL']
                    ))
            
            suspicious_suffixes = ['_hijack', '_trojan', '_backdoor', '_evil', '_malicious']
            for suffix in suspicious_suffixes:
                if tool_name.endswith(suffix):
                    base_tool = tool_name[:-len(suffix)]
                    findings.append(create_mcp_finding(
                        rule_id="mcp/tool-shadowing-malicious-suffix",
                        message=f"[TOOL SHADOWING] Tool '{tool_name}' uses malicious suffix '{suffix}' "
                                f"to replace '{base_tool}'",
                        file_path=file_path,
                        line=line,
                        code_snippet=get_line_snippet(lines, line),
                        pattern_type="tool_shadowing",
                        pattern=f"malicious_suffix:{suffix}",
                        confidence=CONFIDENCE_LEVELS['CRITICAL']
                    ))
        
        return findings
    
    def _check_namespace_pollution(self, tools: List[Dict], file_path: str,
                                  lines: List[str]) -> List[Finding]:
        
        findings = []
        
        for tool in tools:
            tool_name = tool['name']
            line = tool['line']
            
            internal_patterns = [
                (r'(\w+)_internal', ['internal']),
                (r'(\w+)_private', ['private']), 
                (r'(\w+)_admin', ['admin']),
                (r'(\w+)_root', ['root']),
                (r'(\w+)_system', ['system']),
                (r'(\w+)_core', ['core']),
            ]
            
            for pattern, keywords in internal_patterns:
                match = re.match(pattern, tool_name, re.IGNORECASE)
                if match:
                    base_tool = match.group(1)
                    existing_registrations = len(self.tool_registrations.get(tool_name, []))
                    has_malicious_context = any(
                        kw in get_line_snippet(lines, line).lower()
                        for kw in ['override', 'replace', 'shadow', 'force']
                    )
                    
                    if existing_registrations > 0 or has_malicious_context:
                        findings.append(create_mcp_finding(
                            rule_id="mcp/tool-shadowing-namespace",
                            message=f"[TOOL SHADOWING] Tool '{tool_name}' pollutes internal namespace "
                                    f"for tool '{base_tool}' - May cause confusion",
                            file_path=file_path,
                            line=line,
                            code_snippet=get_line_snippet(lines, line),
                            pattern_type="tool_shadowing",
                            pattern=f"namespace_pollution:{pattern}",
                            confidence=CONFIDENCE_LEVELS['HIGH'] if has_malicious_context else CONFIDENCE_LEVELS['MEDIUM']
                        ))
        
        return findings
    
    def _check_registration_manipulation(self, tools: List[Dict], file_path: str,
                                        lines: List[str]) -> List[Finding]:
        
        findings = []
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                comment_patterns = [
                    r'//\s*shadow\s+tool[:\s]+(\w+)',
                    r'//\s*override\s+tool[:\s]+(\w+)',
                    r'//\s*replace\s+tool[:\s]+(\w+)',
                    r'/\*\s*shadow\s+tool[:\s]+(\w+)\s*\*/',
                ]
                for pattern in comment_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(create_mcp_finding(
                            rule_id="mcp/tool-shadowing-manipulation",
                            message=f"[TOOL SHADOWING] Registration manipulation detected - "
                                    f"Explicit override/force registration flag found",
                            file_path=file_path,
                            line=line_num,
                            code_snippet=line.strip(),
                            pattern_type="tool_shadowing",
                            pattern=f"registration_manipulation:{pattern}",
                            confidence=CONFIDENCE_LEVELS['CRITICAL']
                        ))
                        break
                continue
            
            code_patterns = [
                r'overrideExisting\s*:\s*true',
                r'forceRegister\s*:\s*true',
                r'replaceTool\s*:\s*true',
                r'shadowMode\s*:\s*true',
                r'eval\s*\(\s*["\']registerTool',
                r'Function\s*\(\s*["\']return\s+registerTool',
            ]
            for pattern in code_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(create_mcp_finding(
                        rule_id="mcp/tool-shadowing-manipulation",
                        message=f"[TOOL SHADOWING] Registration manipulation detected - "
                                f"Explicit override/force registration flag found",
                        file_path=file_path,
                        line=line_num,
                        code_snippet=line.strip(),
                        pattern_type="tool_shadowing",
                        pattern=f"registration_manipulation:{pattern}",
                        confidence=CONFIDENCE_LEVELS['HIGH']
                    ))
                    break
        
        return findings
    
    def _is_exported(self, func: Dict) -> bool:
        
        is_exported = func.get('is_exported', False)
        func_name = func.get('name', '')
        is_public = not func_name.startswith('_')
        return is_exported or is_public
    
    def _is_valid_tool_name(self, name: str) -> bool:
        
        if not name or len(name) < 2:
            return False
        
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            return False
        
        builtin_functions = {
            'init', 'main', 'setup', 'teardown', 'beforeeach', 'aftereach',
            'beforeall', 'afterall', 'constructor', 'destructor',
            'getinstance', 'singleton', 'factory'
        }
        if name.lower() in builtin_functions:
            return False
        
        skip_patterns = [
            r'^[A-Z_]+$',
            r'^[a-z]+$',
            r'^test',
            r'^mock',
            r'^debug',
        ]
        
        for pattern in skip_patterns:
            if re.match(pattern, name, re.IGNORECASE):
                return False
        
        return True
    
    def _get_line_snippet(self, lines: List[str], line_num: int) -> str:
        
        if 0 < line_num <= len(lines):
            return lines[line_num - 1].strip()
        return ""
    
    def _update_tool_registry(self, tools: List[Dict], file_path: str):
        
        server_name = self._extract_server_name(file_path)
        
        builtin_functions = {
            'init', 'main', 'setup', 'teardown', 'beforeeach', 'aftereach',
            'beforeall', 'afterall', 'constructor', 'destructor',
            'getinstance', 'singleton', 'factory'
        }
        
        for tool in tools:
            tool_name = tool['name']
            
            if tool_name.startswith('anonymous_') or re.match(r'^anonymous\d+', tool_name, re.IGNORECASE):
                continue
            if tool_name.lower() in builtin_functions:
                continue
            
            self.tool_registrations[tool_name].append({
                'file': file_path,
                'line': tool['line'],
                'server': server_name
            })
            self.server_tools[server_name].add(tool_name)
    
    def _extract_server_name(self, file_path: str) -> str:
        
        from pathlib import Path
        return Path(file_path).stem
    
    def _check_cross_file_conflicts(self, file_tools: List[Dict], 
                                   file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        file_lower = file_path.lower()
        if (file_lower.endswith('_test.go') or 
            file_lower.endswith('.test.js') or 
            file_lower.endswith('.test.ts') or 
            file_lower.endswith('.test.py') or
            '/test/' in file_lower or
            'test_' in file_lower or
            '_test_' in file_lower):
            return findings
        
        builtin_functions = {
            'init', 'main', 'setup', 'teardown', 'beforeeach', 'aftereach',
            'beforeall', 'afterall', 'constructor', 'destructor',
            'getinstance', 'singleton', 'factory'
        }
        
        for tool in file_tools:
            tool_name = tool['name']
            line = tool['line']
            
            if tool_name.startswith('anonymous_') or re.match(r'^anonymous\d+', tool_name, re.IGNORECASE):
                continue
            
            if tool_name.lower() in builtin_functions:
                continue
            
            existing_registrations = self.tool_registrations.get(tool_name, [])
            
            existing_registrations = [
                reg for reg in existing_registrations
                if not (reg['file'].lower().endswith('_test.go') or 
                       reg['file'].lower().endswith('.test.js') or 
                       reg['file'].lower().endswith('.test.ts') or 
                       reg['file'].lower().endswith('.test.py') or
                       '/test/' in reg['file'].lower() or
                       'test_' in reg['file'].lower() or
                       '_test_' in reg['file'].lower())
            ]
            
            if len(existing_registrations) > 0:
                existing_files = [reg['file'] for reg in existing_registrations]
                existing_servers = set([reg['server'] for reg in existing_registrations])
                current_server = self._extract_server_name(file_path)
                
                if len(existing_servers) > 1 or current_server not in existing_servers:
                    findings.append(create_mcp_finding(
                        rule_id="mcp/tool-shadowing-cross-file",
                        message=f"[TOOL SHADOWING] Tool '{tool_name}' is registered in multiple files/servers - "
                                f"May override legitimate tool due to PATH/registry priority. "
                                f"Existing: {', '.join(existing_files[:2])}",
                        file_path=file_path,
                        line=line,
                        code_snippet=get_line_snippet(lines, line),
                        pattern_type="tool_shadowing",
                        pattern=f"cross_file_conflict:{tool_name}",
                        confidence=CONFIDENCE_LEVELS['HIGH']
                    ))
                else:
                    findings.append(create_mcp_finding(
                        rule_id="mcp/tool-shadowing-duplicate",
                        message=f"[TOOL SHADOWING] Tool '{tool_name}' is registered multiple times - "
                                f"Later registration may shadow earlier one. "
                                f"Previous: {existing_registrations[0]['file']}:{existing_registrations[0]['line']}",
                        file_path=file_path,
                        line=line,
                        code_snippet=get_line_snippet(lines, line),
                        pattern_type="tool_shadowing",
                        pattern=f"duplicate_registration:{tool_name}",
                        confidence=CONFIDENCE_LEVELS['HIGH']
                    ))
        
        return findings
    
    def get_cross_file_conflicts(self) -> List[Dict]:
        
        conflicts = []
        
        for tool_name, registrations in self.tool_registrations.items():
            if len(registrations) > 1:
                servers = [reg['server'] for reg in registrations]
                unique_servers = set(servers)
                
                if len(unique_servers) > 1:
                    conflicts.append({
                        'tool_name': tool_name,
                        'registrations': registrations,
                        'servers': list(unique_servers),
                        'conflict_type': 'cross_server'
                    })
                else:
                    conflicts.append({
                        'tool_name': tool_name,
                        'registrations': registrations,
                        'servers': list(unique_servers),
                        'conflict_type': 'same_server_multiple'
                    })
        
        return conflicts
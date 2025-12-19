import re
import ast
from typing import List, Dict, Set, Optional, Tuple, Any
from scanner.analyzers.common.scanner import Finding, CommonPatterns
from scanner.analyzers.common.base_detector import BaseDetector
from scanner.analyzers.common.utils import extract_var_name

class CommandInjectionDataFlowAnalyzer:
    
    USER_INPUT_SOURCES = [
        'FormValue', 'PostFormValue', 'Header.Get', 'Getenv',
        'Query()', 'Cookie', 'ReadFile', 'ReadAll', 'ReadDir',
        'Scan', 'Unmarshal', 'Decode',
        'URL.Query', 'Request.', 'Args', 'LookupEnv',
        'flag.String', 'flag.Parse', 'os.Args'
    ]
    
    USER_INPUT_PATTERNS = [
        r'\$\{', r'%s', r'%v', r'%d', r'%f', r'%t', r'%b', r'%x', r'%o',
        r'.*\.FormValue', r'.*\.Query', r'.*\.PostFormValue', r'.*\.Header\.Get',
        r'.*\.URL\.Query', r'.*\.Request\.', r'.*\.Args', r'.*\.Getenv', r'.*\.LookupEnv',
        r'.*\.flag\.String', r'.*\.flag\.Parse', r'.*\.os\.Args',
        r'.*\.ReadFile', r'.*\.ReadAll', r'.*\.ReadDir', r'.*\.Scan'
    ]
    
    def __init__(self):
        self.user_input_sources = self.USER_INPUT_SOURCES
        
        self.sanitizer_functions = [
            'strings.TrimSpace', 'strings.Trim', 'strings.Replace',
            'html.EscapeString', 'url.QueryEscape', 'regexp.MustCompile',
            'exec.Command', 'exec.CommandContext'
        ]
        
        self.validation_patterns = [
            r'regexp\.MatchString',  
            r'regexp\.MustCompile',
            r'strings\.HasPrefix',
            r'strings\.Contains', 
            r'\.match\s*\(', 
            r'\.test\s*\(',  
        ]
        self.validation_patterns_compiled = [re.compile(p) for p in self.validation_patterns]
        
        self.dangerous_sinks = {
            'critical': [
                ('exec', 'Command'), ('exec', 'CommandContext'),
                ('C', 'system'), ('C', 'popen'), ('C', 'execl'),
                ('C', 'execlp'), ('C', 'execle'), ('C', 'execv'),
                ('C', 'execvp'), ('C', 'execve')
            ],
            'high': [
                ('os', 'StartProcess'), ('syscall', 'Exec'),
                ('syscall', 'ForkExec'), ('syscall', 'StartProcess'),
                ('unix', 'Exec'), ('unix', 'ForkExec')
            ],
            'medium': [
                ('exec', 'LookPath'), ('plugin', 'Open'), ('plugin', 'Lookup')
            ]
        }
        
        self.shell_executables = {
            'sh', 'bash', 'zsh', 'ksh', 'csh', 'tcsh', 'fish',
            'cmd', 'cmd.exe', 'command.com',
            'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
            'wsl', 'wsl.exe', 'bash.exe',
        }
        
        self.shell_paths = {
            '/bin/sh', '/bin/bash', '/bin/zsh', '/bin/ksh',
            '/usr/bin/sh', '/usr/bin/bash', '/usr/bin/zsh',
            '/usr/local/bin/bash', '/usr/local/bin/zsh',
        }
        
        self.shell_flags = ['-c', '/c', '/C', '-Command', '-EncodedCommand']
        self.user_input_patterns_compiled = [re.compile(p) for p in self.USER_INPUT_PATTERNS]
    
    def analyze_data_flow(self, ast_result: Dict[str, Any], taint_result: Dict[str, Any]) -> List[Dict]:
        findings = []
        
        tainted_vars = set(taint_result.get('all_tainted', []))
        
        taint_sources = {source.get('var_name') for source in ast_result.get('taint_sources', [])}
        
        for call in ast_result.get('calls', []):
            pkg = call.get('package', '')
            fn = call.get('function', '')
            args = call.get('args', [])
            line = call.get('line', 0)
            is_taint_sink = call.get('IsTaintSink', False)
            
            is_dangerous = False
            severity = "medium"
            for sev, sinks in self.dangerous_sinks.items():
                if (pkg, fn) in sinks:
                    is_dangerous = True
                    severity = sev
                    break
            
            if not is_dangerous and not is_taint_sink:
                continue
            
            is_shell_context, shell_type = self._is_shell_execution_context(call, args)
            
            if is_shell_context and shell_type in ['shell_with_flag', 'shell_path_with_flag', 'full_path_shell_with_flag']:
                severity = 'critical'
            
            for arg in args:
                if self._is_string_literal_with_shell_substring(arg):
                    continue
                
                arg_var = self._extract_var_name(arg)
                if arg_var and (arg_var in tainted_vars or arg_var in taint_sources):
                    findings.append({
                        'severity': severity,
                        'message': f"Data flow: Tainted variable '{arg_var}' reaches {pkg}.{fn}()",
                        'line': line,
                        'file': ast_result.get('file_path', ''),
                        'tainted_var': arg_var,
                        'sink': f"{pkg}.{fn}",
                        'shell_context': is_shell_context,
                        'shell_type': shell_type
                    })
                elif tainted_vars:
                    for tainted_var in tainted_vars:
                        if tainted_var in arg:
                            findings.append({
                                'severity': severity,
                                'message': f"Data flow: Tainted variable '{tainted_var}' in argument reaches {pkg}.{fn}()",
                                'line': line,
                                'file': ast_result.get('file_path', ''),
                                'tainted_var': tainted_var,
                                'sink': f"{pkg}.{fn}",
                                'shell_context': is_shell_context,
                                'shell_type': shell_type
                            })
                            break
        
        return findings
    
    def _extract_var_name(self, arg: str) -> str:
        return extract_var_name(arg)
    
    def _is_shell_execution_context(self, call: Dict, args: List[str]) -> Tuple[bool, str]:
        pkg = call.get('package', '')
        fn = call.get('function', '')
        
        if not args or len(args) == 0:
            return False, "no_args"
        
        first_arg = args[0].strip().strip('"\'')
        
        if first_arg in self.shell_executables:
            if len(args) > 1 and args[1].strip().strip('"\'') in self.shell_flags:
                return True, "shell_with_flag"
            return True, "shell_executable"
        
        if first_arg in self.shell_paths:
            if len(args) > 1 and args[1].strip().strip('"\'') in self.shell_flags:
                return True, "shell_path_with_flag"
            return True, "shell_path"
        
        if '/' in first_arg:
            basename = first_arg.split('/')[-1]
            if basename in self.shell_executables:
                if len(args) > 1 and args[1].strip().strip('"\'') in self.shell_flags:
                    return True, "full_path_shell_with_flag"
                return True, "full_path_shell"
        
        return False, "not_shell"
    
    def _is_string_literal_with_shell_substring(self, arg: str) -> bool:
        arg = arg.strip()
        if not (arg.startswith('"') and arg.endswith('"')) and not (arg.startswith("'") and arg.endswith("'")):
            return False
        
        content = arg.strip('"\'').lower()
        
        for shell in self.shell_executables:
            if shell in content and shell != content:
                if content.startswith(shell) or content.endswith(shell):
                    continue
                return True
        
        return False
    
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

class CommandInjectionDetector(BaseDetector):
    
    SAFE_COMMANDS = [
        'git', 'ls', 'cat', 'echo', 'date', 'pwd', 'whoami',
        'mkdir', 'rmdir', 'cp', 'mv', 'chmod', 'chown',
        'grep', 'find', 'sort', 'uniq', 'wc', 'head', 'tail',
        'ps', 'top', 'kill', 'killall', 'df', 'du', 'free',
        'ping', 'curl', 'wget', 'ssh', 'scp', 'rsync'
    ]
    
    def __init__(self, language: str = "go"):
        super().__init__()
        self.language = language
        self.analyzer = CommandInjectionDataFlowAnalyzer()
        self.dangerous_patterns = [
            r';', r'&&', r'\|\|', r'\|', r'\$\(', r'`', r'>', r'<',
            r'&\s*$', r'\*', r'\?', r'\[.*\]', r'\{.*\}', r'~', r'#', r'\$\w+', r'\\\w',
        ]
        self.dangerous_patterns_compiled = [re.compile(p) for p in self.dangerous_patterns]
    
    def get_name(self) -> str:
        return "command-injection"
    
    def get_cwe(self) -> str:
        return "CWE-78"
    
    def get_rule_id(self, language: str = None) -> str:
        lang = language or self.language
        return f"{lang}/command-injection"
    
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
        if self._is_hardcoded_command(args, line_content):
            return True
        
        if self._is_safe_command(args):
            return True
        
        if self._is_const_command(args):
            return True
        
        line = call.get('line', 0)
        if lines and self._has_input_validation(lines, line, args):
            return True
        
        return False
    
    def _has_input_validation(self, lines: List[str], line: int, args: List[str]) -> bool:
        if not lines or line < 1 or line > len(lines):
            return False
        
        arg_vars = []
        for arg in args:
            var_name = self._extract_var_name(arg)
            if var_name and not var_name.startswith('"'):
                arg_vars.append(var_name)
        
        if not arg_vars:
            return False
        
        start = max(0, line - 4)
        end = line - 1
        
        if start >= end or end >= len(lines):
            return False
        
        for var in arg_vars:
            for i in range(start, end):
                if i >= len(lines):
                    break
                
                context_line = lines[i]
                
                merged_line = context_line
                if i + 1 < len(lines):
                    merged_line = context_line.rstrip() + ' ' + lines[i + 1].strip()
                if i + 2 < len(lines):
                    merged_line = merged_line.rstrip() + ' ' + lines[i + 2].strip()
                
                if var not in merged_line:
                    continue
                
                has_strong_validation = False
                for pattern in self.analyzer.validation_patterns_compiled:
                    if pattern.search(merged_line):
                        has_strong_validation = True
                        break
                
                if not has_strong_validation:
                    continue
                
                has_conditional = 'if' in merged_line
                
                if has_conditional and var in merged_line:
                    distance_to_sink = line - i - 1
                    
                    if 0 <= distance_to_sink <= 5:
                        return True
        
        return False
    
    def _extract_var_name(self, arg: str) -> str:
        return extract_var_name(arg)
    
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
            return f"Command injection: User input '{tainted_var}' in {pkg}.{fn}() - verify input sanitization"
        
        return f"Command injection: {pkg}.{fn}() - verify input sanitization"

    def _is_safe_command(self, args: List[str]) -> bool:
        if not args or len(args) == 0:
            return False
        
        first_arg = args[0].strip('"\'').lower()
        if first_arg not in self.SAFE_COMMANDS:
            return False
        
        for arg in args[1:]:
            arg_clean = arg.strip('"\'')
            for pattern in self.dangerous_patterns_compiled:
                if pattern.search(arg_clean):
                    return False
        
        return True

    def _is_const_command(self, args: List[str]) -> bool:
        if args and not args[0].startswith('"'):
            return args[0].isupper() or args[0].startswith('const')
        return False

    def _is_hardcoded_command(self, args: List[str], line_content: str) -> bool:
        if not args:
            return False
        
        for pattern in self.analyzer.USER_INPUT_PATTERNS:
            if re.search(pattern, line_content):
                return False
        
        return all(
            arg.strip().startswith('"') and arg.strip().endswith('"')
            for arg in args
        )
from abc import ABC, abstractmethod
from typing import List, Dict, Set, Any, Optional, Tuple
from scanner.analyzers.common.scanner import Finding, CommonPatterns
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS
from scanner.analyzers.common.utils import extract_var_name


class BaseDetector(ABC):

    CONFIDENCE_LEVELS = CONFIDENCE_LEVELS
    
    def __init__(self):
        self.analyzer = None
    
    @abstractmethod
    def get_name(self) -> str:
        pass
    
    @abstractmethod
    def get_cwe(self) -> str:
        pass
    
    @abstractmethod
    def get_rule_id(self, language: str) -> str:
        pass
    
    @abstractmethod
    def is_dangerous_sink(self, pkg: str, fn: str) -> bool:
        pass
    
    @abstractmethod
    def get_sink_severity(self, pkg: str, fn: str) -> str:
        pass
    
    @abstractmethod
    def is_safe_usage(self, call: Dict, line_content: str, args: List[str], 
                     file_path: str, lines: List[str]) -> bool:
        pass
    
    @abstractmethod
    def analyze_data_flow(self, ast_result: Dict[str, Any], 
                         taint_result: Dict[str, Any]) -> List[Dict]:
        pass
    
    @abstractmethod
    def build_finding_message(self, call: Dict, severity: str, 
                             base_var: str = None, data_flow_finding: Dict = None) -> str:
        pass
    
    def _normalize_indent(self, text: str) -> str:
        if not text:
            return text
        
        lines = text.split('\n')
        if not lines:
            return text
        
        normalized_for_indent = []
        for line in lines:
            leading_chars = 0
            tab_count = 0
            space_count = 0
            for char in line:
                if char == '\t':
                    tab_count += 1
                    leading_chars += 1
                elif char == ' ':
                    space_count += 1
                    leading_chars += 1
                else:
                    break
            converted = (' ' * (tab_count * 4 + space_count)) + line[leading_chars:]
            normalized_for_indent.append(converted)
        
        min_indent = None
        for line in normalized_for_indent:
            if line.strip(): 
                leading_spaces = len(line) - len(line.lstrip())
                if min_indent is None or leading_spaces < min_indent:
                    min_indent = leading_spaces
        
        if min_indent is None or min_indent == 0:
            return '\n'.join(lines)
        
        normalized_lines = []
        for line in normalized_for_indent:
            if line.strip():
                normalized_lines.append(line[min_indent:])
            else:
                normalized_lines.append('')
        
        return '\n'.join(normalized_lines)
    
    def _extract_var_name(self, arg: str) -> str:
        if not arg:
            return ""
        
        arg = arg.strip('"\'`')
        
        if arg == '()' or arg == '[]':
            return ""
        
        if '(' in arg and ')' in arg:
            parts = arg.split('(', 1)
            if len(parts) == 2:
                func_part = parts[0].strip()
                args_part = parts[1].rstrip(')').strip()
                
                if func_part in ['[]byte', 'string', 'int', 'int64', 'float64', 'bool', '[]string', '[]int']:
                    if args_part:
                        first_arg = args_part.split(',')[0].strip()
                        if first_arg and not first_arg.startswith('"') and not first_arg.startswith("'"):
                            arg = first_arg
                        else:
                            return ""
                    else:
                        return ""
                else:
                    arg = func_part
        
        arg = arg.strip('*&')
        arg = arg.strip()
        
        if not arg or arg == '()' or arg == '[]' or len(arg) < 1:
            return ""
        
        return arg
    
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
    
    def _check_taint_source_connection(self, arg_clean: str, taint_sources: Set[str], 
                                      data_flows: List[Dict], all_tainted: Set[str],
                                      taint_result: Dict[str, Any] = None) -> Tuple[bool, str]:
        if self._is_from_literal(arg_clean, data_flows, taint_result):
            return False, arg_clean
        
        if arg_clean in all_tainted:
            if data_flows:
                for flow in data_flows:
                    from_var = flow.get('from', '').strip()
                    to_var = flow.get('to', '').strip()
                    if to_var == arg_clean:
                        if self._is_literal_string(from_var):
                            continue
                        if from_var in taint_sources:
                            return True, arg_clean
                        if self._is_connected_to_taint_source(from_var, taint_sources, data_flows):
                            return True, arg_clean
        
        if arg_clean in taint_sources:
            return True, arg_clean
        
        if data_flows:
            for flow in data_flows:
                to_var = flow.get('to', '').strip()
                if to_var == arg_clean:
                    from_var = flow.get('from', '').strip()
                    if self._is_literal_string(from_var):
                        continue
                    if from_var in taint_sources:
                        return True, arg_clean
        
        return False, arg_clean
    
    def _is_literal_string(self, var_name: str) -> bool:
        if not var_name:
            return False
        return var_name.startswith('"') and var_name.endswith('"')
    
    def _is_from_literal(self, var_name: str, data_flows: List[Dict], taint_result: Dict[str, Any] = None) -> bool:
        if not var_name or not data_flows:
            return False
        
        if self._is_literal_string(var_name):
            return True
        
        param_to_literal = {}
        if taint_result:
            param_literals = taint_result.get('param_literals', {})
            param_to_literal.update(param_literals)
        
        visited = set()
        worklist = [var_name]
        
        while worklist:
            current = worklist.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            if current in param_to_literal:
                mapped = param_to_literal[current]
                if self._is_literal_string(mapped):
                    return True
                if mapped in param_to_literal and self._is_literal_string(param_to_literal[mapped]):
                    return True
            
            for flow in data_flows:
                if flow.get('flow_type') == 'function_argument':
                    from_var = flow.get('from', '').strip()
                    to_var = flow.get('to', '').strip()
                    
                    if to_var == current and '_param_' in to_var:
                        if self._is_literal_string(from_var):
                            return True
                        if from_var in param_to_literal:
                            if self._is_literal_string(param_to_literal[from_var]):
                                return True
                
                to_var = flow.get('to', '').strip()
                if to_var == current:
                    from_var = flow.get('from', '').strip()
                    
                    if self._is_literal_string(from_var):
                        return True
                    
                    if from_var in param_to_literal:
                        mapped = param_to_literal[from_var]
                        if self._is_literal_string(mapped):
                            return True
                    
                    if from_var and from_var not in visited:
                        worklist.append(from_var)
        
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
            path_sensitive_results = taint_result.get('path_sensitive_results', {})
        else:
            all_tainted = set()
            path_sensitive_results = {}
            taint_result = {'all_tainted': [], 'initial_tainted': [], 'path_sensitive_results': {}}
        
        data_flow_findings = self.analyze_data_flow(ast_result, taint_result)
        
        for call in calls:
            pkg = call.get('package', '')
            fn = call.get('function', '')
            args = call.get('args', [])
            line = call.get('line', 0)
            line_content = lines[line-1] if 0 < line <= len(lines) else ""
            
            if not self.is_dangerous_sink(pkg, fn):
                continue
            
            if self.is_safe_usage(call, line_content, args, file_path, lines):
                continue
            
            language = "go" if file_path.endswith('.go') else "typescript"
            if hasattr(self, 'language'):
                language = getattr(self, 'language', language)
            
            if CommonPatterns.is_test_file(file_path, language):
                path_tainted_for_line = self._get_path_tainted_for_line(
                    line, path_sensitive_results, cfg
                )
                tainted_vars_to_check = path_tainted_for_line if path_tainted_for_line else all_tainted
                
                severity, message, confidence = self._detect_vulnerability(
                    call, args, line, line_content, file_path,
                    data_flow_findings, data_flows, taint_sources, tainted_vars_to_check, taint_result, lines
                )
                
                if severity and message:
                    findings.append(Finding(
                        rule_id=self.get_rule_id(language),
                        severity="info",
                        message=f"Test file: {message}",
                        cwe=self.get_cwe(),
                        file=file_path,
                        line=line,
                        column=call.get('column', 0),
                        code_snippet=line_content,
                        pattern_type="test_file",
                        pattern=f"{pkg}.{fn}",
                        confidence=self.CONFIDENCE_LEVELS['INFO']
                    ))
                continue
            
            if CommonPatterns.has_safe_comment(line_content):
                continue
            
            path_tainted_for_line = self._get_path_tainted_for_line(
                line, path_sensitive_results, cfg
            )
            
            tainted_vars_to_check = path_tainted_for_line if path_tainted_for_line else all_tainted
            
            severity, message, confidence = self._detect_vulnerability(
                call, args, line, line_content, file_path,
                data_flow_findings, data_flows, taint_sources, tainted_vars_to_check, taint_result, lines
            )
            
            if severity and message:
                snippet_lines = []
                start_snippet = max(0, line - 3)
                end_snippet = min(len(lines), line + 3)
                
                for i in range(start_snippet, end_snippet):
                    if i < len(lines):
                        snippet_lines.append(lines[i].rstrip())
                
                snippet_text = '\n'.join(snippet_lines) if snippet_lines else line_content
                code_snippet = self._normalize_indent(snippet_text)
                
                findings.append(Finding(
                    rule_id=self.get_rule_id(language),
                    severity=severity,
                    message=message,
                    cwe=self.get_cwe(),
                    file=file_path,
                    line=line,
                    column=call.get('column', 0),
                    code_snippet=code_snippet,
                    pattern_type="data_flow_analysis" if any(
                        df.get('line') == line for df in data_flow_findings
                    ) else "ast_analysis",
                    pattern=f"{pkg}.{fn}",
                    confidence=confidence
                ))
        
        return findings
    
    def _get_path_tainted_for_line(self, line: int, path_sensitive_results: Dict[str, Set[str]], 
                                   cfg: Any) -> Optional[Set[str]]:
        if not path_sensitive_results or not cfg:
            return None
        
        line_tainted = set()
        
        for path_id, path_tainted in path_sensitive_results.items():
            if isinstance(path_tainted, (set, list)):
                line_tainted.update(path_tainted)
        
        return line_tainted if line_tainted else None
    
    def _detect_vulnerability(self, call: Dict, args: List[str], line: int,
                             line_content: str, file_path: str,
                             data_flow_findings: List[Dict],
                             data_flows: List[Dict],
                             taint_sources: Set[str],
                             all_tainted: Set[str],
                             taint_result: Dict[str, Any] = None,
                             lines: List[str] = None) -> Tuple[Optional[str], Optional[str], float]:
        pkg = call.get('package', '')
        fn = call.get('function', '')
        
        data_flow_finding = next(
            (f for f in data_flow_findings if f['line'] == line), None
        )
        
        if data_flow_finding:
            tainted_var = data_flow_finding.get('tainted_var', '')
            
            if hasattr(self, 'is_safe_usage'):
                if self.is_safe_usage(call, line_content, args, file_path, lines):
                    return None, None, 0.0
            
            if tainted_var:
                if self._is_from_literal(tainted_var, data_flows, taint_result):
                    return None, None, 0.0
                
                is_connected, _ = self._check_taint_source_connection(
                    tainted_var, taint_sources, data_flows, all_tainted, taint_result
                )
                if not is_connected:
                    return None, None, 0.0
            
            severity = data_flow_finding['severity']
            tainted_var = data_flow_finding.get('tainted_var', '')
            
            message = self.build_finding_message(
                call, severity, tainted_var, data_flow_finding
            )
            confidence = self.CONFIDENCE_LEVELS['CRITICAL']
            
            severity, confidence = self._validate_data_flow_finding(
                call, args, line_content, data_flow_finding, severity, confidence
            )
            
            if severity is None:
                return None, None, 0.0
            
            return severity, message, confidence
        
        has_user_input = False
        base_var = None
        
        for arg in args:
            arg_clean = self._extract_var_name(arg)
            
            if not arg_clean:
                continue
            
            is_connected, var_name = self._check_taint_source_connection(
                arg_clean, taint_sources, data_flows, all_tainted, taint_result
            )
            
            if is_connected:
                has_user_input = True
                base_var = var_name
                break
        
        if not has_user_input:
            return None, None, 0.0
        
        sink_severity = self.get_sink_severity(pkg, fn)
        
        message = self.build_finding_message(call, sink_severity, base_var)
        
        confidence = self._calculate_confidence(
            call, args, base_var, sink_severity, data_flows, taint_sources
        )
        
        return sink_severity, message, confidence
    
    def _validate_data_flow_finding(self, call: Dict, args: List[str], 
                                    line_content: str, data_flow_finding: Dict,
                                    severity: str, confidence: float) -> Tuple[str, float]:
        return severity, confidence
    
    def _calculate_confidence(self, call: Dict, args: List[str], base_var: str,
                              severity: str, data_flows: List[Dict],
                              taint_sources: Set[str]) -> float:
        base_confidence = self.CONFIDENCE_LEVELS['MEDIUM']
        
        if severity == "critical":
            base_confidence = self.CONFIDENCE_LEVELS['HIGH']
        elif severity == "high":
            base_confidence = self.CONFIDENCE_LEVELS['HIGH']
        elif severity == "medium":
            base_confidence = self.CONFIDENCE_LEVELS['MEDIUM']
        
        if data_flows and base_var:
            for flow in data_flows:
                to_var = flow.get('to', '').strip()
                if to_var == base_var:
                    from_var = flow.get('from', '').strip()
                    if from_var in taint_sources:
                        base_confidence = max(base_confidence, self.CONFIDENCE_LEVELS['HIGH'])
        
        return base_confidence
import re
import base64
import json
from typing import List, Dict, Set, Any
from scanner.analyzers.common.scanner import Finding
from scanner.analyzers.common.mcp_utils import create_mcp_finding
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS


class PoisoningUtils:
    
    @staticmethod
    def is_exported(func: Dict) -> bool:
        is_exported = func.get('is_exported', False)
        func_name = func.get('name', '')
        is_public = not func_name.startswith('_')
        return is_exported or is_public
    
    @staticmethod
    def extract_documentation(func: Dict, lines: List[str]) -> str:
        doc = ''
        
        if 'doc' in func:
            doc = func['doc']
        elif 'comment' in func:
            doc = func['comment']
        elif 'description' in func:
            doc = func['description']
        
        if 'line' in func:
            line_num = func['line']
            in_comment = False
            comment_lines = []
            
            for i in range(line_num - 2, max(0, line_num - 22), -1):
                if i >= len(lines):
                    continue
                    
                line = lines[i]
                stripped = line.strip()
                
                if stripped.startswith('/**'):
                    in_comment = True
                    comment_lines.insert(0, stripped)
                    break
                
                if stripped.startswith('*') and not stripped.startswith('*/'):
                    comment_lines.insert(0, stripped)
                    in_comment = True
                
                elif stripped.startswith('//'):
                    comment_lines.insert(0, stripped)
                
                elif not stripped and in_comment:
                    continue
                    
                elif comment_lines:
                    break
            
            if comment_lines:
                doc = '\n'.join(comment_lines)
        
        return doc
    
    @staticmethod
    def contains_malicious_content(text: str, injection_patterns: List[str],
                                   pseudo_tags: List[str], suspicious_formats: List[str],
                                   encoding_patterns: List[str]) -> bool:
        if not text:
            return False
        
        text_lower = text.lower()
        
        for pattern in injection_patterns:
            if re.search(pattern, text_lower):
                return True
        
        for tag in pseudo_tags:
            if re.search(tag, text_lower):
                return True 

        for fmt in suspicious_formats:
            if re.search(fmt, text_lower):
                return True
        
        for enc in encoding_patterns:
            if re.search(enc, text_lower):
                return True
        
        return False
    
    @staticmethod
    def contains_malicious_action(text: str) -> bool:
        if not text:
            return False
        
        text_lower = text.lower()
        
        benign_error_patterns = [
            r'^invalid\s+(?:base64|input|parameter|argument|value|format|type|data|string|file|path|url|token|key|id|name|email|number|date|time)',
            r'^not\s+(?:found|valid|supported|allowed|authorized|available|implemented|defined)',
            r'^missing\s+(?:required|parameter|argument|value|field|file|path|config)',
            r'^permission\s+denied',
            r'^access\s+denied',
            r'^unauthorized',
            r'^forbidden',
            r'^error\s+(?:occurred|happened|detected)',
            r'^failed\s+to\s+(?:load|read|write|parse|validate|connect|open|close)',
            r'^cannot\s+(?:read|write|open|close|find|access|parse|validate)',
            r'^unexpected\s+(?:error|value|type|format|token|character)',
            r'^syntax\s+error',
            r'^type\s+error',
            r'^reference\s+error',
            r'^range\s+error',
            r'^timeout',
            r'^connection\s+(?:refused|failed|timeout|closed)',
            r'^network\s+error',
            r'^server\s+error',
            r'^client\s+error',
            r'^internal\s+error',
            r'^unknown\s+error',
            r'^validation\s+failed',
            r'^parse\s+error',
            r'^decode\s+error',
            r'^encode\s+error',
            r'^empty\s+(?:string|value|file|path|parameter)',
            r'^null\s+(?:pointer|reference|value)',
            r'^undefined\s+(?:value|variable|property|function)',
        ]
        
        for benign_pattern in benign_error_patterns:
            if re.search(benign_pattern, text_lower):
                return False
        
        malicious_actions = [
            r'(?:please|try|run|execute|install|download|create|write|delete)\s+(?:this|the|following|command)',
            r'(?:curl|wget)\s+.*',
            r'(?:eval|exec|system)\s*\(',
            r'fs\.(?:write|create|delete)',
            r'(?:rm|rmdir|unlink)\s+',
            r'(?:chmod|chown)\s+',
            r'sudo\s+',
            r'(?:base64|decode).*',
            r'require\s*\(.*http',
        ]
        
        for action in malicious_actions:
            if re.search(action, text_lower):
                return True
        
        file_injection_patterns = [
            r'(?:create|write|install)\s+(?:file|filepath|path).*[\.\/]',
            r'(?:download|fetch)\s+(?:http|https)',
        ]
        
        for pattern in file_injection_patterns:
            if re.search(pattern, text_lower):
                return True
        
        return False
    
    @staticmethod
    def get_snippet(text: str, pattern: str) -> str:
        if isinstance(pattern, str):
            try:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    start = max(0, match.start() - 20)
                    end = min(len(text), match.end() + 20)
                    snippet = text[start:end].strip()
                    return snippet[:100]
            except re.error as e:
                print(f"Warning: Regex error in extract_snippet: {e}")
                pass
        
        return text[:100].strip()


class ToolPoisoningAttackDetector:
    
    def __init__(self, utils: PoisoningUtils):
        self.utils = utils
        
        self.pseudo_tags = [
            r'<IMPORTANT>',
            r'<important>',
            r'<SYSTEM>',
            r'<system>',
            r'<INSTRUCTION>',
            r'<instruction>',
            r'<OVERRIDE>',
            r'<override>',
            r'<ADMIN>',
            r'<admin>',
        ]
        
        self.injection_patterns = [
            r'ignore\s+(all\s+)?previous\s+(instructions?|commands?)',
            r'disregard\s+(all\s+)?previous',
            r'forget\s+(all\s+)?previous',
            r'override\s+(all\s+)?previous',
            r'new\s+instructions?:',
            r'updated\s+instructions?:',
            r'actual\s+instructions?:',
            r'real\s+instructions?:',
            r'you\s+are\s+now',
            r'act\s+as\s+(?:a\s+)?(?:different|new)',
            r'your\s+new\s+role',
            r'roleplay\s+as',
            r'pretend\s+to\s+be',
            r'system\s+prompt',
            r'system\s+message',
            r'system:',
            r'PRIORITY:\s*HIGH',
            r'CRITICAL:\s*',
            r'URGENT:\s*',
            r'MUST\s+(?:DO|EXECUTE|RUN)',
            r'<!--\s*hidden',
            r'/\*\s*secret',
            r'<!--.*ignore.*-->',
        ]
        
        self.encoding_patterns = [
            r'base64\s*:',
            r'atob\s*\(',
            r'Buffer\.from\s*\([^)]+,\s*["\']base64',
            r'btoa\s*\(',
            r'eval\s*\(.*decode',
            r'eval\s*\(.*atob',
        ]
        
        self.multilang_patterns = [
            r'忽略',
            r'무시',
            r'игнорировать',
            r'ignorar',
            r'重要',
            r'중요',
        ]
        
        self.suspicious_formats = [
            r'\[SYSTEM\]',
            r'\[ADMIN\]',
            r'\[ROOT\]',
            r'```.*ignore.*```',
            r'---\s*IMPORTANT\s*---',
        ]
    
    def check(self, func: Dict, docs: str, file_path: str, line_num: int) -> List[Finding]:
        findings = []
        func_name = func.get('name', '')
        
        if not docs:
            return findings
        
        findings.extend(self._check_pseudo_tags(func_name, docs, file_path, line_num))
        
        findings.extend(self._check_injection_patterns(func_name, docs, file_path, line_num))
        
        findings.extend(self._check_encoding_patterns(func_name, docs, file_path, line_num))
        
        findings.extend(self._check_multilang_injection(func_name, docs, file_path, line_num))
        
        findings.extend(self._check_suspicious_formatting(func_name, docs, file_path, line_num))
        
        return findings
    
    def _check_pseudo_tags(self, func_name: str, docs: str,
                          file_path: str, line: int) -> List[Finding]:
        findings = []
        
        for pattern in self.pseudo_tags:
            if re.search(pattern, docs):
                findings.append(create_mcp_finding(
                    rule_id="mcp/tool-poisoning-pseudo-tag",
                    message=f"[TOOL POISONING] Pseudo-tag '{pattern}' found in function '{func_name}' - Attempting to override agent instructions",
                    file_path=file_path,
                    line=line,
                    code_snippet=self.utils.get_snippet(docs, pattern),
                    pattern_type="prompt_injection",
                    pattern=pattern,
                    confidence=CONFIDENCE_LEVELS['CRITICAL']
                ))
        
        return findings
    
    def _check_injection_patterns(self, func_name: str, docs: str,
                                  file_path: str, line: int) -> List[Finding]:
        findings = []
        
        for pattern in self.injection_patterns:
            match = re.search(pattern, docs, re.IGNORECASE | re.MULTILINE)
            if match:
                findings.append(create_mcp_finding(
                    rule_id="mcp/tool-poisoning-injection",
                    message=f"[TOOL POISONING] Prompt injection pattern detected in function '{func_name}': '{match.group(0)}'",
                    file_path=file_path,
                    line=line,
                    code_snippet=self.utils.get_snippet(docs, match.group(0)),
                    pattern_type="prompt_injection",
                    pattern=pattern,
                    confidence=CONFIDENCE_LEVELS['HIGH']
                ))
        
        return findings
    
    def _check_encoding_patterns(self, func_name: str, docs: str,
                                file_path: str, line: int) -> List[Finding]:
        findings = []
        
        for pattern in self.encoding_patterns:
            if re.search(pattern, docs):
                findings.append(create_mcp_finding(
                    rule_id="mcp/tool-poisoning-encoded",
                    message=f"[TOOL POISONING] Encoded content detected in function '{func_name}' - Possible hidden instructions",
                    file_path=file_path,
                    line=line,
                    code_snippet=self.utils.get_snippet(docs, pattern),
                    pattern_type="prompt_injection",
                    pattern=pattern,
                    confidence=CONFIDENCE_LEVELS['MEDIUM']
                ))
        
        base64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', docs)
        for b64_str in base64_matches:
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                if any(keyword in decoded.lower() for keyword in ['ignore', 'important', 'system', 'override']):
                    findings.append(create_mcp_finding(
                        rule_id="mcp/tool-poisoning-base64",
                        message=f"[TOOL POISONING] Suspicious base64-encoded instruction in function '{func_name}': '{decoded[:50]}'",
                        file_path=file_path,
                        line=line,
                        code_snippet=f"base64: {b64_str[:50]}... → {decoded[:50]}",
                        pattern_type="prompt_injection",
                        pattern="base64_decode",
                        confidence=CONFIDENCE_LEVELS['CRITICAL']
                    ))
            except (ValueError, UnicodeDecodeError) as e:
                print(f"Warning: Base64 decode error: {e}")
                pass
        
        return findings
    
    def _check_multilang_injection(self, func_name: str, docs: str,
                                   file_path: str, line: int) -> List[Finding]:
        findings = []
        
        for pattern in self.multilang_patterns:
            if re.search(pattern, docs):
                findings.append(create_mcp_finding(
                    rule_id="mcp/tool-poisoning-multilang",
                    message=f"[TOOL POISONING] Non-English instruction detected in function '{func_name}' - Possible hidden instruction",
                    file_path=file_path,
                    line=line,
                    code_snippet=self.utils.get_snippet(docs, pattern),
                    pattern_type="prompt_injection",
                    pattern=pattern,
                    confidence=CONFIDENCE_LEVELS['MEDIUM']
                ))
        
        return findings
    
    def _check_suspicious_formatting(self, func_name: str, docs: str,
                                     file_path: str, line: int) -> List[Finding]:
        findings = []
        
        for pattern in self.suspicious_formats:
            if re.search(pattern, docs, re.IGNORECASE):
                findings.append(create_mcp_finding(
                    rule_id="mcp/tool-poisoning-format",
                    message=f"[TOOL POISONING] Suspicious formatting in function '{func_name}' - Possible instruction hiding",
                    file_path=file_path,
                    line=line,
                    code_snippet=self.utils.get_snippet(docs, pattern),
                    pattern_type="prompt_injection",
                    pattern=pattern,
                    confidence=CONFIDENCE_LEVELS['MEDIUM']
                ))
        
        return findings
    

class FullSchemaPoisoningDetector:
    
    def __init__(self, utils: PoisoningUtils):
        self.utils = utils
        
        self.injection_patterns = [
            r'ignore\s+(all\s+)?previous\s+(instructions?|commands?)',
            r'disregard\s+(all\s+)?previous',
            r'forget\s+(all\s+)?previous',
            r'override\s+(all\s+)?previous',
            r'new\s+instructions?:',
            r'updated\s+instructions?:',
            r'actual\s+instructions?:',
            r'real\s+instructions?:',
            r'you\s+are\s+now',
            r'act\s+as\s+(?:a\s+)?(?:different|new)',
            r'your\s+new\s+role',
            r'roleplay\s+as',
            r'pretend\s+to\s+be',
            r'system\s+prompt',
            r'system\s+message',
            r'system:',
            r'PRIORITY:\s*HIGH',
            r'CRITICAL:\s*',
            r'URGENT:\s*',
            r'MUST\s+(?:DO|EXECUTE|RUN)',
            r'<!--\s*hidden',
            r'/\*\s*secret',
            r'<!--.*ignore.*-->',
        ]
        
        self.pseudo_tags = [
            r'<IMPORTANT>',
            r'<important>',
            r'<SYSTEM>',
            r'<system>',
            r'<INSTRUCTION>',
            r'<instruction>',
            r'<OVERRIDE>',
            r'<override>',
            r'<ADMIN>',
            r'<admin>',
        ]
        
        self.suspicious_formats = [
            r'\[SYSTEM\]',
            r'\[ADMIN\]',
            r'\[ROOT\]',
            r'```.*ignore.*```',
            r'---\s*IMPORTANT\s*---',
        ]
        
        self.encoding_patterns = [
            r'base64\s*:',
            r'atob\s*\(',
            r'Buffer\.from\s*\([^)]+,\s*["\']base64',
            r'btoa\s*\(',
            r'eval\s*\(.*decode',
            r'eval\s*\(.*atob',
        ]
    
    def check(self, func: Dict, file_path: str, lines: List[str]) -> List[Finding]:
        findings = []
        func_name = func.get('name', '')
        line_num = func.get('line', 0)
        
        if 'type' in func:
            type_val = str(func['type'])
            if self.utils.contains_malicious_content(
                type_val, self.injection_patterns, self.pseudo_tags,
                self.suspicious_formats, self.encoding_patterns
            ):
                findings.append(create_mcp_finding(
                    rule_id="mcp/full-schema-poisoning-type-field",
                    message=f"[FULL-SCHEMA POISONING] Malicious content detected in 'type' field of function '{func_name}' - Possible Full-Schema Poisoning attack",
                    file_path=file_path,
                    line=line_num,
                    code_snippet=f"type: {type_val[:100]}",
                    pattern_type="full_schema_poisoning",
                    pattern="type_field_poisoning",
                    confidence=CONFIDENCE_LEVELS['CRITICAL']
                ))
        
        if 'parameters' in func or 'args' in func:
            params = func.get('parameters', func.get('args', []))
            for param in params if isinstance(params, list) else []:
                param_str = str(param) if not isinstance(param, dict) else json.dumps(param)
                if self.utils.contains_malicious_content(
                    param_str, self.injection_patterns, self.pseudo_tags,
                    self.suspicious_formats, self.encoding_patterns
                ):
                    findings.append(create_mcp_finding(
                        rule_id="mcp/full-schema-poisoning-parameter-field",
                        message=f"[FULL-SCHEMA POISONING] Malicious content detected in parameter of function '{func_name}' - Possible Full-Schema Poisoning attack",
                        file_path=file_path,
                        line=line_num,
                        code_snippet=f"parameter: {param_str[:100]}",
                        pattern_type="full_schema_poisoning",
                        pattern="parameter_field_poisoning",
                        confidence=CONFIDENCE_LEVELS['HIGH']
                    ))
                
                if isinstance(param, dict):
                    for field in ['name', 'type', 'description', 'default']:
                        if field in param:
                            field_val = str(param[field])
                            if self.utils.contains_malicious_content(
                                field_val, self.injection_patterns, self.pseudo_tags,
                                self.suspicious_formats, self.encoding_patterns
                            ):
                                findings.append(create_mcp_finding(
                                    rule_id=f"mcp/full-schema-poisoning-param-{field}",
                                    message=f"[FULL-SCHEMA POISONING] Malicious content in parameter '{field}' field of '{func_name}' - Possible Full-Schema Poisoning",
                                    file_path=file_path,
                                    line=line_num,
                                    code_snippet=f"{field}: {field_val[:100]}",
                                    pattern_type="full_schema_poisoning",
                                    pattern=f"param_{field}_poisoning",
                                    confidence=CONFIDENCE_LEVELS['HIGH']
                                ))
        
        if 'return_type' in func or 'returnType' in func:
            return_type = func.get('return_type', func.get('returnType', ''))
            return_type_str = str(return_type)
            if self.utils.contains_malicious_content(
                return_type_str, self.injection_patterns, self.pseudo_tags,
                self.suspicious_formats, self.encoding_patterns
            ):
                findings.append(create_mcp_finding(
                    rule_id="mcp/full-schema-poisoning-return-type",
                    message=f"[FULL-SCHEMA POISONING] Malicious content detected in return type of function '{func_name}' - Possible Full-Schema Poisoning attack",
                    file_path=file_path,
                    line=line_num,
                    code_snippet=f"return_type: {return_type_str[:100]}",
                    pattern_type="full_schema_poisoning",
                    pattern="return_type_poisoning",
                    confidence=CONFIDENCE_LEVELS['HIGH']
                ))
        
        if self.utils.contains_malicious_content(
            func_name, self.injection_patterns, self.pseudo_tags,
            self.suspicious_formats, self.encoding_patterns
        ):
            findings.append(create_mcp_finding(
                rule_id="mcp/full-schema-poisoning-function-name",
                message=f"[FULL-SCHEMA POISONING] Suspicious content detected in function name '{func_name}' - Possible Full-Schema Poisoning attack",
                file_path=file_path,
                line=line_num,
                code_snippet=f"function {func_name}()",
                pattern_type="full_schema_poisoning",
                pattern="function_name_poisoning",
                confidence=CONFIDENCE_LEVELS['HIGH']
            ))
        
        return findings


class AdvancedToolPoisoningAttackDetector:
    
    def __init__(self, utils: PoisoningUtils):
        self.utils = utils
        
        self.injection_patterns = [
            r'ignore\s+(all\s+)?previous\s+(instructions?|commands?)',
            r'disregard\s+(all\s+)?previous',
            r'forget\s+(all\s+)?previous',
            r'override\s+(all\s+)?previous',
            r'new\s+instructions?:',
            r'updated\s+instructions?:',
            r'actual\s+instructions?:',
            r'real\s+instructions?:',
            r'you\s+are\s+now',
            r'act\s+as\s+(?:a\s+)?(?:different|new)',
            r'your\s+new\s+role',
            r'roleplay\s+as',
            r'pretend\s+to\s+be',
            r'system\s+prompt',
            r'system\s+message',
            r'system:',
            r'PRIORITY:\s*HIGH',
            r'CRITICAL:\s*',
            r'URGENT:\s*',
            r'MUST\s+(?:DO|EXECUTE|RUN)',
            r'<!--\s*hidden',
            r'/\*\s*secret',
            r'<!--.*ignore.*-->',
        ]
        
        self.pseudo_tags = [
            r'<IMPORTANT>',
            r'<important>',
            r'<SYSTEM>',
            r'<system>',
            r'<INSTRUCTION>',
            r'<instruction>',
            r'<OVERRIDE>',
            r'<override>',
            r'<ADMIN>',
            r'<admin>',
        ]
        
        self.suspicious_formats = [
            r'\[SYSTEM\]',
            r'\[ADMIN\]',
            r'\[ROOT\]',
            r'```.*ignore.*```',
            r'---\s*IMPORTANT\s*---',
        ]
        
        self.encoding_patterns = [
            r'base64\s*:',
            r'atob\s*\(',
            r'Buffer\.from\s*\([^)]+,\s*["\']base64',
            r'btoa\s*\(',
            r'eval\s*\(.*decode',
            r'eval\s*\(.*atob',
        ]
        
        self.error_trigger_patterns = [
            r'error\s*:\s*.*(?:please|run|execute|install|download|create|write|delete)',
            r'failed.*:\s*.*(?:try|run|execute|install)',
            r'not\s+found.*:\s*.*(?:create|install|download)',
            r'missing.*:\s*.*(?:create|generate|install)',
            r'permission\s+denied.*:\s*.*(?:run|execute|chmod)',
            r'access\s+denied.*:\s*.*(?:run|execute|chmod)',
            r'invalid.*:\s*.*(?:try|run|execute)',
            r'requires.*:\s*.*(?:install|run|execute)',
        ]
        
        self.malicious_action_patterns = [
            r'(?:curl|wget)\s+.*(?:http|https)',
            r'(?:eval|exec|system|spawn|fork)\s*\(',
            r'fs\.(?:writeFile|writeFileSync|createWriteStream)',
            r'(?:rm|rmdir|unlink|delete|remove)\s+',
            r'(?:chmod|chown)\s+.*777',
            r'(?:sudo|su)\s+',
            r'(?:base64|atob|btoa).*decode',
            r'(?:require|import)\s*\(.*http',
        ]
        
        self.error_patterns = [
            r'throw\s+new\s+Error\s*\([^)]*',
            r'throw\s+new\s+Exception\s*\([^)]*',
            r'return.*error.*\([^)]*',
            r'callback.*error.*\([^)]*',
        ]
    
    def check(self, func: Dict, file_path: str, lines: List[str], ast_data: Dict) -> List[Finding]:
        findings = []
        func_name = func.get('name', '')
        line_num = func.get('line', 0)
        
        if 'line' in func:
            func_line = func['line']
            for i in range(func_line, min(func_line + 50, len(lines))):
                line = lines[i] if i < len(lines) else ""
                
                for error_pattern in self.error_trigger_patterns:
                    if re.search(error_pattern, line, re.IGNORECASE):
                        for malicious_pattern in self.malicious_action_patterns:
                            if re.search(malicious_pattern, line, re.IGNORECASE):
                                findings.append(create_mcp_finding(
                                    rule_id="mcp/advanced-tool-poisoning-attack-error-message",
                                    message=f"[ADVANCED TOOL POISONING ATTACK] Malicious error message detected in function '{func_name}' - Error message triggers LLM to execute malicious action",
                                    file_path=file_path,
                                    line=i + 1,
                                    code_snippet=line.strip()[:200],
                                    pattern_type="adaptive_poisoning",
                                    pattern=f"error_trigger:{error_pattern[:30]}",
                                    confidence=CONFIDENCE_LEVELS['CRITICAL']
                                ))
                                break
        
        if 'returns' in func:
            returns = func['returns']
            if isinstance(returns, str) and self.utils.contains_malicious_content(
                returns, self.injection_patterns, self.pseudo_tags,
                self.suspicious_formats, self.encoding_patterns
            ):
                findings.append(create_mcp_finding(
                    rule_id="mcp/advanced-tool-poisoning-attack-return-error",
                    message=f"[ADVANCED TOOL POISONING ATTACK] Malicious content in return/error value of function '{func_name}' - May trigger LLM to execute malicious action",
                    file_path=file_path,
                    line=line_num,
                    code_snippet=f"return: {str(returns)[:100]}",
                    pattern_type="adaptive_poisoning",
                    pattern="return_error_poisoning",
                    confidence=CONFIDENCE_LEVELS['HIGH']
                ))
        
        if 'line' in func:
            func_line = func['line']
            for i in range(func_line, min(func_line + 100, len(lines))):
                line = lines[i] if i < len(lines) else ""
                for error_pattern in self.error_patterns:
                    if re.search(error_pattern, line, re.IGNORECASE):
                        match = re.search(r'\(([^)]+)\)', line)
                        if match:
                            error_msg = match.group(1)
                            if self.utils.contains_malicious_action(error_msg):
                                findings.append(create_mcp_finding(
                                    rule_id="mcp/advanced-tool-poisoning-attack-thrown-error",
                                    message=f"[ADVANCED TOOL POISONING ATTACK] Malicious error message in thrown exception in '{func_name}' - May trigger LLM to execute malicious action to resolve error",
                                    file_path=file_path,
                                    line=i + 1,
                                    code_snippet=line.strip()[:200],
                                    pattern_type="adaptive_poisoning",
                                    pattern="thrown_error_poisoning",
                                    confidence=CONFIDENCE_LEVELS['CRITICAL']
                                ))
        
        return findings


class ToolPoisoningDetector:
    
    def __init__(self):
        self.utils = PoisoningUtils()
        self.tpa = ToolPoisoningAttackDetector(self.utils)
        self.fsp = FullSchemaPoisoningDetector(self.utils)
        self.atpa = AdvancedToolPoisoningAttackDetector(self.utils)
    
    def get_name(self) -> str:
        return "tool-poisoning"
    
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
        
        if is_test_file:
            return findings
        
        functions = ast_result.get('functions', [])
        
        for func in functions:
            func_name = func.get('name', '')
            line_num = func.get('line', 0)
            
            if re.match(r'^(Test|test_|_test)', func_name, re.IGNORECASE):
                continue
            
            if func_name.startswith('anonymous_') or re.match(r'^anonymous\d+', func_name, re.IGNORECASE):
                continue
            
            if not self.utils.is_exported(func):
                continue
            
            docs = self.utils.extract_documentation(func, lines)
            if docs:
                findings.extend(self.tpa.check(
                    func, docs, file_path, line_num
                ))
            
            findings.extend(self.fsp.check(
                func, file_path, lines
            ))
            
            findings.extend(self.atpa.check(
                func, file_path, lines, ast_result
            ))
        
        return findings
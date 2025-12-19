import re
from typing import List, Dict, Optional, Callable
from scanner.analyzers.common.scanner import Finding
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS

MCP_SEVERITY = "info"
MCP_MESSAGE_SUFFIX = " - Possible vulnerability"

MCP_DEFAULT_CONFIDENCE = CONFIDENCE_LEVELS['HIGH']


def get_cwe_for_mcp_rule(rule_id: str) -> Optional[str]:
    if not rule_id:
        return None
    
    rule_id_lower = rule_id.lower()
    
    if "config-poisoning" in rule_id_lower:
        if "data-exfiltration" in rule_id_lower:
            return "CWE-15"
        elif "malicious-url" in rule_id_lower:
            return "CWE-15" 
        elif "dangerous-tool" in rule_id_lower or "privilege-escalation" in rule_id_lower:
            return "CWE-250"
        elif "auth-bypass" in rule_id_lower:
            return "CWE-287"
        elif "malicious-env" in rule_id_lower:
            return "CWE-312"
        elif "suspicious-path" in rule_id_lower:
            return "CWE-22"
        elif "injection" in rule_id_lower:
            return "CWE-74"
        else:
            return "CWE-15"
    
    elif "tool-name-spoofing" in rule_id_lower:
        if "unicode" in rule_id_lower or "excessive-caps" in rule_id_lower or "inflated" in rule_id_lower:
            return "CWE-1007"
        else:
            return "CWE-250"
    
    elif "toxic-flow" in rule_id_lower:
        if "data-leak" in rule_id_lower:
            return "CWE-200"
        elif "destructive" in rule_id_lower:
            return "CWE-400"
        else:
            return "CWE-200"
    
    elif "tool-shadowing" in rule_id_lower:
        return "CWE-434"
    
    elif "tool-poisoning" in rule_id_lower or "schema-poisoning" in rule_id_lower:
        return "CWE-74"
    
    return None


def create_mcp_finding(
    rule_id: str,
    message: str,
    file_path: str,
    line: int,
    code_snippet: str = "",
    pattern_type: str = "",
    pattern: str = "",
    confidence: float = MCP_DEFAULT_CONFIDENCE,
    column: int = 0,
    cwe: Optional[str] = None
) -> Finding:

    if cwe is None:
        cwe = get_cwe_for_mcp_rule(rule_id)
    
    return Finding(
        rule_id=rule_id,
        severity=MCP_SEVERITY,
        message=message + MCP_MESSAGE_SUFFIX,
        cwe=cwe,
        file=file_path,
        line=line,
        column=column,
        code_snippet=code_snippet,
        pattern_type=pattern_type,
        pattern=pattern,
        confidence=confidence
    )


def scan_lines_for_patterns(
    lines: List[str],
    patterns: List[str],
    file_path: str,
    rule_id_prefix: str,
    message_template: str,
    pattern_category: str = "",
    confidence: float = MCP_DEFAULT_CONFIDENCE,
    condition: Optional[Callable[[str, str], bool]] = None,
    code_snippet_transform: Optional[Callable[[str], str]] = None,
    cwe: Optional[str] = None
) -> List[Finding]:
    findings = []
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        for pattern in patterns:
            if re.search(r'[^\w\s]', pattern):
                matched = re.search(pattern, line, re.IGNORECASE)
            else:
                matched = pattern.lower() in line.lower()
            
            if matched:
                if condition and not condition(line, pattern):
                    continue
                
                code_snippet = code_snippet_transform(line) if code_snippet_transform else line.strip()
                
                message = message_template.format(pattern=pattern)
                
                finding = create_mcp_finding(
                    rule_id=f"{rule_id_prefix}-{pattern_category}",
                    message=message,
                    file_path=file_path,
                    line=line_num,
                    code_snippet=code_snippet,
                    pattern_type=pattern_category,
                    pattern=f"{pattern_category}:{pattern}",
                    confidence=confidence,
                    cwe=cwe
                )
                findings.append(finding)
    
    return findings


def scan_lines_with_custom_check(
    lines: List[str],
    file_path: str,
    check_func: Callable[[str, int], Optional[Finding]]
) -> List[Finding]:
    findings = []
    
    for i, line in enumerate(lines):
        line_num = i + 1
        finding = check_func(line, line_num)
        if finding:
            findings.append(finding)
    
    return findings


def get_line_snippet(lines: List[str], line_num: int, context: int = 0) -> str:
    if not lines or line_num < 1 or line_num > len(lines):
        return ""
    
    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    
    return "\n".join(lines[start:end]).strip()


def extract_pattern_group(pattern: str, line: str) -> Optional[str]:
    match = re.search(pattern, line, re.IGNORECASE)
    if match and match.groups():
        return match.group(1)
    return None
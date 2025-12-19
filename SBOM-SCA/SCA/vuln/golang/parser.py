#!/usr/bin/env python3
"""
govulncheck result parser module
"""

import re
from typing import Dict, List, Any
from pathlib import Path


class VulnCheckParser:
    """govulncheck output parser"""
    
    def __init__(self, vuln_file: str):
        self.vuln_file = Path(vuln_file).expanduser().resolve()
        self.vulnerabilities = []
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse govulncheck detailed output"""
        if not self.vuln_file.exists():
            raise FileNotFoundError(f"File not found: {self.vuln_file}")
        
        with open(self.vuln_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Track all vulnerabilities by ID to merge Symbol and Package results
        vuln_dict = {}
        
        # Parse Symbol Results (reachable vulnerabilities)
        symbol_results_match = re.search(
            r'=== Symbol Results ===\s*(.+?)(?=\n=== Package Results ===|\Z)',
            content,
            re.DOTALL
        )
        
        if symbol_results_match:
            symbol_section = symbol_results_match.group(1)
            vuln_pattern = r'Vulnerability #(\d+):\s*([A-Z0-9-]+)\s+(.+?)(?=Vulnerability #|\Z)'
            vuln_matches = re.finditer(vuln_pattern, symbol_section, re.DOTALL)
            
            for match in vuln_matches:
                vuln_num = match.group(1)
                vuln_id = match.group(2).strip()
                vuln_text = match.group(3)
                
                vuln_data = self._parse_vulnerability(vuln_id, vuln_text, is_reachable=True)
                if vuln_data:
                    vuln_dict[vuln_id] = vuln_data
        
        # Parse Package Results (unreachable vulnerabilities)
        package_results_match = re.search(
            r'=== Package Results ===\s*(.+?)(?=\Z)',
            content,
            re.DOTALL
        )
        
        if package_results_match:
            package_section = package_results_match.group(1)
            vuln_pattern = r'Vulnerability #(\d+):\s*([A-Z0-9-]+)\s+(.+?)(?=Vulnerability #|\Z)'
            vuln_matches = re.finditer(vuln_pattern, package_section, re.DOTALL)
            
            for match in vuln_matches:
                vuln_num = match.group(1)
                vuln_id = match.group(2).strip()
                vuln_text = match.group(3)
                
                # If already in dict (from Symbol Results), mark as reachable
                if vuln_id in vuln_dict:
                    vuln_dict[vuln_id]['is_reachable'] = True
                else:
                    # New vulnerability from Package Results (unreachable)
                    vuln_data = self._parse_vulnerability(vuln_id, vuln_text, is_reachable=False)
                    if vuln_data:
                        vuln_dict[vuln_id] = vuln_data
        
        self.vulnerabilities = list(vuln_dict.values())
        return self.vulnerabilities
    
    def _parse_vulnerability(self, vuln_id: str, vuln_text: str, is_reachable: bool = True) -> Dict[str, Any]:
        """Parse individual vulnerability"""
        title_match = re.search(r'^\s*(.+?)(?:\n|$)', vuln_text.strip())
        title = title_match.group(1).strip() if title_match else ""
        
        link_match = re.search(r'More info:\s*(https?://[^\s]+)', vuln_text)
        link = link_match.group(1) if link_match else ""
        
        is_stdlib = "Standard library" in vuln_text
        module_match = re.search(r'Module:\s*([^\n]+)', vuln_text)
        module = module_match.group(1).strip() if module_match else ("stdlib" if is_stdlib else "")
        
        found_in_match = re.search(r'Found in:\s*([^\n]+)', vuln_text)
        found_in = found_in_match.group(1).strip() if found_in_match else ""
        
        fixed_in_match = re.search(r'Fixed in:\s*([^\n]+)', vuln_text)
        fixed_in = fixed_in_match.group(1).strip() if fixed_in_match else ""
        
        # Extract package from Found in field
        # Format: "package@version" or "module@version"
        package_match = re.search(r'Found in:\s*([^@\n]+)', vuln_text)
        package = ""
        if package_match:
            potential_package = package_match.group(1).strip()
            # If it contains "/", it's a package path (e.g., "crypto/x509")
            if "/" in potential_package:
                package = potential_package
            else:
                # For "stdlib@version" or "std@version", try to extract from title
                # Title often contains package path like "in crypto/x509" or "in archive/tar"
                # Pattern: "in package/path" or "in package/path/subpath"
                title_package_match = re.search(r'\bin\s+([a-zA-Z0-9_]+(?:\/[a-zA-Z0-9_]+)+)', title, re.IGNORECASE)
                if title_package_match:
                    package = title_package_match.group(1).strip()
                # If still not found, leave empty for package-level only vulnerabilities
        
        # Only extract vulnerable functions if reachable (Symbol Results)
        vulnerable_functions = self._extract_vulnerable_functions(vuln_text) if is_reachable else []
        
        vuln_data = {
            'id': vuln_id,
            'title': title,
            'link': link,
            'module': module,
            'package': package,
            'found_in': found_in,
            'fixed_in': fixed_in,
            'is_stdlib': is_stdlib,
            'is_reachable': is_reachable,
            'vulnerable_functions': vulnerable_functions
        }
        
        return vuln_data
    
    def _extract_vulnerable_functions(self, vuln_text: str) -> List[str]:
        """Extract vulnerable functions from example traces"""
        vulnerable_functions = set()
        
        traces_section = re.search(
            r'Example traces found:\s*(.+?)(?=\n\n|Vulnerability #|\Z)',
            vuln_text,
            re.DOTALL
        )
        
        if not traces_section:
            return []
        
        traces_text = traces_section.group(1)
        trace_lines = re.findall(r'#\d+:\s+([^\n]+)', traces_text)
        
        if not trace_lines:
            return []
        
        for trace_line in trace_lines:
            vulnerable_func = None
            
            if "which eventually calls" in trace_line:
                parts = trace_line.split("which eventually calls", 1)
                if len(parts) == 2:
                    last_part = parts[1].strip()
                    func_match = re.search(r'\b([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+){0,2})\b', last_part)
                    if func_match:
                        vulnerable_func = func_match.group(1)
            elif "calls" in trace_line:
                parts = trace_line.rsplit("calls", 1)
                if len(parts) == 2:
                    last_part = parts[1].strip()
                    func_match = re.search(r'\b([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+){0,2})\b', last_part)
                    if func_match:
                        vulnerable_func = func_match.group(1)
            
            if vulnerable_func:
                parts_count = vulnerable_func.count('.') + 1
                if parts_count >= 2:
                    vulnerable_functions.add(vulnerable_func)
        
        return sorted(list(vulnerable_functions))
    
    def _parse_traces(self, vuln_text: str) -> List[Dict[str, Any]]:
        """Parse example traces"""
        traces = []
        traces_section = re.search(
            r'Example traces found:\s*(.+?)(?=\n\n|Vulnerability #|\Z)',
            vuln_text,
            re.DOTALL
        )
        
        if not traces_section:
            return traces
        
        traces_text = traces_section.group(1)
        trace_lines = re.findall(r'#\d+:\s+([^\n]+)', traces_text)
        
        for trace_line in trace_lines:
            entry_point_match = re.search(r'([^:]+:\d+:\d+):', trace_line)
            entry_point = entry_point_match.group(1) if entry_point_match else ""
            
            if entry_point_match:
                calls_part = trace_line[entry_point_match.end():].strip()
            elif ':' in trace_line:
                calls_part = trace_line.split(':', 1)[1].strip()
            else:
                calls_part = trace_line
            
            entry_func_match = re.search(r'\b([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)\s+(?:calls|which eventually calls)', calls_part)
            if entry_func_match:
                entry_function = entry_func_match.group(1)
            else:
                entry_func_match = re.search(r'\b([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+){1,2})\b', calls_part)
                entry_function = entry_func_match.group(1) if entry_func_match else ""
            
            if "which eventually calls" in calls_part:
                parts = calls_part.split("which eventually calls")
                vulnerable_function = parts[-1].strip() if parts else ""
            elif "calls" in calls_part:
                parts = calls_part.rsplit("calls", 1)
                if len(parts) == 2:
                    vulnerable_function = parts[-1].strip()
                    if vulnerable_function == entry_function:
                        vulnerable_function = ""
                else:
                    vulnerable_function = ""
            else:
                vulnerable_function = ""
            
            traces.append({
                'entry_point': entry_point,
                'entry_function': entry_function,
                'vulnerable_function': vulnerable_function,
                'full_path': calls_part.strip(),
                'raw_trace': trace_line
            })
        
        return traces

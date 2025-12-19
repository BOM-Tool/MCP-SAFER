#!/usr/bin/env python3
"""
Call Graph loading and graph construction module
"""

import json
from typing import Dict, List, Any, Optional
from collections import defaultdict
from pathlib import Path


class CallGraphLoader:
    """Call Graph loader and graph manager"""
    
    def __init__(self, callgraph_file: str):
        self.callgraph_file = Path(callgraph_file).expanduser().resolve()
        self.graph = defaultdict(list)
        self.file_to_functions = defaultdict(set)
        self.function_info_map = {}
        self.imported_packages = set()  # All packages that appear in call graph (imported packages)
    
    def load(self) -> bool:
        """Load Call Graph file and build graph"""
        if not self.callgraph_file.exists():
            return False
        
        try:
            with open(self.callgraph_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            call_graph = data.get('call_graph', [])
            
            # Extract all imported packages from call graph
            # If a package appears in call graph, it means it's imported
            for entry in call_graph:
                caller = entry.get('caller', '')
                caller_module = entry.get('caller_module', '')
                caller_package = entry.get('caller_package', '')
                
                # Add caller package to imported packages
                if caller_package:
                    self.imported_packages.add(caller_package.lower())
                
                callees = entry.get('callees', [])
                for callee_info in callees:
                    callee = callee_info.get('callee', '')
                    callee_module = callee_info.get('callee_module', '')
                    callee_package = callee_info.get('callee_package', '')
                    call_site_file = callee_info.get('call_site_file') or callee_info.get('filename', '')
                    
                    # Add callee package to imported packages
                    if callee_package:
                        self.imported_packages.add(callee_package.lower())
                    
                    if caller and callee:
                        self.graph[caller].append({
                            'callee': callee,
                            'module': callee_module,
                            'package': callee_package,
                            'call_site_file': call_site_file
                        })
                    
                    if call_site_file:
                        self.file_to_functions[call_site_file].add(caller)
                    
                    if caller not in self.function_info_map:
                        self.function_info_map[caller] = {
                            'module': caller_module,
                            'package': caller_package,
                            'call_site_files': set()
                        }
                    if call_site_file:
                        self.function_info_map[caller]['call_site_files'].add(call_site_file)
                    
                    if callee not in self.function_info_map:
                        self.function_info_map[callee] = {
                            'module': callee_module,
                            'package': callee_package,
                            'call_site_files': set()
                        }
                    if call_site_file:
                        self.function_info_map[callee]['call_site_files'].add(call_site_file)
            
            return True
        except Exception as e:
            print(f"Error: Call Graph loading failed: {e}")
            return False
    
    def get_function_info(self, func_name: str) -> Dict[str, Any]:
        """Get detailed function information"""
        if func_name in self.function_info_map:
            info = self.function_info_map[func_name]
            return {
                'function': func_name,
                'module': info['module'],
                'package': info['package'],
                'call_site_files': list(info['call_site_files']) if info.get('call_site_files') else []
            }
        
        return {
            'function': func_name,
            'module': '',
            'package': '',
            'call_site_files': []
        }
    
    def find_function_by_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        """Search functions by exact pattern match only"""
        matches = []
        pattern_parts = [p.strip() for p in pattern.split('.') if p.strip()]
        
        if not pattern_parts:
            return matches
        
        with open(self.callgraph_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        call_graph = data.get('call_graph', [])
        seen = set()
        
        def normalize_function_name(func_name: str) -> str:
            """Normalize function name: (*package.Type).Method -> package.Type.Method"""
            func_name = func_name.strip()
            
            if func_name.startswith('(*'):
                func_name = func_name[2:]
                if ')' in func_name:
                    parts = func_name.split(')', 1)
                    if len(parts) == 2:
                        return parts[0] + '.' + parts[1].lstrip('.')
            
            elif func_name.startswith('(') and ')' in func_name:
                parts = func_name.split(')', 1)
                if len(parts) == 2:
                    return parts[0] + '.' + parts[1].lstrip('.')
            
            return func_name
        
        def is_exact_match(func_name: str, package: str, pattern_parts: List[str]) -> bool:
            """Check exact match: all pattern parts must match exactly"""
            normalized = normalize_function_name(func_name)
            
            pattern_package = pattern_parts[0].lower()
            
            if package:
                package_lower = package.lower().replace('/', '').replace('-', '')
                if pattern_package not in package_lower:
                    return False
            
            func_parts = normalized.split('.')
            
            if len(pattern_parts) >= 3:
                pattern_type = pattern_parts[-2]
                pattern_method = pattern_parts[-1]
                
                if len(func_parts) >= 2:
                    last_two = func_parts[-2:]
                    type_match = pattern_type.lower() == last_two[0].lower()
                    method_name = last_two[1]
                    method_match = pattern_method == method_name
                    
                    if type_match and method_match:
                        return True
                
                return False
            
            elif len(pattern_parts) == 2:
                pattern_pkg_or_type = pattern_parts[0]
                pattern_method = pattern_parts[1]
                
                if len(func_parts) >= 2:
                    pkg_or_type_part = func_parts[-2]
                    
                    type_match = (pattern_pkg_or_type.lower() in pkg_or_type_part.lower() or 
                                 pkg_or_type_part.endswith('/' + pattern_pkg_or_type) or
                                 pkg_or_type_part.endswith('.' + pattern_pkg_or_type))
                    
                    method_match = pattern_method == func_parts[-1]
                    return type_match and method_match
                elif len(func_parts) == 1:
                    return pattern_method == func_parts[0]
                return False
            
            else:
                pattern_name = pattern_parts[0].lower()
                if func_parts:
                    return pattern_name == func_parts[-1].lower()
                return False
        
        for entry in call_graph:
            caller = entry.get('caller', '')
            caller_package = entry.get('caller_package', '')
            
            if caller in seen:
                continue
            
            if is_exact_match(caller, caller_package, pattern_parts):
                seen.add(caller)
                matches.append({
                    'function': caller,
                    'module': entry.get('caller_module', ''),
                    'package': caller_package
                })
            
            callees = entry.get('callees', [])
            for callee_info in callees:
                callee = callee_info.get('callee', '')
                if not callee or callee in seen:
                    continue
                
                callee_package = callee_info.get('callee_package', '')
                
                if is_exact_match(callee, callee_package, pattern_parts):
                    seen.add(callee)
                    matches.append({
                        'function': callee,
                        'module': callee_info.get('callee_module', ''),
                        'package': callee_package
                    })
        
        return matches
    
    def find_function_by_file_location(self, file_path: str, line: int) -> List[Dict[str, Any]]:
        """Find functions by file path and line number"""
        if not self.file_to_functions:
            return []
        
        normalized_path = file_path.replace('\\', '/')
        found = []
        
        for file, functions in self.file_to_functions.items():
            if normalized_path in file or file.endswith(normalized_path):
                for func in functions:
                    func_info = self.get_function_info(func)
                    if func_info:
                        found.append(func_info)
        
        return found

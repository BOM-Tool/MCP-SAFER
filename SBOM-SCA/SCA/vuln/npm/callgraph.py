#!/usr/bin/env python3
"""
TypeScript Call Graph loader module
"""

import json
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from collections import defaultdict


class TypeScriptCallGraphLoader:
    """TypeScript Call Graph loader"""
    
    def __init__(self, callgraph_file: str):
        self.callgraph_file = Path(callgraph_file).expanduser().resolve()
        self.graph: Dict[str, List[Dict[str, Any]]] = {}  # caller -> [callee edges]
        self.function_info: Dict[str, Dict[str, Any]] = {}  # function_name -> info
        self.file_to_functions: Dict[str, List[str]] = defaultdict(list)  # file -> [functions]
        self.package_to_functions: Dict[str, List[str]] = defaultdict(list)  # package -> [functions]
        self.imported_packages: Set[str] = set()  # Set of imported package names
        self.loaded = False
    
    def load(self) -> bool:
        """Load call graph from JSON file"""
        if not self.callgraph_file.exists():
            print(f"Error: Call Graph file not found: {self.callgraph_file}")
            return False
        
        try:
            with open(self.callgraph_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            call_graph = data.get('call_graph', [])
            
            # Build graph structure
            for entry in call_graph:
                caller = entry.get('functionName', '')
                if not caller:
                    continue
                
                # Store caller function info in function_info
                caller_func_name = entry.get('functionName', '')
                caller_file = entry.get('filePath', '')
                caller_package = entry.get('packageName', '')
                caller_is_external = entry.get('isExternal', False)
                
                # Use caller_func_name if available, otherwise use caller
                func_name_to_store = caller_func_name if caller_func_name else caller
                
                if func_name_to_store and func_name_to_store not in self.function_info:
                    self.function_info[func_name_to_store] = {
                        'function': func_name_to_store,
                        'file': caller_file,
                        'package': caller_package,
                        'isExternal': caller_is_external,
                        'moduleType': entry.get('moduleType', 'internal'),
                    }
                    
                    # Map caller file and package
                    if caller_file:
                        self.file_to_functions[caller_file].append(func_name_to_store)
                    if caller_package:
                        self.package_to_functions[caller_package].append(func_name_to_store)
                        if caller_is_external:
                            self.imported_packages.add(caller_package)
                
                # Build edges
                callees = entry.get('callees', [])
                edges = []
                
                for callee_info in callees:
                    callee_name = callee_info.get('functionName', '')
                    if not callee_name:
                        continue
                    
                    edge = {
                        'callee': callee_name,
                        'file': callee_info.get('filePath', ''),
                        'package': callee_info.get('packageName', ''),
                        'isExternal': callee_info.get('isExternal', False),
                        'moduleType': callee_info.get('moduleType', 'internal'),
                        'callType': callee_info.get('callType', 'function'),
                        'position': callee_info.get('position', {}),
                        'fullSignature': callee_info.get('fullSignature', ''),
                    }
                    
                    edges.append(edge)
                    
                    # Store callee info if not already stored
                    # If already exists, prefer external package information
                    if callee_name not in self.function_info:
                        self.function_info[callee_name] = {
                            'function': callee_name,
                            'file': callee_info.get('filePath', ''),
                            'package': callee_info.get('packageName', ''),
                            'isExternal': callee_info.get('isExternal', False),
                            'moduleType': callee_info.get('moduleType', 'internal'),
                        }
                    else:
                        # Update if current entry is external and existing is not
                        existing_info = self.function_info[callee_name]
                        callee_is_external = callee_info.get('isExternal', False)
                        callee_package = callee_info.get('packageName', '')
                        existing_is_external = existing_info.get('isExternal', False)
                        existing_package = existing_info.get('package', '')
                        
                        # Prefer external package information
                        if callee_is_external and callee_package and (not existing_is_external or not existing_package):
                            self.function_info[callee_name] = {
                                'function': callee_name,
                                'file': callee_info.get('filePath', ''),
                                'package': callee_package,
                                'isExternal': True,
                                'moduleType': callee_info.get('moduleType', 'npm'),
                            }
                    
                    # Map callee file and package
                    callee_file = callee_info.get('filePath', '')
                    if callee_file:
                        self.file_to_functions[callee_file].append(callee_name)
                    
                    callee_package = callee_info.get('packageName', '')
                    if callee_package:
                        self.package_to_functions[callee_package].append(callee_name)
                        if callee_info.get('isExternal', False):
                            self.imported_packages.add(callee_package)
                
                if edges:
                    self.graph[caller] = edges
            
            self.loaded = True
            return True
            
        except Exception as e:
            print(f"Error loading call graph: {e}")
            return False
    
    def find_function_by_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        """
        Find functions matching a pattern
        
        Pattern can be:
        - Function name: "expand"
        - Class.method: "ConfigCommentParser.parseJSONLikeConfig"
        - Partial match: "parseJSON"
        """
        matches = []
        pattern_lower = pattern.lower()
        
        for func_name, func_info in self.function_info.items():
            func_name_lower = func_name.lower()
            
            # Exact match
            if func_name == pattern:
                matches.append(func_info)
                continue
            
            # Partial match in function name
            if pattern_lower in func_name_lower:
                matches.append(func_info)
                continue
            
            # Match method name (after last dot or #)
            if '.' in pattern or '#' in pattern:
                # Try matching last part
                pattern_parts = pattern.split('.')[-1].split('#')[-1]
                func_parts = func_name.split('.')[-1].split('#')[-1]
                if pattern_parts.lower() in func_parts.lower():
                    matches.append(func_info)
                    continue
        
        return matches
    
    def find_function_by_file_location(self, file_path: str, line: int, column: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Find functions by file location
        """
        matches = []
        
        # First, find functions in this file
        funcs_in_file = self.file_to_functions.get(file_path, [])
        
        # If we have position info, we could match by line/column
        # For now, return all functions in the file
        for func_name in funcs_in_file:
            if func_name in self.function_info:
                matches.append(self.function_info[func_name])
        
        return matches
    
    def get_function_info(self, function_name: str) -> Dict[str, Any]:
        """Get function information"""
        return self.function_info.get(function_name, {
            'function': function_name,
            'file': '',
            'package': '',
            'isExternal': False,
            'moduleType': 'internal',
        })
    
    def find_functions_by_package(self, package_name: str) -> List[Dict[str, Any]]:
        """Find all functions from a specific package"""
        func_names = self.package_to_functions.get(package_name, [])
        return [self.function_info.get(name, {}) for name in func_names if name in self.function_info]
    
    def resolve_function_name(self, function_name: str, package_name: str = None, file_path: str = None) -> List[str]:
        """
        Resolve a function name (possibly simplified) to full function names in Call Graph
        
        Args:
            function_name: Function name (e.g., "append", "FormData.prototype.append", "_multiPartHeader")
            package_name: Optional package name to narrow search
            file_path: Optional file path to narrow search (prioritized for same-file matches)
        
        Returns:
            List of full function names that match and exist in Call Graph
        """
        resolved = []
        func_name_lower = function_name.lower()
        
        # First, try exact match
        if function_name in self.graph:
            resolved.append(function_name)
        
        # Priority 1: If file_path is provided, search in that file FIRST (same-file matches are most accurate)
        if file_path:
            # Normalize file_path to handle various formats
            possible_file_paths = []
            
            if file_path == package_name or (not file_path.startswith('node_modules') and not '/' in file_path):
                # Likely just a package name, construct possible paths
                if package_name:
                    possible_file_paths = [
                        f"node_modules/{package_name}",
                        f"node_modules/{package_name}/lib",
                        f"node_modules/{package_name}/src",
                        f"node_modules/{package_name}/lib/form_data.js",
                        f"node_modules/{package_name}/index.js",
                    ]
            else:
                possible_file_paths = [file_path]
                # Also try normalized versions
                if 'node_modules' in file_path:
                    parts = file_path.split('node_modules/')
                    if len(parts) > 1:
                        possible_file_paths.append('node_modules/' + parts[1])
                        # Also try with full path
                        possible_file_paths.append(file_path)
            
            # Search in all possible file paths (prioritized)
            for search_file_path in possible_file_paths:
                # Strategy 1: Search in file_to_functions (fast lookup)
                for func_name_in_file in self.file_to_functions.get(search_file_path, []):
                    if func_name_in_file in self.graph:
                        # Check if function name matches (exact or method name)
                        if func_name_in_file == function_name:
                            if func_name_in_file not in resolved:
                                resolved.append(func_name_in_file)
                        else:
                            # Check if it's a method name match
                            if '.' in func_name_in_file:
                                method_name = func_name_in_file.split('.')[-1].split('::')[-1]
                                if method_name == function_name or method_name.lower() == func_name_lower:
                                    if func_name_in_file not in resolved:
                                        resolved.append(func_name_in_file)
                            elif func_name_lower in func_name_in_file.lower():
                                if func_name_in_file not in resolved:
                                    resolved.append(func_name_in_file)
                
                # Strategy 2: Search all functions with matching file path (more thorough)
                for full_func_name in self.graph.keys():
                    func_info = self.function_info.get(full_func_name, {})
                    func_file = func_info.get('file', '')
                    
                    # Check if file path matches (substring or exact match)
                    file_matches = (
                        search_file_path in func_file or 
                        func_file.endswith(search_file_path) or
                        func_file == search_file_path
                    )
                    
                    if file_matches:
                        # Check if function name matches
                        if full_func_name == function_name:
                            if full_func_name not in resolved:
                                resolved.append(full_func_name)
                        else:
                            # Extract method name from full path
                            if '.' in full_func_name:
                                method_name = full_func_name.split('.')[-1].split('::')[-1]
                                # Match by method name (e.g., "_multiPartHeader" matches "FormData.prototype._multiPartHeader")
                                if method_name == function_name or method_name.lower() == func_name_lower:
                                    if full_func_name not in resolved:
                                        resolved.append(full_func_name)
                            # Also check if function_name is a substring
                            elif func_name_lower in full_func_name.lower():
                                if full_func_name not in resolved:
                                    resolved.append(full_func_name)
        
        # Priority 2: If package_name is provided, search in that package
        if package_name:
            package_name_lower = package_name.lower().strip()
            
            # Search through all functions in Call Graph that belong to this package
            for full_func_name in self.graph.keys():
                # Skip if already resolved from file_path (prioritize file matches)
                if full_func_name in resolved:
                    continue
                
                # Get package info from function_info
                func_info = self.function_info.get(full_func_name, {})
                func_package = func_info.get('package', '').lower().strip()
                
                # Package must match
                if func_package != package_name_lower:
                    continue
                
                # Check if function name matches
                if full_func_name == function_name:
                    resolved.append(full_func_name)
                elif func_name_lower in full_func_name.lower():
                    # Check if it's a method match (e.g., "append" matches "FormData.prototype.append")
                    if '.' in full_func_name:
                        # Extract method name from full path
                        method_name = full_func_name.split('.')[-1].split('::')[-1]
                        if method_name == function_name or method_name.lower() == func_name_lower:
                            resolved.append(full_func_name)
                    elif full_func_name.lower() == func_name_lower:
                        resolved.append(full_func_name)
        
        # Remove duplicates while preserving order
        seen = set()
        result = []
        for name in resolved:
            if name not in seen and name in self.graph:  # Ensure it exists in graph
                seen.add(name)
                result.append(name)
        
        return result

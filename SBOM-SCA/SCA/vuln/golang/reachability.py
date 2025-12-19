#!/usr/bin/env python3
"""
Reachability analysis module
"""

from typing import Dict, List, Any, Optional
from collections import deque
from .callgraph import CallGraphLoader


class ReachabilityAnalyzer:
    """Reachability analyzer"""
    
    def __init__(self, callgraph_loader: CallGraphLoader):
        self.callgraph = callgraph_loader
    
    def analyze_trace(self, trace: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze reachability for a single trace
        
        Returns:
            {
                'reachable': bool,
                'entry_function': {...} or None,
                'vulnerable_function': {...} or None,
                'path': [...] or None,
                'path_length': int,
                'reason': str (if unreachable)
            }
        """
        entry_point = trace.get('entry_point', '')
        entry_function = trace.get('entry_function', '')
        vulnerable_function = trace.get('vulnerable_function', '')
        
        entry_funcs = []
        if entry_point:
            file_path, line_str = entry_point.split(':')[:2]
            line = int(line_str) if line_str.isdigit() else 0
            found_by_location = self.callgraph.find_function_by_file_location(file_path, line)
            
            if entry_function and found_by_location:
                pattern_funcs = self.callgraph.find_function_by_pattern(entry_function)
                pattern_func_names = {f['function'] for f in pattern_funcs}
                
                entry_funcs = [f for f in found_by_location if f['function'] in pattern_func_names]
                
                if not entry_funcs and pattern_funcs:
                    entry_funcs = pattern_funcs
            else:
                entry_funcs = found_by_location
        
        if not entry_funcs and entry_function:
            entry_funcs = self.callgraph.find_function_by_pattern(entry_function)
        
        if not entry_funcs:
            return {
                'reachable': False,
                'entry_function': None,
                'vulnerable_function': None,
                'path': None,
                'path_length': 0,
                'reason': 'Entry function not found in Call Graph'
            }
        
        if not vulnerable_function:
            return {
                'reachable': False,
                'entry_function': entry_funcs[0] if entry_funcs else None,
                'vulnerable_function': None,
                'path': None,
                'path_length': 0,
                'reason': 'Vulnerable function information missing'
            }
        
        vuln_funcs = self.callgraph.find_function_by_pattern(vulnerable_function)
        if not vuln_funcs:
            return {
                'reachable': False,
                'entry_function': entry_funcs[0] if entry_funcs else None,
                'vulnerable_function': None,
                'path': None,
                'path_length': 0,
                'reason': 'Vulnerable function not found in Call Graph'
            }
        
        start_func = entry_funcs[0]['function']
        path = self._find_path(start_func, vulnerable_function)
        
        if path:
            return {
                'reachable': True,
                'entry_function': entry_funcs[0],
                'vulnerable_function': vuln_funcs[0],
                'path': path,
                'path_length': len(path),
                'reason': None
            }
        else:
            return {
                'reachable': False,
                'entry_function': entry_funcs[0] if entry_funcs else None,
                'vulnerable_function': vuln_funcs[0] if vuln_funcs else None,
                'path': None,
                'path_length': 0,
                'reason': 'Path not found in Call Graph (max_depth=30 exceeded or no path exists)'
            }
    
    def _find_path(self, start_func: str, target_pattern: str, max_depth: int = 30) -> Optional[List[Dict[str, Any]]]:
        """Find path using BFS with exact matches only"""
        if start_func not in self.callgraph.graph:
            return None
        
        target_funcs = self.callgraph.find_function_by_pattern(target_pattern)
        if not target_funcs:
            return None
        
        pattern_parts = target_pattern.split('.')
        original_method = pattern_parts[-1] if pattern_parts else ''
        
        prioritized_funcs = []
        other_funcs = []
        
        for func_info in target_funcs:
            func_name = func_info['function']
            if ')' in func_name:
                parts = func_name.split(')', 1)
                if len(parts) == 2:
                    method_name = parts[1].lstrip('.')
                else:
                    method_name = func_name.split('.')[-1] if '.' in func_name else ''
            else:
                method_name = func_name.split('.')[-1] if '.' in func_name else ''
            
            if method_name == original_method:
                prioritized_funcs.append(func_info)
            else:
                other_funcs.append(func_info)
        
        all_targets = prioritized_funcs + other_funcs
        
        for func_info in all_targets:
            target_func = func_info['function']
            result = self._bfs_search(start_func, target_func, max_depth)
            if result:
                return result
        
        return None
    
    def _bfs_search(self, start_func: str, target_func: str, max_depth: int) -> Optional[List[Dict[str, Any]]]:
        """Find path to target function using BFS"""
        if start_func not in self.callgraph.graph:
            return None
        
        queue = deque([(start_func, [start_func], 0)])
        visited = {start_func}
        
        while queue:
            current, path, depth = queue.popleft()
            
            if depth > max_depth:
                continue
            
            if current == target_func:
                path_info = []
                for func_name in path:
                    func_info = self.callgraph.get_function_info(func_name)
                    path_info.append(func_info)
                return path_info
            
            for edge in self.callgraph.graph.get(current, []):
                callee = edge['callee']
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee], depth + 1))
        
        return None
    
    def get_all_entry_points(self, only_main: bool = False) -> List[Dict[str, Any]]:
        """
        Find entry points in Call Graph
        
        Args:
            only_main: True for main functions only, False for true entry points
        
        Returns:
            List of entry point function info
        """
        entry_points = []
        
        if only_main:
            for caller in self.callgraph.graph.keys():
                if not caller:
                    continue
                
                parts = caller.split('.')
                if parts:
                    last_part = parts[-1]
                    if last_part == 'main' or last_part.startswith('main$'):
                        func_info = self.callgraph.get_function_info(caller)
                        entry_points.append({
                            'function': caller,
                            'module': func_info.get('module', ''),
                            'package': func_info.get('package', ''),
                            'call_site_files': func_info.get('call_site_files', []),
                            'callees_count': len(self.callgraph.graph.get(caller, []))
                        })
        else:
            all_callers = set(self.callgraph.graph.keys())
            all_callees = set()
            
            for caller in self.callgraph.graph.keys():
                for edge in self.callgraph.graph[caller]:
                    callee = edge.get('callee', '')
                    if callee:
                        all_callees.add(callee)
            
            true_entry_points = all_callers - all_callees
            
            for caller in true_entry_points:
                func_info = self.callgraph.get_function_info(caller)
                entry_points.append({
                    'function': caller,
                    'module': func_info.get('module', ''),
                    'package': func_info.get('package', ''),
                    'call_site_files': func_info.get('call_site_files', []),
                    'callees_count': len(self.callgraph.graph.get(caller, []))
                })
        
        return entry_points
    
    def analyze_vulnerable_function_from_all_entries(
        self, 
        vulnerable_function: str, 
        max_entry_points: Optional[int] = None,
        max_depth: int = 50,
        only_main: bool = False
    ) -> Dict[str, Any]:
        """
        Find reachable entry points for a vulnerable function
        
        Args:
            vulnerable_function: Vulnerable function pattern (e.g., "x509.Certificate.Verify")
            max_entry_points: Max entry points to check (None for all)
            max_depth: BFS max depth
            only_main: True for main functions only, False for all entry points
        """
        original_pattern = vulnerable_function
        pattern_candidates = [original_pattern]
        
        alt_pattern = self._generate_go_unexported_variant(original_pattern)
        if alt_pattern and alt_pattern not in pattern_candidates:
            pattern_candidates.append(alt_pattern)
        
        matched_pattern = None
        vuln_funcs = []
        for pattern in pattern_candidates:
            funcs = self.callgraph.find_function_by_pattern(pattern)
            if funcs:
                vuln_funcs = funcs
                matched_pattern = pattern
                break
        
        # Special handling for init functions
        # Init functions are automatically executed when package is imported,
        # regardless of whether they're called or appear in call graph
        is_init_function = original_pattern.endswith('.init') or original_pattern == 'init'
        
        if not vuln_funcs and not is_init_function:
            return {
                'vulnerable_function': original_pattern,
                'vulnerable_function_pattern': original_pattern,
                'call_graph_functions': [],
                'vulnerable_function_info': None,
                'total_entry_points': 0,
                'checked_entry_points': 0,
                'reaching_entry_points': [],
                'unreachable_count': 0,
                'reachable': False,
                'reason': 'Vulnerable function not found in Call Graph'
            }
        
        # For init functions, always check package import (not function calls)
        # Init functions execute automatically when package is imported
        if is_init_function:
            # Extract package from vulnerable_function pattern or from call graph
            # Format: "package.init" or "module/package.init"
            # If found in call graph, use the actual package from there
            if vuln_funcs:
                # Use package from call graph (most accurate)
                package = vuln_funcs[0].get('package', '')
                if not package:
                    # Fallback: extract from function name
                    func_name = vuln_funcs[0].get('function', '')
                    if '.init' in func_name:
                        # Extract package from function name like "github.com/user/pkg.init"
                        parts = func_name.rsplit('.init', 1)
                        if len(parts) == 2:
                            # Remove method receiver if present
                            pkg_part = parts[0]
                            if ')' in pkg_part:
                                pkg_part = pkg_part.split(')')[-1].lstrip('.')
                            package = pkg_part
                else:
                    # Package found, use it
                    pass
            else:
                # Not in call graph, try to extract from pattern
                package = vulnerable_function.replace('.init', '').strip()
            
            # Include function info if found in call graph
            mapped_functions = [{
                'function': f['function'],
                'module': f.get('module', ''),
                'package': f.get('package', '')
            } for f in vuln_funcs] if vuln_funcs else []
            
            # Use function info from call graph if available, otherwise create from package
            if vuln_funcs:
                init_func_info = vuln_funcs[0]
            else:
                init_func_info = {
                    'function': original_pattern,
                    'module': package.split('/')[0] if '/' in package else '',
                    'package': package
                }
            
            # Check if any function from this package is used in the call graph
            # Use actual package name from call graph if available
            package_used = self._is_package_used_in_callgraph(package) if package else False
            
            if package_used:
                # Init functions are automatically executed when package is imported
                # Find entry points that use this package
                all_entry_points = self.get_all_entry_points(only_main=only_main)
                package_using_entries = self._find_entries_using_package(all_entry_points, package)
                
                return {
                    'vulnerable_function': original_pattern,
                    'vulnerable_function_pattern': original_pattern,
                    'call_graph_functions': mapped_functions,
                    'vulnerable_function_info': init_func_info,
                    'target_function': vuln_funcs[0]['function'] if vuln_funcs else None,
                    'total_entry_points': len(all_entry_points),
                    'checked_entry_points': len(all_entry_points),
                    'reaching_entry_points': package_using_entries,
                    'unreachable_count': len(all_entry_points) - len(package_using_entries),
                    'reachable': len(package_using_entries) > 0,
                    'reason': 'Init function - automatically executed when package is imported'
                }
            else:
                return {
                    'vulnerable_function': original_pattern,
                    'vulnerable_function_pattern': original_pattern,
                    'call_graph_functions': mapped_functions,
                    'vulnerable_function_info': init_func_info,
                    'target_function': vuln_funcs[0]['function'] if vuln_funcs else None,
                    'total_entry_points': 0,
                    'checked_entry_points': 0,
                    'reaching_entry_points': [],
                    'unreachable_count': 0,
                    'reachable': False,
                    'reason': 'Init function - package not used in Call Graph'
                }
        
        mapped_functions = [{
            'function': f['function'],
            'module': f.get('module', ''),
            'package': f.get('package', '')
        } for f in vuln_funcs]
        
        target_func = vuln_funcs[0]['function']
        target_func_info = vuln_funcs[0]
        
        all_entry_points = self.get_all_entry_points(only_main=only_main)
        total_entry_points = len(all_entry_points)
        
        entry_points_to_check = all_entry_points
        if max_entry_points and max_entry_points > 0:
            entry_points_to_check = all_entry_points[:max_entry_points]
        
        reaching_entry_points = []
        
        for entry_info in entry_points_to_check:
            entry_func = entry_info['function']
            
            if entry_func not in self.callgraph.graph:
                continue
            
            path = self._bfs_search(entry_func, target_func, max_depth)
            
            if path:
                reaching_entry_points.append({
                    'entry_function': entry_info,
                    'path': path,
                    'path_length': len(path)
                })
        
        if not reaching_entry_points:
            init_reaching_entries = self._analyze_init_based_reachability(
                target_func_info,
                entry_points_to_check
            )
            if init_reaching_entries:
                reaching_entry_points = init_reaching_entries
        
        return {
            'vulnerable_function': original_pattern,
            'vulnerable_function_pattern': original_pattern,
            'call_graph_functions': mapped_functions,
            'vulnerable_function_info': target_func_info,
            'target_function': target_func,
            'total_entry_points': total_entry_points,
            'checked_entry_points': len(entry_points_to_check),
            'reaching_entry_points': reaching_entry_points,
            'unreachable_count': len(entry_points_to_check) - len(reaching_entry_points),
            'reachable': len(reaching_entry_points) > 0,
            'reason': None
        }
    
    def _generate_go_unexported_variant(self, pattern: str) -> Optional[str]:
        """
        Generate an alternative Go function pattern corresponding to an
        unexported variant of the same symbol (e.g., os.NewFile -> os.newFile).
        """
        if not pattern:
            return None
        
        parts = [p for p in pattern.split('.') if p]
        if not parts:
            return None
        
        candidate_parts = parts[:]
        last = candidate_parts[-1]
        if not last:
            return None
        
        if last[0].isupper():
            candidate_parts[-1] = last[0].lower() + last[1:]
            return '.'.join(candidate_parts)
        
        return None
    
    def _analyze_init_based_reachability(
        self,
        target_func_info: Dict[str, Any],
        entry_points: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Handle cases where a vulnerable function is invoked from package init
        functions, making it implicitly reachable when the package is imported.
        """
        if not target_func_info:
            return []
        
        target_function = target_func_info.get('function', '')
        target_package = (target_func_info.get('package') or '').lower()
        
        if not target_function or not target_package:
            return []
        
        init_callers = []
        for caller, edges in self.callgraph.graph.items():
            if not caller:
                continue
            
            if not (caller.endswith('.init') or caller == 'init'):
                continue
            
            caller_info = self.callgraph.get_function_info(caller)
            caller_package = (caller_info.get('package') or '').lower()
            if caller_package and target_package not in caller_package:
                continue
            
            for edge in edges:
                if edge.get('callee') == target_function:
                    init_callers.append(caller_info)
                    break
        
        if not init_callers:
            return []
        
        package_entries = self._find_entries_using_package(entry_points, target_package)
        if not package_entries:
            return []
        
        reaching_entry_points = []
        target_info = target_func_info
        
        for entry in package_entries:
            entry_info = entry['entry_function']
            path = entry.get('path', [])[:]
            if not path:
                path = [self.callgraph.get_function_info(entry_info['function'])]
            
            # Append init caller (first match) and target function
            path = path + [init_callers[0], target_info]
            
            reaching_entry_points.append({
                'entry_function': entry_info,
                'path': path,
                'path_length': len(path)
            })
        
        return reaching_entry_points
    
    def _is_package_used_in_callgraph(self, package: str) -> bool:
        """
        Check if a package is imported/used anywhere in the call graph
        
        Uses pre-extracted imported_packages set for O(1) lookup.
        If a package appears in the call graph, it means it's imported.
        Since init functions are automatically executed when a package is imported,
        we check if the package appears in the imported_packages set.
        """
        package_lower = package.lower()
        
        # Direct lookup in pre-extracted imported packages set
        if package_lower in self.callgraph.imported_packages:
            return True
        
        # Also check if any package in the set starts with the given package path
        # This handles cases like "errors" matching "errors" or "errors/..."
        for imported_pkg in self.callgraph.imported_packages:
            if imported_pkg == package_lower or imported_pkg.startswith(package_lower + '/'):
                return True
        
        return False
    
    def _find_entries_using_package(self, entry_points: List[Dict[str, Any]], package: str) -> List[Dict[str, Any]]:
        """
        Find entry points that import/use the given package
        
        Uses pre-extracted imported_packages set for efficient lookup.
        Since init functions execute when a package is imported (not necessarily called),
        we check if the package appears in the call graph reachable from entry points.
        """
        using_entries = []
        package_lower = package.lower()
        
        # First check if package is imported at all
        if not self._is_package_used_in_callgraph(package):
            return using_entries
        
        for entry_info in entry_points:
            entry_func = entry_info['function']
            
            # Check if entry point itself is from the package
            entry_func_info = self.callgraph.get_function_info(entry_func)
            entry_package = entry_func_info.get('package', '').lower()
            if entry_package == package_lower or entry_package.startswith(package_lower + '/'):
                using_entries.append({
                    'entry_function': entry_info,
                    'path': [entry_func_info],
                    'path_length': 1
                })
                continue
            
            # Check if entry point's call chain reaches any function from the package (BFS)
            # This indicates the package is imported and available in that call chain
            visited = set()
            queue = deque([entry_func])
            visited.add(entry_func)
            found = False
            path_to_package = []
            
            while queue and not found:
                current = queue.popleft()
                
                for edge in self.callgraph.graph.get(current, []):
                    callee = edge.get('callee', '')
                    if callee in visited:
                        continue
                    visited.add(callee)
                    
                    callee_info = self.callgraph.get_function_info(callee)
                    callee_package = callee_info.get('package', '').lower()
                    
                    # If package appears in call chain, it's imported
                    if callee_package == package_lower or callee_package.startswith(package_lower + '/'):
                        # Build path: entry -> ... -> package function
                        path_to_package = [self.callgraph.get_function_info(entry_func), callee_info]
                        using_entries.append({
                            'entry_function': entry_info,
                            'path': path_to_package,
                            'path_length': len(path_to_package)
                        })
                        found = True
                        break
                    
                    queue.append(callee)
        
        return using_entries

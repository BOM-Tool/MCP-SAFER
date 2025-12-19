#!/usr/bin/env python3
"""
TypeScript reachability analysis module
Analyzes reachability of vulnerable functions from entry points using call graph
"""

from typing import Dict, List, Any, Optional
from collections import deque
from .callgraph import TypeScriptCallGraphLoader


class TypeScriptReachabilityAnalyzer:
    """TypeScript reachability analyzer using BFS pathfinding"""
    
    def __init__(self, callgraph_loader: TypeScriptCallGraphLoader):
        self.callgraph = callgraph_loader
    
    def get_all_entry_points(self, only_main: bool = False) -> List[Dict[str, Any]]:
        """
        Get all entry points from the call graph
        
        Args:
            only_main: If True, only return [top-level] functions as entry points
                      If False, return all non-external functions
        
        Returns:
            List of entry point function information
        """
        entry_points = []
        
        for func_name, func_info in self.callgraph.function_info.items():
            # Skip external functions as entry points
            if func_info.get('isExternal', False):
                continue
            
            is_top_level = '[top-level]' in func_name
            
            if only_main:
                # Only [top-level] functions as entry points
                if is_top_level:
                    entry_points.append(func_info)
            else:
                # All non-external functions as potential entry points
                entry_points.append(func_info)
        
        return entry_points
    
    def analyze_vulnerable_function_from_all_entries(
        self, 
        vulnerable_function: str, 
        package_name: Optional[str] = None,
        max_entry_points: Optional[int] = None,
        max_depth: int = 50,
        only_main: bool = False
    ) -> Dict[str, Any]:
        """
        Find reachable entry points for a vulnerable function using BFS
        
        Args:
            vulnerable_function: Vulnerable function pattern (e.g., "ConfigCommentParser.parseJSONLikeConfig")
            package_name: Package name (for package-level analysis when function not in call graph)
            max_entry_points: Max entry points to check (None for all)
            max_depth: BFS max depth
            only_main: True for main functions only, False for all entry points
        
        Returns:
            Analysis result dictionary
        """
        all_entry_points = self.get_all_entry_points(only_main=only_main)
        
        # Try to find vulnerable function in call graph
        # First, try to find functions from the vulnerable package (if package_name provided)
        vuln_funcs = []
        if package_name:
            # Find functions from the vulnerable package first
            package_funcs = self.callgraph.find_functions_by_package(package_name)
            # Then filter by function name pattern
            for pkg_func in package_funcs:
                func_name = pkg_func.get('function', '')
                # Check if function name matches the vulnerable function pattern
                if self._function_name_matches_pattern(func_name, vulnerable_function):
                    vuln_funcs.append(pkg_func)
        
        # If not found by package, try pattern matching (but prefer package-filtered results)
        if not vuln_funcs:
            all_matches = self.callgraph.find_function_by_pattern(vulnerable_function)
            # If package_name is provided, filter matches by package
            if package_name:
                for match in all_matches:
                    match_package = match.get('package', '').strip()
                    match_file = match.get('file', '').strip()
                    
                    # Try to infer package from filePath if package is empty or wrong
                    inferred_package = None
                    if match_file and 'node_modules' in match_file:
                        # Extract package name from node_modules path
                        # e.g., node_modules/form-data/lib/form_data.js -> form-data
                        parts = match_file.split('node_modules/')
                        if len(parts) > 1:
                            remaining = parts[1]
                            # Handle scoped packages (@scope/package)
                            if remaining.startswith('@'):
                                pkg_parts = remaining.split('/')
                                if len(pkg_parts) >= 2:
                                    inferred_package = f"{pkg_parts[0]}/{pkg_parts[1]}"
                            else:
                                pkg_parts = remaining.split('/')
                                if len(pkg_parts) > 0:
                                    inferred_package = pkg_parts[0]
                    
                    # Use inferred package if available and matches
                    package_to_check = inferred_package if inferred_package else match_package
                    
                    if package_to_check:
                        package_to_check_lower = package_to_check.lower().strip()
                        pkg_name_lower = package_name.lower().strip()
                        
                        # Check if match belongs to the vulnerable package (exact match)
                        # Exact package name match (avoid substring matches like "vite" matching "vitest")
                        if package_to_check_lower == pkg_name_lower:
                            # Update match with correct package if inferred
                            if inferred_package and inferred_package != match_package:
                                match = match.copy()
                                match['package'] = inferred_package
                                match['isExternal'] = True
                            vuln_funcs.append(match)
            else:
                # No package filter, use all matches
                vuln_funcs = all_matches
        
        # If function not found, check if package is used in call graph and try to find the vulnerable function
        if not vuln_funcs and package_name:
            package_using_entries = self._find_entries_using_package(
                all_entry_points, package_name, vulnerable_function
            )
            
            if package_using_entries:
                # Found the vulnerable function through BFS search
                return {
                    'vulnerable_function': vulnerable_function,
                    'vulnerable_function_pattern': vulnerable_function,
                    'call_graph_functions': [],
                    'vulnerable_function_info': {
                        'function': vulnerable_function,
                        'package': package_name,
                        'isExternal': True,
                    },
                    'target_function': None,
                    'total_entry_points': len(all_entry_points),
                    'checked_entry_points': len(all_entry_points),
                    'reaching_entry_points': package_using_entries,
                    'unreachable_count': len(all_entry_points) - len(package_using_entries),
                    'reachable': True,
                    'reason': f'Vulnerable function "{vulnerable_function}" found in call graph via BFS search from entry points'
                }
        
        # If still not found, return unreachable
        if not vuln_funcs:
            return {
                'vulnerable_function': vulnerable_function,
                'vulnerable_function_pattern': vulnerable_function,
                'call_graph_functions': [],
                'vulnerable_function_info': None,
                'total_entry_points': len(all_entry_points),
                'checked_entry_points': 0,
                'reaching_entry_points': [],
                'unreachable_count': 0,
                'reachable': False,
                'reason': 'Vulnerable function not found in Call Graph'
            }
        
        # Map found functions
        mapped_functions = [{
            'function': f['function'],
            'file': f.get('file', ''),
            'package': f.get('package', '')
        } for f in vuln_funcs]
        
        # Select target function: prefer the one that exists in Call Graph
        target_func = None
        target_func_info = None
        
        # Helper to resolve and find target in Call Graph
        def find_target_in_graph(func_name: str, func_package: str = None) -> Optional[str]:
            # Check exact match
            if func_name in self.callgraph.graph:
                return func_name
            # Try to resolve
            if func_package:
                resolved = self.callgraph.resolve_function_name(func_name, package_name=func_package)
                for resolved_name in resolved:
                    if resolved_name in self.callgraph.graph:
                        return resolved_name
            return None
        
        # First, try to find a function that exists in Call Graph (exact or resolved)
        for vuln_func in vuln_funcs:
            func_name = vuln_func['function']
            func_package = vuln_func.get('package', package_name)
            
            # Try to find in graph
            found_target = find_target_in_graph(func_name, func_package)
            if found_target:
                target_func = found_target
                target_func_info = vuln_func.copy()
                target_func_info['function'] = found_target
                break
        
        # If none found in graph, use the first one (will try pattern matching in BFS)
        if not target_func:
            target_func = vuln_funcs[0]['function']
            target_func_info = vuln_funcs[0]
        
        # Check reachability from entry points
        entry_points_to_check = all_entry_points
        
        # 개선: main entry point([top-level])에서 취약한 함수까지의 전체 경로를 추적
        # only_main=True일 때는 이미 [top-level] 진입점만 있으므로 추가 필터링 불필요
        if only_main:
            # only_main=True일 때는 이미 필터링된 [top-level] 진입점 사용
            if max_entry_points and max_entry_points > 0:
                entry_points_to_check = all_entry_points[:max_entry_points]
        elif package_name and max_entry_points and max_entry_points > 0:
            # only_main=False일 때는 [top-level]을 제외하고 관련 프로젝트 함수 확인
            package_name_lower = package_name.lower().strip()
            
            # 프로젝트 내부 함수 중에서 해당 패키지를 사용하는 것 찾기 ([top-level] 제외)
            project_entries = []
            for entry_info in all_entry_points:
                entry_func = entry_info.get('function', '')
                entry_file = entry_info.get('file', '')
                
                # [top-level]과 node_modules 내부 함수는 제외
                if '[top-level]' in entry_func or 'node_modules' in entry_file:
                    continue
                
                # Call Graph에서 이 함수가 해당 패키지를 사용하는지 확인
                if entry_func in self.callgraph.graph:
                    edges = self.callgraph.graph[entry_func]
                    for edge in edges:
                        callee_package = edge.get('package', '')
                        callee_file = edge.get('file', '')
                        
                        # 패키지 이름이 일치하거나 파일 경로에 패키지 이름이 포함된 경우
                        if (callee_package and package_name_lower in callee_package.lower()) or \
                           (callee_file and package_name_lower in callee_file.lower()):
                            project_entries.append(entry_info)
                            break
            
            if project_entries:
                entry_points_to_check = project_entries[:max_entry_points]
                print(f"         Found {len(project_entries)} project entry points using package (excluding [top-level])")
            else:
                # 최후의 수단: 모든 진입점 중 [top-level]과 node_modules 제외
                non_top_level = [e for e in all_entry_points 
                                if '[top-level]' not in e.get('function', '') and 'node_modules' not in e.get('file', '')]
                entry_points_to_check = non_top_level[:max_entry_points]
                print(f"         Using {len(entry_points_to_check)} non-[top-level] entry points")
        elif max_entry_points and max_entry_points > 0:
            # 패키지 정보가 없으면 [top-level] 제외하고 프로젝트 내부 함수만
            non_top_level = [e for e in all_entry_points 
                            if '[top-level]' not in e.get('function', '') and 'node_modules' not in e.get('file', '')]
            entry_points_to_check = non_top_level[:max_entry_points]
        
        reaching_entry_points = []
        
        for entry_info in entry_points_to_check:
            entry_func = entry_info.get('function', '')
            
            if not entry_func:
                continue
            
            # Resolve entry function if needed
            entry_resolved = [entry_func]
            if entry_func not in self.callgraph.graph:
                # Try to resolve entry function
                entry_package = entry_info.get('package', '')
                entry_file = entry_info.get('file', '')
                if entry_package:
                    resolved = self.callgraph.resolve_function_name(entry_func, package_name=entry_package, file_path=entry_file)
                    if resolved:
                        entry_resolved = resolved
                    elif entry_func in self.callgraph.graph:
                        entry_resolved = [entry_func]
                    else:
                        continue  # Skip if entry function not found
                else:
                    continue  # Skip if entry function not in graph and no package info
            
            # Try BFS for each resolved entry function
            for resolved_entry in entry_resolved:
                if resolved_entry not in self.callgraph.graph:
                    continue
                
                # Try BFS with exact match first (BFS will handle resolution internally)
                path = self._bfs_search(resolved_entry, target_func, max_depth)
                
                # If not found and target_func is a simple name, try pattern matching
                if not path and target_func and '.' not in target_func and '::' not in target_func:
                    # Try to find all functions matching the pattern
                    matching_funcs = [f for f in self.callgraph.graph.keys() 
                                     if target_func in f or self._function_name_matches_pattern(f, target_func)]
                    
                    for matching_func in matching_funcs:
                        path = self._bfs_search(resolved_entry, matching_func, max_depth)
                        if path:
                            break
                
                if path:
                    reaching_entry_points.append({
                        'entry_function': entry_info,
                        'path': path,
                        'path_length': len(path)
                    })
                    # 최적화: 경로를 찾으면 즉시 중단 (1개만 찾아도 충분)
                    # 성능 개선: 여러 경로를 찾는 것보다 빠르게 하나만 찾는 것이 중요
                    break  # 경로를 찾으면 즉시 중단
            
            # 최적화: 경로를 찾으면 전체 루프 중단 (성능 최적화)
            if reaching_entry_points:
                break
        
        return {
            'vulnerable_function': vulnerable_function,
            'vulnerable_function_pattern': vulnerable_function,
            'call_graph_functions': mapped_functions,
            'vulnerable_function_info': target_func_info,
            'target_function': target_func,
            'total_entry_points': len(all_entry_points),
            'checked_entry_points': len(entry_points_to_check),
            'reaching_entry_points': reaching_entry_points,
            'unreachable_count': len(entry_points_to_check) - len(reaching_entry_points),
            'reachable': len(reaching_entry_points) > 0,
            'reason': None
        }
    
    def _bfs_search(self, start_func: str, target_func: str, max_depth: int) -> Optional[List[Dict[str, Any]]]:
        """
        BFS search to find path from start to target function
        
        Returns:
            List of function info dicts representing the path, or None if not found
        """
        # Helper function to resolve function name to actual Call Graph functions
        def resolve_to_graph_funcs(func_name: str, package: str = None, file_path: str = None) -> List[str]:
            """Resolve a function name to actual functions in Call Graph"""
            # First check if it's already a full path in graph
            if func_name in self.callgraph.graph:
                return [func_name]
            
            resolved = []
            # Try to resolve if package OR file_path is provided (file_path is more accurate)
            if package or file_path:
                resolved = self.callgraph.resolve_function_name(func_name, package_name=package, file_path=file_path)
            
            # Only return functions that actually exist in Call Graph
            return [f for f in resolved if f in self.callgraph.graph]
        
        # Resolve target function to all possible matches in Call Graph
        target_info = self.callgraph.get_function_info(target_func)
        target_package = target_info.get('package', '') if target_info else ''
        target_file = target_info.get('file', '') if target_info else ''
        
        target_funcs = resolve_to_graph_funcs(target_func, target_package, target_file)
        if not target_funcs:
            # If target not in graph, try exact match
            target_funcs = [target_func] if target_func in self.callgraph.graph else []
        
        if not target_funcs:
            return None
        
        # Resolve start function
        start_resolved = resolve_to_graph_funcs(start_func)
        if not start_resolved:
            start_resolved = [start_func] if start_func in self.callgraph.graph else []
        
        if not start_resolved:
            return None
        
        start_func_actual = start_resolved[0]
        
        # Check if start is already target
        if start_func_actual in target_funcs:
            return [self.callgraph.get_function_info(start_func_actual)]
        
        # BFS with proper resolution
        visited = set()
        queue = deque([(start_func_actual, [self.callgraph.get_function_info(start_func_actual)])])
        visited.add(start_func_actual)
        
        depth = 0
        current_level_size = 1
        
        # 성능 최적화: resolve_function_name 결과 캐싱
        resolve_cache = {}
        
        while queue and depth < max_depth:
            current, path = queue.popleft()
            current_level_size -= 1
            
            if current_level_size == 0:
                depth += 1
                current_level_size = len(queue)
            
            # Get edges from Call Graph
            if current not in self.callgraph.graph:
                continue
                
            edges = self.callgraph.graph.get(current, [])
            
            # Get current function's file path for better callee resolution
            current_func_info = self.callgraph.get_function_info(current)
            current_file = current_func_info.get('file', '') if current_func_info else ''
            
            for edge in edges:
                callee = edge.get('callee', '')
                callee_package = edge.get('package', '')
                callee_file = edge.get('file', '')
                
                # Skip if callee is empty
                if not callee:
                    continue
                
                # 캐시 키 생성
                cache_key = (callee, callee_package, callee_file or current_file)
                
                # 캐시 확인
                if cache_key in resolve_cache:
                    resolved_callees = resolve_cache[cache_key]
                else:
                    # Use callee_file from edge if available, otherwise use current_file (same-file calls)
                    file_to_use = callee_file if callee_file else current_file
                    
                    # Resolve callee to actual Call Graph functions
                    # Priority: file_path > package_name (same-file matches are more accurate)
                    resolved_callees = resolve_to_graph_funcs(callee, callee_package, file_to_use)
                    
                    # If no resolution, try with current_file (for same-file calls)
                    if not resolved_callees and current_file and current_file != file_to_use:
                        resolved_callees = resolve_to_graph_funcs(callee, callee_package, current_file)
                    
                    # If still no resolution, check if callee itself is in graph
                    if not resolved_callees and callee in self.callgraph.graph:
                        resolved_callees = [callee]
                    
                    # 캐시에 저장
                    resolve_cache[cache_key] = resolved_callees
                
                # Check each resolved callee
                for resolved_callee in resolved_callees:
                    # Skip if already visited
                    if resolved_callee in visited:
                        continue
                    
                    # Mark as visited
                    visited.add(resolved_callee)
                    
                    # Check if this is the target
                    if resolved_callee in target_funcs:
                        callee_info = self.callgraph.get_function_info(resolved_callee)
                        return path + [callee_info]
                    
                    # Add to queue for further exploration
                    callee_info = self.callgraph.get_function_info(resolved_callee)
                    if callee_info:
                        queue.append((resolved_callee, path + [callee_info]))
        
        return None
    
    def _is_package_imported(self, package_name: str) -> bool:
        """Check if a package is imported in the call graph"""
        package_lower = package_name.lower().strip()
        
        # Direct lookup in imported packages
        if package_lower in self.callgraph.imported_packages:
            return True
        
        # Check if any imported package matches (handle scoped packages)
        for imported_pkg in self.callgraph.imported_packages:
            imported_lower = imported_pkg.lower()
            if imported_lower == package_lower:
                return True
            # Handle partial matches (e.g., "eslint" matches "@eslint/plugin-kit")
            if package_lower in imported_lower or imported_lower in package_lower:
                return True
        
        # Check package_to_functions mapping
        for pkg in self.callgraph.package_to_functions.keys():
            pkg_lower = pkg.lower()
            if package_lower in pkg_lower or pkg_lower in package_lower:
                return True
        
        return False
    
    def _find_entries_using_package(self, entry_points: List[Dict[str, Any]], package_name: str, vulnerable_function: str = None) -> List[Dict[str, Any]]:
        """
        Find entry points that import/use the given package using BFS.
        If vulnerable_function is provided, try to find that specific function from the package.
        """
        using_entries = []
        package_lower = package_name.lower().strip()
        
        if not self._is_package_imported(package_name):
            return using_entries
        
        for entry_info in entry_points:
            entry_func = entry_info['function']
            
            # Check if entry point itself is from the package (and is external)
            entry_func_info = self.callgraph.get_function_info(entry_func)
            entry_package = entry_func_info.get('package', '').lower().strip()
            entry_is_external = entry_func_info.get('isExternal', False)
            # Exact package name match (avoid substring matches like "vite" matching "vitest")
            if entry_package == package_lower and entry_is_external:
                # If vulnerable_function is provided, check if entry point matches it
                if vulnerable_function:
                    if self._function_name_matches_pattern(entry_func, vulnerable_function):
                        using_entries.append({
                            'entry_function': entry_info,
                            'path': [entry_func_info],
                            'path_length': 1
                        })
                else:
                    # No specific function requested
                    using_entries.append({
                        'entry_function': entry_info,
                        'path': [entry_func_info],
                        'path_length': 1
                    })
                continue
            
            # Check if entry point's call chain reaches any function from the package (BFS)
            # Use BFS with path tracking: (current_node, path_so_far, depth)
            visited = set()
            queue = deque([(entry_func, [entry_func], 0)])  # (node, path, depth)
            visited.add(entry_func)
            found = False
            max_search_depth = 20
            
            while queue and not found:
                current, path_so_far, depth = queue.popleft()
                
                if depth >= max_search_depth:
                    continue
                
                for edge in self.callgraph.graph.get(current, []):
                    callee = edge.get('callee', '')
                    if callee in visited:
                        continue
                    visited.add(callee)
                    
                    callee_info = self.callgraph.get_function_info(callee)
                    callee_package = callee_info.get('package', '').lower().strip()
                    callee_is_external = callee_info.get('isExternal', False)
                    
                    # Only consider external functions from the exact package
                    # Exact package name match (avoid substring matches like "vite" matching "vitest")
                    if callee_package == package_lower and callee_is_external:
                        # If vulnerable_function is provided, check if this function matches it
                        if vulnerable_function:
                            if self._function_name_matches_pattern(callee, vulnerable_function):
                                # Found the vulnerable function! Build path to it
                                path_to_func = [self.callgraph.get_function_info(node) for node in path_so_far]
                                path_to_func.append(callee_info)
                                
                                using_entries.append({
                                    'entry_function': entry_info,
                                    'path': path_to_func,
                                    'path_length': len(path_to_func)
                                })
                                found = True
                                break
                        else:
                            # No specific function requested, any function from package is OK
                            # Build full path: convert function names to function info
                            path_to_package = [self.callgraph.get_function_info(node) for node in path_so_far]
                            path_to_package.append(callee_info)
                            
                            using_entries.append({
                                'entry_function': entry_info,
                                'path': path_to_package,
                                'path_length': len(path_to_package)
                            })
                            found = True
                            break
                    
                    queue.append((callee, path_so_far + [callee], depth + 1))
        
        return using_entries
    
    def _function_name_matches_pattern(self, func_name: str, pattern: str) -> bool:
        """
        Check if a function name matches a pattern
        
        Args:
            func_name: Function name to check (e.g., "src/file.ts::expand")
            pattern: Pattern to match (e.g., "expand" or "ConfigCommentParser.parseJSONLikeConfig")
        
        Returns:
            True if function name matches pattern
        """
        func_name_lower = func_name.lower()
        pattern_lower = pattern.lower()
        
        # Exact match
        if func_name == pattern:
            return True
        
        # Partial match in function name
        if pattern_lower in func_name_lower:
            return True
        
        # Match method name (after last dot or #)
        if '.' in pattern or '#' in pattern:
            # Try matching last part
            pattern_parts = pattern.split('.')[-1].split('#')[-1]
            func_parts = func_name.split('.')[-1].split('#')[-1]
            if pattern_parts.lower() in func_parts.lower():
                return True
        
        return False

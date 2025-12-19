from typing import Dict, Set, Any, List, Tuple, Optional
from scanner.analyzers.common.utils import extract_var_name
from dataclasses import dataclass, field
import re

@dataclass
class PathState:
    path_id: str
    tainted_vars: Set[str] = field(default_factory=set)
    sanitized_vars: Set[str] = field(default_factory=set) 
    validated_vars: Set[str] = field(default_factory=set)
    node_states: Dict[str, Set[str]] = field(default_factory=dict)  


class SanitizationRecognizer:
    
    GO_SANITIZER_PATTERNS = [
        r'filepath\.Clean',
        r'filepath\.Join',
        r'filepath\.Abs',
        r'filepath\.EvalSymlinks',
        r'path\.Join',
        r'path\.Clean',
        r'path\.Abs',
        r'strings\.TrimSpace',
        r'strings\.Trim',
        r'strings\.Replace',
        r'strings\.TrimPrefix',
        r'html\.EscapeString',
        r'url\.QueryEscape',
        r'securejoin\.SecureJoin',
        r'regexp\.MustCompile',
        r'validator\.',
        r'\.Validate\(',
        r'\.Sanitize\(',
    ]
    
    TS_SANITIZER_PATTERNS = [
        r'escape',
        r'escapeShellArg',
        r'escapeShellCmd',
        r'sanitize',
        r'validate',
        r'validateInput',
        r'clean',
        r'filter',
        r'stripTags',
        r'removeSpecialChars',
        r'whitelistFilter',
        r'shellEscape',
        r'quote',
        r'shellescape',
        r'validator\.',
        r'\.sanitize\(',
        r'\.escape\(',
        r'\.validate\(',
    ]
    
    def __init__(self, language: str = "go"):
        self.language = language
        if language == "go":
            self.sanitizer_patterns = [re.compile(p, re.IGNORECASE) for p in self.GO_SANITIZER_PATTERNS]
        else:
            self.sanitizer_patterns = [re.compile(p, re.IGNORECASE) for p in self.TS_SANITIZER_PATTERNS]
    
    def is_sanitizer(self, func_name: str) -> bool:
        for pattern in self.sanitizer_patterns:
            if pattern.search(func_name):
                return True
        return False
    
    def find_sanitization_calls(self, ast_result: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        sanitization_calls = {}
        
        for call in ast_result.get('calls', []):
            func_name = call.get('function', '')
            package = call.get('package', '')
            
            if package:
                full_name = f"{package}.{func_name}"
            else:
                full_name = func_name
            
            if self.is_sanitizer(full_name):
                line = call.get('line', 0)
                if line not in sanitization_calls:
                    sanitization_calls[line] = []
                
                sanitization_calls[line].append({
                    'function': full_name,
                    'line': line,
                    'column': call.get('column', 0),
                    'args': call.get('args', [])
                })
        
        return sanitization_calls


class TaintPropagationEngine:
    
    def __init__(self, language: str = "go"):
        self.enable_control_flow_sensitive = True
        self.enable_path_sensitive = True
        self.sanitization_recognizer = SanitizationRecognizer(language)
    
    def analyze(self, ast_result: Dict[str, Any], cfg: Any, dataflow_result: Dict[str, Any]) -> Dict[str, Any]:
        print("  Step 4: Analyzing taint propagation...")
        
        initial_tainted = self._collect_initial_sources(ast_result)
        print(f"    Found {len(initial_tainted)} initial taint sources")
        
        flow_graph = self._build_flow_graph(ast_result)
        print(f"    Built data flow graph: {len(flow_graph)} nodes")
        
        range_vars = self._collect_range_vars(flow_graph, ast_result)
        initial_tainted = initial_tainted | range_vars
        if range_vars:
            print(f"    Added {len(range_vars)} range loop variables as potentially tainted")
        
        propagated = self._propagate_recursive(initial_tainted, flow_graph)
        print(f"    Propagated to {len(propagated)} total variables")
        
        func_call_tainted = self._propagate_through_calls(ast_result, propagated)
        print(f"    Function calls added {len(func_call_tainted - propagated)} variables")
        
        return_value_tainted = self._propagate_return_values(ast_result, func_call_tainted)
        print(f"    Return values added {len(return_value_tainted - func_call_tainted)} variables")
        
        all_tainted = propagated | func_call_tainted | return_value_tainted
        
        if self.enable_control_flow_sensitive and cfg and hasattr(cfg, 'nodes'):
            cf_tainted = self._analyze_control_flow_sensitive(ast_result, cfg, initial_tainted, flow_graph)
            all_tainted = all_tainted | cf_tainted
            print(f"    Control-flow sensitive analysis added {len(cf_tainted - all_tainted)} variables")
        
        path_sensitive_results = {}
        path_states = {}
        if self.enable_path_sensitive and cfg and hasattr(cfg, 'get_all_paths_from_entry'):
            path_sensitive_results, path_states = self._analyze_path_sensitive(
                ast_result, cfg, initial_tainted, flow_graph
            )
            print(f"    Path-sensitive analysis found {len(path_sensitive_results)} unique paths")
        
        print(f"    Total tainted variables: {len(all_tainted)}")
        
        return {
            'initial_tainted': list(initial_tainted),
            'propagated_tainted': list(propagated),
            'func_call_tainted': list(func_call_tainted),
            'all_tainted': list(all_tainted),
            'path_sensitive_results': path_sensitive_results,
            'path_states': {k: {
                'tainted_vars': list(v.tainted_vars),
                'sanitized_vars': list(v.sanitized_vars),
                'validated_vars': list(v.validated_vars)
            } for k, v in path_states.items()}
        }
    
    def _collect_initial_sources(self, ast_result: Dict[str, Any]) -> Set[str]:
        tainted = set()
        
        for source in ast_result.get('taint_sources', []):
            var_name = source.get('var_name', '')
            if var_name:
                tainted.add(var_name)
                
        return tainted
    
    def _build_flow_graph(self, ast_result: Dict[str, Any]) -> Dict[str, Set[str]]:
        flow_graph = {}
        
        for flow in ast_result.get('data_flows', []):
            from_var = flow.get('from', '')
            to_var = flow.get('to', '')
            
            from_var = self._extract_var_name(from_var)
            to_var = self._extract_var_name(to_var)
            
            if from_var and to_var:
                if from_var not in flow_graph:
                    flow_graph[from_var] = set()
                flow_graph[from_var].add(to_var)
        
        return flow_graph
    
    def _collect_range_vars(self, flow_graph: Dict[str, Set[str]], ast_result: Dict[str, Any]) -> Set[str]:
        range_vars = set()
        
        for flow in ast_result.get('data_flows', []):
            if flow.get('flow_type') == 'range_loop':
                to_var = self._extract_var_name(flow.get('to', ''))
                if to_var:
                    range_vars.add(to_var)
        
        return range_vars
    
    def _propagate_recursive(self, sources: Set[str], graph: Dict[str, Set[str]]) -> Set[str]:
        tainted = set(sources)
        worklist = list(sources)
        visited = set(sources)
        
        while worklist:
            current = worklist.pop(0)
            
            if current in graph:
                for target in graph[current]:
                    if target not in visited:
                        visited.add(target)
                        tainted.add(target)
                        worklist.append(target)
        
        return tainted
    
    def _propagate_through_calls(self, ast_result: Dict[str, Any], tainted_vars: Set[str]) -> Set[str]:
        extended_tainted = set(tainted_vars)
        
        func_defs = {}
        for func in ast_result.get('functions', []):
            func_name = func.get('name', '')
            if func_name:
                func_defs[func_name] = func
        
        for call in ast_result.get('calls', []):
            func_name = call.get('function', '')
            args = call.get('args', [])
            
            tainted_args = []
            for i, arg in enumerate(args):
                if isinstance(arg, str) and arg.startswith('"') and arg.endswith('"'):
                    continue
                
                arg_var = self._extract_var_name(arg)
                if arg_var and arg_var in tainted_vars:
                    tainted_args.append(i)
            
            if tainted_args and func_name in func_defs:
                func_def = func_defs[func_name]
                params = func_def.get('params', [])
                
                for arg_idx in tainted_args:
                    if arg_idx < len(params):
                        param_name = params[arg_idx].get('name', '')
                        if param_name:
                            extended_tainted.add(param_name)
        
        return extended_tainted
    
    def _propagate_return_values(self, ast_result: Dict[str, Any], tainted_vars: Set[str]) -> Set[str]:
        extended_tainted = set(tainted_vars)
        
        returns = ast_result.get('returns', [])
        calls = ast_result.get('calls', [])
        data_flows = ast_result.get('data_flows', [])
        
        func_returns_tainted: Dict[str, bool] = {}
        for ret in returns:
            func_name = ret.get('function', '')
            return_value = ret.get('value', '')
            if func_name and return_value:
                return_var = self._extract_var_name(return_value)
                if return_var and return_var in tainted_vars:
                    func_returns_tainted[func_name] = True
                elif return_var:
                    for tainted_var in tainted_vars:
                        if return_var == tainted_var or return_var in tainted_var:
                            func_returns_tainted[func_name] = True
                            break
        
        for call in calls:
            func_name = call.get('function', '')
            call_line = call.get('line', 0)
            
            if func_name in func_returns_tainted:
                for flow in data_flows:
                    flow_line = flow.get('line', 0)
                    flow_type = flow.get('flow_type', '')
                    from_var = flow.get('from', '')
                    to_var = flow.get('to', '')
                    
                    if flow_line == call_line and flow_type == 'assignment':
                        if func_name in from_var or from_var.endswith('()'):
                            to_var_clean = self._extract_var_name(to_var)
                            if to_var_clean:
                                extended_tainted.add(to_var_clean)
                    
                    if func_name in from_var and '()' in from_var:
                        to_var_clean = self._extract_var_name(to_var)
                        if to_var_clean:
                            extended_tainted.add(to_var_clean)
        
        return extended_tainted
    
    def _extract_var_name(self, expr: str) -> str:
        return extract_var_name(expr)
    
    def _analyze_control_flow_sensitive(self, ast_result: Dict[str, Any], cfg: Any, 
                                       initial_tainted: Set[str], flow_graph: Dict[str, Set[str]]) -> Set[str]:
        cf_tainted = set(initial_tainted)
        
        node_taint_states: Dict[str, Set[str]] = {}
        
        if not cfg.entry_node:
            return cf_tainted
        
        worklist = [cfg.entry_node]
        visited = set()
        
        while worklist:
            current_node_id = worklist.pop(0)
            
            if current_node_id in visited:
                continue
            visited.add(current_node_id)
            
            if current_node_id not in node_taint_states:
                predecessors = cfg.get_predecessors(current_node_id)
                if predecessors:
                    merged_taint = set()
                    for pred in predecessors:
                        if pred in node_taint_states:
                            merged_taint = merged_taint | node_taint_states[pred]
                    node_taint_states[current_node_id] = merged_taint.copy()
                else:
                    node_taint_states[current_node_id] = set(initial_tainted)
            
            current_taint = node_taint_states[current_node_id]
            
            for from_var, to_vars in flow_graph.items():
                if from_var in current_taint:
                    for to_var in to_vars:
                        current_taint.add(to_var)
                        cf_tainted.add(to_var)
            
            successors = cfg.get_successors(current_node_id)
            for succ in successors:
                if succ not in node_taint_states:
                    node_taint_states[succ] = current_taint.copy()
                else:
                    node_taint_states[succ] = node_taint_states[succ] | current_taint
                
                if succ not in visited:
                    worklist.append(succ)
        
        return cf_tainted
    
    def _analyze_path_sensitive(self, ast_result: Dict[str, Any], cfg: Any,
                                initial_tainted: Set[str], flow_graph: Dict[str, Set[str]]) -> Tuple[Dict[str, Set[str]], Dict[str, PathState]]:
        path_results = {}
        path_states = {}
        
        all_paths = cfg.get_all_paths_from_entry(max_depth=100)
        
        if not all_paths:
            return path_results, path_states
        
        conditions = ast_result.get('conditions', [])
        condition_validation_map: Dict[int, Dict[str, Any]] = {}
        for cond in conditions:
            line = cond.get('line', 0)
            condition_validation_map[line] = {
                'has_validation': cond.get('has_validation', False),
                'validation_type': cond.get('validation_type'),
                'variables': cond.get('variables', []),
                'is_negated': cond.get('is_negated', False),
                'then_line': cond.get('then_line', 0),
                'else_line': cond.get('else_line', 0)
            }
        
        sanitization_calls = self.sanitization_recognizer.find_sanitization_calls(ast_result)
        data_flows = ast_result.get('data_flows', [])
        
        print(f"      Analyzing {len(all_paths)} execution paths...")
        
        for path_idx, path in enumerate(all_paths[:50]):
            path_id = f"path_{path_idx}"
            path_state = PathState(path_id=path_id)
            path_state.tainted_vars = set(initial_tainted)
            
            path_conditions: List[Tuple[int, bool]] = []  # (line, is_then_branch)
            
            for node_id in path:
                node = cfg.nodes.get(node_id)
                if not node:
                    continue
                
                node_tainted = set(path_state.tainted_vars)
                
                if hasattr(node, 'node_type') and node.node_type == 'condition':
                    cond_line = node.line if hasattr(node, 'line') else 0
                    if cond_line in condition_validation_map:
                        node_idx = path.index(node_id) if node_id in path else -1
                        if node_idx >= 0 and node_idx + 1 < len(path):
                            next_node_id = path[node_idx + 1]
                            is_then = False
                            for edge in cfg.edges:
                                if edge.from_node == node_id and edge.to_node == next_node_id:
                                    if edge.edge_type == "true_branch":
                                        is_then = True
                                    elif edge.edge_type == "false_branch":
                                        is_then = False
                                    else:
                                        next_node = cfg.nodes.get(next_node_id)
                                        if next_node and hasattr(next_node, 'line'):
                                            next_line = next_node.line
                                            cond_info = condition_validation_map[cond_line]
                                            is_then = (cond_info['then_line'] > 0 and 
                                                      next_line >= cond_info['then_line'] and
                                                      (cond_info['else_line'] == 0 or next_line < cond_info['else_line']))
                                    break
                            path_conditions.append((cond_line, is_then))
                
                if hasattr(node, 'node_type') and node.node_type == 'function_call':
                    node_line = node.line if hasattr(node, 'line') else 0
                    if node_line in sanitization_calls:
                        for sanit_call in sanitization_calls[node_line]:
                            for arg in sanit_call.get('args', []):
                                arg_var = self._extract_var_name(arg)
                                if arg_var and arg_var in path_state.tainted_vars:
                                    path_state.sanitized_vars.add(arg_var)
                                    path_state.tainted_vars.discard(arg_var)
                
                for from_var, to_vars in flow_graph.items():
                    if from_var in path_state.tainted_vars:
                        for to_var in to_vars:
                            path_state.tainted_vars.add(to_var)
                
                if node.taint_sources:
                    for source in node.taint_sources:
                        path_state.tainted_vars.add(source)
                
                path_state.node_states[node_id] = set(path_state.tainted_vars)
            
            path_state.tainted_vars = self._apply_taint_killing(
                path_state.tainted_vars, path_conditions, condition_validation_map, path_state
            )
            
            path_results[path_id] = path_state.tainted_vars
            path_states[path_id] = path_state
        
        return path_results, path_states
    
    def _apply_taint_killing(self, tainted: Set[str], path_conditions: List[Tuple[int, bool]],
                            condition_validation_map: Dict[int, Dict[str, Any]],
                            path_state: Optional[PathState] = None) -> Set[str]:
        cleaned_tainted = set(tainted)
        
        for cond_line, is_then_branch in path_conditions:
            if cond_line not in condition_validation_map:
                continue
            
            cond_info = condition_validation_map[cond_line]
            
            if cond_info['has_validation'] and is_then_branch:
                validated_vars = cond_info.get('variables', [])
                for var in validated_vars:
                    var_clean = self._extract_var_name(var)
                    if var_clean and var_clean in cleaned_tainted:
                        cleaned_tainted.remove(var_clean)
                        if path_state:
                            path_state.validated_vars.add(var_clean)
                        print(f"        Taint killed for {var_clean} at line {cond_line} (validated)")
            
            elif cond_info['is_negated'] and not is_then_branch:
                pass
        
        return cleaned_tainted
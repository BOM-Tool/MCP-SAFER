from typing import List, Dict, Set, Tuple, Any
import re
from scanner.analyzers.common.scanner import Finding
from scanner.analyzers.common.mcp_utils import create_mcp_finding
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS
from scanner.analyzers.common.utils import extract_var_name

class ToxicFlowDetector:
    
    def __init__(self):
        self.private_data_sources = [
            'process.env',
            'process.env.API_KEY',
            'process.env.SECRET',
            'process.env.PASSWORD',
            'process.env.TOKEN',
            'fs.readFileSync',
            'readFileSync',
            'fs.readFile',
            'readFile',
            '.env',
            'config.secret',
            'credentials',
            'jwt.sign',
            'jwt.decode',
            'crypto.randomBytes',
            'bcrypt.hash',
            'password',
            'apiKey',
            'secretKey',
            'localStorage.getItem',
            'sessionStorage.getItem',
            'IndexedDB',
            'req.session',
            'session.user',
            'cookies.get',
            'getCookie',
            'db.password',
            'connection.password',
            'MONGODB_URI',
            'DATABASE_URL',
        ]
        
        self.untrusted_sources = [
            # TypeScript/JavaScript
            'req.query',
            'req.params',
            'req.body',
            'req.headers',
            'req.cookies',
            'request.query',
            'request.params',
            'request.body',
            'location.search',
            'location.hash',
            'window.location',
            'URLSearchParams',
            'document.cookie',
            'document.referrer',
            'postMessage',
            'addEventListener',
            'fetch(',
            'WebSocket',
            'EventSource',
            'XMLHttpRequest',
            'prompt(',
            'confirm(',
            'document.getElementById',
            'querySelector',
            'input.value',
            # Go
            '.FormValue',
            '.PostFormValue',
            '.Query',
            '.Header.Get',
            '.Cookie',
            '.Getenv',
            'os.Args',
            'flag.String',
            'flag.Parse',
            '.LookupEnv',
        ]
        
        self.public_sinks = [
            'fetch', 'axios', 'request', 'XMLHttpRequest', 'sendBeacon', 'WebSocket', 'EventSource',
            'post', 'get', 'put', 'delete',
            'callTool', 'tool(', 'server.setRequestHandler', 'browser_navigate', 'open_url',
            'webhook', 'sendEmail', 'smtp', 'nodemailer', 'postMessage', 'send',
            'analytics', 'gtag', 'ga', 'track', 'captureMessage', 'captureException', 'notify',
        ]

        self.destructive_sinks = [
            # TypeScript/JavaScript
            'unlink', 'unlinkSync', 'rmdir', 'rmdirSync', 'rm', 'rmSync', 'deleteFile', 'removeFile', 'rimraf',
            'exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'fork',
            'db.drop', 'collection.drop', 'deleteMany', 'remove(', 'truncate',
            # Go
            '.Remove',
            '.RemoveAll',
            '.Truncate',
            '.Drop',
            'exec.Command',
            '.StartProcess',
            'os.Remove',
            'os.RemoveAll',
        ]
    
    def _normalize_func(self, name: str) -> str:
        return (name or '').strip()

    def _matches_any(self, func_name: str, candidates: List[str]) -> Tuple[bool, str]:
        fn = self._normalize_func(func_name).lower()
        for c in candidates:
            c_lower = c.lower()
            if fn == c_lower:
                return True, c
            if c_lower.startswith('.') and fn.endswith(c_lower):
                return True, c
            if '.' in c_lower and c_lower in fn:
                return True, c
            if not c_lower.startswith('.') and fn.endswith('.' + c_lower):
                return True, c
        return False, ''

    def _pattern_matches_source(self, pattern: str, source_code: str) -> bool:
        if not pattern or not source_code:
            return False

        normalized_source = source_code.lower()
        normalized_pattern = pattern.lower()

        if re.search(r'[^\w.]', normalized_pattern):
            return normalized_pattern in normalized_source

        if normalized_pattern.startswith('.'):
            return normalized_source.endswith(normalized_pattern)

        boundary_pattern = rf'(?<![a-z0-9_]){re.escape(normalized_pattern)}(?![a-z0-9_])'
        return re.search(boundary_pattern, normalized_source) is not None

    def _trace_to_source(self, var_name: str, taint_result: Dict[str, Any], 
                         data_flows: List[Dict], source_patterns: List[str]) -> Tuple[bool, str]:
        all_tainted = set(taint_result.get('all_tainted', []))
        
        if var_name not in all_tainted:
            return False, ''
        
        reverse_graph = {}
        for flow in data_flows:
            from_var = flow.get('from', '').strip()
            to_var = flow.get('to', '').strip()
            if from_var and to_var:
                if to_var not in reverse_graph:
                    reverse_graph[to_var] = []
                reverse_graph[to_var].append(from_var)
        
        visited = set()
        queue = [var_name]
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            for pattern in source_patterns:
                if self._pattern_matches_source(pattern, current):
                    return True, current
            
            if current in reverse_graph:
                queue.extend(reverse_graph[current])
        
        return False, ''

    def _arg_contains_keywords(self, args: List[str], keywords: List[str]) -> bool:
        joined = ' '.join(args).lower()
        return any(k.lower() in joined for k in keywords)
    
    def get_name(self) -> str:
        return "toxic-flow"
    
    def check(self, calls: List[Dict], tainted_vars: Set[str], 
              lines: List[str], file_path: str, 
              ast_result: Dict = None, taint_result: Dict = None, cfg: Any = None) -> List[Finding]:
        findings = []
        
        if not ast_result or not taint_result:
            return findings
        
        sources = ast_result.get('taint_sources', [])
        data_flows = ast_result.get('data_flows', [])
        
        private_var_map = {}
        untrusted_var_map = {}
        
        for source in sources:
            var_name = source.get('var_name', '')
            source_code = source.get('source', '')
            if not var_name:
                continue
            
            for pattern in self.private_data_sources:
                if self._pattern_matches_source(pattern, source_code):
                    private_var_map[var_name] = {
                        'source': source_code,
                        'line': source.get('line', 0),
                        'pattern': pattern
                    }
                    break
            
            if var_name not in private_var_map:
                for pattern in self.untrusted_sources:
                    if self._pattern_matches_source(pattern, source_code):
                        untrusted_var_map[var_name] = {
                            'source': source_code,
                            'line': source.get('line', 0),
                            'pattern': pattern
                        }
                        break
        
        for call in calls:
            findings.extend(self._check_data_exfiltration(
                call, private_var_map, tainted_vars, data_flows, taint_result, lines, file_path
            ))
            
            findings.extend(self._check_destructive_flow(
                call, untrusted_var_map, tainted_vars, data_flows, taint_result, lines, file_path
            ))
        
        return findings
    
    def _check_data_exfiltration(self, call: Dict, private_var_map: Dict[str, Dict],
                                  tainted_vars: Set[str], data_flows: List[Dict],
                                  taint_result: Dict[str, Any], lines: List[str],
                                  file_path: str) -> List[Finding]:
        findings = []
        
        pkg = call.get('package', '')
        func = call.get('function', '')
        func_name = f"{pkg}.{func}" if pkg else func
        args = call.get('args', [])
        line = call.get('line', 0)
        
        is_public_sink, matched_sink = self._matches_any(func_name, self.public_sinks)
        
        if not is_public_sink:
            return findings
        
        for arg in args:
            arg_vars = self._extract_vars_from_arg(arg)
            
            for arg_var in arg_vars:
                if arg_var in private_var_map:
                    findings.append(create_mcp_finding(
                        rule_id="mcp/toxic-flow-data-leak",
                        message=f"[TOXIC FLOW] Sensitive data '{arg_var}' from {private_var_map[arg_var]['source']} "
                                f"sent to external endpoint via {func_name}",
                        file_path=file_path,
                        line=line,
                        column=call.get('column', 0),
                        code_snippet=lines[line-1] if 0 < line <= len(lines) else "",
                        pattern_type="toxic_flow",
                        pattern="private_data->public_sink",
                        confidence=CONFIDENCE_LEVELS['CRITICAL']
                    ))
                elif arg_var in tainted_vars:
                    is_private, source_var = self._trace_to_source(
                        arg_var, taint_result, data_flows, self.private_data_sources
                    )
                    if is_private:
                        findings.append(create_mcp_finding(
                            rule_id="mcp/toxic-flow-data-leak",
                            message=f"[TOXIC FLOW] Sensitive data '{arg_var}' (traced from {source_var}) "
                                    f"sent to external endpoint via {func_name}",
                            file_path=file_path,
                            line=line,
                            code_snippet=lines[line-1] if 0 < line <= len(lines) else "",
                            pattern_type="toxic_flow",
                            pattern="private_data->public_sink",
                            confidence=CONFIDENCE_LEVELS['HIGH']
                        ))
                elif '.' in arg_var:
                    base_var = arg_var.split('.')[0]
                    if base_var in private_var_map:
                        findings.append(create_mcp_finding(
                            rule_id="mcp/toxic-flow-data-leak",
                            message=f"[TOXIC FLOW] Potentially sensitive data '{arg_var}' "
                                    f"sent to external endpoint via {func_name}",
                            file_path=file_path,
                            line=line,
                            code_snippet=lines[line-1] if 0 < line <= len(lines) else "",
                            pattern_type="toxic_flow",
                            pattern="private_data->public_sink",
                            confidence=CONFIDENCE_LEVELS['HIGH']
                        ))
        
        return findings
    
    def _check_destructive_flow(self, call: Dict, untrusted_var_map: Dict[str, Dict],
                                 tainted_vars: Set[str], data_flows: List[Dict],
                                 taint_result: Dict[str, Any], lines: List[str],
                                 file_path: str) -> List[Finding]:
        findings = []
        
        pkg = call.get('package', '')
        func = call.get('function', '')
        func_name = f"{pkg}.{func}" if pkg else func
        args = call.get('args', [])
        line = call.get('line', 0)
        
        is_destructive, matched_sink = self._matches_any(func_name, self.destructive_sinks)
        
        if not is_destructive and self._arg_contains_keywords(args, ['drop table', 'delete from', 'truncate', 'alter table']):
            is_destructive = True
            matched_sink = 'sql.keyword'
        
        if not is_destructive:
            return findings

        keyword_arg_indexes: Set[int] = set()
        if matched_sink == 'sql.keyword':
            lowered_keywords = ['drop table', 'delete from', 'truncate', 'alter table']
            keyword_arg_indexes = {
                idx for idx, value in enumerate(args)
                if isinstance(value, str) and any(kw in value.lower() for kw in lowered_keywords)
            }
        restrict_to_keyword_args = bool(keyword_arg_indexes)
        
        for idx, arg in enumerate(args):
            if matched_sink == 'sql.keyword' and restrict_to_keyword_args and idx not in keyword_arg_indexes:
                continue
            
            arg_vars = self._extract_vars_from_arg(arg)
            
            for arg_var in arg_vars:
                if arg_var in untrusted_var_map:
                    findings.append(create_mcp_finding(
                        rule_id="mcp/toxic-flow-destructive",
                        message=f"[TOXIC FLOW] Untrusted input '{arg_var}' from {untrusted_var_map[arg_var]['source']} "
                                f"used in destructive operation {func_name}",
                        file_path=file_path,
                        line=line,
                        column=call.get('column', 0),
                        code_snippet=lines[line-1] if 0 < line <= len(lines) else "",
                        pattern_type="toxic_flow",
                        pattern="untrusted_input->destructive_sink",
                        confidence=CONFIDENCE_LEVELS['CRITICAL']
                    ))
                elif arg_var in tainted_vars:
                    is_untrusted, source_var = self._trace_to_source(
                        arg_var, taint_result, data_flows, self.untrusted_sources
                    )
                    if is_untrusted:
                        findings.append(create_mcp_finding(
                            rule_id="mcp/toxic-flow-destructive",
                            message=f"[TOXIC FLOW] Untrusted input '{arg_var}' (traced from {source_var}) "
                                    f"used in destructive operation {func_name}",
                            file_path=file_path,
                            line=line,
                            code_snippet=lines[line-1] if 0 < line <= len(lines) else "",
                            pattern_type="toxic_flow",
                            pattern="untrusted_input->destructive_sink",
                            confidence=CONFIDENCE_LEVELS['CRITICAL']
                        ))
                elif '.' in arg_var:
                    base_var = arg_var.split('.')[0]
                    if base_var in untrusted_var_map:
                        findings.append(create_mcp_finding(
                            rule_id="mcp/toxic-flow-destructive",
                            message=f"[TOXIC FLOW] Untrusted input '{arg_var}' from {untrusted_var_map[base_var]['source']} "
                                    f"used in destructive operation {func_name}",
                            file_path=file_path,
                            line=line,
                            code_snippet=lines[line-1] if 0 < line <= len(lines) else "",
                            pattern_type="toxic_flow",
                            pattern="untrusted_input->destructive_sink",
                            confidence=CONFIDENCE_LEVELS['HIGH']
                        ))
        
        return findings
    
    def _extract_var_name(self, expr: str) -> str:
        return extract_var_name(expr)
    
    def _extract_vars_from_arg(self, arg: str) -> List[str]:
        vars: List[str] = []
        if not arg:
            return vars

        v = self._extract_var_name(arg)
        if v and not v.startswith('{'):
            vars.append(v)

        pattern_kv = r':\s*([a-zA-Z_$][a-zA-Z0-9_$\.]*)(?=[,}\]])'
        pattern_shorthand = r'\{\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:[,}]|$)'
        vars.extend(re.findall(pattern_kv, arg))
        vars.extend(re.findall(pattern_shorthand, arg))

        template_var = r'\$\{\s*([a-zA-Z_$][a-zA-Z0-9_$\.]+)\s*\}'
        vars.extend(re.findall(template_var, arg))

        seen: Set[str] = set()
        deduped: List[str] = []
        for item in vars:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped
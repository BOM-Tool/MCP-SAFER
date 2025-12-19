import re
from typing import List, Dict, Set, Any
from scanner.analyzers.common.scanner import Finding, CommonPatterns
from scanner.analyzers.common.base_detector import BaseDetector
from scanner.analyzers.common.constants import CONFIDENCE_LEVELS
from scanner.analyzers.common.utils import extract_var_name

class CommandInjectionDetector(BaseDetector):
    def __init__(self, language: str = "typescript"):
        super().__init__()
        self.language = language
        self.exec_sinks = [
            ('child_process', 'exec'), ('', 'exec'),
            ('child_process', 'execSync'), ('', 'execSync'),
            ('child_process', 'spawn'), ('', 'spawn'),
            ('child_process', 'spawnSync'), ('', 'spawnSync'),
            ('child_process', 'execFile'), ('', 'execFile'),
            ('child_process', 'execFileSync'), ('', 'execFileSync'),
            ('child_process', 'fork'), ('', 'fork'),
        ]
        self.third_party_sinks = [
            ('shelljs', 'exec'),
            ('shelljs', 'ShellString.exec'),
            ('execa', 'command'),
            ('execa', 'commandSync'),
            ('execa', 'shell'),
            ('execa', 'shellSync'),
            ('execa', ''),
            ('cross-spawn', 'spawn'),
            ('cross-spawn', 'sync'),
            ('npm-run', 'exec'),
            ('npm-run', 'execSync'),
            ('npm-run', 'spawn'),
            ('npm-run', 'spawnSync'),
            ('cmd-shim', 'cmdShim'),
            ('cmd-shim', 'cmdShimIfExists'),
        ]
        self.wrapper_sinks = [
            ('', 'execAsync'),
            ('', 'execPromise'),
            ('', 'runCommand'),
            ('', 'executeCommand'),
            ('', 'runScript'),
            ('', 'executeScript'),
            ('', 'systemCommand'),
            ('', 'shellCommand'),
        ]
        self.code_exec_sinks = [
            ('eval', ''),
            ('Function', ''),
            ('vm', 'runInContext'),
            ('vm', 'runInNewContext'),
            ('vm', 'runInThisContext'),
            ('vm', 'Script'),
            ('vm2', 'run'),
            ('vm2', 'NodeVM'),
        ]
        self.dangerous_functions = [
            'convertToValidJSONString',
            'evalString',
            'executeString',
            'runCode',
            'executeCode',
            'compileCode',
            'parseAndExecute',
            'dynamicEval',
            'unsafeEval',
            'stringToFunction',
            'codeFromString',
        ]
        self.dynamic_load_sinks = [
            ('', 'require'),
            ('', 'import'),
            ('module', '_load'),
            ('module', 'createRequire'),
        ]
        self.dangerous_sinks = (
            self.exec_sinks +
            self.third_party_sinks +
            self.wrapper_sinks +
            self.code_exec_sinks +
            self.dynamic_load_sinks
        )
        self.shell_patterns = [
            'sh', 'bash', 'zsh', 'ksh', 'csh', 'tcsh', 'fish', 'dash',
            '/bin/sh', '/bin/bash', '/bin/zsh', '/bin/ksh', '/bin/dash',
            '/usr/bin/sh', '/usr/bin/bash', '/usr/bin/zsh',
            '/usr/local/bin/bash', '/usr/local/bin/zsh',
            'cmd', 'cmd.exe', 'command.com',
            'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
            'conhost.exe', 'wscript', 'cscript',
        ]
        self.shell_flags = ['-c', '/c', '/C', '-Command', '-EncodedCommand', '-File']
        self.shell_metacharacters = [
            ';', '&', '|', '||', '&&', '$(', '`', '$(',
            '>', '>>', '<', '\n', '\r\n', '2>&1', '2>',
        ]
        self.sanitization_functions = [
            'escape', 'escapeShellArg', 'escapeShellCmd', 'sanitize',
            'validate', 'validateInput', 'clean', 'filter',
            'stripTags', 'removeSpecialChars', 'whitelistFilter',
            'shellEscape', 'quote', 'shellescape',
        ]
        self.safe_comment_patterns = [
            r'//\s*eslint-disable',
            r'//\s*@ts-ignore',
            r'//\s*safe',
            r'//\s*sanitized',
            r'//\s*trusted',
            r'//\s*validated',
            r'//\s*whitelisted',
            r'/\*\s*security:\s*reviewed\s*\*/',
        ]
        self.safe_comment_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.safe_comment_patterns]
        self.whitelist_patterns = [
            r'allowedCommands\.includes',
            r'commandWhitelist\.has',
            r'SAFE_COMMANDS\.indexOf',
            r'if\s*\(.*===.*\)',
        ]
        self.whitelist_patterns_compiled = [re.compile(p) for p in self.whitelist_patterns]
        self.safe_commands = [
            'node', 'npm', 'yarn', 'pnpm', 'git', 'echo', 'pwd', 'ls', 'dir',
            'whoami', 'which', 'where', 'type', 'cat', 'head', 'tail',
            'grep', 'find', 'wc', 'date', 'uname', 'hostname',
            'tsc', 'ts-node', 'esbuild', 'webpack', 'rollup', 'vite',
            'jest', 'mocha', 'cypress', 'playwright', 'vitest',
            'eslint', 'prettier', 'husky', 'lint-staged',
            'docker', 'docker-compose', 'kubectl', 'helm',
            'aws', 'gcloud', 'az', 'terraform',
            'mkdir', 'rmdir', 'cp', 'mv', 'rm', 'chmod', 'chown',
            'curl', 'wget', 'tar', 'zip', 'unzip', 'gzip', 'gunzip',
        ]
        self.suspicious_param_names = [
            'command', 'cmd', 'input', 'userInput', 'userCommand',
            'query', 'param', 'params', 'args', 'data', 'payload',
            'request', 'req', 'body', 'header', 'headers',
            'filename', 'filepath', 'filePath', 'path', 'url', 'endpoint',
            'search', 'filter', 'sort', 'order', 'content', 'message', 'text',
            'value', 'val', 'str', 'string', 'text', 'content',
            'uvPath', 'uvpath', 'execPath', 'execpath', 'binPath', 'binpath',
            'toolPath', 'toolpath', 'binaryPath', 'binarypath',
            'packageName', 'package', 'pkg', 'pkgName', 'module', 'moduleName',
            'symbol', 'symbolName', 'code', 'codeString', 'script', 'scriptContent',
            'tmx_url', 'tmxUrl', 'tmxUrl', 'downloadUrl', 'download_url', 'fileUrl', 'file_url',
            'container_id', 'containerId', 'container', 'containerName', 'container_name',
            'image_id', 'imageId', 'image', 'imageName', 'image_name',
            'sandbox_id', 'sandboxId', 'sandbox', 'sandboxName', 'sandbox_name',
            'namespace', 'name', 'resourceType', 'resource_type', 'resource', 'resourceName',
            'replicas', 'replica', 'pod', 'podName', 'pod_name', 'deployment', 'deploymentName',
            'service', 'serviceName', 'service_name', 'kubectl', 'k8s',
            'initialBranch', 'branch', 'branchName', 'branch_name', 'targetPath', 'target_path',
            'files', 'file', 'filesArg', 'files_arg', 'repo', 'repository', 'remote', 'remoteUrl',
            'duration', 'udid', 'x', 'y', 'coordinate', 'coordinates', 'position', 'pos',
            'width', 'height', 'left', 'right', 'top', 'bottom',
        ]
        self.external_input_function_patterns = [
            'handler', 'tool', 'api', 'route', 'endpoint', 'controller',
            'action', 'method', 'callback', 'listener', 'on',
            'process', 'handle', 'execute', 'run', 'call',
            'resolve', 'resolveCommand', 'resolvePath',
        ]
        self.curl_command_patterns = [
            r'curlCommand\s*=',
            r'curlCmd\s*=',
            r'curl.*command\s*=',
            r'const\s+\w*curl\w*\s*=.*curl',
            r'let\s+\w*curl\w*\s*=.*curl',
            r'var\s+\w*curl\w*\s*=.*curl',
        ]
        self.curl_command_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.curl_command_patterns]
        self.header_serialization_functions = [
            'formatHeadersForCurl',
            'formatHeaders',
            'serializeHeaders',
            'headersToCurl',
            'buildCurlHeaders',
            'curlHeaders',
        ]
        self.curl_exec_patterns = [
            r'exec\s*\([^)]*curl',
            r'execSync\s*\([^)]*curl',
            r'\.exec\s*\([^)]*curl',
            r'\.execSync\s*\([^)]*curl',
            r'child_process\.exec\s*\([^)]*curl',
            r'child_process\.execSync\s*\([^)]*curl',
        ]
        self.curl_exec_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.curl_exec_patterns]

    def get_name(self) -> str:
        return "command-injection"

    def get_cwe(self) -> str:
        return "CWE-78"

    def get_rule_id(self, language: str = None) -> str:
        lang = language or self.language
        return f"{lang}/command-injection"

    def is_dangerous_sink(self, pkg: str, fn: str) -> bool:
        if pkg:
            return (pkg, fn) in self.dangerous_sinks
        else:
            return fn in ['eval', 'Function', 'exec', 'execSync', 'spawn', 'spawnSync',
                         'execFile', 'execFileSync', 'fork', 'execAsync', 'execPromise',
                         'runCommand', 'executeCommand', 'runScript', 'executeScript',
                         'systemCommand', 'shellCommand', 'require', 'import', 'execa',
                         'command', 'commandSync', 'shell', 'shellSync']

    def get_sink_severity(self, pkg: str, fn: str) -> str:
        if (pkg, fn) in self.code_exec_sinks or fn == 'eval' or fn == 'Function':
            return "critical"
        if (pkg, fn) in self.exec_sinks or (pkg, fn) in self.third_party_sinks:
            return "high"

        if (pkg, fn) in self.dynamic_load_sinks or fn == 'require' or fn == 'import':
            return "medium"
        return "high"

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
        else:
            all_tainted = set()
            taint_result = {'all_tainted': [], 'initial_tainted': []}

        for call in calls:
            pkg = call.get('package', '')
            fn = call.get('function', '')
            line = call.get('line', 0)
            line_content = lines[line-1] if 0 < line <= len(lines) else ""

            is_shell_exec = False
            if (pkg == 'child_process' and fn in ['exec', 'execSync']):
                is_shell_exec = True
            elif not pkg and fn in ['exec', 'execSync']:

                is_shell_exec = True

            is_user_defined_wrapper = False
            if not pkg and fn in ['execAsync', 'execPromise', 'runCommand', 'executeCommand',
                                 'runScript', 'executeScript', 'systemCommand', 'shellCommand']:

                is_user_defined_wrapper = self._is_user_defined_wrapper_function(
                    fn, ast_result, file_path, lines
                )

            is_code_exec = False
            if (pkg, fn) in self.code_exec_sinks or (not pkg and fn in ['eval', 'Function']):
                is_code_exec = True

            is_new_expression = call.get('is_new_expression', False)
            if is_new_expression and fn in ['Function', 'MCPToolkit', 'MCPClient', 'MCPServer']:
                is_code_exec = True

            is_dangerous_function = False
            if fn in self.dangerous_functions:
                is_dangerous_function = True

            if (is_shell_exec or is_user_defined_wrapper or is_code_exec or is_dangerous_function) and fn:
                args = call.get('args', [])

                is_array_arg = False
                if args and len(args) > 0:
                    first_arg = args[0].strip()

                    if first_arg.startswith('[') or first_arg.startswith('Array'):
                        is_array_arg = True

                    if not is_array_arg and '[' in line_content:
                        array_pattern = rf'{re.escape(fn)}\s*\(\s*\['
                        if re.search(array_pattern, line_content, re.IGNORECASE):
                            is_array_arg = True

                if is_array_arg and is_user_defined_wrapper:

                    continue

                template_content = None

                if args and len(args) > 0:
                    first_arg = args[0].strip()
                    if first_arg.startswith('`') and first_arg.endswith('`'):
                        template_content = first_arg[1:-1]
                    elif '`' in first_arg:
                        template_match = re.search(r'`([^`]+)`', first_arg)
                        if template_match:
                            template_content = template_match.group(1)

                if not template_content:
                    fn_pattern = re.escape(fn)
                    template_literal_pattern = rf'{fn_pattern}\s*\(\s*`([^`]+)`'
                    template_match = re.search(template_literal_pattern, line_content, re.IGNORECASE)
                    if template_match:
                        template_content = template_match.group(1)

                if not template_content and '`' in line_content:
                    lines_to_check = []
                    start_line = max(0, line - 5)
                    end_line = min(len(lines), line + 5)
                    for i in range(start_line, end_line):
                        if i < len(lines):
                            lines_to_check.append(lines[i])

                    full_context = ''.join(lines_to_check)
                    fn_pattern = re.escape(fn)
                    template_literal_pattern = rf'{fn_pattern}\s*\([^`]*`([^`]+)`'
                    template_match = re.search(template_literal_pattern, full_context, re.DOTALL | re.IGNORECASE)
                    if template_match:
                        template_content = template_match.group(1)

                if template_content:
                    template_vars = re.findall(r'\$\{([^}]+)\}', template_content)

                    context_start = max(0, line - 10)
                    context_end = min(len(lines), line + 1)
                    context_lines = lines[context_start:context_end]

                    has_user_input = False
                    unsafe_vars = []

                    for var_expr in template_vars:
                        var_clean = var_expr.strip()

                        var_is_safe = False

                        for ctx_line in context_lines:
                            if re.search(rf'const\s+{re.escape(var_clean)}\s*=', ctx_line, re.IGNORECASE) or \
                               re.search(rf'let\s+{re.escape(var_clean)}\s*=', ctx_line, re.IGNORECASE) or \
                               re.search(rf'var\s+{re.escape(var_clean)}\s*=', ctx_line, re.IGNORECASE):

                                if re.search(r'===?\s*[\'"][^\'"]+[\'"]\s*\?\s*[\'"][^\'"]+[\'"]\s*:\s*[\'"][^\'"]+[\'"]', ctx_line):
                                    var_is_safe = True
                                    break

                                if 'writeToTempFile' in ctx_line or 'writeFile' in ctx_line:
                                    var_is_safe = True
                                    break

                                if '.split(' in ctx_line and '.pop()' in ctx_line:
                                    var_is_safe = True
                                    break

                                if re.search(rf'{re.escape(var_clean)}\s*[:=]\s*[\'"][^\'"]+[\'"]', ctx_line):
                                    var_is_safe = True
                                    break

                        if var_is_safe:
                            continue

                        if var_clean in all_tainted:
                            has_user_input = True
                            unsafe_vars.append(var_clean)
                            continue

                        if var_clean in taint_sources:
                            has_user_input = True
                            unsafe_vars.append(var_clean)
                            continue

                        for taint_source in taint_sources:
                            if taint_source.endswith('.') and var_clean.startswith(taint_source):
                                has_user_input = True
                                unsafe_vars.append(var_clean)
                                break
                            if var_clean.startswith(taint_source + '.'):
                                has_user_input = True
                                unsafe_vars.append(var_clean)
                                break

                        if has_user_input:
                            break

                        for flow in data_flows:
                            to_var = flow.get('to', '').strip()
                            if to_var == var_clean:
                                from_var = flow.get('from', '').strip()
                                if from_var in taint_sources or from_var in all_tainted:
                                    has_user_input = True
                                    unsafe_vars.append(var_clean)
                                    break
                            if has_user_input:
                                break

                        if has_user_input:
                            break

                        common_taint_patterns = [
                            'args.', 'req.', 'request.', 'input.', 'user.',
                            'param.', 'query.', 'body.', 'data.', 'payload.',
                            'params.', 'queryParams.', 'routeParams.', 'formData.',
                            'inputs.', 'inputs.mcpServerConfig', 'mcpServerConfig',
                            'node.inputs.', 'node.inputs.mcpServerConfig',
                            'validatedArgs.', 'validatedArgs.filepath', 'validatedArgs.filePath',
                            'validatedArgs.uvPath', 'validatedArgs.path', 'validatedArgs.url',
                            'validatedArgs.tmx_url', 'validatedArgs.tmxUrl', 'validatedArgs.tmxUrl',
                            'input.name', 'input.namespace', 'input.resourceType', 'input.replicas',
                            'input.resource', 'input.resourceName', 'input.pod', 'input.podName',
                            'input.deployment', 'input.deploymentName', 'input.service', 'input.serviceName',
                            'input.initialBranch', 'input.branch', 'input.branchName', 'input.targetPath',
                            'input.files', 'input.file', 'input.path', 'input.repo', 'input.repository',
                            'input.remote', 'input.remoteUrl', 'input.url',
                            'input.duration', 'input.udid', 'input.x', 'input.y', 'input.coordinate',
                            'input.coordinates', 'input.position', 'input.pos', 'input.width', 'input.height',
                            'args.package', 'args.packageName', 'args.symbol', 'args.symbolName',
                            'args.code', 'args.codeString', 'args.script', 'args.scriptContent',
                            'args.module', 'args.moduleName', 'args.pkg', 'args.pkgName',
                        ]
                        for pattern in common_taint_patterns:
                            if var_clean.startswith(pattern) or var_clean == pattern:
                                has_user_input = True
                                unsafe_vars.append(var_clean)
                                break

                        if has_user_input:
                            break

                        if self._is_suspicious_parameter_name(var_clean):
                            if self._is_function_parameter(var_clean, ast_result, line, context_lines):
                                has_user_input = True
                                unsafe_vars.append(var_clean)
                                break

                        if has_user_input:
                            break

                    if has_user_input and unsafe_vars:

                        has_insufficient_sanitization = False
                        simple_replace_patterns = [
                            r'\.replace\s*\(',
                            r'\.replaceAll\s*\(',
                            r'\.replace\s*\([^,]+,\s*[\'"]',
                            r'\.replaceAll\s*\([^,]+,\s*[\'"]',
                        ]

                        for ctx_line in context_lines:
                            for var_name in unsafe_vars:
                                if var_name in ctx_line:

                                    has_replace = any(re.search(p, ctx_line) for p in simple_replace_patterns)

                                    has_proper_sanitization = any(
                                        sanitize_fn in ctx_line
                                        for sanitize_fn in ['escape', 'escapeShellArg', 'escapeShellCmd',
                                                           'shellEscape', 'quote', 'shellescape',
                                                           'spawn', 'execFile', 'execFileSync']
                                    )

                                    metachar_patterns = [
                                        r'metachar',
                                        r'special.*char',
                                        r'shell.*char',
                                        r'dangerous.*char',
                                        r'[;&|`$<>]',
                                        r'shell.*escape',
                                        r'escape.*shell',
                                    ]
                                    has_metachar_check = any(
                                        re.search(pattern, ctx_line, re.IGNORECASE)
                                        for pattern in metachar_patterns
                                    )

                                    if has_replace and not has_proper_sanitization and not has_metachar_check:
                                        has_insufficient_sanitization = True
                                        break
                            if has_insufficient_sanitization:
                                break

                        language = self.language
                        unsafe_vars_str = ', '.join(unsafe_vars[:3])

                        is_wrapper = is_user_defined_wrapper

                        if has_insufficient_sanitization:
                            if is_wrapper:
                                if pkg:
                                    message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) combined via string template and passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Use proper shell escaping (e.g., spawn with array args, execFile, or shellEscape)"
                                else:
                                    message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) combined via string template and passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Use proper shell escaping (e.g., spawn with array args, execFile, or shellEscape)"
                            else:
                                if pkg:
                                    message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) in template literal passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                else:
                                    message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) in template literal passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                        else:
                            if is_wrapper:
                                if pkg:
                                    message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) combined via string template and passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                else:
                                    message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) combined via string template and passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                            else:
                                if pkg:
                                    message = f"[CRITICAL] Command injection in {pkg}.{fn}() - Unvalidated user input ({unsafe_vars_str}) in template literal passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                else:
                                    message = f"[CRITICAL] Command injection in {fn}() - Unvalidated user input ({unsafe_vars_str}) in template literal passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"

                        snippet_lines = []
                        start_snippet = max(0, line - 3)
                        end_snippet = min(len(lines), line + 3)

                        for i in range(start_snippet, end_snippet):
                            if i < len(lines):
                                snippet_lines.append(lines[i].rstrip())

                        code_snippet = self._normalize_indent('\n'.join(snippet_lines))

                        findings.append(Finding(
                            rule_id=self.get_rule_id(language),
                            severity="critical",
                            message=message,
                            cwe=self.get_cwe(),
                            file=file_path,
                            line=line,
                            column=call.get('column', 0),
                            code_snippet=code_snippet,
                            pattern_type="template_literal_injection" if not has_insufficient_sanitization else "insufficient_sanitization_injection",
                            pattern=f"{pkg}.{fn}" if pkg else fn,
                            confidence=CONFIDENCE_LEVELS['CRITICAL'] if has_insufficient_sanitization else CONFIDENCE_LEVELS['CRITICAL']
                        ))
                        continue

                if not template_content and '+' in line_content:
                    fn_pattern = re.escape(fn)
                    string_concat_pattern = rf'{fn_pattern}\s*\(\s*([^)]+)'
                    concat_match = re.search(string_concat_pattern, line_content, re.IGNORECASE)
                    if concat_match:
                        concat_content = concat_match.group(1)
                        if '+' in concat_content:
                            var_pattern = r'\b([a-zA-Z_$][a-zA-Z0-9_$.]*)\b'
                            vars_in_concat = re.findall(var_pattern, concat_content)

                            context_start = max(0, line - 10)
                            context_end = min(len(lines), line + 1)
                            context_lines = lines[context_start:context_end]

                            has_user_input = False
                            unsafe_vars = []

                            for var_name in vars_in_concat:
                                if var_name in ['exec', 'execSync', 'execAsync', 'spawn', 'shell']:
                                    continue

                                var_is_safe = False

                                for ctx_line in context_lines:
                                    if re.search(rf'const\s+{re.escape(var_name)}\s*=', ctx_line, re.IGNORECASE) or \
                                       re.search(rf'let\s+{re.escape(var_name)}\s*=', ctx_line, re.IGNORECASE) or \
                                       re.search(rf'var\s+{re.escape(var_name)}\s*=', ctx_line, re.IGNORECASE):

                                        if re.search(r'===?\s*[\'"][^\'"]+[\'"]\s*\?\s*[\'"][^\'"]+[\'"]\s*:\s*[\'"][^\'"]+[\'"]', ctx_line):
                                            var_is_safe = True
                                            break

                                        if 'writeToTempFile' in ctx_line or 'writeFile' in ctx_line:
                                            var_is_safe = True
                                            break

                                        if '.split(' in ctx_line and '.pop()' in ctx_line:
                                            var_is_safe = True
                                            break

                                        if re.search(rf'{re.escape(var_name)}\s*[:=]\s*[\'"][^\'"]+[\'"]', ctx_line):
                                            var_is_safe = True
                                            break

                                if var_is_safe:
                                    continue

                                if var_name in all_tainted:
                                    has_user_input = True
                                    unsafe_vars.append(var_name)
                                    continue

                                if var_name in taint_sources:
                                    has_user_input = True
                                    unsafe_vars.append(var_name)
                                    continue

                                for taint_source in taint_sources:
                                    if taint_source.endswith('.') and var_name.startswith(taint_source):
                                        has_user_input = True
                                        unsafe_vars.append(var_name)
                                        break
                                    if var_name.startswith(taint_source + '.'):
                                        has_user_input = True
                                        unsafe_vars.append(var_name)
                                        break

                                if has_user_input:
                                    break

                                for flow in data_flows:
                                    to_var = flow.get('to', '').strip()
                                    if to_var == var_name:
                                        from_var = flow.get('from', '').strip()
                                        if from_var in taint_sources or from_var in all_tainted:
                                            has_user_input = True
                                            unsafe_vars.append(var_name)
                                            break
                                    if has_user_input:
                                        break

                                if has_user_input:
                                    break

                                common_taint_patterns = [
                                    'args.', 'req.', 'request.', 'input.', 'user.',
                                    'param.', 'query.', 'body.', 'data.', 'payload.',
                                    'params.', 'queryParams.', 'routeParams.', 'formData.',
                                    'inputs.', 'inputs.mcpServerConfig', 'mcpServerConfig',
                                    'node.inputs.', 'node.inputs.mcpServerConfig',
                                    'validatedArgs.', 'validatedArgs.filepath', 'validatedArgs.filePath',
                                    'validatedArgs.uvPath', 'validatedArgs.path', 'validatedArgs.url',
                                    'validatedArgs.tmx_url', 'validatedArgs.tmxUrl', 'validatedArgs.tmxUrl',
                                    'input.name', 'input.namespace', 'input.resourceType', 'input.replicas',
                                    'input.resource', 'input.resourceName', 'input.pod', 'input.podName',
                                    'input.deployment', 'input.deploymentName', 'input.service', 'input.serviceName',
                                    'input.initialBranch', 'input.branch', 'input.branchName', 'input.targetPath',
                                    'input.files', 'input.file', 'input.path', 'input.repo', 'input.repository',
                                    'input.remote', 'input.remoteUrl', 'input.url',
                                    'input.duration', 'input.udid', 'input.x', 'input.y', 'input.coordinate',
                                    'input.coordinates', 'input.position', 'input.pos', 'input.width', 'input.height',
                                    'args.package', 'args.packageName', 'args.symbol', 'args.symbolName',
                                    'args.code', 'args.codeString', 'args.script', 'args.scriptContent',
                                    'args.module', 'args.moduleName', 'args.pkg', 'args.pkgName',
                                ]
                                for pattern in common_taint_patterns:
                                    if var_name.startswith(pattern) or var_name == pattern:
                                        has_user_input = True
                                        unsafe_vars.append(var_name)
                                        break

                                if has_user_input:
                                    break

                            if has_user_input and unsafe_vars:

                                has_insufficient_sanitization = False
                                simple_replace_patterns = [
                                    r'\.replace\s*\(',
                                    r'\.replaceAll\s*\(',
                                    r'\.replace\s*\([^,]+,\s*[\'"]',
                                    r'\.replaceAll\s*\([^,]+,\s*[\'"]',
                                ]

                                for ctx_line in context_lines:
                                    for var_name in unsafe_vars:
                                        if var_name in ctx_line:

                                            has_replace = any(re.search(p, ctx_line) for p in simple_replace_patterns)

                                            has_proper_sanitization = any(
                                                sanitize_fn in ctx_line
                                                for sanitize_fn in ['escape', 'escapeShellArg', 'escapeShellCmd',
                                                                   'shellEscape', 'quote', 'shellescape',
                                                                   'spawn', 'execFile', 'execFileSync']
                                            )

                                            metachar_patterns = [
                                                r'metachar',
                                                r'special.*char',
                                                r'shell.*char',
                                                r'dangerous.*char',
                                                r'[;&|`$<>]',
                                                r'shell.*escape',
                                                r'escape.*shell',
                                            ]
                                            has_metachar_check = any(
                                                re.search(pattern, ctx_line, re.IGNORECASE)
                                                for pattern in metachar_patterns
                                            )

                                            if has_replace and not has_proper_sanitization and not has_metachar_check:
                                                has_insufficient_sanitization = True
                                                break
                                    if has_insufficient_sanitization:
                                        break

                                language = self.language
                                unsafe_vars_str = ', '.join(unsafe_vars[:3])

                                is_user_defined_wrapper_concat = False
                                if not pkg and fn in ['execAsync', 'execPromise', 'runCommand', 'executeCommand',
                                                     'runScript', 'executeScript', 'systemCommand', 'shellCommand']:
                                    is_user_defined_wrapper_concat = self._is_user_defined_wrapper_function(
                                        fn, ast_result, file_path, lines
                                    )
                                is_wrapper = is_user_defined_wrapper_concat

                                if has_insufficient_sanitization:
                                    if is_wrapper:
                                        if pkg:
                                            message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) combined via string concatenation and passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Use proper shell escaping (e.g., spawn with array args, execFile, or shellEscape)"
                                        else:
                                            message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) combined via string concatenation and passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Use proper shell escaping (e.g., spawn with array args, execFile, or shellEscape)"
                                    else:
                                        if pkg:
                                            message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) in string concatenation passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                        else:
                                            message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) in string concatenation passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                else:
                                    if is_wrapper:
                                        if pkg:
                                            message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) combined via string concatenation and passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                        else:
                                            message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) combined via string concatenation and passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                    else:
                                        if pkg:
                                            message = f"[CRITICAL] Command injection in {pkg}.{fn}() - Unvalidated user input ({unsafe_vars_str}) in string concatenation passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                        else:
                                            message = f"[CRITICAL] Command injection in {fn}() - Unvalidated user input ({unsafe_vars_str}) in string concatenation passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"

                                snippet_lines = []
                                start_snippet = max(0, line - 3)
                                end_snippet = min(len(lines), line + 3)

                                for i in range(start_snippet, end_snippet):
                                    if i < len(lines):
                                        snippet_lines.append(lines[i].rstrip())

                                code_snippet = self._normalize_indent('\n'.join(snippet_lines))

                                findings.append(Finding(
                                    rule_id=self.get_rule_id(language),
                                    severity="critical",
                                    message=message,
                                    cwe=self.get_cwe(),
                                    file=file_path,
                                    line=line,
                                    column=call.get('column', 0),
                                    code_snippet=code_snippet,
                                    pattern_type="string_concatenation_injection" if not has_insufficient_sanitization else "insufficient_sanitization_injection",
                                    pattern=f"{pkg}.{fn}" if pkg else fn,
                                    confidence=CONFIDENCE_LEVELS['CRITICAL'] if has_insufficient_sanitization else CONFIDENCE_LEVELS['CRITICAL']
                                ))
                                continue

        curl_command_findings = self._check_curl_command_construction(lines, file_path, ast_result, taint_result)
        findings.extend(curl_command_findings)

        base_findings = super().check(calls, tainted_vars, lines, file_path, ast_result, taint_result, cfg)
        findings.extend(base_findings)

        return findings

    def is_safe_usage(self, call: Dict, line_content: str, args: List[str],
                     file_path: str, lines: List[str]) -> bool:
        if self._is_safe_usage(line_content, args, file_path):
            return True
        
        line = call.get('line', 0)
        if lines and self._has_input_validation(lines, line, args):
            return True
        
        return False
    
    def _has_input_validation(self, lines: List[str], line: int, args: List[str]) -> bool:
        if not lines or line < 1 or line > len(lines):
            return False
        
        arg_vars = [self._extract_var_name(arg) for arg in args if arg]
        arg_vars = [v for v in arg_vars if v and not v.startswith('"') and not v.startswith("'")]
        
        if not arg_vars:
            return False
        
        start = max(0, line - 5)
        end = line - 1
        
        if start >= end or end >= len(lines):
            return False
        
        validation_patterns = [
            r'\.match\s*\(',
            r'\.test\s*\(',
            r'\.includes\s*\(',
            r'\.startsWith\s*\(',
            r'\.endsWith\s*\(',
            r'validator\.',
            r'validate',
            r'sanitize',
        ]
        validation_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in validation_patterns]
        
        for var in arg_vars:
            for i in range(start, end):
                if i >= len(lines):
                    break
                
                context_line = lines[i]
                
                merged_line = context_line
                if i + 1 < len(lines):
                    merged_line = context_line.rstrip() + ' ' + lines[i + 1].strip()
                if i + 2 < len(lines):
                    merged_line = merged_line.rstrip() + ' ' + lines[i + 2].strip()
                
                if var not in merged_line:
                    continue
                
                has_validation = False
                for pattern in validation_patterns_compiled:
                    if pattern.search(merged_line):
                        has_validation = True
                        break
                
                if not has_validation:
                    continue
                
                if 'if' in merged_line and var in merged_line:
                    distance_to_sink = line - i - 1
                    
                    if 0 <= distance_to_sink <= 5:
                        return True
        
        return False
    
    def _extract_var_name(self, arg: str) -> str:
        return extract_var_name(arg)

    def analyze_data_flow(self, ast_result: Dict[str, Any],
                         taint_result: Dict[str, Any]) -> List[Dict]:
        return []

    def build_finding_message(self, call: Dict, severity: str,
                             base_var: str = None, data_flow_finding: Dict = None) -> str:
        pkg = call.get('package', '')
        fn = call.get('function', '')

        if data_flow_finding:
            return data_flow_finding['message']

        sink_category = self._get_sink_category(pkg, fn)

        if base_var:
            if sink_category == 'code_eval':
                return f"Code Injection: User input '{base_var}' in {fn}() - Arbitrary code execution"
            elif sink_category == 'exec':
                return f"Command injection: User input '{base_var}' in {pkg}.{fn}() if pkg else {fn}() - verify input sanitization"
            else:
                return f"Command injection: User input '{base_var}' in {pkg}.{fn}() if pkg else {fn}() - verify input sanitization"

        return f"Command injection: {pkg}.{fn}() if pkg else {fn}() - verify input sanitization"

    def _get_sink_category(self, pkg: str, fn: str) -> str:
        if pkg:
            if (pkg, fn) in self.code_exec_sinks:
                return 'code_eval'
            elif (pkg, fn) in self.exec_sinks:
                return 'exec'
            elif (pkg, fn) in self.third_party_sinks:
                return 'third_party'

            elif False:
                return 'wrapper'
            elif (pkg, fn) in self.dynamic_load_sinks:
                return 'dynamic_load'
        else:
            if fn in ['eval', 'Function']:
                return 'code_eval'
            elif fn in ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']:
                return 'exec'
            elif fn in ['execAsync', 'execPromise', 'runCommand', 'executeCommand', 'runScript', 'executeScript', 'systemCommand', 'shellCommand']:
                return 'wrapper'
            elif fn in ['require', 'import']:
                return 'dynamic_load'
            elif fn in ['execa', 'command', 'commandSync', 'shell', 'shellSync']:
                return 'third_party'
        return 'exec'

    def _is_user_defined_wrapper_function(self, fn_name: str, ast_result: Dict[str, Any],
                                          file_path: str, lines: List[str]) -> bool:

        if not ast_result:
            return False

        functions = ast_result.get('functions', [])
        func_def = None
        for func in functions:
            if func.get('name', '') == fn_name:
                func_def = func
                break

        if not func_def:

            common_wrapper_names = ['execPromise', 'execAsync', 'runCommand', 'executeCommand',
                                  'runScript', 'executeScript', 'systemCommand', 'shellCommand']
            if fn_name in common_wrapper_names:

                return True
            return False

        func_line = func_def.get('line', 0)
        if func_line == 0:
            return False

        start_line_idx = func_line - 1
        if start_line_idx >= len(lines):
            return False

        brace_count = 0
        in_function = False
        end_line_idx = start_line_idx

        for i in range(start_line_idx, min(len(lines), start_line_idx + 200)):
            line = lines[i]

            if '{' in line:
                brace_count += line.count('{')
                in_function = True
            if '}' in line:
                brace_count -= line.count('}')
                if in_function and brace_count == 0:

                    end_line_idx = i + 1
                    break

            if i > start_line_idx and in_function:
                next_func_pattern = r'^\s*(?:async\s+)?(?:function|const|let|var)\s+\w+\s*[=:]?\s*(?:async\s*)?\s*\(|^\s*export\s+(?:async\s+)?function'
                if re.search(next_func_pattern, line):

                    end_line_idx = i
                    break

        if end_line_idx == start_line_idx:
            end_line_idx = min(len(lines), start_line_idx + 100)

        body_lines = lines[start_line_idx:end_line_idx]
        body_content = '\n'.join(body_lines)

        dangerous_patterns = [
            r'child_process\.(exec|execSync)',
            r'require\s*\([^)]*child_process[^)]*\)\.exec',
            r'require\s*\([^)]*child_process[^)]*\)\.execSync',
            r'import.*child_process.*exec',
            r'\.exec\s*\(',
            r'\.execSync\s*\(',

            r'(?:^|\s)(?:exec|execSync)\s*\(',
        ]

        has_dangerous_call = False
        for pattern in dangerous_patterns:
            if re.search(pattern, body_content, re.IGNORECASE):
                has_dangerous_call = True
                break

        if not has_dangerous_call:

            return False

        safe_patterns = [

            r'spawn\s*\([^,]*,\s*\[',
            r'\.spawn\s*\([^,]*,\s*\[',
            r'child_process\.spawn\s*\([^,]*,\s*\[',

            r'execFile\s*\(',
            r'\.execFile\s*\(',
            r'child_process\.execFile',

            r'execFileSync\s*\(',
            r'\.execFileSync\s*\(',
            r'child_process\.execFileSync',

            r'shellEscape\s*\(',
            r'escapeShellArg\s*\(',
            r'escapeShellCmd\s*\(',
            r'quote\s*\(',
            r'shellescape\s*\(',

            r'spawn\s*\([^,]*,\s*[^,]*,\s*\{[^}]*shell\s*:\s*false',
            r'\.spawn\s*\([^,]*,\s*[^,]*,\s*\{[^}]*shell\s*:\s*false',
        ]

        has_safe_pattern = False
        for pattern in safe_patterns:
            if re.search(pattern, body_content, re.IGNORECASE):
                has_safe_pattern = True
                break

        if has_safe_pattern:

            spawn_array_pattern = r'spawn\s*\([^,]*,\s*\[[^\]]+\]'
            if re.search(spawn_array_pattern, body_content, re.IGNORECASE):

                return False

        func_params = func_def.get('params', [])
        has_array_param = False
        for param in func_params:
            param_type = param.get('type', '')
            if '[]' in param_type or 'Array' in param_type or 'string[]' in param_type:
                has_array_param = True
                break

        if has_array_param and has_safe_pattern:
            return False

        return True

    def _is_suspicious_parameter_name(self, var_name: str) -> bool:
        var_lower = var_name.lower()
        for suspicious_name in self.suspicious_param_names:
            if var_lower == suspicious_name.lower() or var_lower.startswith(suspicious_name.lower() + '.'):
                return True
        return False

    def _is_function_parameter(self, var_name: str, ast_result: Dict[str, Any], 
                               current_line: int, context_lines: List[str]) -> bool:
        if not ast_result:
            return False

        functions = ast_result.get('functions', [])
        
        for func in functions:
            func_name = func.get('name', '')
            func_line = func.get('line', 0)
            func_type = func.get('type', '')
            params = func.get('params', [])
            
            if func_line == 0:
                continue
            
            for param in params:
                param_name = param.get('name', '')
                if param_name == var_name:
                    if current_line >= func_line:
                        func_name_lower = func_name.lower()
                        func_type_lower = func_type.lower() if func_type else ''
                        
                        for pattern in self.external_input_function_patterns:
                            if pattern in func_name_lower or pattern in func_type_lower:
                                return True
                        
                        for ctx_line in context_lines:
                            ctx_lower = ctx_line.lower()
                            for pattern in self.external_input_function_patterns:
                                if pattern in ctx_lower and func_name in ctx_line:
                                    return True
                        
                        if any(keyword in func_name_lower for keyword in ['export', 'async', 'public']):
                            if any(keyword in func_name_lower for keyword in ['handler', 'tool', 'api', 'route']):
                                return True
                        
                        if 'export' in context_lines[0].lower() if context_lines else False:
                            return True
                    
                    break
        
        for ctx_line in context_lines:
            if re.search(rf'function\s+\w+\s*\([^)]*{re.escape(var_name)}', ctx_line, re.IGNORECASE):
                return True
            if re.search(rf'\([^)]*{re.escape(var_name)}\s*:', ctx_line, re.IGNORECASE):
                return True
            if re.search(rf'const\s+\w+\s*=\s*\([^)]*{re.escape(var_name)}', ctx_line, re.IGNORECASE):
                return True
        
        return False

    def _is_safe_usage(self, line_content: str, args: List[str], file_path: str) -> bool:
        if '.test.' in file_path or '.spec.' in file_path or '/test/' in file_path or '/__tests__/' in file_path:
            return True
        for pattern in self.safe_comment_patterns_compiled:
            if pattern.search(line_content):
                return True
        for sanitize_fn in self.sanitization_functions:
            if sanitize_fn in line_content:
                return True
        for pattern in self.whitelist_patterns_compiled:
            if pattern.search(line_content):
                return True

        if args and len(args) > 0:
            first_arg = args[0].strip('"`\'')
            safe_node_modules = [
                'path', 'fs', 'crypto', 'util', 'url', 'http', 'https',
                'os', 'stream', 'events', 'net', 'tls', 'dns',
                'child_process', 'cluster', 'worker_threads', 'perf_hooks',
                'async_hooks', 'timers', 'buffer', 'querystring', 'punycode',
                'module', 'assert', 'console', 'process', 'zlib', 'readline',
                'v8', 'vm', 'domain', 'string_decoder', 'inspector', 'trace_events'
            ]
            if first_arg in safe_node_modules or first_arg.startswith('node:'):
                return True

            if first_arg in self.safe_commands:
                return True
            if args[0].startswith('"') and '${' not in args[0] and '$(' not in args[0]:
                has_metachar = any(meta in args[0] for meta in self.shell_metacharacters)
                if not has_metachar:
                    return True
        if 'spawn(' in line_content and '[' in line_content:
            if 'shell:' not in line_content and 'shell :' not in line_content:
                return True

        script_patterns = [
            r'/scripts/',
            r'devcheck\.ts',
            r'devdocs\.ts',
            r'build\.ts',
            r'deploy\.ts',
            r'validate.*\.ts',
            r'fetch.*\.ts',
        ]

        for pattern in script_patterns:
            if re.search(pattern, file_path):
                return True

        if 'execa(' in line_content and 'args' in line_content:
            return True

        if 'spawn(' in line_content and 'args' in line_content:
            return True

        return False

    def _check_curl_command_construction(self, lines: List[str], file_path: str,
                                        ast_result: Dict[str, Any] = None,
                                        taint_result: Dict[str, Any] = None) -> List[Finding]:
        findings = []
        
        if not ast_result:
            return findings
        
        taint_sources = {s.get('var_name') for s in ast_result.get('taint_sources', [])}
        if taint_result:
            all_tainted = set(taint_result.get('all_tainted', []))
        else:
            all_tainted = set()
        
        data_flows = ast_result.get('data_flows', [])
        
        for line_num, line_content in enumerate(lines, 1):
            line_lower = line_content.lower()
            
            has_curl_command = False
            curl_var_name = None
            
            for pattern in self.curl_command_patterns_compiled:
                match = pattern.search(line_content)
                if match:
                    has_curl_command = True
                    var_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=', line_content, re.IGNORECASE)
                    if var_match:
                        curl_var_name = var_match.group(1)
                    break
            
            if not has_curl_command:
                if 'curl' in line_lower and ('`' in line_content or '"' in line_content or "'" in line_content):
                    curl_template_pattern = r'curl\s+[^`"\']*[`"\'][^`"\']*\$'
                    if re.search(curl_template_pattern, line_content, re.IGNORECASE):
                        has_curl_command = True
            
            if has_curl_command:
                has_user_input = False
                unsafe_vars = []
                template_vars = []
                
                if '`' in line_content:
                    template_vars = re.findall(r'\$\{([^}]+)\}', line_content)
                elif '"' in line_content or "'" in line_content:
                    string_concat_pattern = r'["\']\s*\+\s*(\w+)\s*\+|(\w+)\s*\+\s*["\']'
                    concat_matches = re.findall(string_concat_pattern, line_content)
                    for match in concat_matches:
                        var_name = match[0] if match[0] else match[1]
                        if var_name:
                            template_vars.append(var_name)
                
                for var_expr in template_vars:
                    var_clean = var_expr.strip()
                    
                    if var_clean in all_tainted or var_clean in taint_sources:
                        has_user_input = True
                        unsafe_vars.append(var_clean)
                        continue
                    
                    for taint_source in taint_sources:
                        if taint_source.endswith('.') and var_clean.startswith(taint_source):
                            has_user_input = True
                            unsafe_vars.append(var_clean)
                            break
                        if var_clean.startswith(taint_source + '.'):
                            has_user_input = True
                            unsafe_vars.append(var_clean)
                            break
                    
                    if has_user_input:
                        break
                    
                    for flow in data_flows:
                        to_var = flow.get('to', '').strip()
                        if to_var == var_clean:
                            from_var = flow.get('from', '').strip()
                            if from_var in taint_sources or from_var in all_tainted:
                                has_user_input = True
                                unsafe_vars.append(var_clean)
                                break
                    
                    if has_user_input:
                        break
                    
                    common_taint_patterns = [
                        'args.', 'req.', 'request.', 'input.', 'user.',
                        'param.', 'query.', 'body.', 'data.', 'payload.',
                        'params.', 'queryParams.', 'routeParams.', 'formData.',
                        'inputs.', 'inputs.mcpServerConfig', 'mcpServerConfig',
                        'node.inputs.', 'node.inputs.mcpServerConfig',
                        'validatedArgs.', 'validatedArgs.filepath', 'validatedArgs.filePath',
                        'validatedArgs.uvPath', 'validatedArgs.path', 'validatedArgs.url',
                        'validatedArgs.tmx_url', 'validatedArgs.tmxUrl', 'validatedArgs.tmxUrl',
                        'input.name', 'input.namespace', 'input.resourceType', 'input.replicas',
                        'input.resource', 'input.resourceName', 'input.pod', 'input.podName',
                        'input.deployment', 'input.deploymentName', 'input.service', 'input.serviceName',
                        'input.initialBranch', 'input.branch', 'input.branchName', 'input.targetPath',
                        'input.files', 'input.file', 'input.path', 'input.repo', 'input.repository',
                        'input.remote', 'input.remoteUrl', 'input.url',
                        'input.duration', 'input.udid', 'input.x', 'input.y', 'input.coordinate',
                        'input.coordinates', 'input.position', 'input.pos', 'input.width', 'input.height',
                        'args.package', 'args.packageName', 'args.symbol', 'args.symbolName',
                        'args.code', 'args.codeString', 'args.script', 'args.scriptContent',
                        'args.module', 'args.moduleName', 'args.pkg', 'args.pkgName',
                        'url', 'headers', 'options.headers', 'options.url',
                    ]
                    for pattern in common_taint_patterns:
                        if var_clean.startswith(pattern) or var_clean == pattern:
                            has_user_input = True
                            unsafe_vars.append(var_clean)
                            break
                    
                    if has_user_input:
                        break
                    
                    if self._is_suspicious_parameter_name(var_clean):
                        context_start = max(0, line_num - 10)
                        context_end = min(len(lines), line_num + 1)
                        context_lines = lines[context_start:context_end]
                        if self._is_function_parameter(var_clean, ast_result, line_num, context_lines):
                            has_user_input = True
                            unsafe_vars.append(var_clean)
                            break
                
                has_header_serialization = False
                for header_func in self.header_serialization_functions:
                    if header_func in line_content:
                        has_header_serialization = True
                        break
                
                has_shell_metachar = False
                for meta in self.shell_metacharacters:
                    if meta in line_content:
                        has_shell_metachar = True
                        break
                
                has_exec_usage = False
                exec_line = None
                if curl_var_name:
                    for i in range(line_num, min(len(lines), line_num + 20)):
                        check_line = lines[i]
                        for pattern in self.curl_exec_patterns_compiled:
                            if pattern.search(check_line) and curl_var_name in check_line:
                                has_exec_usage = True
                                exec_line = i + 1
                                break
                        if has_exec_usage:
                            break
                
                if has_user_input or has_header_serialization or has_shell_metachar or has_exec_usage:
                    context_start = max(0, line_num - 5)
                    context_end = min(len(lines), line_num + 10)
                    context_lines = lines[context_start:context_end]
                    
                    unsafe_vars_str = ', '.join(unsafe_vars[:3]) if unsafe_vars else 'user input'
                    
                    if has_exec_usage:
                        message = f"[CRITICAL] Command injection via curl command construction - Curl command string containing {unsafe_vars_str} is passed to exec/execSync - Shell metacharacters in URL/headers may be interpreted, allowing arbitrary command execution - Use execFile/spawn with array arguments instead of string concatenation"
                        severity = "critical"
                        confidence = CONFIDENCE_LEVELS['CRITICAL']
                    elif has_header_serialization and has_user_input:
                        message = f"[HIGH] Command injection risk via curl command construction - Header serialization function ({', '.join([f for f in self.header_serialization_functions if f in line_content][:2])}) used with {unsafe_vars_str} in curl command string - Shell metacharacters may be interpreted if command is executed - Use array arguments (execFile/spawn) instead of string concatenation"
                        severity = "high"
                        confidence = CONFIDENCE_LEVELS['HIGH']
                    elif has_user_input and has_shell_metachar:
                        message = f"[HIGH] Command injection risk via curl command construction - Curl command string contains {unsafe_vars_str} with shell metacharacters - Shell metacharacters may be interpreted if command is executed - Use array arguments (execFile/spawn) instead of string concatenation"
                        severity = "high"
                        confidence = CONFIDENCE_LEVELS['HIGH']
                    elif has_user_input:
                        message = f"[MEDIUM] Command injection risk via curl command construction - Curl command string contains {unsafe_vars_str} - If executed via exec/execSync, shell metacharacters may be interpreted - Use array arguments (execFile/spawn) instead of string concatenation"
                        severity = "medium"
                        confidence = CONFIDENCE_LEVELS['MEDIUM']
                    elif has_header_serialization:
                        message = f"[MEDIUM] Header serialization for curl command detected - Header serialization function ({', '.join([f for f in self.header_serialization_functions if f in line_content][:2])}) may create unsafe command strings if user input is included - Verify proper escaping or use array arguments"
                        severity = "medium"
                        confidence = CONFIDENCE_LEVELS['MEDIUM']
                    else:
                        continue
                    
                    snippet_lines = []
                    start_snippet = max(0, line_num - 3)
                    end_snippet = min(len(lines), line_num + 3)
                    
                    for i in range(start_snippet, end_snippet):
                        if i < len(lines):
                            snippet_lines.append(lines[i].rstrip())
                    
                    code_snippet = self._normalize_indent('\n'.join(snippet_lines))
                    
                    findings.append(Finding(
                        rule_id=self.get_rule_id(self.language),
                        severity=severity,
                        message=message,
                        cwe="CWE-78",
                        file=file_path,
                        line=exec_line if has_exec_usage and exec_line else line_num,
                        column=0,
                        code_snippet=code_snippet,
                        pattern_type="curl_command_construction",
                        pattern="curl_command_construction",
                        confidence=confidence
                    ))
        
        return findings
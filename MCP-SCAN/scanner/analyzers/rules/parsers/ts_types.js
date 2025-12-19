const ARRAY_METHODS = ['forEach', 'map', 'filter', 'find', 'some', 'every', 
                       'reduce', 'reduceRight', 'flatMap'];

const TAINT_SOURCE_LIST = [
    'req.body', 'req.query', 'req.params', 'req.headers',
    'document.getElementById', 'window.location', 'location.search',
    'process.env', 'process.argv', 'fs.readFile', 'fs.readFileSync',
    'JSON.parse', 'eval', 'new Function',
    'Buffer.from', 'atob', 'Buffer.from.*base64',
    'localStorage.getItem', 'sessionStorage.getItem',
    'crypto.randomBytes', 'Math.random',
    // 추가된 사용자 입력 소스들
    'args', 'args.', 'req', 'request', 'input', 'user', 'param', 'query', 'body', 'data', 'payload',
    // GitHub CLI 특화 사용자 입력 패턴들
    'args.title', 'args.emoji', 'args.issue_number', 'args.repo', 'args.body', 'args.labels', 'args.assignees', 'args.state',
    'titleWithEmoji', 'bodyFlag', 'labelsFlag', 'assigneesFlag', 'owner', 'repo',
    // 일반적인 사용자 입력 패턴들
    'userInput', 'userCommand', 'command', 'cmd', 'filename', 'filepath', 'path', 'url', 'endpoint',
    'search', 'filter', 'query', 'sort', 'order', 'content', 'message', 'text',
    // inputs.* 패턴 (MCP, Flowise 등)
    'inputs', 'inputs.', 'inputs.mcpServerConfig', 'mcpServerConfig',
    'node.inputs', 'node.inputs.mcpServerConfig',
    // validatedArgs.* 패턴 (MCP 서버 등)
    'validatedArgs', 'validatedArgs.', 'validatedArgs.filepath', 'validatedArgs.uvPath',
    'validatedArgs.filePath', 'validatedArgs.path', 'validatedArgs.url',
    'validatedArgs.tmx_url', 'validatedArgs.tmxUrl', 'validatedArgs.tmxUrl',
    // args.* 패턴 (MCP 툴 인자 등)
    'args.package', 'args.packageName', 'args.symbol', 'args.symbolName',
    'args.code', 'args.codeString', 'args.script', 'args.scriptContent',
    'args.module', 'args.moduleName', 'args.pkg', 'args.pkgName',
    // input.* 패턴 (MCP 툴 인자 등)
    'input.name', 'input.namespace', 'input.resourceType', 'input.replicas',
    'input.resource', 'input.resourceName', 'input.pod', 'input.podName',
    'input.deployment', 'input.deploymentName', 'input.service', 'input.serviceName',
    'input.initialBranch', 'input.branch', 'input.branchName', 'input.targetPath',
    'input.files', 'input.file', 'input.path', 'input.repo', 'input.repository',
    'input.remote', 'input.remoteUrl', 'input.url',
    'input.duration', 'input.udid', 'input.x', 'input.y', 'input.coordinate',
    'input.coordinates', 'input.position', 'input.pos', 'input.width', 'input.height',
    // config 파라미터 패턴
    'configParam', 'config.param', 'configParam', 'config.base64', 'base64.config',
    'smitheryConfig', 'config.apiUrl', 'config.endpoint', 'config.url'
];

const TAINT_SINK_LIST = [
    'exec', 'spawn', 'execFile', 'child_process',
    'readFile', 'readFileSync', 'createReadStream',
    'fs.readFile', 'fs.readFileSync', 'fs.createReadStream',
    'writeFile', 'writeFileSync', 'appendFile',
    'fs.writeFile', 'fs.writeFileSync', 'fs.appendFile',
    'unlink', 'unlinkSync', 'rm', 'rmSync',
    'fs.unlink', 'fs.unlinkSync', 'fs.rm', 'fs.rmSync',
    'http.request', 'fetch', 'axios', 'request',
    'console.log', 'console.error', 'console.warn',
    'document.write', 'innerHTML', 'outerHTML',
    'eval', 'Function', 'setTimeout', 'setInterval',
    // execAsync 래퍼 함수들 추가
    'execAsync', 'execPromise', 'runCommand', 'executeCommand', 'runScript', 'executeScript'
];

module.exports = {
    ARRAY_METHODS,
    TAINT_SOURCE_LIST,
    TAINT_SINK_LIST
};
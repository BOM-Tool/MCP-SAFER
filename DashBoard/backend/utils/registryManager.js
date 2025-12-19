/**
 * 중앙 레지스트리 관리 유틸리티
 * - 승인된 MCP 서버를 중앙 레지스트리에 git clone
 * - 실행 방법 자동 감지 및 DB 저장
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const { detectRunCommand } = require('./mcpSandboxScanner');

const execAsync = promisify(exec);

const DEFAULT_SSH_HOST = '13.125.27.16';
const DEFAULT_SSH_USER = 'ubuntu';
const DEFAULT_SSH_KEY = path.join(__dirname, '../../pem/MCP-Server.pem');

function registryKeyExists(keyPath) {
  if (!keyPath) {
    console.log('[레지스트리] SSH 키 경로가 없습니다.');
    return false;
  }
  try {
    fsSync.accessSync(keyPath, fsSync.constants.R_OK);
    console.log(`[레지스트리] SSH 키 파일 확인됨: ${keyPath}`);
    return true;
  } catch (error) {
    console.log(`[레지스트리] SSH 키 파일을 찾을 수 없습니다: ${keyPath} (오류: ${error.message})`);
    return false;
  }
}

function getRegistrySshConfig() {
  const keyPath = process.env.MCP_REGISTRY_SSH_KEY || DEFAULT_SSH_KEY;
  console.log(`[레지스트리] SSH 키 경로 확인: ${keyPath} (환경변수: ${process.env.MCP_REGISTRY_SSH_KEY || '없음'})`);
  const keyExists = registryKeyExists(keyPath);
  const config = {
    host: process.env.MCP_REGISTRY_SSH_HOST || DEFAULT_SSH_HOST,
    user: process.env.MCP_REGISTRY_SSH_USER || DEFAULT_SSH_USER,
    key: keyExists ? keyPath : null,
    keyExists
  };
  console.log(`[레지스트리] SSH 설정: host=${config.host}, user=${config.user}, keyExists=${config.keyExists}`);
  return config;
}

function canUseRegistry() {
  const { keyExists } = getRegistrySshConfig();
  console.log(`[레지스트리] 레지스트리 사용 가능 여부: ${keyExists}`);
  return keyExists;
}

/**
 * GitHub API를 사용하여 기본 브랜치 감지
 */
async function getDefaultBranch(owner, repo) {
  try {
    // GitHub API로 기본 브랜치 가져오기
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}`;
    const response = await fetch(apiUrl, {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'BOM-Tool-Registry'
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      return data.default_branch || 'main';
    }
  } catch (error) {
    console.warn(`기본 브랜치 감지 실패, 'main' 사용: ${error.message}`);
  }
  
  // 기본값: main
  return 'main';
}

/**
 * GitHub URL 파싱 (기본 브랜치 자동 감지)
 */
async function parseGitHubUrl(url) {
  if (!url) return null;
  const u = url.replace(/\.git$/i, '');
  
  // 브랜치가 명시된 경우
  const m1 = u.match(/github\.com\/([^/]+)\/([^/]+)\/tree\/([^/]+)/i);
  if (m1) return { owner: m1[1], repo: m1[2], branch: m1[3] };
  
  // 짧은 형식: owner/repo
  const short = u.match(/^([^/]+)\/([^/]+)$/);
  if (short) {
    const branch = await getDefaultBranch(short[1], short[2]);
    return { owner: short[1], repo: short[2], branch };
  }
  
  // 일반 형식: github.com/owner/repo
  const m2 = u.match(/github\.com\/([^/]+)\/([^/]+)/i);
  if (m2) {
    const branch = await getDefaultBranch(m2[1], m2[2]);
    return { owner: m2[1], repo: m2[2], branch };
  }
  
  return null;
}

/**
 * 서버 이름을 파일 시스템에 안전한 이름으로 변환
 * 공백, 특수문자 등을 언더스코어로 변경
 */
function sanitizeServerName(serverName) {
  return serverName
    .replace(/\s+/g, '_')  // 공백을 언더스코어로
    .replace(/[^a-zA-Z0-9_-]/g, '_')  // 특수문자를 언더스코어로
    .toLowerCase();
}

/**
 * 중앙 레지스트리에 리포지토리 클론 (SSH를 통해 원격 서버에서 실행)
 * @param {string} githubUrl - GitHub 리포지토리 URL
 * @param {string} serverName - 서버 이름 (디렉토리명으로 사용)
 * @returns {Promise<{repoPath: string, owner: string, repo: string, branch: string}>}
 */
async function cloneToRegistry(githubUrl, serverName) {
  const parsed = await parseGitHubUrl(githubUrl);
  if (!parsed) {
    throw new Error('유효하지 않은 GitHub URL입니다.');
  }

  const { owner, repo, branch } = parsed;
  const repoUrl = `https://github.com/${owner}/${repo}.git`;
  
  // SSH 연결 정보 (환경변수에서 가져오기)
  const { host: sshHost, user: sshUser, key: sshKey } = getRegistrySshConfig();
  if (!sshKey) {
    throw new Error('레지스트리 SSH 키 파일을 찾을 수 없어 클론을 건너뜁니다.');
  }
  // 원격 서버 경로는 항상 /home/ubuntu/mcp-servers 사용 (로컬 경로와 혼동 방지)
  const registryBasePath = '/home/ubuntu/mcp-servers';
  
  // 서버 이름을 파일 시스템에 안전한 이름으로 변환
  const safeServerName = sanitizeServerName(serverName);
  const targetDir = `${registryBasePath}/${safeServerName}`;
  
  // SSH 키 옵션
  const keyOption = sshKey ? `-i ${sshKey}` : '';
  
  // 브랜치가 있으면 --branch 옵션 사용, 없으면 기본 브랜치로 클론
  const branchOption = branch ? `--branch ${branch}` : '';
  
  // 원격 서버에서 실행할 명령어들
  const remoteCommands = [
    `mkdir -p ${registryBasePath}`,  // 디렉토리 생성
    `rm -rf "${targetDir}"`,  // 기존 디렉토리 삭제
    `git clone --depth 1 ${branchOption} ${repoUrl} "${targetDir}"`  // git clone (브랜치 자동 감지)
  ];
  
  // SSH를 통해 원격 서버에서 명령어 실행
  const sshCommand = `ssh ${keyOption} -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${sshUser}@${sshHost} '${remoteCommands.join(' && ')}'`;
  
  console.log(`[레지스트리] SSH를 통해 원격 서버에 클론 중: ${sshHost}:${targetDir} (브랜치: ${branch})`);
  await execAsync(sshCommand, { timeout: 120000 }); // 2분 타임아웃
  
  return {
    repoPath: targetDir,  // 원격 서버 경로 (SSH 접근용)
    owner,
    repo,
    branch: branch || 'main'
  };
}

/**
 * SSH를 통해 원격 서버의 파일 읽기
 */
async function readRemoteFile(sshHost, sshUser, sshKey, remotePath) {
  const keyOption = sshKey ? `-i ${sshKey}` : '';
  const sshCommand = `ssh ${keyOption} -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${sshUser}@${sshHost} 'cat "${remotePath}"'`;
  
  try {
    const { stdout } = await execAsync(sshCommand, { timeout: 10000 });
    return stdout;
  } catch (error) {
    return null; // 파일이 없으면 null 반환
  }
}

/**
 * SSH를 통해 원격 서버의 디렉토리 목록 읽기
 */
async function listRemoteDirectory(sshHost, sshUser, sshKey, remotePath) {
  const keyOption = sshKey ? `-i ${sshKey}` : '';
  const sshCommand = `ssh ${keyOption} -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${sshUser}@${sshHost} 'find "${remotePath}" -maxdepth 3 -type f -name "*.json" -o -name "*.toml" -o -name "Dockerfile" -o -name "go.mod" -o -name "main.go" 2>/dev/null | head -20'`;
  
  try {
    const { stdout } = await execAsync(sshCommand, { timeout: 10000 });
    return stdout.trim().split('\n').filter(f => f);
  } catch (error) {
    return [];
  }
}

/**
 * 리포지토리에서 실행 방법 감지 및 connection_config 생성 (원격 서버)
 * @param {string} repoPath - 원격 서버의 리포지토리 경로
 * @param {string} serverName - 서버 이름
 * @returns {Promise<object>} connection_config 객체
 */
async function detectAndBuildConnectionConfig(repoPath, serverName) {
  // SSH 연결 정보
  const { host: sshHost, user: sshUser, key: sshKey } = getRegistrySshConfig();
  if (!sshKey) {
    throw new Error('레지스트리 SSH 키 파일을 찾을 수 없어 실행 방법 감지를 진행할 수 없습니다.');
  }
  
  // 원격 서버의 파일을 읽어서 실행 방법 감지
  const runCommands = [];
  
  try {
    // 1. README.md에서 실행 방법 파싱 (최우선)
    const readmeContent = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/README.md`);
    if (readmeContent) {
      // 코드 블록에서 실행 명령어 추출 (```bash, ```sh, ```shell 등)
      const codeBlockRegex = /```(?:bash|sh|shell|console|cmd|powershell)?\n([\s\S]*?)```/gi;
      const codeBlocks = [];
      let match;
      while ((match = codeBlockRegex.exec(readmeContent)) !== null) {
        codeBlocks.push(match[1]);
      }
      
      // 코드 블록이 없으면 일반 텍스트에서 찾기
      const searchText = codeBlocks.length > 0 ? codeBlocks.join('\n') : readmeContent;
      
      // Go 서버: "go run ... stdio" 또는 "./server stdio" 패턴 찾기 (옵션 포함)
      const goPatterns = [
        // "go run cmd/.../main.go stdio --toolsets all" 형태
        /(?:^|\n|```)\s*(?:\.\/)?(?:go\s+run\s+)?([^\s]+main\.go(?:\s+stdio)?(?:\s+[^\n]+)?)/gim,
        // "./github-mcp-server stdio --toolsets all" 형태
        /(?:^|\n|```)\s*\.\/([^\s]+)\s+stdio(?:\s+[^\n]+)?/gim
      ];
      
      for (const pattern of goPatterns) {
        const matches = searchText.matchAll(pattern);
        for (const match of matches) {
          const fullCommand = match[0].trim();
          // stdio가 포함되어 있고, MCP 서버 실행 명령어로 보이는 경우
          if (fullCommand.includes('stdio') || fullCommand.includes('main.go')) {
            // main.go 경로 추출
            const mainGoMatch = fullCommand.match(/([^\s]+main\.go)/);
            const mainGoPath = mainGoMatch ? mainGoMatch[1] : null;
            
            if (mainGoPath) {
              // 명령어에서 stdio 이후의 옵션 추출 (--toolsets all 등)
              // 예: "go run cmd/.../main.go stdio --toolsets all" -> "--toolsets all"
              let options = '';
              if (fullCommand.includes('stdio')) {
                const stdioIndex = fullCommand.indexOf('stdio');
                const afterStdio = fullCommand.substring(stdioIndex + 5).trim(); // "stdio" 길이 5
                if (afterStdio) {
                  options = afterStdio;
                }
              }
              
              // 옵션이 있으면 그대로 사용, 없으면 stdio만
              const finalOptions = options ? `stdio ${options}` : 'stdio';
              runCommands.push({
                command: 'sh',
                args: ['-c', `cd ${repoPath} && go run ${mainGoPath} ${finalOptions}`],
                env: {},
                type: 'go',
                priority: options.includes('--toolsets') || options.includes('all') ? 0 : 1, // 옵션이 있으면 최우선
                mainGoPath: mainGoPath,
                detectedOptions: options
              });
            }
          }
        }
      }
      
      // TypeScript/Node.js 서버: "npm start", "node dist/index.js stdio", "tsx src/index.ts stdio" 등
      const nodePatterns = [
        // "npm start" 또는 "npm run dev" (stdio 포함 여부 확인)
        /(?:^|\n|```)\s*npm\s+(?:run\s+)?(start|dev|build:start)(?:\s+stdio)?(?:\s+[^\n]+)?/gim,
        // "node dist/index.js stdio" 또는 "node src/server.js stdio"
        /(?:^|\n|```)\s*node\s+([^\s]+\.js)(?:\s+stdio)?(?:\s+[^\n]+)?/gim,
        // "tsx src/index.ts stdio" 또는 "ts-node src/index.ts stdio"
        /(?:^|\n|```)\s*(?:tsx|ts-node)\s+([^\s]+\.ts)(?:\s+stdio)?(?:\s+[^\n]+)?/gim,
        // "npx @modelcontextprotocol/server-slack stdio"
        /(?:^|\n|```)\s*npx\s+([^\s]+)(?:\s+stdio)?(?:\s+[^\n]+)?/gim
      ];
      
      for (const pattern of nodePatterns) {
        const matches = searchText.matchAll(pattern);
        for (const match of matches) {
          const fullCommand = match[0].trim();
          // stdio가 포함되어 있거나 MCP 서버 실행 명령어로 보이는 경우
          if (fullCommand.includes('stdio') || match[1]) {
            if (fullCommand.includes('npm')) {
              const scriptName = match[1] || 'start';
              // stdio가 포함되어 있으면 npm 스크립트가 stdio를 처리하는 것으로 간주
              runCommands.push({
                command: 'npm',
                args: scriptName === 'start' ? ['start'] : ['run', scriptName],
                env: {},
                type: 'node',
                priority: 0
              });
            } else if (fullCommand.includes('node') || fullCommand.includes('tsx') || fullCommand.includes('ts-node')) {
              const scriptPath = match[1];
              const command = fullCommand.includes('tsx') ? 'tsx' : fullCommand.includes('ts-node') ? 'ts-node' : 'node';
              // stdio가 이미 포함되어 있으면 그대로 사용
              const hasStdio = fullCommand.includes('stdio');
              runCommands.push({
                command: command,
                args: hasStdio ? [scriptPath, 'stdio'] : [scriptPath, 'stdio'], // 항상 stdio 추가
                env: {},
                type: 'node',
                priority: 0
              });
            } else if (fullCommand.includes('npx')) {
              const packageName = match[1];
              // stdio가 이미 포함되어 있으면 그대로 사용
              const hasStdio = fullCommand.includes('stdio');
              runCommands.push({
                command: 'npx',
                args: hasStdio ? ['-y', packageName, 'stdio'] : ['-y', packageName, 'stdio'], // 항상 stdio 추가
                env: {},
                type: 'node',
                priority: 0
              });
            }
          }
        }
      }
    }
    
    // 2. Makefile에서 실행 방법 파싱
    const makefileContent = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/Makefile`);
    if (makefileContent && !runCommands.some(c => c.type === 'make')) {
      // "run:", "start:", "server:" 등의 타겟 찾기
      const makeTargets = makefileContent.match(/^(run|start|server|dev):/gm);
      if (makeTargets && makeTargets.length > 0) {
        const target = makeTargets[0].replace(':', '');
        runCommands.push({
          command: 'make',
          args: [target],
          env: {},
          type: 'make',
          priority: 1
        });
      }
    }
    
    // 3. Dockerfile에서 CMD/ENTRYPOINT 파싱
    const dockerfileContent = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/Dockerfile`);
    if (dockerfileContent && runCommands.length === 0) {
      // CMD 또는 ENTRYPOINT 찾기
      const cmdMatch = dockerfileContent.match(/^(?:CMD|ENTRYPOINT)\s+\[?["']?([^"']+)["']?\]?/m);
      if (cmdMatch) {
        const cmdParts = cmdMatch[1].split(/\s+/);
        const command = cmdParts[0];
        const args = cmdParts.slice(1);
        
        // stdio가 포함되어 있으면 MCP 서버로 판단
        if (args.includes('stdio') || args.some(a => a.includes('stdio'))) {
          runCommands.push({
            command: command,
            args: args,
            env: {},
            type: command.includes('go') ? 'go' : command.includes('node') ? 'node' : 'python',
            priority: 2
          });
        }
      }
    }
    
    // 4. package.json 확인 (README에서 찾지 못한 경우)
    if (!runCommands.some(c => c.type === 'node')) {
      const packageJsonContent = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/package.json`);
      if (packageJsonContent) {
        try {
          const packageJson = JSON.parse(packageJsonContent);
          
          // TypeScript 확인
          const tsconfigContent = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/tsconfig.json`);
          const isTypeScript = !!tsconfigContent;
          
          // scripts 확인
          if (packageJson.scripts) {
            if (packageJson.scripts.start) {
              runCommands.push({
                command: 'npm',
                args: ['start'],
                env: {},
                type: 'node',
                priority: 3
              });
            }
            if (packageJson.scripts.dev) {
              runCommands.push({
                command: 'npm',
                args: ['run', 'dev'],
                env: {},
                type: 'node',
                priority: 4
              });
            }
            // build 후 start (TypeScript)
            if (isTypeScript && packageJson.scripts.build && packageJson.scripts.start) {
              runCommands.push({
                command: 'sh',
                args: ['-c', `cd ${repoPath} && npm install && npm run build && npm start`],
                env: {},
                type: 'node',
                priority: 5
              });
            }
          }
          
          // bin 필드 확인 (CLI 패키지)
          if (packageJson.bin) {
            const binName = typeof packageJson.bin === 'string' ? packageJson.bin : Object.keys(packageJson.bin)[0];
            if (packageJson.name) {
              runCommands.push({
                command: 'npx',
                args: ['-y', packageJson.name, 'stdio'],
                env: {},
                type: 'node',
                priority: 6
              });
            }
          }
          
          // main 필드 확인
          if (packageJson.main) {
            const mainPath = packageJson.main;
            if (isTypeScript) {
              // TypeScript: dist/ 또는 build/ 디렉토리 확인
              const distIndex = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/dist/${mainPath.replace(/^src\//, '')}`);
              const buildIndex = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/build/${mainPath.replace(/^src\//, '')}`);
              
              if (distIndex || buildIndex) {
                runCommands.push({
                  command: 'sh',
                  args: ['-c', `cd ${repoPath} && npm install && npm run build && node ${distIndex ? 'dist' : 'build'}/${mainPath.replace(/^src\//, '')} stdio`],
                  env: {},
                  type: 'node',
                  priority: 7
                });
              } else {
                // 빌드 디렉토리 없으면 tsx나 ts-node 사용
                runCommands.push({
                  command: 'npx',
                  args: ['tsx', mainPath, 'stdio'],
                  env: {},
                  type: 'node',
                  priority: 8
                });
              }
            } else {
              // JavaScript: 직접 실행
              runCommands.push({
                command: 'node',
                args: [mainPath, 'stdio'],
                env: {},
                type: 'node',
                priority: 7
              });
            }
          }
          
          // src/index.ts 또는 src/index.js 확인 (main이 없는 경우)
          if (!packageJson.main) {
            const srcIndexTs = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/src/index.ts`);
            const srcIndexJs = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/src/index.js`);
            
            if (srcIndexTs) {
              runCommands.push({
                command: 'npx',
                args: ['tsx', 'src/index.ts', 'stdio'],
                env: {},
                type: 'node',
                priority: 9
              });
            } else if (srcIndexJs) {
              runCommands.push({
                command: 'node',
                args: ['src/index.js', 'stdio'],
                env: {},
                type: 'node',
                priority: 9
              });
            }
          }
        } catch (e) {
          console.error('package.json 파싱 오류:', e.message);
        }
      }
    }
    
    // 5. go.mod 확인 (README에서 찾지 못한 경우)
    if (!runCommands.some(c => c.type === 'go')) {
      const goModContent = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/go.mod`);
      if (goModContent) {
        // main.go 파일 찾기
        const mainGoFiles = await listRemoteDirectory(sshHost, sshUser, sshKey, repoPath);
        const goMainFiles = mainGoFiles.filter(f => f.endsWith('main.go') && !f.includes('vendor') && !f.includes('test'));
        
        for (const mainGoFile of goMainFiles.slice(0, 3)) { // 최대 3개만
          // 원격 경로에서 상대 경로 추출
          const relativePath = mainGoFile.startsWith(repoPath) 
            ? mainGoFile.substring(repoPath.length + 1) 
            : mainGoFile;
          
          if (relativePath.startsWith('cmd/')) {
            // fallback: README에서 찾지 못한 경우, github-mcp-server처럼 보이면 --toolsets all 추가
            // 다른 서버는 옵션이 없어도 동작하므로 기본값은 stdio만
            const isGithubMcpServer = relativePath.includes('github') || repoPath.includes('github');
            const fallbackOptions = isGithubMcpServer ? '--toolsets all' : '';
            runCommands.push({
              command: 'sh',
              args: ['-c', `cd ${repoPath} && go run ${relativePath} stdio ${fallbackOptions}`.trim()],
              env: {}, // 사용자가 URL 파라미터로 토큰을 전달하므로 DB에 저장하지 않음
              type: 'go',
              priority: 5, // README에서 찾지 못한 경우 fallback
              mainGoPath: relativePath,
              detectedOptions: fallbackOptions
            });
          } else {
            const isGithubMcpServer = relativePath.includes('github') || repoPath.includes('github');
            const fallbackOptions = isGithubMcpServer ? '--toolsets all' : '';
            runCommands.push({
              command: 'sh',
              args: ['-c', `cd ${repoPath} && go run ${relativePath} stdio ${fallbackOptions}`.trim()],
              env: {}, // 사용자가 URL 파라미터로 토큰을 전달하므로 DB에 저장하지 않음
              type: 'go',
              priority: 6, // README에서 찾지 못한 경우 fallback
              mainGoPath: relativePath,
              detectedOptions: fallbackOptions
            });
          }
        }
      }
    }
    
    // pyproject.toml 확인
    const pyprojectContent = await readRemoteFile(sshHost, sshUser, sshKey, `${repoPath}/pyproject.toml`);
    if (pyprojectContent) {
      const entryPointMatch = pyprojectContent.match(/\[project\.scripts\]\s*\n\s*(\w+)\s*=\s*["']([^"']+)["']/);
      if (entryPointMatch) {
        runCommands.push({
          command: 'python',
          args: ['-m', entryPointMatch[2].replace(/\.py$/, '')],
          env: {},
          type: 'python',
          priority: 1
        });
      }
    }
  } catch (error) {
    console.error('원격 파일 읽기 오류:', error.message);
  }
  
  if (runCommands.length === 0) {
    throw new Error('실행 방법을 감지할 수 없습니다.');
  }
  
  // 우선순위로 정렬
  runCommands.sort((a, b) => (a.priority || 999) - (b.priority || 999));
  
  // 첫 번째 우선순위 명령어 사용
  const runConfig = runCommands[0];
  
  // SSH 연결 정보 (환경변수에서 가져오기)
  // 원격 서버 경로는 항상 /home/ubuntu/mcp-servers 사용 (로컬 경로와 혼동 방지)
  const registryBasePath = '/home/ubuntu/mcp-servers';
  
  // 서버 이름을 안전한 이름으로 변환 (cloneToRegistry에서 사용한 것과 동일)
  const safeServerName = sanitizeServerName(serverName);
  const serverPath = `${registryBasePath}/${safeServerName}`;
  
  // connection_config 생성
  let command = null;
  let args = [];
  let env = runConfig.env || {};
  
  if (runConfig.type === 'go') {
    // Go 서버: MCP Proxy가 go를 절대 경로로 변환하는 것을 방지
    // env를 사용하여 PATH를 명시적으로 설정하고 go를 실행
    const mainGoPath = runConfig.mainGoPath || 'main.go';
    command = 'sh';
    
    // README에서 감지된 옵션이 있으면 사용, 없으면 stdio만
    const detectedOptions = runConfig.detectedOptions || '';
    const finalOptions = detectedOptions ? `stdio ${detectedOptions}` : 'stdio';
    
    // env PATH를 설정하여 go가 PATH에서 찾아지도록 하고, MCP Proxy의 경로 변환을 우회
    args = ['-c', `cd ${serverPath} && env PATH="/usr/local/go/bin:/usr/bin:/bin:$PATH" go run ${mainGoPath} ${finalOptions}`];
  } else if (runConfig.type === 'make') {
    // Makefile 사용: make run 등
    command = 'sh';
    args = ['-c', `cd ${serverPath} && make ${runConfig.args[0] || 'run'}`];
  } else if (runConfig.type === 'node') {
    // Node.js/TypeScript 서버
    if (runConfig.command === 'npm') {
      // npm start 또는 npm run <script>
      const scriptName = runConfig.args[0] === 'start' ? 'start' : runConfig.args[1] || 'start';
      command = 'sh';
      args = ['-c', `cd ${serverPath} && npm ${runConfig.args[0] === 'start' ? 'start' : `run ${scriptName}`}`];
    } else if (runConfig.command === 'npx') {
      // npx <package> stdio
      const packageName = runConfig.args[0];
      command = 'npx';
      args = ['-y', packageName, 'stdio'];
    } else if (runConfig.command === 'tsx' || runConfig.command === 'ts-node') {
      // tsx src/index.ts stdio 또는 ts-node src/index.ts stdio
      const scriptPath = runConfig.args[0];
      command = runConfig.command;
      args = [scriptPath, 'stdio'];
    } else {
      // node <script> stdio
      const scriptPath = runConfig.args[0] || 'server.js';
      command = 'node';
      // stdio가 이미 args에 포함되어 있으면 그대로 사용, 없으면 추가
      const hasStdio = runConfig.args.includes('stdio');
      args = hasStdio ? runConfig.args : [`${serverPath}/${scriptPath}`, 'stdio'];
    }
  } else if (runConfig.type === 'python') {
    // Python 서버
    const scriptPath = runConfig.args[0] || 'server.py';
    command = 'python';
    args = [`${serverPath}/${scriptPath}`];
  } else {
    // 기본값: runConfig의 command와 args를 그대로 사용하되 경로 조정
    command = runConfig.command;
    args = runConfig.args.map(arg => {
      // 경로인 경우 서버 경로와 결합
      if (arg.startsWith('./') || (!arg.startsWith('/') && !arg.startsWith('http') && !arg.startsWith('-c'))) {
        return `${serverPath}/${arg.replace(/^\.\//, '')}`;
      }
      // -c 옵션인 경우 전체 명령어를 서버 경로로 조정
      if (arg === '-c' && runConfig.args.length > 1) {
        const nextArg = runConfig.args[runConfig.args.indexOf(arg) + 1];
        if (nextArg && nextArg.includes('cd')) {
          return arg; // -c는 그대로 유지
        }
      }
      return arg;
    });
  }
  
  // connection_config 생성
  // 프록시 서버(게이트웨이)에서 사용할 수 있는 경로로 설정
  // 프록시 서버는 /home/ubuntu/mcp-gateway/pem/MCP-Server.pem 경로를 사용
  const proxyServerSshKey = '/home/ubuntu/mcp-gateway/pem/MCP-Server.pem';
  
  const connectionConfig = {
    type: 'ssh',
    ssh_host: sshHost,  // 함수 시작 부분에서 선언됨
    ssh_user: sshUser,  // 함수 시작 부분에서 선언됨
    ssh_key: proxyServerSshKey,    // 프록시 서버 경로 사용
    command: command,
    args: args,
    env: env
  };
  
  return connectionConfig;
}

/**
 * 승인 시 중앙 레지스트리에 클론 및 connection_config 생성
 * @param {string} githubUrl - GitHub 리포지토리 URL
 * @param {string} serverName - 서버 이름
 * @returns {Promise<object>} connection_config 객체
 */
async function registerServerToRegistry(githubUrl, serverName) {
  try {
    // 1. 중앙 레지스트리에 git clone
    console.log(`[레지스트리] 중앙 레지스트리에 클론 시작: ${githubUrl}`);
    const { repoPath } = await cloneToRegistry(githubUrl, serverName);
    console.log(`[레지스트리] 클론 완료: ${repoPath}`);
    
    // 2. 실행 방법 감지 및 connection_config 생성
    console.log(`[레지스트리] 실행 방법 감지 중: ${repoPath}`);
    const connectionConfig = await detectAndBuildConnectionConfig(repoPath, serverName);
    console.log(`[레지스트리] connection_config 생성 완료:`, JSON.stringify(connectionConfig, null, 2));
    
    return connectionConfig;
  } catch (error) {
    console.error('[레지스트리] 등록 실패:', error);
    throw error;
  }
}

module.exports = {
  cloneToRegistry,
  detectAndBuildConnectionConfig,
  registerServerToRegistry,
  sanitizeServerName,
  canUseRegistry
};


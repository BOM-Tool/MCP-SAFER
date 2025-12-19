/**
 * Docker 샌드박스 기반 MCP Tool 스캐너
 * - 격리된 컨테이너에서 MCP 서버 실행
 * - tools/list 호출하여 정확한 Tool 목록 추출
 * - 보안 제한: 네트워크 차단, 리소스 제한, 타임아웃
 */

const { spawn, exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const execAsync = promisify(exec);

// 임시 디렉토리 생성
const TEMP_DIR = path.join(os.tmpdir(), 'mcp-sandbox');
const SANDBOX_TIMEOUT = 180000; // 180초 (3분) - go mod download와 빌드 시간 고려
const MAX_MEMORY = '2g'; // Go 빌드를 위해 512m → 2g로 증가
const MAX_CPU = '2.0'; // 빌드 속도를 위해 1.0 → 2.0으로 증가

/**
 * Docker 설치 확인
 */
async function checkDockerInstalled() {
  try {
    await execAsync('docker --version', { timeout: 5000 });
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Docker 실행 중 확인
 */
async function checkDockerRunning() {
  try {
    await execAsync('docker ps', { timeout: 5000 });
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * GitHub 리포지토리를 shallow clone
 */
async function cloneRepository(githubUrl, targetDir) {
  const parsed = parseGitHubUrl(githubUrl);
  if (!parsed) {
    throw new Error('유효하지 않은 GitHub URL입니다.');
  }

  const { owner, repo, branch } = parsed;
  const repoUrl = `https://github.com/${owner}/${repo}.git`;
  
  // 기존 디렉토리 정리
  try {
    await fs.rm(targetDir, { recursive: true, force: true });
  } catch (e) {
    // 디렉토리가 없으면 무시
  }
  await fs.mkdir(targetDir, { recursive: true });

  // Shallow clone
  const cloneCmd = `git clone --depth 1 --branch ${branch || 'main'} ${repoUrl} ${targetDir}`;
  await execAsync(cloneCmd, { timeout: 30000 });
  
  return { owner, repo, branch: branch || 'main' };
}

/**
 * GitHub URL 파싱
 */
function parseGitHubUrl(url) {
  if (!url) return null;
  const u = url.replace(/\.git$/i, '');
  
  const short = u.match(/^([^/]+)\/([^/]+)$/);
  if (short) return { owner: short[1], repo: short[2], branch: 'main' };
  
  const m1 = u.match(/github\.com\/([^/]+)\/([^/]+)\/tree\/([^/]+)/i);
  if (m1) return { owner: m1[1], repo: m1[2], branch: m1[3] };
  
  const m2 = u.match(/github\.com\/([^/]+)\/([^/]+)/i);
  if (m2) return { owner: m2[1], repo: m2[2], branch: 'main' };
  
  return null;
}

/**
 * 리포지토리에서 실행 명령어 자동 감지
 */
async function detectRunCommand(repoPath) {
  const commands = [];
  
  try {
    // package.json (Node.js)
    const packageJsonPath = path.join(repoPath, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf-8'));
    
    if (packageJson.scripts?.start) {
      commands.push({
        command: 'npm',
        args: ['start'],
        env: {},
        type: 'node'
      });
    }
    if (packageJson.bin) {
      const binName = typeof packageJson.bin === 'string' ? packageJson.bin : Object.keys(packageJson.bin)[0];
      commands.push({
        command: 'node',
        args: [binName],
        env: {},
        type: 'node'
      });
    }
    if (packageJson.main) {
      commands.push({
        command: 'node',
        args: [packageJson.main],
        env: {},
        type: 'node'
      });
    }
  } catch (e) {
    // package.json 없음
  }
  
  try {
    // pyproject.toml (Python)
    const pyprojectPath = path.join(repoPath, 'pyproject.toml');
    const pyproject = await fs.readFile(pyprojectPath, 'utf-8');
    const entryPointMatch = pyproject.match(/\[project\.scripts\]\s*\n\s*(\w+)\s*=\s*["']([^"']+)["']/);
    if (entryPointMatch) {
      commands.push({
        command: 'python',
        args: ['-m', entryPointMatch[2].replace(/\.py$/, '')],
        env: {},
        type: 'python'
      });
    }
  } catch (e) {
    // pyproject.toml 없음
  }
  
  try {
    // Dockerfile
    const dockerfilePath = path.join(repoPath, 'Dockerfile');
    const dockerfile = await fs.readFile(dockerfilePath, 'utf-8');
    const cmdMatch = dockerfile.match(/CMD\s+\[(.*?)\]/);
    if (cmdMatch) {
      const cmdArgs = cmdMatch[1].split(',').map(s => s.trim().replace(/["']/g, ''));
      // stdio는 명령어가 아니라 MCP 프로토콜 전송 방식이므로 제외
      const filteredArgs = cmdArgs.filter(arg => arg !== 'stdio');
      if (filteredArgs.length > 0 && filteredArgs[0] !== 'stdio') {
        commands.push({
          command: filteredArgs[0],
          args: filteredArgs.slice(1),
          env: {},
          type: 'docker'
        });
      }
    }
  } catch (e) {
    // Dockerfile 없음
  }
  
  try {
    // go.mod (Go 서버)
    const goModPath = path.join(repoPath, 'go.mod');
    await fs.access(goModPath);
    
    // 재귀적으로 main.go 찾기
    async function findMainGoFiles(dir, depth = 0, maxDepth = 3) {
      if (depth > maxDepth) return [];
      
      const mainGoFiles = [];
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          
          // 제외할 디렉토리
          if (entry.isDirectory()) {
            if (entry.name.startsWith('.') || 
                entry.name === 'vendor' || 
                entry.name === 'node_modules' ||
                entry.name === 'test' ||
                entry.name === 'tests') {
              continue;
            }
            // 재귀 검색
            const subFiles = await findMainGoFiles(fullPath, depth + 1, maxDepth);
            mainGoFiles.push(...subFiles);
          } else if (entry.name === 'main.go') {
            // 상대 경로 계산
            const relativePath = path.relative(repoPath, fullPath);
            mainGoFiles.push(relativePath);
          }
        }
      } catch (e) {
        // 디렉토리 읽기 실패 무시
      }
      
      return mainGoFiles;
    }
    
    const mainGoFiles = await findMainGoFiles(repoPath);
    
    // 각 main.go 파일에 대해 실행 명령어 생성
    for (const mainGoFile of mainGoFiles) {
      const mainGoPath = path.join(repoPath, mainGoFile);
      const dirPath = path.dirname(mainGoFile);
      
      // cmd/ 디렉토리 내의 main.go 우선
      if (mainGoFile.startsWith('cmd/')) {
        const cmdName = dirPath.split(path.sep)[1]; // cmd/name/main.go -> name
        commands.push({
          command: 'sh',
          args: ['-c', `cd /workspace && go run ${mainGoFile} stdio`],
          env: {},
          type: 'go',
          priority: 1 // cmd/ 디렉토리 우선
        });
      } else {
        commands.push({
          command: 'sh',
          args: ['-c', `cd /workspace && go run ${mainGoFile} stdio`],
          env: {},
          type: 'go',
          priority: 2
        });
      }
    }
    
    // 우선순위로 정렬 (cmd/ 디렉토리가 먼저)
    commands.sort((a, b) => (a.priority || 999) - (b.priority || 999));
  } catch (e) {
    // go.mod 없음
  }
  
  // 기본값: README에서 추론하거나 일반적인 패턴
  if (commands.length === 0) {
    // 일반적인 MCP 서버 패턴
    commands.push(
      { command: 'node', args: ['server.js'], env: {}, type: 'node' },
      { command: 'node', args: ['index.js'], env: {}, type: 'node' },
      { command: 'python', args: ['server.py'], env: {}, type: 'python' },
      { command: 'python', args: ['main.py'], env: {}, type: 'python' }
    );
  }
  
  return commands;
}

/**
 * 언어별 Docker 이미지 선택
 */
function getDockerImage(type) {
  switch (type) {
    case 'go':
      return 'golang:1.24-alpine'; // Go 1.24 이상 필요 (github-mcp-server 요구사항)
    case 'python':
      return 'python:3.11-alpine';
    case 'node':
    default:
      return 'node:20-alpine';
  }
}

/**
 * Docker 컨테이너에서 MCP 서버 실행 및 tools/list 호출
 * @param {string|null} repoPath - 리포지토리 경로 (null이면 컨테이너 내부에서 clone)
 * @param {Object} runConfig - 실행 설정
 * @param {string} [repoUrl] - GitHub 리포지토리 URL (repoPath가 null일 때 사용)
 * @param {string} [branch] - 브랜치 이름 (repoPath가 null일 때 사용)
 */
async function runMcpServerInSandbox(repoPath, runConfig, repoUrl = null, branch = 'main') {
  const { command, args = [], env = {} } = runConfig;
  
  // Docker 컨테이너 이름
  const containerName = `mcp-sandbox-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  // 환경 변수 배열 생성 (spawn에 직접 전달)
  const envVarArgs = Object.entries(env)
    .flatMap(([k, v]) => ['-e', `${k}=${v}`]);
  
  // Docker run 명령어 구성
  // 보안 옵션:
  // --network=none: 네트워크 차단
  // --memory=512m: 메모리 제한
  // --cpus=0.5: CPU 제한
  // --read-only: 읽기 전용 루트
  // --tmpfs /tmp: /tmp만 쓰기 가능
  // --security-opt no-new-privileges: 권한 상승 방지
  // --rm: 종료 시 자동 삭제
  // Go 서버의 경우 의존성 다운로드를 위해 네트워크 필요 (모듈 다운로드 후 차단 가능)
  // 하지만 실행 단계에서는 네트워크 차단이 안전하므로, 빌드와 실행을 분리하는 것이 좋음
  // 현재는 간단하게 Go 서버의 경우 네트워크 허용 (개선 필요)
  const useNetwork = runConfig.type === 'go'; // Go는 의존성 다운로드 필요
  
  // 실행 명령어 구성
  // 이미 sh -c 형태면 그대로 사용, 아니면 sh -c로 감싸기
  const execCommand = command === 'sh' && args.length > 0 && args[0] === '-c'
    ? args.slice(1).join(' ') // 이미 sh -c 형태
    : `cd /workspace && ${command} ${args.join(' ')}`;
  
  // Docker 명령어를 배열로 구성 (spawn에 직접 전달)
  // Go 빌드를 위한 충분한 디스크 공간 확보
  // 주의: /workspace와 /tmp는 noexec 제거 (Go 빌드 실행 파일 실행 필요)
  const dockerArgs = [
    'run', '--rm', '-i', // -i: stdin을 열어둠 (interactive mode)
    useNetwork ? null : '--network=none',
    `--memory=${MAX_MEMORY}`,
    `--cpus=${MAX_CPU}`,
    '--tmpfs', '/workspace:rw,size=2g', // noexec, nosuid 제거: Go 빌드 실행 파일 실행 필요
    // /tmp tmpfs 제거: Go run이 생성하는 임시 실행 파일 실행을 위해 컨테이너 기본 파일시스템 사용
    runConfig.type === 'go' ? '--tmpfs' : null,
    runConfig.type === 'go' ? '/go:rw,noexec,nosuid,size=1g' : null, // Go 모듈 캐시 (noexec 유지)
    runConfig.type === 'go' ? '--tmpfs' : null,
    runConfig.type === 'go' ? '/root/.cache:rw,noexec,nosuid,size=500m' : null, // Go 빌드 캐시용
    // no-new-privileges 제거: 샌드박스 환경에서 파일 실행 문제 해결
    '--name', containerName,
    ...envVarArgs, // 환경 변수 배열 전개
    '--workdir', '/workspace',
    getDockerImage(runConfig.type),
    'sh', '-c', execCommand
  ].flat().filter(Boolean);
  
  // 디버깅: 실제 실행되는 명령어 출력
  console.log(`[DEBUG] Docker 명령어: docker ${dockerArgs.join(' ').substring(0, 300)}...`);
  
  return new Promise((resolve, reject) => {
    const tools = [];
    const fullToolDetails = [];
    let stdoutData = '';
    let stderrData = '';
    let responseReceived = false;
    let initMessageSent = false;
    
    // initialize 메시지 정의 (stderr 핸들러에서 사용)
    const initMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {
          tools: {}
        },
        clientInfo: {
          name: 'bom-tool-sandbox-scanner',
          version: '1.0.0'
        }
      }
    };
    
    // 타임아웃 설정
    const timeoutId = setTimeout(() => {
      if (!responseReceived) {
        // 컨테이너 강제 종료
        exec(`docker kill ${containerName}`, () => {});
        responseReceived = true;
        reject(new Error('MCP Server 응답 타임아웃 (60초)'));
      }
    }, SANDBOX_TIMEOUT);
    
    // MCP 클라이언트 프로세스 (Docker 컨테이너와 통신)
    // Docker 명령어를 배열로 직접 전달하여 인용부호 문제 해결
    const dockerProcess = spawn('docker', dockerArgs, {
      stdio: ['pipe', 'pipe', 'pipe']
    });
    
    // stdin이 제대로 설정되었는지 확인
    console.log('[DEBUG] stdin 설정 확인 - readable:', dockerProcess.stdin.readable, 'writable:', dockerProcess.stdin.writable);
    
    // stdin이 닫히지 않도록 에러 처리
    dockerProcess.stdin.on('error', (err) => {
      console.error('[ERROR] stdin 에러:', err);
    });
    
    // stdin이 닫히는 것을 방지 (서버가 stdin을 읽을 수 있도록)
    dockerProcess.stdin.on('close', () => {
      console.log('[DEBUG] stdin이 닫혔습니다');
    });
    
    // checkServerStart 변수 선언 (stderr 핸들러에서 사용)
    let checkServerStart = null;
    
    // stdout에서 JSON-RPC 메시지 파싱
    dockerProcess.stdout.on('data', (data) => {
      const text = data.toString();
      stdoutData += text;
      // 디버깅: 모든 stdout 출력 확인
      const outputLines = text.split('\n').filter(l => l.trim());
      for (const line of outputLines) {
        if (line.trim()) {
          // JSON 메시지 확인
          if (line.trim().startsWith('{') || line.trim().startsWith('[')) {
            console.log(`[Docker stdout (JSON)] ${line}`);
          } else {
            // 비-JSON 출력 (프로세스 상태 등)
            console.log(`[Docker stdout] ${line.substring(0, 200)}`);
          }
        }
      }
      
      // 줄 단위로 파싱 (개행 문자로 분리)
      const lines = stdoutData.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        
        try {
          const message = JSON.parse(line);
          console.log(`[DEBUG] 파싱된 메시지: id=${message.id}, method=${message.method || 'response'}`);
          
          // initialize 응답 (한 번만 처리)
          if (message.id === 1 && message.result && !responseReceived) {
            console.log('[DEBUG] Initialize 성공, tools/list 요청 전송');
            // initialize 성공, tools/list 요청 전송
            const toolsListMessage = {
              jsonrpc: '2.0',
              id: 2,
              method: 'tools/list',
              params: {}
            };
            setTimeout(() => {
              if (!responseReceived) {
                console.log('[DEBUG] tools/list 메시지 전송:', JSON.stringify(toolsListMessage));
                dockerProcess.stdin.write(JSON.stringify(toolsListMessage) + '\n');
              }
            }, 500);
          }
          
          // tools/list 응답 (한 번만 처리)
          if (message.id === 2 && message.result && message.result.tools && !responseReceived) {
            console.log(`[DEBUG] tools/list 응답 받음: ${message.result.tools.length}개 도구`);
            responseReceived = true;
            clearTimeout(timeoutId);
            
            message.result.tools.forEach(tool => {
              if (tool.name) {
                tools.push(tool.name);
                fullToolDetails.push({
                  name: tool.name,
                  description: tool.description || '',
                  input_schema: tool.inputSchema || tool.input_schema || {}
                });
              }
            });
            
            dockerProcess.kill();
            exec(`docker kill ${containerName}`, () => {});
            
            resolve({
              tools: [...new Set(tools)].sort(),
              toolDetails: fullToolDetails,
              success: true,
              method: 'sandbox_docker'
            });
            return;
          }
        } catch (e) {
          // JSON 파싱 실패 무시 (디버깅용으로 로그 출력)
          if (line.length > 10) {
            // console.log(`[DEBUG] JSON 파싱 실패: ${line.substring(0, 100)}`);
          }
        }
      }
    });
    
    // stderr 처리 (디버깅용 로그 추가)
    dockerProcess.stderr.on('data', (data) => {
      const text = data.toString();
      stderrData += text;
      // 디버깅: 모든 stderr 출력 (필터링 없이)
      // stderr는 보통 git clone, go mod download 등의 진행 상황을 보여줌
      if (text.trim()) {
        console.log(`[Docker stderr] ${text.trim()}`);
      }
      
      // 디버깅: stderr 핸들러가 호출되는지 확인 (항상 로그 출력)
      console.log(`[DEBUG] stderr 핸들러 호출됨, initMessageSent=${initMessageSent}, 누적 길이=${stderrData.length}, 현재 텍스트 길이=${text.length}`);
      
      // stderr에서 서버 시작 메시지 감지 (실시간)
      // 현재 청크와 누적된 stderrData 모두 확인
      const currentText = text.toLowerCase();
      const accumulatedText = stderrData.toLowerCase();
      
      // 디버깅: 서버 시작 메시지 패턴 확인
      const hasRunningOnStdio = currentText.includes('running on stdio') || accumulatedText.includes('running on stdio');
      const hasStartingServer = currentText.includes('starting server') || accumulatedText.includes('starting server');
      
      // 서버 시작 메시지가 감지되면 initialize 전송 (이미 전송했어도 다시 전송)
      // 타임아웃으로 먼저 전송했을 수 있지만, 서버가 시작된 후 다시 전송하는 것이 안전
      if (hasRunningOnStdio || hasStartingServer) {
        // 이미 전송했어도 서버가 시작된 후 다시 전송 (더 안전)
        if (!initMessageSent) {
          initMessageSent = true;
          if (checkServerStart) {
            clearInterval(checkServerStart);
          }
        }
        console.log('[DEBUG] ===== 서버 시작 감지 =====');
        console.log('[DEBUG] 현재 텍스트:', text.substring(0, 200));
        console.log('[DEBUG] 누적 텍스트 길이:', stderrData.length);
        console.log('[DEBUG] running on stdio 감지:', hasRunningOnStdio);
        console.log('[DEBUG] starting server 감지:', hasStartingServer);
        console.log('[DEBUG] Initialize 메시지 전송 시작 (이미 전송했어도 재전송)');
        console.log('[DEBUG] Initialize 메시지:', JSON.stringify(initMessage));
        
        // 즉시 전송 (지연 없이, 서버가 stdin을 기다리고 있음)
        // stdin이 닫혔는지 확인
        if (dockerProcess.stdin.destroyed || dockerProcess.stdin.writableEnded) {
          console.error('[ERROR] stdin이 이미 닫혔습니다');
          return;
        }
        
        try {
          const messageStr = JSON.stringify(initMessage) + '\n';
          console.log('[DEBUG] stdin에 쓰는 메시지 길이:', messageStr.length);
          console.log('[DEBUG] stdin 상태 - destroyed:', dockerProcess.stdin.destroyed, 'writableEnded:', dockerProcess.stdin.writableEnded);
          
          const success = dockerProcess.stdin.write(messageStr, (err) => {
            if (err) {
              console.error('[ERROR] stdin write 실패:', err);
            } else {
              console.log('[DEBUG] ✅ Initialize 메시지 전송 완료');
              // 전송 후 stdout/stderr 모니터링 강화
              console.log('[DEBUG] stdout/stderr 모니터링 시작...');
            }
          });
          
          if (!success) {
            console.log('[DEBUG] stdin 버퍼가 가득 참, drain 이벤트 대기');
            dockerProcess.stdin.once('drain', () => {
              console.log('[DEBUG] stdin drain 이벤트 발생, 다시 시도');
            });
          } else {
            // 전송 성공 후 stdin을 열어둠 (서버가 계속 읽을 수 있도록)
            console.log('[DEBUG] stdin을 열어둡니다 (서버가 계속 읽을 수 있도록)');
          }
        } catch (err) {
          console.error('[ERROR] stdin write 예외:', err);
        }
      }
    });
    
    // 프로세스 종료 처리
    dockerProcess.on('close', (code) => {
      clearTimeout(timeoutId);
      exec(`docker kill ${containerName}`, () => {});
      
      console.log(`[DEBUG] 프로세스 종료: code=${code}, responseReceived=${responseReceived}, tools.length=${tools.length}`);
      console.log(`[DEBUG] stdout 길이: ${stdoutData.length}, stderr 길이: ${stderrData.length}`);
      if (stdoutData) {
        console.log(`[DEBUG] stdout 내용 (마지막 500자): ${stdoutData.substring(Math.max(0, stdoutData.length - 500))}`);
      }
      
      if (!responseReceived) {
        if (tools.length > 0) {
          resolve({
            tools: [...new Set(tools)].sort(),
            toolDetails: fullToolDetails,
            success: true,
            method: 'sandbox_docker'
          });
        } else {
          // 더 자세한 에러 정보 출력
          const errorMsg = `컨테이너 종료 (code: ${code}).`;
          const stderrMsg = stderrData ? `\nstderr: ${stderrData.substring(0, 1000)}` : '';
          const stdoutMsg = stdoutData ? `\nstdout: ${stdoutData.substring(0, 1000)}` : '';
          reject(new Error(errorMsg + stderrMsg + stdoutMsg));
        }
      }
    });
    
    // 에러 처리
    dockerProcess.on('error', (error) => {
      clearTimeout(timeoutId);
      exec(`docker kill ${containerName}`, () => {});
      if (!responseReceived) {
        responseReceived = true;
        reject(new Error(`Docker 실행 실패: ${error.message}`));
      }
    });
    
    // initialize 메시지 전송 (서버 시작 대기 후 즉시 전송)
    // stdout에서 "running on stdio" 같은 메시지를 감지하면 즉시 전송
    let serverStarted = false;
    
    checkServerStart = setInterval(() => {
      if (serverStarted || responseReceived || initMessageSent) {
        clearInterval(checkServerStart);
        return;
      }
      
      // stderr나 stdout에 서버 시작 메시지가 있는지 확인
      if (stderrData.includes('running on stdio') || stderrData.includes('starting server') || 
          stdoutData.includes('running on stdio') || stdoutData.includes('starting server')) {
        serverStarted = true;
        initMessageSent = true;
        clearInterval(checkServerStart);
        console.log('[DEBUG] 서버 시작 감지, Initialize 메시지 즉시 전송');
        console.log('[DEBUG] Initialize 메시지:', JSON.stringify(initMessage));
        
        // 즉시 전송 (버퍼링 방지)
        try {
          dockerProcess.stdin.write(JSON.stringify(initMessage) + '\n', (err) => {
            if (err) {
              console.error('[ERROR] stdin write 실패:', err);
            } else {
              console.log('[DEBUG] Initialize 메시지 전송 완료');
            }
          });
        } catch (err) {
          console.error('[ERROR] stdin write 예외:', err);
        }
      }
    }, 100); // 0.1초마다 확인 (더 빠른 감지)
    
    // 최대 30초 후에는 강제로 initialize 전송 (서버가 시작 메시지를 출력하지 않는 경우 대비)
    // Go 빌드와 서버 시작에 시간이 걸릴 수 있으므로 충분한 시간 제공
    setTimeout(() => {
      if (!responseReceived && !initMessageSent) {
        clearInterval(checkServerStart);
        initMessageSent = true;
        console.log('[DEBUG] 타임아웃 후 Initialize 메시지 강제 전송');
        console.log('[DEBUG] 현재 stderr 길이:', stderrData.length);
        console.log('[DEBUG] 현재 stdout 길이:', stdoutData.length);
        try {
          dockerProcess.stdin.write(JSON.stringify(initMessage) + '\n');
        } catch (err) {
          console.error('[ERROR] stdin write 예외:', err);
        }
      }
    }, 30000); // 30초 후 강제 전송 (Go 빌드 시간 고려)
  });
}

/**
 * 컨테이너 내부에서 실행 명령어 감지 (git clone 후)
 */
async function detectRunCommandInContainer(repoUrl, branch, dockerImage) {
  return new Promise((resolve, reject) => {
    const containerName = `detect-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const shellCmd = `apk add --no-cache git >/dev/null 2>&1 && git clone --depth 1 --branch ${branch || 'main'} ${repoUrl} /tmp/repo && cd /tmp/repo && find . -name "main.go" -type f -not -path "*/vendor/*" -not -path "*/test/*" -not -path "*/.git/*" | head -10`;
    
    // 배열로 전달하여 인용부호 문제 해결
    const dockerArgs = [
      'run', '--rm',
      '--network=bridge',
      `--name=${containerName}`,
      dockerImage,
      'sh', '-c', shellCmd
    ];
    
    const dockerProcess = spawn('docker', dockerArgs, {
      stdio: ['ignore', 'pipe', 'pipe']
    });
    
    let stdout = '';
    let stderr = '';
    
    dockerProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    dockerProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    dockerProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`명령어 감지 실패 (code: ${code}): ${stderr.substring(0, 200)}`));
        return;
      }
      
      const mainGoFiles = stdout.split('\n')
        .filter(line => line.trim() && line.includes('main.go'))
        .map(line => line.replace(/^\.\//, '').trim())
        .filter(line => line.length > 0);
      
      if (mainGoFiles.length === 0) {
        reject(new Error('main.go 파일을 찾을 수 없습니다.'));
        return;
      }
      
      resolve(mainGoFiles);
    });
    
    dockerProcess.on('error', (error) => {
      reject(new Error(`Docker 실행 실패: ${error.message}`));
    });
  });
}

/**
 * 메인 함수: GitHub URL에서 Sandbox 스캔 (컨테이너 내부에서 git clone)
 */
async function scanToolsFromSandbox(githubUrl, options = {}) {
  const {
    timeout = SANDBOX_TIMEOUT,
    maxMemory = MAX_MEMORY,
    maxCpu = MAX_CPU
  } = options;
  
  // Docker 설치 및 실행 확인
  const dockerInstalled = await checkDockerInstalled();
  if (!dockerInstalled) {
    throw new Error('Docker가 설치되어 있지 않습니다. Docker Desktop을 설치해주세요. (참고: backend/DOCKER_SETUP.md)');
  }
  
  const dockerRunning = await checkDockerRunning();
  if (!dockerRunning) {
    throw new Error('Docker가 실행 중이 아닙니다. Docker Desktop을 실행해주세요.');
  }
  
  // GitHub URL 파싱
  const parsed = parseGitHubUrl(githubUrl);
  if (!parsed) {
    throw new Error('유효하지 않은 GitHub URL입니다.');
  }
  
  const { owner, repo, branch } = parsed;
  const repoUrl = `https://github.com/${owner}/${repo}.git`;
  
  // 언어 감지 (일단 Go로 가정, 나중에 개선 가능)
  const dockerImage = 'golang:1.24-alpine'; // Go 1.24 이상 필요 (github-mcp-server 요구사항)
  
  try {
    // 1. 컨테이너 내부에서 git clone 및 파일 구조 파악
    console.log(`📦 컨테이너 내부에서 리포지토리 클론 중: ${githubUrl}`);
    
    // 임시로 파일 구조를 파악하기 위한 컨테이너 실행
    let runCommands = [];
    
    // Go 서버인 경우 재귀적으로 main.go 찾기
    try {
      const mainGoFiles = await detectRunCommandInContainer(repoUrl, branch, dockerImage);
      console.log(`🔍 발견된 main.go 파일: ${mainGoFiles.join(', ')}`);
      
      for (const mainGoFile of mainGoFiles) {
        // mcpcurl은 stdio 명령을 지원하지 않으므로 제외
        if (mainGoFile.includes('mcpcurl')) {
          continue;
        }
        
        // git clone과 실행을 하나의 명령어로 (alpine에 git 설치 필요)
        // git clone은 타겟 디렉토리를 명시하면 그 디렉토리에 직접 클론됨
        // /workspace/repo에 클론한 후 그 안으로 이동
        // Go 모듈 다운로드 추가 및 환경 변수 설정 (GITHUB_PERSONAL_ACCESS_TOKEN은 선택적)
        // go run을 직접 사용 (빌드 파일 생성 없이, 권한 문제 회피)
        // TMPDIR을 /root/tmp로 설정 (컨테이너 기본 파일시스템 사용, tmpfs 아님)
        const execCmd = `apk add --no-cache git >/dev/null 2>&1 && mkdir -p /root/tmp && export TMPDIR=/root/tmp && git clone --depth 1 --branch ${branch || 'main'} ${repoUrl} /workspace/repo && cd /workspace/repo && go mod download && go run ${mainGoFile} stdio --toolsets all`;
        
        if (mainGoFile.startsWith('cmd/')) {
          runCommands.push({
            command: 'sh',
            args: ['-c', execCmd],
            env: {
              GITHUB_PERSONAL_ACCESS_TOKEN: process.env.GITHUB_PERSONAL_ACCESS_TOKEN || ''
            },
            type: 'go',
            priority: 1
          });
        } else {
          runCommands.push({
            command: 'sh',
            args: ['-c', execCmd],
            env: {
              GITHUB_PERSONAL_ACCESS_TOKEN: process.env.GITHUB_PERSONAL_ACCESS_TOKEN || ''
            },
            type: 'go',
            priority: 2
          });
        }
      }
    } catch (e) {
      console.warn('파일 구조 파악 실패, 기본 패턴 사용:', e.message);
      // 기본 패턴: git clone 후 main.go 찾기
      runCommands.push({
        command: 'sh',
        args: ['-c', `apk add --no-cache git >/dev/null 2>&1 && mkdir -p /root/tmp && export TMPDIR=/root/tmp && git clone --depth 1 --branch ${branch || 'main'} ${repoUrl} /workspace/repo && cd /workspace/repo && go mod download && find . -name "main.go" -type f -not -path "*/vendor/*" -not -path "*/test/*" -not -path "*/.git/*" | head -1 | xargs -I {} sh -c "go run {} stdio --toolsets all"`],
        env: {
          GITHUB_PERSONAL_ACCESS_TOKEN: process.env.GITHUB_PERSONAL_ACCESS_TOKEN || ''
        },
        type: 'go',
        priority: 3
      });
    }
    
    if (runCommands.length === 0) {
      throw new Error('실행 명령어를 감지할 수 없습니다.');
    }
    
    // 우선순위로 정렬
    runCommands.sort((a, b) => (a.priority || 999) - (b.priority || 999));
    
    // 2. 각 명령어 시도 (첫 번째 성공 시 종료)
    let lastError = null;
    for (const runConfig of runCommands) {
      try {
        console.log(`🚀 샌드박스에서 실행 시도: ${runConfig.command} ${runConfig.args.join(' ')}`);
        const result = await runMcpServerInSandbox(null, runConfig, repoUrl, branch); // repoPath 대신 null, repoUrl 전달
        
        return {
          ...result,
          repository: `${owner}/${repo}`,
          branch: branch || 'main',
          commitSha: null, // 컨테이너 내부에서 가져올 수 있음
          runCommand: `${runConfig.command} ${runConfig.args.join(' ')}`,
          runType: runConfig.type
        };
      } catch (error) {
        console.warn(`⚠️ 실행 실패: ${error.message}`);
        if (error.message.includes('stderr:')) {
          console.warn(`   상세 오류: ${error.message.split('stderr:')[1]?.substring(0, 300)}`);
        }
        lastError = error;
        continue; // 다음 명령어 시도
      }
    }
    
    // 모든 명령어 실패
    throw lastError || new Error('모든 실행 명령어가 실패했습니다.');
    
  } catch (error) {
    throw error;
  }
}

/**
 * 커밋 SHA 가져오기
 */
async function getCommitSha(repoPath) {
  try {
    const { stdout } = await execAsync('git rev-parse HEAD', { cwd: repoPath });
    return stdout.trim();
  } catch {
    return null;
  }
}

module.exports = {
  scanToolsFromSandbox,
  parseGitHubUrl,
  detectRunCommand
};


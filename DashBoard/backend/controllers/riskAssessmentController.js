const { exec, spawn } = require('child_process');
const { promisify } = require('util');
const path = require('path');
const fs = require('fs').promises;
const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const { getKoreaTimeSQLite } = require('../utils/dateTime');

const execAsync = promisify(exec);

// dev-server.js처럼 spawn('docker', ...) 형식으로 사용하므로
// Docker 경로를 찾는 함수가 필요 없습니다. PATH에서 자동으로 찾습니다.

// GitHub URL 유효성 검사 함수 (dev-server.js에서 가져옴)
function isValidGithubUrl(url) {
  if (typeof url !== 'string') return false;
  const trimmed = url.trim();
  const pattern = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)(?:\.git)?$/i;
  return pattern.test(trimmed);
}

// 서버 이름 정규화 함수 (GitHub URL에서 추출 시 일관된 형식으로 변환)
// 예: "https://github.com/github/github-mcp-server.git" -> "github-mcp-server"
function normalizeServerName(githubUrl, fallbackName = null) {
  let serverName = null;
  
  // GitHub URL에서 추출
  if (githubUrl && isValidGithubUrl(githubUrl)) {
    const match = githubUrl.match(/github\.com\/[^\/]+\/([^\/]+)/);
    if (match && match[1]) {
      serverName = match[1].replace(/\.git$/, ''); // .git 제거
    }
  }
  
  // GitHub URL에서 추출 실패 시 fallback 사용
  if (!serverName && fallbackName) {
    serverName = fallbackName;
  }
  
  // 기본값
  if (!serverName || serverName.trim() === '') {
    serverName = 'finding';
  }
  
  // 숫자만 있는 경우 방지
  if (/^\d+$/.test(serverName)) {
    serverName = `mcp_server_${serverName}`;
  }
  
  // 소문자로 변환하고 공백을 하이픈으로 변환 (일관된 형식)
  serverName = serverName
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9_-]/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-+|-$/g, '');
  
  return serverName;
}

// 스캐너 경로 설정 (환경 변수로 오버라이드 가능 - 클라우드 환경에서 유용)
const SCANNER_PATH = process.env.SCANNER_PATH || path.resolve(__dirname, '../../../MCP-SCAN');
const OUTPUT_DIR = path.join(SCANNER_PATH, 'output');
const CONTAINER_NAME = process.env.DOCKER_CONTAINER_NAME || 'bomtool-scanner';

// Bomtori 분석 설정 (dev-server.js와 동일)
const BOMTORI_ROOT = process.env.BOMTORI_ROOT || path.resolve(__dirname, '../../../SBOM-SCA');
const BOMTORI_OUTPUT_DIR = process.env.BOMTORI_OUTPUT_DIR || path.join(BOMTORI_ROOT, 'output');
const BOMTORI_CONTAINER_NAME = process.env.BOMTORI_CONTAINER_NAME || 'bomtori';

// TOOL-VET 분석 설정
const TOOL_VET_ROOT = process.env.TOOL_VET_ROOT || path.resolve(__dirname, '../../../TOOL-VET');
const TOOL_VET_OUTPUT_DIR = process.env.TOOL_VET_OUTPUT_DIR || path.join(TOOL_VET_ROOT, 'output');
const TOOL_VET_CONTAINER_NAME = process.env.TOOL_VET_CONTAINER_NAME || 'mcp-vetting';

// Go 프로젝트 버전에서 "v" 접두사 제거 함수
const removeVersionPrefix = (version) => {
  if (!version || typeof version !== 'string') {
    return version;
  }
  // "v"로 시작하면 제거
  return version.startsWith('v') ? version.substring(1) : version;
};

// 진행률 추적을 위한 메모리 저장소 (스캔 세션별 진행률)
const scanProgress = new Map(); // { scanId: { bomtori: 0-100, scanner: 0-100, status: 'running'|'completed'|'failed' } }

const riskAssessmentController = {
  // 코드 스캔 실행 (도커 컨테이너 사용)
  scanCode: async (req, res) => {
    try {
      const { github_url, repository_path, mcp_server_name } = req.body;
      
      console.log(`[SCAN] scanCode 호출됨: github_url="${github_url}", repository_path="${repository_path}", mcp_server_name="${mcp_server_name}"`);
      
      if (!github_url && !repository_path) {
        return res.status(400).json({
          success: false,
          message: 'github_url 또는 repository_path가 필요합니다.'
        });
      }

      // GitHub URL을 우선적으로 사용, 없으면 파일 경로 사용
      let scanPath = null;
      if (github_url) {
        scanPath = github_url;
      } else if (repository_path) {
        // 파일 경로를 절대 경로로 변환
        // repository_path는 /uploads/filename 형식이므로 절대 경로로 변환
        const uploadsDir = path.join(__dirname, '..', 'uploads');
        const fileName = path.basename(repository_path);
        const fullPath = path.join(uploadsDir, fileName);
        
        // 파일 존재 확인
        try {
          await fs.access(fullPath);
          scanPath = fullPath;
        } catch (e) {
          return res.status(400).json({
            success: false,
            message: `파일을 찾을 수 없습니다: ${fullPath}`
          });
        }
      }
      
      // MCP 서버 이름 결정: GitHub URL에서 추출 (우선순위 1), 없으면 파일 경로에서 추출
      let serverName = null;
      let fallbackName = null;
      
      // GitHub URL이 있으면 무조건 GitHub URL에서 리포지토리 이름 추출
      if (github_url) {
        // GitHub URL에서 repo 이름 추출: https://github.com/user/repo -> repo
        const match = github_url.match(/github\.com\/[^\/]+\/([^\/]+)/);
        if (match && match[1]) {
          serverName = match[1].replace(/\.git$/, ''); // .git 제거
          console.log(`[SCAN] GitHub URL에서 서버 이름 추출: ${serverName}`);
        }
      }
      
      // GitHub URL이 없거나 추출 실패한 경우 파일 경로에서 추출
      if (!serverName && repository_path) {
        const fileName = path.basename(repository_path);
        // 타임스탬프_파일명 형식에서 파일명 추출
        const match = fileName.match(/^\d+_\d+_(.+)$/);
        if (match && match[1]) {
          fallbackName = match[1].replace(/\.[^.]*$/, ''); // 확장자 제거
        } else {
          fallbackName = fileName.replace(/\.[^.]*$/, ''); // 확장자 제거
        }
        console.log(`[SCAN] 파일 경로에서 서버 이름 추출: ${fallbackName}`);
      }
      
      // 서버 이름 정규화 (일관된 형식으로 변환)
      serverName = normalizeServerName(github_url, fallbackName);
      console.log(`[SCAN] 정규화된 서버 이름: ${serverName}`);

      // serverName을 안전한 파일명으로 변환 (Python 스캐너용)
      // Python의 save_mcp_scan_result와 동일한 로직 사용
      const safeServerName = serverName
        .split('')
        .map(c => (c.match(/[a-zA-Z0-9_-]/) ? c : '_'))
        .join('')
        .replace(/_{2,}/g, '_')
        .replace(/^_+|_+$/g, '');
      
      console.log(`[SCAN] 안전한 파일명: "${safeServerName}"`);

      // scanPath가 null인 경우 에러 반환
      if (!scanPath) {
        return res.status(400).json({
          success: false,
          message: '스캔 경로를 결정할 수 없습니다.'
        });
      }

      // ========== MCP-SCAN (Code Scanner) ==========
      // 도커 컨테이너가 실행 중인지 확인 (dev-server.js처럼 spawn 사용)
      try {
        const checkProcess = spawn('docker', [
          'ps',
          '--filter',
          `name=${CONTAINER_NAME}`,
          '--format',
          '{{.Names}}'
        ], {
          cwd: SCANNER_PATH
        });
        
        let stdout = '';
        let stderr = '';
        
        checkProcess.stdout.on('data', (data) => {
          stdout += data.toString();
        });
        
        checkProcess.stderr.on('data', (data) => {
          stderr += data.toString();
        });
        
        await new Promise((resolve, reject) => {
          checkProcess.on('close', (code) => {
            if (code !== 0) {
              reject(new Error(`Docker 명령 실행 실패: ${stderr || '알 수 없는 오류'}`));
          } else {
              resolve();
            }
          });
          
          checkProcess.on('error', (error) => {
            reject(error);
          });
        });
        
        if (!stdout.trim()) {
          return res.status(500).json({
            success: false,
            message: `Docker 컨테이너가 실행 중이 아닙니다: ${CONTAINER_NAME}. 컨테이너를 먼저 시작해주세요.`
          });
        }
        
        console.log(`Docker 컨테이너 확인됨: ${CONTAINER_NAME}`);
      } catch (error) {
        console.error('도커 컨테이너 확인 오류:', error);
        return res.status(500).json({
          success: false,
          message: `도커 컨테이너 확인 실패: ${error.message}`
        });
      }

      // output 디렉토리 권한 설정 (컨테이너 내부에서 root 권한으로)
      try {
        const chmodArgs = ['exec', '-u', 'root', CONTAINER_NAME, 'bash', '-c', 'chmod 777 /app/output && chown -R appuser:appuser /app/output 2>/dev/null || true'];
        const chmodProcess = spawn('docker', chmodArgs, { cwd: SCANNER_PATH });
        await new Promise((resolve) => {
          chmodProcess.on('close', () => resolve());
          chmodProcess.on('error', () => resolve());
        });
        console.log(`[SCAN] output 디렉토리 권한 설정 완료`);
      } catch (chmodError) {
        console.warn(`[SCAN] output 디렉토리 권한 설정 실패 (무시): ${chmodError.message}`);
      }
      
      // 도커 컨테이너에서 스캔 실행
      // cli.py는 --output 옵션을 지원하지 않으며, 자동으로 저장소 이름을 기반으로 출력 파일명을 생성합니다
      // 작업 디렉토리를 /app으로 명시하여 output 디렉토리가 /app/output에 생성되도록 함
      // PYTHONPATH를 /app으로 설정하여 scanner 모듈을 찾을 수 있도록 함
      // bash -c를 사용하여 환경 변수를 확실하게 설정하고, scanPath를 따옴표로 감싸서 특수문자 처리
      const escapedScanPath = scanPath.replace(/'/g, "'\"'\"'"); // 작은따옴표 이스케이프
      // bash -c는 하나의 문자열 인자를 받으므로 전체 명령을 하나로 묶어야 함
      const bashCommand = `cd /app && PYTHONPATH=/app python -m scanner.cli --path '${escapedScanPath}'`;
      const dockerArgs = [
        'exec',
        '-w', '/app',  // 작업 디렉토리를 /app으로 설정
        CONTAINER_NAME,
        'bash',
        '-c',
        bashCommand
      ];
      
      console.log(`[SCAN] 스캔 시작: ${scanPath}`);
      console.log(`[SCAN] 서버 이름: ${serverName} (GitHub URL에서 추출)`);
      console.log(`[SCAN] 안전한 파일명: ${safeServerName}`);
      console.log(`[SCAN] 실행 명령: docker exec -w /app ${CONTAINER_NAME} bash -c '${bashCommand}'`);
      console.log(`[SCAN] 현재 작업 디렉토리: ${SCANNER_PATH}`);
      
      // 스캔 ID 미리 생성 (Bomtori와 code scanner가 동일한 scan_id 사용)
      const scanId = uuidv4();
      
      // 진행률 초기화
      const hasBomtori = github_url && isValidGithubUrl(github_url);
      const hasScanner = true; // Code Scanner는 항상 실행
      const hasToolVet = github_url && isValidGithubUrl(github_url);
      console.log(`[SCAN] 진행률 초기화: hasBomtori=${hasBomtori}, hasScanner=${hasScanner}, hasToolVet=${hasToolVet}, github_url="${github_url}", isValidGithubUrl=${github_url ? isValidGithubUrl(github_url) : false}`);
      scanProgress.set(scanId, {
        bomtori: hasBomtori ? 0 : null,
        scanner: hasScanner ? 0 : null,
        toolVet: hasToolVet ? 0 : null,
        status: 'running',
        bomtoriCompleted: false,
        scannerCompleted: false,
        toolVetCompleted: false
      });
      
      // 즉시 scan_id 반환 (비동기로 진행)
      if (!res.headersSent) {
        res.json({
          success: true,
          scan_id: scanId,
          message: '스캔이 시작되었습니다.'
        });
      }
      
      // ========== SBOM-SCA (Bomtori) ==========
      // Bomtori와 Scanner를 동시에 시작하기 위한 Promise 배열
      const scanPromises = [];
      
      // Bomtori 분석도 동시에 실행 (GitHub URL이 있는 경우만)
      let bomtoriProcess = null;
      if (github_url && isValidGithubUrl(github_url)) {
        try {
          // Bomtori 컨테이너가 실행 중인지 확인 (재시작 중이면 대기)
          let bomtoriReady = false;
          let retryCount = 0;
          const maxRetries = 10; // 최대 10번 재시도 (약 20초)
          
          while (!bomtoriReady && retryCount < maxRetries) {
            try {
              const checkBomtoriProcess = spawn('docker', [
                'ps',
                '--filter',
                `name=${BOMTORI_CONTAINER_NAME}`,
                '--format',
                '{{.Names}}\t{{.Status}}'
              ], {
                cwd: BOMTORI_ROOT
              });
              
              let bomtoriStdout = '';
              let bomtoriStderr = '';
              
              checkBomtoriProcess.stdout.on('data', (data) => {
                bomtoriStdout += data.toString();
              });
              
              checkBomtoriProcess.stderr.on('data', (data) => {
                bomtoriStderr += data.toString();
              });
              
              await new Promise((resolve, reject) => {
                checkBomtoriProcess.on('close', (code) => {
                  if (code !== 0) {
                    reject(new Error(`Docker 명령 실행 실패: ${bomtoriStderr || '알 수 없는 오류'}`));
                  } else {
                    resolve();
                  }
                });
                
                checkBomtoriProcess.on('error', (error) => {
                  reject(error);
                });
              });
              
              if (!bomtoriStdout.trim()) {
                throw new Error(`Bomtori 컨테이너가 실행 중이 아닙니다: ${BOMTORI_CONTAINER_NAME}. 컨테이너를 먼저 시작해주세요.`);
              }
              
              // 컨테이너 상태 확인
              const statusLine = bomtoriStdout.trim();
              const status = statusLine.split('\t')[1] || '';
              
              if (status.includes('Restarting') || status.includes('restarting')) {
                console.log(`[Bomtori] 컨테이너가 재시작 중입니다. 대기 중... (${retryCount + 1}/${maxRetries})`);
                retryCount++;
                await new Promise(resolve => setTimeout(resolve, 2000)); // 2초 대기
                continue;
              } else if (status.includes('Up') || status.includes('running')) {
                console.log(`Bomtori 컨테이너 확인됨: ${BOMTORI_CONTAINER_NAME} (상태: ${status})`);
                bomtoriReady = true;
              } else {
                console.log(`[Bomtori] 컨테이너 상태: ${status}, 재시도 중... (${retryCount + 1}/${maxRetries})`);
                retryCount++;
                await new Promise(resolve => setTimeout(resolve, 2000)); // 2초 대기
                continue;
              }
            } catch (error) {
              if (retryCount < maxRetries - 1) {
                console.warn(`[Bomtori] 컨테이너 확인 오류 (재시도): ${error.message}`);
                retryCount++;
                await new Promise(resolve => setTimeout(resolve, 2000)); // 2초 대기
                continue;
              } else {
                console.error('Bomtori 컨테이너 확인 오류:', error);
                throw error; // 최대 재시도 횟수 초과 시 오류 전파
              }
            }
          }
          
          if (!bomtoriReady) {
            throw new Error(`Bomtori 컨테이너가 준비되지 않았습니다: ${BOMTORI_CONTAINER_NAME}. 컨테이너를 확인해주세요.`);
          }
          
          // Bomtori 출력 디렉토리 생성
          await fs.mkdir(BOMTORI_OUTPUT_DIR, { recursive: true });
          
          // docker exec로 실행 (bomtool-scanner와 동일한 방식)
          // 작업 디렉토리를 /app으로 명시하여 main.py가 올바른 경로에서 실행되도록 함
          const bomtoriArgs = [
            'exec',
            '-w', '/app',  // 작업 디렉토리를 /app으로 설정
            BOMTORI_CONTAINER_NAME,
            'python',
            'main.py',
            github_url,
            '--output-dir',
            '/app/output'
          ];
          
          console.log(`Bomtori 분석 시작: ${github_url}`);
          console.log(`Bomtori 실행 명령: docker ${bomtoriArgs.join(' ')}`);
          
          // Bomtori를 Promise로 감싸서 동시 실행
          const bomtoriPromise = new Promise((resolve, reject) => {
            // Bomtori 시작 시 즉시 진행률 업데이트
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.bomtori = 1; // 시작됨을 표시
              scanProgress.set(scanId, currentProgress);
            }
            
            bomtoriProcess = spawn('docker', bomtoriArgs, { cwd: BOMTORI_ROOT });
          
          // Bomtori 진행률 추적
          let bomtoriStartTime = Date.now();
          const bomtoriEstimatedDuration = 120000; // 2분 예상
          
          // 시간 기반 진행률 업데이트를 위한 인터벌 설정
          const bomtoriProgressInterval = setInterval(() => {
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress && currentProgress.bomtori !== null && currentProgress.bomtori < 100 && !currentProgress.bomtoriCompleted) {
              const elapsed = Date.now() - bomtoriStartTime;
              const estimatedProgress = Math.min(Math.floor((elapsed / bomtoriEstimatedDuration) * 100), 99);
              // 최소 1%씩 증가하도록 보장
              if (estimatedProgress > currentProgress.bomtori) {
                currentProgress.bomtori = estimatedProgress;
                scanProgress.set(scanId, currentProgress);
              }
            }
          }, 2000); // 2초마다 업데이트
          
          bomtoriProcess.stdout.on('data', (data) => {
            const output = data.toString().trim();
            console.log('[Bomtori]', output);
            
            // 진행률 파싱 시도 (예: "Progress: 50%" 또는 "50%")
            const progressMatch = output.match(/(\d+)%/);
            if (progressMatch) {
              const progress = parseInt(progressMatch[1]);
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress && !currentProgress.bomtoriCompleted) {
                currentProgress.bomtori = Math.min(progress, 99);
                scanProgress.set(scanId, currentProgress);
              }
            }
          });
          
          bomtoriProcess.stderr.on('data', (data) => {
            console.error('[Bomtori Error]', data.toString().trim());
          });
          
          bomtoriProcess.on('close', async (code) => {
              // 진행률 업데이트 인터벌 정리
              clearInterval(bomtoriProgressInterval);
              
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.bomtori = 100;
                currentProgress.bomtoriCompleted = true;
                scanProgress.set(scanId, currentProgress);
              }
              
              if (code === 0) {
                console.log('Bomtori 분석 완료 (종료 코드: 0)');
                
                // Bomtori 결과 파일 읽기 및 저장
                try {
                  // repo_name 추출 (GitHub URL에서 - Bomtori와 동일한 방식)
                  // Bomtori는 github_url.split('/')[-1].replace('.git', '')를 사용
                  const repoName = github_url.split('/').pop().replace('.git', '').replace(/[^a-zA-Z0-9_-]/g, '_');
                  
                  console.log(`Bomtori 결과 파일 확인 중 (repoName: ${repoName})`);
                  console.log(`BOMTORI_OUTPUT_DIR: ${BOMTORI_OUTPUT_DIR}`);
                  
                  // 출력 디렉토리의 모든 파일 확인 (디버깅용)
                  let allFiles = [];
                  try {
                    allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
                    console.log(`BOMTORI_OUTPUT_DIR의 파일 목록:`, allFiles);
                    
                    // dashboard.json 파일 찾기 (repoName으로 시작하는 파일)
                    const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
                    console.log(`발견된 dashboard.json 파일들:`, dashboardFiles);
                  } catch (dirError) {
                    console.error('BOMTORI_OUTPUT_DIR 읽기 실패:', dirError);
                  }
                  
                  // 예상 파일명
                  const dashboardFile = path.join(BOMTORI_OUTPUT_DIR, `${repoName}-dashboard.json`);
                  console.log(`예상 파일 경로: ${dashboardFile}`);
                  
                  // 파일 존재 확인 (최대 60초 대기, 컨테이너 종료 후 파일이 완전히 쓰여질 때까지 대기)
                  let fileExists = false;
                  let foundDashboardFile = null;
                  
                  for (let i = 0; i < 120; i++) {
                    // 먼저 예상 파일명 확인
                    try {
                      await fs.access(dashboardFile);
                      const stats = await fs.stat(dashboardFile);
                      if (stats.size > 0) {
                        fileExists = true;
                        foundDashboardFile = dashboardFile;
                        console.log(`Bomtori 결과 파일 확인됨: ${dashboardFile} (크기: ${stats.size} bytes)`);
                        break;
                      }
                    } catch (e) {
                      // 예상 파일명이 없으면 모든 dashboard.json 파일 확인
                      if (i % 5 === 0 && allFiles.length > 0) {
                        const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
                        // 파일을 수정 시간순으로 정렬 (가장 최근 파일 우선)
                        const dashboardFilesWithStats = [];
                        for (const file of dashboardFiles) {
                          const filePath = path.join(BOMTORI_OUTPUT_DIR, file);
                          try {
                            const stats = await fs.stat(filePath);
                            if (stats.size > 0) {
                              dashboardFilesWithStats.push({ file, filePath, mtime: stats.mtime });
                            }
                          } catch (fileError) {
                            // 파일 접근 실패, 무시
                          }
                        }
                        // 수정 시간순으로 정렬 (최신 파일이 먼저)
                        dashboardFilesWithStats.sort((a, b) => b.mtime - a.mtime);
                        
                        // 가장 최근 파일 사용 (파일명 매칭보다 최신 파일 우선)
                        if (dashboardFilesWithStats.length > 0) {
                          const latestFile = dashboardFilesWithStats[0];
                          fileExists = true;
                          foundDashboardFile = latestFile.filePath;
                          console.log(`가장 최근 dashboard.json 파일 사용: ${latestFile.file} (크기: ${(await fs.stat(latestFile.filePath)).size} bytes, 수정 시간: ${latestFile.mtime})`);
                          break;
                        }
                      }
                      
                      if (i % 10 === 0) {
                        console.log(`Bomtori 결과 파일 대기 중... (${i + 1}/120): ${dashboardFile}`);
                      }
                    }
                    await new Promise(resolve => setTimeout(resolve, 500));
                  }
                  
                  if (fileExists && foundDashboardFile) {
                    console.log(`Bomtori 결과 파일 읽기: ${foundDashboardFile}`);
                    const dashboardData = JSON.parse(await fs.readFile(foundDashboardFile, 'utf-8'));
                    const vulnerabilities = dashboardData.vulnerabilities || [];
                    
                    // 프로젝트 타입(언어) 추출: packages 배열에서 ecosystem 정보 수집
                    let projectLanguages = [];
                    if (dashboardData.packages && Array.isArray(dashboardData.packages)) {
                      const ecosystems = new Set();
                      dashboardData.packages.forEach(pkg => {
                        if (pkg.ecosystem) {
                          ecosystems.add(pkg.ecosystem);
                        } else if (pkg.type) {
                          ecosystems.add(pkg.type);
                        }
                      });
                      projectLanguages = Array.from(ecosystems);
                      
                      // ecosystem을 언어 코드로 변환
                      const ecosystemToLanguage = {
                        'npm': 'js',
                        'pypi': 'py',
                        'go': 'go',
                        'maven': 'java',
                        'nuget': 'csharp',
                        'cargo': 'rs',
                        'rubygems': 'rb',
                        'composer': 'php'
                      };
                      
                      projectLanguages = projectLanguages.map(eco => {
                        return ecosystemToLanguage[eco.toLowerCase()] || eco.toLowerCase();
                      });
                      
                      console.log(`[Bomtori] 프로젝트 타입 추출: ${JSON.stringify(projectLanguages)}`);
                      
                      // scanProgress에 언어 정보 저장
                      const currentProgress = scanProgress.get(scanId);
                      if (currentProgress) {
                        currentProgress.languages = projectLanguages;
                      }
                    }
                    
                    if (vulnerabilities.length > 0) {
                      // 기존 OSS 취약점 데이터 삭제 (같은 scan_path와 mcp_server_name의 이전 스캔 결과)
                      try {
                        if (serverName) {
                          const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ?');
                          deleteOssStmt.run(scanPath, serverName);
                          console.log(`기존 OSS 취약점 데이터 삭제 완료: ${scanPath} (서버: ${serverName})`);
                        } else {
                        const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ?');
                        deleteOssStmt.run(scanPath);
                          console.log(`기존 OSS 취약점 데이터 삭제 완료: ${scanPath} (서버 이름 없음)`);
                        }
                      } catch (deleteError) {
                        console.error('기존 OSS 취약점 데이터 삭제 오류:', deleteError);
                      }
                      
                      // code scanner와 동일한 scan_id 사용
                      
                      const insertOssStmt = db.prepare(`
                        INSERT INTO oss_vulnerabilities (
                          scan_id, scan_path, mcp_server_name, scan_timestamp,
                          package_name, package_version, package_fixed_version, package_all_fixed_versions,
                          package_affected_range, package_dependency_type,
                          vulnerability_id, vulnerability_cve, vulnerability_cvss, vulnerability_severity,
                          vulnerability_title, vulnerability_description, vulnerability_reference_url,
                          reachable, functions_count, reachable_functions, unreachable_functions, raw_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                      `);
                      
                      for (const vuln of vulnerabilities) {
                        try {
                          const pkg = vuln.package || {};
                          const vulnInfo = vuln.vulnerability || {};
                          
                          // Go 프로젝트와 npm 프로젝트 모두 지원
                          const packageName = pkg.name || null;
                          // Go 프로젝트 버전에서 "v" 접두사 제거
                          const currentVersion = removeVersionPrefix(pkg.current_version) || null;
                          const fixedVersion = removeVersionPrefix(pkg.fixed_version) || null;
                          const allFixedVersions = Array.isArray(pkg.all_fixed_versions) 
                            ? pkg.all_fixed_versions.map(v => removeVersionPrefix(v))
                            : [];
                          const affectedRange = pkg.affected_range || null;
                          const dependencyType = pkg.dependency_type || null;
                          
                          const vulnId = vulnInfo.id || null;
                          const cve = vulnInfo.cve || null;
                          const cvss = vulnInfo.cvss != null ? vulnInfo.cvss : null;
                          const severity = vulnInfo.severity || null;
                          const title = vulnInfo.title || null;
                          const description = vulnInfo.description || null;
                          const referenceUrl = vulnInfo.reference_url || null;
                          
                          const reachable = vuln.reachable === true ? 1 : 0;
                          const functionsCount = vuln.functions_count || 0;
                          const reachableFunctions = vuln.reachable_functions || 0;
                          const unreachableFunctions = vuln.unreachable_functions || 0;
                          
                          insertOssStmt.run(
                            scanId,
                            scanPath,
                            serverName, // mcp_server_name 추가
                            getKoreaTimeSQLite(),
                            packageName,
                            currentVersion,
                            fixedVersion,
                            JSON.stringify(allFixedVersions),
                            affectedRange,
                            dependencyType,
                            vulnId,
                            cve,
                            cvss,
                            severity,
                            title,
                            description,
                            referenceUrl,
                            reachable,
                            functionsCount,
                            reachableFunctions,
                            unreachableFunctions,
                            JSON.stringify(vuln)
                          );
                        } catch (insertError) {
                          console.error('OSS 취약점 저장 오류:', insertError);
                        }
                      }
                      
                      console.log(`OSS 취약점 ${vulnerabilities.length}개 저장 완료`);
                    } else {
                      console.log('Bomtori dashboard 파일에는 취약점이 없습니다.');
                    }
                  } else {
                    console.error(`Bomtori 결과 파일을 찾을 수 없습니다: ${dashboardFile}`);
                    console.error(`대기 시간 초과 (60초)`);
                    console.error(`발견된 dashboard.json 파일들:`, allFiles.filter(f => f.includes('dashboard.json')));
                    
                    // 파일을 찾지 못했지만 dashboard.json 파일이 있으면 가장 최근 파일 사용
                    const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
                    if (dashboardFiles.length > 0) {
                      console.log(`예상 파일명을 찾지 못했지만 dashboard.json 파일이 있습니다. 가장 최근 파일을 사용합니다.`);
                      const dashboardFilesWithStats = [];
                      for (const file of dashboardFiles) {
                        const filePath = path.join(BOMTORI_OUTPUT_DIR, file);
                        try {
                          const stats = await fs.stat(filePath);
                          if (stats.size > 0) {
                            dashboardFilesWithStats.push({ file, filePath, mtime: stats.mtime });
                          }
                        } catch (fileError) {
                          // 파일 접근 실패, 무시
                        }
                      }
                      if (dashboardFilesWithStats.length > 0) {
                        dashboardFilesWithStats.sort((a, b) => b.mtime - a.mtime);
                        const latestFile = dashboardFilesWithStats[0];
                        foundDashboardFile = latestFile.filePath;
                        fileExists = true;
                        console.log(`가장 최근 dashboard.json 파일 사용: ${latestFile.file}`);
                        
                        // 파일을 찾았으므로 다시 읽기 시도
                        const dashboardData = JSON.parse(await fs.readFile(foundDashboardFile, 'utf-8'));
                        const vulnerabilities = dashboardData.vulnerabilities || [];
                        
                        // 프로젝트 타입(언어) 추출: packages 배열에서 ecosystem 정보 수집
                        let projectLanguages = [];
                        if (dashboardData.packages && Array.isArray(dashboardData.packages)) {
                          const ecosystems = new Set();
                          dashboardData.packages.forEach(pkg => {
                            if (pkg.ecosystem) {
                              ecosystems.add(pkg.ecosystem);
                            } else if (pkg.type) {
                              ecosystems.add(pkg.type);
                            }
                          });
                          projectLanguages = Array.from(ecosystems);
                          
                          // ecosystem을 언어 코드로 변환
                          const ecosystemToLanguage = {
                            'npm': 'js',
                            'pypi': 'py',
                            'go': 'go',
                            'maven': 'java',
                            'nuget': 'csharp',
                            'cargo': 'rs',
                            'rubygems': 'rb',
                            'composer': 'php'
                          };
                          
                          projectLanguages = projectLanguages.map(eco => {
                            return ecosystemToLanguage[eco.toLowerCase()] || eco.toLowerCase();
                          });
                          
                          console.log(`[Bomtori] 프로젝트 타입 추출: ${JSON.stringify(projectLanguages)}`);
                          
                          // scanProgress에 언어 정보 저장
                          const currentProgress = scanProgress.get(scanId);
                          if (currentProgress) {
                            currentProgress.languages = projectLanguages;
                          }
                        }
                        
                        if (vulnerabilities.length > 0) {
                          // 기존 OSS 취약점 데이터 삭제 (같은 scan_path와 mcp_server_name의 이전 스캔 결과)
                          try {
                            if (serverName) {
                              const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ?');
                              deleteOssStmt.run(scanPath, serverName);
                              console.log(`기존 OSS 취약점 데이터 삭제 완료: ${scanPath} (서버: ${serverName})`);
                            } else {
                            const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ?');
                            deleteOssStmt.run(scanPath);
                              console.log(`기존 OSS 취약점 데이터 삭제 완료: ${scanPath} (서버 이름 없음)`);
                            }
                          } catch (deleteError) {
                            console.error('기존 OSS 취약점 데이터 삭제 오류:', deleteError);
                          }
                          
                          const insertOssStmt = db.prepare(`
                            INSERT INTO oss_vulnerabilities (
                              scan_id, scan_path, mcp_server_name, scan_timestamp,
                              package_name, package_version, package_fixed_version, package_all_fixed_versions,
                              package_affected_range, package_dependency_type,
                              vulnerability_id, vulnerability_cve, vulnerability_cvss, vulnerability_severity,
                              vulnerability_title, vulnerability_description, vulnerability_reference_url,
                              reachable, functions_count, reachable_functions, unreachable_functions, raw_data
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                          `);
                          
                          for (const vuln of vulnerabilities) {
                            try {
                              const pkg = vuln.package || {};
                              const vulnInfo = vuln.vulnerability || {};
                              
                              // Go 프로젝트와 npm 프로젝트 모두 지원
                              const packageName = pkg.name || null;
                              // Go 프로젝트 버전에서 "v" 접두사 제거
                              const currentVersion = removeVersionPrefix(pkg.current_version) || null;
                              const fixedVersion = removeVersionPrefix(pkg.fixed_version) || null;
                              const allFixedVersions = Array.isArray(pkg.all_fixed_versions) 
                                ? pkg.all_fixed_versions.map(v => removeVersionPrefix(v))
                                : [];
                              const affectedRange = pkg.affected_range || null;
                              const dependencyType = pkg.dependency_type || null;
                              
                              const vulnId = vulnInfo.id || null;
                              const cve = vulnInfo.cve || null;
                              const cvss = vulnInfo.cvss != null ? vulnInfo.cvss : null;
                              const severity = vulnInfo.severity || null;
                              const title = vulnInfo.title || null;
                              const description = vulnInfo.description || null;
                              const referenceUrl = vulnInfo.reference_url || null;
                              
                              const reachable = vuln.reachable === true ? 1 : 0;
                              const functionsCount = vuln.functions_count || 0;
                              const reachableFunctions = vuln.reachable_functions || 0;
                              const unreachableFunctions = vuln.unreachable_functions || 0;
                              
                              insertOssStmt.run(
                                scanId,
                                scanPath,
                                serverName, // mcp_server_name 추가
                                getKoreaTimeSQLite(),
                                packageName,
                                currentVersion,
                                fixedVersion,
                                JSON.stringify(allFixedVersions),
                                affectedRange,
                                dependencyType,
                                vulnId,
                                cve,
                                cvss,
                                severity,
                                title,
                                description,
                                referenceUrl,
                                reachable,
                                functionsCount,
                                reachableFunctions,
                                unreachableFunctions,
                                JSON.stringify(vuln)
                              );
                            } catch (insertError) {
                              console.error('OSS 취약점 저장 오류:', insertError);
                              console.error('저장 실패한 취약점:', JSON.stringify(vuln, null, 2));
                            }
                          }
                          
                          console.log(`OSS 취약점 ${vulnerabilities.length}개 저장 완료 (대체 파일 사용)`);
                        }
                      }
                    }
                    
                    // dashboard.json 파일이 없는 경우, summary.json을 확인하여 실패 원인 로깅
                    if (!fileExists) {
                      const summaryFile = path.join(BOMTORI_OUTPUT_DIR, `${repoName}-summary.json`);
                      try {
                        const summaryExists = await fs.access(summaryFile).then(() => true).catch(() => false);
                        if (summaryExists) {
                          const summaryData = JSON.parse(await fs.readFile(summaryFile, 'utf-8'));
                          const vulnStatus = summaryData.vulnerability?.status || 'unknown';
                          console.log(`Bomtori summary 파일 확인됨: ${summaryFile}`);
                          console.log(`Vulnerability 분석 상태: ${vulnStatus}`);
                          if (vulnStatus === 'Skipped or Failed') {
                            console.log('Vulnerability 분석이 실패하여 dashboard.json이 생성되지 않았습니다.');
                          }
                        } else {
                          console.error(`Bomtori summary 파일도 찾을 수 없습니다: ${summaryFile}`);
                          console.error('가능한 원인: 컨테이너가 종료되기 전에 파일이 완전히 쓰여지지 않았거나, 볼륨 마운트 문제일 수 있습니다.');
                        }
                      } catch (error) {
                        console.error('Bomtori summary 파일 확인 중 오류:', error);
                      }
                    }
                  }
                } catch (error) {
                  console.error('Bomtori 결과 저장 오류:', error);
                  // 오류가 발생해도 계속 진행
                }
                resolve();
              } else {
                console.error(`Bomtori 분석 실패 (종료 코드: ${code})`);
                const currentProgress = scanProgress.get(scanId);
                if (currentProgress) {
                  currentProgress.bomtori = 100; // 실패해도 100%로 표시
                  currentProgress.bomtoriCompleted = true;
                  currentProgress.bomtoriError = `Bomtori 분석 실패 (종료 코드: ${code})`;
                  scanProgress.set(scanId, currentProgress);
                }
                resolve(); // 실패해도 resolve (오류는 무시하지만 오류 정보는 저장)
              }
            });
            
            bomtoriProcess.on('error', (error) => {
              // 진행률 업데이트 인터벌 정리
              clearInterval(bomtoriProgressInterval);
              
              console.error('Bomtori 실행 오류:', error.message);
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.bomtori = 100;
                currentProgress.bomtoriCompleted = true;
                currentProgress.bomtoriError = `Bomtori 실행 오류: ${error.message}`;
                scanProgress.set(scanId, currentProgress);
              }
              resolve(); // 오류는 무시하고 resolve (오류 정보는 저장)
            });
          });
          
          scanPromises.push(bomtoriPromise);
        } catch (error) {
          console.error('Bomtori 분석 시작 실패:', error.message);
          // Bomtori 시작 실패 시에도 진행률 업데이트
          const currentProgress = scanProgress.get(scanId);
          if (currentProgress) {
            currentProgress.bomtori = 100;
            currentProgress.bomtoriCompleted = true;
            currentProgress.bomtoriError = `Bomtori 시작 실패: ${error.message}`;
            scanProgress.set(scanId, currentProgress);
          }
        }
      }
      
      // ========== MCP-SCAN (Code Scanner) ==========
      // Code Scanner도 Promise로 감싸서 동시 실행
      const scannerPromise = new Promise(async (resolve, reject) => {
        // 호스트의 output 디렉토리 확인 및 생성 (볼륨 마운트를 위해)
        try {
          const fsSync = require('fs');
          const { execSync } = require('child_process');
          
          // 디렉토리가 없으면 생성
          if (!fsSync.existsSync(OUTPUT_DIR)) {
            fsSync.mkdirSync(OUTPUT_DIR, { recursive: true });
            console.log(`[Scanner] 호스트 output 디렉토리 생성: ${OUTPUT_DIR}`);
          }
          
          // 권한 설정 (읽기/쓰기/실행 권한) - chmod 명령으로 확실하게 설정
          // 볼륨 마운트된 디렉토리는 호스트 권한을 따르므로 호스트에서 반드시 설정해야 함
          try {
            // chmod로 권한 설정
            execSync(`chmod -R 777 "${OUTPUT_DIR}"`, { stdio: 'ignore' });
            // chown으로 소유권도 설정 (ubuntu 사용자)
            try {
              execSync(`chown -R ubuntu:ubuntu "${OUTPUT_DIR}"`, { stdio: 'ignore' });
            } catch (chownError) {
              // chown 실패해도 계속 진행 (권한만으로도 충분할 수 있음)
              console.warn(`[Scanner] chown 실패 (무시): ${chownError.message}`);
            }
            console.log(`[Scanner] 호스트 output 디렉토리 권한 설정 완료 (chmod 777): ${OUTPUT_DIR}`);
          } catch (chmodError) {
            // chmod 실패 시 fs.chmodSync 시도
            try {
              fsSync.chmodSync(OUTPUT_DIR, 0o777);
              console.log(`[Scanner] 호스트 output 디렉토리 권한 설정 완료 (fs.chmodSync): ${OUTPUT_DIR}`);
            } catch (fsChmodError) {
              console.warn(`[Scanner] 호스트 output 디렉토리 권한 설정 실패: ${fsChmodError.message}`);
            }
          }
          
          // 권한 확인 (읽기/쓰기 가능한지)
          await fs.access(OUTPUT_DIR, fs.constants.R_OK | fs.constants.W_OK);
          console.log(`[Scanner] 호스트 output 디렉토리 권한 확인 완료`);
        } catch (dirError) {
          console.error(`[Scanner] 호스트 output 디렉토리 확인/생성 실패: ${dirError.message}`);
          // 디렉토리 문제가 있어도 계속 진행 (컨테이너 내부에서 생성 시도)
        }
        
        // 컨테이너 내부 output 디렉토리 확인 및 생성
        try {
          const checkOutputDir = spawn('docker', ['exec', CONTAINER_NAME, 'test', '-d', '/app/output'], {
            cwd: SCANNER_PATH
          });
          await new Promise((resolveCheck) => {
            checkOutputDir.on('close', (code) => {
              if (code !== 0) {
                // output 디렉토리가 없으면 생성
                const mkdirOutput = spawn('docker', ['exec', CONTAINER_NAME, 'mkdir', '-p', '/app/output'], {
                  cwd: SCANNER_PATH
                });
                mkdirOutput.on('close', () => resolveCheck());
                mkdirOutput.on('error', () => resolveCheck());
              } else {
                resolveCheck();
              }
            });
            checkOutputDir.on('error', () => resolveCheck());
          });
        } catch (dirError) {
          console.error('[Scanner] 컨테이너 내부 output 디렉토리 확인/생성 실패:', dirError);
        }
        
        const scanProcess = spawn('docker', dockerArgs, {
          cwd: SCANNER_PATH
        });
        
        // 타임아웃 설정
        const timeout = setTimeout(() => {
          scanProcess.kill();
          reject(new Error('스캔 타임아웃 (5분 초과)'));
        }, 300000); // 5분

        let stdout = '';
        let stderr = '';

        // Scanner 진행률 추적
        let scannerStartTime = Date.now();
        const scannerEstimatedDuration = 180000; // 3분 예상

        scanProcess.stdout.on('data', (data) => {
          const output = data.toString();
          stdout += output;
          const trimmed = output.trim();
          console.log('[Scanner]', trimmed);
          
          // 진행률 파싱 시도 (예: "Progress: 50%" 또는 "50%")
          const progressMatch = trimmed.match(/(\d+)%/);
          if (progressMatch) {
            const progress = parseInt(progressMatch[1]);
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.scanner = Math.min(progress, 99);
              scanProgress.set(scanId, currentProgress);
            }
          } else {
            // 시간 기반 진행률 추정
            const elapsed = Date.now() - scannerStartTime;
            const estimatedProgress = Math.min(Math.floor((elapsed / scannerEstimatedDuration) * 100), 99);
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.scanner = estimatedProgress;
              scanProgress.set(scanId, currentProgress);
            }
          }
        });

        scanProcess.stderr.on('data', (data) => {
          stderr += data.toString();
          console.error('[Scanner Error]', data.toString().trim());
        });

        scanProcess.on('close', async (code) => {
          clearTimeout(timeout);
          
          const currentProgress = scanProgress.get(scanId);
          if (currentProgress) {
            currentProgress.scanner = 100;
            currentProgress.scannerCompleted = true;
            scanProgress.set(scanId, currentProgress);
          }
          
          if (code !== 0) {
            console.error(`스캔 프로세스 종료 코드: ${code}`);
            console.error(`stderr: ${stderr}`);
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.scanner = 100;
              currentProgress.scannerCompleted = true;
              currentProgress.scannerError = `Code Scanner 실패 (종료 코드: ${code}): ${stderr || '알 수 없는 오류'}`;
              scanProgress.set(scanId, currentProgress);
            }
            if (!res.headersSent) {
            res.status(500).json({
              success: false,
              message: `스캔 실패: ${stderr || '알 수 없는 오류'}`
            });
            }
            return reject(new Error(`스캔 실패: ${stderr || '알 수 없는 오류'}`));
          }

          try {
            // 결과 파일 읽기 (GitHub URL에서 추출한 리포지토리 이름 사용)
            // Python의 save_mcp_scan_result와 동일한 파일명 생성 로직 사용
            // Python: "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in server_name)
            
            // GitHub URL에서 리포지토리 이름 추출 (스캔 실행 시와 동일한 로직)
            let fileServerName = serverName; // 이미 GitHub URL에서 추출한 값
            if (github_url) {
              const match = github_url.match(/github\.com\/[^\/]+\/([^\/]+)/);
              if (match && match[1]) {
                fileServerName = match[1].replace(/\.git$/, '');
                console.log(`[Scanner] GitHub URL에서 파일명용 서버 이름 추출: ${fileServerName}`);
              }
            }
            
            // Python과 동일한 파일명 생성 로직
            const pythonSafeName = fileServerName
              .split('')
              .map(c => (c.match(/[a-zA-Z0-9_-]/) ? c : '_'))
              .join('')
              .replace(/_{2,}/g, '_')
              .replace(/^_+|_+$/g, '');
            
            console.log(`[Scanner] 파일 찾기 - serverName: ${serverName}, fileServerName: ${fileServerName}, pythonSafeName: ${pythonSafeName}`);
            const resultFile = path.join(OUTPUT_DIR, `${pythonSafeName}.json`);
            console.log(`[Scanner] 찾는 파일 경로: ${resultFile}`);
            
            // 파일 존재 확인 (최대 30초 대기, 1초마다 체크)
            let fileExists = false;
            let actualResultFile = resultFile;
            
            for (let i = 0; i < 30; i++) {
              try {
                await fs.access(resultFile);
                fileExists = true;
                actualResultFile = resultFile;
                break;
              } catch (e) {
                // 파일이 없으면 디렉토리에서 유사한 파일 찾기
                try {
                  const allFiles = await fs.readdir(OUTPUT_DIR);
                  
                  // 파일명 매칭: pythonSafeName의 기본 이름 부분 추출 (숫자 제거)
                  const baseName = pythonSafeName.replace(/\d+$/, '').replace(/_+$/, '');
                  console.log(`[Scanner] 기본 이름으로 검색: ${baseName}`);
                  
                  const matchingFiles = allFiles.filter(f => {
                    if (!f.endsWith('.json')) return false;
                    const fileNameWithoutExt = f.replace(/\.json$/, '');
                    // 정확한 매칭 또는 기본 이름으로 시작하는 파일
                    return fileNameWithoutExt === pythonSafeName ||
                           fileNameWithoutExt === safeServerName ||
                           fileNameWithoutExt.includes(pythonSafeName) ||
                           fileNameWithoutExt.includes(safeServerName) ||
                           fileNameWithoutExt.startsWith(baseName) ||
                           baseName && fileNameWithoutExt.startsWith(baseName);
                  });
                  
                  console.log(`[Scanner] 매칭된 파일들: ${matchingFiles.join(', ')}`);
                  
                  if (matchingFiles.length > 0) {
                    // 가장 최근에 수정된 파일 선택
                    const fileStats = await Promise.all(
                      matchingFiles.map(f => fs.stat(path.join(OUTPUT_DIR, f)).then(stats => ({ file: f, stats })))
                    );
                    const latestFile = fileStats.sort((a, b) => b.stats.mtime - a.stats.mtime)[0];
                    actualResultFile = path.join(OUTPUT_DIR, latestFile.file);
                    fileExists = true;
                    console.log(`[Scanner] 유사한 파일 발견 및 사용: ${latestFile.file}`);
                    break;
                  }
                } catch (dirError) {
                  // 디렉토리 읽기 실패는 무시
                  console.error(`[Scanner] 디렉토리 읽기 오류: ${dirError.message}`);
                }
                
                await new Promise(resolve => setTimeout(resolve, 1000));
              }
            }

            if (!fileExists) {
              // 호스트에 파일이 없으면 Docker 컨테이너에서 직접 복사 시도
              try {
                console.log(`[Scanner] 호스트에 파일이 없어 컨테이너에서 복사 시도: ${pythonSafeName}.json`);
                
                // 컨테이너 내부 파일 확인
                const checkContainerFile = spawn('docker', ['exec', CONTAINER_NAME, 'test', '-f', `/app/output/${pythonSafeName}.json`], {
                  cwd: SCANNER_PATH
                });
                
                let containerFileExists = false;
                await new Promise((resolve) => {
                  checkContainerFile.on('close', (code) => {
                    containerFileExists = code === 0;
                    resolve();
                  });
                  checkContainerFile.on('error', () => resolve());
                });
                
                if (containerFileExists) {
                  // 컨테이너에서 호스트로 파일 복사
                  console.log(`[Scanner] 컨테이너에서 호스트로 파일 복사 중...`);
                  const copyProcess = spawn('docker', ['cp', `${CONTAINER_NAME}:/app/output/${pythonSafeName}.json`, resultFile], {
                    cwd: SCANNER_PATH
                  });
                  
                  await new Promise((resolve, rejectCopy) => {
                    copyProcess.on('close', (code) => {
                      if (code === 0) {
                        console.log(`[Scanner] 파일 복사 성공: ${resultFile}`);
                        fileExists = true;
                        actualResultFile = resultFile;
                        resolve();
                      } else {
                        console.error(`[Scanner] 파일 복사 실패 (종료 코드: ${code})`);
                        resolve(); // 복사 실패해도 계속 진행
                      }
                    });
                    copyProcess.on('error', (error) => {
                      console.error(`[Scanner] 파일 복사 오류: ${error.message}`);
                      resolve(); // 오류 발생해도 계속 진행
                    });
                  });
                } else {
                  // 컨테이너에도 파일이 없으면 디렉토리에서 찾기
                  console.log(`[Scanner] 컨테이너 내부 디렉토리에서 파일 검색...`);
                  const listContainerFiles = spawn('docker', ['exec', CONTAINER_NAME, 'ls', '-1', '/app/output/'], {
                    cwd: SCANNER_PATH
                  });
                  
                  let containerFiles = '';
                  listContainerFiles.stdout.on('data', (data) => {
                    containerFiles += data.toString();
                  });
                  
                  await new Promise((resolve) => {
                    listContainerFiles.on('close', () => {
                      const jsonFiles = containerFiles.split('\n').filter(f => f.endsWith('.json') && f.trim());
                      console.log(`[Scanner] 컨테이너 내부 JSON 파일들:`, jsonFiles);
                      
                      // 유사한 파일 찾기
                      const matchingFile = jsonFiles.find(f => {
                        const nameWithoutExt = f.replace(/\.json$/, '');
                        return nameWithoutExt === pythonSafeName || 
                               nameWithoutExt === safeServerName ||
                               nameWithoutExt.includes(pythonSafeName) ||
                               nameWithoutExt.includes(safeServerName);
                      });
                      
                      if (matchingFile) {
                        console.log(`[Scanner] 컨테이너에서 매칭된 파일 발견: ${matchingFile}`);
                        // 파일 복사
                        const copyProcess = spawn('docker', ['cp', `${CONTAINER_NAME}:/app/output/${matchingFile}`, resultFile], {
                          cwd: SCANNER_PATH
                        });
                        
                        copyProcess.on('close', (code) => {
                          if (code === 0) {
                            console.log(`[Scanner] 파일 복사 성공: ${resultFile}`);
                            fileExists = true;
                            actualResultFile = resultFile;
                          }
                          resolve();
                        });
                        copyProcess.on('error', () => resolve());
                      } else {
                        resolve();
                      }
                    });
                    listContainerFiles.on('error', () => resolve());
                  });
                }
              } catch (copyError) {
                console.error('[Scanner] 컨테이너에서 파일 복사 시도 중 오류:', copyError);
              }
              
              // 여전히 파일이 없으면 마지막 확인
              if (!fileExists) {
                try {
                  await fs.access(resultFile);
                  fileExists = true;
                  actualResultFile = resultFile;
                } catch (e) {
                  // 마지막으로 디렉토리의 모든 JSON 파일 확인
                  try {
                    const allFiles = await fs.readdir(OUTPUT_DIR);
                    const jsonFiles = allFiles.filter(f => f.endsWith('.json'));
                    console.log(`[Scanner] OUTPUT_DIR의 모든 JSON 파일:`, jsonFiles);
                    console.log(`[Scanner] 찾는 파일명: ${pythonSafeName}.json 또는 ${safeServerName}.json`);
                  } catch (dirError) {
                    console.error('[Scanner] OUTPUT_DIR 읽기 실패:', dirError);
                  }
                  
                  const currentProgress = scanProgress.get(scanId);
                  if (currentProgress) {
                    currentProgress.scannerError = `스캔 결과 파일을 찾을 수 없습니다: ${resultFile}`;
                    scanProgress.set(scanId, currentProgress);
                  }
                  if (!res.headersSent) {
                  res.status(500).json({
                    success: false,
                    message: `스캔 결과 파일을 찾을 수 없습니다: ${resultFile}`
                  });
                  }
                  return reject(new Error(`스캔 결과 파일을 찾을 수 없습니다: ${resultFile}`));
                }
              }
            }

            const resultData = await fs.readFile(actualResultFile, 'utf-8');
            console.log(`[Scanner] 결과 파일 읽기 성공: ${actualResultFile}`);
            const scanResult = JSON.parse(resultData);

            // 결과 형식: { scan_info: {...}, findings: [...], summary: {...} }
            const findings = scanResult.findings || (Array.isArray(scanResult) ? scanResult : []);

            // scanId는 이미 생성되어 있음 (Bomtori와 동일한 ID 사용)
            
            // 실제 생성된 파일명 추출 (DB에 저장하기 위해)
            const actualFileName = path.basename(actualResultFile);
            console.log(`[Scanner] 실제 생성된 파일명: ${actualFileName}`);

            // 기존 코드 취약점 데이터 삭제 (같은 scan_path와 mcp_server_name의 이전 스캔 결과)
            try {
              if (serverName) {
                const deleteStmt = db.prepare('DELETE FROM code_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ?');
                deleteStmt.run(scanPath, serverName);
                console.log(`기존 코드 취약점 데이터 삭제 완료: ${scanPath} (서버: ${serverName})`);
              } else {
              const deleteStmt = db.prepare('DELETE FROM code_vulnerabilities WHERE scan_path = ?');
              deleteStmt.run(scanPath);
                console.log(`기존 코드 취약점 데이터 삭제 완료: ${scanPath} (서버 이름 없음)`);
              }
            } catch (deleteError) {
              console.error('기존 코드 취약점 데이터 삭제 오류:', deleteError);
            }

            // 데이터베이스에 저장 (실제 파일명도 함께 저장, mcp_server_name 포함)
            const insertStmt = db.prepare(`
              INSERT INTO code_vulnerabilities (
                scan_id, scan_path, mcp_server_name, scan_timestamp, rule_id, vulnerability, severity,
                language, file, line, column, message, description, cwe,
                code_snippet, pattern_type, pattern, confidence, raw_finding, result_filename
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);

            for (const finding of findings) {
              try {
                insertStmt.run(
                  scanId,
                  scanPath,
                  serverName || null, // mcp_server_name 추가
                  getKoreaTimeSQLite(),
                  finding.rule_id || null,
                  finding.vulnerability || finding.message || null,
                  finding.severity || null,
                  finding.language || null,
                  finding.file || null,
                  finding.line || null,
                  finding.column || null,
                  finding.message || null,
                  finding.description || null,
                  finding.cwe || null,
                  finding.code_snippet || null,
                  finding.pattern_type || null,
                  finding.pattern || null,
                  finding.confidence || null,
                  JSON.stringify(finding),
                  actualFileName  // 실제 생성된 파일명 저장
                );
              } catch (insertError) {
                console.error('취약점 저장 오류:', insertError);
              }
            }

            // Scanner 완료 처리
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.scannerCompleted = true;
              // 스캔 결과에서 언어 정보 추출하여 저장
              if (scanResult.scan_info && scanResult.scan_info.languages) {
                currentProgress.languages = scanResult.scan_info.languages;
                console.log(`[Scanner] 언어 정보 저장: ${JSON.stringify(scanResult.scan_info.languages)}`);
              }
            }
            
            resolve();
          } catch (error) {
            console.error('결과 파싱 오류:', error);
            if (!res.headersSent) {
            res.status(500).json({
              success: false,
              message: `결과 파싱 실패: ${error.message}`
            });
            }
            reject(error);
          }
        });

        scanProcess.on('error', (error) => {
          clearTimeout(timeout);
          console.error('스캐너 실행 오류:', error);
          console.error('오류 코드:', error.code);
          console.error('오류 메시지:', error.message);
          
          const currentProgress = scanProgress.get(scanId);
          if (currentProgress) {
            currentProgress.scanner = 100;
            currentProgress.scannerCompleted = true;
            // 더 자세한 오류 메시지 제공
            let errorMessage = `스캐너 실행 실패: ${error.message}`;
            if (error.code === 'ENOENT') {
              errorMessage = `Docker를 찾을 수 없습니다. PATH에 docker가 설정되어 있는지 확인해주세요.`;
            }
            currentProgress.scannerError = errorMessage;
            scanProgress.set(scanId, currentProgress);
          }
          
          reject(error);
        });
      });
      
      scanPromises.push(scannerPromise);
      
      // TOOL-VET 분석도 동시에 실행 (GitHub URL이 있는 경우만)
      console.log(`[TOOL-VET] TOOL-VET 실행 조건 확인: github_url="${github_url}", isValidGithubUrl=${github_url ? isValidGithubUrl(github_url) : false}`);
      console.log(`[TOOL-VET] ========== TOOL-VET 분석 시작 ==========`);
      if (github_url && isValidGithubUrl(github_url)) {
        try {
          // TOOL-VET은 항상 새로 분석 실행 (기존 리포트 파일 확인 로직 제거)
          let existingReportFile = null; // 항상 null로 설정하여 새로 스캔하도록 함
          console.log(`[TOOL-VET] 기존 리포트 파일 확인 스킵 - 항상 새로 스캔 실행`);
          
          // 기존 리포트 파일이 있어도 항상 새로 스캔 실행 (주석 처리)
          if (false && existingReportFile) {
            console.log(`기존 TOOL-VET 리포트 파일 사용: ${existingReportFile} (스캔 스킵)`);
            
            // 리포트 파일 처리 함수
            const processReportFile = async (reportFile) => {
              const reportPath = path.join(TOOL_VET_OUTPUT_DIR, reportFile);
              const reportData = JSON.parse(await fs.readFile(reportPath, 'utf-8'));
              
              // MCP 서버 이름 추출
              // 서버 이름 정규화 (일관된 형식으로 변환)
              let mcpServerName = normalizeServerName(github_url, serverName);
              if (reportFile && reportFile.includes('-report.json')) {
                const fileServerName = reportFile.replace('-report.json', '');
                const normalizedFileServerName = normalizeServerName(null, fileServerName);
                if (normalizedFileServerName && normalizedFileServerName !== 'finding') {
                  mcpServerName = normalizedFileServerName;
                }
              }
              console.log(`[TOOL-VET] 정규화된 서버 이름: ${mcpServerName}`);
              
              // 리포트 요약 정보 계산
              let totalTools = 0;
              let totalEndpoints = 0;
              let totalVulns = 0;
              
              if (reportData.tools && Array.isArray(reportData.tools)) {
                totalTools = reportData.tools.length;
                for (const tool of reportData.tools) {
                  if (tool.api_endpoints && Array.isArray(tool.api_endpoints)) {
                    totalEndpoints += tool.api_endpoints.length;
                    for (const endpoint of tool.api_endpoints) {
                      if (endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities)) {
                        totalVulns += endpoint.vulnerabilities.length;
                      }
                    }
                  }
                }
              }
              
              // summary가 있으면 사용
              if (reportData.summary) {
                if (reportData.summary.total_tools !== undefined) {
                  totalTools = reportData.summary.total_tools;
                }
                if (reportData.summary.total_vulnerabilities !== undefined) {
                  totalVulns = reportData.summary.total_vulnerabilities;
                }
              }
              
              // 기존 tool validation 리포트 삭제 (같은 scan_path의 이전 스캔 결과)
              try {
                const deleteReportStmt = db.prepare('DELETE FROM tool_validation_reports WHERE scan_path = ?');
                deleteReportStmt.run(scanPath);
                console.log(`기존 Tool Validation 리포트 삭제 완료: ${scanPath}`);
              } catch (deleteError) {
                console.error('기존 Tool Validation 리포트 삭제 오류:', deleteError);
              }
              
              // 리포트 전체 저장
              const insertReportStmt = db.prepare(`
                INSERT INTO tool_validation_reports (
                  scan_id, scan_path, mcp_server_name, scan_timestamp,
                  report_data, total_tools, total_endpoints, total_vulnerabilities
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              `);
              
              insertReportStmt.run(
                scanId,
                scanPath,
                mcpServerName,
                getKoreaTimeSQLite(),
                JSON.stringify(reportData),
                totalTools,
                totalEndpoints,
                totalVulns
              );
              
              console.log(`Tool Validation 리포트 저장 완료: ${mcpServerName || 'unknown'} (tools: ${totalTools}, endpoints: ${totalEndpoints}, vulnerabilities: ${totalVulns})`);
              
              // 취약점 데이터도 저장
              try {
                if (mcpServerName) {
                  const deleteStmt = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ?');
                  deleteStmt.run(scanPath, mcpServerName);
                  console.log(`기존 Tool Validation 취약점 데이터 삭제 완료: ${scanPath} (서버: ${mcpServerName})`);
                } else {
                const deleteStmt = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_path = ?');
                deleteStmt.run(scanPath);
                  console.log(`기존 Tool Validation 취약점 데이터 삭제 완료: ${scanPath} (서버 이름 없음)`);
                }
                
                if (reportData.tools && Array.isArray(reportData.tools)) {
                  const insertStmt = db.prepare(`
                    INSERT INTO tool_validation_vulnerabilities (
                      scan_id, scan_path, mcp_server_name, scan_timestamp,
                      tool_name, host, method, path,
                      category_code, category_name, title, description, evidence, recommendation, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                  `);
                  
                  let savedVulns = 0;
                  for (const tool of reportData.tools) {
                    const toolName = tool.name || '';
                    
                    if (tool.api_endpoints && Array.isArray(tool.api_endpoints)) {
                      for (const endpoint of tool.api_endpoints) {
                        const host = endpoint.host || '';
                        const method = endpoint.method || '';
                        const path = endpoint.path || '';
                        
                        if (endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities)) {
                          for (const vuln of endpoint.vulnerabilities) {
                            try {
                              insertStmt.run(
                                scanId,
                                scanPath,
                                mcpServerName, // mcp_server_name 추가
                                getKoreaTimeSQLite(),
                                toolName,
                                host,
                                method,
                                path,
                                vuln.category_code || '',
                                vuln.category_name || '',
                                vuln.title || '',
                                vuln.description || '',
                                vuln.evidence || '',
                                vuln.recommendation || '',
                                JSON.stringify(vuln)
                              );
                              savedVulns++;
                            } catch (insertError) {
                              console.error('Tool Validation 취약점 저장 오류:', insertError);
                            }
                          }
                        }
                      }
                    }
                  }
                  
                  console.log(`Tool Validation 취약점 ${savedVulns}개 저장 완료`);
                }
              } catch (vulnError) {
                console.error('Tool Validation 취약점 저장 오류:', vulnError);
              }
            };
            
            // 기존 리포트 파일 처리
            try {
              await processReportFile(existingReportFile);
              
              // 진행률 업데이트
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.toolVet = 100;
                currentProgress.toolVetCompleted = true;
                scanProgress.set(scanId, currentProgress);
              }
              
              console.log('기존 TOOL-VET 리포트 파일 사용 완료 (스캔 스킵)');
            } catch (reportError) {
              console.error('기존 리포트 파일 처리 오류:', reportError);
              // 오류가 발생하면 새로 스캔 실행
              console.log('기존 리포트 파일 처리 실패, 새로 스캔 실행...');
              existingReportFile = null; // 새로 스캔하도록 설정
            }
          }
          
          // 기존 리포트 파일이 없거나 처리 실패한 경우에만 새로 스캔 실행
          console.log(`[TOOL-VET] 기존 리포트 파일 확인 결과: ${existingReportFile ? `발견됨 (${existingReportFile})` : '없음 - 새로 스캔 실행'}`);
          console.log(`[TOOL-VET] ========== 새로 스캔 실행 시작 ==========`);
          console.log(`[TOOL-VET] existingReportFile 값: ${existingReportFile}`);
          console.log(`[TOOL-VET] !existingReportFile 조건: ${!existingReportFile}`);
          if (!existingReportFile) {
            console.log(`[TOOL-VET] ✅ 스캔 실행 블록 진입 성공!`);
            // 호스트의 output 디렉토리 확인 및 생성
            try {
              const fsSync = require('fs');
              const { execSync } = require('child_process');
              
              // 디렉토리가 없으면 생성
              if (!fsSync.existsSync(TOOL_VET_OUTPUT_DIR)) {
                fsSync.mkdirSync(TOOL_VET_OUTPUT_DIR, { recursive: true });
                console.log(`[TOOL-VET] 호스트 output 디렉토리 생성: ${TOOL_VET_OUTPUT_DIR}`);
              }
              
              // 권한 설정 (읽기/쓰기/실행 권한) - chmod 명령으로 확실하게 설정
              // 볼륨 마운트된 디렉토리는 호스트 권한을 따르므로 호스트에서 반드시 설정해야 함
              try {
                // chmod로 권한 설정
                execSync(`chmod -R 777 "${TOOL_VET_OUTPUT_DIR}"`, { stdio: 'ignore' });
                // chown으로 소유권도 설정 (ubuntu 사용자)
                try {
                  execSync(`chown -R ubuntu:ubuntu "${TOOL_VET_OUTPUT_DIR}"`, { stdio: 'ignore' });
                } catch (chownError) {
                  // chown 실패해도 계속 진행 (권한만으로도 충분할 수 있음)
                  console.warn(`[TOOL-VET] chown 실패 (무시): ${chownError.message}`);
                }
                console.log(`[TOOL-VET] 호스트 output 디렉토리 권한 설정 완료 (chmod 777): ${TOOL_VET_OUTPUT_DIR}`);
              } catch (chmodError) {
                // chmod 실패 시 fs.chmodSync 시도
                try {
                  fsSync.chmodSync(TOOL_VET_OUTPUT_DIR, 0o777);
                  console.log(`[TOOL-VET] 호스트 output 디렉토리 권한 설정 완료 (fs.chmodSync): ${TOOL_VET_OUTPUT_DIR}`);
                } catch (fsChmodError) {
                  console.warn(`[TOOL-VET] 호스트 output 디렉토리 권한 설정 실패: ${fsChmodError.message}`);
                }
              }
              
              // 권한 확인 (읽기/쓰기 가능한지)
              await fs.access(TOOL_VET_OUTPUT_DIR, fs.constants.R_OK | fs.constants.W_OK);
              console.log(`[TOOL-VET] 호스트 output 디렉토리 권한 확인 완료`);
            } catch (dirError) {
              console.error(`[TOOL-VET] output 디렉토리 확인/생성 실패: ${dirError.message}`);
              // 디렉토리 문제가 있어도 계속 진행 (컨테이너 내부에서 생성 시도)
            }
            
            // 컨테이너 내부의 output 디렉토리 생성 및 권한 설정
            try {
              // 먼저 디렉토리 존재 여부 확인
              const checkArgs = ['exec', TOOL_VET_CONTAINER_NAME, 'test', '-d', '/app/output'];
              const checkProcess = spawn('docker', checkArgs, { cwd: TOOL_VET_ROOT });
              let dirExists = false;
              await new Promise((resolve) => {
                checkProcess.on('close', (code) => {
                  dirExists = code === 0;
                  resolve();
                });
                checkProcess.on('error', () => resolve());
              });
              
              if (!dirExists) {
                // 컨테이너 내부에서 디렉토리 생성
                const mkdirOutputArgs = ['exec', TOOL_VET_CONTAINER_NAME, 'mkdir', '-p', '/app/output'];
                const mkdirOutputProcess = spawn('docker', mkdirOutputArgs, { cwd: TOOL_VET_ROOT });
                await new Promise((resolve) => {
                  mkdirOutputProcess.on('close', () => resolve());
                  mkdirOutputProcess.on('error', () => resolve());
                });
                console.log(`[TOOL-VET] 컨테이너 내부 output 디렉토리 생성 완료`);
              }
              
              // 호스트에서도 디렉토리 확인 및 생성 (볼륨 마운트를 위해)
              const fsSync = require('fs');
              if (!fsSync.existsSync(TOOL_VET_OUTPUT_DIR)) {
                fsSync.mkdirSync(TOOL_VET_OUTPUT_DIR, { recursive: true });
                console.log(`[TOOL-VET] 호스트 output 디렉토리 재생성: ${TOOL_VET_OUTPUT_DIR}`);
              }
              
              // 권한 설정 시도 (root 권한으로 실행하여 볼륨 마운트된 디렉토리도 권한 변경 가능)
              // 볼륨 마운트된 디렉토리는 호스트에서 권한을 설정해야 하므로, 호스트에서도 다시 시도
              const chmodArgs = ['exec', '-u', 'root', TOOL_VET_CONTAINER_NAME, 'bash', '-c', 'chmod -R 777 /app/output && chown -R appuser:appuser /app/output 2>/dev/null || true'];
              const chmodProcess = spawn('docker', chmodArgs, { cwd: TOOL_VET_ROOT });
              let chmodSuccess = false;
              await new Promise((resolve) => {
                chmodProcess.on('close', (code) => {
                  chmodSuccess = code === 0;
                  resolve();
                });
                chmodProcess.on('error', () => resolve());
              });
              
              // 호스트에서도 다시 권한 설정 시도 (볼륨 마운트된 디렉토리는 호스트 권한을 따름)
              try {
                const { execSync } = require('child_process');
                execSync(`chmod -R 777 "${TOOL_VET_OUTPUT_DIR}"`, { stdio: 'ignore' });
                console.log(`[TOOL-VET] 호스트 output 디렉토리 권한 재설정 완료: ${TOOL_VET_OUTPUT_DIR}`);
              } catch (hostChmodError) {
                console.warn(`[TOOL-VET] 호스트 output 디렉토리 권한 재설정 실패: ${hostChmodError.message}`);
              }
              
              if (chmodSuccess) {
                console.log(`[TOOL-VET] 컨테이너 내부 output 디렉토리 권한 설정 완료`);
              } else {
                console.log(`[TOOL-VET] 컨테이너 내부 output 디렉토리 권한 설정 실패 (볼륨 마운트로 인한 제한일 수 있음, 호스트에서 설정 완료)`);
              }
            } catch (containerDirError) {
              console.error(`[TOOL-VET] 컨테이너 내부 output 디렉토리 설정 중 오류: ${containerDirError.message}`);
              // 오류가 발생해도 계속 진행
            }
            
            // TOOL-VET 컨테이너가 실행 중인지 확인
            try {
              const checkToolVetProcess = spawn('docker', [
                'ps',
                '--filter',
                `name=${TOOL_VET_CONTAINER_NAME}`,
                '--format',
                '{{.Names}}'
              ], {
                cwd: TOOL_VET_ROOT
              });
              
              let toolVetStdout = '';
              let toolVetStderr = '';
              
              checkToolVetProcess.stdout.on('data', (data) => {
                toolVetStdout += data.toString();
              });
              
              checkToolVetProcess.stderr.on('data', (data) => {
                toolVetStderr += data.toString();
              });
              
              await new Promise((resolve, reject) => {
                checkToolVetProcess.on('close', (code) => {
                  if (code !== 0) {
                    reject(new Error(`Docker 명령 실행 실패: ${toolVetStderr || '알 수 없는 오류'}`));
                  } else {
                    resolve();
                  }
                });
                
                checkToolVetProcess.on('error', (error) => {
                  reject(error);
                });
              });
              
              if (!toolVetStdout.trim()) {
                throw new Error(`Docker 컨테이너가 실행 중이 아닙니다: ${TOOL_VET_CONTAINER_NAME}. 컨테이너를 먼저 시작해주세요.`);
              }
            } catch (error) {
              console.error(`TOOL-VET 컨테이너 확인 실패: ${error.message}`);
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.toolVet = 100;
                currentProgress.toolVetCompleted = true;
                currentProgress.toolVetError = `TOOL-VET 시작 실패: TOOL-VET 컨테이너가 실행 중이 아닙니다: ${TOOL_VET_CONTAINER_NAME}. 컨테이너를 먼저 시작해주세요.`;
                scanProgress.set(scanId, currentProgress);
              }
              // 컨테이너가 없어도 계속 진행 (오류만 기록)
            }
          
          // MCP 서버 이름으로 API 키 조회 및 .env 파일 생성
          // mcp_server_name이 없으면 github_url에서 추출 시도
          let targetServerName = mcp_server_name;
          if (!targetServerName && github_url) {
            // GitHub URL에서 서버 이름 추출 (예: https://github.com/owner/repo -> repo)
            const urlParts = github_url.split('/');
            if (urlParts.length > 0) {
              targetServerName = urlParts[urlParts.length - 1].replace('.git', '');
            }
          }
          
          console.log(`[TOOL-VET] MCP 서버 이름: ${targetServerName || '(없음)'}`);
          console.log(`[TOOL-VET] 사용자 ID: ${req.user ? req.user.id : '(없음)'}`);
          
          let envFilePath = null;
          if (targetServerName && req.user && req.user.id) {
            try {
              const fs = require('fs');
              const path = require('path');
              let envContent = '';
              
              // api_keys 테이블 존재 여부 확인
              const apiKeysTableExists = db.prepare(`
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='api_keys'
              `).get();
              
              let apiKeys = [];
              if (apiKeysTableExists) {
                // 1. 정확히 일치하는 서버 이름으로 API 키 조회
                try {
                  apiKeys = db.prepare(`
                    SELECT field_name, field_value, mcp_server_name
                    FROM api_keys 
                    WHERE user_id = ? AND mcp_server_name = ?
                  `).all(req.user.id, targetServerName);
                } catch (queryError) {
                  console.error(`[TOOL-VET] API 키 조회 오류: ${queryError.message}`);
                  apiKeys = [];
                }
              } else {
                console.log(`[TOOL-VET] api_keys 테이블이 존재하지 않습니다. API 키 조회를 건너뜁니다.`);
              }
              
              console.log(`[TOOL-VET] MCP 서버 "${targetServerName}"에 대한 API 키 조회 (정확 일치)`);
              console.log(`[TOOL-VET] 조회된 API 키 개수: ${apiKeys ? apiKeys.length : 0}`);
              
              // 2. 정확히 일치하지 않으면 부분 일치로 찾기 (서버 이름에 포함되거나 포함하는 경우)
              if (apiKeysTableExists && (!apiKeys || apiKeys.length === 0)) {
                try {
                  const allUserApiKeys = db.prepare(`
                    SELECT field_name, field_value, mcp_server_name
                    FROM api_keys 
                    WHERE user_id = ?
                  `).all(req.user.id);
                
                  // 서버 이름 부분 일치 검색 (대소문자 무시)
                  const lowerTargetName = targetServerName.toLowerCase();
                  apiKeys = allUserApiKeys.filter(key => {
                    const lowerKeyName = key.mcp_server_name.toLowerCase();
                    return lowerKeyName === lowerTargetName || 
                           lowerKeyName.includes(lowerTargetName) || 
                           lowerTargetName.includes(lowerKeyName);
                  });
                  
                  console.log(`[TOOL-VET] 부분 일치 검색 결과: ${apiKeys.length}개 발견`);
                  if (apiKeys.length > 0) {
                    console.log(`[TOOL-VET] 매칭된 서버 이름: ${apiKeys.map(k => k.mcp_server_name).join(', ')}`);
                  }
                } catch (partialMatchError) {
                  console.error(`[TOOL-VET] 부분 일치 검색 오류: ${partialMatchError.message}`);
                  apiKeys = [];
                }
              }
              
              if (apiKeys && apiKeys.length > 0) {
                console.log(`[TOOL-VET] API 키 필드명: ${apiKeys.map(k => `${k.mcp_server_name}:${k.field_name}`).join(', ')}`);
                
                // .env 파일 내용 생성 (Settings에서 등록한 API 키 - 사용자가 입력한 필드명과 필드값 그대로 사용)
                envContent = apiKeys.map(key => 
                  `${key.field_name}=${key.field_value}`
                ).join('\n');
              } else {
                console.log(`[TOOL-VET] MCP 서버 "${targetServerName}"에 대한 API 키가 등록되지 않았습니다.`);
                console.log(`[TOOL-VET] Server Request의 토큰을 확인합니다.`);
                
                // mcp_register_requests에서 auth_tokens 또는 auth_field_name/auth_field_value 조회
                try {
                  const registerRequest = db.prepare(`
                    SELECT auth_tokens, auth_field_name, auth_field_value, auth_token
                    FROM mcp_register_requests
                    WHERE name = ? AND (auth_tokens IS NOT NULL OR auth_field_name IS NOT NULL OR auth_token IS NOT NULL)
                    ORDER BY created_at DESC
                    LIMIT 1
                  `).get(targetServerName);
                  
                  if (registerRequest) {
                    // auth_tokens JSON이 있으면 우선 사용 (여러 개의 토큰)
                    if (registerRequest.auth_tokens) {
                      try {
                        const tokens = JSON.parse(registerRequest.auth_tokens);
                        if (Array.isArray(tokens) && tokens.length > 0) {
                          envContent = tokens
                            .filter(token => token.field_name && token.field_value)
                            .map(token => `${token.field_name}=${token.field_value}`)
                            .join('\n');
                          console.log(`[TOOL-VET] Server Request의 토큰 사용 (${tokens.length}개): ${tokens.map(t => t.field_name).join(', ')}`);
                        }
                      } catch (parseError) {
                        console.error('[TOOL-VET] auth_tokens JSON 파싱 오류:', parseError);
                      }
                    }
                    
                    // auth_tokens가 없고 auth_field_name과 auth_field_value가 있으면 사용
                    if (!envContent && registerRequest.auth_field_name && registerRequest.auth_field_value) {
                      envContent = `${registerRequest.auth_field_name}=${registerRequest.auth_field_value}`;
                      console.log(`[TOOL-VET] Server Request의 토큰 사용: ${registerRequest.auth_field_name}=***`);
                    } 
                    // 하위 호환성: auth_token이 있으면 사용 (필드명은 기본값 사용)
                    else if (!envContent && registerRequest.auth_token) {
                      // auth_token만 있고 필드명이 없으면 기본 필드명 사용
                      const defaultFieldName = 'AUTH_TOKEN'; // 또는 서버 이름 기반으로 추론
                      envContent = `${defaultFieldName}=${registerRequest.auth_token}`;
                      console.log(`[TOOL-VET] Server Request의 auth_token 사용 (기본 필드명: ${defaultFieldName})`);
                    }
                  } else {
                    console.log(`[TOOL-VET] Server Request에도 토큰이 등록되지 않았습니다.`);
                    // 모든 API 키 조회 (디버깅용) - 테이블이 존재하는 경우에만
                    if (apiKeysTableExists) {
                      try {
                        const allApiKeys = db.prepare(`
                          SELECT mcp_server_name, field_name 
                          FROM api_keys 
                          WHERE user_id = ?
                        `).all(req.user.id);
                        console.log(`[TOOL-VET] 사용자의 전체 API 키 목록:`, allApiKeys.map(k => `${k.mcp_server_name}: ${k.field_name}`).join(', '));
                      } catch (allKeysError) {
                        console.error(`[TOOL-VET] 전체 API 키 조회 오류: ${allKeysError.message}`);
                      }
                    }
                  }
                } catch (requestError) {
                  console.error('[TOOL-VET] Server Request 토큰 조회 오류:', requestError);
                }
              }
              
              // envContent가 있으면 .env 파일 생성
              if (envContent) {
                const tempDir = path.join(TOOL_VET_ROOT, 'temp_env');
                
                // temp_env 디렉토리가 없으면 생성
                if (!fs.existsSync(tempDir)) {
                  fs.mkdirSync(tempDir, { recursive: true });
                }
                
                // 고유한 파일명 생성 (scanId 사용)
                envFilePath = path.join(tempDir, `${scanId}.env`);
                
                fs.writeFileSync(envFilePath, envContent, 'utf-8');
                const envLines = envContent.split('\n').length;
                console.log(`[TOOL-VET] API 키 .env 파일 생성: ${envFilePath} (${envLines}개 키)`);
                console.log(`[TOOL-VET] .env 파일 내용 (마스킹): ${envContent.split('\n').map(line => {
                  const [key] = line.split('=');
                  return key ? `${key}=***` : line;
                }).join('\n')}`);
              }
            } catch (envError) {
              console.error('[TOOL-VET] API 키 .env 파일 생성 오류:', envError);
              // 오류가 발생해도 TOOL-VET 실행은 계속 진행
            }
          } else {
            console.log(`[TOOL-VET] API 키 조회 조건 불만족: targetServerName=${targetServerName}, userId=${req.user ? req.user.id : '없음'}`);
          }
          
          // execution_args 조회 (mcp_register_requests에서)
          let executionArgs = null;
          if (targetServerName) {
            try {
              const registerRequest = db.prepare(`
                SELECT execution_args
                FROM mcp_register_requests
                WHERE name = ? AND execution_args IS NOT NULL AND execution_args != ''
                ORDER BY created_at DESC
                LIMIT 1
              `).get(targetServerName);
              
              if (registerRequest && registerRequest.execution_args) {
                executionArgs = registerRequest.execution_args;
                console.log(`[TOOL-VET] Server Request의 실행 인자 발견: ${executionArgs}`);
              }
            } catch (execArgsError) {
              console.error('[TOOL-VET] 실행 인자 조회 오류:', execArgsError);
            }
          }
          
          // docker exec로 실행
          console.log(`[TOOL-VET] TOOL-VET 실행 준비: github_url="${github_url}"`);
          const toolVetArgs = [
            'exec',
            TOOL_VET_CONTAINER_NAME,
            'python',
            'main.py',
            '--git-url',
            github_url,
            '--output-dir',
            '/app/output'
          ];
          
          // execution_args가 있으면 --server-args 옵션 추가
          // executionArgs는 이미 전체 문자열이므로 그대로 전달 (예: "--toolsets all")
          if (executionArgs) {
            toolVetArgs.push('--server-args', executionArgs.trim());
            console.log(`[TOOL-VET] TOOL-VET 실행 인자에 서버 인자 추가: --server-args "${executionArgs.trim()}"`);
          }
          
          console.log(`[TOOL-VET] TOOL-VET 실행 인자 구성 완료: --git-url ${github_url}`);
          
          // .env 파일이 있으면 --env-file 옵션 추가
          if (envFilePath) {
            // Docker 컨테이너 내부 경로로 변환
            // TOOL-VET 컨테이너의 작업 디렉토리는 /app이므로 상대 경로 사용
            // 또는 볼륨 마운트를 통해 전달 (docker-compose.yml에서 설정 필요)
            const containerEnvPath = `/app/temp_env/${path.basename(envFilePath)}`;
            
            // Docker cp를 사용하여 파일을 컨테이너에 복사
            try {
              // 먼저 temp_env 디렉토리가 존재하는지 확인하고 없으면 생성
              const mkdirArgs = ['exec', TOOL_VET_CONTAINER_NAME, 'mkdir', '-p', '/app/temp_env'];
              const mkdirProcess = spawn('docker', mkdirArgs, { cwd: TOOL_VET_ROOT });
              await new Promise((resolve) => {
                mkdirProcess.on('close', () => resolve());
                mkdirProcess.on('error', () => resolve()); // 오류 무시
              });
              
              console.log(`[TOOL-VET] .env 파일 복사 시작: ${envFilePath} -> ${TOOL_VET_CONTAINER_NAME}:${containerEnvPath}`);
              const copyArgs = ['cp', envFilePath, `${TOOL_VET_CONTAINER_NAME}:${containerEnvPath}`];
              console.log(`[TOOL-VET] docker 명령: docker ${copyArgs.join(' ')}`);
              const copyProcess = spawn('docker', copyArgs, { cwd: TOOL_VET_ROOT });
              
              await new Promise((resolve, reject) => {
                let copyStdout = '';
                let copyStderr = '';
                
                copyProcess.stdout.on('data', (data) => {
                  copyStdout += data.toString();
                  console.log(`[TOOL-VET] docker cp stdout: ${data.toString().trim()}`);
                });
                
                copyProcess.stderr.on('data', (data) => {
                  copyStderr += data.toString();
                  console.error(`[TOOL-VET] docker cp stderr: ${data.toString().trim()}`);
                });
                
                copyProcess.on('close', (code) => {
                  if (code === 0) {
                    console.log(`[TOOL-VET] .env 파일을 컨테이너에 복사 완료: ${containerEnvPath}`);
                    // 복사 후 파일이 실제로 존재하는지 확인
                    const checkArgs = ['exec', TOOL_VET_CONTAINER_NAME, 'test', '-f', containerEnvPath];
                    const checkProcess = spawn('docker', checkArgs, { cwd: TOOL_VET_ROOT });
                    checkProcess.on('close', (checkCode) => {
                      if (checkCode === 0) {
                        console.log(`[TOOL-VET] .env 파일 존재 확인: ${containerEnvPath}`);
                      } else {
                        console.error(`[TOOL-VET] .env 파일 존재 확인 실패: ${containerEnvPath}`);
                      }
                      resolve();
                    });
                    checkProcess.on('error', (checkError) => {
                      console.error(`[TOOL-VET] .env 파일 확인 오류: ${checkError.message}`);
                      resolve();
                    });
                  } else {
                    console.error(`[TOOL-VET] .env 파일 복사 실패 (종료 코드: ${code}): ${copyStderr || '알 수 없는 오류'}`);
                    resolve(); // 실패해도 계속 진행
                  }
                });
                
                copyProcess.on('error', (error) => {
                  console.error(`[TOOL-VET] .env 파일 복사 오류: ${error.message}`);
                  resolve(); // 오류가 발생해도 계속 진행
                });
              });
            } catch (copyError) {
              console.error(`[TOOL-VET] .env 파일 복사 중 예외: ${copyError.message}`);
            }
            
            toolVetArgs.push('--env-file', containerEnvPath);
            console.log(`[TOOL-VET] TOOL-VET 실행 인자에 .env 파일 추가: --env-file ${containerEnvPath}`);
          }
          
          // repo_name 추출 함수 (TOOL-VET의 extract_repo_name과 동일한 로직)
          const extractRepoNameFromUrl = (gitUrl) => {
            if (!gitUrl) return null;
            let url = gitUrl.replace(/\/$/, '');
            if (url.endsWith('.git')) {
              url = url.slice(0, -4);
            }
            const parts = url.split('/');
            return parts[parts.length - 1];
          };
          
          // expectedRepoName 추출: github_url 우선, 없으면 serverName, 없으면 scan_path에서 추출
          let expectedRepoName = null;
          if (github_url && isValidGithubUrl(github_url)) {
            expectedRepoName = extractRepoNameFromUrl(github_url);
          } else if (serverName) {
            // GitHub URL이 아닌 경우 serverName 사용
            expectedRepoName = serverName;
          } else if (scanPath) {
            // scan_path에서 추출
            if (isValidGithubUrl(scanPath)) {
              expectedRepoName = extractRepoNameFromUrl(scanPath);
            } else {
              // GitHub URL이 아닌 경우 scan_path 자체 사용
              expectedRepoName = scanPath.replace(/\.git$/, '');
            }
          }
          
          const expectedReportFile = expectedRepoName ? `${expectedRepoName}-report.json` : 'unknown-report.json';
          
          console.log(`[TOOL-VET] 실행 명령: docker ${toolVetArgs.join(' ')}`);
          console.log(`[TOOL-VET] 분석 대상 GitHub URL: ${github_url}`);
          console.log(`[TOOL-VET] 분석 대상 서버 이름: ${serverName}`);
          console.log(`[TOOL-VET] 분석 대상 scan_path: ${scanPath}`);
          console.log(`[TOOL-VET] 추출된 repo_name: ${expectedRepoName}`);
          console.log(`[TOOL-VET] 예상 리포트 파일: ${expectedReportFile}`);
          
          const toolVetPromise = new Promise((resolve, reject) => {
            console.log(`[TOOL-VET] ========== TOOL-VET 프로세스 시작 ==========`);
            console.log(`[TOOL-VET] 최종 실행 명령어: docker ${toolVetArgs.join(' ')}`);
            console.log(`[TOOL-VET] 작업 디렉토리: ${TOOL_VET_ROOT}`);
            console.log(`[TOOL-VET] 컨테이너 이름: ${TOOL_VET_CONTAINER_NAME}`);
            
            const toolVetProcess = spawn('docker', toolVetArgs, { 
              cwd: TOOL_VET_ROOT,
              stdio: ['ignore', 'pipe', 'pipe'] // stdin은 무시, stdout/stderr는 파이프
            });
            
            console.log(`[TOOL-VET] 프로세스 시작됨 (PID: ${toolVetProcess.pid})`);
            
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.toolVet = 1; // 시작됨을 표시
              scanProgress.set(scanId, currentProgress);
            }
            
            let toolVetStdout = '';
            let toolVetStderr = '';
            let stdoutBuffer = '';
            let stderrBuffer = '';
            
            toolVetProcess.stdout.on('data', (data) => {
              const output = data.toString();
              toolVetStdout += output;
              stdoutBuffer += output;
              
              // 줄 단위로 출력
              const lines = stdoutBuffer.split('\n');
              stdoutBuffer = lines.pop() || ''; // 마지막 불완전한 줄은 버퍼에 보관
              
              for (const line of lines) {
                if (line.trim()) {
                  console.log(`[TOOL-VET] stdout: ${line}`);
                  
                  // 진행률 파싱 시도 (예: "진행: 10/14" 또는 "10%")
                  const progressMatch = line.match(/진행:\s*(\d+)\/(\d+)/) || line.match(/(\d+)%/);
                  if (progressMatch) {
                    let progress;
                    if (progressMatch[2]) {
                      // "진행: 10/14" 형식
                      const current = parseInt(progressMatch[1]);
                      const total = parseInt(progressMatch[2]);
                      progress = Math.floor((current / total) * 100);
                    } else {
                      // "10%" 형식
                      progress = parseInt(progressMatch[1]);
                    }
                    const currentProgress = scanProgress.get(scanId);
                    if (currentProgress && !currentProgress.toolVetCompleted && progress > currentProgress.toolVet) {
                      currentProgress.toolVet = Math.min(progress, 99);
                      scanProgress.set(scanId, currentProgress);
                    }
                  }
                }
              }
            });
            
            toolVetProcess.stderr.on('data', (data) => {
              const output = data.toString();
              toolVetStderr += output;
              stderrBuffer += output;
              
              // 줄 단위로 출력
              const lines = stderrBuffer.split('\n');
              stderrBuffer = lines.pop() || ''; // 마지막 불완전한 줄은 버퍼에 보관
              
              for (const line of lines) {
                if (line.trim()) {
                  console.error(`[TOOL-VET] stderr: ${line}`);
                }
              }
            });
            
            toolVetProcess.on('error', (error) => {
              console.error(`[TOOL-VET] 프로세스 오류: ${error.message}`);
              console.error(`[TOOL-VET] 오류 스택: ${error.stack}`);
              reject(error);
            });
            
            let toolVetStartTime = Date.now();
            const toolVetEstimatedDuration = 300000; // 5분 예상
            
            // 시간 기반 진행률 업데이트를 위한 인터벌 설정
            const toolVetProgressInterval = setInterval(() => {
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress && currentProgress.toolVet !== null && currentProgress.toolVet < 100 && !currentProgress.toolVetCompleted) {
                const elapsed = Date.now() - toolVetStartTime;
                const estimatedProgress = Math.min(Math.floor((elapsed / toolVetEstimatedDuration) * 100), 99);
                if (estimatedProgress > currentProgress.toolVet) {
                  currentProgress.toolVet = estimatedProgress;
                  scanProgress.set(scanId, currentProgress);
                }
              }
            }, 2000); // 2초마다 업데이트
            
            // 진행률 파싱은 위의 stdout 핸들러에서 처리됨 (1547줄)
            
            toolVetProcess.on('close', async (code) => {
              clearInterval(toolVetProgressInterval);
              
              console.log(`[TOOL-VET] 프로세스 종료됨 (종료 코드: ${code})`);
              console.log(`[TOOL-VET] stdout 총 길이: ${toolVetStdout.length} bytes`);
              console.log(`[TOOL-VET] stderr 총 길이: ${toolVetStderr.length} bytes`);
              
              // 마지막 버퍼 출력
              if (stdoutBuffer.trim()) {
                console.log(`[TOOL-VET] stdout (마지막): ${stdoutBuffer.trim()}`);
              }
              if (stderrBuffer.trim()) {
                console.error(`[TOOL-VET] stderr (마지막): ${stderrBuffer.trim()}`);
              }
              
              // .env 파일 정리 (분석 완료 후 삭제)
              if (envFilePath) {
                try {
                  const fsSync = require('fs');
                  if (fsSync.existsSync(envFilePath)) {
                    fsSync.unlinkSync(envFilePath);
                    console.log(`임시 .env 파일 삭제: ${envFilePath}`);
                  }
                  
                  // 컨테이너 내부 파일도 삭제 시도
                  const containerEnvPath = `/app/temp_env/${path.basename(envFilePath)}`;
                  const rmArgs = ['exec', TOOL_VET_CONTAINER_NAME, 'rm', '-f', containerEnvPath];
                  const rmProcess = spawn('docker', rmArgs, { cwd: TOOL_VET_ROOT });
                  rmProcess.on('close', () => {
                    // 삭제 실패해도 무시
                  });
                } catch (cleanupError) {
                  console.warn(`.env 파일 정리 오류 (무시): ${cleanupError.message}`);
                }
              }
              
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.toolVet = 100;
                currentProgress.toolVetCompleted = true;
                scanProgress.set(scanId, currentProgress);
              }
              
              if (code === 0) {
                console.log('TOOL-VET 분석 완료');
                
                // TOOL-VET 결과 파일 파싱 및 저장
                try {
                  // report.json 파일 찾기
                  const reportFiles = await fs.readdir(TOOL_VET_OUTPUT_DIR);
                  
                  // 정확한 리포트 파일 찾기: scan_path나 mcp_server_name 기반
                  let reportFile = null;
                  
                  // 1. expectedRepoName 기반으로 정확히 매칭되는 파일 찾기
                  if (expectedRepoName) {
                    const expectedReportFile = `${expectedRepoName}-report.json`;
                    if (reportFiles.includes(expectedReportFile)) {
                      reportFile = expectedReportFile;
                      console.log(`[TOOL-VET] 예상 리포트 파일 발견: ${reportFile}`);
                    }
                  }
                  
                  // 2. serverName 기반으로 찾기 (GitHub URL이 아닌 경우)
                  if (!reportFile && serverName) {
                    const serverReportFile = `${serverName}-report.json`;
                    if (reportFiles.includes(serverReportFile)) {
                      reportFile = serverReportFile;
                      console.log(`[TOOL-VET] 서버 이름 기반 리포트 파일 발견: ${reportFile}`);
                    }
                  }
                  
                  // 3. scan_path에서 추출한 이름으로 찾기
                  if (!reportFile && scanPath) {
                    let scanPathName = scanPath;
                    if (isValidGithubUrl(scanPath)) {
                      // GitHub URL인 경우 repo 이름 추출
                      const urlParts = scanPath.split('/');
                      scanPathName = urlParts[urlParts.length - 1].replace('.git', '');
                    }
                    const scanPathReportFile = `${scanPathName}-report.json`;
                    if (reportFiles.includes(scanPathReportFile)) {
                      reportFile = scanPathReportFile;
                      console.log(`[TOOL-VET] scan_path 기반 리포트 파일 발견: ${reportFile}`);
                    }
                  }
                  
                  // 4. 최신 파일 사용 (fallback)
                  if (!reportFile) {
                    const reportJsonFiles = reportFiles.filter(f => f.endsWith('-report.json'));
                    if (reportJsonFiles.length > 0) {
                      // 수정 시간순으로 정렬하여 최신 파일 선택
                      const reportFilesWithStats = [];
                      for (const file of reportJsonFiles) {
                        const filePath = path.join(TOOL_VET_OUTPUT_DIR, file);
                        try {
                          const stats = await fs.stat(filePath);
                          if (stats.size > 0) {
                            reportFilesWithStats.push({ file, mtime: stats.mtime });
                          }
                        } catch (fileError) {
                          // 파일 접근 실패, 무시
                        }
                      }
                      if (reportFilesWithStats.length > 0) {
                        reportFilesWithStats.sort((a, b) => b.mtime - a.mtime);
                        reportFile = reportFilesWithStats[0].file;
                        console.log(`[TOOL-VET] 최신 리포트 파일 사용 (fallback): ${reportFile}`);
                      }
                    }
                  }
                  
                  // 5. 마지막 fallback: report.json으로 끝나는 파일 찾기
                  if (!reportFile) {
                    reportFile = reportFiles.find(f => f === 'report.json' || f.endsWith('report.json'));
                  }
                  
                  if (reportFile) {
                    const reportPath = path.join(TOOL_VET_OUTPUT_DIR, reportFile);
                    console.log(`TOOL-VET 리포트 파일 경로: ${reportPath}`);
                    const reportData = JSON.parse(await fs.readFile(reportPath, 'utf-8'));
                    
                    console.log(`TOOL-VET 리포트 파일 발견: ${reportFile}`);
                    
                    // MCP 서버 이름 추출 (reportFile에서 추출: {server-name}-report.json)
                    // 서버 이름 정규화 (일관된 형식으로 변환)
                    // 우선순위: mcp_server_name > serverName > github_url > reportFile
                    let mcpServerName = null;
                    if (mcp_server_name) {
                      mcpServerName = normalizeServerName(null, mcp_server_name);
                    } else if (serverName) {
                      mcpServerName = normalizeServerName(github_url, serverName);
                    } else if (github_url) {
                      mcpServerName = normalizeServerName(github_url, null);
                    } else if (reportFile && reportFile.includes('-report.json')) {
                      const fileServerName = reportFile.replace('-report.json', '');
                      mcpServerName = normalizeServerName(null, fileServerName);
                    }
                    
                    console.log(`[TOOL-VET] 정규화된 서버 이름: ${mcpServerName} (원본: mcp_server_name=${mcp_server_name}, serverName=${serverName}, github_url=${github_url})`);
                    
                    // 리포트 요약 정보 계산
                    let totalTools = 0;
                    let totalEndpoints = 0;
                    let totalVulns = 0;
                    
                    if (reportData.tools && Array.isArray(reportData.tools)) {
                      totalTools = reportData.tools.length;
                      for (const tool of reportData.tools) {
                        // tool-level vulnerabilities 카운트
                        if (tool.vulnerabilities && Array.isArray(tool.vulnerabilities)) {
                          totalVulns += tool.vulnerabilities.length;
                        }
                        
                        if (tool.api_endpoints && Array.isArray(tool.api_endpoints)) {
                          totalEndpoints += tool.api_endpoints.length;
                          for (const endpoint of tool.api_endpoints) {
                            if (endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities)) {
                              totalVulns += endpoint.vulnerabilities.length;
                            }
                          }
                        }
                      }
                    }
                    
                    // global_vulnerabilities 카운트
                    if (reportData.global_vulnerabilities && Array.isArray(reportData.global_vulnerabilities)) {
                      totalVulns += reportData.global_vulnerabilities.length;
                    }
                    
                    // summary가 있으면 사용 (더 정확할 수 있음)
                    if (reportData.summary) {
                      if (reportData.summary.total_tools !== undefined) {
                        totalTools = reportData.summary.total_tools;
                      }
                      if (reportData.summary.total_vulnerabilities !== undefined) {
                        totalVulns = reportData.summary.total_vulnerabilities;
                      }
                    }
                    
                    console.log(`[TOOL-VET] 리포트 요약 계산: tools=${totalTools}, endpoints=${totalEndpoints}, vulnerabilities=${totalVulns} (global: ${reportData.global_vulnerabilities?.length || 0}, tool-level: ${reportData.tools?.reduce((sum, t) => sum + (t.vulnerabilities?.length || 0), 0) || 0})`);
                    
                    // scan_path 정규화 (리포트 삭제용)
                    let normalizedScanPathForReportDelete = scanPath;
                    if (scanPath && isValidGithubUrl(scanPath)) {
                      normalizedScanPathForReportDelete = scanPath.replace(/\.git$/i, '').toLowerCase();
                    }
                    
                    // 기존 tool validation 리포트 삭제 (같은 scan_path의 이전 스캔 결과)
                    try {
                      // 정규화된 scan_path로 삭제 (원본과 정규화된 값 모두 삭제)
                      const deleteReportStmt1 = db.prepare('DELETE FROM tool_validation_reports WHERE scan_path = ? OR scan_path = ?');
                      deleteReportStmt1.run(scanPath, normalizedScanPathForReportDelete);
                      console.log(`[TOOL-VET] 기존 Tool Validation 리포트 삭제 완료: ${scanPath} / ${normalizedScanPathForReportDelete}`);
                    } catch (deleteError) {
                      console.error('[TOOL-VET] 기존 Tool Validation 리포트 삭제 오류:', deleteError);
                    }
                    
                    // 리포트 전체 저장
                    try {
                      const insertReportStmt = db.prepare(`
                        INSERT INTO tool_validation_reports (
                          scan_id, scan_path, mcp_server_name, scan_timestamp,
                          report_data, total_tools, total_endpoints, total_vulnerabilities
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                      `);
                      
                      insertReportStmt.run(
                        scanId,
                        scanPath,
                        mcpServerName,
                        getKoreaTimeSQLite(),
                        JSON.stringify(reportData),
                        totalTools,
                        totalEndpoints,
                        totalVulns
                      );
                      
                      console.log(`Tool Validation 리포트 저장 완료: ${mcpServerName || 'unknown'} (tools: ${totalTools}, endpoints: ${totalEndpoints}, vulnerabilities: ${totalVulns})`);
                    } catch (reportInsertError) {
                      console.error('Tool Validation 리포트 저장 오류:', reportInsertError);
                    }
                    
                    // ========== 서버 이름 결정 (tools 저장과 취약점 저장 모두에서 사용) ==========
                        // 서버 이름 결정: 사용자가 등록 요청 시 입력한 이름을 우선 사용
                        // 1순위: req.body에서 받은 mcp_server_name (사용자가 입력한 이름)
                        // 2순위: scan_path로 mcp_register_requests 테이블에서 조회
                    // 모든 서버 이름은 정규화하여 일관된 형식으로 저장
                    let finalServerName = mcp_server_name ? normalizeServerName(null, mcp_server_name) : null;
                        
                        // mcp_server_name이 없으면 scan_path로 mcp_register_requests에서 조회
                        if (!finalServerName && scanPath) {
                          if (isValidGithubUrl(scanPath)) {
                            // GitHub URL인 경우 mcp_register_requests에서 name 찾기
                            const request = db.prepare(`
                              SELECT name FROM mcp_register_requests 
                              WHERE github_link = ? AND status IN ('pending', 'approved')
                              ORDER BY created_at DESC
                              LIMIT 1
                            `).get(scanPath);
                            
                            if (request) {
                              finalServerName = request.name;
                              console.log(`[TOOL-VET] mcp_register_requests에서 서버 이름 찾음 (GitHub URL): ${finalServerName}`);
                            }
                          } else {
                            // 파일 경로인 경우 mcp_register_requests에서 name 찾기
                            const request = db.prepare(`
                              SELECT name FROM mcp_register_requests 
                              WHERE file_path = ? AND status IN ('pending', 'approved')
                              ORDER BY created_at DESC
                              LIMIT 1
                            `).get(scanPath);
                            
                            if (request) {
                          finalServerName = normalizeServerName(null, request.name);
                              console.log(`[TOOL-VET] mcp_register_requests에서 서버 이름 찾음 (파일 경로): ${finalServerName}`);
                            }
                          }
                        }
                        
                        // 여전히 없으면 scan_id로 조회 시도
                        if (!finalServerName && scanId) {
                          const scanRecord = db.prepare(`
                            SELECT mcp_server_name FROM tool_validation_reports 
                            WHERE scan_id = ?
                            LIMIT 1
                          `).get(scanId);
                          
                          if (scanRecord && scanRecord.mcp_server_name) {
                        finalServerName = normalizeServerName(null, scanRecord.mcp_server_name);
                            console.log(`[TOOL-VET] tool_validation_reports에서 서버 이름 찾음: ${finalServerName}`);
                          }
                        }
                        
                    // 여전히 없으면 mcpServerName 사용
                        if (!finalServerName) {
                      finalServerName = mcpServerName;
                      console.log(`[TOOL-VET] finalServerName을 mcpServerName으로 설정: ${finalServerName}`);
                        }
                        
                    // 사용자 입력 서버 이름을 정규화하여 저장/조회 이름 통일
                    const finalServerNameNormalized = finalServerName ? normalizeServerName(null, finalServerName) : mcpServerName;
                        console.log(`[TOOL-VET] 최종 서버 이름 (사용자 입력): ${finalServerName}`);
                    console.log(`[TOOL-VET] 최종 서버 이름(정규화): ${finalServerNameNormalized}`);
                        
                    // ========== TOOL-VET 결과에서 tools를 mcp_tools 테이블에 저장 ==========
                    if (reportData.tools && Array.isArray(reportData.tools)) {
                      try {
                        
                        // mcp_server_name으로 mcp_server_id 찾기 (승인된 서버)
                        const server = db.prepare(`
                          SELECT id FROM mcp_servers WHERE name = ? AND status = 'approved'
                        `).get(finalServerNameNormalized);
                        
                        const mcpServerId = server ? server.id : null;
                        
                        if (mcpServerId) {
                          console.log(`[TOOL-VET] MCP 서버 ID 찾음: ${finalServerNameNormalized} -> ${mcpServerId}`);
                        } else {
                          console.log(`[TOOL-VET] MCP 서버가 아직 승인되지 않음: ${finalServerNameNormalized} (server_name으로 저장)`);
                        }
                        
                        // 기존 tools 삭제 (같은 서버 이름의 이전 tool 정보)
                        const deleteToolsStmt = db.prepare('DELETE FROM mcp_tools WHERE server_name = ?');
                        deleteToolsStmt.run(finalServerNameNormalized);
                        console.log(`[TOOL-VET] 기존 tool 정보 삭제 완료: server_name=${finalServerNameNormalized}`);
                        
                        // tools 저장 (server_name으로 저장, mcp_server_id는 있으면 함께 저장)
                        const insertToolStmt = db.prepare(`
                          INSERT INTO mcp_tools (mcp_server_id, server_name, tool_name, tool_description, input_schema)
                          VALUES (?, ?, ?, ?, ?)
                        `);
                        
                        let savedTools = 0;
                        for (const tool of reportData.tools) {
                          const toolName = tool.name || '';
                          const toolDescription = tool.description || '';
                          const inputSchema = tool.inputSchema ? JSON.stringify(tool.inputSchema) : null;
                          
                          if (toolName) {
                            try {
                              insertToolStmt.run(mcpServerId, finalServerNameNormalized, toolName, toolDescription, inputSchema);
                              savedTools++;
                              console.log(`[TOOL-VET] Tool 저장 완료: ${toolName} (server_name: ${finalServerNameNormalized})`);
                            } catch (toolError) {
                              // UNIQUE 제약조건 위반 시 무시 (이미 존재)
                              if (toolError.code !== 'SQLITE_CONSTRAINT_UNIQUE') {
                                console.error(`[TOOL-VET] Tool 저장 오류: ${toolName}`, toolError);
                                console.error(`[TOOL-VET] 오류 상세:`, {
                                  code: toolError.code,
                                  message: toolError.message,
                                  mcpServerId: mcpServerId,
                                  finalServerName: finalServerName,
                                  toolName: toolName
                                });
                              }
                            }
                          }
                        }
                        
                        console.log(`[TOOL-VET] ${savedTools}개 tool 정보 저장 완료: server_name=${finalServerNameNormalized}${mcpServerId ? `, mcp_server_id=${mcpServerId}` : ''}`);
                      } catch (toolsSaveError) {
                        console.error('[TOOL-VET] Tools 저장 오류:', toolsSaveError);
                        console.error('[TOOL-VET] 오류 스택:', toolsSaveError.stack);
                      }
                    }
                    
                    // scan_path 정규화 (삭제 시에도 정규화된 값 사용)
                    let normalizedScanPathForDelete = scanPath;
                    if (scanPath && isValidGithubUrl(scanPath)) {
                      normalizedScanPathForDelete = scanPath.replace(/\.git$/i, '').toLowerCase();
                    }
                    
                    // 기존 tool validation 취약점 데이터 삭제 (같은 scan_path와 mcp_server_name의 이전 스캔 결과)
                    try {
                      if (finalServerNameNormalized) {
                        // 정규화된 scan_path로 삭제 (원본과 정규화된 값 모두 삭제)
                        const deleteStmt1 = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ?');
                        deleteStmt1.run(scanPath, finalServerNameNormalized);
                        if (normalizedScanPathForDelete !== scanPath) {
                          const deleteStmt2 = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ?');
                          deleteStmt2.run(normalizedScanPathForDelete, finalServerNameNormalized);
                        }
                        console.log(`[TOOL-VET] 기존 Tool Validation 취약점 데이터 삭제 완료: ${scanPath} / ${normalizedScanPathForDelete} (서버: ${finalServerNameNormalized})`);
                      } else {
                        const deleteStmt = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_path = ? OR scan_path = ?');
                        deleteStmt.run(scanPath, normalizedScanPathForDelete);
                        console.log(`[TOOL-VET] 기존 Tool Validation 취약점 데이터 삭제 완료: ${scanPath} / ${normalizedScanPathForDelete} (서버 이름 없음)`);
                      }
                    } catch (deleteError) {
                      console.error('[TOOL-VET] 기존 Tool Validation 취약점 데이터 삭제 오류:', deleteError);
                    }
                    
                    // 취약점 데이터 저장 (global_vulnerabilities + tool-level + api-endpoint-level)
                      const insertStmt = db.prepare(`
                        INSERT INTO tool_validation_vulnerabilities (
                          scan_id, scan_path, mcp_server_name, scan_timestamp,
                          tool_name, host, method, path,
                          category_code, category_name, title, description, evidence, recommendation, raw_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                      `);
                      
                      let savedVulns = 0;
                    const serverNameForInsert = finalServerNameNormalized || mcpServerName;
                    
                    // scan_path 정규화 (저장 시와 조회 시 일치시키기 위해)
                    let normalizedScanPathForInsert = scanPath;
                    if (scanPath && isValidGithubUrl(scanPath)) {
                      normalizedScanPathForInsert = scanPath.replace(/\.git$/i, '').toLowerCase();
                    }
                    
                    console.log(`[TOOL-VET] 취약점 저장에 사용할 서버 이름: ${serverNameForInsert}, scan_path: ${scanPath} -> normalized: ${normalizedScanPathForInsert}`);
                    
                    // global_vulnerabilities는 저장하지 않음 (tool-level과 api-endpoint-level만 저장)
                    if (reportData.global_vulnerabilities && Array.isArray(reportData.global_vulnerabilities)) {
                      console.log(`[TOOL-VET] global_vulnerabilities 발견: ${reportData.global_vulnerabilities.length}개 (저장하지 않음)`);
                    }
                    
                    // tools 배열 순회하며 tool-level 및 api-endpoint-level 취약점 저장
                    if (reportData.tools && Array.isArray(reportData.tools)) {
                      console.log(`[TOOL-VET] tools 배열 발견: ${reportData.tools.length}개 도구`);
                      let totalEndpoints = 0;
                      
                      for (const tool of reportData.tools) {
                        const toolName = tool.name || '';
                        
                        // 2-1. tool-level vulnerabilities 저장 (API가 없는 tool의 취약점)
                        if (tool.vulnerabilities && Array.isArray(tool.vulnerabilities)) {
                          console.log(`[TOOL-VET] Tool '${toolName}'의 tool-level 취약점 발견: ${tool.vulnerabilities.length}개`);
                          for (const vuln of tool.vulnerabilities) {
                            try {
                              insertStmt.run(
                                scanId,
                                normalizedScanPathForInsert, // 정규화된 scan_path 사용
                                serverNameForInsert,
                                getKoreaTimeSQLite(),
                                toolName,
                                null, // host 없음
                                null, // method 없음
                                null, // path 없음
                                vuln.category_code || '',
                                vuln.category_name || '',
                                vuln.title || '',
                                vuln.description || '',
                                vuln.evidence || '',
                                vuln.recommendation || '',
                                JSON.stringify(vuln)
                              );
                              savedVulns++;
                              console.log(`[TOOL-VET] Tool-level 취약점 저장 완료: ${toolName} - ${vuln.category_code} - ${vuln.title}`);
                            } catch (insertError) {
                              console.error(`[TOOL-VET] Tool-level 취약점 저장 오류 (${toolName}):`, insertError);
                            }
                          }
                        }
                        
                        // 2-2. api_endpoints 배열 순회
                        if (tool.api_endpoints && Array.isArray(tool.api_endpoints)) {
                          totalEndpoints += tool.api_endpoints.length;
                          for (const endpoint of tool.api_endpoints) {
                            const host = endpoint.host || '';
                            const method = endpoint.method || '';
                            const path = endpoint.path || '';
                            
                            // api-endpoint-level vulnerabilities 저장
                            if (endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities)) {
                              for (const vuln of endpoint.vulnerabilities) {
                                try {
                                  insertStmt.run(
                                    scanId,
                                    normalizedScanPathForInsert, // 정규화된 scan_path 사용
                                    serverNameForInsert,
                                    getKoreaTimeSQLite(),
                                    toolName,
                                    host,
                                    method,
                                    path,
                                    vuln.category_code || '',
                                    vuln.category_name || '',
                                    vuln.title || '',
                                    vuln.description || '',
                                    vuln.evidence || '',
                                    vuln.recommendation || '',
                                    JSON.stringify(vuln)
                                  );
                                  savedVulns++;
                                } catch (insertError) {
                                  console.error(`[TOOL-VET] API-endpoint 취약점 저장 오류 (${toolName}):`, insertError);
                                }
                              }
                            }
                          }
                        }
                      }
                      
                      console.log(`[TOOL-VET] Tool Validation 취약점 ${savedVulns}개 저장 완료 (총 ${totalEndpoints}개 엔드포인트 확인)`);
                    } else {
                      console.log('[TOOL-VET] TOOL-VET 리포트에 tools 배열이 없습니다.');
                    }
                    
                    // 저장 후 검증: 실제로 저장된 취약점 개수 확인
                    if (serverNameForInsert) {
                      // 정규화된 scan_path로 조회 (저장 시 사용한 값과 동일)
                      const verifyStmt = db.prepare(`
                        SELECT COUNT(*) as count 
                        FROM tool_validation_vulnerabilities 
                        WHERE scan_path = ? AND mcp_server_name = ?
                      `);
                      const verifyResult = verifyStmt.get(normalizedScanPathForInsert, serverNameForInsert);
                      console.log(`[TOOL-VET] 저장 검증: DB에 실제 저장된 취약점 개수 = ${verifyResult.count}개 (저장 시도: ${savedVulns}개, 서버: ${serverNameForInsert}, scan_path: ${normalizedScanPathForInsert})`);
                      
                      // tool_name별로 개수 확인 (null 포함)
                      const toolNameStmt = db.prepare(`
                        SELECT tool_name, COUNT(*) as count 
                        FROM tool_validation_vulnerabilities 
                        WHERE scan_path = ? AND mcp_server_name = ?
                        GROUP BY tool_name
                      `);
                      const toolNameCounts = toolNameStmt.all(normalizedScanPathForInsert, serverNameForInsert);
                      console.log(`[TOOL-VET] tool_name별 취약점 개수:`, toolNameCounts);
                      
                      // category_code별로 개수 확인
                      const categoryStmt = db.prepare(`
                        SELECT category_code, COUNT(*) as count 
                        FROM tool_validation_vulnerabilities 
                        WHERE scan_path = ? AND mcp_server_name = ?
                        GROUP BY category_code
                      `);
                      const categoryCounts = categoryStmt.all(normalizedScanPathForInsert, serverNameForInsert);
                      console.log(`[TOOL-VET] category_code별 취약점 개수:`, categoryCounts);
                    }
                    
                    if (savedVulns === 0) {
                      console.log(`[TOOL-VET] ⚠️ 취약점이 0개 저장되었습니다. 리포트 파일 구조를 확인하세요. (scan_path: ${scanPath})`);
                      console.log(`[TOOL-VET] 리포트 파일 내용 확인:`, {
                        has_global_vulnerabilities: !!reportData.global_vulnerabilities,
                        global_vulnerabilities_count: reportData.global_vulnerabilities?.length || 0,
                        has_tools: !!reportData.tools,
                        tools_count: reportData.tools?.length || 0,
                        tools_with_vulnerabilities: reportData.tools?.filter(t => t.vulnerabilities && t.vulnerabilities.length > 0).length || 0
                      });
                    }
                  } else {
                    console.log('TOOL-VET 리포트 파일을 찾을 수 없습니다.');
                    
                    // 리포트 파일을 찾지 못했을 때, 모든 리포트 파일 확인
                    try {
                      const allReportFiles = await fs.readdir(TOOL_VET_OUTPUT_DIR);
                      const reportJsonFiles = allReportFiles.filter(f => f.endsWith('-report.json'));
                      console.log(`발견된 리포트 파일들: ${reportJsonFiles.join(', ')}`);
                      
                      if (reportJsonFiles.length > 0) {
                        // 가장 최근 파일 사용
                        const reportFilesWithStats = [];
                        for (const file of reportJsonFiles) {
                          const filePath = path.join(TOOL_VET_OUTPUT_DIR, file);
                          try {
                            const stats = await fs.stat(filePath);
                            if (stats.size > 0) {
                              reportFilesWithStats.push({ file, filePath, mtime: stats.mtime });
                            }
                          } catch (fileError) {
                            // 파일 접근 실패, 무시
                          }
                        }
                        // 수정 시간순으로 정렬 (최신 파일이 먼저)
                        reportFilesWithStats.sort((a, b) => b.mtime - a.mtime);
                        
                        if (reportFilesWithStats.length > 0) {
                          const latestReportFile = reportFilesWithStats[0].file;
                          console.log(`대체 리포트 파일 사용: ${latestReportFile}`);
                          
                          // 리포트 파일 처리 (위의 로직 재사용)
                          const reportPath = path.join(TOOL_VET_OUTPUT_DIR, latestReportFile);
                          const reportData = JSON.parse(await fs.readFile(reportPath, 'utf-8'));
                          
                          // MCP 서버 이름 추출 및 정규화
                          let mcpServerName = normalizeServerName(github_url, serverName);
                          if (latestReportFile && latestReportFile.includes('-report.json')) {
                            const fileServerName = latestReportFile.replace('-report.json', '');
                            const normalizedFileServerName = normalizeServerName(null, fileServerName);
                            if (normalizedFileServerName && normalizedFileServerName !== 'finding') {
                              mcpServerName = normalizedFileServerName;
                            }
                          }
                          console.log(`[TOOL-VET] 정규화된 서버 이름: ${mcpServerName}`);
                          
                          // 리포트 요약 정보 계산
                          let totalTools = 0;
                          let totalEndpoints = 0;
                          let totalVulns = 0;
                          
                          if (reportData.tools && Array.isArray(reportData.tools)) {
                            totalTools = reportData.tools.length;
                            for (const tool of reportData.tools) {
                              if (tool.api_endpoints && Array.isArray(tool.api_endpoints)) {
                                totalEndpoints += tool.api_endpoints.length;
                                for (const endpoint of tool.api_endpoints) {
                                  if (endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities)) {
                                    totalVulns += endpoint.vulnerabilities.length;
                                  }
                                }
                              }
                            }
                          }
                          
                          // summary가 있으면 사용
                          if (reportData.summary) {
                            if (reportData.summary.total_tools !== undefined) {
                              totalTools = reportData.summary.total_tools;
                            }
                            if (reportData.summary.total_vulnerabilities !== undefined) {
                              totalVulns = reportData.summary.total_vulnerabilities;
                            }
                          }
                          
                          // 기존 tool validation 리포트 삭제
                          try {
                            const deleteReportStmt = db.prepare('DELETE FROM tool_validation_reports WHERE scan_path = ?');
                            deleteReportStmt.run(scanPath);
                            console.log(`기존 Tool Validation 리포트 삭제 완료: ${scanPath}`);
                          } catch (deleteError) {
                            console.error('기존 Tool Validation 리포트 삭제 오류:', deleteError);
                          }
                          
                          // 리포트 전체 저장
                          try {
                            const insertReportStmt = db.prepare(`
                              INSERT INTO tool_validation_reports (
                                scan_id, scan_path, mcp_server_name, scan_timestamp,
                                report_data, total_tools, total_endpoints, total_vulnerabilities
                              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            `);
                            
                            insertReportStmt.run(
                              scanId,
                              scanPath,
                              mcpServerName,
                              getKoreaTimeSQLite(),
                              JSON.stringify(reportData),
                              totalTools,
                              totalEndpoints,
                              totalVulns
                            );
                            
                            console.log(`Tool Validation 리포트 저장 완료: ${mcpServerName || 'unknown'} (tools: ${totalTools}, endpoints: ${totalEndpoints}, vulnerabilities: ${totalVulns})`);
                          } catch (reportInsertError) {
                            console.error('Tool Validation 리포트 저장 오류:', reportInsertError);
                          }
                          
                          // 취약점 데이터 저장
                          try {
                            if (mcpServerName) {
                              const deleteStmt = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ?');
                              deleteStmt.run(scanPath, mcpServerName);
                              console.log(`기존 Tool Validation 취약점 데이터 삭제 완료: ${scanPath} (서버: ${mcpServerName})`);
                            } else {
                            const deleteStmt = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_path = ?');
                            deleteStmt.run(scanPath);
                              console.log(`기존 Tool Validation 취약점 데이터 삭제 완료: ${scanPath} (서버 이름 없음)`);
                            }
                            
                            if (reportData.tools && Array.isArray(reportData.tools)) {
                              const insertStmt = db.prepare(`
                                INSERT INTO tool_validation_vulnerabilities (
                                  scan_id, scan_path, mcp_server_name, scan_timestamp,
                                  tool_name, host, method, path,
                                  category_code, category_name, title, description, evidence, recommendation, raw_data
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                              `);
                              
                              let savedVulns = 0;
                              for (const tool of reportData.tools) {
                                const toolName = tool.name || '';
                                
                                // tool 레벨의 취약점을 api_endpoints와 연결하여 저장
                                const toolVulnerabilities = tool.vulnerabilities || [];
                                
                                if (tool.api_endpoints && Array.isArray(tool.api_endpoints) && tool.api_endpoints.length > 0) {
                                  // api_endpoints가 있는 경우, 각 endpoint에 대해 취약점 저장
                                  for (const endpoint of tool.api_endpoints) {
                                    const host = endpoint.host || '';
                                    const method = endpoint.method || '';
                                    const path = endpoint.path || '';
                                    
                                    // endpoint 레벨의 취약점이 있으면 우선 사용, 없으면 tool 레벨 취약점 사용
                                    const endpointVulns = endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities) 
                                      ? endpoint.vulnerabilities 
                                      : toolVulnerabilities;
                                    
                                    for (const vuln of endpointVulns) {
                                      try {
                                        insertStmt.run(
                                          scanId,
                                          scanPath,
                                          mcpServerName,
                                          getKoreaTimeSQLite(),
                                          toolName,
                                          host,
                                          method,
                                          path,
                                          vuln.category_code || '',
                                          vuln.category_name || '',
                                          vuln.title || '',
                                          vuln.description || '',
                                          vuln.evidence || '',
                                          vuln.recommendation || '',
                                          JSON.stringify(vuln)
                                        );
                                        savedVulns++;
                                      } catch (insertError) {
                                        console.error('Tool Validation 취약점 저장 오류:', insertError);
                                      }
                                    }
                                  }
                                } else if (toolVulnerabilities.length > 0) {
                                  // api_endpoints가 없지만 tool 레벨 취약점이 있는 경우, 빈 endpoint로 저장
                                  for (const vuln of toolVulnerabilities) {
                                    try {
                                      insertStmt.run(
                                        scanId,
                                        scanPath,
                                        mcpServerName,
                                        getKoreaTimeSQLite(),
                                        toolName,
                                        '', // host 빈값
                                        '', // method 빈값
                                        '', // path 빈값
                                        vuln.category_code || '',
                                        vuln.category_name || '',
                                        vuln.title || '',
                                        vuln.description || '',
                                        vuln.evidence || '',
                                        vuln.recommendation || '',
                                        JSON.stringify(vuln)
                                      );
                                      savedVulns++;
                                    } catch (insertError) {
                                      console.error('Tool Validation 취약점 저장 오류:', insertError);
                                    }
                                  }
                                }
                              }
                              
                              console.log(`Tool Validation 취약점 ${savedVulns}개 저장 완료`);
                            }
                          } catch (vulnError) {
                            console.error('Tool Validation 취약점 저장 오류:', vulnError);
                          }
                        }
                      }
                    } catch (fallbackError) {
                      console.error('대체 리포트 파일 처리 오류:', fallbackError);
                    }
                  }
                } catch (parseError) {
                  console.error('TOOL-VET 리포트 파싱 오류:', parseError);
                  // 오류가 발생해도 분석은 완료된 것으로 처리
                }
                
                resolve();
              } else {
                console.error(`TOOL-VET 분석 실패 (종료 코드: ${code})`);
                
                // 오류 메시지 구성
                let errorMessage = `TOOL-VET 분석 실패 (종료 코드: ${code})`;
                
                // stderr에서 오류 메시지 추출 시도
                if (toolVetStderr.trim()) {
                  console.log(`[TOOL-VET] 전체 stderr 출력:\n${toolVetStderr}`);
                  const stderrLines = toolVetStderr.trim().split('\n').filter(line => line.trim());
                  
                  // tools/list 관련 오류 찾기
                  const toolsListError = stderrLines.find(line => 
                    line.includes('tools/list') || 
                    line.includes('tool을 가져오지') ||
                    line.includes('❌')
                  );
                  
                  // MCP 서버 시작 실패 오류 찾기
                  const serverStartError = stderrLines.find(line => 
                    line.includes('MCP 서버') || 
                    line.includes('서버 시작 실패') ||
                    line.includes('프로세스가 종료')
                  );
                  
                  // 오류 메시지 우선순위: tools/list > 서버 시작 > 마지막 라인
                  let errorLine = toolsListError || serverStartError || stderrLines[stderrLines.length - 1];
                  
                  // 마지막 오류 라인에서 의미있는 메시지 추출
                  if (errorLine && errorLine.length > 0) {
                    // 너무 긴 메시지는 잘라내기
                    const shortError = errorLine.length > 500 
                      ? errorLine.substring(0, 500) + '...' 
                      : errorLine;
                    errorMessage += `. 오류: ${shortError}`;
                  } else {
                    // stderr 전체가 짧으면 전체 사용
                    const shortStderr = toolVetStderr.trim().length > 200 
                      ? toolVetStderr.trim().substring(0, 200) + '...' 
                      : toolVetStderr.trim();
                    if (shortStderr) {
                      errorMessage += `. 오류: ${shortStderr}`;
                    }
                  }
                } else if (toolVetStdout.trim()) {
                  // stderr가 없으면 stdout에서 오류 찾기
                  const stdoutLines = toolVetStdout.trim().split('\n').filter(line => 
                    line.toLowerCase().includes('error') || 
                    line.toLowerCase().includes('fail') ||
                    line.toLowerCase().includes('exception')
                  );
                  if (stdoutLines.length > 0) {
                    const lastErrorLine = stdoutLines[stdoutLines.length - 1];
                    const shortError = lastErrorLine.length > 200 
                      ? lastErrorLine.substring(0, 200) + '...' 
                      : lastErrorLine;
                    errorMessage += `. 오류: ${shortError}`;
                  } else {
                    errorMessage += '. 프로젝트 타입을 감지할 수 없거나 지원되지 않는 프로젝트입니다.';
                  }
                } else {
                  errorMessage += '. 프로젝트 타입을 감지할 수 없거나 지원되지 않는 프로젝트입니다.';
                }
                
                const currentProgress = scanProgress.get(scanId);
                if (currentProgress) {
                  currentProgress.toolVetError = errorMessage;
                  scanProgress.set(scanId, currentProgress);
                }
                
                // 상세 로그 출력
                console.error('[TOOL-VET 상세 오류]');
                console.error('stdout:', toolVetStdout);
                console.error('stderr:', toolVetStderr);
                
                resolve(); // 실패해도 resolve (오류는 무시하지만 오류 정보는 저장)
              }
            });
            
            toolVetProcess.on('error', (error) => {
              clearInterval(toolVetProgressInterval);
              
              console.error('TOOL-VET 실행 오류:', error);
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.toolVet = 100;
                currentProgress.toolVetCompleted = true;
                currentProgress.toolVetError = `TOOL-VET 실행 오류: ${error.message}`;
                scanProgress.set(scanId, currentProgress);
              }
              resolve(); // 오류는 무시하고 resolve (오류 정보는 저장)
            });
          });
          
          scanPromises.push(toolVetPromise);
          console.log(`[TOOL-VET] TOOL-VET Promise가 scanPromises에 추가됨`);
          } else {
            console.log(`[TOOL-VET] 기존 리포트 파일이 있어서 TOOL-VET 스캔을 스킵합니다`);
          } // if (!existingReportFile) 블록 닫기
        } catch (error) {
          console.error('[TOOL-VET] TOOL-VET 분석 시작 실패:', error.message);
          console.error('[TOOL-VET] 에러 스택:', error.stack);
          const currentProgress = scanProgress.get(scanId);
          if (currentProgress) {
            currentProgress.toolVet = 100;
            currentProgress.toolVetCompleted = true;
            currentProgress.toolVetError = `TOOL-VET 시작 실패: ${error.message}`;
            scanProgress.set(scanId, currentProgress);
          }
        }
      } else {
        console.log(`[TOOL-VET] ❌ TOOL-VET 실행 조건 불만족: github_url="${github_url}", isValidGithubUrl=${github_url ? isValidGithubUrl(github_url) : false}`);
        console.log(`[TOOL-VET] github_url 타입: ${typeof github_url}, 값: ${github_url}`);
        if (github_url) {
          console.log(`[TOOL-VET] isValidGithubUrl 함수 결과: ${isValidGithubUrl(github_url)}`);
        }
      }
      
      console.log(`[SCAN] 총 ${scanPromises.length}개의 스캔 Promise가 실행됩니다 (Bomtori: ${hasBomtori ? '예' : '아니오'}, Scanner: ${hasScanner ? '예' : '아니오'}, TOOL-VET: ${hasToolVet ? '예' : '아니오'})`);
      
      // 모든 스캔을 동시에 시작하고 완료될 때까지 대기
      try {
        await Promise.all(scanPromises);
        
        // 모든 스캔이 완료되었는지 최종 확인
        const finalProgress = scanProgress.get(scanId);
        if (finalProgress) {
          // 실행된 스캔 성공 여부 (TOOL-VET 실패는 전체 완료를 막지 않음)
          const bomtoriSuccess = !hasBomtori || (finalProgress.bomtoriCompleted && !finalProgress.bomtoriError);
          const scannerSuccess = finalProgress.scannerCompleted && !finalProgress.scannerError;
          const toolVetSuccess = !hasToolVet || (finalProgress.toolVetCompleted && !finalProgress.toolVetError);
          
          // 필수 스캔(Bomtori+Scanner) 성공 여부
          const hasRequiredSuccess = hasBomtori ? (bomtoriSuccess && scannerSuccess) : scannerSuccess;
          
          if (hasRequiredSuccess) {
            // TOOL-VET 실패해도 필수 스캔이 성공하면 완료 처리
            finalProgress.status = 'completed';
            
            // 스캔 완료 시 mcp_register_requests 테이블의 scanned 필드, analysis_timestamp, languages 업데이트
            if (serverName) {
              try {
                // scanProgress에서 언어 정보 가져오기
                let languagesJson = null;
                if (finalProgress && finalProgress.languages) {
                  languagesJson = JSON.stringify(finalProgress.languages);
                  console.log(`[Scanner] 언어 정보 사용: ${languagesJson}`);
                }
                
                // pending 상태인 경우 업데이트
                let updateStmt;
                if (languagesJson) {
                  updateStmt = db.prepare('UPDATE mcp_register_requests SET scanned = 1, analysis_timestamp = datetime(\'now\'), languages = ? WHERE name = ? AND status = ?');
                  var result = updateStmt.run(languagesJson, serverName, 'pending');
                } else {
                  updateStmt = db.prepare('UPDATE mcp_register_requests SET scanned = 1, analysis_timestamp = datetime(\'now\') WHERE name = ? AND status = ?');
                  var result = updateStmt.run(serverName, 'pending');
                }
                
                // pending 상태에서 업데이트되지 않았다면 approved 상태에서도 시도
                if (result.changes === 0) {
                  if (languagesJson) {
                    updateStmt = db.prepare('UPDATE mcp_register_requests SET scanned = 1, analysis_timestamp = datetime(\'now\'), languages = ? WHERE name = ? AND status = ?');
                    result = updateStmt.run(languagesJson, serverName, 'approved');
                  } else {
                    updateStmt = db.prepare('UPDATE mcp_register_requests SET scanned = 1, analysis_timestamp = datetime(\'now\') WHERE name = ? AND status = ?');
                    result = updateStmt.run(serverName, 'approved');
                  }
                }
                
                // mcp_servers 테이블도 업데이트 (분석 완료 시 analysis_timestamp와 status 업데이트)
                try {
                  // scanPath (github_url 또는 file_path)를 사용해서 mcp_servers 테이블에서 서버 찾기
                  let serverUpdateResult = null;
                  
                  if (scanPath) {
                    // GitHub URL 또는 file_path로 서버 찾기
                    let serverQuery;
                    if (scanPath.startsWith('http') || scanPath.startsWith('https')) {
                      // GitHub URL인 경우
                      serverQuery = db.prepare('SELECT id, name, status FROM mcp_servers WHERE github_link = ?');
                      serverUpdateResult = serverQuery.get(scanPath);
                    } else {
                      // 파일 경로인 경우
                      serverQuery = db.prepare('SELECT id, name, status FROM mcp_servers WHERE file_path = ?');
                      serverUpdateResult = serverQuery.get(scanPath);
                    }
                    
                    // GitHub URL/file_path로 찾지 못했으면 서버 이름으로 시도
                    if (!serverUpdateResult && serverName) {
                      const nameQuery = db.prepare('SELECT id, name, status FROM mcp_servers WHERE name = ?');
                      serverUpdateResult = nameQuery.get(serverName);
                    }
                    
                    // 정규화된 서버 이름으로도 시도
                    if (!serverUpdateResult && serverName) {
                      const normalizedName = normalizeServerName(scanPath, serverName);
                      if (normalizedName && normalizedName !== serverName) {
                        const normalizedQuery = db.prepare('SELECT id, name, status FROM mcp_servers WHERE name = ? OR LOWER(REPLACE(name, \' \', \'-\')) = ?');
                        serverUpdateResult = normalizedQuery.get(serverName, normalizedName);
                      }
                    }
                  } else if (serverName) {
                    // scanPath가 없으면 서버 이름으로만 찾기
                    const nameQuery = db.prepare('SELECT id, name, status FROM mcp_servers WHERE name = ?');
                    serverUpdateResult = nameQuery.get(serverName);
                  }
                  
                  if (serverUpdateResult) {
                    // mcp_servers 테이블 업데이트
                    let updateFields = ['analysis_timestamp = datetime(\'now\')'];
                    let updateValues = [];
                    
                    // languages 업데이트
                if (languagesJson) {
                      updateFields.push('languages = ?');
                      updateValues.push(languagesJson);
                    }
                    
                    // status가 'pending'이면 'approved'로 변경
                    if (serverUpdateResult.status === 'pending') {
                      updateFields.push('status = ?');
                      updateValues.push('approved');
                    }
                    
                    // UPDATE 쿼리 실행
                    const updateQuery = `UPDATE mcp_servers SET ${updateFields.join(', ')} WHERE id = ?`;
                    const serverUpdateStmt = db.prepare(updateQuery);
                    updateValues.push(serverUpdateResult.id);
                    const serverUpdate = serverUpdateStmt.run(...updateValues);
                    
                    console.log(`[Scanner] mcp_servers 업데이트 완료: ${serverUpdateResult.name} (ID: ${serverUpdateResult.id})`);
                    console.log(`  - analysis_timestamp 업데이트됨`);
                    if (languagesJson) {
                      console.log(`  - languages 업데이트됨`);
                    }
                    if (serverUpdateResult.status === 'pending') {
                      console.log(`  - status: pending -> approved`);
                    }
                  } else {
                    console.log(`[Scanner] mcp_servers에서 서버를 찾을 수 없음: ${serverName || scanPath}`);
                  }
                } catch (serverUpdateError) {
                  console.error('[Scanner] mcp_servers 업데이트 오류:', serverUpdateError);
                  // 오류가 발생해도 계속 진행
                }
                
                if (result.changes > 0) {
                  console.log(`스캔 완료: ${serverName} 요청의 scanned 필드, analysis_timestamp, languages 업데이트 완료`);
                } else {
                  console.log(`스캔 완료: ${serverName} 요청을 찾을 수 없거나 이미 거부됨`);
                }
              } catch (updateError) {
                console.error('스캔 완료 상태 업데이트 오류:', updateError);
                // 오류가 발생해도 스캔 결과는 정상적으로 저장되므로 계속 진행
              }
            }
          } else {
            // 필수 스캔이 실패한 경우에만 실패 처리 (TOOL-VET 실패는 여기서 포함하지 않음)
            finalProgress.status = 'failed';
            const errors = [];
            if (hasBomtori && finalProgress.bomtoriError) {
              errors.push(`Bomtori: ${finalProgress.bomtoriError}`);
            }
            if (finalProgress.scannerError) {
              errors.push(`Scanner: ${finalProgress.scannerError}`);
            }
            // TOOL-VET 오류는 완료를 막지 않으므로 여기서는 포함하지 않음
            finalProgress.error = errors.join('; ') || '일부 스캔이 실패했습니다.';
            console.error(`[SCAN] 스캔 실패: ${finalProgress.error}`);
          }
          scanProgress.set(scanId, finalProgress);
        }
      } catch (error) {
        // 오류 발생 시 상태를 'failed'로 설정
        console.error('스캔 프로세스 오류:', error);
        const finalProgress = scanProgress.get(scanId);
        if (finalProgress) {
          finalProgress.status = 'failed';
          finalProgress.error = error.message || '스캔 중 오류가 발생했습니다.';
          scanProgress.set(scanId, finalProgress);
        }
      }

    } catch (error) {
      console.error('코드 스캔 오류:', error);
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          message: '코드 스캔 중 오류가 발생했습니다.'
        });
      }
    }
  },

  // 진행률 조회 API
  getScanProgress: async (req, res) => {
    try {
      const { scan_id } = req.query;
      
      if (!scan_id) {
        return res.status(400).json({
          success: false,
          message: 'scan_id가 필요합니다.'
        });
      }
      
      const progress = scanProgress.get(scan_id);
      
      if (!progress) {
        // 진행률이 없을 때 기본값 반환 (클라우드 환경에서 네트워크 지연으로 인한 일시적 문제 대응)
        // 프론트엔드에서 이전 진행률을 유지할 수 있도록 null이 아닌 기본 구조 반환
        return res.json({
          success: true,
          data: {
            bomtori: null,
            scanner: null,
            toolVet: null,
            status: 'running',
            bomtoriCompleted: false,
            scannerCompleted: false,
            toolVetCompleted: false
          }
        });
      }
      
      res.json({
        success: true,
        data: progress
      });
    } catch (error) {
      console.error('진행률 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '진행률 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // OSS 취약점 조회 (데이터베이스에서 조회)
  getOssVulnerabilities: async (req, res) => {
    console.log(`[OSS] ========== getOssVulnerabilities 함수 호출됨 ==========`);
    console.log(`[OSS] req.query:`, req.query);
    console.log(`[OSS] req.method:`, req.method);
    console.log(`[OSS] req.url:`, req.url);
    
    try {
      const { scan_id, scan_path, mcp_server_name } = req.query;
      
      console.log(`[OSS] getOssVulnerabilities 호출: scan_id=${scan_id}, scan_path=${scan_path}, mcp_server_name=${mcp_server_name}`);
      
      // scan_id나 scan_path가 없으면 에러 반환 (모든 데이터 반환 방지)
      if (!scan_id && !scan_path) {
        return res.status(400).json({
          success: false,
          message: 'scan_id 또는 scan_path가 필요합니다.'
        });
      }
      
      let vulnerabilities = [];
      
      if (scan_id) {
        // scan_id로 조회
        if (mcp_server_name) {
          // mcp_server_name이 있으면 mcp_server_name으로 정확히 필터링
          vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_id = ? AND mcp_server_name = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_id, mcp_server_name);
        } else if (scan_path) {
          // scan_path가 있으면 scan_path로도 필터링하여 다른 서버의 데이터가 섞이지 않도록 함
          vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_id = ? AND scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_id, scan_path);
        } else {
          vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_id);
        }
        console.log(`[OSS] scan_id로 조회: ${vulnerabilities.length}개 발견`);
      } else if (scan_path) {
        // scan_path로 최신 스캔 결과 조회
        let query = 'SELECT DISTINCT scan_id FROM oss_vulnerabilities WHERE scan_path = ?';
        const params = [scan_path];
        
        // mcp_server_name이 있으면 추가 필터링
        if (mcp_server_name) {
          // mcp_server_name 정규화
          const normalizedServerName = normalizeServerName(scan_path, mcp_server_name);
          console.log(`[OSS] 정규화된 서버 이름: ${normalizedServerName} (원본: ${mcp_server_name})`);
          
          // 정규화된 서버 이름으로 필터링 시도
          query = 'SELECT DISTINCT scan_id FROM oss_vulnerabilities WHERE scan_path = ? AND (mcp_server_name = ? OR mcp_server_name = ?)';
          params.push(mcp_server_name, normalizedServerName);
          const latestScan = db.prepare(query).get(...params);
          if (latestScan && latestScan.scan_id) {
            vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_id = ? AND (mcp_server_name = ? OR mcp_server_name = ?) ORDER BY scan_timestamp DESC, id DESC').all(latestScan.scan_id, mcp_server_name, normalizedServerName);
            console.log(`[OSS] scan_path로 최신 scan_id 조회 (서버 필터링, 정규화): ${vulnerabilities.length}개 발견`);
          } else {
            // 정규화된 이름만으로 시도
            vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path, normalizedServerName);
            console.log(`[OSS] scan_path로 직접 조회 (정규화된 이름): ${vulnerabilities.length}개 발견`);
            
            // 여전히 없으면 scan_path의 최신 리포트에서 mcp_server_name 가져오기
            if (vulnerabilities.length === 0) {
              const reportInfo = db.prepare('SELECT mcp_server_name FROM tool_validation_reports WHERE scan_path = ? ORDER BY scan_timestamp DESC LIMIT 1').get(scan_path);
              if (reportInfo && reportInfo.mcp_server_name) {
                const reportServerName = normalizeServerName(scan_path, reportInfo.mcp_server_name);
                console.log(`[OSS] 리포트에서 서버 이름 발견: ${reportInfo.mcp_server_name} -> ${reportServerName}`);
                vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path, reportServerName);
                console.log(`[OSS] 리포트의 서버 이름으로 조회: ${vulnerabilities.length}개 발견`);
              }
            }
          }
        } else {
          const latestScan = db.prepare(query).get(...params);
          if (latestScan && latestScan.scan_id) {
            // scan_id로 조회하되, scan_path도 함께 필터링하여 다른 서버의 데이터가 섞이지 않도록 함
            vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_id = ? AND scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(latestScan.scan_id, scan_path);
            console.log(`[OSS] scan_path로 최신 scan_id 조회 (scan_path 필터링): ${vulnerabilities.length}개 발견`);
          } else {
            // scan_path로 직접 조회 시도 (scan_id가 없는 경우)
            vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
            console.log(`[OSS] scan_path로 직접 조회: ${vulnerabilities.length}개 발견`);
          }
        }
        
        // 데이터베이스에 데이터가 없으면 dashboard.json 파일에서 직접 로드 시도
        if (vulnerabilities.length === 0 && scan_path) {
          try {
            let repoName;
            
            // GitHub URL인 경우
            if (isValidGithubUrl(scan_path)) {
              // repo_name 추출 (GitHub URL에서)
              // 예: https://github.com/github/github-mcp-server -> github-mcp-server
              // 예: https://github.com/github/github-mcp-server.git -> github-mcp-server
              let tempRepoName = scan_path.split('/').pop().replace('.git', '');
              // GitHub URL 형식: https://github.com/owner/repo
              const urlParts = scan_path.split('/');
              if (urlParts.length >= 2 && urlParts[urlParts.length - 2] && urlParts[urlParts.length - 1]) {
                // owner/repo 형식으로 추출
                tempRepoName = `${urlParts[urlParts.length - 2]}-${urlParts[urlParts.length - 1]}`.replace('.git', '');
              }
              repoName = tempRepoName.replace(/[^a-zA-Z0-9_-]/g, '_');
            } else {
              // GitHub URL이 아닌 경우 (예: notion-mcp-server), scan_path 자체를 repoName으로 사용
              repoName = scan_path.replace(/[^a-zA-Z0-9_-]/g, '_');
            }
            
            const dashboardFile = path.join(BOMTORI_OUTPUT_DIR, `${repoName}-dashboard.json`);
            
            console.log(`[OSS] 데이터베이스에 OSS 취약점이 없어 dashboard.json 파일에서 로드 시도`);
            console.log(`[OSS] scan_path: ${scan_path}`);
            console.log(`[OSS] 추출된 repoName: ${repoName}`);
            console.log(`[OSS] 예상 파일 경로: ${dashboardFile}`);
            
            // 파일 존재 확인
            try {
              await fs.access(dashboardFile);
              const dashboardData = JSON.parse(await fs.readFile(dashboardFile, 'utf-8'));
              const dashboardVulnerabilities = dashboardData.vulnerabilities || [];
              
              console.log(`dashboard.json에서 발견된 취약점 개수: ${dashboardVulnerabilities.length}`);
              
              if (dashboardVulnerabilities.length > 0) {
                // scan_id 생성 (없으면 새로 생성)
                const scanId = uuidv4();
                
                // 기존 OSS 취약점 데이터 삭제 (같은 scan_path의 이전 스캔 결과)
                try {
                  const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ?');
                  deleteOssStmt.run(scan_path);
                  console.log(`기존 OSS 취약점 데이터 삭제 완료: ${scan_path}`);
                } catch (deleteError) {
                  console.error('기존 OSS 취약점 데이터 삭제 오류:', deleteError);
                }
                
                // 데이터베이스에 저장
                const insertOssStmt = db.prepare(`
                  INSERT INTO oss_vulnerabilities (
                    scan_id, scan_path, mcp_server_name, scan_timestamp,
                    package_name, package_version, package_fixed_version, package_all_fixed_versions,
                    package_affected_range, package_dependency_type,
                    vulnerability_id, vulnerability_cve, vulnerability_cvss, vulnerability_severity,
                    vulnerability_title, vulnerability_description, vulnerability_reference_url,
                    reachable, functions_count, reachable_functions, unreachable_functions, raw_data
                  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `);
                
                let successCount = 0;
                let errorCount = 0;
                
                for (const vuln of dashboardVulnerabilities) {
                  try {
                    const pkg = vuln.package || {};
                    const vulnInfo = vuln.vulnerability || {};
                    
                    // Go 프로젝트의 경우 module 필드가 있을 수 있음
                    // npm 프로젝트와 Go 프로젝트 모두 동일한 필드명 사용
                    const packageName = pkg.name || null;
                    // Go 프로젝트 버전에서 "v" 접두사 제거
                    const currentVersion = removeVersionPrefix(pkg.current_version) || null;
                    const fixedVersion = removeVersionPrefix(pkg.fixed_version) || null;
                    const allFixedVersions = Array.isArray(pkg.all_fixed_versions) 
                      ? pkg.all_fixed_versions.map(v => removeVersionPrefix(v))
                      : [];
                    const affectedRange = pkg.affected_range || null;
                    const dependencyType = pkg.dependency_type || null;
                    
                    // vulnerability 정보
                    const vulnId = vulnInfo.id || null;
                    const cve = vulnInfo.cve || null;
                    const cvss = vulnInfo.cvss != null ? vulnInfo.cvss : null; // 0도 유효한 값
                    const severity = vulnInfo.severity || null;
                    const title = vulnInfo.title || null;
                    const description = vulnInfo.description || null;
                    const referenceUrl = vulnInfo.reference_url || null;
                    
                    // reachability 정보
                    const reachable = vuln.reachable === true ? 1 : 0;
                    const functionsCount = vuln.functions_count || 0;
                    const reachableFunctions = vuln.reachable_functions || 0;
                    const unreachableFunctions = vuln.unreachable_functions || 0;
                    
                    insertOssStmt.run(
                      scanId,
                      scan_path,
                      mcp_server_name || null, // mcp_server_name 추가 (API 파라미터에서 가져옴)
                      getKoreaTimeSQLite(),
                      packageName,
                      currentVersion,
                      fixedVersion,
                      JSON.stringify(allFixedVersions),
                      affectedRange,
                      dependencyType,
                      vulnId,
                      cve,
                      cvss,
                      severity,
                      title,
                      description,
                      referenceUrl,
                      reachable,
                      functionsCount,
                      reachableFunctions,
                      unreachableFunctions,
                      JSON.stringify(vuln)
                    );
                    successCount++;
                  } catch (insertError) {
                    errorCount++;
                    console.error('OSS 취약점 저장 오류:', insertError);
                    console.error('에러 메시지:', insertError.message);
                    console.error('에러 스택:', insertError.stack);
                    console.error('저장 실패한 취약점:', JSON.stringify(vuln, null, 2));
                  }
                }
                
                console.log(`[OSS] OSS 취약점 저장 완료: 성공 ${successCount}개, 실패 ${errorCount}개 (총 ${dashboardVulnerabilities.length}개)`);
                
                // 저장한 데이터 다시 조회 (mcp_server_name이 있으면 필터링)
                if (mcp_server_name) {
                  const normalizedServerName = normalizeServerName(scan_path, mcp_server_name);
                  vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_path = ? AND (mcp_server_name = ? OR mcp_server_name = ?) ORDER BY scan_timestamp DESC, id DESC').all(scan_path, mcp_server_name, normalizedServerName);
                  console.log(`[OSS] 데이터베이스에서 조회된 취약점 개수 (서버 필터링): ${vulnerabilities.length}`);
                } else {
                  vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
                  console.log(`[OSS] 데이터베이스에서 조회된 취약점 개수: ${vulnerabilities.length}`);
                }
              } else {
                console.log(`dashboard.json에 취약점이 없습니다 (vulnerabilities 배열이 비어있음)`);
              }
            } catch (fileError) {
              console.log(`[OSS] dashboard.json 파일을 찾을 수 없거나 읽을 수 없습니다: ${dashboardFile}`);
              console.log(`[OSS] 파일 에러:`, fileError.message);
              
              // 파일을 찾지 못한 경우, output 디렉토리의 모든 dashboard.json 파일 확인
              try {
                const allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
                const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
                console.log(`[OSS] 발견된 dashboard.json 파일들:`, dashboardFiles);
                
                // 파일명에 repoName이 포함된 파일 찾기 (더 정확한 매칭)
                const matchingFiles = dashboardFiles.filter(f => {
                  const fileLower = f.toLowerCase();
                  const repoNameLower = repoName.toLowerCase();
                  const fileBaseName = f.replace('-dashboard.json', '').toLowerCase();
                  
                  // 정확한 매칭 또는 부분 매칭
                  return fileBaseName === repoNameLower || 
                         fileBaseName.includes(repoNameLower) || 
                         repoNameLower.includes(fileBaseName) ||
                         fileLower.includes(repoNameLower) || 
                         repoNameLower.includes(fileLower.replace('-dashboard.json', ''));
                });
                
                if (matchingFiles.length > 0) {
                  console.log(`[OSS] 매칭되는 파일 발견: ${matchingFiles.join(', ')}`);
                  // 가장 최근 파일 사용 시도
                  const latestFile = path.join(BOMTORI_OUTPUT_DIR, matchingFiles[0]);
                  console.log(`[OSS] 사용할 파일: ${latestFile}`);
                  try {
                    const dashboardData = JSON.parse(await fs.readFile(latestFile, 'utf-8'));
                    const dashboardVulnerabilities = dashboardData.vulnerabilities || [];
                    console.log(`대체 파일에서 발견된 취약점 개수: ${dashboardVulnerabilities.length}`);
                    
                    if (dashboardVulnerabilities.length > 0) {
                      const scanId = uuidv4();
                      // 기존 데이터 삭제
                      try {
                        const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ?');
                        deleteOssStmt.run(scan_path);
                      } catch (deleteError) {
                        console.error('기존 OSS 취약점 데이터 삭제 오류:', deleteError);
                      }
                      
                      // 저장 로직 (위와 동일)
                      const insertOssStmt = db.prepare(`
                        INSERT INTO oss_vulnerabilities (
                          scan_id, scan_path, mcp_server_name, scan_timestamp,
                          package_name, package_version, package_fixed_version, package_all_fixed_versions,
                          package_affected_range, package_dependency_type,
                          vulnerability_id, vulnerability_cve, vulnerability_cvss, vulnerability_severity,
                          vulnerability_title, vulnerability_description, vulnerability_reference_url,
                          reachable, functions_count, reachable_functions, unreachable_functions, raw_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                      `);
                      
                      let successCount = 0;
                      let errorCount = 0;
                      
                      for (const vuln of dashboardVulnerabilities) {
                        try {
                          const pkg = vuln.package || {};
                          const vulnInfo = vuln.vulnerability || {};
                          
                          const packageName = pkg.name || null;
                          // Go 프로젝트 버전에서 "v" 접두사 제거
                          const currentVersion = removeVersionPrefix(pkg.current_version) || null;
                          const fixedVersion = removeVersionPrefix(pkg.fixed_version) || null;
                          const allFixedVersions = Array.isArray(pkg.all_fixed_versions) 
                            ? pkg.all_fixed_versions.map(v => removeVersionPrefix(v))
                            : [];
                          const affectedRange = pkg.affected_range || null;
                          const dependencyType = pkg.dependency_type || null;
                          
                          const vulnId = vulnInfo.id || null;
                          const cve = vulnInfo.cve || null;
                          const cvss = vulnInfo.cvss != null ? vulnInfo.cvss : null;
                          const severity = vulnInfo.severity || null;
                          const title = vulnInfo.title || null;
                          const description = vulnInfo.description || null;
                          const referenceUrl = vulnInfo.reference_url || null;
                          
                          const reachable = vuln.reachable === true ? 1 : 0;
                          const functionsCount = vuln.functions_count || 0;
                          const reachableFunctions = vuln.reachable_functions || 0;
                          const unreachableFunctions = vuln.unreachable_functions || 0;
                          
                          insertOssStmt.run(
                            scanId,
                            scan_path,
                            mcp_server_name || null, // mcp_server_name 추가 (API 파라미터에서 가져옴)
                            getKoreaTimeSQLite(),
                            packageName,
                            currentVersion,
                            fixedVersion,
                            JSON.stringify(allFixedVersions),
                            affectedRange,
                            dependencyType,
                            vulnId,
                            cve,
                            cvss,
                            severity,
                            title,
                            description,
                            referenceUrl,
                            reachable,
                            functionsCount,
                            reachableFunctions,
                            unreachableFunctions,
                            JSON.stringify(vuln)
                          );
                          successCount++;
                        } catch (insertError) {
                          errorCount++;
                          console.error('OSS 취약점 저장 오류:', insertError);
                          console.error('저장 실패한 취약점:', JSON.stringify(vuln, null, 2));
                        }
                      }
                      
                      console.log(`대체 파일에서 OSS 취약점 저장 완료: 성공 ${successCount}개, 실패 ${errorCount}개`);
                      vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
                      console.log(`데이터베이스에서 조회된 취약점 개수: ${vulnerabilities.length}`);
                    }
                  } catch (readError) {
                    console.error('대체 파일 읽기 실패:', readError);
                  }
                }
              } catch (dirError) {
                console.error('output 디렉토리 읽기 실패:', dirError);
              }
            }
          } catch (loadError) {
            console.error('dashboard.json 파일에서 OSS 취약점 로드 오류:', loadError);
          }
        }
      }
      
      // raw_data JSON 파싱
      const findings = vulnerabilities.map(v => {
        const finding = {
          package: {
            name: v.package_name,
            current_version: v.package_version,
            fixed_version: v.package_fixed_version,
            all_fixed_versions: v.package_all_fixed_versions ? JSON.parse(v.package_all_fixed_versions) : [],
            affected_range: v.package_affected_range,
            dependency_type: v.package_dependency_type
          },
          vulnerability: {
            id: v.vulnerability_id,
            cve: v.vulnerability_cve,
            cvss: v.vulnerability_cvss,
            severity: v.vulnerability_severity,
            title: v.vulnerability_title,
            description: v.vulnerability_description,
            reference_url: v.vulnerability_reference_url
          },
          reachable: v.reachable === 1,
          functions_count: v.functions_count,
          reachable_functions: v.reachable_functions,
          unreachable_functions: v.unreachable_functions
        };
        
        // raw_data가 있으면 파싱하여 추가
        if (v.raw_data) {
          try {
            const rawData = JSON.parse(v.raw_data);
            // rawData에 functions 배열이 있으면 finding에 포함
            if (rawData.functions && Array.isArray(rawData.functions)) {
              finding.functions = rawData.functions;
            }
            return { ...finding, rawData };
          } catch (e) {
            return { ...finding, rawData: v.raw_data };
          }
        }
        
        return finding;
      });
      
      // packages 배열도 함께 반환 (license 정보 포함)
      // 무조건 dashboard.json 파일에서 packages를 로드
      let packages = [];
      let projectType = null; // 프로젝트 타입 (언어 정보)
      let actualScanPath = scan_path;
      
      // 강제로 stdout에 출력 (버퍼링 방지)
      process.stdout.write(`[OSS] ========== packages 로드 시작 ==========\n`);
      process.stdout.write(`[OSS] scan_path=${scan_path}, scan_id=${scan_id}, vulnerabilities.length=${vulnerabilities.length}\n`);
      console.log(`[OSS] ========== packages 로드 시작 ==========`);
      console.log(`[OSS] scan_path=${scan_path}, scan_id=${scan_id}, vulnerabilities.length=${vulnerabilities.length}`);
      
      // scan_path나 scan_id가 없으면, 모든 dashboard.json 파일을 확인하여 packages가 있는 파일 찾기
      if (!actualScanPath && !scan_id) {
        console.log(`[OSS] scan_path와 scan_id가 모두 없음 - 모든 dashboard.json 파일 확인`);
        try {
          const allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
          const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
          console.log(`[OSS] 발견된 dashboard.json 파일들:`, dashboardFiles);
          
          // 모든 dashboard.json 파일을 순회하여 packages가 있는 파일 찾기
          for (const dashboardFile of dashboardFiles) {
            const filePath = path.join(BOMTORI_OUTPUT_DIR, dashboardFile);
            try {
              const dashboardData = JSON.parse(await fs.readFile(filePath, 'utf-8'));
              const filePackages = dashboardData.packages || [];
              console.log(`[OSS] ${dashboardFile}에서 packages: ${filePackages.length}개`);
              if (filePackages.length > 0) {
                packages = filePackages;
                console.log(`[OSS] ✅✅✅ ${dashboardFile}에서 ${packages.length}개 패키지 로드 완료 ✅✅✅`);
                console.log(`[OSS] packages 샘플 (처음 3개):`, packages.slice(0, 3).map(p => ({ name: p.name, dependency_type: p.dependency_type })));
                break;
              }
            } catch (readError) {
              console.error(`[OSS] ${dashboardFile} 읽기 실패:`, readError.message);
            }
          }
        } catch (dirError) {
          console.error('[OSS] 디렉토리 읽기 실패:', dirError.message);
        }
      }
      
      // scan_id로 조회한 경우 scan_path를 가져오기 (모든 경로에서 동일하게 처리)
      if (!actualScanPath && vulnerabilities.length > 0) {
        actualScanPath = vulnerabilities[0].scan_path;
        console.log(`[OSS] scan_id로 조회: scan_path 추출됨 - ${actualScanPath}`);
      }
      
      // scan_path가 여전히 없으면 scan_id로 조회한 경우에도 scan_path를 다시 시도
      if (!actualScanPath && scan_id) {
        const scanPathFromDb = db.prepare('SELECT DISTINCT scan_path FROM oss_vulnerabilities WHERE scan_id = ? LIMIT 1').get(scan_id);
        if (scanPathFromDb && scanPathFromDb.scan_path) {
          actualScanPath = scanPathFromDb.scan_path;
          console.log(`[OSS] scan_id로 scan_path 재조회: ${actualScanPath}`);
        }
      }
      
      console.log(`[OSS] 최종 actualScanPath: ${actualScanPath}`);
      
      // actualScanPath가 있으면 해당 파일을 먼저 시도
      if (actualScanPath) {
        try {
          let repoName;
          
          // GitHub URL인 경우
          if (isValidGithubUrl(actualScanPath)) {
            // repo_name 추출 (실제 파일명은 repo-dashboard.json 형식)
            // GitHub URL 형식: https://github.com/owner/repo
            const urlParts = actualScanPath.split('/');
            if (urlParts.length >= 2) {
              // owner/repo 형식에서 repo만 추출
              let tempRepoName = urlParts[urlParts.length - 1].replace('.git', '');
              repoName = tempRepoName.replace(/[^a-zA-Z0-9_-]/g, '_');
            } else {
              let tempRepoName = actualScanPath.split('/').pop().replace('.git', '');
              repoName = tempRepoName.replace(/[^a-zA-Z0-9_-]/g, '_');
            }
          } else {
            // GitHub URL이 아닌 경우 (예: notion-mcp-server), scan_path 자체를 repoName으로 사용
            repoName = actualScanPath.replace(/[^a-zA-Z0-9_-]/g, '_');
          }
          
          const dashboardFile = path.join(BOMTORI_OUTPUT_DIR, `${repoName}-dashboard.json`);
          
          console.log(`[OSS] dashboard.json 파일 로드 시도: ${dashboardFile}`);
          console.log(`[OSS] repoName: ${repoName}, actualScanPath: ${actualScanPath}`);
          
          try {
            await fs.access(dashboardFile);
            const dashboardData = JSON.parse(await fs.readFile(dashboardFile, 'utf-8'));
            packages = dashboardData.packages || [];
            console.log(`[OSS] ✅ packages 배열 로드 완료: ${packages.length}개 패키지`);
            console.log(`[OSS] dashboard.json 파일 경로: ${dashboardFile}`);
            if (packages.length > 0) {
              console.log(`[OSS] packages 배열 샘플 (처음 3개):`, packages.slice(0, 3).map(p => ({ name: p.name, dependency_type: p.dependency_type })));
            }
          } catch (fileError) {
            console.log(`[OSS] ❌ dashboard.json 파일을 찾을 수 없습니다: ${dashboardFile}`);
            console.log(`[OSS] 파일 에러:`, fileError.message);
            
            // 파일을 찾지 못한 경우, output 디렉토리의 모든 dashboard.json 파일 확인
            try {
              const allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
              console.log(`[OSS] BOMTORI_OUTPUT_DIR: ${BOMTORI_OUTPUT_DIR}`);
              console.log(`[OSS] BOMTORI_OUTPUT_DIR의 모든 파일:`, allFiles);
              const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
              console.log(`[OSS] 발견된 dashboard.json 파일들:`, dashboardFiles);
              
              // 파일명에 repoName이 포함된 파일 찾기 (더 정확한 매칭)
              const matchingFiles = dashboardFiles.filter(f => {
                const fileLower = f.toLowerCase();
                const repoNameLower = repoName.toLowerCase();
                const fileBaseName = f.replace('-dashboard.json', '').toLowerCase();
                
                // 정확한 매칭 또는 부분 매칭
                return fileBaseName === repoNameLower || 
                       fileBaseName.includes(repoNameLower) || 
                       repoNameLower.includes(fileBaseName) ||
                       fileLower.includes(repoNameLower) || 
                       repoNameLower.includes(fileLower.replace('-dashboard.json', ''));
              });
              
              console.log(`[OSS] 매칭되는 파일들:`, matchingFiles);
              
              if (matchingFiles.length > 0) {
                // 매칭되는 파일 중 packages가 있는 파일 찾기
                for (const matchingFile of matchingFiles) {
                  const latestFile = path.join(BOMTORI_OUTPUT_DIR, matchingFile);
                  console.log(`[OSS] 대체 파일 시도: ${latestFile}`);
                  try {
                    const dashboardData = JSON.parse(await fs.readFile(latestFile, 'utf-8'));
                    const filePackages = dashboardData.packages || [];
                    console.log(`[OSS] ${matchingFile}에서 packages: ${filePackages.length}개`);
                    if (filePackages.length > 0) {
                      packages = filePackages;
                      console.log(`[OSS] ✅ 대체 파일에서 packages 배열 로드 완료: ${packages.length}개 패키지 (파일: ${matchingFile})`);
                      console.log(`[OSS] packages 배열 샘플 (처음 3개):`, packages.slice(0, 3).map(p => ({ name: p.name, dependency_type: p.dependency_type })));
                      break; // packages를 찾았으면 중단
                    }
                  } catch (readError) {
                    console.error(`[OSS] ${matchingFile} 읽기 실패:`, readError);
                  }
                }
              } else {
                // 매칭되는 파일이 없으면 모든 dashboard.json 파일 시도
                console.log(`[OSS] 매칭되는 파일이 없어서 모든 dashboard.json 파일 시도`);
                for (const dashboardFile of dashboardFiles) {
                  const filePath = path.join(BOMTORI_OUTPUT_DIR, dashboardFile);
                  console.log(`[OSS] 파일 시도: ${filePath}`);
                  try {
                    const dashboardData = JSON.parse(await fs.readFile(filePath, 'utf-8'));
                    const filePackages = dashboardData.packages || [];
                    console.log(`[OSS] ${dashboardFile}에서 packages: ${filePackages.length}개`);
                    if (filePackages.length > 0) {
                      packages = filePackages;
                      console.log(`[OSS] ✅ ${dashboardFile}에서 packages 배열 로드 완료: ${packages.length}개 패키지`);
                      console.log(`[OSS] packages 배열 샘플 (처음 3개):`, packages.slice(0, 3).map(p => ({ name: p.name, dependency_type: p.dependency_type })));
                      break; // packages를 찾았으면 중단
                    }
                  } catch (readError) {
                    console.error(`[OSS] ${dashboardFile} 읽기 실패:`, readError);
                  }
                }
              }
            } catch (dirError) {
              console.error('[OSS] output 디렉토리 읽기 실패:', dirError);
            }
          }
        } catch (loadError) {
          console.error('[OSS] dashboard.json 파일에서 packages 로드 오류:', loadError);
        }
      }
      
      // packages가 아직 로드되지 않았으면 무조건 모든 dashboard.json 파일을 확인하여 로드 시도
      if (packages.length === 0) {
        console.log(`[OSS] ⚠️ packages가 0개이므로 모든 dashboard.json 파일에서 packages 로드 시도`);
        console.log(`[OSS] BOMTORI_OUTPUT_DIR 절대 경로: ${BOMTORI_OUTPUT_DIR}`);
        console.log(`[OSS] __dirname: ${__dirname}`);
        console.log(`[OSS] BOMTORI_ROOT: ${BOMTORI_ROOT}`);
        
        try {
          // 디렉토리 존재 확인
          try {
            await fs.access(BOMTORI_OUTPUT_DIR);
            console.log(`[OSS] ✅ BOMTORI_OUTPUT_DIR 존재 확인됨`);
          } catch (accessError) {
            console.error(`[OSS] ❌ BOMTORI_OUTPUT_DIR 접근 실패:`, accessError.message);
            console.error(`[OSS] 경로: ${BOMTORI_OUTPUT_DIR}`);
          }
          
          const allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
          console.log(`[OSS] 모든 파일 (${allFiles.length}개):`, allFiles);
          const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
          console.log(`[OSS] 발견된 dashboard.json 파일들 (${dashboardFiles.length}개):`, dashboardFiles);
          
          if (dashboardFiles.length > 0) {
            // 모든 dashboard.json 파일을 시도하여 packages가 있는 파일 찾기
            for (const dashboardFile of dashboardFiles) {
              const filePath = path.join(BOMTORI_OUTPUT_DIR, dashboardFile);
              console.log(`[OSS] 📄 파일 시도: ${filePath}`);
              try {
                const fileStats = await fs.stat(filePath);
                console.log(`[OSS] 파일 크기: ${fileStats.size} bytes`);
                
                const dashboardData = JSON.parse(await fs.readFile(filePath, 'utf-8'));
                const filePackages = dashboardData.packages || [];
                console.log(`[OSS] ${dashboardFile}에서 packages: ${filePackages.length}개`);
                
                if (filePackages.length > 0) {
                  packages = filePackages;
                  console.log(`[OSS] ✅✅✅ ${dashboardFile}에서 packages 배열 로드 완료: ${packages.length}개 패키지 ✅✅✅`);
                  console.log(`[OSS] packages 배열 샘플 (처음 3개):`, packages.slice(0, 3).map(p => ({ name: p.name, dependency_type: p.dependency_type })));
                  break; // packages를 찾았으면 중단
                } else {
                  console.log(`[OSS] ⚠️ ${dashboardFile}에 packages 배열이 비어있거나 없습니다.`);
                }
              } catch (readError) {
                console.error(`[OSS] ❌ ${dashboardFile} 읽기 실패:`, readError.message);
                console.error(`[OSS] 에러 스택:`, readError.stack);
              }
            }
          } else {
            console.log(`[OSS] ❌ dashboard.json 파일을 찾을 수 없습니다.`);
          }
        } catch (dirError) {
          console.error('[OSS] ❌ output 디렉토리 읽기 실패:', dirError.message);
          console.error('[OSS] 에러 스택:', dirError.stack);
        }
      }
      
      // packages가 여전히 0개이면 무조건 모든 dashboard.json 파일에서 찾기
      if (packages.length === 0) {
        console.log(`[OSS] ⚠️⚠️⚠️ 최종 확인: packages가 0개이므로 강제로 모든 dashboard.json 파일 확인 ⚠️⚠️⚠️`);
        try {
          const allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
          console.log(`[OSS] BOMTORI_OUTPUT_DIR 절대 경로: ${BOMTORI_OUTPUT_DIR}`);
          console.log(`[OSS] 모든 파일 (${allFiles.length}개):`, allFiles);
          const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
          console.log(`[OSS] 발견된 dashboard.json 파일들 (${dashboardFiles.length}개):`, dashboardFiles);
          
          // 모든 dashboard.json 파일을 순회하여 packages가 있는 파일 찾기
          for (const dashboardFile of dashboardFiles) {
            const filePath = path.join(BOMTORI_OUTPUT_DIR, dashboardFile);
            console.log(`[OSS] 📄 파일 읽기 시도: ${filePath}`);
            try {
              const fileStats = await fs.stat(filePath);
              console.log(`[OSS] 파일 크기: ${fileStats.size} bytes, 수정 시간: ${fileStats.mtime}`);
              
              const fileContent = await fs.readFile(filePath, 'utf-8');
              console.log(`[OSS] 파일 내용 길이: ${fileContent.length} characters`);
              
              const dashboardData = JSON.parse(fileContent);
              const filePackages = dashboardData.packages || [];
              console.log(`[OSS] ${dashboardFile}에서 packages: ${filePackages.length}개`);
              
              if (filePackages.length > 0) {
                packages = filePackages;
                
                // 프로젝트 타입 추출 (packages의 ecosystem 정보 우선 사용)
                // library, application 같은 값은 무시하고 실제 언어 정보만 사용
                if (!projectType && packages.length > 0) {
                  // packages에서 ecosystem 정보로 프로젝트 타입 추론
                  const ecosystems = new Set();
                  packages.forEach(pkg => {
                    // ecosystem 필드 우선 확인
                    if (pkg.ecosystem) {
                      ecosystems.add(pkg.ecosystem);
                    } else if (pkg.purl) {
                      // PURL에서 언어 정보 추출 (예: pkg:npm/... -> npm)
                      const purlMatch = pkg.purl.match(/^pkg:([^\/]+)/);
                      if (purlMatch) {
                        ecosystems.add(purlMatch[1]);
                      }
                    }
                  });
                  
                  const ecosystemToProjectType = {
                    'npm': 'npm',
                    'go': 'go',
                    'golang': 'go'
                  };
                  
                  const projectTypes = Array.from(ecosystems).map(eco => {
                    return ecosystemToProjectType[eco.toLowerCase()] || eco.toLowerCase();
                  });
                  
                  if (projectTypes.length > 0) {
                    projectType = projectTypes.join(', ');
                  }
                }
                
                // packages에서 추출하지 못한 경우에만 dashboard의 project_type 확인 (library, application 제외)
                if (!projectType) {
                  if (dashboardData.project_type && 
                      dashboardData.project_type !== 'library' && 
                      dashboardData.project_type !== 'application') {
                    projectType = dashboardData.project_type;
                  } else if (dashboardData.application && dashboardData.application.stack) {
                    projectType = dashboardData.application.stack;
                  }
                }
                
                console.log(`[OSS] ✅✅✅ 최종 성공: ${dashboardFile}에서 ${packages.length}개 패키지 로드 ✅✅✅`);
                console.log(`[OSS] 프로젝트 타입: ${projectType || '알 수 없음'}`);
                console.log(`[OSS] packages 샘플 (처음 5개):`, packages.slice(0, 5).map(p => ({ 
                  name: p.name, 
                  dependency_type: p.dependency_type,
                  version: p.version 
                })));
                break;
              } else {
                console.log(`[OSS] ⚠️ ${dashboardFile}에 packages 배열이 비어있습니다.`);
              }
            } catch (readError) {
              console.error(`[OSS] ❌ ${dashboardFile} 읽기 실패:`, readError.message);
              console.error(`[OSS] 에러 스택:`, readError.stack);
            }
          }
        } catch (dirError) {
          console.error('[OSS] ❌ 디렉토리 읽기 실패:', dirError.message);
          console.error('[OSS] 에러 스택:', dirError.stack);
        }
      }
      
      console.log(`[OSS] ========== 최종 응답 전송 ==========`);
      console.log(`[OSS] findings: ${findings.length}개`);
      console.log(`[OSS] packages: ${packages.length}개`);
      if (packages.length > 0) {
        console.log(`[OSS] packages 샘플:`, packages.slice(0, 3).map(p => ({ name: p.name, dependency_type: p.dependency_type })));
      }
      
      // CDX JSON 파일에서 dependencies 정보 추출
      let cdxDependencies = null;
      try {
        let cdxFilePath = null;
        
        // dashboard.json 파일이 로드된 경우, 같은 이름의 CDX JSON 파일 찾기
        // dashboard.json 파일 경로 찾기
        let dashboardFilePath = null;
        
        if (actualScanPath || scan_id) {
          let repoName = '';
          if (actualScanPath) {
            // GitHub URL인 경우
            if (actualScanPath.includes('github.com')) {
              const match = actualScanPath.match(/github\.com\/([^\/]+\/[^\/]+)/);
              if (match) {
                repoName = match[1].replace(/[^a-zA-Z0-9_-]/g, '_');
              }
            } else {
              // 로컬 경로인 경우
              repoName = path.basename(actualScanPath.replace(/\.git$/, ''));
              repoName = repoName.replace(/[^a-zA-Z0-9_-]/g, '_');
            }
          } else {
            repoName = scan_id.replace(/[^a-zA-Z0-9_-]/g, '_');
          }
          
          // dashboard.json과 같은 이름으로 sbom.cdx.json 파일 찾기
          const possibleCdxFiles = [
            `${repoName}-sbom.cdx.json`,
            `${repoName}.sbom.cdx.json`,
            `${repoName}-dashboard.json`.replace('-dashboard.json', '-sbom.cdx.json')
          ];
          
          for (const fileName of possibleCdxFiles) {
            const testPath = path.join(BOMTORI_OUTPUT_DIR, fileName);
            try {
              await fs.access(testPath);
              cdxFilePath = testPath;
              console.log(`[OSS] CDX JSON 파일 발견: ${fileName}`);
              break;
            } catch (e) {
              // 파일 없음, 다음 시도
            }
          }
        }
        
        // 파일명 패턴으로 찾지 못했으면 모든 .sbom.cdx.json 파일 확인
        if (!cdxFilePath) {
          try {
            const allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
            const cdxFiles = allFiles.filter(f => f.includes('sbom.cdx.json') || (f.includes('.cdx.json') && !f.includes('metadata')));
            if (cdxFiles.length > 0) {
              // 파일 수정 시간으로 정렬하여 가장 최근 파일 사용
              const cdxFilesWithStats = await Promise.all(
                cdxFiles.map(async (file) => {
                  const filePath = path.join(BOMTORI_OUTPUT_DIR, file);
                  const stats = await fs.stat(filePath);
                  return { file, path: filePath, mtime: stats.mtime };
                })
              );
              cdxFilesWithStats.sort((a, b) => b.mtime - a.mtime);
              cdxFilePath = cdxFilesWithStats[0].path;
              console.log(`[OSS] CDX JSON 파일 발견 (가장 최근): ${cdxFilesWithStats[0].file}`);
            }
          } catch (e) {
            console.log(`[OSS] CDX JSON 파일 검색 실패:`, e.message);
          }
        }
        
        // CDX JSON 파일 읽기
        if (cdxFilePath) {
          const cdxData = JSON.parse(await fs.readFile(cdxFilePath, 'utf-8'));
          if (cdxData.dependencies && Array.isArray(cdxData.dependencies)) {
            cdxDependencies = cdxData.dependencies;
            console.log(`[OSS] ✅ CDX dependencies 추출 완료: ${cdxDependencies.length}개 의존성`);
          } else {
            console.log(`[OSS] ⚠️ CDX JSON 파일에 dependencies 배열이 없음`);
          }
        } else {
          console.log(`[OSS] ⚠️ CDX JSON 파일을 찾을 수 없음`);
        }
      } catch (cdxError) {
        console.log(`[OSS] CDX JSON dependencies 추출 실패 (무시):`, cdxError.message);
        // 오류가 발생해도 계속 진행
      }
      
      res.json({
        success: true,
        data: findings,
        packages: packages,
        cdxDependencies: cdxDependencies, // CDX JSON의 dependencies 정보 추가
        projectType: projectType // 프로젝트 타입 (언어 정보) 추가
      });
    } catch (error) {
      console.error('OSS 취약점 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'OSS 취약점 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 스캔 결과 조회 (데이터베이스에서 조회)
  getCodeVulnerabilities: async (req, res) => {
    try {
      const { scan_id, scan_path, mcp_server_name } = req.query;
      
      console.log(`[CODE] getCodeVulnerabilities 호출: scan_id=${scan_id}, scan_path=${scan_path}, mcp_server_name=${mcp_server_name}`);
      
      // mcp_server_name 정규화 (프론트엔드에서 전달된 서버 이름을 정규화)
      const normalizedServerName = mcp_server_name ? normalizeServerName(scan_path, mcp_server_name) : null;
      console.log(`[CODE] 정규화된 서버 이름: ${normalizedServerName} (원본: ${mcp_server_name})`);
      
      let vulnerabilities = [];
      
      if (scan_id) {
        // scan_id로 조회
        if (normalizedServerName) {
          // 정규화된 서버 이름으로 필터링 (정확 일치 또는 정규화된 이름으로 매칭)
          vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_id = ? AND (mcp_server_name = ? OR LOWER(REPLACE(mcp_server_name, \' \', \'-\')) = ?) ORDER BY scan_timestamp DESC, id DESC').all(scan_id, mcp_server_name, normalizedServerName);
          console.log(`[CODE] scan_id로 조회 (서버 필터링, 정규화): ${vulnerabilities.length}개 발견`);
          
          // 정규화된 이름으로 매칭 실패 시 정규화된 이름만으로 시도
          if (vulnerabilities.length === 0) {
            vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_id = ? AND LOWER(REPLACE(mcp_server_name, \' \', \'-\')) = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_id, normalizedServerName);
            console.log(`[CODE] scan_id로 조회 (정규화된 이름만): ${vulnerabilities.length}개 발견`);
          }
        } else {
        vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_id);
          console.log(`[CODE] scan_id로 조회: ${vulnerabilities.length}개 발견`);
        }
      } else if (scan_path) {
        // scan_path로 최신 스캔 결과 조회
        if (normalizedServerName) {
          // 정규화된 서버 이름으로 필터링
          let query = 'SELECT DISTINCT scan_id FROM code_vulnerabilities WHERE scan_path = ? AND (mcp_server_name = ? OR LOWER(REPLACE(mcp_server_name, \' \', \'-\')) = ?) ORDER BY scan_timestamp DESC LIMIT 1';
          const latestScan = db.prepare(query).get(scan_path, mcp_server_name, normalizedServerName);
          if (latestScan && latestScan.scan_id) {
            vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_id = ? AND (mcp_server_name = ? OR LOWER(REPLACE(mcp_server_name, \' \', \'-\')) = ?) ORDER BY scan_timestamp DESC, id DESC').all(latestScan.scan_id, mcp_server_name, normalizedServerName);
            console.log(`[CODE] scan_path로 최신 scan_id 조회 (서버 필터링, 정규화): ${vulnerabilities.length}개 발견`);
          } else {
            // 정규화된 이름만으로 시도
            vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_path = ? AND LOWER(REPLACE(mcp_server_name, \' \', \'-\')) = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path, normalizedServerName);
            console.log(`[CODE] scan_path로 직접 조회 (정규화된 이름): ${vulnerabilities.length}개 발견`);
          }
          
          // 여전히 없으면 scan_path의 최신 리포트에서 mcp_server_name 가져오기
          if (vulnerabilities.length === 0) {
            const reportInfo = db.prepare('SELECT mcp_server_name FROM tool_validation_reports WHERE scan_path = ? ORDER BY scan_timestamp DESC LIMIT 1').get(scan_path);
            if (reportInfo && reportInfo.mcp_server_name) {
              const reportServerName = normalizeServerName(scan_path, reportInfo.mcp_server_name);
              console.log(`[CODE] 리포트에서 서버 이름 발견: ${reportInfo.mcp_server_name} -> ${reportServerName}`);
              vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path, reportServerName);
              console.log(`[CODE] 리포트의 서버 이름으로 조회: ${vulnerabilities.length}개 발견`);
            }
          }
          
          // 여전히 없으면 scan_path만으로 조회 (하위 호환성)
          if (vulnerabilities.length === 0) {
        const latestScan = db.prepare('SELECT DISTINCT scan_id FROM code_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC LIMIT 1').get(scan_path);
        if (latestScan && latestScan.scan_id) {
          vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(latestScan.scan_id);
              console.log(`[CODE] scan_path로 최신 scan_id 조회 (서버 필터링 실패, 전체 조회): ${vulnerabilities.length}개 발견`);
        } else {
          vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
              console.log(`[CODE] scan_path로 직접 조회 (서버 필터링 실패, 전체 조회): ${vulnerabilities.length}개 발견`);
            }
          }
        } else {
          // mcp_server_name이 없으면 기존 로직 사용
          const latestScan = db.prepare('SELECT DISTINCT scan_id FROM code_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC LIMIT 1').get(scan_path);
          if (latestScan && latestScan.scan_id) {
            vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(latestScan.scan_id);
            console.log(`[CODE] scan_path로 최신 scan_id 조회: ${vulnerabilities.length}개 발견`);
          } else {
            vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
            console.log(`[CODE] scan_path로 직접 조회: ${vulnerabilities.length}개 발견`);
          }
        }
      }
      
      // raw_finding JSON 파싱
      const findings = vulnerabilities.map(v => {
        const finding = {
          rule_id: v.rule_id,
          vulnerability: v.vulnerability,
          severity: v.severity,
          language: v.language,
          file: v.file,
          line: v.line,
          column: v.column,
          message: v.message,
          description: v.description,
          cwe: v.cwe,
          code_snippet: v.code_snippet,
          pattern_type: v.pattern_type,
          pattern: v.pattern,
          confidence: v.confidence
        };
        
        // raw_finding이 있으면 파싱하여 추가
        if (v.raw_finding) {
          try {
            const rawData = JSON.parse(v.raw_finding);
            return { ...finding, ...rawData, rawFinding: rawData };
          } catch (e) {
            return { ...finding, rawFinding: v.raw_finding };
          }
        }
        
        return finding;
      });
      
      res.json({
        success: true,
        data: findings
      });
    } catch (error) {
      console.error('스캔 결과 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '스캔 결과 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // Tool Validation 취약점 조회
  getToolValidationVulnerabilities: async (req, res) => {
    try {
      const { scan_id, scan_path, mcp_server_name } = req.query;
      
      // mcp_server_name 정규화 (scan_path와 함께 사용)
      // 중요: mcp_server_name이 있으면 반드시 정규화해야 함
      let normalizedServerName = null;
      if (mcp_server_name) {
        normalizedServerName = normalizeServerName(scan_path, mcp_server_name);
      console.log(`[TOOL-VET] getToolValidationVulnerabilities 호출: scan_id=${scan_id}, scan_path=${scan_path}, mcp_server_name=${mcp_server_name} -> normalized=${normalizedServerName}`);
        
        // 정규화 실패 시 경고
        if (!normalizedServerName || normalizedServerName === 'finding') {
          console.warn(`[TOOL-VET] ⚠️ mcp_server_name 정규화 실패 또는 기본값: ${mcp_server_name} -> ${normalizedServerName}`);
        }
      } else {
        console.log(`[TOOL-VET] getToolValidationVulnerabilities 호출: scan_id=${scan_id}, scan_path=${scan_path}, mcp_server_name 없음`);
      }
      
      // scan_id, scan_path, mcp_server_name 중 하나는 있어야 함
      if (!scan_id && !scan_path && !mcp_server_name) {
        return res.status(400).json({
          success: false,
          message: 'scan_id, scan_path, 또는 mcp_server_name 중 하나는 필요합니다.'
        });
      }
      
      // mcp_server_name만 있는 경우: 해당 서버의 최신 스캔 결과 조회
      if (!scan_id && !scan_path && mcp_server_name) {
        // mcp_server_name 정규화 (scan_path가 없으므로 fallback으로 사용)
        const normalizedServerNameForQuery = normalizeServerName(null, mcp_server_name);
        console.log(`[TOOL-VET] mcp_server_name만으로 조회 시도: ${mcp_server_name} -> normalized: ${normalizedServerNameForQuery}`);
        
        // 해당 서버의 최신 scan_id 찾기
        const latestScan = db.prepare(`
          SELECT DISTINCT scan_id, scan_path
          FROM tool_validation_vulnerabilities 
          WHERE mcp_server_name = ?
          ORDER BY scan_timestamp DESC 
          LIMIT 1
        `).get(normalizedServerNameForQuery);
        
        console.log(`[TOOL-VET] latestScan 결과:`, latestScan);
        
        if (latestScan && latestScan.scan_id) {
          // scan_id가 있으면 scan_id로 조회
          const vulnerabilities = db.prepare(`
            SELECT * FROM tool_validation_vulnerabilities 
            WHERE scan_id = ? 
              AND mcp_server_name = ?
            ORDER BY scan_timestamp DESC, id DESC
          `).all(latestScan.scan_id, normalizedServerNameForQuery);
          console.log(`[TOOL-VET] mcp_server_name만으로 조회 (최신 scan_id 사용): ${vulnerabilities.length}개 발견 (서버: ${normalizedServerNameForQuery})`);
          if (vulnerabilities.length > 0) {
            console.log(`[TOOL-VET] 샘플 데이터 (첫 번째):`, {
              tool_name: vulnerabilities[0].tool_name,
              host: vulnerabilities[0].host,
              method: vulnerabilities[0].method,
              path: vulnerabilities[0].path
            });
          }
          return res.json({
            success: true,
            data: vulnerabilities
          });
        } else if (latestScan && latestScan.scan_path) {
          // scan_id가 null이지만 scan_path가 있으면 scan_path로 직접 조회
          const normalizedScanPath = latestScan.scan_path.replace(/\.git$/i, '').toLowerCase();
          console.log(`[TOOL-VET] scan_path로 조회 시도: ${latestScan.scan_path} -> normalized: ${normalizedScanPath}`);
          const vulnerabilities = db.prepare(`
            SELECT * FROM tool_validation_vulnerabilities 
            WHERE LOWER(REPLACE(scan_path, '.git', '')) = ? 
              AND mcp_server_name = ?
            ORDER BY scan_timestamp DESC, id DESC
          `).all(normalizedScanPath, normalizedServerNameForQuery);
          console.log(`[TOOL-VET] mcp_server_name만으로 조회 (scan_path 사용, scan_id가 null): ${vulnerabilities.length}개 발견 (서버: ${normalizedServerNameForQuery})`);
          if (vulnerabilities.length > 0) {
            console.log(`[TOOL-VET] 샘플 데이터 (첫 번째):`, {
              tool_name: vulnerabilities[0].tool_name,
              host: vulnerabilities[0].host,
              method: vulnerabilities[0].method,
              path: vulnerabilities[0].path
            });
          }
          return res.json({
            success: true,
            data: vulnerabilities
          });
        } else {
          console.log(`[TOOL-VET] mcp_server_name으로 조회했지만 데이터 없음: ${normalizedServerNameForQuery}`);
          // 디버깅: 실제로 어떤 mcp_server_name이 있는지 확인
          const allServerNames = db.prepare(`
            SELECT DISTINCT mcp_server_name FROM tool_validation_vulnerabilities 
            WHERE tool_name IN ('kubectl_rollout', 'kubectl_generic')
          `).all();
          console.log(`[TOOL-VET] 데이터베이스에 있는 mcp_server_name 목록:`, allServerNames.map(s => s.mcp_server_name));
          return res.json({
            success: true,
            data: []
          });
        }
      }
      
      let vulnerabilities = [];
      
      if (scan_id) {
        // scan_id로 조회
        // 중요: mcp_server_name이 요청에 있으면 반드시 그것만 사용 (reportInfo의 mcp_server_name은 사용하지 않음)
        if (mcp_server_name) {
          // mcp_server_name이 있으면 반드시 정규화된 이름으로 필터링
          if (!normalizedServerName) {
            console.error(`[TOOL-VET] ⚠️ mcp_server_name이 있지만 정규화 실패: ${mcp_server_name}`);
            return res.status(400).json({
              success: false,
              message: `서버 이름 정규화 실패: ${mcp_server_name}`
            });
          }
          
          // 요청에 mcp_server_name이 있으면 정규화된 이름으로 엄격하게 필터링
          // 먼저 해당 scan_id에 어떤 서버들이 있는지 확인 (디버깅용)
          const allServersInScan = db.prepare(`
            SELECT DISTINCT mcp_server_name 
            FROM tool_validation_vulnerabilities 
            WHERE scan_id = ?
          `).all(scan_id);
          console.log(`[TOOL-VET] scan_id=${scan_id}에 포함된 서버들:`, allServersInScan.map(s => s.mcp_server_name));
          
          vulnerabilities = db.prepare(`
            SELECT * FROM tool_validation_vulnerabilities 
            WHERE scan_id = ? 
              AND mcp_server_name = ?
            ORDER BY scan_timestamp DESC, id DESC
          `).all(scan_id, normalizedServerName);
          console.log(`[TOOL-VET] scan_id + mcp_server_name으로 엄격 필터링: ${vulnerabilities.length}개 (scan_id: ${scan_id}, 요청 서버: ${mcp_server_name}, 정규화된 서버: ${normalizedServerName})`);
          
          // 서버 필터가 있고 결과가 없으면 빈 배열 반환 (다른 서버 데이터로 대체하지 않음)
          if (vulnerabilities.length === 0) {
            console.log(`[TOOL-VET] ⚠️ 서버 필터(${mcp_server_name} -> ${normalizedServerName}) + scan_id=${scan_id} 이지만 데이터 없음 → 빈 배열 반환`);
          return res.json({ success: true, data: [] });
          }
        } else {
          // mcp_server_name이 없으면 scan_id로만 조회 (경고 - 보안상 비권장)
          console.log(`[TOOL-VET] ⚠️ scan_id로만 조회 (mcp_server_name 없음): ${scan_id}`);
          vulnerabilities = db.prepare('SELECT * FROM tool_validation_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_id);
          console.log(`[TOOL-VET] ⚠️ scan_id로만 조회 결과: ${vulnerabilities.length}개 발견`);
        }
      } else if (scan_path) {
        // scan_path 정규화 (GitHub URL의 경우 .git 제거, 소문자 변환)
        let normalizedScanPath = scan_path;
        if (isValidGithubUrl(scan_path)) {
          normalizedScanPath = scan_path.replace(/\.git$/i, '').toLowerCase();
        }
        
        // mcp_server_name이 있으면 추가 필터링
        if (mcp_server_name) {
          // mcp_server_name이 있으면 반드시 정규화된 이름으로 필터링
          if (!normalizedServerName) {
            console.error(`[TOOL-VET] ⚠️ mcp_server_name이 있지만 정규화 실패: ${mcp_server_name}`);
            return res.status(400).json({
              success: false,
              message: `서버 이름 정규화 실패: ${mcp_server_name}`
            });
          }
          
          // 정규화된 scan_path와 정규화된 서버 이름으로 최신 스캔 결과 조회
          // 중요: scan_id가 null이고 host/method/path가 있는 데이터를 우선 조회
          console.log(`[TOOL-VET] scan_path + mcp_server_name으로 조회 시도: scan_path=${scan_path} (정규화: ${normalizedScanPath}), mcp_server_name=${mcp_server_name} (정규화: ${normalizedServerName})`);
          
          // 먼저 scan_id가 null이고 host/method/path가 있는 데이터 조회 (최신 데이터)
          vulnerabilities = db.prepare(`
            SELECT * FROM tool_validation_vulnerabilities 
            WHERE LOWER(REPLACE(scan_path, '.git', '')) = ? 
              AND mcp_server_name = ?
              AND scan_id IS NULL
              AND host IS NOT NULL AND host != ''
              AND method IS NOT NULL AND method != ''
              AND path IS NOT NULL AND path != ''
            ORDER BY scan_timestamp DESC, id DESC
          `).all(normalizedScanPath, normalizedServerName);
          
          console.log(`[TOOL-VET] scan_id가 null인 데이터 조회: ${vulnerabilities.length}개 발견`);
          
          // scan_id가 null인 데이터가 없으면, scan_id가 있는 데이터 중에서도 host/method/path가 있는 것만 조회
          if (vulnerabilities.length === 0) {
            console.log(`[TOOL-VET] scan_id가 null인 데이터 없음. scan_id가 있는 데이터 중 host/method/path가 있는 것 조회 시도`);
            let latestScan = db.prepare(`
              SELECT DISTINCT scan_id 
              FROM tool_validation_vulnerabilities 
              WHERE LOWER(REPLACE(scan_path, '.git', '')) = ? 
                AND mcp_server_name = ?
                AND host IS NOT NULL AND host != ''
                AND method IS NOT NULL AND method != ''
                AND path IS NOT NULL AND path != ''
              ORDER BY scan_timestamp DESC LIMIT 1
            `).get(normalizedScanPath, normalizedServerName);
            
            if (latestScan && latestScan.scan_id) {
              vulnerabilities = db.prepare(`
                SELECT * FROM tool_validation_vulnerabilities 
                WHERE scan_id = ? 
                  AND mcp_server_name = ?
                  AND host IS NOT NULL AND host != ''
                  AND method IS NOT NULL AND method != ''
                  AND path IS NOT NULL AND path != ''
                ORDER BY scan_timestamp DESC, id DESC
              `).all(latestScan.scan_id, normalizedServerName);
              console.log(`[TOOL-VET] scan_id로 조회 (host/method/path 필터링): ${vulnerabilities.length}개 발견`);
            } else {
              // host/method/path가 있는 데이터가 없으면 모든 데이터 조회 (fallback)
              latestScan = db.prepare(`
                SELECT DISTINCT scan_id 
                FROM tool_validation_vulnerabilities 
                WHERE LOWER(REPLACE(scan_path, '.git', '')) = ? 
                  AND mcp_server_name = ?
                ORDER BY scan_timestamp DESC LIMIT 1
              `).get(normalizedScanPath, normalizedServerName);
              
              if (latestScan && latestScan.scan_id) {
                vulnerabilities = db.prepare(`
                  SELECT * FROM tool_validation_vulnerabilities 
                  WHERE scan_id = ? 
                    AND mcp_server_name = ?
                  ORDER BY scan_timestamp DESC, id DESC
                `).all(latestScan.scan_id, normalizedServerName);
                console.log(`[TOOL-VET] scan_id로 조회 (fallback): ${vulnerabilities.length}개 발견`);
              } else {
                // scan_id도 없으면 직접 조회
                vulnerabilities = db.prepare(`
                  SELECT * FROM tool_validation_vulnerabilities 
                  WHERE LOWER(REPLACE(scan_path, '.git', '')) = ? 
                    AND mcp_server_name = ?
                  ORDER BY scan_timestamp DESC, id DESC
                `).all(normalizedScanPath, normalizedServerName);
                console.log(`[TOOL-VET] 직접 조회: ${vulnerabilities.length}개 발견`);
              }
            }
          }
          
          if (vulnerabilities.length > 0) {
            console.log(`[TOOL-VET] 샘플 데이터 (첫 번째):`, {
              tool_name: vulnerabilities[0].tool_name,
              host: vulnerabilities[0].host,
              method: vulnerabilities[0].method,
              path: vulnerabilities[0].path,
              scan_id: vulnerabilities[0].scan_id
            });
            // 최종 응답 전에 host/method/path가 있는지 확인
            const hasHostMethodPath = vulnerabilities.filter(v => 
              v.host && v.host !== '' && 
              v.method && v.method !== '' && 
              v.path && v.path !== ''
            ).length;
            console.log(`[TOOL-VET] host/method/path가 있는 데이터: ${hasHostMethodPath}개 / 전체: ${vulnerabilities.length}개`);
          }
          
          if (vulnerabilities.length === 0) {
            console.log(`[TOOL-VET] ⚠️ scan_path=${scan_path} + mcp_server_name=${normalizedServerName} 이지만 데이터 없음 → 빈 배열 반환`);
            return res.json({ success: true, data: [] });
          }
        } else {
          // mcp_server_name이 없으면 scan_path로만 조회 (경고 - 보안상 비권장)
          // 하지만 mcp_server_name이 요청에 있으면 반드시 필터링해야 함
          console.log(`[TOOL-VET] ⚠️ scan_path로만 조회 (mcp_server_name 없음): ${scan_path}`);
          
          // 정규화된 scan_path로 최신 스캔 결과 조회
          let latestScan = db.prepare(`
            SELECT DISTINCT scan_id, mcp_server_name
            FROM tool_validation_vulnerabilities 
            WHERE LOWER(REPLACE(scan_path, '.git', '')) = ? 
            ORDER BY scan_timestamp DESC LIMIT 1
          `).get(normalizedScanPath);
          
          if (latestScan && latestScan.scan_id) {
            // scan_id로 조회하되, mcp_server_name이 있으면 필터링
            if (mcp_server_name && normalizedServerName) {
              vulnerabilities = db.prepare(`
                SELECT * FROM tool_validation_vulnerabilities 
                WHERE scan_id = ? 
                  AND mcp_server_name = ?
                ORDER BY scan_timestamp DESC, id DESC
              `).all(latestScan.scan_id, normalizedServerName);
              console.log(`[TOOL-VET] scan_path로 조회 (scan_id 사용, mcp_server_name 필터링): ${vulnerabilities.length}개 발견 (서버: ${normalizedServerName})`);
              
              if (vulnerabilities.length === 0) {
                console.log(`[TOOL-VET] ⚠️ scan_path=${scan_path} + mcp_server_name=${normalizedServerName} 이지만 데이터 없음 → 빈 배열 반환`);
                return res.json({ success: true, data: [] });
              }
            } else {
            vulnerabilities = db.prepare('SELECT * FROM tool_validation_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(latestScan.scan_id);
              console.log(`[TOOL-VET] ⚠️ scan_path로 조회 (scan_id 사용, mcp_server_name 없음): ${vulnerabilities.length}개 발견`);
            }
          } else {
            // 정규화된 scan_path로 직접 조회 시도 (scan_id가 없는 경우)
            if (mcp_server_name && normalizedServerName) {
              vulnerabilities = db.prepare(`
                SELECT * FROM tool_validation_vulnerabilities 
                WHERE LOWER(REPLACE(scan_path, '.git', '')) = ? 
                  AND mcp_server_name = ?
                ORDER BY scan_timestamp DESC, id DESC
              `).all(normalizedScanPath, normalizedServerName);
              console.log(`[TOOL-VET] scan_path로 직접 조회 (mcp_server_name 필터링): ${vulnerabilities.length}개 발견 (서버: ${normalizedServerName})`);
              
              if (vulnerabilities.length === 0) {
                console.log(`[TOOL-VET] ⚠️ scan_path=${scan_path} + mcp_server_name=${normalizedServerName} 이지만 데이터 없음 → 빈 배열 반환`);
                return res.json({ success: true, data: [] });
              }
            } else {
            vulnerabilities = db.prepare('SELECT * FROM tool_validation_vulnerabilities WHERE LOWER(REPLACE(scan_path, \'.git\', \'\')) = ? ORDER BY scan_timestamp DESC, id DESC').all(normalizedScanPath);
              console.log(`[TOOL-VET] ⚠️ scan_path로 직접 조회 (mcp_server_name 없음): ${vulnerabilities.length}개 발견`);
            }
          }
        }
        
        // 서버 필터가 있고 결과가 없으면 다른 서버/파일로 대체하지 않고 바로 반환
        if (mcp_server_name && vulnerabilities.length === 0) {
          console.log(`[TOOL-VET] 서버 필터(${mcp_server_name}) + scan_path=${scan_path} 이지만 데이터 없음 → 빈 배열 반환, fallback 차단`);
          return res.json({ success: true, data: [] });
        }

        // 데이터베이스에 데이터가 없고 서버 필터가 없을 때만 리포트 파일에서 직접 로드 시도
        if (!mcp_server_name && vulnerabilities.length === 0 && scan_path) {
          try {
            // TOOL-VET의 extract_repo_name과 동일한 로직으로 repo_name 추출
            const extractRepoNameFromUrl = (gitUrl) => {
              if (!gitUrl) return null;
              let url = gitUrl.replace(/\/$/, '');
              if (url.endsWith('.git')) {
                url = url.slice(0, -4);
              }
              const parts = url.split('/');
              return parts[parts.length - 1];
            };
            
            let repoName = null;
            let possibleRepoNames = [];
            
            if (isValidGithubUrl(scan_path)) {
              // GitHub URL인 경우: TOOL-VET의 extract_repo_name과 동일한 로직 사용
              repoName = extractRepoNameFromUrl(scan_path);
              
              // 여러 가지 가능한 repoName 패턴 시도 (대소문자 변형 포함)
              possibleRepoNames = [
                repoName, // 원본 (대소문자 유지)
                repoName.toLowerCase(), // 소문자
                repoName.replace(/[^a-zA-Z0-9_-]/g, '_'),
                repoName.replace(/[^a-zA-Z0-9_-]/g, '-'),
                repoName.toLowerCase().replace(/[^a-zA-Z0-9_-]/g, '_'),
                repoName.toLowerCase().replace(/[^a-zA-Z0-9_-]/g, '-'),
              ];
            } else {
              // GitHub URL이 아닌 경우: scan_path 자체를 repoName으로 사용
              // 예: "notion-mcp-server" 같은 MCP 서버 이름
              repoName = scan_path.replace(/\.git$/, '');
              possibleRepoNames = [
                repoName,
                repoName.toLowerCase(),
                repoName.replace(/[^a-zA-Z0-9_-]/g, '_'),
                repoName.replace(/[^a-zA-Z0-9_-]/g, '-'),
                repoName.toLowerCase().replace(/[^a-zA-Z0-9_-]/g, '_'),
                repoName.toLowerCase().replace(/[^a-zA-Z0-9_-]/g, '-'),
              ];
            }
            
            console.log(`[TOOL-VET] 데이터베이스에 Tool Validation 취약점이 없어 리포트 파일에서 로드 시도`);
            console.log(`[TOOL-VET] scan_path: "${scan_path}"`);
            console.log(`[TOOL-VET] 정규화된 repoName: "${repoName}"`);
            console.log(`[TOOL-VET] 가능한 repoName 패턴:`, possibleRepoNames);
            
            // 리포트 파일 찾기
            let reportFiles = [];
            let reportJsonFiles = [];
            try {
              reportFiles = await fs.readdir(TOOL_VET_OUTPUT_DIR);
              reportJsonFiles = reportFiles.filter(f => f.endsWith('-report.json'));
              console.log(`[TOOL-VET] 발견된 리포트 파일들:`, reportJsonFiles);
            } catch (dirError) {
              console.error(`[TOOL-VET] output 디렉토리 읽기 실패: ${TOOL_VET_OUTPUT_DIR}`, dirError.message);
              throw dirError; // 상위 catch로 전파
            }
            
            // repoName으로 정확히 매칭되는 파일 찾기
            let reportFile = null;
            for (const possibleName of possibleRepoNames) {
              const expectedReportFile = `${possibleName}-report.json`;
              if (reportFiles.includes(expectedReportFile)) {
                reportFile = expectedReportFile;
                console.log(`정확히 매칭된 리포트 파일 발견: ${reportFile}`);
                break;
              }
            }
            
            // 정확히 매칭되지 않으면, 리포트 파일 이름에서 repo 이름을 추출하여 비교
            if (!reportFile && reportJsonFiles.length > 0) {
              for (const file of reportJsonFiles) {
                const fileRepoName = file.replace('-report.json', '');
                // repoName과 파일 이름이 유사한지 확인 (대소문자 무시, 특수문자 무시)
                const normalizedFileRepoName = fileRepoName.toLowerCase().replace(/[^a-zA-Z0-9_-]/g, '');
                const normalizedTargetRepoName = repoName.toLowerCase().replace(/[^a-zA-Z0-9_-]/g, '');
                
                if (normalizedFileRepoName === normalizedTargetRepoName) {
                  reportFile = file;
                  console.log(`유사도 매칭으로 리포트 파일 발견: ${reportFile}`);
                  break;
                }
              }
            }
            
            // 여전히 매칭되지 않으면, scan_path에 포함된 키워드로 매칭 시도
            if (!reportFile && reportJsonFiles.length > 0) {
              const scanPathLower = scan_path.toLowerCase();
              console.log(`[TOOL-VET] 정확한 매칭 실패, 키워드 매칭 시도: scan_path="${scanPathLower}"`);
              
              for (const file of reportJsonFiles) {
                const fileLower = file.toLowerCase();
                const fileBaseName = fileLower.replace('-report.json', '');
                
                // scan_path에서 마지막 부분만 추출 (GitHub URL인 경우)
                let scanPathKey = scanPathLower;
                if (scanPathLower.includes('/')) {
                  const parts = scanPathLower.split('/');
                  scanPathKey = parts[parts.length - 1].replace('.git', '');
                }
                
                // scan_path에 포함된 단어가 파일 이름에 포함되어 있는지 확인
                // 또는 파일 이름이 scan_path에 포함되어 있는지 확인
                if (fileBaseName.includes(scanPathKey) || scanPathKey.includes(fileBaseName) || 
                    fileBaseName.includes(scanPathLower) || scanPathLower.includes(fileBaseName)) {
                  reportFile = file;
                  console.log(`[TOOL-VET] 키워드 매칭으로 리포트 파일 발견: ${reportFile} (scan_path: ${scanPathLower})`);
                  break;
                }
              }
            }
            
            // 여전히 매칭되지 않으면, 모든 리포트 파일을 확인하고 가장 유사한 것 찾기
            if (!reportFile && reportJsonFiles.length > 0) {
              console.log(`[TOOL-VET] 키워드 매칭도 실패, 모든 파일 확인 중...`);
              const scanPathLower = scan_path.toLowerCase();
              let scanPathKey = scanPathLower;
              if (scanPathLower.includes('/')) {
                const parts = scanPathLower.split('/');
                scanPathKey = parts[parts.length - 1].replace('.git', '');
              }
              
              // 파일 이름에서 공통 부분 찾기
              for (const file of reportJsonFiles) {
                const fileBaseName = file.toLowerCase().replace('-report.json', '');
                // 단어 단위로 비교
                const scanWords = scanPathKey.split(/[-_]/).filter(w => w.length > 2);
                const fileWords = fileBaseName.split(/[-_]/).filter(w => w.length > 2);
                
                // 공통 단어가 있으면 매칭
                const commonWords = scanWords.filter(w => fileWords.includes(w));
                if (commonWords.length > 0) {
                  reportFile = file;
                  console.log(`[TOOL-VET] 공통 단어 매칭으로 리포트 파일 발견: ${reportFile} (공통 단어: ${commonWords.join(', ')})`);
                  break;
                }
              }
            }
            
            // 여전히 매칭되지 않으면 에러 로그만 출력 (잘못된 데이터를 반환하지 않음)
            if (!reportFile) {
              console.error(`[TOOL-VET] scan_path "${scan_path}"에 해당하는 리포트 파일을 찾을 수 없습니다.`);
              console.error(`[TOOL-VET] 사용 가능한 리포트 파일:`, reportJsonFiles);
              console.error(`[TOOL-VET] 시도한 repoName 패턴:`, possibleRepoNames);
            }
            
            if (reportFile) {
              const reportPath = path.join(TOOL_VET_OUTPUT_DIR, reportFile);
              let reportData;
              try {
                const reportContent = await fs.readFile(reportPath, 'utf-8');
                reportData = JSON.parse(reportContent);
              } catch (readError) {
                console.error(`[TOOL-VET] 리포트 파일 읽기/파싱 실패: ${reportPath}`, readError.message);
                throw readError; // 상위 catch로 전파
              }
              
              // MCP 서버 이름 추출 및 정규화
              let mcpServerName = null;
              if (reportFile.includes('-report.json')) {
                const fileServerName = reportFile.replace('-report.json', '');
                mcpServerName = normalizeServerName(scan_path, fileServerName);
              }
              
              // mcp_server_name 파라미터가 있으면 정규화하여 비교
              if (mcp_server_name) {
                const normalizedRequestName = normalizeServerName(scan_path, mcp_server_name);
                if (mcpServerName && mcpServerName !== normalizedRequestName) {
                  console.log(`[TOOL-VET] 서버 이름 불일치: 리포트 파일="${mcpServerName}", 요청="${normalizedRequestName}" - 스킵`);
                reportFile = null;
                } else {
                  mcpServerName = normalizedRequestName; // 요청된 이름 사용
                }
              }
              
              // 리포트 요약 정보 계산
              let totalTools = 0;
              let totalEndpoints = 0;
              let totalVulns = 0;
              
              if (reportData.tools && Array.isArray(reportData.tools)) {
                totalTools = reportData.tools.length;
                for (const tool of reportData.tools) {
                  // tool-level vulnerabilities 카운트
                  if (tool.vulnerabilities && Array.isArray(tool.vulnerabilities)) {
                    totalVulns += tool.vulnerabilities.length;
                  }
                  
                  if (tool.api_endpoints && Array.isArray(tool.api_endpoints)) {
                    totalEndpoints += tool.api_endpoints.length;
                    for (const endpoint of tool.api_endpoints) {
                      if (endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities)) {
                        totalVulns += endpoint.vulnerabilities.length;
                      }
                    }
                  }
                }
              }
              
              // global_vulnerabilities 카운트
              if (reportData.global_vulnerabilities && Array.isArray(reportData.global_vulnerabilities)) {
                totalVulns += reportData.global_vulnerabilities.length;
              }
              
              // summary가 있으면 사용
              if (reportData.summary) {
                if (reportData.summary.total_tools !== undefined) {
                  totalTools = reportData.summary.total_tools;
                }
                if (reportData.summary.total_vulnerabilities !== undefined) {
                  totalVulns = reportData.summary.total_vulnerabilities;
                }
              }
              
              // 리포트 전체 저장
              const scanId = uuidv4();
              try {
                const insertReportStmt = db.prepare(`
                  INSERT INTO tool_validation_reports (
                    scan_id, scan_path, mcp_server_name, scan_timestamp,
                    report_data, total_tools, total_endpoints, total_vulnerabilities
                  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                `);
                
                insertReportStmt.run(
                  scanId,
                  scan_path,
                  mcpServerName,
                  getKoreaTimeSQLite(),
                  JSON.stringify(reportData),
                  totalTools,
                  totalEndpoints,
                  totalVulns
                );
                
                console.log(`Tool Validation 리포트 저장 완료: ${mcpServerName || 'unknown'} (tools: ${totalTools}, endpoints: ${totalEndpoints}, vulnerabilities: ${totalVulns})`);
              } catch (reportInsertError) {
                console.error('Tool Validation 리포트 저장 오류:', reportInsertError);
              }
              
              // 취약점 데이터 저장 (global_vulnerabilities + tool-level + api-endpoint-level)
              try {
                if (mcpServerName) {
                  const deleteStmt = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ?');
                  deleteStmt.run(scan_path, mcpServerName);
                  console.log(`[TOOL-VET] 기존 Tool Validation 취약점 데이터 삭제 완료: ${scan_path} (서버: ${mcpServerName})`);
                } else {
                const deleteStmt = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_path = ?');
                deleteStmt.run(scan_path);
                  console.log(`[TOOL-VET] 기존 Tool Validation 취약점 데이터 삭제 완료: ${scan_path} (서버 이름 없음)`);
                }
                
                  const insertStmt = db.prepare(`
                    INSERT INTO tool_validation_vulnerabilities (
                      scan_id, scan_path, mcp_server_name, scan_timestamp,
                      tool_name, host, method, path,
                      category_code, category_name, title, description, evidence, recommendation, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                  `);
                  
                  let savedVulns = 0;
                
                // global_vulnerabilities는 저장하지 않음 (tool-level과 api-endpoint-level만 저장)
                if (reportData.global_vulnerabilities && Array.isArray(reportData.global_vulnerabilities)) {
                  console.log(`[TOOL-VET] global_vulnerabilities 발견: ${reportData.global_vulnerabilities.length}개 (저장하지 않음)`);
                }
                
                // tools 배열 순회하며 tool-level 및 api-endpoint-level 취약점 저장
                if (reportData.tools && Array.isArray(reportData.tools)) {
                  for (const tool of reportData.tools) {
                    const toolName = tool.name || '';
                    
                    // 2-1. tool-level vulnerabilities 저장
                    if (tool.vulnerabilities && Array.isArray(tool.vulnerabilities)) {
                      console.log(`[TOOL-VET] Tool '${toolName}'의 tool-level 취약점 발견: ${tool.vulnerabilities.length}개`);
                      for (const vuln of tool.vulnerabilities) {
                        try {
                          insertStmt.run(
                            scanId,
                            scan_path,
                            mcpServerName,
                            getKoreaTimeSQLite(),
                            toolName,
                            null, // host 없음
                            null, // method 없음
                            null, // path 없음
                            vuln.category_code || '',
                            vuln.category_name || '',
                            vuln.title || '',
                            vuln.description || '',
                            vuln.evidence || '',
                            vuln.recommendation || '',
                            JSON.stringify(vuln)
                          );
                          savedVulns++;
                        } catch (insertError) {
                          console.error(`[TOOL-VET] Tool-level 취약점 저장 오류 (${toolName}):`, insertError);
                        }
                      }
                    }
                    
                    // 2-2. api_endpoints 배열 순회
                    if (tool.api_endpoints && Array.isArray(tool.api_endpoints)) {
                      for (const endpoint of tool.api_endpoints) {
                        const host = endpoint.host || '';
                        const method = endpoint.method || '';
                        const path = endpoint.path || '';
                        
                        // api-endpoint-level vulnerabilities 저장
                        if (endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities)) {
                          for (const vuln of endpoint.vulnerabilities) {
                            try {
                              insertStmt.run(
                                scanId,
                                scan_path,
                                mcpServerName,
                                getKoreaTimeSQLite(),
                                toolName,
                                host,
                                method,
                                path,
                                vuln.category_code || '',
                                vuln.category_name || '',
                                vuln.title || '',
                                vuln.description || '',
                                vuln.evidence || '',
                                vuln.recommendation || '',
                                JSON.stringify(vuln)
                              );
                              savedVulns++;
                            } catch (insertError) {
                              console.error(`[TOOL-VET] API-endpoint 취약점 저장 오류 (${toolName}):`, insertError);
                            }
                            }
                          }
                        }
                      }
                    }
                  }
                  
                console.log(`[TOOL-VET] Tool Validation 취약점 ${savedVulns}개 저장 완료`);
                  
                // 저장 후 다시 조회 (정규화된 서버 이름으로 필터링)
                if (mcpServerName) {
                  vulnerabilities = db.prepare('SELECT * FROM tool_validation_vulnerabilities WHERE scan_path = ? AND mcp_server_name = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path, mcpServerName);
                  } else {
                    vulnerabilities = db.prepare('SELECT * FROM tool_validation_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
                  }
                console.log(`[TOOL-VET] 데이터베이스에서 조회된 취약점 개수: ${vulnerabilities.length} (mcp_server_name: ${mcpServerName || '없음'})`);
              } catch (vulnError) {
                console.error('[TOOL-VET] 취약점 데이터 저장 오류:', vulnError);
              }
            } else {
              console.log(`리포트 파일을 찾을 수 없습니다: ${scan_path}`);
            }
          } catch (fileError) {
            console.error('리포트 파일에서 로드 오류:', fileError);
          }
        }
      }
      
      // raw_data JSON 파싱
      const findings = vulnerabilities.map(v => {
        let rawData = null;
        if (v.raw_data) {
          try {
            rawData = JSON.parse(v.raw_data);
          } catch (parseError) {
            console.error(`[TOOL-VET] raw_data JSON 파싱 실패 (id: ${v.id}):`, parseError.message);
            rawData = null;
          }
        }
        
        const finding = {
          id: v.id,
          scan_id: v.scan_id,
          scan_path: v.scan_path,
          scan_timestamp: v.scan_timestamp,
          tool_name: v.tool_name,
          host: v.host,
          method: v.method,
          path: v.path,
          category_code: v.category_code,
          category_name: v.category_name,
          title: v.title,
          description: v.description,
          evidence: v.evidence,
          recommendation: v.recommendation,
          raw_data: rawData
        };
        return finding;
      });
      
      res.json({
        success: true,
        data: findings
      });
    } catch (error) {
      console.error('[TOOL-VET] Tool Validation 취약점 조회 오류:', error);
      console.error('[TOOL-VET] 에러 스택:', error.stack);
      console.error('[TOOL-VET] 에러 메시지:', error.message);
      res.status(500).json({
        success: false,
        message: `Tool Validation 취약점 조회 중 오류가 발생했습니다: ${error.message}`
      });
    }
  },

  getToolValidationReports: async (req, res) => {
    try {
      const { scan_id, scan_path, mcp_server_name } = req.query;
      
      let reports = [];
      
      if (scan_id) {
        // scan_id로 조회
        if (mcp_server_name) {
          // mcp_server_name 정규화
          const normalizedServerName = normalizeServerName(scan_path, mcp_server_name);
          reports = db.prepare('SELECT * FROM tool_validation_reports WHERE scan_id = ? AND mcp_server_name = ? ORDER BY scan_timestamp DESC').all(scan_id, normalizedServerName);
          console.log(`[TOOL-VET] getToolValidationReports: scan_id + mcp_server_name으로 엄격 필터링: ${reports.length}개 (scan_id: ${scan_id}, 서버: ${normalizedServerName})`);
          
          // 서버 필터가 있고 결과가 없으면 빈 배열 반환
          if (reports.length === 0) {
            console.log(`[TOOL-VET] getToolValidationReports: 서버 필터(${mcp_server_name} -> ${normalizedServerName}) + scan_id=${scan_id} 이지만 데이터 없음 → 빈 배열 반환`);
            return res.json({ success: true, data: [] });
          }
        } else {
          // mcp_server_name이 없으면 scan_id로만 조회 (경고 - 보안상 비권장)
          console.log(`[TOOL-VET] getToolValidationReports: ⚠️ scan_id로만 조회 (mcp_server_name 없음): ${scan_id}`);
          reports = db.prepare('SELECT * FROM tool_validation_reports WHERE scan_id = ? ORDER BY scan_timestamp DESC').all(scan_id);
          console.log(`[TOOL-VET] getToolValidationReports: ⚠️ scan_id로만 조회 결과: ${reports.length}개 발견`);
        }
      } else if (scan_path) {
        // scan_path 정규화 (GitHub URL의 경우 .git 제거, 소문자 변환)
        let normalizedScanPath = scan_path;
        if (isValidGithubUrl(scan_path)) {
          normalizedScanPath = scan_path.replace(/\.git$/i, '').toLowerCase();
        }
        
        // scan_path로 최신 스캔 결과 조회
        if (mcp_server_name) {
          // mcp_server_name 정규화
          const normalizedServerName = normalizeServerName(scan_path, mcp_server_name);
          reports = db.prepare('SELECT * FROM tool_validation_reports WHERE scan_path = ? AND mcp_server_name = ? ORDER BY scan_timestamp DESC LIMIT 1').all(normalizedScanPath, normalizedServerName);
        } else {
          reports = db.prepare('SELECT * FROM tool_validation_reports WHERE scan_path = ? ORDER BY scan_timestamp DESC LIMIT 1').all(normalizedScanPath);
        }
      } else if (mcp_server_name) {
        // mcp_server_name만 있는 경우: 정규화된 서버 이름으로 최신 리포트 조회
        const normalizedServerName = normalizeServerName(null, mcp_server_name);
        console.log(`[TOOL-VET] getToolValidationReports: mcp_server_name만으로 조회: ${mcp_server_name} -> normalized: ${normalizedServerName}`);
        reports = db.prepare('SELECT * FROM tool_validation_reports WHERE mcp_server_name = ? ORDER BY scan_timestamp DESC LIMIT 1').all(normalizedServerName);
        console.log(`[TOOL-VET] mcp_server_name만으로 리포트 조회: ${reports.length}개 발견 (서버: ${normalizedServerName})`);
      } else {
        // 모든 리포트 조회 (보안상 비권장이지만 기존 동작 유지)
        reports = db.prepare('SELECT * FROM tool_validation_reports ORDER BY scan_timestamp DESC').all();
      }
      
      // report_data JSON 파싱
      const parsedReports = reports.map(r => {
        const report = {
          id: r.id,
          scan_id: r.scan_id,
          scan_path: r.scan_path,
          mcp_server_name: r.mcp_server_name,
          scan_timestamp: r.scan_timestamp,
          total_tools: r.total_tools,
          total_endpoints: r.total_endpoints,
          total_vulnerabilities: r.total_vulnerabilities,
          created_at: r.created_at,
          report_data: r.report_data ? JSON.parse(r.report_data) : null
        };
        return report;
      });
      
      res.json({
        success: true,
        data: parsedReports
      });
    } catch (error) {
      console.error('Tool Validation 리포트 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'Tool Validation 리포트 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 기존 TOOL-VET 리포트 파일을 데이터베이스에 수동으로 저장
  importToolValidationReports: async (req, res) => {
    try {
      console.log('기존 TOOL-VET 리포트 파일 임포트 시작...');
      
      // TOOL-VET output 디렉토리에서 모든 리포트 파일 찾기
      const reportFiles = await fs.readdir(TOOL_VET_OUTPUT_DIR);
      const reportJsonFiles = reportFiles.filter(f => f.endsWith('-report.json') || f === 'report.json' || f.endsWith('report.json'));
      
      console.log(`발견된 리포트 파일: ${reportJsonFiles.length}개`);
      
      let importedCount = 0;
      let errorCount = 0;
      
      for (const reportFile of reportJsonFiles) {
        try {
          const reportPath = path.join(TOOL_VET_OUTPUT_DIR, reportFile);
          console.log(`리포트 파일 처리 중: ${reportFile}`);
          
          const reportData = JSON.parse(await fs.readFile(reportPath, 'utf-8'));
          
          // MCP 서버 이름 추출
          let mcpServerName = null;
          if (reportFile.includes('-report.json')) {
            mcpServerName = reportFile.replace('-report.json', '');
          }
          
          // MCP 서버 이름 정규화
          const normalizedMcpServerName = mcpServerName ? normalizeServerName(null, mcpServerName) : null;
          
          // 리포트 요약 정보 계산
          let totalTools = 0;
          let totalEndpoints = 0;
          let totalVulns = 0;
          
          if (reportData.tools && Array.isArray(reportData.tools)) {
            totalTools = reportData.tools.length;
            for (const tool of reportData.tools) {
              // tool-level vulnerabilities 카운트
              if (tool.vulnerabilities && Array.isArray(tool.vulnerabilities)) {
                totalVulns += tool.vulnerabilities.length;
              }
              
              if (tool.api_endpoints && Array.isArray(tool.api_endpoints)) {
                totalEndpoints += tool.api_endpoints.length;
                for (const endpoint of tool.api_endpoints) {
                  if (endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities)) {
                    totalVulns += endpoint.vulnerabilities.length;
                  }
                }
              }
            }
          }
          
          // global_vulnerabilities 카운트
          if (reportData.global_vulnerabilities && Array.isArray(reportData.global_vulnerabilities)) {
            totalVulns += reportData.global_vulnerabilities.length;
          }
          
          // summary가 있으면 사용
          if (reportData.summary) {
            if (reportData.summary.total_tools !== undefined) {
              totalTools = reportData.summary.total_tools;
            }
            if (reportData.summary.total_vulnerabilities !== undefined) {
              totalVulns = reportData.summary.total_vulnerabilities;
            }
          }
          
          // scan_path 생성 (mcp_server_name 기반)
          const scanPath = mcpServerName || 'unknown';
          const scanId = `import-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
          
          // scan_path 정규화
          let normalizedScanPath = scanPath;
          if (scanPath && isValidGithubUrl(scanPath)) {
            normalizedScanPath = scanPath.replace(/\.git$/i, '').toLowerCase();
          }
          
          // 기존 리포트가 있는지 확인
          const existingReport = db.prepare('SELECT scan_id FROM tool_validation_reports WHERE mcp_server_name = ? ORDER BY scan_timestamp DESC LIMIT 1').get(normalizedMcpServerName);
          
          let finalScanId = scanId;
          if (existingReport && existingReport.scan_id) {
            console.log(`기존 리포트가 존재합니다: ${normalizedMcpServerName} (scan_id: ${existingReport.scan_id})`);
            finalScanId = existingReport.scan_id;
            // 기존 취약점 삭제 후 다시 저장
            const deleteStmt = db.prepare('DELETE FROM tool_validation_vulnerabilities WHERE scan_id = ?');
            deleteStmt.run(finalScanId);
            console.log(`[IMPORT] 기존 취약점 데이터 삭제 완료: ${finalScanId}`);
          } else {
            // 리포트 저장 (새로운 리포트인 경우만)
          const insertReportStmt = db.prepare(`
            INSERT INTO tool_validation_reports (
              scan_id, scan_path, mcp_server_name, scan_timestamp,
              report_data, total_tools, total_endpoints, total_vulnerabilities
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `);
          
          insertReportStmt.run(
            scanId,
              normalizedScanPath,
              normalizedMcpServerName,
            getKoreaTimeSQLite(),
            JSON.stringify(reportData),
            totalTools,
            totalEndpoints,
            totalVulns
          );
          
            console.log(`리포트 저장 완료: ${normalizedMcpServerName} (tools: ${totalTools}, endpoints: ${totalEndpoints}, vulnerabilities: ${totalVulns})`);
          }
          
          // ========== 취약점 데이터 저장 (global_vulnerabilities + tool-level + api-endpoint-level) ==========
          const insertStmt = db.prepare(`
            INSERT INTO tool_validation_vulnerabilities (
              scan_id, scan_path, mcp_server_name, scan_timestamp,
              tool_name, host, method, path,
              category_code, category_name, title, description, evidence, recommendation, raw_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          
          let savedVulns = 0;
          
          // global_vulnerabilities는 저장하지 않음 (tool-level과 api-endpoint-level만 저장)
          if (reportData.global_vulnerabilities && Array.isArray(reportData.global_vulnerabilities)) {
            console.log(`[IMPORT] global_vulnerabilities 발견: ${reportData.global_vulnerabilities.length}개 (저장하지 않음)`);
          }
          
          // tools 배열 순회하며 tool-level 및 api-endpoint-level 취약점 저장
          if (reportData.tools && Array.isArray(reportData.tools)) {
            for (const tool of reportData.tools) {
              const toolName = tool.name || '';
              
              // 2-1. tool-level vulnerabilities 저장
              if (tool.vulnerabilities && Array.isArray(tool.vulnerabilities)) {
                console.log(`[IMPORT] Tool '${toolName}'의 tool-level 취약점 발견: ${tool.vulnerabilities.length}개`);
                for (const vuln of tool.vulnerabilities) {
                  try {
                    insertStmt.run(
                      finalScanId,
                      normalizedScanPath,
                      normalizedMcpServerName,
                      getKoreaTimeSQLite(),
                      toolName,
                      null,
                      null,
                      null,
                      vuln.category_code || '',
                      vuln.category_name || '',
                      vuln.title || '',
                      vuln.description || '',
                      vuln.evidence || '',
                      vuln.recommendation || '',
                      JSON.stringify(vuln)
                    );
                    savedVulns++;
                    console.log(`[IMPORT] Tool-level 취약점 저장 완료: ${toolName} - ${vuln.category_code} - ${vuln.title}`);
                  } catch (insertError) {
                    console.error(`[IMPORT] Tool-level 취약점 저장 오류 (${toolName}):`, insertError);
                  }
                }
              }
              
              // 2-2. api_endpoints 배열 순회
              if (tool.api_endpoints && Array.isArray(tool.api_endpoints)) {
                for (const endpoint of tool.api_endpoints) {
                  const host = endpoint.host || '';
                  const method = endpoint.method || '';
                  const path = endpoint.path || '';
                  
                  // api-endpoint-level vulnerabilities 저장
                  if (endpoint.vulnerabilities && Array.isArray(endpoint.vulnerabilities)) {
                    for (const vuln of endpoint.vulnerabilities) {
                      try {
                        insertStmt.run(
                          finalScanId,
                          normalizedScanPath,
                          normalizedMcpServerName,
                          getKoreaTimeSQLite(),
                          toolName,
                          host,
                          method,
                          path,
                          vuln.category_code || '',
                          vuln.category_name || '',
                          vuln.title || '',
                          vuln.description || '',
                          vuln.evidence || '',
                          vuln.recommendation || '',
                          JSON.stringify(vuln)
                        );
                        savedVulns++;
                      } catch (insertError) {
                        console.error(`[IMPORT] API-endpoint 취약점 저장 오류 (${toolName}):`, insertError);
                      }
                    }
                  }
                }
              }
            }
          }
          
          console.log(`[IMPORT] 취약점 ${savedVulns}개 저장 완료: ${normalizedMcpServerName}`);
          
          // 저장 후 검증
          if (normalizedMcpServerName) {
            const verifyStmt = db.prepare(`
              SELECT COUNT(*) as count 
              FROM tool_validation_vulnerabilities 
              WHERE scan_path = ? AND mcp_server_name = ?
            `);
            const verifyResult = verifyStmt.get(normalizedScanPath, normalizedMcpServerName);
            console.log(`[IMPORT] 저장 검증: DB에 실제 저장된 취약점 개수 = ${verifyResult.count}개 (저장 시도: ${savedVulns}개)`);
            
            // category_code별로 개수 확인
            const categoryStmt = db.prepare(`
              SELECT category_code, COUNT(*) as count 
              FROM tool_validation_vulnerabilities 
              WHERE scan_path = ? AND mcp_server_name = ?
              GROUP BY category_code
            `);
            const categoryCounts = categoryStmt.all(normalizedScanPath, normalizedMcpServerName);
            console.log(`[IMPORT] category_code별 취약점 개수:`, categoryCounts);
          }
          
          importedCount++;
        } catch (fileError) {
          console.error(`리포트 파일 처리 오류 (${reportFile}):`, fileError);
          errorCount++;
        }
      }
      
      res.json({
        success: true,
        message: `리포트 임포트 완료: ${importedCount}개 성공, ${errorCount}개 실패`,
        imported: importedCount,
        errors: errorCount
      });
    } catch (error) {
      console.error('리포트 임포트 오류:', error);
      res.status(500).json({
        success: false,
        message: '리포트 임포트 중 오류가 발생했습니다.'
      });
    }
  }
};

module.exports = riskAssessmentController;


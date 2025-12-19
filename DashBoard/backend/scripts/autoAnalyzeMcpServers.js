const db = require('../config/db');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { promisify } = require('util');
const { v4: uuidv4 } = require('uuid');

const execAsync = promisify(require('child_process').exec);

// GitHub URL 유효성 검사 함수
function isValidGithubUrl(url) {
  if (typeof url !== 'string') return false;
  const trimmed = url.trim();
  const pattern = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)(?:\.git)?$/i;
  return pattern.test(trimmed);
}

// 서버 이름 정규화 함수
function normalizeServerName(githubUrl, fallbackName = null) {
  let serverName = null;
  
  if (githubUrl && isValidGithubUrl(githubUrl)) {
    const match = githubUrl.match(/github\.com\/[^\/]+\/([^\/]+)/);
    if (match && match[1]) {
      serverName = match[1].replace(/\.git$/, '');
    }
  }
  
  if (!serverName && fallbackName) {
    serverName = fallbackName;
  }
  
  if (!serverName || serverName.trim() === '') {
    serverName = 'unknown';
  }
  
  serverName = serverName
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9_-]/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-+|-$/g, '');
  
  return serverName;
}

// 스캐너 경로 설정
const SCANNER_PATH = process.env.SCANNER_PATH || path.resolve(__dirname, '../../../MCP-SCAN');
const BOMTORI_ROOT = process.env.BOMTORI_ROOT || path.resolve(__dirname, '../../../SBOM-SCA');
const TOOL_VET_ROOT = process.env.TOOL_VET_ROOT || path.resolve(__dirname, '../../../TOOL-VET');
const CONTAINER_NAME = process.env.DOCKER_CONTAINER_NAME || 'bomtool-scanner';
const BOMTORI_CONTAINER_NAME = process.env.BOMTORI_CONTAINER_NAME || 'bomtori';
const TOOL_VET_CONTAINER_NAME = process.env.TOOL_VET_CONTAINER_NAME || 'mcp-vetting';

// Docker 컨테이너 실행 확인
async function checkDockerContainer(containerName, rootPath) {
  return new Promise((resolve, reject) => {
    const checkProcess = spawn('docker', [
      'ps',
      '--filter',
      `name=${containerName}`,
      '--format',
      '{{.Names}}'
    ], {
      cwd: rootPath
    });
    
    let stdout = '';
    let stderr = '';
    
    checkProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    checkProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    checkProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Docker 명령 실행 실패: ${stderr || '알 수 없는 오류'}`));
      } else {
        resolve(stdout.trim() !== '');
      }
    });
    
    checkProcess.on('error', (error) => {
      reject(error);
    });
  });
}

// MCP-SCAN 실행
async function runMcpScan(scanPath, containerName, scannerPath) {
  return new Promise((resolve, reject) => {
    console.log(`[MCP-SCAN] 스캔 시작: ${scanPath}`);
    
    const dockerArgs = [
      'exec',
      '-w', '/app',
      containerName,
      'python',
      '-m',
      'scanner.cli',
      '--path',
      scanPath
    ];
    
    const scanProcess = spawn('docker', dockerArgs, {
      cwd: scannerPath,
      stdio: 'inherit'
    });
    
    scanProcess.on('close', (code) => {
      if (code === 0) {
        console.log(`[MCP-SCAN] 스캔 완료`);
        resolve();
      } else {
        reject(new Error(`MCP-SCAN 실패: 종료 코드 ${code}`));
      }
    });
    
    scanProcess.on('error', (error) => {
      reject(new Error(`MCP-SCAN 실행 오류: ${error.message}`));
    });
  });
}

// SBOM-SCA (Bomtori) 실행
async function runBomtori(scanPath, containerName, bomtoriRoot) {
  return new Promise((resolve, reject) => {
    console.log(`[SBOM-SCA] 스캔 시작: ${scanPath}`);
    
    const dockerArgs = [
      'exec',
      '-w', '/app',
      containerName,
      'python',
      'main.py',
      '--path',
      scanPath
    ];
    
    const bomtoriProcess = spawn('docker', dockerArgs, {
      cwd: bomtoriRoot,
      stdio: 'inherit'
    });
    
    bomtoriProcess.on('close', (code) => {
      if (code === 0) {
        console.log(`[SBOM-SCA] 스캔 완료`);
        resolve();
      } else {
        reject(new Error(`SBOM-SCA 실패: 종료 코드 ${code}`));
      }
    });
    
    bomtoriProcess.on('error', (error) => {
      reject(new Error(`SBOM-SCA 실행 오류: ${error.message}`));
    });
  });
}

// TOOL-VET 실행
async function runToolVet(githubUrl, containerName, toolVetRoot, serverName) {
  return new Promise((resolve, reject) => {
    console.log(`[TOOL-VET] 스캔 시작: ${githubUrl}`);
    
    const dockerArgs = [
      'exec',
      '-w', '/app',
      containerName,
      'python',
      'main.py',
      '--git-url',
      githubUrl
    ];
    
    const toolVetProcess = spawn('docker', dockerArgs, {
      cwd: toolVetRoot,
      stdio: 'inherit'
    });
    
    toolVetProcess.on('close', (code) => {
      if (code === 0) {
        console.log(`[TOOL-VET] 스캔 완료`);
        resolve();
      } else {
        reject(new Error(`TOOL-VET 실패: 종료 코드 ${code}`));
      }
    });
    
    toolVetProcess.on('error', (error) => {
      reject(new Error(`TOOL-VET 실행 오류: ${error.message}`));
    });
  });
}

// 서버 분석 실행
async function analyzeServer(server, options = {}) {
  const { skipMcpScan = false, skipBomtori = false, skipToolVet = false } = options;
  
  const githubUrl = server.github_link;
  const filePath = server.file_path;
  const serverName = server.name || normalizeServerName(githubUrl);
  
  console.log(`\n${'='.repeat(60)}`);
  console.log(`서버 분석 시작: ${serverName}`);
  console.log(`GitHub URL: ${githubUrl || '(없음)'}`);
  console.log(`파일 경로: ${filePath || '(없음)'}`);
  console.log(`${'='.repeat(60)}\n`);
  
  const scanPath = githubUrl || filePath;
  
  if (!scanPath) {
    console.log(`[SKIP] 스캔 경로가 없습니다: ${serverName}`);
    return { success: false, reason: '스캔 경로 없음' };
  }
  
  try {
    // Docker 컨테이너 확인
    const containers = {
      mcpScan: await checkDockerContainer(CONTAINER_NAME, SCANNER_PATH).catch(() => false),
      bomtori: await checkDockerContainer(BOMTORI_CONTAINER_NAME, BOMTORI_ROOT).catch(() => false),
      toolVet: await checkDockerContainer(TOOL_VET_CONTAINER_NAME, TOOL_VET_ROOT).catch(() => false)
    };
    
    console.log(`[Docker 컨테이너 상태]`);
    console.log(`  MCP-SCAN: ${containers.mcpScan ? '실행 중' : '중지됨'}`);
    console.log(`  SBOM-SCA: ${containers.bomtori ? '실행 중' : '중지됨'}`);
    console.log(`  TOOL-VET: ${containers.toolVet ? '실행 중' : '중지됨'}\n`);
    
    const results = {
      mcpScan: null,
      bomtori: null,
      toolVet: null
    };
    
    // MCP-SCAN 실행
    if (!skipMcpScan && containers.mcpScan) {
      try {
        await runMcpScan(scanPath, CONTAINER_NAME, SCANNER_PATH);
        results.mcpScan = { success: true };
      } catch (error) {
        console.error(`[MCP-SCAN] 오류: ${error.message}`);
        results.mcpScan = { success: false, error: error.message };
      }
    } else if (!skipMcpScan && !containers.mcpScan) {
      console.log(`[MCP-SCAN] 스킵: Docker 컨테이너가 실행 중이 아닙니다`);
      results.mcpScan = { success: false, reason: '컨테이너 미실행' };
    }
    
    // SBOM-SCA 실행 (GitHub URL이 있는 경우만)
    if (!skipBomtori && githubUrl && isValidGithubUrl(githubUrl) && containers.bomtori) {
      try {
        await runBomtori(githubUrl, BOMTORI_CONTAINER_NAME, BOMTORI_ROOT);
        results.bomtori = { success: true };
      } catch (error) {
        console.error(`[SBOM-SCA] 오류: ${error.message}`);
        results.bomtori = { success: false, error: error.message };
      }
    } else if (!skipBomtori && githubUrl && isValidGithubUrl(githubUrl) && !containers.bomtori) {
      console.log(`[SBOM-SCA] 스킵: Docker 컨테이너가 실행 중이 아닙니다`);
      results.bomtori = { success: false, reason: '컨테이너 미실행' };
    }
    
    // TOOL-VET 실행 (GitHub URL이 있는 경우만)
    if (!skipToolVet && githubUrl && isValidGithubUrl(githubUrl) && containers.toolVet) {
      try {
        await runToolVet(githubUrl, TOOL_VET_CONTAINER_NAME, TOOL_VET_ROOT, serverName);
        results.toolVet = { success: true };
      } catch (error) {
        console.error(`[TOOL-VET] 오류: ${error.message}`);
        results.toolVet = { success: false, error: error.message };
      }
    } else if (!skipToolVet && githubUrl && isValidGithubUrl(githubUrl) && !containers.toolVet) {
      console.log(`[TOOL-VET] 스킵: Docker 컨테이너가 실행 중이 아닙니다`);
      results.toolVet = { success: false, reason: '컨테이너 미실행' };
    }
    
    // 분석 완료 후 DB 업데이트
    const allSuccess = Object.values(results).every(r => r === null || r.success);
    const hasAnyResult = Object.values(results).some(r => r !== null);
    
    if (hasAnyResult) {
      try {
        const updateStmt = db.prepare(`
          UPDATE mcp_register_requests 
          SET scanned = 1, analysis_timestamp = datetime('now', '+9 hours')
          WHERE id = ?
        `);
        updateStmt.run(server.id);
        console.log(`[DB] 분석 완료 상태 업데이트: ${serverName}`);
      } catch (dbError) {
        console.error(`[DB] 업데이트 오류: ${dbError.message}`);
      }
    }
    
    return {
      success: allSuccess,
      results
    };
    
  } catch (error) {
    console.error(`[ERROR] 서버 분석 실패: ${serverName} - ${error.message}`);
    return {
      success: false,
      error: error.message
    };
  }
}

// 메인 함수
async function autoAnalyzeMcpServers(options = {}) {
  const {
    maxServers = null,  // null이면 모든 서버 분석
    status = 'pending',  // 'pending', 'approved', 또는 null (모두)
    skipMcpScan = false,
    skipBomtori = false,
    skipToolVet = false
  } = options;
  
  console.log('=== MCP 서버 자동 분석 시작 ===\n');
  console.log(`옵션:`);
  console.log(`  최대 서버 수: ${maxServers || '제한 없음'}`);
  console.log(`  상태 필터: ${status || '모두'}`);
  console.log(`  MCP-SCAN 스킵: ${skipMcpScan}`);
  console.log(`  SBOM-SCA 스킵: ${skipBomtori}`);
  console.log(`  TOOL-VET 스킵: ${skipToolVet}\n`);
  
  try {
    // DB에서 서버 조회
    let query = 'SELECT * FROM mcp_register_requests';
    const params = [];
    
    if (status) {
      query += ' WHERE status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY created_at ASC';
    
    if (maxServers) {
      query += ' LIMIT ?';
      params.push(maxServers);
    }
    
    const servers = db.prepare(query).all(...params);
    
    console.log(`분석 대상 서버: ${servers.length}개\n`);
    
    if (servers.length === 0) {
      console.log('분석할 서버가 없습니다.');
      return;
    }
    
    const results = {
      total: servers.length,
      success: 0,
      failed: 0,
      skipped: 0
    };
    
    // 각 서버 분석
    for (let i = 0; i < servers.length; i++) {
      const server = servers[i];
      console.log(`\n[${i + 1}/${servers.length}] 서버 분석 중...`);
      
      const result = await analyzeServer(server, {
        skipMcpScan,
        skipBomtori,
        skipToolVet
      });
      
      if (result.success) {
        results.success++;
      } else if (result.reason === '스캔 경로 없음') {
        results.skipped++;
      } else {
        results.failed++;
      }
      
      // 서버 간 대기 시간 (선택적)
      if (i < servers.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    console.log(`\n${'='.repeat(60)}`);
    console.log(`=== 분석 완료 ===`);
    console.log(`총 서버: ${results.total}개`);
    console.log(`성공: ${results.success}개`);
    console.log(`실패: ${results.failed}개`);
    console.log(`스킵: ${results.skipped}개`);
    console.log(`${'='.repeat(60)}\n`);
    
  } catch (error) {
    console.error('자동 분석 중 오류 발생:', error);
    throw error;
  }
}

// 스크립트 실행
if (require.main === module) {
  // 커맨드라인 인자 파싱
  const args = process.argv.slice(2);
  const options = {
    maxServers: null,
    status: 'pending',
    skipMcpScan: false,
    skipBomtori: false,
    skipToolVet: false
  };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '--max' || arg === '-m') {
      const max = parseInt(args[++i], 10);
      if (!isNaN(max) && max > 0) {
        options.maxServers = max;
      }
    } else if (arg === '--status' || arg === '-s') {
      options.status = args[++i] || 'pending';
    } else if (arg === '--skip-mcp-scan') {
      options.skipMcpScan = true;
    } else if (arg === '--skip-bomtori') {
      options.skipBomtori = true;
    } else if (arg === '--skip-tool-vet') {
      options.skipToolVet = true;
    } else if (arg === '--help' || arg === '-h') {
      console.log('사용법: node autoAnalyzeMcpServers.js [옵션]');
      console.log('');
      console.log('옵션:');
      console.log('  --max, -m <개수>        최대 분석 서버 수 (기본값: 제한 없음)');
      console.log('  --status, -s <상태>      서버 상태 필터 (pending, approved, null) (기본값: pending)');
      console.log('  --skip-mcp-scan          MCP-SCAN 스킵');
      console.log('  --skip-bomtori          SBOM-SCA 스킵');
      console.log('  --skip-tool-vet         TOOL-VET 스킵');
      console.log('  --help, -h               도움말 표시');
      console.log('');
      console.log('예시:');
      console.log('  node autoAnalyzeMcpServers.js');
      console.log('  node autoAnalyzeMcpServers.js --max 10');
      console.log('  node autoAnalyzeMcpServers.js --status pending --skip-tool-vet');
      process.exit(0);
    }
  }
  
  autoAnalyzeMcpServers(options)
    .then(() => {
      console.log('\n자동 분석 완료!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n자동 분석 실패:', error);
      process.exit(1);
    });
}

module.exports = { autoAnalyzeMcpServers, analyzeServer };


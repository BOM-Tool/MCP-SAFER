const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// 데이터베이스 연결
const dbPath = path.join(__dirname, '../mcp_safer.db');
if (!fs.existsSync(dbPath)) {
  console.error(`데이터베이스 파일을 찾을 수 없습니다: ${dbPath}`);
  process.exit(1);
}
const db = new Database(dbPath);

// 리포트 파일 읽기
// __dirname: /Users/hyunjung/Desktop/mcp-safer/DashBoard/backend/scripts
// 목표: /Users/hyunjung/Desktop/mcp-safer/TOOL-VET/output/mcp-server-kubernetes-report.json
const reportPath = '/Users/hyunjung/Desktop/mcp-safer/TOOL-VET/output/mcp-server-kubernetes-report.json';
if (!fs.existsSync(reportPath)) {
  console.error(`리포트 파일을 찾을 수 없습니다: ${reportPath}`);
  process.exit(1);
}
const reportData = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));

// mcp_server_name (정규화된 이름 - 여러 가능한 이름 시도)
const possibleNames = ['mcp-server-kubernetes', 'kubernetes-mcp-server', 'mcp_server_kubernetes'];

// scan_path와 scan_id 찾기 (기존 데이터에서)
let existingScan = null;
let mcpServerName = null;

for (const name of possibleNames) {
  try {
    const scan = db.prepare(`
      SELECT scan_id, scan_path, mcp_server_name 
      FROM tool_validation_reports 
      WHERE mcp_server_name = ? 
      ORDER BY scan_timestamp DESC 
      LIMIT 1
    `).get(name);
    
    if (scan) {
      existingScan = scan;
      mcpServerName = scan.mcp_server_name;
      break;
    }
  } catch (e) {
    // 테이블이 없을 수 있음
  }
}

// 테이블이 없거나 데이터가 없으면 기본값 사용
let scanId, scanPath;
if (!existingScan) {
  console.log('기존 스캔 데이터를 찾을 수 없습니다. GitHub URL을 사용합니다.');
  // 실제 GitHub URL 사용
  mcpServerName = 'mcp-server-kubernetes';
  scanId = null; // scan_id는 null로 저장 (나중에 생성될 수 있음)
  scanPath = 'https://github.com/Flux159/mcp-server-kubernetes.git'; // 실제 GitHub URL
} else {
  scanId = existingScan.scan_id;
  scanPath = existingScan.scan_path;
  mcpServerName = existingScan.mcp_server_name;
}

console.log(`스캔 정보: scan_id=${scanId}, scan_path=${scanPath}, mcp_server_name=${mcpServerName}`);

// 테이블 존재 확인 및 생성
const tableExists = db.prepare(`
  SELECT name FROM sqlite_master 
  WHERE type='table' AND name='tool_validation_vulnerabilities'
`).get();

if (!tableExists) {
  console.log('tool_validation_vulnerabilities 테이블이 없습니다. 생성합니다...');
  db.exec(`
    CREATE TABLE IF NOT EXISTS tool_validation_vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT,
      scan_path TEXT,
      scan_timestamp DATETIME DEFAULT (datetime('now', '+9 hours')),
      tool_name TEXT,
      host TEXT,
      method TEXT,
      path TEXT,
      category_code TEXT,
      category_name TEXT,
      title TEXT,
      description TEXT,
      evidence TEXT,
      recommendation TEXT,
      raw_data TEXT,
      mcp_server_name TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);
  console.log('테이블 생성 완료');
}

// 기존 취약점 데이터 삭제 (kubectl_rollout, kubectl_generic만)
const deleteStmt = db.prepare(`
  DELETE FROM tool_validation_vulnerabilities 
  WHERE mcp_server_name = ? 
  AND tool_name IN ('kubectl_rollout', 'kubectl_generic')
`);
const deleted = deleteStmt.run(mcpServerName);
console.log(`기존 데이터 ${deleted.changes}개 삭제 완료`);

// 현재 시간
const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

// INSERT 문 준비
const insertStmt = db.prepare(`
  INSERT INTO tool_validation_vulnerabilities (
    scan_id, scan_path, mcp_server_name, scan_timestamp,
    tool_name, host, method, path,
    category_code, category_name, title, description, evidence, recommendation, raw_data
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

let savedCount = 0;

// 트랜잭션 시작
const insertMany = db.transaction((tools) => {
  for (const tool of tools) {
    const toolName = tool.name || '';
    const toolVulnerabilities = tool.vulnerabilities || [];
    const apiEndpoints = tool.api_endpoints || [];
    
    if (toolName !== 'kubectl_rollout' && toolName !== 'kubectl_generic') {
      continue;
    }
    
    if (apiEndpoints.length > 0) {
      // api_endpoints가 있는 경우, 각 endpoint에 대해 취약점 저장
      for (const endpoint of apiEndpoints) {
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
              now,
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
            savedCount++;
          } catch (error) {
            console.error(`저장 오류 (${toolName}):`, error.message);
          }
        }
      }
    } else if (toolVulnerabilities.length > 0) {
      // api_endpoints가 없지만 tool 레벨 취약점이 있는 경우
      for (const vuln of toolVulnerabilities) {
        try {
          insertStmt.run(
            scanId,
            scanPath,
            mcpServerName,
            now,
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
          savedCount++;
        } catch (error) {
          console.error(`저장 오류 (${toolName}):`, error.message);
        }
      }
    }
  }
});

// 실행
insertMany(reportData.tools);

console.log(`\n총 ${savedCount}개의 취약점 데이터가 저장되었습니다.`);

// 저장된 데이터 확인
const checkStmt = db.prepare(`
  SELECT tool_name, host, method, path, category_code, COUNT(*) as count
  FROM tool_validation_vulnerabilities 
  WHERE mcp_server_name = ? 
  AND tool_name IN ('kubectl_rollout', 'kubectl_generic')
  GROUP BY tool_name, host, method, path, category_code
`);

const results = checkStmt.all(mcpServerName);
console.log('\n저장된 데이터:');
for (const row of results) {
  console.log(`  ${row.tool_name}: ${row.host || '-'} ${row.method || '-'} ${row.path || '-'} (${row.count}개)`);
}

db.close();
console.log('\n완료!');


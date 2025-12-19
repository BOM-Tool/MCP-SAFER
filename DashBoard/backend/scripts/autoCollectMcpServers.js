const db = require('../config/db');
const https = require('https');

// GitHub URL에서 서버명 추출 함수
// 예: https://github.com/makenotion/notion-mcp-server.git -> notion-mcp-server
function extractServerNameFromUrl(githubUrl) {
  if (!githubUrl) return null;
  
  // GitHub URL 패턴 매칭
  const match = githubUrl.match(/github\.com\/[^\/]+\/([^\/]+)/);
  if (match && match[1]) {
    let serverName = match[1].replace(/\.git$/, ''); // .git 제거
    return serverName;
  }
  
  return null;
}

// GitHub API로 리포지토리 검색
async function searchGitHubRepositories(query, language = null, maxResults = 30) {
  return new Promise((resolve, reject) => {
    let url = `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&sort=stars&order=desc&per_page=100`;
    if (language) {
      url += `+language:${language}`;
    }
    
    const options = {
      headers: {
        'User-Agent': 'MCP-Server-Collector',
        'Accept': 'application/vnd.github.v3+json'
      }
    };
    
    // GitHub Personal Access Token이 있으면 사용 (API rate limit 증가)
    const githubToken = process.env.GITHUB_TOKEN;
    if (githubToken) {
      options.headers['Authorization'] = `token ${githubToken}`;
    }
    
    https.get(url, options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`GitHub API error: ${res.statusCode} - ${data}`));
          return;
        }
        
        try {
          const result = JSON.parse(data);
          const repositories = result.items || [];
          
          // maxResults만큼만 반환
          resolve(repositories.slice(0, maxResults));
        } catch (error) {
          reject(error);
        }
      });
    }).on('error', (error) => {
      reject(error);
    });
  });
}

// 리포지토리가 MCP 서버인지 확인 (package.json, go.mod, 또는 README에서 확인)
async function checkIfMcpServer(repo) {
  // 간단한 휴리스틱: 리포지토리 이름이나 설명에 "mcp"가 포함되어 있는지 확인
  const name = (repo.name || '').toLowerCase();
  const description = (repo.description || '').toLowerCase();
  const fullName = (repo.full_name || '').toLowerCase();
  
  // 이름이나 설명에 "mcp"가 포함되어 있으면 MCP 서버로 간주
  if (name.includes('mcp') || description.includes('mcp') || fullName.includes('mcp')) {
    return true;
  }
  
  return false;
}

// 리포지토리의 언어 확인 (Go 또는 TypeScript/JavaScript)
function isTargetLanguage(repo) {
  const language = (repo.language || '').toLowerCase();
  return language === 'go' || language === 'typescript' || language === 'javascript';
}

// DB에 이미 존재하는지 확인
function isDuplicate(githubUrl) {
  const normalizedUrl = githubUrl.replace(/\.git$/, '');
  
  // github_link로 검색
  const existing = db.prepare(`
    SELECT id FROM mcp_register_requests 
    WHERE github_link = ? OR github_link = ? OR github_link = ?
  `).get(normalizedUrl, normalizedUrl + '.git', githubUrl);
  
  if (existing) return true;
  
  // name으로도 검색 (서버명이 같으면 중복으로 간주)
  const serverName = extractServerNameFromUrl(githubUrl);
  if (serverName) {
    const existingByName = db.prepare(`
      SELECT id FROM mcp_register_requests WHERE name = ?
    `).get(serverName);
    
    if (existingByName) return true;
  }
  
  return false;
}

// admin 사용자 ID 가져오기 (없으면 생성)
function getAdminUserId() {
  let adminUser = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  
  if (!adminUser) {
    // admin 사용자가 없으면 생성
    const userStmt = db.prepare(`
      INSERT INTO users (username, employee_id, email, password, team, position) 
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = userStmt.run('admin', 'ADMIN001', 'admin@system.com', 'system', 'IT', 'Administrator');
    adminUser = { id: result.lastInsertRowid };
    console.log(`[INFO] Admin 사용자 생성: ID ${adminUser.id}`);
  }
  
  return adminUser.id;
}

// DB에 서버 등록 요청 저장
function saveServerToDb(repo) {
  const githubUrl = repo.html_url || repo.clone_url || '';
  const serverName = extractServerNameFromUrl(githubUrl);
  
  if (!serverName) {
    console.log(`[SKIP] 서버명 추출 실패: ${githubUrl}`);
    return false;
  }
  
  // 중복 체크
  if (isDuplicate(githubUrl)) {
    console.log(`[SKIP] 중복 서버: ${serverName} (${githubUrl})`);
    return false;
  }
  
  // admin 사용자 ID 가져오기
  const requestedBy = getAdminUserId();
  
  try {
    const stmt = db.prepare(`
      INSERT INTO mcp_register_requests (
        title, name, description, github_link, status, requested_by
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    const title = repo.name || serverName;
    const description = repo.description || '';
    const status = 'pending';
    
    stmt.run(title, serverName, description, githubUrl, status, requestedBy);
    
    console.log(`[SUCCESS] 서버 저장: ${serverName} (${githubUrl})`);
    return true;
  } catch (error) {
    console.error(`[ERROR] 서버 저장 실패: ${serverName} - ${error.message}`);
    return false;
  }
}

// 메인 함수
async function collectMcpServers(maxResults = 30) {
  console.log('=== MCP 서버 자동 수집 시작 ===\n');
  console.log(`수집 목표 개수: ${maxResults}개\n`);
  
  const collectedServers = [];
  const collectedUrls = new Set(); // 중복 체크용 URL Set
  
  try {
    // 1. Go 언어로 된 MCP 서버 검색
    console.log('1. Go 언어 MCP 서버 검색 중...');
    const goQuery = 'mcp-server language:go';
    const goRepos = await searchGitHubRepositories(goQuery, 'go', 50);
    let goCount = 0;
    
    for (const repo of goRepos) {
      if (collectedServers.length >= maxResults) break;
      
      const githubUrl = repo.html_url || repo.clone_url || '';
      if (collectedUrls.has(githubUrl)) continue; // 이미 수집된 URL이면 스킵
      
      if (await checkIfMcpServer(repo) && isTargetLanguage(repo)) {
        if (saveServerToDb(repo)) {
          collectedServers.push(repo);
          collectedUrls.add(githubUrl);
          goCount++;
        }
      }
    }
    
    console.log(`   Go 서버 수집: ${goCount}개\n`);
    
    // 2. TypeScript로 된 MCP 서버 검색
    if (collectedServers.length < maxResults) {
      console.log('2. TypeScript 언어 MCP 서버 검색 중...');
      const tsQuery = 'mcp-server language:typescript';
      const tsRepos = await searchGitHubRepositories(tsQuery, 'typescript', 50);
      let tsCount = 0;
      
      for (const repo of tsRepos) {
        if (collectedServers.length >= maxResults) break;
        
        const githubUrl = repo.html_url || repo.clone_url || '';
        if (collectedUrls.has(githubUrl)) continue;
        
        if (await checkIfMcpServer(repo) && isTargetLanguage(repo)) {
          if (saveServerToDb(repo)) {
            collectedServers.push(repo);
            collectedUrls.add(githubUrl);
            tsCount++;
          }
        }
      }
      
      console.log(`   TypeScript 서버 수집: ${tsCount}개\n`);
    }
    
    // 3. JavaScript로 된 MCP 서버 검색
    if (collectedServers.length < maxResults) {
      console.log('3. JavaScript 언어 MCP 서버 검색 중...');
      const jsQuery = 'mcp-server language:javascript';
      const jsRepos = await searchGitHubRepositories(jsQuery, 'javascript', 50);
      let jsCount = 0;
      
      for (const repo of jsRepos) {
        if (collectedServers.length >= maxResults) break;
        
        const githubUrl = repo.html_url || repo.clone_url || '';
        if (collectedUrls.has(githubUrl)) continue;
        
        if (await checkIfMcpServer(repo) && isTargetLanguage(repo)) {
          if (saveServerToDb(repo)) {
            collectedServers.push(repo);
            collectedUrls.add(githubUrl);
            jsCount++;
          }
        }
      }
      
      console.log(`   JavaScript 서버 수집: ${jsCount}개\n`);
    }
    
    // 4. 추가 검색: "model context protocol" 키워드로 검색
    if (collectedServers.length < maxResults) {
      console.log('4. "model context protocol" 키워드로 검색 중...');
      const mcpQuery = 'model context protocol';
      const mcpRepos = await searchGitHubRepositories(mcpQuery, null, 50);
      let mcpCount = 0;
      
      for (const repo of mcpRepos) {
        if (collectedServers.length >= maxResults) break;
        
        const githubUrl = repo.html_url || repo.clone_url || '';
        if (collectedUrls.has(githubUrl)) continue;
        
        if (await checkIfMcpServer(repo) && isTargetLanguage(repo)) {
          if (saveServerToDb(repo)) {
            collectedServers.push(repo);
            collectedUrls.add(githubUrl);
            mcpCount++;
          }
        }
      }
      
      console.log(`   추가 검색 서버 수집: ${mcpCount}개\n`);
    }
    
    console.log(`\n=== 수집 완료 ===`);
    console.log(`총 수집된 서버: ${collectedServers.length}개`);
    
  } catch (error) {
    console.error('수집 중 오류 발생:', error);
    throw error;
  }
}

// 스크립트 실행
if (require.main === module) {
  // 커맨드라인 인자에서 개수 가져오기
  let maxResults = 30; // 기본값
  
  if (process.argv.length > 2) {
    const arg = parseInt(process.argv[2], 10);
    if (!isNaN(arg) && arg > 0) {
      maxResults = arg;
    } else {
      console.error('오류: 유효한 숫자를 입력해주세요.');
      console.log('사용법: node autoCollectMcpServers.js [개수]');
      console.log('예시: node autoCollectMcpServers.js 50');
      process.exit(1);
    }
  }
  
  collectMcpServers(maxResults)
    .then(() => {
      console.log('\n자동 수집 완료!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n자동 수집 실패:', error);
      process.exit(1);
    });
}

module.exports = { collectMcpServers, extractServerNameFromUrl };


const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const { getKoreaTimeSQL } = require('../utils/dateTime');

// 데이터베이스 디렉토리 경로
const dbDir = path.join(__dirname, '..', 'db');

// 데이터베이스 디렉토리가 없으면 생성
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
  // 디렉토리 권한 설정 (읽기/쓰기/실행)
  try {
    fs.chmodSync(dbDir, 0o755);
    console.log(`데이터베이스 디렉토리 생성 및 권한 설정: ${dbDir}`);
  } catch (chmodError) {
    console.error(`디렉토리 권한 설정 실패: ${chmodError.message}`);
  }
}

// 데이터베이스 파일 경로 (프로젝트 루트의 db 폴더에 생성)
const dbPath = path.join(dbDir, 'bomtool.db');

// 데이터베이스 파일이 이미 존재하면 권한 확인 및 수정
if (fs.existsSync(dbPath)) {
  try {
    // 더 강력한 권한 설정 (읽기/쓰기 가능)
    fs.chmodSync(dbPath, 0o666);
    console.log(`데이터베이스 파일 권한 확인: ${dbPath}`);
    
    // 파일 소유자 확인
    const stats = fs.statSync(dbPath);
    console.log(`데이터베이스 파일 소유자: uid=${stats.uid}, gid=${stats.gid}`);
  } catch (chmodError) {
    console.error(`데이터베이스 파일 권한 설정 실패: ${chmodError.message}`);
    console.error(`파일 경로: ${dbPath}`);
    console.error(`파일 존재 여부: ${fs.existsSync(dbPath)}`);
  }
} else {
  console.log(`데이터베이스 파일이 없습니다. 새로 생성합니다: ${dbPath}`);
}

// 데이터베이스 연결 시 WAL 모드 사용 (더 나은 동시성 및 성능)
const db = new Database(dbPath, { 
  verbose: (sql) => {
    // SQL 쿼리 로그는 필요시 활성화
    // console.log('[SQL]', sql);
  }
});

// WAL 모드 활성화 (Write-Ahead Logging - 더 나은 동시성)
try {
  db.pragma('journal_mode = WAL');
  console.log('데이터베이스 WAL 모드 활성화 완료');
} catch (walError) {
  console.error('WAL 모드 활성화 실패:', walError.message);
  // WAL 모드가 실패해도 계속 진행
}

// 외래 키 제약 조건 활성화
db.pragma('foreign_keys = ON');

// 한국 시간을 사용하는 CURRENT_TIMESTAMP 함수 (SQLite에서 사용)
const KOREA_TIMESTAMP = "datetime('now', '+9 hours')";

// 기존 테이블 마이그레이션 (스키마 업데이트)
const migrateTables = () => {
  try {
    // Users 테이블 존재 여부 확인
    const tableExists = db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' AND name='users'
    `).get();
    
    // 테이블이 없으면 마이그레이션 건너뛰기 (initializeTables에서 생성됨)
    if (!tableExists) {
      console.log('Users 테이블이 아직 생성되지 않았습니다. 초기화 후 마이그레이션됩니다.');
      return;
    }
    
    // Users 테이블 마이그레이션
    const tableInfo = db.prepare("PRAGMA table_info(users)").all();
    const columnNames = tableInfo.map(col => col.name);
    
    // employee_id 컬럼 추가
    if (!columnNames.includes('employee_id')) {
      // SQLite는 ALTER TABLE ADD COLUMN에서 DEFAULT만 지원하므로, UNIQUE 제약은 별도 처리
      db.exec(`ALTER TABLE users ADD COLUMN employee_id TEXT`);
      // 기존 데이터에 기본값 할당
      const existingUsers = db.prepare('SELECT id FROM users WHERE employee_id IS NULL').all();
      if (existingUsers.length > 0) {
        const updateStmt = db.prepare('UPDATE users SET employee_id = ? WHERE id = ?');
        existingUsers.forEach(user => {
          updateStmt.run(`EMP${String(user.id).padStart(3, '0')}`, user.id);
        });
      }
      // UNIQUE 인덱스 생성
      db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_employee_id ON users(employee_id)');
      console.log('Users 테이블: employee_id 컬럼 추가 완료');
    }
    
    // team 컬럼 추가
    if (!columnNames.includes('team')) {
      db.exec('ALTER TABLE users ADD COLUMN team TEXT');
      console.log('Users 테이블: team 컬럼 추가 완료');
    }
    
    // position 컬럼 추가
    if (!columnNames.includes('position')) {
      db.exec('ALTER TABLE users ADD COLUMN position TEXT');
      console.log('Users 테이블: position 컬럼 추가 완료');
    }
    
    // is_active 컬럼 추가
    if (!columnNames.includes('is_active')) {
      db.exec('ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1');
      console.log('Users 테이블: is_active 컬럼 추가 완료');
    }
    
    // role 컬럼이 있으면 제거 (RBAC로 대체)
    if (columnNames.includes('role')) {
      // role 컬럼은 유지하되, user_roles 테이블을 우선 사용
      console.log('Users 테이블: role 컬럼은 유지 (하위 호환성)');
    }

    // MCP Register Requests 테이블 마이그레이션
    try {
      const requestTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_register_requests'
      `).get();
      
      if (requestTableExists) {
        const requestTableInfo = db.prepare("PRAGMA table_info(mcp_register_requests)").all();
        const requestColumnNames = requestTableInfo.map(col => col.name);
        
        // title 컬럼 추가
        if (!requestColumnNames.includes('title')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN title TEXT`);
          // 기존 name 값을 title로 복사
          db.exec(`UPDATE mcp_register_requests SET title = name WHERE title IS NULL`);
          console.log('MCP Register Requests 테이블: title 컬럼 추가 완료');
        }
        
        // priority 컬럼 추가
        if (!requestColumnNames.includes('priority')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN priority TEXT DEFAULT 'normal'`);
          console.log('MCP Register Requests 테이블: priority 컬럼 추가 완료');
        }
        
        // reviewed_by 컬럼 추가
        if (!requestColumnNames.includes('reviewed_by')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN reviewed_by INTEGER`);
          console.log('MCP Register Requests 테이블: reviewed_by 컬럼 추가 완료');
        }
        
        // review_comment 컬럼 추가
        if (!requestColumnNames.includes('review_comment')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN review_comment TEXT`);
          console.log('MCP Register Requests 테이블: review_comment 컬럼 추가 완료');
        }
        
        // reviewed_at 컬럼 추가
        if (!requestColumnNames.includes('reviewed_at')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN reviewed_at DATETIME`);
          console.log('MCP Register Requests 테이블: reviewed_at 컬럼 추가 완료');
        }
        
        // connection_snippet 컬럼 추가
        if (!requestColumnNames.includes('connection_snippet')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN connection_snippet TEXT`);
          console.log('MCP Register Requests 테이블: connection_snippet 컬럼 추가 완료');
        }
        
        // image_path 컬럼 추가
        if (!requestColumnNames.includes('image_path')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN image_path TEXT`);
          console.log('MCP Register Requests 테이블: image_path 컬럼 추가 완료');
        }
        
        // scanned 컬럼 추가 (스캔 완료 여부)
        if (!requestColumnNames.includes('scanned')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN scanned INTEGER DEFAULT 0`);
          console.log('MCP Register Requests 테이블: scanned 컬럼 추가 완료');
        }
        // auth_token 컬럼 추가 (하위 호환성 유지)
        if (!requestColumnNames.includes('auth_token')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN auth_token TEXT`);
          console.log('MCP Register Requests 테이블: auth_token 컬럼 추가 완료');
        }
        // auth_field_name, auth_field_value 컬럼 추가 (필드명과 필드값 분리)
        if (!requestColumnNames.includes('auth_field_name')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN auth_field_name TEXT`);
          console.log('MCP Register Requests 테이블: auth_field_name 컬럼 추가 완료');
        }
        if (!requestColumnNames.includes('auth_field_value')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN auth_field_value TEXT`);
          console.log('MCP Register Requests 테이블: auth_field_value 컬럼 추가 완료');
        }
        // execution_args 컬럼 추가 (MCP 서버 실행 시 추가 인자)
        if (!requestColumnNames.includes('execution_args')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN execution_args TEXT`);
          console.log('MCP Register Requests 테이블: execution_args 컬럼 추가 완료');
        }
        // auth_tokens 컬럼 추가 (여러 개의 토큰을 JSON으로 저장)
        if (!requestColumnNames.includes('auth_tokens')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN auth_tokens TEXT`);
          console.log('MCP Register Requests 테이블: auth_tokens 컬럼 추가 완료');
        }
        
        // languages 컬럼 추가 (스캔 결과에서 감지된 언어)
        if (!requestColumnNames.includes('languages')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN languages TEXT`);
          console.log('MCP Register Requests 테이블: languages 컬럼 추가 완료');
        }
        
        // analysis_timestamp 컬럼 추가 (분석 완료 시각)
        if (!requestColumnNames.includes('analysis_timestamp')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN analysis_timestamp DATETIME`);
          console.log('MCP Register Requests 테이블: analysis_timestamp 컬럼 추가 완료');
        }
      }
    } catch (requestError) {
      console.error('MCP Register Requests 테이블 마이그레이션 오류:', requestError);
    }

    // MCP Servers 테이블 마이그레이션
    try {
      const serverTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_servers'
      `).get();
      
      if (serverTableExists) {
        const serverTableInfo = db.prepare("PRAGMA table_info(mcp_servers)").all();
        const serverColumnNames = serverTableInfo.map(col => col.name);
        
        // short_description 컬럼 추가 (카드 표지용)
        if (!serverColumnNames.includes('short_description')) {
          db.exec(`ALTER TABLE mcp_servers ADD COLUMN short_description TEXT`);
          console.log('MCP Servers 테이블: short_description 컬럼 추가 완료');
        }
        
        // 기존 데이터의 short_description이 NULL인 경우 description과 동일하게 설정
        db.exec(`UPDATE mcp_servers SET short_description = description WHERE short_description IS NULL AND description IS NOT NULL`);
        console.log('기존 MCP 서버 데이터의 short_description 업데이트 완료');
        
        // allowed_teams 컬럼 추가 (팀별 접근 권한)
        if (!serverColumnNames.includes('allowed_teams')) {
          db.exec(`ALTER TABLE mcp_servers ADD COLUMN allowed_teams TEXT`);
          console.log('MCP Servers 테이블: allowed_teams 컬럼 추가 완료');
          // 기존 데이터는 모든 팀이 접근 가능하도록 NULL 유지 (NULL = 모든 팀 접근 가능)
        }
        
        // languages 컬럼 추가 (스캔 결과에서 감지된 언어)
        if (!serverColumnNames.includes('languages')) {
          db.exec(`ALTER TABLE mcp_servers ADD COLUMN languages TEXT`);
          console.log('MCP Servers 테이블: languages 컬럼 추가 완료');
        }
        
        // analysis_timestamp 컬럼 추가 (분석 완료 시각)
        if (!serverColumnNames.includes('analysis_timestamp')) {
          db.exec(`ALTER TABLE mcp_servers ADD COLUMN analysis_timestamp DATETIME`);
          console.log('MCP Servers 테이블: analysis_timestamp 컬럼 추가 완료');
        }
      }
    } catch (serverError) {
      console.error('MCP Servers 테이블 마이그레이션 오류:', serverError);
    }

    // DLP Violation Logs 테이블 마이그레이션
    try {
      const dlpTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='dlp_violation_logs'
      `).get();
      
      if (dlpTableExists) {
        const dlpTableInfo = db.prepare("PRAGMA table_info(dlp_violation_logs)").all();
        const dlpColumnNames = dlpTableInfo.map(col => col.name);
        
        // original_text, masked_text, original_json 컬럼 추가
        if (!dlpColumnNames.includes('original_text')) {
          db.exec(`ALTER TABLE dlp_violation_logs ADD COLUMN original_text TEXT`);
          console.log('DLP Violation Logs 테이블: original_text 컬럼 추가 완료');
        }
        if (!dlpColumnNames.includes('masked_text')) {
          db.exec(`ALTER TABLE dlp_violation_logs ADD COLUMN masked_text TEXT`);
          console.log('DLP Violation Logs 테이블: masked_text 컬럼 추가 완료');
        }
        if (!dlpColumnNames.includes('original_json')) {
          db.exec(`ALTER TABLE dlp_violation_logs ADD COLUMN original_json TEXT`);
          console.log('DLP Violation Logs 테이블: original_json 컬럼 추가 완료');
        }
      }
    } catch (dlpError) {
      console.error('DLP Violation Logs 테이블 마이그레이션 오류:', dlpError);
    }

    // IP User Mappings 테이블 마이그레이션 (테이블 생성 확인만, 컬럼 추가는 불필요)
    try {
      const ipMappingTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='ip_user_mappings'
      `).get();
      
      if (!ipMappingTableExists) {
        db.exec(`
          CREATE TABLE ip_user_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            username TEXT,
            employee_id TEXT,
            description TEXT,
            created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
            updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
            FOREIGN KEY (username) REFERENCES users(username),
            FOREIGN KEY (employee_id) REFERENCES users(employee_id)
          )
        `);
        console.log('IP User Mappings 테이블 생성 완료');
      }
    } catch (ipMappingError) {
      console.error('IP User Mappings 테이블 마이그레이션 오류:', ipMappingError);
    }

    // Users 테이블에 ip_address 컬럼 추가 마이그레이션
    try {
      const usersTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='users'
      `).get();
      
      if (usersTableExists) {
        const usersTableInfo = db.prepare("PRAGMA table_info(users)").all();
        const usersColumnNames = usersTableInfo.map(col => col.name);
        
        if (!usersColumnNames.includes('ip_address')) {
          db.exec(`ALTER TABLE users ADD COLUMN ip_address TEXT`);
          console.log('Users 테이블: ip_address 컬럼 추가 완료');
        }
      }
    } catch (usersError) {
      console.error('Users 테이블 마이그레이션 오류:', usersError);
    }

    // ==================== API 키 관리 테이블 생성 ====================
    try {
      const apiKeysTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='api_keys'
      `).get();
      
      if (!apiKeysTableExists) {
        db.exec(`
          CREATE TABLE api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mcp_server_name TEXT NOT NULL,
            field_name TEXT NOT NULL,
            field_value TEXT NOT NULL,
            field_description TEXT,
            auth_type TEXT DEFAULT 'Key/Token 인증',
            created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
            updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
          )
        `);
        // 사용자별 MCP 서버별 필드명 중복 방지 인덱스
        db.exec(`
          CREATE UNIQUE INDEX IF NOT EXISTS idx_user_server_field 
          ON api_keys(user_id, mcp_server_name, field_name)
        `);
        console.log('API Keys 테이블 생성 완료');
      }
    } catch (apiKeysError) {
      console.error('API Keys 테이블 마이그레이션 오류:', apiKeysError);
    }

    // ==================== Code Vulnerabilities 테이블 마이그레이션 ====================
    try {
      const codeVulnTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='code_vulnerabilities'
      `).get();
      
      if (codeVulnTableExists) {
        const codeVulnTableInfo = db.prepare("PRAGMA table_info(code_vulnerabilities)").all();
        const codeVulnColumnNames = codeVulnTableInfo.map(col => col.name);
        
        // mcp_server_name 컬럼 추가
        if (!codeVulnColumnNames.includes('mcp_server_name')) {
          db.exec(`ALTER TABLE code_vulnerabilities ADD COLUMN mcp_server_name TEXT`);
          console.log('Code Vulnerabilities 테이블: mcp_server_name 컬럼 추가 완료');
        }
        
        // result_filename 컬럼 추가
        if (!codeVulnColumnNames.includes('result_filename')) {
          db.exec(`ALTER TABLE code_vulnerabilities ADD COLUMN result_filename TEXT`);
          console.log('Code Vulnerabilities 테이블: result_filename 컬럼 추가 완료');
        }
      }
    } catch (codeVulnError) {
      console.error('Code Vulnerabilities 테이블 마이그레이션 오류:', codeVulnError);
    }

    // ==================== Tool 권한 관리 마이그레이션 ====================
    try {
      // mcp_servers 테이블에 tools 컬럼 추가
      const serverColumnInfo = db.prepare(`PRAGMA table_info(mcp_servers)`).all();
      const serverColumnNames = serverColumnInfo.map(col => col.name);
      
      if (!serverColumnNames.includes('tools')) {
        db.exec(`ALTER TABLE mcp_servers ADD COLUMN tools TEXT`);
        console.log('MCP Servers 테이블: tools 컬럼 추가 완료');
        // 기존 데이터는 NULL로 유지 (Tool 정보 없음 = 서버 전체 권한으로 처리)
      }

      // ==================== MCP Proxy 연동용 스키마 확장 ====================
      // server_type: 서버 연결 타입 (local, ssh, http, sse)
      if (!serverColumnNames.includes('server_type')) {
        db.exec(`ALTER TABLE mcp_servers ADD COLUMN server_type TEXT DEFAULT 'local'`);
        console.log('MCP Servers 테이블: server_type 컬럼 추가 완료');
      }

      // connection_config: 서버 연결 설정 (JSON 형식)
      if (!serverColumnNames.includes('connection_config')) {
        db.exec(`ALTER TABLE mcp_servers ADD COLUMN connection_config TEXT`);
        console.log('MCP Servers 테이블: connection_config 컬럼 추가 완료');
      }

      // mcp_tool_permissions 테이블에 tool_name 컬럼 추가
      const toolPermTableExists = db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='mcp_tool_permissions'
      `).get();
      
      if (toolPermTableExists) {
        const toolPermColumnInfo = db.prepare(`PRAGMA table_info(mcp_tool_permissions)`).all();
        const toolPermColumnNames = toolPermColumnInfo.map(col => col.name);
        
        if (!toolPermColumnNames.includes('tool_name')) {
          // tool_name 컬럼 추가
          db.exec(`ALTER TABLE mcp_tool_permissions ADD COLUMN tool_name TEXT`);
          console.log('MCP Tool Permissions 테이블: tool_name 컬럼 추가 완료');
          
          // 기존 UNIQUE 제약조건 제거 (수동으로 처리 필요)
          // SQLite는 ALTER TABLE로 UNIQUE 제약조건을 직접 제거할 수 없으므로
          // 새 인덱스 생성으로 대체 (기존 UNIQUE 제약조건은 유지하고 tool_name NULL 허용)
          
          // 새로운 복합 인덱스 생성 (tool_name 포함)
          try {
            db.exec(`
              CREATE UNIQUE INDEX IF NOT EXISTS idx_user_server_tool 
              ON mcp_tool_permissions(user_id, mcp_server_id, tool_name)
            `);
            console.log('MCP Tool Permissions 테이블: 복합 인덱스 생성 완료');
          } catch (indexError) {
            // 인덱스가 이미 존재하면 무시
            console.log('인덱스 생성 건너뜀 (이미 존재 또는 기존 UNIQUE 제약조건과 충돌 가능)');
          }
        }
      }

      // mcp_tool_team_permissions 테이블 생성
      const toolTeamPermTableExists = db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='mcp_tool_team_permissions'
      `).get();
      
      if (!toolTeamPermTableExists) {
        db.exec(`
          CREATE TABLE mcp_tool_team_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mcp_server_id INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            team TEXT NOT NULL,
            permission_type TEXT DEFAULT 'allow',
            created_by INTEGER,
            created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
            FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id),
            UNIQUE(mcp_server_id, tool_name, team)
          )
        `);
        console.log('MCP Tool Team Permissions 테이블 생성 완료');
      }
    } catch (toolError) {
      console.error('Tool 권한 관리 마이그레이션 오류:', toolError);
    }
    
  } catch (error) {
    console.error('마이그레이션 오류:', error);
  }
};

// 테이블 초기화
const initializeTables = () => {
  // ==================== RBAC 구조 ====================
  
  // Users 테이블 (확장)
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      employee_id TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      team TEXT,
      position TEXT,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      updated_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // Roles 테이블 (역할 정의)
  db.exec(`
    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // Permissions 테이블 (권한 정의)
  db.exec(`
    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      resource TEXT,
      action TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // User_Roles 테이블 (사용자-역할 매핑, 다대다)
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      role_id INTEGER NOT NULL,
      assigned_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      UNIQUE(user_id, role_id)
    )
  `);

  // Role_Permissions 테이블 (역할-권한 매핑, 다대다)
  db.exec(`
    CREATE TABLE IF NOT EXISTS role_permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role_id INTEGER NOT NULL,
      permission_id INTEGER NOT NULL,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
      UNIQUE(role_id, permission_id)
    )
  `);

  // MCP Servers 테이블 (마켓플레이스용)
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      short_description TEXT,
      github_link TEXT,
      connection_snippet TEXT,
      file_path TEXT,
      allowed_teams TEXT,
      tools TEXT,
      server_type TEXT DEFAULT 'local',
      connection_config TEXT,
      status TEXT DEFAULT 'approved',
      created_by INTEGER,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )
  `);

  // ==================== MCP 관련 ====================
  
  // MCP Register Requests 테이블 (게시판 기능 포함)
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_register_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      connection_snippet TEXT,
      github_link TEXT,
      file_path TEXT,
      image_path TEXT,
      status TEXT DEFAULT 'pending',
      priority TEXT DEFAULT 'normal',
      requested_by INTEGER NOT NULL,
      reviewed_by INTEGER,
      review_comment TEXT,
      reviewed_at DATETIME,
      scanned INTEGER DEFAULT 0,
      auth_token TEXT,
      auth_field_name TEXT,
      auth_field_value TEXT,
      execution_args TEXT,
      auth_tokens TEXT,
      languages TEXT,
      analysis_timestamp DATETIME,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (requested_by) REFERENCES users(id),
      FOREIGN KEY (reviewed_by) REFERENCES users(id)
    )
  `);

  // MCP Tools 테이블 (서버별 tool 정보 저장)
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_tools (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mcp_server_id INTEGER,
      server_name TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      tool_description TEXT,
      input_schema TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE,
      UNIQUE(server_name, tool_name)
    )
  `);
  
  // mcp_tools 테이블 마이그레이션 (server_name 추가 및 mcp_server_id NOT NULL 제약조건 제거)
  try {
    const toolsTableInfo = db.prepare("PRAGMA table_info(mcp_tools)").all();
    const toolsColumnNames = toolsTableInfo.map(col => col.name);
    const mcpServerIdColumn = toolsTableInfo.find(col => col.name === 'mcp_server_id');
    const isMcpServerIdNotNull = mcpServerIdColumn && mcpServerIdColumn.notnull === 1;
    
    // server_name 컬럼이 없거나 mcp_server_id가 NOT NULL이면 테이블 재생성
    if (!toolsColumnNames.includes('server_name') || isMcpServerIdNotNull) {
      console.log('mcp_tools 테이블 마이그레이션 시작...');
      
      // 기존 데이터 백업
      const existingData = db.prepare('SELECT * FROM mcp_tools').all();
      console.log(`기존 데이터 백업: ${existingData.length}개 레코드`);
      
      // 기존 테이블 삭제
      db.exec('DROP TABLE IF EXISTS mcp_tools');
      console.log('기존 mcp_tools 테이블 삭제 완료');
      
      // 새 테이블 생성 (mcp_server_id는 NULL 허용)
      db.exec(`
        CREATE TABLE mcp_tools (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          mcp_server_id INTEGER,
          server_name TEXT NOT NULL,
          tool_name TEXT NOT NULL,
          tool_description TEXT,
          input_schema TEXT,
          created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
          updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
          FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE,
          UNIQUE(server_name, tool_name)
        )
      `);
      console.log('새 mcp_tools 테이블 생성 완료');
      
      // 기존 데이터 복원 (server_name이 있으면 복원, 없으면 mcp_server_id로 조회)
      if (existingData.length > 0) {
        const insertStmt = db.prepare(`
          INSERT INTO mcp_tools (mcp_server_id, server_name, tool_name, tool_description, input_schema, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        
        let restoredCount = 0;
        for (const row of existingData) {
          let serverName = row.server_name;
          
          // server_name이 없으면 mcp_server_id로 조회
          if (!serverName && row.mcp_server_id) {
            const server = db.prepare('SELECT name FROM mcp_servers WHERE id = ?').get(row.mcp_server_id);
            if (server) {
              serverName = server.name;
            }
          }
          
          // server_name이 있으면 복원
          if (serverName) {
            try {
              insertStmt.run(
                row.mcp_server_id || null,
                serverName,
                row.tool_name,
                row.tool_description || null,
                row.input_schema || null,
                row.created_at || null,
                row.updated_at || null
              );
              restoredCount++;
            } catch (restoreError) {
              console.error('데이터 복원 오류:', restoreError);
            }
          }
        }
        console.log(`기존 데이터 복원 완료: ${restoredCount}개 레코드`);
      }
      
      console.log('mcp_tools 테이블 마이그레이션 완료');
    }
  } catch (migrationError) {
    console.error('mcp_tools 테이블 마이그레이션 오류:', migrationError);
  }

  // MCP Tool Access Permissions 테이블 (MCP 서버별 접근 권한)
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_tool_permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      mcp_server_id INTEGER NOT NULL,
      tool_name TEXT,
      granted_by INTEGER,
      granted_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE,
      FOREIGN KEY (granted_by) REFERENCES users(id),
      UNIQUE(user_id, mcp_server_id, tool_name)
    )
  `);

  // ==================== 추적/로그 ====================
  
  // Download Logs 테이블 (파일 다운로드 추적)
  db.exec(`
    CREATE TABLE IF NOT EXISTS download_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      file_path TEXT NOT NULL,
      file_name TEXT,
      mcp_server_id INTEGER,
      downloaded_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      ip_address TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id)
    )
  `);

  // MCP Tool Usage Logs 테이블 (MCP 도구 사용 추적)
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_tool_usage_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      mcp_server_id INTEGER NOT NULL,
      action TEXT,
      details TEXT,
      used_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      ip_address TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id)
    )
  `);

  // IP 사용자 매핑 테이블 (IP → 사용자 매핑)
  db.exec(`
    CREATE TABLE IF NOT EXISTS ip_user_mappings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_address TEXT UNIQUE NOT NULL,
      username TEXT,
      employee_id TEXT,
      description TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (username) REFERENCES users(username),
      FOREIGN KEY (employee_id) REFERENCES users(employee_id)
    )
  `);

  // DLP Violation Logs 테이블 (DLP 위반 추적)
  db.exec(`
    CREATE TABLE IF NOT EXISTS dlp_violation_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      employee_id TEXT,
      source_ip TEXT NOT NULL,
      destination_ip TEXT,
      protocol TEXT,
      action_type TEXT NOT NULL,
      violation_type TEXT NOT NULL,
      severity TEXT DEFAULT 'medium',
      file_name TEXT,
      file_path TEXT,
      file_size INTEGER,
      file_hash TEXT,
      content_summary TEXT,
      matched_pattern TEXT,
      rule_id TEXT,
      rule_name TEXT,
      user_agent TEXT,
      timestamp DATETIME DEFAULT (datetime('now', '+9 hours')),
      status TEXT DEFAULT 'pending',
      handled_by INTEGER,
      handled_at DATETIME,
      notes TEXT,
      original_text TEXT,
      masked_text TEXT,
      original_json TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (handled_by) REFERENCES users(id)
    )
  `);

  // Permission Violation Logs 테이블 (권한 위반 추적)
  db.exec(`
    CREATE TABLE IF NOT EXISTS permission_violation_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      employee_id TEXT,
      source_ip TEXT NOT NULL,
      mcp_server_id INTEGER,
      mcp_server_name TEXT,
      tool_name TEXT NOT NULL,
      violation_type TEXT NOT NULL,
      reason TEXT,
      severity TEXT DEFAULT 'medium',
      timestamp DATETIME DEFAULT (datetime('now', '+9 hours')),
      status TEXT DEFAULT 'pending',
      handled_by INTEGER,
      handled_at DATETIME,
      notes TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id),
      FOREIGN KEY (handled_by) REFERENCES users(id)
    )
  `);

  // Code Vulnerabilities 테이블 (코드 스캔 결과 저장)
  db.exec(`
    CREATE TABLE IF NOT EXISTS code_vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT,
      scan_path TEXT,
      mcp_server_name TEXT,
      scan_timestamp DATETIME DEFAULT (datetime('now', '+9 hours')),
      rule_id TEXT,
      vulnerability TEXT,
      severity TEXT,
      language TEXT,
      file TEXT,
      line INTEGER,
      column INTEGER,
      message TEXT,
      description TEXT,
      cwe TEXT,
      code_snippet TEXT,
      pattern_type TEXT,
      pattern TEXT,
      confidence TEXT,
      raw_finding TEXT,
      result_filename TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // OSS Vulnerabilities 테이블 생성
  db.exec(`
    CREATE TABLE IF NOT EXISTS oss_vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT,
      scan_path TEXT,
      scan_timestamp DATETIME DEFAULT (datetime('now', '+9 hours')),
      package_name TEXT NOT NULL,
      package_version TEXT,
      package_fixed_version TEXT,
      package_all_fixed_versions TEXT,
      package_affected_range TEXT,
      package_dependency_type TEXT,
      vulnerability_id TEXT,
      vulnerability_cve TEXT,
      vulnerability_cvss REAL,
      vulnerability_severity TEXT,
      vulnerability_title TEXT,
      vulnerability_description TEXT,
      vulnerability_reference_url TEXT,
      reachable INTEGER DEFAULT 0,
      functions_count INTEGER DEFAULT 0,
      reachable_functions INTEGER DEFAULT 0,
      unreachable_functions INTEGER DEFAULT 0,
      raw_data TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // Tool Validation Vulnerabilities 테이블 (TOOL-VET 결과 저장)
  // tool_name은 nullable (global_vulnerabilities는 tool_name이 null일 수 있음)
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

  // OSS Vulnerabilities 테이블에 mcp_server_name 컬럼 추가 (마이그레이션)
  try {
    const ossColumnInfo = db.prepare("PRAGMA table_info(oss_vulnerabilities)").all();
    const ossColumnNames = ossColumnInfo.map(col => col.name);
    if (!ossColumnNames.includes('mcp_server_name')) {
      db.exec(`ALTER TABLE oss_vulnerabilities ADD COLUMN mcp_server_name TEXT`);
      console.log('OSS Vulnerabilities 테이블: mcp_server_name 컬럼 추가 완료');
    }
  } catch (ossError) {
    console.error('OSS Vulnerabilities 테이블 마이그레이션 오류:', ossError);
  }

  // Tool Validation Vulnerabilities 테이블에 mcp_server_name 컬럼 추가 (마이그레이션)
  try {
    const toolVulnColumnInfo = db.prepare("PRAGMA table_info(tool_validation_vulnerabilities)").all();
    const toolVulnColumnNames = toolVulnColumnInfo.map(col => col.name);
    if (!toolVulnColumnNames.includes('mcp_server_name')) {
      db.exec(`ALTER TABLE tool_validation_vulnerabilities ADD COLUMN mcp_server_name TEXT`);
      console.log('Tool Validation Vulnerabilities 테이블: mcp_server_name 컬럼 추가 완료');
    }
  } catch (toolVulnError) {
    console.error('Tool Validation Vulnerabilities 테이블 마이그레이션 오류:', toolVulnError);
  }

  // Tool Validation Vulnerabilities 테이블의 tool_name을 nullable로 변경 (마이그레이션)
  // SQLite는 NOT NULL 제약조건을 직접 제거할 수 없으므로, 테이블을 재생성해야 함
  try {
    const toolVulnTableExists = db.prepare(`
      SELECT name FROM sqlite_master WHERE type='table' AND name='tool_validation_vulnerabilities'
    `).get();
    
    if (toolVulnTableExists) {
      const toolVulnColumnInfo = db.prepare("PRAGMA table_info(tool_validation_vulnerabilities)").all();
      const toolNameColumn = toolVulnColumnInfo.find(col => col.name === 'tool_name');
      
      // tool_name이 NOT NULL이고 nullable로 변경이 필요한 경우
      if (toolNameColumn && toolNameColumn.notnull === 1) {
        console.log('Tool Validation Vulnerabilities 테이블: tool_name을 nullable로 변경 중...');
        
        // 기존 데이터 백업
        const existingData = db.prepare('SELECT * FROM tool_validation_vulnerabilities').all();
        
        // 기존 테이블 삭제
        db.exec('DROP TABLE IF EXISTS tool_validation_vulnerabilities_backup');
        db.exec('ALTER TABLE tool_validation_vulnerabilities RENAME TO tool_validation_vulnerabilities_backup');
        
        // 새 테이블 생성 (tool_name을 nullable로)
        db.exec(`
          CREATE TABLE tool_validation_vulnerabilities (
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
        
        // 기존 데이터 복원
        if (existingData.length > 0) {
          const insertStmt = db.prepare(`
            INSERT INTO tool_validation_vulnerabilities (
              id, scan_id, scan_path, scan_timestamp, tool_name, host, method, path,
              category_code, category_name, title, description, evidence, recommendation, raw_data, mcp_server_name, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          
          for (const row of existingData) {
            insertStmt.run(
              row.id,
              row.scan_id,
              row.scan_path,
              row.scan_timestamp,
              row.tool_name,
              row.host,
              row.method,
              row.path,
              row.category_code,
              row.category_name,
              row.title,
              row.description,
              row.evidence,
              row.recommendation,
              row.raw_data,
              row.mcp_server_name || null,
              row.created_at
            );
          }
        }
        
        // 백업 테이블 삭제
        db.exec('DROP TABLE IF EXISTS tool_validation_vulnerabilities_backup');
        
        console.log('Tool Validation Vulnerabilities 테이블: tool_name을 nullable로 변경 완료');
      }
    }
  } catch (toolNameMigrateError) {
    console.error('Tool Validation Vulnerabilities 테이블 tool_name 마이그레이션 오류:', toolNameMigrateError);
  }

  // Tool Validation Reports 테이블 (TOOL-VET 리포트 전체 저장)
  db.exec(`
    CREATE TABLE IF NOT EXISTS tool_validation_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT,
      scan_path TEXT,
      mcp_server_name TEXT,
      scan_timestamp DATETIME DEFAULT (datetime('now', '+9 hours')),
      report_data TEXT NOT NULL,
      total_tools INTEGER DEFAULT 0,
      total_endpoints INTEGER DEFAULT 0,
      total_vulnerabilities INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      UNIQUE(scan_path, scan_timestamp)
    )
  `);

  // ==================== 기본 데이터 초기화 ====================
  
  // 기본 Roles 생성
  const roleCount = db.prepare('SELECT COUNT(*) as count FROM roles').get();
  if (roleCount.count === 0) {
    const roleStmt = db.prepare('INSERT INTO roles (name, description) VALUES (?, ?)');
    roleStmt.run('admin', '시스템 관리자 - 모든 권한');
    roleStmt.run('manager', '팀 매니저 - 팀 관리 및 승인 권한');
    roleStmt.run('user', '일반 사용자 - 기본 접근 권한');
    console.log('기본 역할 생성 완료');
  }

  // 기본 Permissions 생성
  const permCount = db.prepare('SELECT COUNT(*) as count FROM permissions').get();
  if (permCount.count === 0) {
    const permStmt = db.prepare('INSERT INTO permissions (name, description, resource, action) VALUES (?, ?, ?, ?)');
    
    // 파일 다운로드 관련
    permStmt.run('download_file', '파일 다운로드', 'file', 'download');
    permStmt.run('view_download_log', '다운로드 로그 조회', 'log', 'view');
    
    // MCP 도구 관련
    permStmt.run('use_mcp_tool', 'MCP 도구 사용', 'mcp_tool', 'use');
    permStmt.run('manage_mcp_tool', 'MCP 도구 관리', 'mcp_tool', 'manage');
    
    // 게시판/요청 관련
    permStmt.run('create_request', 'MCP 서버 등록 요청', 'request', 'create');
    permStmt.run('view_request', '등록 요청 조회', 'request', 'view');
    permStmt.run('approve_request', '등록 요청 승인', 'request', 'approve');
    permStmt.run('reject_request', '등록 요청 거부', 'request', 'reject');
    
    // 사용자 관리
    permStmt.run('view_user', '사용자 조회', 'user', 'view');
    permStmt.run('manage_user', '사용자 관리', 'user', 'manage');
    
    // 대시보드
    permStmt.run('view_dashboard', '대시보드 조회', 'dashboard', 'view');
    
    console.log('기본 권한 생성 완료');
  }

  // Role-Permission 매핑 (관리자는 모든 권한)
  const adminRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('admin');
  const managerRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('manager');
  const userRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('user');
  
  const rolePermCount = db.prepare('SELECT COUNT(*) as count FROM role_permissions').get();
  if (rolePermCount.count === 0 && adminRole && managerRole && userRole) {
    const rolePermStmt = db.prepare('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)');
    const allPerms = db.prepare('SELECT id FROM permissions').all();
    
    // Admin: 모든 권한
    allPerms.forEach(perm => {
      rolePermStmt.run(adminRole.id, perm.id);
    });
    
    // Manager: 관리 권한
    const managerPerms = ['view_dashboard', 'view_user', 'view_request', 'approve_request', 'reject_request', 'view_download_log', 'use_mcp_tool'];
    managerPerms.forEach(permName => {
      const perm = db.prepare('SELECT id FROM permissions WHERE name = ?').get(permName);
      if (perm) rolePermStmt.run(managerRole.id, perm.id);
    });
    
    // User: 기본 권한
    const userPerms = ['view_dashboard', 'create_request', 'view_request', 'use_mcp_tool'];
    userPerms.forEach(permName => {
      const perm = db.prepare('SELECT id FROM permissions WHERE name = ?').get(permName);
      if (perm) rolePermStmt.run(userRole.id, perm.id);
    });
    
    console.log('역할-권한 매핑 완료');
  }

  // 기본 관리자 계정 생성 또는 role 할당
  const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  const userExists = db.prepare('SELECT id FROM users WHERE username = ?').get('user');
  
  if (!adminExists) {
    // 새로 생성
    const userStmt = db.prepare('INSERT INTO users (username, employee_id, email, password, team, position) VALUES (?, ?, ?, ?, ?, ?)');
    const adminUserId = userStmt.run('admin', 'EMP001', 'admin@example.com', 'admin', 'IT', 'Administrator').lastInsertRowid;
    const userUserId = userExists 
      ? userExists.id 
      : userStmt.run('user', 'EMP002', 'user@example.com', 'user', 'Development', 'Developer').lastInsertRowid;
    
    // 관리자 역할 할당
    if (adminRole) {
      const userRoleStmt = db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
      userRoleStmt.run(adminUserId, adminRole.id);
      if (!userExists) {
        userRoleStmt.run(userUserId, userRole.id);
      }
    }
    
    console.log('기본 사용자 계정 생성 완료');
  } else {
    // 기존 계정에 role이 없는 경우 추가
    const adminUserRoles = db.prepare('SELECT COUNT(*) as count FROM user_roles WHERE user_id = ?').get(adminExists.id);
    if (adminUserRoles.count === 0 && adminRole) {
      const userRoleStmt = db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
      userRoleStmt.run(adminExists.id, adminRole.id);
      console.log('기존 admin 계정에 admin 역할 추가 완료');
    }
    
    // user 계정에도 role 확인 및 추가
    if (userExists) {
      const userUserRoles = db.prepare('SELECT COUNT(*) as count FROM user_roles WHERE user_id = ?').get(userExists.id);
      if (userUserRoles.count === 0 && userRole) {
        const userRoleStmt = db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
        userRoleStmt.run(userExists.id, userRole.id);
        console.log('기존 user 계정에 user 역할 추가 완료');
      }
    }
  }

  // 기본 MCP 서버 데이터가 없으면 생성
  const mcpCount = db.prepare('SELECT COUNT(*) as count FROM mcp_servers WHERE status = ?').get('approved');
  if (mcpCount.count === 0) {
    const mcpStmt = db.prepare(`
      INSERT INTO mcp_servers (name, description, short_description, github_link, connection_snippet, status, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    
  }

  // Code Vulnerabilities 테이블 마이그레이션
  try {
    const codeVulnTableExists = db.prepare(`
      SELECT name FROM sqlite_master WHERE type='table' AND name='code_vulnerabilities'
    `).get();
    
    if (codeVulnTableExists) {
      const codeVulnTableInfo = db.prepare("PRAGMA table_info(code_vulnerabilities)").all();
      const codeVulnColumnNames = codeVulnTableInfo.map(col => col.name);
      
      // result_filename 컬럼 추가
      if (!codeVulnColumnNames.includes('result_filename')) {
        db.exec(`ALTER TABLE code_vulnerabilities ADD COLUMN result_filename TEXT`);
        console.log('Code Vulnerabilities 테이블: result_filename 컬럼 추가 완료');
      }
    }
  } catch (codeVulnError) {
    console.error('Code Vulnerabilities 테이블 마이그레이션 오류:', codeVulnError);
  }

  console.log('데이터베이스 테이블 초기화 완료');
};

// 데이터베이스 초기화 실행
migrateTables(); // 먼저 마이그레이션
initializeTables(); // 그 다음 테이블 생성 및 데이터 초기화

module.exports = db;


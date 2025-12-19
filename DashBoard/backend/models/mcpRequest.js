const db = require('../config/db');

const mcpRequestModel = {
  // 모든 등록 요청 조회
  findAll: (status = null) => {
    if (status) {
      return db.prepare('SELECT * FROM mcp_register_requests WHERE status = ? ORDER BY created_at DESC').all(status);
    }
    return db.prepare('SELECT * FROM mcp_register_requests ORDER BY created_at DESC').all();
  },

  // 페이징을 포함한 등록 요청 조회
  findAllPaginated: (status = null, page = 1, limit = 20, userId = null, userTeam = null) => {
    const offset = (page - 1) * limit;
    let countQuery, dataQuery, params = [];

    // WHERE 조건 구성
    const conditions = [];

    if (status) {
      conditions.push('status = ?');
      params.push(status);
    }
    
    if (userId !== null) {
      // user: 자신이 신청한 것만
      conditions.push('requested_by = ?');
      params.push(userId);
    } else if (userTeam !== null) {
      // manager: 자신의 팀에서 신청한 것만
      // 요청자의 팀을 확인하기 위해 JOIN 필요
      conditions.push(`requested_by IN (
        SELECT id FROM users WHERE team = ?
      )`);
      params.push(userTeam);
    }
    // admin: 조건 없음 (모든 요청)

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    
    countQuery = `SELECT COUNT(*) as total FROM mcp_register_requests ${whereClause}`;
    dataQuery = `SELECT * FROM mcp_register_requests ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    
    params.push(limit, offset);

    const totalResult = db.prepare(countQuery).get(...params.slice(0, -2));
    const total = totalResult.total;
    const data = db.prepare(dataQuery).all(...params);

    return {
      data,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    };
  },

  // ID로 조회
  findById: (id) => {
    return db.prepare('SELECT * FROM mcp_register_requests WHERE id = ?').get(id);
  },

  // 사용자별 등록 요청 조회
  findByUserId: (userId) => {
    return db.prepare('SELECT * FROM mcp_register_requests WHERE requested_by = ? ORDER BY created_at DESC').all(userId);
  },

  // 등록 요청 생성
  create: (title, name, description, connectionSnippet, githubLink, filePath, requestedBy, priority = 'normal', imagePath = null, authToken = null, authFieldName = null, authFieldValue = null, executionArgs = null, authTokens = null) => {
    const stmt = db.prepare(`
      INSERT INTO mcp_register_requests (title, name, description, connection_snippet, github_link, file_path, image_path, requested_by, priority, auth_token, auth_field_name, auth_field_value, execution_args, auth_tokens) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const authTokensJson = authTokens ? JSON.stringify(authTokens) : null;
    const result = stmt.run(title || name, name, description, connectionSnippet || null, githubLink, filePath, imagePath, requestedBy, priority, authToken || null, authFieldName || null, authFieldValue || null, executionArgs || null, authTokensJson);
    return {
      id: result.lastInsertRowid,
      title: title || name,
      name,
      description,
      connection_snippet: connectionSnippet,
      github_link: githubLink,
      file_path: filePath,
      image_path: imagePath,
      auth_token: authToken,
      auth_field_name: authFieldName,
      auth_field_value: authFieldValue,
      execution_args: executionArgs,
      auth_tokens: authTokens,
      status: 'pending',
      priority
    };
  },

  // 등록 요청 상태 업데이트 (관리자 승인/거부)
  updateStatus: (id, status, reviewedBy, reviewComment = null) => {
    return db.prepare(`
      UPDATE mcp_register_requests 
      SET status = ?, reviewed_by = ?, review_comment = ?, reviewed_at = datetime('now', '+9 hours'), updated_at = datetime('now', '+9 hours') 
      WHERE id = ?
    `).run(status, reviewedBy, reviewComment, id);
  },

  // 등록 요청 삭제
  delete: (id) => {
    return db.prepare('DELETE FROM mcp_register_requests WHERE id = ?').run(id);
  }
};

module.exports = mcpRequestModel;


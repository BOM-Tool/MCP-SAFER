const db = require('../config/db');

const mcpServerModel = {
  // 모든 MCP 서버 조회 (status 필터링 옵션)
  findAll: (status = null) => {
    if (status) {
      return db.prepare('SELECT * FROM mcp_servers WHERE status = ?').all(status);
    }
    return db.prepare('SELECT * FROM mcp_servers').all();
  },

  // 특정 팀이 접근 가능한 MCP 서버 조회
  findByTeam: (team) => {
    // allowed_teams가 NULL이면 모든 팀 접근 가능, 아니면 JSON 배열에 팀이 포함되어야 함
    const servers = db.prepare(`
      SELECT * FROM mcp_servers 
      WHERE status = ? 
      AND (allowed_teams IS NULL OR allowed_teams = '[]' OR allowed_teams LIKE ?)
    `).all('approved', `%${team}%`);
    
    // JSON 파싱하여 정확히 매칭되는지 확인
    return servers.filter(server => {
      if (!server.allowed_teams || server.allowed_teams === '[]') return true;
      try {
        const teams = JSON.parse(server.allowed_teams);
        return Array.isArray(teams) && teams.includes(team);
      } catch (e) {
        // JSON 파싱 실패 시 LIKE 매칭 결과 사용
        return true;
      }
    });
  },

  // ID로 조회
  findById: (id) => {
    return db.prepare('SELECT * FROM mcp_servers WHERE id = ?').get(id);
  },

  // 이름으로 조회
  findByName: (name) => {
    return db.prepare('SELECT * FROM mcp_servers WHERE name = ?').get(name);
  },

  // 서버 ID(이름)로 조회 (Proxy용)
  findByServerId: (serverId) => {
    return db.prepare(`
      SELECT * FROM mcp_servers 
      WHERE name = ? AND status = 'approved'
    `).get(serverId);
  },

  // MCP 서버 생성
  create: (name, description, shortDescription, githubLink, connectionSnippet, filePath, createdBy, allowedTeams = null, tools = null, serverType = null, connectionConfig = null) => {
    // allowedTeams가 배열이면 JSON 문자열로 변환
    const allowedTeamsJson = allowedTeams ? JSON.stringify(allowedTeams) : null;
    // tools가 배열이면 JSON 문자열로 변환
    const toolsJson = tools ? JSON.stringify(tools) : null;
    // connectionConfig가 객체이면 JSON 문자열로 변환
    const connectionConfigJson = connectionConfig ? JSON.stringify(connectionConfig) : null;
    
    const stmt = db.prepare(`
      INSERT INTO mcp_servers (name, description, short_description, github_link, connection_snippet, file_path, allowed_teams, tools, created_by, server_type, connection_config, status) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(name, description, shortDescription, githubLink, connectionSnippet, filePath, allowedTeamsJson, toolsJson, createdBy, serverType, connectionConfigJson, 'approved');
    return {
      id: result.lastInsertRowid,
      name,
      description,
      short_description: shortDescription,
      github_link: githubLink,
      connection_snippet: connectionSnippet,
      file_path: filePath,
      allowed_teams: allowedTeams,
      tools: tools,
      server_type: serverType,
      connection_config: connectionConfig,
      status: 'approved'
    };
  },

  // MCP 서버 업데이트
  update: (id, data) => {
    const updates = [];
    const values = [];

    if (data.name) {
      updates.push('name = ?');
      values.push(data.name);
    }
    if (data.description) {
      updates.push('description = ?');
      values.push(data.description);
    }
    if (data.github_link) {
      updates.push('github_link = ?');
      values.push(data.github_link);
    }
    if (data.connection_snippet) {
      updates.push('connection_snippet = ?');
      values.push(data.connection_snippet);
    }
    if (data.status) {
      updates.push('status = ?');
      values.push(data.status);
    }

    if (updates.length === 0) return null;

    updates.push("updated_at = datetime('now', '+9 hours')");
    values.push(id);

    const stmt = db.prepare(`UPDATE mcp_servers SET ${updates.join(', ')} WHERE id = ?`);
    return stmt.run(...values);
  },

  // MCP 서버 삭제
  delete: (id) => {
    return db.prepare('DELETE FROM mcp_servers WHERE id = ?').run(id);
  }
};

module.exports = mcpServerModel;


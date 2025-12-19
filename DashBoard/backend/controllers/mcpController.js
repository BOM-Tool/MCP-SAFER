const db = require('../config/db');
const { getUserByIP } = require('../utils/userByIP');
const { extractClientIP, isLocalIP } = require('../middleware/clientIP');
const slackNotifier = require('../services/slackNotifier');
const permissionViolationEmitter = require('./permissionViolationController').emitter;

/**
 * Tool 접근 권한 확인
 * POST /api/mcp/check-permission
 * 
 * Headers:
 *   X-Original-Client-IP: 클라이언트 IP (MCP Proxy가 설정)
 *   X-Forwarded-For: 클라이언트 IP (프록시를 통한 경우)
 *   X-MCP-Proxy-Request: true (MCP Proxy 요청임을 표시)
 *   X-API-Key: API 키 (선택적)
 * 
 * Body: {
 *   tool_name: string,
 *   mcp_server_id: number
 * }
 */
const checkPermission = (req, res) => {
  try {
    // 요청 로깅 (디버깅용)
    console.log('\n=== MCP Proxy 권한 확인 요청 ===');
    console.log('시간:', new Date().toISOString());
    console.log('Method:', req.method);
    console.log('URL:', req.url);
    console.log('Headers:', {
      'x-original-client-ip': req.headers['x-original-client-ip'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-mcp-proxy-request': req.headers['x-mcp-proxy-request'],
      'x-api-key': req.headers['x-api-key'] ? '***' : undefined
    });
    console.log('Body:', req.body);
    console.log('Remote Address:', req.socket.remoteAddress);
    console.log('================================\n');

    const { tool_name, mcp_server_id, server_name } = req.body;

    // 필수 파라미터 검증 (mcp_server_id 또는 server_name 중 하나는 필수)
    if (!tool_name || (!mcp_server_id && !server_name)) {
      console.log('[권한 체크] 필수 파라미터 누락:', { tool_name, mcp_server_id, server_name });
      return res.status(400).json({
        success: false,
        message: 'tool_name과 mcp_server_id(또는 server_name)는 필수입니다.'
      });
    }

    // 클라이언트 IP 추출
    const clientIP = req.clientIP || extractClientIP(req);
    console.log('[권한 체크] 추출된 클라이언트 IP:', clientIP);

    // 로컬 IP 필터링 (선택적) - IP 기반 권한 추적 테스트를 위해 주석 처리
    // if (isLocalIP(clientIP)) {
    //   console.warn(`Local IP detected: ${clientIP}, skipping user lookup`);
    //   // 로컬 IP는 기본적으로 허용하지 않음 (또는 특별 처리)
    //   return res.json({
    //     success: true,
    //     allowed: false,
    //     reason: '로컬 IP는 사용자 인증이 필요합니다.',
    //     client_ip: clientIP
    //   });
    // }

    // IP 기반 사용자 조회
    const user = getUserByIP(clientIP);
    console.log('[권한 체크] 조회된 사용자:', user ? { id: user.id, username: user.username, team: user.team } : null);

    if (!user) {
      // 사용자를 찾을 수 없음
      console.log('[권한 체크] 사용자를 찾을 수 없음');
      return res.json({
        success: true,
        allowed: false,
        reason: `IP ${clientIP}에 해당하는 사용자를 찾을 수 없습니다.`,
        client_ip: clientIP
      });
    }

    // 서버 ID 또는 이름으로 서버 찾기
    let actualServerId = mcp_server_id;
    if (!actualServerId && server_name) {
      const serverByName = db.prepare(`
        SELECT id 
        FROM mcp_servers 
        WHERE name = ? AND status = 'approved'
        LIMIT 1
      `).get(server_name);
      
      if (serverByName) {
        actualServerId = serverByName.id;
        console.log(`[권한 체크] 서버 이름으로 서버 찾음: ${server_name} -> ID: ${actualServerId}`);
      } else {
        console.log(`[권한 체크] 서버 이름으로 서버를 찾을 수 없음: ${server_name}`);
        return res.json({
          success: true,
          allowed: false,
          reason: `MCP 서버(이름: ${server_name})를 찾을 수 없거나 승인되지 않았습니다.`,
          client_ip: clientIP,
          user: user
        });
      }
    }

    // 권한 체크
    const result = checkToolPermission(user, tool_name, actualServerId);
    console.log('[권한 체크] 결과:', { allowed: result.allowed, reason: result.reason, server_id: actualServerId });

    // 권한이 거부된 경우 로그 저장
    if (!result.allowed) {
      try {
        // MCP 서버 정보 조회
        const mcpServer = db.prepare('SELECT id, name FROM mcp_servers WHERE id = ?').get(mcp_server_id);
        
        // 위반 유형 결정
        let violationType = 'unauthorized_access';
        if (result.reason?.includes('팀')) {
          violationType = 'team_restriction';
        } else if (result.reason?.includes('Tool')) {
          violationType = 'tool_restriction';
        } else if (result.reason?.includes('서버')) {
          violationType = 'server_restriction';
        }

        // 권한 위반 로그 저장
        const insertLog = db.prepare(`
          INSERT INTO permission_violation_logs 
          (user_id, username, employee_id, source_ip, mcp_server_id, mcp_server_name, tool_name, violation_type, reason, severity)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        
        insertLog.run(
          user.id,
          user.username,
          user.employee_id,
          clientIP,
          mcp_server_id,
          mcpServer?.name || null,
          tool_name,
          violationType,
          result.reason || '권한이 없습니다.',
          'high' // 권한 위반은 높은 심각도
        );
        
        const savedLog = {
          id: insertLog.lastInsertRowid,
          user_id: user.id,
          username: user.username,
          employee_id: user.employee_id,
          source_ip: clientIP,
          mcp_server_id: mcp_server_id,
          mcp_server_name: mcpServer?.name || null,
          tool_name: tool_name,
          violation_type: violationType,
          reason: result.reason || '권한이 없습니다.',
          severity: 'high',
          timestamp: new Date().toISOString(),
          status: 'pending'
        };

        console.log('🚨 권한 위반 로그 저장 완료:', {
          user: user.username,
          tool: tool_name,
          server: mcpServer?.name,
          reason: result.reason
        });

        // SSE로 새로운 로그 알림 전송
        permissionViolationEmitter.emit('newLog', savedLog);

        // Slack 알림 전송 (비동기)
        slackNotifier.notifyPermissionViolation(savedLog);
      } catch (logError) {
        console.error('권한 위반 로그 저장 실패:', logError);
        // 로그 저장 실패해도 응답은 정상 반환
      }
    }

    const response = {
      success: true,
      allowed: result.allowed,
      reason: result.reason || null,
      client_ip: clientIP,
      user: {
        id: user.id,
        username: user.username,
        employee_id: user.employee_id,
        team: user.team
      }
    };

    console.log('[권한 체크] 응답:', JSON.stringify(response, null, 2));
    console.log('================================\n');

    res.json(response);
  } catch (error) {
    console.error('Tool 권한 확인 오류:', error);
    res.status(500).json({
      success: false,
      message: '권한 확인 중 오류가 발생했습니다.'
    });
  }
};

/**
 * Tool 권한 체크 로직
 */
function checkToolPermission(user, toolName, mcpServerId) {
  // 1. 관리자는 모든 Tool 접근 가능
  if (user.roles && user.roles.includes('admin')) {
    return { allowed: true };
  }

  // 2. MCP 서버 정보 조회 (먼저 서버 존재 여부 확인)
  const serverExists = db.prepare(`
    SELECT id, status 
    FROM mcp_servers 
    WHERE id = ?
  `).get(mcpServerId);

  if (!serverExists) {
    return { 
      allowed: false, 
      reason: `MCP 서버(ID: ${mcpServerId})를 찾을 수 없습니다.`,
      error_type: 'server_not_found'
    };
  }

  if (serverExists.status !== 'approved') {
    return { 
      allowed: false, 
      reason: `MCP 서버(ID: ${mcpServerId})가 승인되지 않았습니다. (현재 상태: ${serverExists.status})`,
      error_type: 'server_not_approved'
    };
  }

  // 서버가 존재하고 승인되었으므로 상세 정보 조회 (tools만 확인, allowed_teams는 마켓플레이스 필터링용이므로 권한 체크에 사용하지 않음)
  const server = db.prepare(`
    SELECT tools 
    FROM mcp_servers 
    WHERE id = ? AND status = 'approved'
  `).get(mcpServerId);

  // 3. Tool 존재 여부 확인 (tools 필드가 있으면)
  if (server.tools) {
    try {
      const tools = JSON.parse(server.tools);
      if (!Array.isArray(tools) || !tools.includes(toolName)) {
        return { 
          allowed: false, 
          reason: `해당 서버에 '${toolName}' Tool이 없습니다.` 
        };
      }
    } catch (e) {
      console.error('tools JSON 파싱 오류:', e);
      // JSON 파싱 실패 시 계속 진행 (하위 호환성)
    }
  }

  // 4. 사용자별 특정 Tool 권한 확인 (mcp_tool_permissions)
  const userToolPermission = db.prepare(`
    SELECT id 
    FROM mcp_tool_permissions 
    WHERE mcp_server_id = ? 
      AND user_id = ?
      AND tool_name = ?
  `).get(mcpServerId, user.id, toolName);

  if (userToolPermission) {
    return { allowed: true };
  }

  // 5. 팀별 Tool 권한 확인 (mcp_tool_team_permissions)
  // 명시적으로 설정된 Tool 권한이 있으면 그것을 우선 적용
  if (user.team) {
    const teamPermission = db.prepare(`
      SELECT permission_type 
      FROM mcp_tool_team_permissions 
      WHERE mcp_server_id = ? 
        AND tool_name = ?
        AND team = ?
    `).get(mcpServerId, toolName, user.team);

    if (teamPermission) {
      return { 
        allowed: teamPermission.permission_type === 'allow',
        reason: teamPermission.permission_type === 'deny' 
          ? `권한 위반: '${toolName}' Tool에 대한 접근이 거부되었습니다.`
          : null,
        error_type: teamPermission.permission_type === 'deny' ? 'permission_denied' : null
      };
    }
  }

  // 6. Tool별 권한 확인 (mcp_tool_team_permissions만 사용)
  // allowed_teams는 마켓플레이스 필터링용이므로 권한 체크에 사용하지 않음
  // mcp_tools 테이블에 툴이 있으면 Tool별 권한 관리가 활성화된 것으로 간주
  // mcp_tool_team_permissions에 명시적으로 allow된 Tool만 접근 가능
  
  // 이 서버에 대해 mcp_tools 테이블에 툴이 있는지 확인
  const hasTools = db.prepare(`
    SELECT COUNT(*) as count
    FROM mcp_tools 
    WHERE mcp_server_id = ? OR (mcp_server_id IS NULL AND server_name = (SELECT name FROM mcp_servers WHERE id = ?))
  `).get(mcpServerId, mcpServerId);

  if (hasTools && hasTools.count > 0) {
    // mcp_tools에 툴이 있으면 Tool별 권한 관리가 활성화된 것으로 간주
    // mcp_tool_team_permissions에 명시적으로 allow된 Tool만 접근 가능
    // 현재 Tool에 대한 권한이 없으면 접근 불가
    if (user.team) {
      const hasToolPermission = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_tool_team_permissions 
        WHERE mcp_server_id = ? 
          AND tool_name = ?
          AND team = ?
          AND permission_type = 'allow'
      `).get(mcpServerId, toolName, user.team);

      if (!hasToolPermission || hasToolPermission.count === 0) {
        return { 
          allowed: false, 
          reason: `권한 위반: '${toolName}' Tool에 대한 접근 권한이 없습니다.`,
          error_type: 'permission_denied'
        };
      } else {
        // 명시적으로 allow된 권한이 있으면 접근 허용
        return { allowed: true };
      }
    }
  }

  // 7. 기본 정책: 권한 없음
  return { 
    allowed: false, 
    reason: `권한 위반: '${toolName}' Tool에 대한 접근 권한이 없습니다.`,
    error_type: 'permission_denied'
  };
}

/**
 * MCP 서버 정보 조회 (Proxy용)
 * GET /api/mcp/servers/{server_id}
 * 
 * server_id는 name 필드로 조회
 */
const getServerConfig = (req, res) => {
  try {
    const { server_id } = req.params;

    if (!server_id) {
      return res.status(400).json({
        success: false,
        error: 'server_id는 필수입니다.'
      });
    }

    // DB에서 서버 정보 조회 (name으로 조회)
    const server = db.prepare(`
      SELECT * FROM mcp_servers 
      WHERE name = ? AND status = 'approved'
    `).get(server_id);

    if (!server) {
      return res.status(404).json({
        success: false,
        error: `Server not found: ${server_id}`
      });
    }

    // connection_config가 있으면 파싱
    let connectionConfig = {};
    if (server.connection_config) {
      try {
        connectionConfig = JSON.parse(server.connection_config);
      } catch (e) {
        console.error('connection_config JSON 파싱 오류:', e);
      }
    }

    // server_type 기본값 설정
    const serverType = server.server_type || connectionConfig.type || 'local';

    // Proxy가 요구하는 형식으로 변환
    const response = {
      id: server.id,
      name: server.name,
      server_id: server.name, // server_id는 name과 동일
      type: serverType,
      mcp_server_id: server.id
    };

    // 타입별 설정 추가
    if (serverType === 'local' || !connectionConfig.type) {
      // 로컬 서버
      response.command = connectionConfig.command || null;
      response.args = connectionConfig.args || [];
      response.env = connectionConfig.env || {};
    } else if (serverType === 'ssh') {
      // SSH 서버
      response.ssh_host = connectionConfig.ssh_host || null;
      response.ssh_user = connectionConfig.ssh_user || null;
      response.ssh_key = connectionConfig.ssh_key || null; // 경로만 저장
      response.command = connectionConfig.command || null;
      response.args = connectionConfig.args || [];
      response.env = connectionConfig.env || {};
    } else if (serverType === 'http' || serverType === 'sse') {
      // HTTP/SSE 서버
      response.url = connectionConfig.url || null;
      response.headers = connectionConfig.headers || {};
      response.env = connectionConfig.env || {};
    }

    // 로깅 (디버깅용)
    console.log(`[MCP 서버 정보 조회] ${server_id}`);
    console.log('타입:', serverType);
    console.log('응답:', JSON.stringify(response, null, 2));
    console.log('================================\n');

    res.json(response);
  } catch (error) {
    console.error('서버 정보 조회 오류:', error);
    res.status(500).json({
      success: false,
      error: '서버 정보 조회 중 오류가 발생했습니다.'
    });
  }
};

module.exports = {
  checkPermission,
  getServerConfig
};


const db = require('../config/db');
const EventEmitter = require('events');

// SSE를 위한 이벤트 에미터
const permissionViolationEmitter = new EventEmitter();

const permissionViolationController = {
  // 권한 위반 로그 목록 조회
  getViolationLogs: (req, res) => {
    try {
      const { page = 1, limit = 20, status, severity } = req.query;
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      const offset = (pageNum - 1) * limitNum;

      // 조건 구성
      let conditions = [];
      let params = [];

      if (status) {
        conditions.push('status = ?');
        params.push(status);
      }

      if (severity) {
        conditions.push('severity = ?');
        params.push(severity);
      }

      const whereClause = conditions.length > 0 
        ? `WHERE ${conditions.join(' AND ')}`
        : '';

      // 전체 개수 조회
      const countQuery = `SELECT COUNT(*) as total FROM permission_violation_logs ${whereClause}`;
      const totalResult = db.prepare(countQuery).get(...params);
      const total = totalResult.total;

      // 로그 목록 조회
      const query = `
        SELECT 
          id, user_id, username, employee_id, source_ip,
          mcp_server_id, mcp_server_name, tool_name,
          violation_type, reason, severity, timestamp, status,
          handled_by, handled_at, notes
        FROM permission_violation_logs
        ${whereClause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
      `;
      
      const logs = db.prepare(query).all(...params, limitNum, offset);

      res.json({
        success: true,
        data: logs,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total: total,
          totalPages: Math.ceil(total / limitNum)
        }
      });
    } catch (error) {
      console.error('권한 위반 로그 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '권한 위반 로그 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 권한 위반 로그 상세 조회
  getViolationLogById: (req, res) => {
    try {
      const { id } = req.params;
      
      const log = db.prepare(`
        SELECT 
          id, user_id, username, employee_id, source_ip,
          mcp_server_id, mcp_server_name, tool_name,
          violation_type, reason, severity, timestamp, status,
          handled_by, handled_at, notes
        FROM permission_violation_logs
        WHERE id = ?
      `).get(id);

      if (!log) {
        return res.status(404).json({
          success: false,
          message: '권한 위반 로그를 찾을 수 없습니다.'
        });
      }

      res.json({
        success: true,
        data: log
      });
    } catch (error) {
      console.error('권한 위반 로그 상세 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '권한 위반 로그 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 권한 위반 로그 상태 업데이트
  updateLogStatus: (req, res) => {
    try {
      const { id } = req.params;
      const { status, notes } = req.body;
      const handledBy = req.user?.id || null;

      if (!status || !['pending', 'resolved', 'ignored'].includes(status)) {
        return res.status(400).json({
          success: false,
          message: '유효하지 않은 상태입니다. (pending, resolved, ignored)'
        });
      }

      const updateQuery = `
        UPDATE permission_violation_logs
        SET status = ?, handled_by = ?, handled_at = datetime('now', '+9 hours'), notes = ?
        WHERE id = ?
      `;
      
      db.prepare(updateQuery).run(status, handledBy, notes || null, id);

      res.json({
        success: true,
        message: '권한 위반 로그 상태가 업데이트되었습니다.'
      });
    } catch (error) {
      console.error('권한 위반 로그 상태 업데이트 오류:', error);
      res.status(500).json({
        success: false,
        message: '권한 위반 로그 상태 업데이트 중 오류가 발생했습니다.'
      });
    }
  },

  // 최신 로그 ID 조회 (폴링용)
  getLatestLogId: (req, res) => {
    try {
      const result = db.prepare(`
        SELECT id FROM permission_violation_logs
        ORDER BY timestamp DESC
        LIMIT 1
      `).get();

      res.json({
        success: true,
        latestId: result?.id || 0
      });
    } catch (error) {
      console.error('최신 로그 ID 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '최신 로그 ID 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // Pending 상태의 권한 위반 로그 개수 조회 (알림용)
  getPendingCount: (req, res) => {
    try {
      const result = db.prepare(`
        SELECT COUNT(*) as count 
        FROM permission_violation_logs 
        WHERE status = 'pending'
      `).get();

      res.json({
        success: true,
        count: result?.count || 0
      });
    } catch (error) {
      console.error('Pending 권한 위반 로그 개수 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'Pending 권한 위반 로그 개수 조회 중 오류가 발생했습니다.',
        count: 0
      });
    }
  },

  // SSE 스트림 (실시간 업데이트)
  streamLogs: (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendEvent = (data) => {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    // 새로운 로그 이벤트 리스너
    const onNewLog = (log) => {
      sendEvent({
        type: 'newLog',
        data: log
      });
    };

    permissionViolationEmitter.on('newLog', onNewLog);

    // 연결 종료 시 리스너 제거
    req.on('close', () => {
      permissionViolationEmitter.removeListener('newLog', onNewLog);
    });

    // 초기 연결 확인
    sendEvent({ type: 'connected' });
  }
};

// 이벤트 에미터 export (mcpController에서 사용)
permissionViolationController.emitter = permissionViolationEmitter;

module.exports = permissionViolationController;


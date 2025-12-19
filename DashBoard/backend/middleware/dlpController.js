const dlpLogModel = require('../models/dlpLog');
const userModel = require('../models/user');
const db = require('../config/db');
const { getKoreaTimeSQLite } = require('../utils/dateTime');
const EventEmitter = require('events');

// SSE를 위한 이벤트 에미터
const dlpLogEmitter = new EventEmitter();

const dlpController = {
  // 외부 프록시 서버에서 DLP 위반 로그 수신
  receiveViolationLog: (req, res) => {
    try {
      console.log('🔔 DLP 위반 로그 수신 시도:', {
        method: req.method,
        path: req.path,
        headers: {
          'x-api-key': req.headers['x-api-key'] ? '***설정됨***' : '없음',
          'x-mcp-proxy-request': req.headers['x-mcp-proxy-request'],
          'content-type': req.headers['content-type']
        },
        body: req.body
      });

      // 필수 필드 검증
      const { source_ip, action_type, violation_type } = req.body;

      if (!source_ip || !action_type || !violation_type) {
        return res.status(400).json({
          success: false,
          message: '필수 필드가 누락되었습니다. (source_ip, action_type, violation_type)'
        });
      }

      // 사용자 정보가 있으면 찾기 (username, employee_id 등으로)
      // 헤더에서도 사용자 정보 확인 (프록시에서 전달 가능)
      const headerUsername = req.headers['x-user-name'] || req.body.username;
      const headerEmployeeId = req.headers['x-employee-id'] || req.body.employee_id;
      
      let userId = null;
      if (headerUsername) {
        const user = userModel.findByUsername(headerUsername);
        if (user) userId = user.id;
      } else if (headerEmployeeId) {
        const user = userModel.findByEmployeeId(headerEmployeeId);
        if (user) userId = user.id;
      }
      
      // IP 기반 사용자 조회
      if (!userId && source_ip) {
        // IP → 사용자 매핑 테이블 확인
        try {
          const ipMapping = db.prepare('SELECT username, employee_id FROM ip_user_mappings WHERE ip_address = ?').get(source_ip);
          if (ipMapping) {
            // 매핑된 사용자로 다시 조회
            if (ipMapping.username) {
              const user = userModel.findByUsername(ipMapping.username);
              if (user) userId = user.id;
            } else if (ipMapping.employee_id) {
              const user = userModel.findByEmployeeId(ipMapping.employee_id);
              if (user) userId = user.id;
            }
            
            // 헤더에서 가져온 사용자 정보 업데이트
            if (!headerUsername && ipMapping.username) {
              headerUsername = ipMapping.username;
            }
            if (!headerEmployeeId && ipMapping.employee_id) {
              headerEmployeeId = ipMapping.employee_id;
            }
          }
        } catch (error) {
          // ip_user_mappings 테이블이 없으면 무시 (선택사항)
          // console.log('IP 매핑 조회 실패 (테이블 없음):', error.message);
        }
      }

      // 로그 데이터 구성 (필요한 필드만)
      const logData = {
        user_id: userId,
        username: headerUsername || req.body.username || null,
        employee_id: headerEmployeeId || req.body.employee_id || null,
        source_ip: source_ip,
        action_type: action_type,
        violation_type: violation_type,
        severity: req.body.severity || 'medium',
        original_text: req.body.original_text || null,
        masked_text: req.body.masked_text || null,
        original_json: req.body.original_json || null,
        // 기본값들
        status: 'pending'
      };

      // 로그 저장
      const log = dlpLogModel.create(logData);
      
      console.log('✅ DLP 위반 로그 저장 완료:', {
        id: log.id,
        source_ip: source_ip,
        violation_type: violation_type,
        action_type: action_type
      });
      
      // SSE로 새로운 로그 알림 전송
      dlpLogEmitter.emit('newLog', log);
      
      // 응답 데이터도 null 필드 제거
      const responseData = {
        id: log.id,
        source_ip: source_ip,
        action_type: action_type,
        violation_type: violation_type,
        severity: logData.severity || 'medium',
        timestamp: getKoreaTimeSQLite()
      };
      
      if (logData.original_text) responseData.original_text = logData.original_text;
      if (logData.masked_text) responseData.masked_text = logData.masked_text;
      if (logData.original_json) responseData.original_json = logData.original_json;
      if (userId) responseData.user_id = userId;
      if (headerUsername || req.body.username) responseData.username = headerUsername || req.body.username;
      if (headerEmployeeId || req.body.employee_id) responseData.employee_id = headerEmployeeId || req.body.employee_id;

      res.json({
        success: true,
        message: 'DLP 위반 로그가 기록되었습니다.',
        data: responseData
      });
    } catch (error) {
      console.error('DLP 위반 로그 수신 오류:', error);
      res.status(500).json({
        success: false,
        message: 'DLP 로그 저장 중 오류가 발생했습니다.',
        error: error.message
      });
    }
  },

  // DLP 로그 조회 (관리자용)
  getViolationLogs: (req, res) => {
    try {
      const { page = 1, limit = 20 } = req.query;
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      const offset = (pageNum - 1) * limitNum;

      const filters = {
        user_id: req.query.user_id,
        violation_type: req.query.violation_type,
        severity: req.query.severity,
        status: req.query.status,
        start_date: req.query.start_date,
        end_date: req.query.end_date
      };

      // 빈 값 제거
      Object.keys(filters).forEach(key => {
        if (!filters[key]) delete filters[key];
      });

      // 전체 개수 조회
      const db = require('../config/db');
      let countQuery = 'SELECT COUNT(*) as total FROM dlp_violation_logs WHERE 1=1';
      const countParams = [];
      
      if (filters.user_id) {
        countQuery += ' AND user_id = ?';
        countParams.push(filters.user_id);
      }
      if (filters.violation_type) {
        countQuery += ' AND violation_type = ?';
        countParams.push(filters.violation_type);
      }
      if (filters.severity) {
        countQuery += ' AND severity = ?';
        countParams.push(filters.severity);
      }
      if (filters.status) {
        countQuery += ' AND status = ?';
        countParams.push(filters.status);
      }
      if (filters.start_date) {
        countQuery += ' AND timestamp >= ?';
        countParams.push(filters.start_date);
      }
      if (filters.end_date) {
        countQuery += ' AND timestamp <= ?';
        countParams.push(filters.end_date);
      }

      const totalResult = db.prepare(countQuery).get(...countParams);
      const total = totalResult.total;

      // 페이징된 로그 조회
      filters.limit = limitNum;
      filters.offset = offset;
      const logs = dlpLogModel.findAll(filters);

      res.json({
        success: true,
        data: logs,
        count: logs.length,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total: total,
          totalPages: Math.ceil(total / limitNum)
        }
      });
    } catch (error) {
      console.error('DLP 로그 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'DLP 로그 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 최신 로그 ID 확인 (변경 감지용, 가벼운 API)
  getLatestLogId: (req, res) => {
    try {
      const db = require('../config/db');
      const latest = db.prepare(`
        SELECT id, timestamp 
        FROM dlp_violation_logs 
        ORDER BY timestamp DESC, id DESC 
        LIMIT 1
      `).get();

      res.json({
        success: true,
        data: latest || { id: null, timestamp: null }
      });
    } catch (error) {
      console.error('최신 로그 ID 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '최신 로그 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // Pending 상태의 DLP 위반 로그 개수 조회 (알림용)
  getPendingCount: (req, res) => {
    try {
      const db = require('../config/db');
      const result = db.prepare(`
        SELECT COUNT(*) as count 
        FROM dlp_violation_logs 
        WHERE status = 'pending'
      `).get();

      res.json({
        success: true,
        count: result?.count || 0
      });
    } catch (error) {
      console.error('Pending DLP 위반 로그 개수 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'Pending DLP 위반 로그 개수 조회 중 오류가 발생했습니다.',
        count: 0
      });
    }
  },

  // DLP 로그 상세 조회
  getViolationLogById: (req, res) => {
    try {
      const { id } = req.params;
      const log = dlpLogModel.findById(id);

      if (!log) {
        return res.status(404).json({
          success: false,
          message: 'DLP 로그를 찾을 수 없습니다.'
        });
      }

      res.json({
        success: true,
        data: log
      });
    } catch (error) {
      console.error('DLP 로그 상세 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'DLP 로그 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // DLP 로그 상태 업데이트 (처리 완료 등)
  updateLogStatus: (req, res) => {
    try {
      const { id } = req.params;
      const { status, notes } = req.body;
      const handledBy = req.user?.id || null;

      if (!status) {
        return res.status(400).json({
          success: false,
          message: '상태(status)를 지정해주세요.'
        });
      }

      const log = dlpLogModel.findById(id);
      if (!log) {
        return res.status(404).json({
          success: false,
          message: 'DLP 로그를 찾을 수 없습니다.'
        });
      }

      dlpLogModel.updateStatus(id, status, handledBy, notes);

      res.json({
        success: true,
        message: 'DLP 로그 상태가 업데이트되었습니다.'
      });
    } catch (error) {
      console.error('DLP 로그 상태 업데이트 오류:', error);
      res.status(500).json({
        success: false,
        message: 'DLP 로그 상태 업데이트 중 오류가 발생했습니다.'
      });
    }
  },

  // SSE 스트림 (실시간 업데이트)
  streamLogs: (req, res) => {
    // SSE 헤더 설정
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Cache-Control');

    // 연결 확인 메시지 전송
    res.write(`data: ${JSON.stringify({ type: 'connected', message: 'DLP 로그 스트림 연결됨' })}\n\n`);

    // 새로운 로그 이벤트 리스너
    const onNewLog = (log) => {
      try {
        res.write(`data: ${JSON.stringify({ type: 'newLog', data: log })}\n\n`);
      } catch (error) {
        console.error('SSE 전송 오류:', error);
      }
    };

    dlpLogEmitter.on('newLog', onNewLog);

    // 클라이언트 연결 종료 시 정리
    req.on('close', () => {
      dlpLogEmitter.removeListener('newLog', onNewLog);
      res.end();
    });
  }
};

// 이벤트 에미터를 외부에서 접근 가능하도록 export
dlpController.emitter = dlpLogEmitter;

module.exports = dlpController;


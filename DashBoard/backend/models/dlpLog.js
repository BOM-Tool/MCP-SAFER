const db = require('../config/db');

const dlpLogModel = {
  // DLP 위반 로그 생성 (필요한 필드만)
  create: (logData) => {
    // 필수 필드
    const {
      source_ip,
      action_type,
      violation_type,
      severity = 'medium',
      status = 'pending'
    } = logData;

    // 선택 필드 (있는 것만 사용)
    const user_id = logData.user_id || null;
    const username = logData.username || null;
    const employee_id = logData.employee_id || null;
    const original_text = logData.original_text || null;
    const masked_text = logData.masked_text || null;
    const original_json = logData.original_json || null;

    // 실제 값이 있는 필드만 INSERT (null 제외)
    const fields = [];
    const values = [];
    const placeholders = [];

    // 필수 필드
    fields.push('source_ip', 'action_type', 'violation_type', 'severity', 'status');
    values.push(source_ip, action_type, violation_type, severity, status);
    placeholders.push('?', '?', '?', '?', '?');

    // 선택 필드 (값이 있을 때만 추가)
    if (user_id !== null) {
      fields.push('user_id');
      values.push(user_id);
      placeholders.push('?');
    }
    if (username !== null && username !== '') {
      fields.push('username');
      values.push(username);
      placeholders.push('?');
    }
    if (employee_id !== null && employee_id !== '') {
      fields.push('employee_id');
      values.push(employee_id);
      placeholders.push('?');
    }
    if (original_text !== null && original_text !== '') {
      fields.push('original_text');
      values.push(original_text);
      placeholders.push('?');
    }
    if (masked_text !== null && masked_text !== '') {
      fields.push('masked_text');
      values.push(masked_text);
      placeholders.push('?');
    }
    if (original_json !== null && original_json !== '') {
      fields.push('original_json');
      values.push(original_json);
      placeholders.push('?');
    }

    const query = `
      INSERT INTO dlp_violation_logs (${fields.join(', ')})
      VALUES (${placeholders.join(', ')})
    `;

    const stmt = db.prepare(query);
    const result = stmt.run(...values);

    return {
      id: result.lastInsertRowid,
      ...logData
    };
  },

  // 모든 DLP 로그 조회 (필요한 필드만)
  findAll: (filters = {}) => {
    // 필요한 필드만 SELECT
    let query = `
      SELECT 
        id,
        user_id,
        username,
        employee_id,
        source_ip,
        action_type,
        violation_type,
        severity,
        original_text,
        masked_text,
        original_json,
        timestamp,
        status
      FROM dlp_violation_logs 
      WHERE 1=1
    `;
    const params = [];

    if (filters.user_id) {
      query += ' AND user_id = ?';
      params.push(filters.user_id);
    }
    if (filters.violation_type) {
      query += ' AND violation_type = ?';
      params.push(filters.violation_type);
    }
    if (filters.severity) {
      query += ' AND severity = ?';
      params.push(filters.severity);
    }
    if (filters.status) {
      query += ' AND status = ?';
      params.push(filters.status);
    }
    if (filters.start_date) {
      query += ' AND timestamp >= ?';
      params.push(filters.start_date);
    }
    if (filters.end_date) {
      query += ' AND timestamp <= ?';
      params.push(filters.end_date);
    }

    query += ' ORDER BY timestamp DESC';
    if (filters.limit) {
      query += ' LIMIT ?';
      params.push(filters.limit);
      if (filters.offset) {
        query += ' OFFSET ?';
        params.push(filters.offset);
      }
    }

    const logs = db.prepare(query).all(...params);
    
    // IP 기반으로 사용자 정보 조회 및 보강
    const enrichedLogs = logs.map(log => {
      const cleaned = {};
      Object.keys(log).forEach(key => {
        if (log[key] !== null && log[key] !== undefined) {
          cleaned[key] = log[key];
        }
      });
      
      // username이나 employee_id가 없고 source_ip가 있으면 IP 매핑에서 찾기
      if ((!cleaned.username && !cleaned.employee_id) && cleaned.source_ip) {
        // ip_user_mappings 테이블에서 조회
        const ipMapping = db.prepare(`
          SELECT username, employee_id 
          FROM ip_user_mappings 
          WHERE ip_address = ?
        `).get(cleaned.source_ip);
        
        if (ipMapping) {
          if (ipMapping.username) cleaned.username = ipMapping.username;
          if (ipMapping.employee_id) cleaned.employee_id = ipMapping.employee_id;
        } else {
          // users 테이블에서 IP로 직접 조회
          const user = db.prepare(`
            SELECT username, employee_id 
            FROM users 
            WHERE ip_address = ?
          `).get(cleaned.source_ip);
          
          if (user) {
            if (user.username) cleaned.username = user.username;
            if (user.employee_id) cleaned.employee_id = user.employee_id;
          }
        }
      }
      
      return cleaned;
    });
    
    return enrichedLogs;
  },

  // ID로 조회 (필요한 필드만)
  findById: (id) => {
    const log = db.prepare(`
      SELECT 
        id,
        user_id,
        username,
        employee_id,
        source_ip,
        action_type,
        violation_type,
        severity,
        original_text,
        masked_text,
        original_json,
        timestamp,
        status
      FROM dlp_violation_logs 
      WHERE id = ?
    `).get(id);
    
    if (!log) return null;
    
    // null 필드 제거
    const cleaned = {};
    Object.keys(log).forEach(key => {
      if (log[key] !== null && log[key] !== undefined) {
        cleaned[key] = log[key];
      }
    });
    
    // IP 기반으로 사용자 정보 조회 및 보강
    if ((!cleaned.username && !cleaned.employee_id) && cleaned.source_ip) {
      // ip_user_mappings 테이블에서 조회
      const ipMapping = db.prepare(`
        SELECT username, employee_id 
        FROM ip_user_mappings 
        WHERE ip_address = ?
      `).get(cleaned.source_ip);
      
      if (ipMapping) {
        if (ipMapping.username) cleaned.username = ipMapping.username;
        if (ipMapping.employee_id) cleaned.employee_id = ipMapping.employee_id;
      } else {
        // users 테이블에서 IP로 직접 조회
        const user = db.prepare(`
          SELECT username, employee_id 
          FROM users 
          WHERE ip_address = ?
        `).get(cleaned.source_ip);
        
        if (user) {
          if (user.username) cleaned.username = user.username;
          if (user.employee_id) cleaned.employee_id = user.employee_id;
        }
      }
    }
    
    return cleaned;
  },

  // 로그 상태 업데이트
  updateStatus: (id, status, handledBy, notes = null) => {
    const stmt = db.prepare(`
      UPDATE dlp_violation_logs 
      SET status = ?, handled_by = ?, handled_at = datetime('now', '+9 hours'), notes = ?
      WHERE id = ?
    `);
    return stmt.run(status, handledBy, notes, id);
  }
};

module.exports = dlpLogModel;


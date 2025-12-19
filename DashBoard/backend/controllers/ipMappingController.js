const db = require('../config/db');

const ipMappingController = {
  // IP 매핑 목록 조회
  getAllMappings: (req, res) => {
    try {
      const mappings = db.prepare('SELECT * FROM ip_user_mappings ORDER BY ip_address').all();
      res.json({
        success: true,
        data: mappings,
        count: mappings.length
      });
    } catch (error) {
      console.error('IP 매핑 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'IP 매핑 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 특정 IP 매핑 조회
  getMappingByIP: (req, res) => {
    try {
      const { ip } = req.params;
      const mapping = db.prepare('SELECT * FROM ip_user_mappings WHERE ip_address = ?').get(ip);

      if (!mapping) {
        return res.status(404).json({
          success: false,
          message: 'IP 매핑을 찾을 수 없습니다.'
        });
      }

      res.json({
        success: true,
        data: mapping
      });
    } catch (error) {
      console.error('IP 매핑 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'IP 매핑 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // IP 매핑 생성 또는 업데이트
  createOrUpdateMapping: (req, res) => {
    try {
      const { ip_address, username, employee_id, description } = req.body;

      if (!ip_address) {
        return res.status(400).json({
          success: false,
          message: 'IP 주소(ip_address)는 필수입니다.'
        });
      }

      if (!username && !employee_id) {
        return res.status(400).json({
          success: false,
          message: 'username 또는 employee_id 중 하나는 필수입니다.'
        });
      }

      // 기존 매핑 확인
      const existing = db.prepare('SELECT * FROM ip_user_mappings WHERE ip_address = ?').get(ip_address);

      if (existing) {
        // 업데이트
        const stmt = db.prepare(`
          UPDATE ip_user_mappings 
          SET username = ?, employee_id = ?, description = ?, updated_at = datetime('now', '+9 hours')
          WHERE ip_address = ?
        `);
        stmt.run(username || null, employee_id || null, description || null, ip_address);
        
        res.json({
          success: true,
          message: 'IP 매핑이 업데이트되었습니다.',
          data: {
            ip_address,
            username,
            employee_id,
            description
          }
        });
      } else {
        // 생성
        const stmt = db.prepare(`
          INSERT INTO ip_user_mappings (ip_address, username, employee_id, description)
          VALUES (?, ?, ?, ?)
        `);
        const result = stmt.run(ip_address, username || null, employee_id || null, description || null);
        
        res.json({
          success: true,
          message: 'IP 매핑이 생성되었습니다.',
          data: {
            id: result.lastInsertRowid,
            ip_address,
            username,
            employee_id,
            description
          }
        });
      }
    } catch (error) {
      console.error('IP 매핑 생성/업데이트 오류:', error);
      res.status(500).json({
        success: false,
        message: 'IP 매핑 처리 중 오류가 발생했습니다.',
        error: error.message
      });
    }
  },

  // IP 매핑 삭제
  deleteMapping: (req, res) => {
    try {
      const { ip } = req.params;
      
      const result = db.prepare('DELETE FROM ip_user_mappings WHERE ip_address = ?').run(ip);
      
      if (result.changes === 0) {
        return res.status(404).json({
          success: false,
          message: 'IP 매핑을 찾을 수 없습니다.'
        });
      }

      res.json({
        success: true,
        message: 'IP 매핑이 삭제되었습니다.'
      });
    } catch (error) {
      console.error('IP 매핑 삭제 오류:', error);
      res.status(500).json({
        success: false,
        message: 'IP 매핑 삭제 중 오류가 발생했습니다.'
      });
    }
  }
};

module.exports = ipMappingController;


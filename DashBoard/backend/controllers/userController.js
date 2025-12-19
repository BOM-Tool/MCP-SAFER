const userModel = require('../models/user');
const db = require('../config/db');

const userController = {
  // 모든 사용자 조회 (관리자용, 페이징)
  getAllUsers: (req, res) => {
    try {
      const { page = 1, limit = 20 } = req.query;
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      const offset = (pageNum - 1) * limitNum;

      // 전체 개수 조회
      let countQuery = 'SELECT COUNT(*) as total FROM users';
      let countParams = [];
      
      if (req.query.ip) {
        countQuery += ' WHERE ip_address = ?';
        countParams.push(req.query.ip);
      }
      
      const totalResult = db.prepare(countQuery).get(...countParams);
      const total = totalResult.total;

      // IP 필터링이 있으면 적용
      let whereClause = '';
      let whereParams = [];
      
      if (req.query.ip) {
        whereClause = ' WHERE ip_address = ?';
        whereParams.push(req.query.ip);
      }

      // 페이징된 사용자 조회
      const users = db.prepare(`
        SELECT id, username, employee_id, email, team, position, ip_address, is_active, created_at 
        FROM users 
        ${whereClause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `).all(...whereParams, limitNum, offset);
      
      // 각 사용자의 역할 정보 포함
      const usersWithRoles = users.map(user => {
        const roles = db.prepare(`
          SELECT r.id, r.name, r.description 
          FROM roles r
          JOIN user_roles ur ON r.id = ur.role_id
          WHERE ur.user_id = ?
        `).all(user.id);
        
        return {
          ...user,
          roles: roles.map(r => r.name)
        };
      });
      
      res.json({
        success: true,
        data: usersWithRoles,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total: total,
          totalPages: Math.ceil(total / limitNum)
        }
      });
    } catch (error) {
      console.error('사용자 목록 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '사용자 목록을 불러오는 중 오류가 발생했습니다.'
      });
    }
  },

  // 사용자 상세 정보 조회
  getUserById: (req, res) => {
    try {
      const { id } = req.params;
      const user = userModel.findById(parseInt(id));
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: '사용자를 찾을 수 없습니다.'
        });
      }
      
      res.json({
        success: true,
        data: user
      });
    } catch (error) {
      console.error('사용자 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '사용자 정보를 불러오는 중 오류가 발생했습니다.'
      });
    }
  },

  // 사용자 정보 수정
  updateUser: (req, res) => {
    try {
      const { id } = req.params;
      const { username, email, team, position, employee_id, ip_address } = req.body;
      
      const user = userModel.findById(parseInt(id));
      if (!user) {
        return res.status(404).json({
          success: false,
          message: '사용자를 찾을 수 없습니다.'
        });
      }
      
      // 업데이트할 데이터 구성
      const updateData = {};
      if (username) updateData.username = username;
      if (email) updateData.email = email;
      if (team !== undefined) updateData.team = team;
      if (position !== undefined) updateData.position = position;
      if (employee_id) updateData.employee_id = employee_id;
      if (ip_address !== undefined) updateData.ip_address = ip_address || null;
      
      userModel.update(parseInt(id), updateData);
      
      // IP 매핑 테이블도 동기화
      if (ip_address !== undefined) {
        try {
          if (ip_address && ip_address.trim() !== '') {
            // IP 매핑 생성/업데이트
            const stmt = db.prepare(`
              INSERT INTO ip_user_mappings (ip_address, username, employee_id)
              VALUES (?, ?, ?)
              ON CONFLICT(ip_address) DO UPDATE SET
                username = EXCLUDED.username,
                employee_id = EXCLUDED.employee_id,
                updated_at = datetime('now', '+9 hours')
            `);
            stmt.run(ip_address, user.username, user.employee_id);
          } else {
            // IP가 비어있으면 매핑 삭제
            const deleteStmt = db.prepare('DELETE FROM ip_user_mappings WHERE username = ? OR employee_id = ?');
            deleteStmt.run(user.username, user.employee_id);
          }
        } catch (ipError) {
          console.error('IP 매핑 동기화 오류:', ipError);
          // IP 매핑 실패해도 사용자 업데이트는 진행
        }
      }
      
      // 업데이트된 사용자 정보 조회
      const updatedUser = userModel.findById(parseInt(id));
      
      res.json({
        success: true,
        message: '사용자 정보가 업데이트되었습니다.',
        data: updatedUser
      });
    } catch (error) {
      console.error('사용자 정보 수정 오류:', error);
      res.status(500).json({
        success: false,
        message: '사용자 정보 수정 중 오류가 발생했습니다.'
      });
    }
  },

  // 사용자 역할 할당
  assignRole: (req, res) => {
    try {
      const { id } = req.params;
      const { roleName } = req.body;
      
      if (!roleName) {
        return res.status(400).json({
          success: false,
          message: '역할 이름을 지정해주세요.'
        });
      }
      
      const role = db.prepare('SELECT id FROM roles WHERE name = ?').get(roleName);
      if (!role) {
        return res.status(404).json({
          success: false,
          message: '역할을 찾을 수 없습니다.'
        });
      }
      
      userModel.assignRole(parseInt(id), role.id);
      
      res.json({
        success: true,
        message: '역할이 할당되었습니다.'
      });
    } catch (error) {
      console.error('역할 할당 오류:', error);
      res.status(500).json({
        success: false,
        message: '역할 할당 중 오류가 발생했습니다.'
      });
    }
  },

  // 사용자 역할 제거
  removeRole: (req, res) => {
    try {
      const { id, roleId } = req.params;
      
      userModel.removeRole(parseInt(id), parseInt(roleId));
      
      res.json({
        success: true,
        message: '역할이 제거되었습니다.'
      });
    } catch (error) {
      console.error('역할 제거 오류:', error);
      res.status(500).json({
        success: false,
        message: '역할 제거 중 오류가 발생했습니다.'
      });
    }
  },

  // 내 정보 조회 (현재 로그인한 사용자)
  getMyInfo: (req, res) => {
    try {
      const userId = req.user.id;
      const user = userModel.findById(userId);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: '사용자를 찾을 수 없습니다.'
        });
      }

      // roles를 문자열 배열로 변환
      const userData = {
        ...user,
        roles: user.roles ? user.roles.map(r => r.name || r) : []
      };

      res.json({
        success: true,
        data: userData
      });
    } catch (error) {
      console.error('내 정보 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '내 정보를 불러오는 중 오류가 발생했습니다.'
      });
    }
  },

  // 비밀번호 변경
  changePassword: (req, res) => {
    try {
      const userId = req.user.id;
      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          success: false,
          message: '현재 비밀번호와 새 비밀번호를 모두 입력해주세요.'
        });
      }

      if (newPassword.length < 4) {
        return res.status(400).json({
          success: false,
          message: '새 비밀번호는 최소 4자 이상이어야 합니다.'
        });
      }

      const user = userModel.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: '사용자를 찾을 수 없습니다.'
        });
      }

      // 현재 비밀번호 확인
      if (user.password !== currentPassword) {
        return res.status(401).json({
          success: false,
          message: '현재 비밀번호가 일치하지 않습니다.'
        });
      }

      // 새 비밀번호로 업데이트
      userModel.update(userId, { password: newPassword });

      res.json({
        success: true,
        message: '비밀번호가 성공적으로 변경되었습니다.'
      });
    } catch (error) {
      console.error('비밀번호 변경 오류:', error);
      res.status(500).json({
        success: false,
        message: '비밀번호 변경 중 오류가 발생했습니다.'
      });
    }
  },

  toggleUserStatus: (req, res) => {
    try {
      const { id } = req.params;
      const { is_active } = req.body;
      
      if (typeof is_active !== 'boolean') {
        return res.status(400).json({
          success: false,
          message: 'is_active는 boolean 값이어야 합니다.'
        });
      }
      
      userModel.update(parseInt(id), { is_active });
      
      res.json({
        success: true,
        message: `사용자가 ${is_active ? '활성화' : '비활성화'}되었습니다.`
      });
    } catch (error) {
      console.error('사용자 상태 변경 오류:', error);
      res.status(500).json({
        success: false,
        message: '사용자 상태 변경 중 오류가 발생했습니다.'
      });
    }
  },

  // 모든 팀 목록 조회
  getAllTeams: (req, res) => {
    try {
      const teams = db.prepare(`
        SELECT DISTINCT team 
        FROM users 
        WHERE team IS NOT NULL AND team != ''
        ORDER BY team ASC
      `).all();
      
      const teamList = teams.map(t => t.team);
      
      res.json({
        success: true,
        data: teamList
      });
    } catch (error) {
      console.error('팀 목록 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '팀 목록을 불러오는 중 오류가 발생했습니다.'
      });
    }
  },

  // 모든 직책 목록 조회
  getAllPositions: (req, res) => {
    try {
      const positions = db.prepare(`
        SELECT DISTINCT position 
        FROM users 
        WHERE position IS NOT NULL AND position != ''
        ORDER BY position ASC
      `).all();
      
      const positionList = positions.map(p => p.position);
      
      res.json({
        success: true,
        data: positionList
      });
    } catch (error) {
      console.error('직책 목록 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '직책 목록을 불러오는 중 오류가 발생했습니다.'
      });
    }
  },

  // API 키 조회 (현재 로그인한 사용자)
  getMyApiKeys: (req, res) => {
    try {
      // api_keys 테이블 존재 여부 확인
      const apiKeysTableExists = db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='api_keys'
      `).get();
      
      if (!apiKeysTableExists) {
        // 테이블이 없으면 빈 배열 반환
        return res.json({
          success: true,
          data: []
        });
      }
      
      const userId = req.user.id;
      const { mcp_server_name } = req.query;
      
      let query = 'SELECT * FROM api_keys WHERE user_id = ?';
      const params = [userId];
      
      if (mcp_server_name) {
        query += ' AND mcp_server_name = ?';
        params.push(mcp_server_name);
      }
      
      query += ' ORDER BY mcp_server_name, field_name';
      
      const apiKeys = db.prepare(query).all(...params);
      
      // 보안을 위해 field_value는 마스킹하여 반환 (앞 4자만 표시)
      const maskedKeys = apiKeys.map(key => ({
        ...key,
        field_value: key.field_value ? 
          (key.field_value.length > 4 ? 
            key.field_value.slice(0, 4) + '*'.repeat(Math.max(0, key.field_value.length - 4)) : 
            key.field_value) : 
          ''
      }));
      
      res.json({
        success: true,
        data: maskedKeys
      });
    } catch (error) {
      console.error('API 키 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'API 키 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // API 키 생성
  createApiKey: (req, res) => {
    try {
      // api_keys 테이블 존재 여부 확인
      const apiKeysTableExists = db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='api_keys'
      `).get();
      
      if (!apiKeysTableExists) {
        return res.status(500).json({
          success: false,
          message: 'API 키 테이블이 아직 생성되지 않았습니다. 잠시 후 다시 시도해주세요.'
        });
      }
      
      const userId = req.user.id;
      const { mcp_server_name, field_name, field_value } = req.body;
      
      // 필수 필드 검증
      if (!mcp_server_name || !field_name || !field_value) {
        return res.status(400).json({
          success: false,
          message: 'MCP 서버 이름, 필드명, 필드값은 필수입니다.'
        });
      }
      
      // 중복 확인
      const existing = db.prepare(`
        SELECT id FROM api_keys 
        WHERE user_id = ? AND mcp_server_name = ? AND field_name = ?
      `).get(userId, mcp_server_name, field_name);
      
      if (existing) {
        return res.status(400).json({
          success: false,
          message: '이미 등록된 필드명입니다.'
        });
      }
      
      // API 키 생성
      const stmt = db.prepare(`
        INSERT INTO api_keys (user_id, mcp_server_name, field_name, field_value, field_description, auth_type)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      
      const result = stmt.run(
        userId,
        mcp_server_name,
        field_name,
        field_value,
        null, // field_description
        'Key/Token 인증' // auth_type 기본값
      );
      
      res.json({
        success: true,
        message: 'API 키가 등록되었습니다.',
        data: {
          id: result.lastInsertRowid,
          mcp_server_name,
          field_name
        }
      });
    } catch (error) {
      console.error('API 키 생성 오류:', error);
      console.error('API 키 생성 오류 상세:', {
        message: error.message,
        stack: error.stack,
        body: req.body,
        userId: req.user?.id
      });
      res.status(500).json({
        success: false,
        message: error.message || 'API 키 등록 중 오류가 발생했습니다.'
      });
    }
  },

  // API 키 수정
  updateApiKey: (req, res) => {
    try {
      // api_keys 테이블 존재 여부 확인
      const apiKeysTableExists = db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='api_keys'
      `).get();
      
      if (!apiKeysTableExists) {
        return res.status(500).json({
          success: false,
          message: 'API 키 테이블이 아직 생성되지 않았습니다. 잠시 후 다시 시도해주세요.'
        });
      }
      
      const userId = req.user.id;
      const { id } = req.params;
      const { field_name, field_value } = req.body;
      
      // API 키 소유권 확인
      const existing = db.prepare(`
        SELECT id FROM api_keys WHERE id = ? AND user_id = ?
      `).get(id, userId);
      
      if (!existing) {
        return res.status(404).json({
          success: false,
          message: 'API 키를 찾을 수 없거나 권한이 없습니다.'
        });
      }
      
      // 업데이트할 필드 구성
      const updates = [];
      const params = [];
      
      if (field_name !== undefined) {
        // 필드명 변경 시 중복 확인
        const duplicate = db.prepare(`
          SELECT id FROM api_keys 
          WHERE user_id = ? AND mcp_server_name = (SELECT mcp_server_name FROM api_keys WHERE id = ?) 
          AND field_name = ? AND id != ?
        `).get(userId, id, field_name, id);
        
        if (duplicate) {
          return res.status(400).json({
            success: false,
            message: '이미 등록된 필드명입니다.'
          });
        }
        updates.push('field_name = ?');
        params.push(field_name);
      }
      
      if (field_value !== undefined) {
        updates.push('field_value = ?');
        params.push(field_value);
      }
      
      if (updates.length === 0) {
        return res.status(400).json({
          success: false,
          message: '수정할 필드가 없습니다.'
        });
      }
      
      updates.push('updated_at = datetime("now", "+9 hours")');
      params.push(id);
      
      const stmt = db.prepare(`
        UPDATE api_keys 
        SET ${updates.join(', ')}
        WHERE id = ? AND user_id = ?
      `);
      
      stmt.run(...params, userId);
      
      res.json({
        success: true,
        message: 'API 키가 수정되었습니다.'
      });
    } catch (error) {
      console.error('API 키 수정 오류:', error);
      res.status(500).json({
        success: false,
        message: 'API 키 수정 중 오류가 발생했습니다.'
      });
    }
  },

  // API 키 삭제
  deleteApiKey: (req, res) => {
    try {
      // api_keys 테이블 존재 여부 확인
      const apiKeysTableExists = db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='api_keys'
      `).get();
      
      if (!apiKeysTableExists) {
        return res.status(500).json({
          success: false,
          message: 'API 키 테이블이 아직 생성되지 않았습니다. 잠시 후 다시 시도해주세요.'
        });
      }
      
      const userId = req.user.id;
      const { id } = req.params;
      
      // API 키 소유권 확인
      const existing = db.prepare(`
        SELECT id FROM api_keys WHERE id = ? AND user_id = ?
      `).get(id, userId);
      
      if (!existing) {
        return res.status(404).json({
          success: false,
          message: 'API 키를 찾을 수 없거나 권한이 없습니다.'
        });
      }
      
      const stmt = db.prepare('DELETE FROM api_keys WHERE id = ? AND user_id = ?');
      stmt.run(id, userId);
      
      res.json({
        success: true,
        message: 'API 키가 삭제되었습니다.'
      });
    } catch (error) {
      console.error('API 키 삭제 오류:', error);
      res.status(500).json({
        success: false,
        message: 'API 키 삭제 중 오류가 발생했습니다.'
      });
    }
  }
};

module.exports = userController;


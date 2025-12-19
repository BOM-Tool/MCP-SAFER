const db = require('../config/db');

const userModel = {
  // 사용자 ID로 조회 (역할 포함)
  findById: (id) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) return null;
    
    // 사용자의 역할들 조회
    const roles = db.prepare(`
      SELECT r.id, r.name, r.description 
      FROM roles r
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = ?
    `).all(id);
    
    return { ...user, roles };
  },

  // 사용자명으로 조회
  findByUsername: (username) => {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return null;
    
    // 역할 포함
    const roles = db.prepare(`
      SELECT r.id, r.name, r.description 
      FROM roles r
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = ?
    `).all(user.id);
    
    return { ...user, roles };
  },

  // 사원번호로 조회
  findByEmployeeId: (employeeId) => {
    return db.prepare('SELECT * FROM users WHERE employee_id = ?').get(employeeId);
  },

  // 이메일로 조회
  findByEmail: (email) => {
    return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  },

  // 사용자명 또는 이메일로 조회
  findByUsernameOrEmail: (username, email) => {
    return db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, email);
  },

  // 새 사용자 생성
  create: (username, employeeId, email, password, team, position) => {
    const stmt = db.prepare(`
      INSERT INTO users (username, employee_id, email, password, team, position) 
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(username, employeeId, email, password, team || null, position || null);
    return {
      id: result.lastInsertRowid,
      username,
      employee_id: employeeId,
      email,
      team,
      position
    };
  },

  // 사용자 역할 할당
  assignRole: (userId, roleId) => {
    const stmt = db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
    return stmt.run(userId, roleId);
  },

  // 사용자 역할 제거
  removeRole: (userId, roleId) => {
    return db.prepare('DELETE FROM user_roles WHERE user_id = ? AND role_id = ?').run(userId, roleId);
  },

  // 사용자 정보 업데이트
  update: (id, data) => {
    const updates = [];
    const values = [];

    if (data.username) {
      updates.push('username = ?');
      values.push(data.username);
    }
    if (data.employee_id) {
      updates.push('employee_id = ?');
      values.push(data.employee_id);
    }
    if (data.email) {
      updates.push('email = ?');
      values.push(data.email);
    }
    if (data.password) {
      updates.push('password = ?');
      values.push(data.password);
    }
    if (data.team !== undefined) {
      updates.push('team = ?');
      values.push(data.team);
    }
    if (data.position !== undefined) {
      updates.push('position = ?');
      values.push(data.position);
    }
    if (data.ip_address !== undefined) {
      updates.push('ip_address = ?');
      values.push(data.ip_address);
    }
    if (data.is_active !== undefined) {
      updates.push('is_active = ?');
      values.push(data.is_active ? 1 : 0);
    }

    if (updates.length === 0) return null;

    updates.push("updated_at = datetime('now', '+9 hours')");
    values.push(id);

    const stmt = db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`);
    return stmt.run(...values);
  },

  // 사용자 삭제
  delete: (id) => {
    return db.prepare('DELETE FROM users WHERE id = ?').run(id);
  },

  // 모든 사용자 조회 (관리자용)
  findAll: () => {
    return db.prepare(`
      SELECT id, username, employee_id, email, team, position, is_active, created_at 
      FROM users 
      ORDER BY created_at DESC
    `).all();
  },

  // 사용자의 권한 목록 조회 (역할을 통해)
  getUserPermissions: (userId) => {
    return db.prepare(`
      SELECT DISTINCT p.id, p.name, p.description, p.resource, p.action
      FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      JOIN user_roles ur ON rp.role_id = ur.role_id
      WHERE ur.user_id = ?
    `).all(userId);
  },

  // 사용자가 특정 권한을 가지고 있는지 확인
  hasPermission: (userId, permissionName) => {
    const perm = db.prepare(`
      SELECT COUNT(*) as count
      FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      JOIN user_roles ur ON rp.role_id = ur.role_id
      WHERE ur.user_id = ? AND p.name = ?
    `).get(userId, permissionName);
    return perm.count > 0;
  }
};

module.exports = userModel;


const db = require('../config/db');

const roleModel = {
  // 모든 역할 조회
  findAll: () => {
    return db.prepare('SELECT * FROM roles ORDER BY name').all();
  },

  // ID로 조회
  findById: (id) => {
    return db.prepare('SELECT * FROM roles WHERE id = ?').get(id);
  },

  // 이름으로 조회
  findByName: (name) => {
    return db.prepare('SELECT * FROM roles WHERE name = ?').get(name);
  },

  // 역할 생성
  create: (name, description) => {
    const stmt = db.prepare('INSERT INTO roles (name, description) VALUES (?, ?)');
    const result = stmt.run(name, description);
    return {
      id: result.lastInsertRowid,
      name,
      description
    };
  },

  // 역할에 권한 추가
  addPermission: (roleId, permissionId) => {
    const stmt = db.prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)');
    return stmt.run(roleId, permissionId);
  },

  // 역할에서 권한 제거
  removePermission: (roleId, permissionId) => {
    return db.prepare('DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?').run(roleId, permissionId);
  },

  // 역할의 권한 목록 조회
  getPermissions: (roleId) => {
    return db.prepare(`
      SELECT p.*
      FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      WHERE rp.role_id = ?
    `).all(roleId);
  },

  // 역할 업데이트
  update: (id, data) => {
    const updates = [];
    const values = [];

    if (data.name) {
      updates.push('name = ?');
      values.push(data.name);
    }
    if (data.description !== undefined) {
      updates.push('description = ?');
      values.push(data.description);
    }

    if (updates.length === 0) return null;
    values.push(id);

    const stmt = db.prepare(`UPDATE roles SET ${updates.join(', ')} WHERE id = ?`);
    return stmt.run(...values);
  },

  // 역할 삭제
  delete: (id) => {
    return db.prepare('DELETE FROM roles WHERE id = ?').run(id);
  }
};

module.exports = roleModel;


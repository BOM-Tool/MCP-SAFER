const db = require('../config/db');

const permissionModel = {
  // 모든 권한 조회
  findAll: () => {
    return db.prepare('SELECT * FROM permissions ORDER BY resource, action').all();
  },

  // ID로 조회
  findById: (id) => {
    return db.prepare('SELECT * FROM permissions WHERE id = ?').get(id);
  },

  // 이름으로 조회
  findByName: (name) => {
    return db.prepare('SELECT * FROM permissions WHERE name = ?').get(name);
  },

  // 리소스별 권한 조회
  findByResource: (resource) => {
    return db.prepare('SELECT * FROM permissions WHERE resource = ?').all(resource);
  },

  // 권한 생성
  create: (name, description, resource, action) => {
    const stmt = db.prepare('INSERT INTO permissions (name, description, resource, action) VALUES (?, ?, ?, ?)');
    const result = stmt.run(name, description, resource, action);
    return {
      id: result.lastInsertRowid,
      name,
      description,
      resource,
      action
    };
  },

  // 권한 업데이트
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
    if (data.resource) {
      updates.push('resource = ?');
      values.push(data.resource);
    }
    if (data.action) {
      updates.push('action = ?');
      values.push(data.action);
    }

    if (updates.length === 0) return null;
    values.push(id);

    const stmt = db.prepare(`UPDATE permissions SET ${updates.join(', ')} WHERE id = ?`);
    return stmt.run(...values);
  },

  // 권한 삭제
  delete: (id) => {
    return db.prepare('DELETE FROM permissions WHERE id = ?').run(id);
  }
};

module.exports = permissionModel;


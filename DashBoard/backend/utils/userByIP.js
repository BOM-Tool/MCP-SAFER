const db = require('../config/db');
const userModel = require('../models/user');

/**
 * IP 주소로 사용자 정보 조회
 * 우선순위:
 * 1. ip_user_mappings 테이블
 * 2. users 테이블의 ip_address 필드
 */
function getUserByIP(clientIP) {
  if (!clientIP) {
    return null;
  }

  // 1. ip_user_mappings 테이블에서 조회
  try {
    const ipMapping = db.prepare(`
      SELECT username, employee_id 
      FROM ip_user_mappings 
      WHERE ip_address = ?
    `).get(clientIP);

    if (ipMapping) {
      // 매핑된 사용자 정보로 조회
      let user = null;
      if (ipMapping.username) {
        user = userModel.findByUsername(ipMapping.username);
      } else if (ipMapping.employee_id) {
        user = userModel.findByEmployeeId(ipMapping.employee_id);
      }

      if (user) {
        return user;
      }
    }
  } catch (error) {
    // ip_user_mappings 테이블이 없으면 무시
    console.error('IP 매핑 조회 오류:', error.message);
  }

  // 2. users 테이블의 ip_address 필드에서 직접 조회
  try {
    const user = db.prepare(`
      SELECT * FROM users 
      WHERE ip_address = ? AND is_active = 1
    `).get(clientIP);

    if (user) {
      // 역할 포함하여 반환
      const roles = db.prepare(`
        SELECT r.id, r.name, r.description 
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
      `).all(user.id);

      return { ...user, roles: roles.map(r => r.name || r) };
    }
  } catch (error) {
    console.error('사용자 IP 조회 오류:', error.message);
  }

  return null;
}

module.exports = {
  getUserByIP
};



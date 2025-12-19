#!/usr/bin/env node
/**
 * 기본 사용자 계정 확인/생성 스크립트
 * - admin 계정 확인/생성
 * - user 계정 확인/생성
 */

const db = require('../config/db');

// 비밀번호 해시 함수 (간단한 버전 - 실제로는 bcrypt 사용)
function hashPassword(password) {
  // 실제 환경에서는 bcrypt를 사용해야 하지만, 샘플 데이터이므로 간단하게 처리
  // 실제로는: const bcrypt = require('bcryptjs'); return bcrypt.hashSync(password, 10);
  return password; // 샘플 데이터이므로 평문 사용 (실제 환경에서는 절대 금지!)
}

function getKoreaTime() {
  const now = new Date();
  const koreaTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
  return koreaTime.toISOString().replace('T', ' ').substring(0, 19);
}

async function addSampleData() {
  try {
    console.log('=== 기본 사용자 계정 확인 ===\n');

    // user와 admin 계정만 확인/생성
    console.log('[1/1] 기본 사용자 계정 확인 중...');
    const userStmt = db.prepare(`
      INSERT OR IGNORE INTO users (username, employee_id, email, password, team, position, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // admin 사용자 확인/생성
    const adminUser = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
    if (!adminUser) {
      const adminResult = userStmt.run('admin', 'ADMIN001', 'admin@example.com', hashPassword('admin123'), 'Admin', 'Administrator', getKoreaTime(), getKoreaTime());
      if (adminResult.lastInsertRowid) {
        console.log(`  ✓ Admin User 추가: admin (ID: ${adminResult.lastInsertRowid})`);
      }
    } else {
      console.log(`  - Admin User 이미 존재: admin (ID: ${adminUser.id})`);
    }

    // user 사용자 확인/생성
    const userUser = db.prepare('SELECT id FROM users WHERE username = ?').get('user');
    if (!userUser) {
      const userResult = userStmt.run('user', 'EMP002', 'user@example.com', hashPassword('user'), 'Development', 'Developer', getKoreaTime(), getKoreaTime());
      if (userResult.lastInsertRowid) {
        console.log(`  ✓ User 추가: user (ID: ${userResult.lastInsertRowid})`);
      }
    } else {
      console.log(`  - User 이미 존재: user (ID: ${userUser.id})`);
    }

    console.log('\n=== 기본 사용자 계정 확인 완료 ===');

  } catch (error) {
    console.error('샘플 데이터 추가 중 오류 발생:', error);
    throw error;
  }
}

// 스크립트 실행
if (require.main === module) {
  addSampleData()
    .then(() => {
      console.log('\n스크립트 실행 완료');
      process.exit(0);
    })
    .catch((error) => {
      console.error('스크립트 실행 실패:', error);
      process.exit(1);
    });
}

module.exports = { addSampleData };


// DLP 로그 전체 삭제 스크립트
const db = require('./config/db');

console.log('=== DLP 로그 삭제 시작 ===\n');

// 현재 로그 개수 확인
const beforeCount = db.prepare('SELECT COUNT(*) as count FROM dlp_violation_logs').get();
console.log(`삭제 전 로그 개수: ${beforeCount.count}`);

// 모든 로그 삭제
try {
  const result = db.prepare('DELETE FROM dlp_violation_logs').run();
  console.log(`삭제된 행 수: ${result.changes}`);
} catch (error) {
  console.error('삭제 중 오류 발생:', error.message);
  process.exit(1);
}

// 삭제 후 로그 개수 확인
const afterCount = db.prepare('SELECT COUNT(*) as count FROM dlp_violation_logs').get();
console.log(`삭제 후 로그 개수: ${afterCount.count}\n`);

console.log('✅ DLP 로그가 모두 삭제되었습니다.');

process.exit(0);


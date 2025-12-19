/**
 * 한국 시간(UTC+9) 관련 유틸리티 함수
 */

/**
 * 현재 한국 시간을 ISO 문자열 형식으로 반환
 * @returns {string} YYYY-MM-DDTHH:mm:ss.sssZ 형식의 한국 시간
 */
function getKoreaTimeISOString() {
  const now = new Date();
  // UTC 시간에 9시간을 더함
  const koreaTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
  return koreaTime.toISOString();
}

/**
 * 현재 한국 시간을 SQLite DATETIME 형식으로 반환
 * @returns {string} YYYY-MM-DD HH:mm:ss 형식의 한국 시간
 */
function getKoreaTimeSQLite() {
  const now = new Date();
  // UTC 시간에 9시간을 더함
  const koreaTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
  
  const year = koreaTime.getUTCFullYear();
  const month = String(koreaTime.getUTCMonth() + 1).padStart(2, '0');
  const day = String(koreaTime.getUTCDate()).padStart(2, '0');
  const hours = String(koreaTime.getUTCHours()).padStart(2, '0');
  const minutes = String(koreaTime.getUTCMinutes()).padStart(2, '0');
  const seconds = String(koreaTime.getUTCSeconds()).padStart(2, '0');
  
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

/**
 * SQLite의 CURRENT_TIMESTAMP를 한국 시간으로 변환하는 SQL 함수
 * @returns {string} datetime('now', '+9 hours')
 */
function getKoreaTimeSQL() {
  return "datetime('now', '+9 hours')";
}

module.exports = {
  getKoreaTimeISOString,
  getKoreaTimeSQLite,
  getKoreaTimeSQL
};


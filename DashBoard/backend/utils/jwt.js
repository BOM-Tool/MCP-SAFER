const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

/**
 * JWT 토큰 발급
 * @param {Object} user - 사용자 정보
 * @param {number} user.id - 사용자 ID
 * @param {string} user.username - 사용자명
 * @param {string} user.employee_id - 사원번호
 * @param {string} user.email - 이메일
 * @param {string} user.team - 팀
 * @param {Array<string>} user.roles - 역할 배열
 * @returns {string} JWT 토큰
 */
function generateToken(user) {
  const payload = {
    type: 'access',
    sub: user.id.toString(),
    id: user.id,
    username: user.username,
    employee_id: user.employee_id,
    email: user.email,
    team: user.team || null,
    roles: user.roles || []
  };

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    issuer: 'bom-tool',
    audience: 'bom-tool-api'
  });
}

/**
 * JWT 토큰 검증
 * @param {string} token - JWT 토큰
 * @returns {Object|null} 디코딩된 토큰 페이로드 또는 null
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET, {
      issuer: 'bom-tool',
      audience: 'bom-tool-api'
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('토큰이 만료되었습니다.');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('유효하지 않은 토큰입니다.');
    } else {
      throw new Error('토큰 검증 중 오류가 발생했습니다.');
    }
  }
}

/**
 * Authorization 헤더에서 토큰 추출
 * @param {string} authHeader - Authorization 헤더 값 (예: "Bearer <token>")
 * @returns {string|null} 토큰 또는 null
 */
function extractTokenFromHeader(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7); // "Bearer " 제거
}

module.exports = {
  generateToken,
  verifyToken,
  extractTokenFromHeader,
  JWT_SECRET
};







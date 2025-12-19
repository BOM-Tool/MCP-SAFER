const { verifyToken, extractTokenFromHeader } = require('../utils/jwt');

/**
 * JWT 토큰 검증 미들웨어
 * req.user에 사용자 정보를 설정합니다.
 */
function jwtAuth(req, res, next) {
  try {
    // Authorization 헤더에서 토큰 추출
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: '인증 토큰이 제공되지 않았습니다.'
      });
    }

    // 토큰 검증
    const decoded = verifyToken(token);

    // req.user에 사용자 정보 설정
    req.user = {
      id: decoded.id,
      username: decoded.username,
      employee_id: decoded.employee_id,
      email: decoded.email,
      team: decoded.team,
      roles: decoded.roles || []
    };

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: error.message || '인증 실패'
    });
  }
}

/**
 * 선택적 JWT 인증 미들웨어
 * 토큰이 있으면 검증하고, 없으면 통과
 */
function optionalJwtAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (token) {
      const decoded = verifyToken(token);
      req.user = {
        id: decoded.id,
        username: decoded.username,
        employee_id: decoded.employee_id,
        email: decoded.email,
        team: decoded.team,
        roles: decoded.roles || []
      };
    }
  } catch (error) {
    // 선택적 인증이므로 오류를 무시하고 통과
  }
  next();
}

module.exports = {
  jwtAuth,
  optionalJwtAuth
};







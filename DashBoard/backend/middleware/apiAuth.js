// 외부 API 인증 미들웨어 (API Key 기반)
// MCP Proxy 요청은 선택적으로 API 키 검증
const apiAuth = (req, res, next) => {
  // MCP Proxy 요청인지 확인
  const isMCPProxyRequest = req.headers['x-mcp-proxy-request'] === 'true';
  
  // MCP Proxy 요청이고 API 키가 설정되지 않았으면 통과
  if (isMCPProxyRequest && !process.env.MCP_API_KEY && !process.env.DLP_API_KEY) {
    return next();
  }

  // 환경변수에서 API 키 가져오기 (MCP용 우선, 없으면 DLP용)
  const validApiKey = process.env.MCP_API_KEY || process.env.DLP_API_KEY;

  // API 키가 설정되지 않았으면 통과 (선택적 인증)
  if (!validApiKey) {
    return next();
  }

  // 헤더 또는 쿼리 파라미터에서 API 키 확인
  const apiKey = req.headers['x-api-key'] || req.headers['api-key'] || req.query.api_key;

  if (!apiKey || apiKey !== validApiKey) {
    return res.status(401).json({
      success: false,
      message: '유효하지 않은 API 키입니다.'
    });
  }

  next();
};

module.exports = { apiAuth };


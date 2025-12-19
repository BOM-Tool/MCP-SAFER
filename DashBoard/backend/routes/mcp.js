const express = require('express');
const router = express.Router();
const mcpController = require('../controllers/mcpController');
const { clientIPMiddleware } = require('../middleware/clientIP');
const { apiAuth } = require('../middleware/apiAuth');

// Tool 접근 권한 확인 (MCP Proxy용)
// IP 기반 인증 사용 (JWT 대신)
router.post('/check-permission', 
  clientIPMiddleware,  // 클라이언트 IP 추출
  apiAuth,             // API 키 검증 (선택적, 설정된 경우에만)
  mcpController.checkPermission
);

// MCP 서버 정보 조회 (Proxy용)
// server_id로 서버 연결 설정 조회
router.get('/servers/:server_id', 
  apiAuth,  // API 키 검증 (선택적)
  mcpController.getServerConfig
);

module.exports = router;






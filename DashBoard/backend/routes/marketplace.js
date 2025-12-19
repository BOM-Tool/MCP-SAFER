const express = require('express');
const router = express.Router();
const marketplaceController = require('../controllers/marketplaceController');
const upload = require('../middleware/upload');
const { jwtAuth, optionalJwtAuth } = require('../middleware/jwtAuth');

// MCP 서버 목록 조회 (선택적 인증: admin 체크를 위해)
router.get('/', optionalJwtAuth, marketplaceController.getMcpServers);

// MCP 서버 등록 요청 (파일 및 이미지 업로드 포함)
router.post('/request', upload.fields, marketplaceController.createMcpRequest);

// GitHub 링크에서 Tool 목록 스캔
router.get('/scan-tools', marketplaceController.scanGitHubTools);

// 등록 요청 목록 조회 (게시판 형태, 역할별 필터링) - :id 라우트보다 먼저 정의
router.get('/requests', jwtAuth, marketplaceController.getMcpRequests);

// 등록 요청 승인/거부 (관리자용) - :id 라우트보다 먼저 정의
router.put('/requests/:id/review', marketplaceController.reviewRequest);

// 등록 요청 삭제 (관리자 또는 요청자 본인) - :id 라우트보다 먼저 정의
router.delete('/requests/:id', jwtAuth, marketplaceController.deleteMcpRequest);

// MCP 서버 삭제 (관리자용) - :id 라우트보다 먼저 정의
router.delete('/server/:id', marketplaceController.deleteMcpServer);

// Pending 상태의 등록 요청 개수 조회 (알림용)
router.get('/requests/pending-count', jwtAuth, marketplaceController.getPendingRequestCount);

// MCP 서버의 tools 조회 (mcp_tools 테이블에서)
router.get('/tools', marketplaceController.getToolsByServerName);

// MCP 서버 상세 조회 (마지막에 위치 - 와일드카드 라우트)
router.get('/:id', marketplaceController.getMcpServerDetail);

module.exports = router;


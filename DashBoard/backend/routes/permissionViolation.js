const express = require('express');
const router = express.Router();
const permissionViolationController = require('../controllers/permissionViolationController');
const { jwtAuth } = require('../middleware/jwtAuth');

// 권한 위반 로그 목록 조회
router.get('/logs', jwtAuth, permissionViolationController.getViolationLogs);

// 구체적인 라우트를 먼저 정의 (와일드카드 라우트보다 먼저)
// Pending 상태의 권한 위반 로그 개수 조회 (알림용)
router.get('/logs/pending-count', jwtAuth, permissionViolationController.getPendingCount);

// 최신 로그 ID 조회 (폴링용)
router.get('/logs/latest', jwtAuth, permissionViolationController.getLatestLogId);

// SSE 스트림 (실시간 업데이트)
router.get('/logs/stream', jwtAuth, permissionViolationController.streamLogs);

// 권한 위반 로그 상태 업데이트
router.put('/logs/:id/status', jwtAuth, permissionViolationController.updateLogStatus);

// 권한 위반 로그 상세 조회 (와일드카드 라우트는 마지막에)
router.get('/logs/:id', jwtAuth, permissionViolationController.getViolationLogById);

module.exports = router;


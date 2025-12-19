const express = require('express');
const router = express.Router();
const dlpController = require('../controllers/dlpController');
const { apiAuth } = require('../middleware/apiAuth');

// 외부 프록시 서버에서 DLP 위반 로그 전송 (API Key 인증 필요)
router.post('/violation', apiAuth, dlpController.receiveViolationLog);

// 최신 로그 ID 확인 (변경 감지용)
router.get('/logs/latest', dlpController.getLatestLogId);

// Pending 상태의 DLP 위반 로그 개수 조회 (알림용)
router.get('/logs/pending-count', dlpController.getPendingCount);

// DLP 로그 조회 (관리자용)
router.get('/logs', dlpController.getViolationLogs);

// DLP 로그 상세 조회
router.get('/logs/:id', dlpController.getViolationLogById);

// DLP 로그 상태 업데이트
router.put('/logs/:id/status', dlpController.updateLogStatus);

// DLP 로그 실시간 스트림 (SSE)
router.get('/logs/stream', dlpController.streamLogs);

// 위반 유형 목록 조회
router.get('/violation-types', dlpController.getViolationTypes);

module.exports = router;


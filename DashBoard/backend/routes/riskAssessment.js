const express = require('express');
const router = express.Router();
const riskAssessmentController = require('../controllers/riskAssessmentController');
const { jwtAuth } = require('../middleware/jwtAuth');

// 모든 엔드포인트는 인증 필요
router.use(jwtAuth);

// 라우트 등록 확인용 로그
console.log('[Risk Assessment Routes] 라우트 등록됨');

// 코드 스캔 실행 (도커 컨테이너 사용)
router.post('/scan-code', riskAssessmentController.scanCode);

// 진행률 조회
router.get('/scan-progress', riskAssessmentController.getScanProgress);

// 스캔 결과 조회
router.get('/code-vulnerabilities', riskAssessmentController.getCodeVulnerabilities);
router.get('/oss-vulnerabilities', riskAssessmentController.getOssVulnerabilities);
router.get('/tool-validation-vulnerabilities', riskAssessmentController.getToolValidationVulnerabilities);
router.get('/tool-validation-reports', riskAssessmentController.getToolValidationReports);

// 기존 리포트 임포트 (수동)
router.post('/import-tool-validation-reports', riskAssessmentController.importToolValidationReports);

module.exports = router;


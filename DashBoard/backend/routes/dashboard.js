const express = require('express');
const router = express.Router();
const dashboardController = require('../controllers/dashboardController');
const { jwtAuth } = require('../middleware/jwtAuth');

// 모든 엔드포인트는 인증 필요
router.use(jwtAuth);

// MCP 서버 트래픽 통계 (앱별)
router.get('/traffic/app', dashboardController.getMcpTrafficByApp);

// 애플리케이션별 MCP 서버 트래픽 (스택 영역 차트용)
router.get('/traffic/app-stacked', dashboardController.getAppTrafficStacked);

// Host별 사용량
router.get('/traffic/host', dashboardController.getMcpTrafficByHost);

// 실시간 탐지 결과
router.get('/detections', dashboardController.getDetectionResults);

// 사용자 통계
router.get('/statistics', dashboardController.getUserStatistics);

// MCP 서버별 사용자 분포
router.get('/user-distribution', dashboardController.getMcpUserDistribution);

// MCP 서버 통계 (개수 및 카테고리별 분포)
router.get('/mcp-server-stats', dashboardController.getMcpServerStats);

// 시간별 스택형 차트 데이터
router.get('/stacked-area-chart', dashboardController.getStackedAreaChartData);

// KPI 데이터
router.get('/kpi', dashboardController.getKpiData);

// 서버별 사용자 수 Top 10
router.get('/top-servers-by-users', dashboardController.getTopServersByUsers);

// 가장 오래된 스캔 일시 보유 서버 Top 10
router.get('/oldest-scan-servers', dashboardController.getOldestScanServers);

// 다운로드가 많이 된 서버 Top 10
router.get('/top-download-servers', dashboardController.getTopDownloadServers);

// 최근 탐지된 DLP Top 10
router.get('/recent-dlp-detections', dashboardController.getRecentDlpDetections);

module.exports = router;


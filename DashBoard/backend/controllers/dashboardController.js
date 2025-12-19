const db = require('../config/db');
const { getKoreaTimeSQLite } = require('../utils/dateTime');
const dlpLogModel = require('../models/dlpLog');

const dashboardController = {
  // MCP 서버 트래픽 통계 (앱별 사용량) - 단순 집계
  getMcpTrafficByApp: (req, res) => {
    try {
      const { days = 7 } = req.query;
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - parseInt(days));
      // 한국 시간으로 변환 (UTC+9)
      const koreaStartDate = new Date(startDate.getTime() + (9 * 60 * 60 * 1000));
      const koreaStartDateStr = koreaStartDate.toISOString().replace('T', ' ').substring(0, 19);

      const query = `
        SELECT 
          ms.name as app_name,
          ms.id as server_id,
          COUNT(utl.id) as usage_count,
          COUNT(DISTINCT utl.user_id) as unique_users
        FROM mcp_tool_usage_logs utl
        JOIN mcp_servers ms ON utl.mcp_server_id = ms.id
        WHERE utl.used_at >= ?
        GROUP BY ms.id, ms.name
        ORDER BY usage_count DESC
      `;

      const traffic = db.prepare(query).all(koreaStartDateStr);
      
      res.json({
        success: true,
        data: traffic
      });
    } catch (error) {
      console.error('MCP 트래픽 통계 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '트래픽 통계 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 애플리케이션별 MCP 서버 트래픽 (스택 영역 차트용 - 시간별)
  getAppTrafficStacked: (req, res) => {
    try {
      const { days = 7 } = req.query;
      const daysInt = parseInt(days);
      
      // 시간별로 그룹화하고, 각 애플리케이션별 트래픽 집계
      const query = `
        SELECT 
          strftime('%Y-%m-%d %H:00:00', datetime(utl.used_at, '+9 hours')) as hour,
          ms.name as app_name,
          COUNT(utl.id) as count
        FROM mcp_tool_usage_logs utl
        JOIN mcp_servers ms ON utl.mcp_server_id = ms.id
        WHERE datetime(utl.used_at, '+9 hours') >= datetime('now', '+9 hours', '-${daysInt} days')
        GROUP BY strftime('%Y-%m-%d %H:00:00', datetime(utl.used_at, '+9 hours')), ms.id, ms.name
        ORDER BY hour ASC, count DESC
      `;

      const trafficData = db.prepare(query).all();
      
      // 전체 기간 동안 앱별 총 트래픽 계산하여 Top 5 선정
      const appTotalTraffic = {};
      trafficData.forEach(item => {
        if (!appTotalTraffic[item.app_name]) {
          appTotalTraffic[item.app_name] = 0;
        }
        appTotalTraffic[item.app_name] += item.count;
      });
      
      // 트래픽 순으로 정렬하여 Top 5 선정
      const sortedApps = Object.entries(appTotalTraffic)
        .sort((a, b) => b[1] - a[1])
        .map(([name]) => name);
      
      const top5Apps = sortedApps.slice(0, 5);
      const otherApps = sortedApps.slice(5);
      
      // 시간별로 그룹화하고 각 앱별 데이터 구성
      const timeMap = {};
      const appNames = new Set(top5Apps);
      if (otherApps.length > 0) {
        appNames.add('Other');
      }
      
      trafficData.forEach(item => {
        if (!timeMap[item.hour]) {
          timeMap[item.hour] = {};
        }
        
        // Top 5에 포함된 앱은 그대로, 나머지는 "Other"로 집계
        if (top5Apps.includes(item.app_name)) {
          timeMap[item.hour][item.app_name] = (timeMap[item.hour][item.app_name] || 0) + item.count;
        } else {
          timeMap[item.hour]['Other'] = (timeMap[item.hour]['Other'] || 0) + item.count;
        }
      });
      
      // 시간 포맷팅 함수
      const formatTimeLabel = (hourStr) => {
        const match = hourStr.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):/);
        if (!match) return hourStr;
        const hour = parseInt(match[4], 10);
        const ampm = hour >= 12 ? 'PM' : 'AM';
        const displayHour = hour % 12 || 12;
        return `${displayHour.toString().padStart(2, '0')}:00 ${ampm}`;
      };
      
      // 시간순으로 정렬된 데이터 배열 생성
      const sortedTimes = Object.keys(timeMap).sort();
      const result = sortedTimes.map(hour => {
        const dataPoint = { time: formatTimeLabel(hour), timestamp: hour };
        appNames.forEach(appName => {
          dataPoint[appName] = timeMap[hour][appName] || 0;
        });
        return dataPoint;
      });
      
      res.json({
        success: true,
        data: result,
        apps: Array.from(appNames)
      });
    } catch (error) {
      console.error('애플리케이션별 스택 트래픽 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '애플리케이션별 트래픽 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // Host별 사용량
  getMcpTrafficByHost: (req, res) => {
    try {
      const { days = 7 } = req.query;
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - parseInt(days));
      // 한국 시간으로 변환 (UTC+9)
      const koreaStartDate = new Date(startDate.getTime() + (9 * 60 * 60 * 1000));
      const koreaStartDateStr = koreaStartDate.toISOString().replace('T', ' ').substring(0, 19);

      const query = `
        SELECT 
          utl.ip_address as host,
          COUNT(utl.id) as usage_count,
          COUNT(DISTINCT utl.user_id) as unique_users,
          COUNT(DISTINCT utl.mcp_server_id) as unique_servers
        FROM mcp_tool_usage_logs utl
        WHERE utl.used_at >= ? AND utl.ip_address IS NOT NULL
        GROUP BY utl.ip_address
        ORDER BY usage_count DESC
        LIMIT 20
      `;

      const traffic = db.prepare(query).all(koreaStartDateStr);
      
      res.json({
        success: true,
        data: traffic
      });
    } catch (error) {
      console.error('Host별 트래픽 통계 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'Host별 트래픽 통계 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 실시간 탐지 결과 (DLP + RBAC)
  getDetectionResults: (req, res) => {
    try {
      const { limit = 50, offset = 0 } = req.query;
      
      // DLP 탐지 결과
      const dlpLogs = dlpLogModel.findAll({
        limit: parseInt(limit),
        offset: parseInt(offset)
      });

      // RBAC 위반 로그 (mcp_tool_usage_logs에서 권한 없는 사용 추출)
      // 실제로는 별도 테이블이 필요하지만, 현재는 mcp_tool_permissions와 비교
      const rbacViolations = db.prepare(`
        SELECT 
          utl.id,
          utl.user_id,
          u.username,
          u.employee_id,
          u.team,
          ms.name as mcp_server_name,
          utl.action as tool_name,
          utl.details,
          utl.used_at as timestamp,
          utl.ip_address,
          'RBAC' as detection_type
        FROM mcp_tool_usage_logs utl
        JOIN users u ON utl.user_id = u.id
        JOIN mcp_servers ms ON utl.mcp_server_id = ms.id
        LEFT JOIN mcp_tool_permissions mtp ON utl.user_id = mtp.user_id 
          AND utl.mcp_server_id = mtp.mcp_server_id
        WHERE mtp.id IS NULL
        ORDER BY utl.used_at DESC
        LIMIT ? OFFSET ?
      `).all(parseInt(limit), parseInt(offset));

      // DLP 로그를 탐지 결과 형식으로 변환
      const dlpDetections = dlpLogs.map(log => ({
        id: log.id,
        user_id: log.user_id,
        username: log.username,
        employee_id: log.employee_id,
        team: null, // DLP 로그에는 team 정보가 없을 수 있음
        mcp_server_name: null, // DLP 로그에는 서버 정보가 없을 수 있음
        tool_name: null,
        request_content: log.original_text || log.masked_text,
        response_content: log.original_json ? JSON.stringify(log.original_json) : null,
        direction: log.action_type === 'request' ? 'in' : 'out',
        detection_tags: [log.violation_type],
        detection_type: 'DLP',
        severity: log.severity,
        timestamp: log.timestamp
      }));

      // RBAC 위반을 탐지 결과 형식으로 변환
      const rbacDetections = rbacViolations.map(log => ({
        id: log.id,
        user_id: log.user_id,
        username: log.username,
        employee_id: log.employee_id,
        team: log.team,
        mcp_server_name: log.mcp_server_name,
        tool_name: log.tool_name,
        request_content: log.details,
        response_content: null,
        direction: 'in',
        detection_tags: ['RBAC Violation'],
        detection_type: 'RBAC',
        severity: 'high',
        timestamp: log.timestamp
      }));

      // 시간순으로 정렬하여 합치기
      const allDetections = [...dlpDetections, ...rbacDetections]
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, parseInt(limit));

      res.json({
        success: true,
        data: allDetections,
        total: allDetections.length
      });
    } catch (error) {
      console.error('탐지 결과 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '탐지 결과 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 사용자 통계
  getUserStatistics: (req, res) => {
    try {
      // 1. MCP Server 사용자 수 (원그래프용)
      const userStats = db.prepare(`
        SELECT 
          COUNT(DISTINCT utl.user_id) as total_users,
          COUNT(DISTINCT CASE WHEN utl.used_at >= datetime('now', '-7 days') THEN utl.user_id END) as active_users_7d,
          COUNT(DISTINCT CASE WHEN utl.used_at >= datetime('now', '-30 days') THEN utl.user_id END) as active_users_30d
        FROM mcp_tool_usage_logs utl
      `).get();

      // 2. Health check 안 된 사용자 수 (최근 30일간 사용하지 않은 사용자)
      const inactiveUsers = db.prepare(`
        SELECT COUNT(DISTINCT u.id) as count
        FROM users u
        LEFT JOIN mcp_tool_usage_logs utl ON u.id = utl.user_id 
          AND utl.used_at >= datetime('now', '-30 days')
        WHERE u.is_active = 1 AND utl.id IS NULL
      `).get();

      // 3. 검증 날짜 오래된 MCP 서버 (30일 이상 업데이트 안 된 서버)
      const outdatedServers = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE updated_at < datetime('now', '-30 days')
          OR updated_at IS NULL
      `).get();

      // 4. 취약점 관련 통계 (DLP 위반 기준)
      const vulnerabilityStats = db.prepare(`
        SELECT 
          violation_type,
          COUNT(*) as count,
          severity
        FROM dlp_violation_logs
        WHERE timestamp >= datetime('now', '-30 days')
        GROUP BY violation_type, severity
      `).all();

      // 5. 트래픽 그래프 데이터 (시간별)
      const trafficGraph = db.prepare(`
        SELECT 
          DATE(used_at) as date,
          COUNT(*) as count
        FROM mcp_tool_usage_logs
        WHERE used_at >= datetime('now', '-30 days')
        GROUP BY DATE(used_at)
        ORDER BY date ASC
      `).all();

      // 6. 신청 들어온 MCP Server 수
      const pendingRequests = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_register_requests
        WHERE status = 'pending'
      `).get();

      res.json({
        success: true,
        data: {
          userStats,
          inactiveUsers: inactiveUsers.count,
          outdatedServers: outdatedServers.count,
          vulnerabilityStats,
          trafficGraph,
          pendingRequests: pendingRequests.count
        }
      });
    } catch (error) {
      console.error('사용자 통계 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '사용자 통계 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // MCP 서버별 사용자 분포 (원그래프용)
  getMcpUserDistribution: (req, res) => {
    try {
      const query = `
        SELECT 
          ms.name as server_name,
          COUNT(DISTINCT utl.user_id) as user_count
        FROM mcp_servers ms
        LEFT JOIN mcp_tool_usage_logs utl ON ms.id = utl.mcp_server_id
          AND utl.used_at >= datetime('now', '-30 days')
        GROUP BY ms.id, ms.name
        HAVING user_count > 0
        ORDER BY user_count DESC
      `;

      const distribution = db.prepare(query).all();
      
      res.json({
        success: true,
        data: distribution
      });
    } catch (error) {
      console.error('MCP 서버별 사용자 분포 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '사용자 분포 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 시간별 스택형 차트 데이터 (트래픽 + DLP 탐지)
  getStackedAreaChartData: (req, res) => {
    try {
      const { hours = 24 } = req.query; // 기본값: 최근 24시간
      const hoursInt = parseInt(hours);
      
      // SQLite datetime 함수를 사용하여 시간별로 그룹화 (한국 시간 기준)
      // 각 시간대별로:
      // 1. 일반 트래픽 (mcp_tool_usage_logs)
      // 2. DLP 탐지 (dlp_violation_logs)
      
      // SQLite에서 시간별로 데이터를 그룹화하여 가져오기
      // datetime('now', '+9 hours')를 사용하여 한국 시간 기준으로 계산
      const trafficQuery = `
        SELECT 
          strftime('%Y-%m-%d %H:00:00', datetime(used_at, '+9 hours')) as hour,
          COUNT(*) as count
        FROM mcp_tool_usage_logs
        WHERE datetime(used_at, '+9 hours') >= datetime('now', '+9 hours', '-${hoursInt} hours')
        GROUP BY strftime('%Y-%m-%d %H:00:00', datetime(used_at, '+9 hours'))
        ORDER BY hour ASC
      `;
      
      const dlpQuery = `
        SELECT 
          strftime('%Y-%m-%d %H:00:00', datetime(timestamp, '+9 hours')) as hour,
          COUNT(*) as count
        FROM dlp_violation_logs
        WHERE datetime(timestamp, '+9 hours') >= datetime('now', '+9 hours', '-${hoursInt} hours')
        GROUP BY strftime('%Y-%m-%d %H:00:00', datetime(timestamp, '+9 hours'))
        ORDER BY hour ASC
      `;
      
      const trafficData = db.prepare(trafficQuery).all();
      const dlpData = db.prepare(dlpQuery).all();
      
      // 데이터를 맵으로 변환하여 빠른 조회
      const trafficMap = {};
      trafficData.forEach(item => {
        if (item.hour) {
          trafficMap[item.hour] = item.count;
        }
      });
      
      const dlpMap = {};
      dlpData.forEach(item => {
        if (item.hour) {
          dlpMap[item.hour] = item.count;
        }
      });
      
      // 시간 문자열을 파싱하여 시간 포맷팅 함수
      const formatTimeLabel = (hourStr) => {
        // hourStr 형식: "YYYY-MM-DD HH:00:00"
        const match = hourStr.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):/);
        if (!match) return hourStr;
        
        const hour = parseInt(match[4], 10);
        const ampm = hour >= 12 ? 'PM' : 'AM';
        const displayHour = hour % 12 || 12;
        return `${displayHour.toString().padStart(2, '0')}:00 ${ampm}`;
      };
      
      // 최근 N시간의 모든 시간대 생성 (한국 시간 기준)
      // JavaScript에서 시간대를 생성하여 빈 시간대도 포함
      const data = [];
      const now = new Date();
      const koreaOffset = 9 * 60 * 60 * 1000;
      
      // 현재 시간을 한국 시간으로 변환
      const koreaNow = new Date(now.getTime() + koreaOffset);
      // 현재 시간의 정시로 맞춤
      koreaNow.setUTCMinutes(0);
      koreaNow.setUTCSeconds(0);
      koreaNow.setUTCMilliseconds(0);
      
      for (let i = hoursInt - 1; i >= 0; i--) {
        // i시간 전의 시간 계산
        const targetTime = new Date(koreaNow);
        targetTime.setUTCHours(targetTime.getUTCHours() - i);
        
        // SQLite 형식의 시간 문자열 (YYYY-MM-DD HH:00:00) - 한국 시간 기준
        const year = targetTime.getUTCFullYear();
        const month = String(targetTime.getUTCMonth() + 1).padStart(2, '0');
        const day = String(targetTime.getUTCDate()).padStart(2, '0');
        const hour = String(targetTime.getUTCHours()).padStart(2, '0');
        const hourStr = `${year}-${month}-${day} ${hour}:00:00`;
        
        // 시간 포맷 (HH:MM AM/PM) - 한국 시간 기준
        const displayHour = targetTime.getUTCHours();
        const ampm = displayHour >= 12 ? 'PM' : 'AM';
        const displayHour12 = displayHour % 12 || 12;
        const timeLabel = `${displayHour12.toString().padStart(2, '0')}:00 ${ampm}`;
        
        const traffic = trafficMap[hourStr] || 0;
        const detections = dlpMap[hourStr] || 0;
        
        data.push({
          time: timeLabel,
          timestamp: hourStr,
          traffic: traffic,
          detections: detections,
          total: traffic + detections
        });
      }
      
      res.json({
        success: true,
        data: data
      });
    } catch (error) {
      console.error('스택형 차트 데이터 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '차트 데이터 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // MCP 서버 통계 (개수 및 카테고리별 분포)
  getMcpServerStats: (req, res) => {
    try {
      // 전체 MCP 서버 개수
      const totalServers = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE status = 'approved'
      `).get();

      // 카테고리별 분포 (현재는 description이나 name 기반으로 분류)
      // 실제 카테고리 필드가 없으므로 샘플 데이터로 구성
      // 추후 카테고리 필드가 추가되면 수정 필요
      const categories = [
        { name: 'Databases & Storage', count: 0, color: '#8B5CF6' },
        { name: 'Productivity & Workflow', count: 0, color: '#3B82F6' },
        { name: 'Coding Documentation', count: 0, color: '#14B8A6' },
        { name: 'Containerization & Orchestration', count: 0, color: '#F59E0B' },
        { name: 'Code Repositories & Versioning', count: 0, color: '#60A5FA' },
        { name: 'Project Management', count: 0, color: '#003153' }
      ];

      // 전체 서버를 카테고리별로 분류 (임시로 균등 분배)
      const total = totalServers.count || 0;
      const perCategory = Math.floor(total / categories.length);
      const remainder = total % categories.length;
      
      categories.forEach((cat, index) => {
        cat.count = perCategory + (index < remainder ? 1 : 0);
      });

      // 통계 정보
      const withCredentials = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE status = 'approved' AND connection_snippet IS NOT NULL AND connection_snippet != ''
      `).get();

      // DLP 위반 로그에는 mcp_server_id 컬럼이 없으므로, 
      // source_ip나 다른 방법으로 연결하거나 통계에서 제외
      // 현재는 DLP 위반이 있는 서버 수를 0으로 설정 (또는 다른 로직으로 계산)
      const withRisks = { count: 0 };

      const withIssues = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE status = 'approved' AND updated_at < datetime('now', '-30 days')
      `).get();

      const credentialsPercent = total > 0 ? Math.round((withCredentials.count / total) * 100) : 0;
      const risksPercent = total > 0 ? Math.round((withRisks.count / total) * 100) : 0;
      const issuesPercent = total > 0 ? Math.round((withIssues.count / total) * 100) : 0;

      res.json({
        success: true,
        data: {
          total: total,
          categories: categories,
          stats: {
            withCredentials: {
              count: withCredentials.count,
              percent: credentialsPercent
            },
            withRisks: {
              count: withRisks.count,
              percent: risksPercent
            },
            withIssues: {
              count: withIssues.count,
              percent: issuesPercent
            }
          }
        }
      });
    } catch (error) {
      console.error('MCP 서버 통계 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'MCP 서버 통계 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // KPI 데이터 (상단 지표 카드)
  getKpiData: (req, res) => {
    try {
      // 1. 등록된 서버 수
      const registeredServers = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE status = 'approved'
      `).get();

      // 2. 사용자 수
      const totalUsers = db.prepare(`
        SELECT COUNT(*) as count
        FROM users
        WHERE is_active = 1
      `).get();

      // 3. 30일 비활성 사용자 수
      const inactiveUsers = db.prepare(`
        SELECT COUNT(DISTINCT u.id) as count
        FROM users u
        LEFT JOIN mcp_tool_usage_logs utl ON u.id = utl.user_id 
          AND utl.used_at >= datetime('now', '-30 days')
        WHERE u.is_active = 1 AND utl.id IS NULL
      `).get();

      // 4. 전체 스캔 수 (code_vulnerabilities와 oss_vulnerabilities의 고유 scan_path 개수)
      const totalScans = db.prepare(`
        SELECT COUNT(DISTINCT scan_path) as count
        FROM (
          SELECT scan_path FROM code_vulnerabilities WHERE scan_path IS NOT NULL
          UNION
          SELECT scan_path FROM oss_vulnerabilities WHERE scan_path IS NOT NULL
        )
      `).get();

      // 5. 최근 승인된 서버 수(7일)
      const recentApprovedServers = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE status = 'approved' 
          AND created_at >= datetime('now', '-7 days')
      `).get();

      // 6. 실시간 탐지 건수(최근 5분)
      const recentDetections = db.prepare(`
        SELECT COUNT(*) as count
        FROM dlp_violation_logs
        WHERE timestamp >= datetime('now', '-5 minutes')
      `).get();

      res.json({
        success: true,
        data: {
          registeredServers: registeredServers.count || 0,
          totalUsers: totalUsers.count || 0,
          inactiveUsers: inactiveUsers.count || 0,
          totalScans: totalScans.count || 0,
          recentApprovedServers: recentApprovedServers.count || 0,
          recentDetections: recentDetections.count || 0
        }
      });
    } catch (error) {
      console.error('KPI 데이터 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'KPI 데이터 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 서버별 사용자 수 Top 10
  getTopServersByUsers: (req, res) => {
    try {
      const query = `
        SELECT 
          ms.id,
          ms.name as server_name,
          COUNT(DISTINCT utl.user_id) as user_count
        FROM mcp_servers ms
        LEFT JOIN mcp_tool_usage_logs utl ON ms.id = utl.mcp_server_id
        WHERE ms.status = 'approved'
        GROUP BY ms.id, ms.name
        ORDER BY user_count DESC
        LIMIT 10
      `;

      const topServers = db.prepare(query).all();
      
      res.json({
        success: true,
        data: topServers
      });
    } catch (error) {
      console.error('서버별 사용자 수 Top 10 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '서버별 사용자 수 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 가장 오래된 스캔 일시 보유 서버 Top 10
  getOldestScanServers: (req, res) => {
    try {
      // 모든 스캔 데이터에서 서버별로 가장 오래된 스캔 일시 찾기
      // scan_path를 기준으로 mcp_servers와 매칭
      const allScans = db.prepare(`
        SELECT scan_path, MIN(scan_timestamp) as oldest_scan_timestamp
        FROM (
          SELECT scan_path, scan_timestamp FROM code_vulnerabilities WHERE scan_path IS NOT NULL
          UNION ALL
          SELECT scan_path, scan_timestamp FROM oss_vulnerabilities WHERE scan_path IS NOT NULL
        )
        GROUP BY scan_path
      `).all();

      // mcp_servers와 매칭
      const servers = db.prepare(`
        SELECT id, name, github_link, file_path
        FROM mcp_servers
        WHERE status = 'approved'
      `).all();

      const serverScanMap = [];
      
      servers.forEach(server => {
        let oldestTimestamp = null;
        
        // scan_path와 매칭 시도
        for (const scan of allScans) {
          const scanPath = scan.scan_path || '';
          const githubLink = server.github_link || '';
          const filePath = server.file_path || '';
          
          // github_link 매칭 (여러 형태 고려)
          if (githubLink) {
            const githubName = githubLink.replace('https://github.com/', '').replace('.git', '').replace(/\/tree\/.*$/, '');
            if (scanPath.includes(githubName) || scanPath === githubLink) {
              if (!oldestTimestamp || scan.oldest_scan_timestamp < oldestTimestamp) {
                oldestTimestamp = scan.oldest_scan_timestamp;
              }
            }
          }
          
          // file_path 매칭
          if (filePath && scanPath === filePath) {
            if (!oldestTimestamp || scan.oldest_scan_timestamp < oldestTimestamp) {
              oldestTimestamp = scan.oldest_scan_timestamp;
            }
          }
        }
        
        if (oldestTimestamp) {
          serverScanMap.push({
            id: server.id,
            server_name: server.name,
            oldest_scan_timestamp: oldestTimestamp
          });
        }
      });
      
      // 가장 오래된 순으로 정렬 (오래된 것이 먼저)
      serverScanMap.sort((a, b) => {
        if (!a.oldest_scan_timestamp) return 1;
        if (!b.oldest_scan_timestamp) return -1;
        return new Date(a.oldest_scan_timestamp) - new Date(b.oldest_scan_timestamp);
      });
      
      res.json({
        success: true,
        data: serverScanMap.slice(0, 10)
      });
    } catch (error) {
      console.error('가장 오래된 스캔 서버 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '가장 오래된 스캔 서버 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 다운로드가 많이 된 서버 Top 10
  getTopDownloadServers: (req, res) => {
    try {
      const query = `
        SELECT 
          ms.id,
          ms.name as server_name,
          COUNT(dl.id) as download_count
        FROM mcp_servers ms
        LEFT JOIN download_logs dl ON ms.id = dl.mcp_server_id
        WHERE ms.status = 'approved'
        GROUP BY ms.id, ms.name
        HAVING download_count > 0
        ORDER BY download_count DESC
        LIMIT 10
      `;

      const topDownloadServers = db.prepare(query).all();
      
      res.json({
        success: true,
        data: topDownloadServers
      });
    } catch (error) {
      console.error('다운로드 많은 서버 Top 10 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '다운로드 많은 서버 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 최근 탐지된 DLP Top 10
  getRecentDlpDetections: (req, res) => {
    try {
      const query = `
        SELECT 
          id,
          username,
          employee_id,
          violation_type,
          severity,
          timestamp,
          original_text,
          masked_text
        FROM dlp_violation_logs
        ORDER BY timestamp DESC
        LIMIT 10
      `;

      const recentDlp = db.prepare(query).all();
      
      res.json({
        success: true,
        data: recentDlp
      });
    } catch (error) {
      console.error('최근 DLP 탐지 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '최근 DLP 탐지 조회 중 오류가 발생했습니다.'
      });
    }
  }
};

module.exports = dashboardController;


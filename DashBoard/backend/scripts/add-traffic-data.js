#!/usr/bin/env node
/**
 * MCP Server Traffic 및 User Distribution 예시 데이터 추가 스크립트
 * - MCP Server Traffic by Application: mcp_tool_usage_logs 데이터
 * - MCP Server User Distribution: 사용자별 MCP 서버 사용 분포
 */

const db = require('../config/db');

function getKoreaTime() {
  const now = new Date();
  const koreaTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
  return koreaTime.toISOString().replace('T', ' ').substring(0, 19);
}

function getPastTime(daysAgo, hoursAgo = 0) {
  const now = new Date();
  const past = new Date(now.getTime() - (daysAgo * 24 * 60 * 60 * 1000) - (hoursAgo * 60 * 60 * 1000) + (9 * 60 * 60 * 1000));
  return past.toISOString().replace('T', ' ').substring(0, 19);
}

async function addTrafficData() {
  try {
    console.log('=== MCP Server Traffic 및 User Distribution 데이터 추가 시작 ===\n');

    // 1. 사용자 및 MCP 서버 조회
    console.log('[1/3] 사용자 및 MCP 서버 조회 중...');
    const users = db.prepare('SELECT id, username, team FROM users WHERE team IN (?, ?)').all('Development', 'Security');
    const mcpServers = db.prepare('SELECT id, name FROM mcp_servers WHERE status = ?').all('approved');

    if (users.length === 0) {
      console.error('❌ 사용자가 없습니다. 먼저 사용자를 추가해주세요.');
      return;
    }

    if (mcpServers.length === 0) {
      console.error('❌ MCP 서버가 없습니다. 먼저 MCP 서버를 추가해주세요.');
      return;
    }

    console.log(`  ✓ 사용자 ${users.length}명 조회 완료`);
    console.log(`  ✓ MCP 서버 ${mcpServers.length}개 조회 완료`);

    // 2. MCP Tool Usage Logs 추가
    console.log('\n[2/3] MCP Tool Usage Logs 추가 중...');
    const usageLogStmt = db.prepare(`
      INSERT INTO mcp_tool_usage_logs 
      (user_id, mcp_server_id, action, details, used_at, ip_address)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    // 액션 종류
    const actions = [
      'create_repository',
      'get_file',
      'search_code',
      'create_issue',
      'update_page',
      'query_database',
      'read_file',
      'list_files',
      'search',
      'create_page'
    ];

    // IP 주소 목록
    const ipAddresses = [
      '192.168.1.100',
      '192.168.1.101',
      '192.168.1.102',
      '192.168.1.103',
      '10.0.0.10',
      '10.0.0.11',
      '172.16.0.5',
      '172.16.0.6'
    ];

    // 최근 30일간의 데이터 생성
    let totalLogs = 0;
    const days = 30;
    
    for (let day = 0; day < days; day++) {
      // 각 날짜마다 랜덤한 수의 로그 생성 (5-20개)
      const logsPerDay = Math.floor(Math.random() * 15) + 5;
      
      for (let i = 0; i < logsPerDay; i++) {
        // 랜덤 사용자 선택
        const user = users[Math.floor(Math.random() * users.length)];
        // 랜덤 MCP 서버 선택
        const server = mcpServers[Math.floor(Math.random() * mcpServers.length)];
        // 랜덤 액션 선택
        const action = actions[Math.floor(Math.random() * actions.length)];
        // 랜덤 IP 주소 선택
        const ipAddress = ipAddresses[Math.floor(Math.random() * ipAddresses.length)];
        // 랜덤 시간 (해당 날짜 내)
        const hoursAgo = Math.floor(Math.random() * 24);
        const usedAt = getPastTime(day, hoursAgo);
        // 랜덤 디테일
        const details = JSON.stringify({
          tool: action,
          timestamp: usedAt,
          user: user.username,
          server: server.name
        });

        try {
          usageLogStmt.run(
            user.id,
            server.id,
            action,
            details,
            usedAt,
            ipAddress
          );
          totalLogs++;
        } catch (error) {
          console.error(`  ✗ 로그 추가 실패:`, error.message);
        }
      }
    }

    console.log(`  ✓ MCP Tool Usage Logs ${totalLogs}개 추가 완료`);

    // 3. 서버별 통계 확인
    console.log('\n[3/3] 통계 확인 중...');
    const trafficStats = db.prepare(`
      SELECT 
        ms.name as app_name,
        ms.id as server_id,
        COUNT(utl.id) as usage_count,
        COUNT(DISTINCT utl.user_id) as unique_users
      FROM mcp_tool_usage_logs utl
      JOIN mcp_servers ms ON utl.mcp_server_id = ms.id
      WHERE utl.used_at >= datetime('now', '-30 days')
      GROUP BY ms.id, ms.name
      ORDER BY usage_count DESC
    `).all();

    console.log('\n  MCP Server Traffic by Application:');
    trafficStats.forEach(stat => {
      console.log(`    - ${stat.app_name}: ${stat.usage_count}회 사용 (${stat.unique_users}명의 사용자)`);
    });

    const userDistribution = db.prepare(`
      SELECT 
        ms.name as server_name,
        COUNT(DISTINCT utl.user_id) as user_count
      FROM mcp_servers ms
      LEFT JOIN mcp_tool_usage_logs utl ON ms.id = utl.mcp_server_id
        AND utl.used_at >= datetime('now', '-30 days')
      GROUP BY ms.id, ms.name
      HAVING user_count > 0
      ORDER BY user_count DESC
    `).all();

    console.log('\n  MCP Server User Distribution:');
    userDistribution.forEach(dist => {
      console.log(`    - ${dist.server_name}: ${dist.user_count}명의 사용자`);
    });

    console.log('\n=== MCP Server Traffic 및 User Distribution 데이터 추가 완료 ===');
    console.log(`\n요약:`);
    console.log(`- 총 사용 로그: ${totalLogs}개`);
    console.log(`- 기간: 최근 ${days}일`);
    console.log(`- 서버별 통계: ${trafficStats.length}개 서버`);
    console.log(`- 사용자 분포: ${userDistribution.length}개 서버`);

  } catch (error) {
    console.error('데이터 추가 중 오류 발생:', error);
    throw error;
  }
}

// 스크립트 실행
if (require.main === module) {
  addTrafficData()
    .then(() => {
      console.log('\n스크립트 실행 완료');
      process.exit(0);
    })
    .catch((error) => {
      console.error('스크립트 실행 실패:', error);
      process.exit(1);
    });
}

module.exports = { addTrafficData };


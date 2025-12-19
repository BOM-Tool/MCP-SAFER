import React, { useState, useEffect } from 'react';
import { apiGet } from '../../utils/api';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';
import './Dashboard.css';

const Dashboard = () => {
  const [loading, setLoading] = useState(true);
  
  // KPI 데이터
  const [kpiData, setKpiData] = useState(null);
  
  // 중단 카드 & 차트 데이터
  const [topServersByUsers, setTopServersByUsers] = useState([]);
  const [oldestScanServers, setOldestScanServers] = useState([]);
  const [topDownloadServers, setTopDownloadServers] = useState([]);
  const [recentDlpDetections, setRecentDlpDetections] = useState([]);
  
  // 트래픽 & 실시간 데이터
  const [trafficByApp, setTrafficByApp] = useState([]);
  const [trafficByAppStacked, setTrafficByAppStacked] = useState([]);
  const [appNames, setAppNames] = useState([]);
  const [selectedApp, setSelectedApp] = useState(null); // 클릭된 앱 추적
  const [trafficByHost, setTrafficByHost] = useState([]);
  const [realtimeDetections, setRealtimeDetections] = useState([]);
  
  // 데이터 로드
  useEffect(() => {
    loadDashboardData();
    // 실시간 업데이트 (30초마다)
    const interval = setInterval(loadDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // 모든 API 호출
      const [
        kpiRes,
        topServersRes,
        oldestScanRes,
        topDownloadRes,
        recentDlpRes,
        trafficAppRes,
        trafficAppStackedRes,
        trafficHostRes,
        detectionsRes
      ] = await Promise.all([
        apiGet('/dashboard/kpi'),
        apiGet('/dashboard/top-servers-by-users'),
        apiGet('/dashboard/oldest-scan-servers'),
        apiGet('/dashboard/top-download-servers'),
        apiGet('/dashboard/recent-dlp-detections'),
        apiGet('/dashboard/traffic/app?days=7'),
        apiGet('/dashboard/traffic/app-stacked?days=7'),
        apiGet('/dashboard/traffic/host?days=7'),
        apiGet('/dashboard/detections?limit=20')
      ]);
      
      if (kpiRes.success) {
        setKpiData(kpiRes.data);
      }
      
      if (topServersRes.success) {
        setTopServersByUsers(topServersRes.data || []);
      }
      
      if (oldestScanRes.success) {
        setOldestScanServers(oldestScanRes.data || []);
      }
      
      if (topDownloadRes.success) {
        setTopDownloadServers(topDownloadRes.data || []);
      }
      
      if (recentDlpRes.success) {
        setRecentDlpDetections(recentDlpRes.data || []);
      }
      
      if (trafficAppRes.success) {
        setTrafficByApp(trafficAppRes.data || []);
      }
      
      if (trafficAppStackedRes.success) {
        setTrafficByAppStacked(trafficAppStackedRes.data || []);
        setAppNames(trafficAppStackedRes.apps || []);
        setSelectedApp(null); // 데이터 새로고침 시 선택 초기화
      }
      
      if (trafficHostRes.success) {
        setTrafficByHost(trafficHostRes.data || []);
      }
      
      if (detectionsRes.success) {
        setRealtimeDetections(detectionsRes.data || []);
      }
      
    } catch (error) {
      console.error('Dashboard 데이터 로드 오류:', error);
    } finally {
      setLoading(false);
    }
  };

  // 날짜 포맷팅
  const formatDate = (dateString) => {
    if (!dateString) return '-';
    try {
      const date = new Date(dateString.replace(' ', 'T'));
      return date.toLocaleString('ko-KR', { 
        year: 'numeric', 
        month: '2-digit', 
        day: '2-digit', 
        hour: '2-digit', 
        minute: '2-digit' 
      });
    } catch (e) {
      return dateString;
    }
  };

  // DLP 탐지 태그 색상
  const getDetectionTagColor = (tag) => {
    const colors = {
      'PII': '#EF4444',
      'Secret Info': '#F59E0B',
      'Credential Info': '#DC2626',
      'Unknown Link': '#8B5CF6',
      'RBAC Violation': '#DC2626'
    };
    return colors[tag] || '#6B7280';
  };

  const maxUsers = topServersByUsers.length > 0 ? Math.max(...topServersByUsers.map(s => s.user_count || 0)) : 1;
  const maxDownloads = topDownloadServers.length > 0 ? Math.max(...topDownloadServers.map(s => s.download_count || 0)) : 1;

  return (
    <div className="dashboard-page">
      {/* 헤더 */}
      <div className="dashboard-header-section">
        <div className="dashboard-welcome">
          <h1>Dashboard</h1>
        </div>
      </div>

      {loading ? (
        <div className="loading-message">데이터를 불러오는 중...</div>
      ) : (
        <>
          {/* 1. 상단 KPI 4~6개 */}
          <div className="dashboard-stats-grid">
            <div className="stat-card primary">
              <div className="stat-content">
                <div className="stat-number">{kpiData?.registeredServers || 0}</div>
                <div className="stat-label">등록된 서버 수</div>
              </div>
            </div>
            <div className="stat-card secondary">
              <div className="stat-content">
                <div className="stat-number">{kpiData?.totalUsers || 0}</div>
                <div className="stat-label">사용자 수</div>
              </div>
            </div>
            <div className="stat-card tool-card">
              <div className="stat-content">
                <div className="stat-number">{kpiData?.inactiveUsers || 0}</div>
                <div className="stat-label">30일 비활성 사용자 수</div>
              </div>
            </div>
            <div className="stat-card tool-card">
              <div className="stat-content">
                <div className="stat-number">{kpiData?.totalScans || 0}</div>
                <div className="stat-label">전체 스캔 수</div>
              </div>
            </div>
            <div className="stat-card tool-card">
              <div className="stat-content">
                <div className="stat-number">{kpiData?.recentApprovedServers || 0}</div>
                <div className="stat-label">최근 승인된 서버 수 (7일)</div>
              </div>
            </div>
            <div className="stat-card tool-card">
              <div className="stat-content">
                <div className="stat-number">{kpiData?.recentDetections || 0}</div>
                <div className="stat-label">실시간 탐지 건수 (5분)</div>
              </div>
            </div>
          </div>

          {/* 2. 중단 카드 & 차트 */}
            <div className="dashboard-content-grid">
            {/* 서버별 사용자 수 Top 10 (가로 막대) */}
            <div className="content-card">
              <h3>서버별 사용자 수 Top 10</h3>
              <div className="chart-container">
                {topServersByUsers.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart 
                      data={[...topServersByUsers].reverse()} 
                      layout="vertical"
                      margin={{ top: 5, right: 10, left: 100, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                      <XAxis 
                        type="number"
                        stroke="#666"
                        tick={{ fontSize: '0.75rem', fill: '#666' }}
                        />
                      <YAxis 
                        type="category"
                        dataKey="server_name"
                        stroke="#666"
                        tick={{ fontSize: '0.75rem', fill: '#666' }}
                        width={90}
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#fff', 
                          border: '1px solid #e0e0e0',
                          borderRadius: '8px',
                          padding: '12px'
                        }}
                      />
                      <Bar dataKey="user_count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="no-data">데이터가 없습니다</div>
                )}
                </div>
              </div>

            {/* 가장 오래된 스캔 일시 보유 서버 Top 10 (테이블) */}
              <div className="content-card">
              <h3>가장 오래된 스캔 일시 보유 서버 Top 10</h3>
              <div className="table-container">
                {oldestScanServers.length > 0 ? (
                  <table className="dashboard-table">
                    <thead>
                      <tr>
                        <th>서버 이름</th>
                        <th>가장 오래된 스캔 일시</th>
                      </tr>
                    </thead>
                    <tbody>
                      {oldestScanServers.map((server, index) => (
                        <tr key={index}>
                          <td>{server.server_name || '-'}</td>
                          <td>{formatDate(server.oldest_scan_timestamp)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="no-data">데이터가 없습니다</div>
                )}
              </div>
            </div>
          </div>

          <div className="dashboard-content-grid">
            {/* 다운로드가 많이 된 서버 Top 10 (가로 막대) */}
            <div className="content-card">
              <h3>다운로드가 많이 된 서버 Top 10</h3>
              <div className="chart-container">
                {topDownloadServers.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart 
                      data={[...topDownloadServers].reverse()} 
                      layout="vertical"
                      margin={{ top: 5, right: 10, left: 100, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                      <XAxis 
                        type="number"
                        stroke="#666"
                        tick={{ fontSize: '0.75rem', fill: '#666' }}
                      />
                      <YAxis 
                        type="category"
                        dataKey="server_name"
                        stroke="#666"
                        tick={{ fontSize: '0.75rem', fill: '#666' }}
                        width={90}
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#fff', 
                          border: '1px solid #e0e0e0',
                          borderRadius: '8px',
                          padding: '12px'
                          }}
                        />
                      <Bar dataKey="download_count" fill="#10b981" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="no-data">데이터가 없습니다</div>
                )}
              </div>
            </div>

            {/* 최근 탐지된 DLP Top 10 (테이블) */}
              <div className="content-card">
              <h3>최근 탐지된 DLP Top 10</h3>
              <div className="table-container">
                {recentDlpDetections.length > 0 ? (
                  <table className="dashboard-table">
                    <thead>
                      <tr>
                        <th>시간</th>
                        <th>사용자</th>
                        <th>위반 유형</th>
                        <th>심각도</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentDlpDetections.map((dlp, index) => (
                        <tr key={index}>
                          <td>{formatDate(dlp.timestamp)}</td>
                          <td>{dlp.username || dlp.employee_id || '-'}</td>
                          <td>{dlp.violation_type || '-'}</td>
                          <td>
                            <span className={`severity-badge severity-${dlp.severity?.toLowerCase() || 'medium'}`}>
                              {dlp.severity || '-'}
                            </span>
                          </td>
                        </tr>
                  ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="no-data">데이터가 없습니다</div>
                )}
              </div>
            </div>
          </div>

          {/* 3. 트래픽 & 실시간 */}
          <div className="dashboard-content-grid">
            {/* 애플리케이션별 MCP 서버 트래픽(스택 영역) */}
            <div className="content-card stacked-chart-card">
              <h3>애플리케이션별 MCP 서버 트래픽 Top 5</h3>
              <div className="stacked-area-chart-container">
                {trafficByAppStacked.length > 0 && appNames.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart
                      data={trafficByAppStacked}
                      margin={{ top: 10, right: 30, left: 0, bottom: 20 }}
                    >
                      <defs>
                        {appNames.map((appName, index) => {
                          const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16'];
                          const color = colors[index % colors.length];
                          // 선택된 앱이 없으면 모두 불투명, 선택된 앱이 있으면 선택된 것만 불투명, 나머지는 완전히 투명
                          const gradientOpacity = selectedApp === null ? 1 : (selectedApp === appName ? 1 : 0);
                          return (
                            <linearGradient key={appName} id={`colorApp${index}`} x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor={color} stopOpacity={0.8 * gradientOpacity}/>
                              <stop offset="95%" stopColor={color} stopOpacity={0.15 * gradientOpacity}/>
                            </linearGradient>
                          );
                        })}
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                      <XAxis 
                        dataKey="time" 
                        stroke="#666"
                        tick={{ fontSize: '0.75rem', fill: '#666' }}
                        interval={Math.max(0, Math.floor((trafficByAppStacked.length - 1) / 6))}
                        angle={-45}
                        textAnchor="end"
                        height={60}
                      />
                      <YAxis 
                        stroke="#666"
                        tick={{ fontSize: '0.75rem', fill: '#666' }}
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#fff', 
                          border: '1px solid #e0e0e0',
                          borderRadius: '8px',
                          padding: '12px'
                        }}
                      />
                      <Legend 
                        onClick={(e) => {
                          const clickedApp = e.dataKey;
                          // 같은 앱을 다시 클릭하면 선택 해제, 다른 앱을 클릭하면 선택
                          setSelectedApp(selectedApp === clickedApp ? null : clickedApp);
                        }}
                        wrapperStyle={{ cursor: 'pointer' }}
                      />
                      {(() => {
                        // 선택된 앱이 있으면 선택된 앱을 맨 마지막에 렌더링하여 제일 위에 표시
                        const sortedAppNames = selectedApp && appNames.includes(selectedApp)
                          ? [...appNames.filter(name => name !== selectedApp), selectedApp]
                          : [...appNames];
                        
                        // 선택된 앱이 하나만 보일 때는 스택을 사용하지 않음 (그래프 빵꾸 방지)
                        // selectedApp이 null이 아니면 하나만 보이므로 스택 사용 안 함
                        const useStack = selectedApp === null;
                        
                        return sortedAppNames.map((appName, sortedIndex) => {
                          const originalIndex = appNames.indexOf(appName);
                          const colors = ['#2563eb', '#059669', '#d97706', '#dc2626', '#7c3aed', '#db2777', '#0891b2', '#65a30d'];
                          const color = colors[originalIndex % colors.length];
                          // 선택된 앱이 없으면 모두 불투명, 선택된 앱이 있으면 선택된 것만 불투명, 나머지는 완전히 투명
                          const opacity = selectedApp === null ? 1 : (selectedApp === appName ? 1 : 0);
                        return (
                            <Area 
                              key={appName}
                              type="monotone" 
                              dataKey={appName} 
                              stackId={useStack ? "1" : undefined}
                              stroke={color} 
                              strokeWidth={1.5}
                              strokeOpacity={opacity}
                              fillOpacity={opacity} 
                              fill={`url(#colorApp${originalIndex})`}
                              name={appName}
                              style={{ cursor: 'pointer' }}
                            />
                          );
                        });
                      })()}
                    </AreaChart>
                  </ResponsiveContainer>
              ) : (
                  <div className="no-data">데이터가 없습니다</div>
              )}
            </div>
          </div>

            {/* 호스트별 트래픽(막대/도넛) */}
            <div className="content-card stacked-chart-card">
              <h3>호스트별 트래픽</h3>
              <div className="chart-container">
                {trafficByHost.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={trafficByHost.slice(0, 10)}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                      <XAxis 
                        dataKey="host" 
                        stroke="#666"
                        tick={{ fontSize: '0.75rem', fill: '#666' }}
                        angle={-45}
                        textAnchor="end"
                        height={80}
                      />
                      <YAxis 
                        stroke="#666"
                        tick={{ fontSize: '0.75rem', fill: '#666' }}
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#fff', 
                          border: '1px solid #e0e0e0',
                          borderRadius: '8px',
                          padding: '12px'
                          }}
                        />
                      <Bar dataKey="usage_count" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="no-data">데이터가 없습니다</div>
                )}
              </div>
            </div>
          </div>

          {/* 실시간 탐지 결과(스트림 리스트) */}
          <div className="content-card detection-results">
            <h3>실시간 탐지 결과</h3>
            <div className="detection-table-container">
              <table className="detection-table">
                <thead>
                  <tr>
                    <th>시간</th>
                    <th>사용자</th>
                    <th>MCP 서버</th>
                    <th>도구</th>
                    <th>방향</th>
                    <th>요청/응답</th>
                    <th>탐지 태그</th>
                    <th>심각도</th>
                  </tr>
                </thead>
                <tbody>
                  {realtimeDetections.length > 0 ? (
                    realtimeDetections.map((detection, index) => (
                      <tr key={index}>
                        <td>{formatDate(detection.timestamp)}</td>
                        <td>
                          <div className="user-info">
                            <div>{detection.username || detection.employee_id || 'Unknown'}</div>
                            {detection.team && <div className="user-team">{detection.team}</div>}
                          </div>
                        </td>
                        <td>{detection.mcp_server_name || '-'}</td>
                        <td>{detection.tool_name || '-'}</td>
                        <td>
                          <span className={`direction-badge direction-${detection.direction || 'in'}`}>
                            {detection.direction || '-'}
                          </span>
                        </td>
                        <td>
                          <div className="request-response">
                            {detection.request_content && (
                              <div className="content-item">
                                <strong>Request:</strong> 
                                <div className="content-text">{detection.request_content.substring(0, 100)}...</div>
                              </div>
                            )}
                            {detection.response_content && (
                              <div className="content-item">
                                <strong>Response:</strong> 
                                <div className="content-text">{detection.response_content.substring(0, 100)}...</div>
                              </div>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="detection-tags">
                            {detection.detection_tags && detection.detection_tags.map((tag, tagIndex) => (
                              <span
                                key={tagIndex}
                                className="detection-tag"
                                style={{ backgroundColor: getDetectionTagColor(tag) }}
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <span className={`severity-badge severity-${detection.severity?.toLowerCase() || 'medium'}`}>
                            {detection.severity || '-'}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="8" style={{ textAlign: 'center', padding: '20px', color: '#666' }}>
                        탐지 결과가 없습니다
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;

import React, { useState, useEffect } from 'react';
import MCPRegistryDetail from './MCPRegistryDetail';
import { apiGet } from '../../utils/api';
import './MCPRegistry.css';

const MCPRegistry = () => {
  const [mcpServers, setMcpServers] = useState([]);
  const [loading, setLoading] = useState(true);
  
  // marketplace 총 서버 개수 (승인된 서버만 카운트)
  const [totalServers, setTotalServers] = useState(0); // 검색 전 전체 서버 개수 (승인된 서버만)
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('newest');
  const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const [selectedServerId, setSelectedServerId] = useState(null);
  const [serverRiskData, setServerRiskData] = useState({}); // { serverId: { riskLevel, riskValue } }

  // MCP 서버 목록 가져오기
  useEffect(() => {
    fetchServers();
  }, [searchQuery, sortBy]);
  

  // 서버 목록이 로드되면 위험도 데이터도 함께 로드
  useEffect(() => {
    if (mcpServers.length > 0) {
      loadRiskData();
    }
  }, [mcpServers.length]);

  // 위험도 정렬이 선택되었을 때 위험도 데이터 로드
  useEffect(() => {
    if ((sortBy === 'risk-low' || sortBy === 'risk-high') && mcpServers.length > 0) {
      loadRiskData();
    }
  }, [sortBy]);

  // 위험도 데이터가 로드되면 정렬 다시 적용
  useEffect(() => {
    if ((sortBy === 'risk-low' || sortBy === 'risk-high') && Object.keys(serverRiskData).length > 0 && mcpServers.length > 0) {
      let sortedServers = [...mcpServers];
      sortedServers = sortedServers.sort((a, b) => {
        const aRisk = serverRiskData[a.id];
        const bRisk = serverRiskData[b.id];
        
        // 위험도 값 추출
        const getRiskValue = (riskData) => {
          if (!riskData || !riskData.riskDisplayText) return 999; // 위험도 없으면 맨 뒤로
          const match = riskData.riskDisplayText.match(/\(([\d.]+)\)/);
          return match ? parseFloat(match[1]) : 999;
        };
        
        // 위험도 레벨 우선순위
        const getRiskLevelPriority = (riskData) => {
          if (!riskData || !riskData.riskLevel) return 999;
          const levelMap = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
          return levelMap[riskData.riskLevel] || 999;
        };
        
        const aLevelPriority = getRiskLevelPriority(aRisk);
        const bLevelPriority = getRiskLevelPriority(bRisk);
        
        // 먼저 레벨로 정렬
        if (aLevelPriority !== bLevelPriority) {
          if (sortBy === 'risk-high') {
            return bLevelPriority - aLevelPriority; // 높은 위험도부터
          } else {
            return aLevelPriority - bLevelPriority; // 낮은 위험도부터
          }
        }
        
        // 레벨이 같으면 숫자 값으로 정렬
        const aRiskValue = getRiskValue(aRisk);
        const bRiskValue = getRiskValue(bRisk);
        
        if (sortBy === 'risk-high') {
          return bRiskValue - aRiskValue; // 높은 위험도부터
        } else {
          return aRiskValue - bRiskValue; // 낮은 위험도부터
        }
      });
      
      setMcpServers(sortedServers);
    }
  }, [serverRiskData, sortBy]);

  const fetchServers = async () => {
    try {
      setLoading(true);
      
      const savedUser = localStorage.getItem('user');
      let userTeam = null;
      let isAdmin = false;
      
      if (savedUser) {
        const user = JSON.parse(savedUser);
        userTeam = user.team || null;
        // admin 체크
        const userRoles = user.roles || [];
        isAdmin = Array.isArray(userRoles) 
          ? userRoles.includes('admin') 
          : userRoles === 'admin' || user.role === 'admin';
      }
      
      const queryParams = new URLSearchParams();
      // admin이 아니면 팀 필터 적용
      if (userTeam && !isAdmin) {
        queryParams.append('team', userTeam);
      }
      queryParams.append('status', 'approved'); // MCP Registry는 승인된 서버만 표시
      // 클라이언트 측에서 검색 필터링 및 페이징을 처리하기 위해 모든 데이터를 가져옴
      queryParams.append('limit', '10000');
      
      const data = await apiGet(`/marketplace?${queryParams}`);
      console.log('서버 목록 응답:', data);
      
      if (data.success) {
        let servers = data.data || [];
        console.log('서버 목록:', servers);

        // API 응답에서 실제 승인된 서버 개수 가져오기
        const approvedCount = data.pagination?.total || 0;
        setTotalServers(approvedCount);
        
        // 검색 필터링
        if (searchQuery) {
          servers = servers.filter(server => 
            server.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            (server.short_description && server.short_description.toLowerCase().includes(searchQuery.toLowerCase()))
          );
        }

        // 정렬
        if (sortBy === 'newest') {
          servers = [...servers].reverse();
        } else if (sortBy === 'oldest') {
          // 이미 정렬된 상태
        } else if (sortBy === 'a-z') {
          servers = [...servers].sort((a, b) => a.name.localeCompare(b.name));
        } else if (sortBy === 'z-a') {
          servers = [...servers].sort((a, b) => b.name.localeCompare(a.name));
        } else if (sortBy === 'risk-low' || sortBy === 'risk-high') {
          // 위험도 정렬은 위험도 데이터가 있을 때만 적용
          if (Object.keys(serverRiskData).length > 0) {
            servers = [...servers].sort((a, b) => {
              const aRisk = serverRiskData[a.id];
              const bRisk = serverRiskData[b.id];
              
              // 위험도 값 추출
              const getRiskValue = (riskData) => {
                if (!riskData || !riskData.riskDisplayText) return 999; // 위험도 없으면 맨 뒤로
                const match = riskData.riskDisplayText.match(/\(([\d.]+)\)/);
                return match ? parseFloat(match[1]) : 999;
              };
              
              // 위험도 레벨 우선순위
              const getRiskLevelPriority = (riskData) => {
                if (!riskData || !riskData.riskLevel) return 999;
                const levelMap = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
                return levelMap[riskData.riskLevel] || 999;
              };
              
              const aLevelPriority = getRiskLevelPriority(aRisk);
              const bLevelPriority = getRiskLevelPriority(bRisk);
              
              // 먼저 레벨로 정렬
              if (aLevelPriority !== bLevelPriority) {
                if (sortBy === 'risk-high') {
                  return bLevelPriority - aLevelPriority; // 높은 위험도부터
                } else {
                  return aLevelPriority - bLevelPriority; // 낮은 위험도부터
                }
              }
              
              // 레벨이 같으면 숫자 값으로 정렬
              const aRiskValue = getRiskValue(aRisk);
              const bRiskValue = getRiskValue(bRisk);
              
              if (sortBy === 'risk-high') {
                return bRiskValue - aRiskValue; // 높은 위험도부터
              } else {
                return aRiskValue - bRiskValue; // 낮은 위험도부터
              }
            });
          }
        }
        
        setMcpServers(servers);
      } else {
        setMcpServers([]);
        setTotalServers(0);
      }
      
    } catch (error) {
      console.error('서버 목록 로드 실패:', error);
    } finally {
      setLoading(false);
    }
  };

  // 위험도 데이터 로드
  const loadRiskData = async () => {
    if (mcpServers.length === 0) return;
    
    const token = localStorage.getItem('token');
    const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001/api';
    const riskDataMap = {};
    
    // 각 서버에 대해 위험도 정보 가져오기
    await Promise.all(mcpServers.map(async (server) => {
      try {
        const scanPath = server.github_link || server.file_path;
        if (!scanPath) return;
        
        const serverNameParam = server.name ? `&mcp_server_name=${encodeURIComponent(server.name)}` : '';
        
        // OSS 취약점 데이터 가져오기
        let ossIssues = [];
        try {
          const ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          const ossData = await ossRes.json();
          if (ossData.success && ossData.data) {
            ossIssues = ossData.data;
          }
        } catch (error) {
          console.error(`[${server.name}] OSS 데이터 로드 실패:`, error);
        }
        
        // Code 취약점 데이터 가져오기
        let codeIssues = [];
        try {
          const codeRes = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          const codeData = await codeRes.json();
          if (codeData.success && codeData.data) {
            codeIssues = codeData.data;
          }
        } catch (error) {
          console.error(`[${server.name}] Code 데이터 로드 실패:`, error);
        }
        
        // Tool Validation 통계 가져오기
        let toolValidationStats = null;
        try {
          const toolRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          const toolData = await toolRes.json();
          if (toolData.success && toolData.data) {
            const categoryCounts = {};
            toolData.data.forEach(vuln => {
              const cat = vuln.category_code || vuln.category_name || 'Unknown';
              categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
            });
            toolValidationStats = {
              categoryCounts: Object.entries(categoryCounts).map(([name, value]) => ({ name, value }))
            };
          }
        } catch (error) {
          console.error(`[${server.name}] Tool Validation 데이터 로드 실패:`, error);
        }
        
        // 위험도 계산
        const riskResult = calculateTotalRisk(ossIssues, codeIssues, toolValidationStats);
        
        riskDataMap[server.id] = {
          riskLevel: riskResult.riskLevel,
          riskDisplayText: riskResult.riskDisplayText,
          riskValue: riskResult.totalRisk
        };
      } catch (error) {
        console.error(`[${server.name}] 위험도 계산 실패:`, error);
        riskDataMap[server.id] = {
          riskLevel: null,
          riskDisplayText: '-',
          riskValue: 0
        };
      }
    }));
    
    setServerRiskData(riskDataMap);
  };

  // 위험도 계산 함수
  const calculateTotalRisk = (ossIssues, codeIssues, toolValidationStats) => {
    // SCA 위험도 계산
    const ReachableWeight = 0.5;
    let maxScaRisk = 0;
    if (ossIssues && ossIssues.length > 0) {
      ossIssues.forEach(issue => {
        const cvss = issue.vulnerability?.cvss || issue.cvss || 0;
        const reachable = (issue.reachable === 1 || issue.reachable === true || issue.reachable === '1' || 
                          issue.reachable === 'Reachable' || 
                          (issue.functions && Array.isArray(issue.functions) && issue.functions.some(f => f.reachable === true))) ? 1 : 0;
        const scaRiskValue = cvss * (1 + ReachableWeight * reachable);
        maxScaRisk = Math.max(maxScaRisk, scaRiskValue);
      });
    }
    
    // SAST 위험도 계산
    const severityWeights = {
      'info': 1, 'low': 2, 'medium': 4, 'high': 7, 'critical': 10
    };
    const confidenceValues = {
      'info': 0.1, 'low': 0.3, 'medium': 0.6, 'high': 0.9, 'critical': 1.0
    };
    let maxSastRisk = 0;
    if (codeIssues && codeIssues.length > 0) {
      codeIssues.forEach(issue => {
        const severity = (issue.severity || 'unknown').toLowerCase();
        const severityWeight = severityWeights[severity] || 1;
        let confidence = issue.confidence;
        if (confidence === null || confidence === undefined) {
          confidence = confidenceValues[severity] || 0.6;
        } else if (typeof confidence === 'string') {
          confidence = confidenceValues[confidence.toLowerCase()] || parseFloat(confidence) || 0.6;
        } else {
          confidence = Math.max(0.1, Math.min(1.0, confidence));
        }
        const sastRiskValue = Math.max(0.1, Math.min(10, severityWeight * confidence));
        maxSastRisk = Math.max(maxSastRisk, sastRiskValue);
      });
    }
    
    // Tool_Risk 계산
    let toolRisk = 0;
    if (toolValidationStats && toolValidationStats.categoryCounts && toolValidationStats.categoryCounts.length > 0) {
      const categoryMap = {};
      toolValidationStats.categoryCounts.forEach(cat => {
        categoryMap[cat.name] = cat.value > 0 ? 1 : 0;
      });
      const T1 = categoryMap['MCP-01'] || 0;
      const T2 = categoryMap['MCP-02'] || 0;
      const T3 = categoryMap['MCP-03'] || 0;
      const T4 = categoryMap['MCP-04'] || 0;
      toolRisk = (T1 * 0.2) + (T2 * 0.3) + (T3 * 0.3) + (T4 * 0.2);
    }
    const toolRiskScaled = toolRisk * 10;
    
    // Total_Risk 계산
    const SCA_Weight = 0.6;
    const SAST_Weight = 0.2;
    const Tool_Weight = 0.2;
    const totalRisk = (maxScaRisk * SCA_Weight) + (maxSastRisk * SAST_Weight) + (toolRiskScaled * Tool_Weight);
    
    // 위험도 레벨 결정
    let riskLevel = null;
    let riskDisplayText = '';
    if (totalRisk >= 9.0) {
      riskLevel = 'CRITICAL';
      riskDisplayText = `Critical(${Math.round(totalRisk * 10) / 10})`;
    } else if (totalRisk >= 7.0) {
      riskLevel = 'HIGH';
      riskDisplayText = `HIGH(${Math.round(totalRisk * 10) / 10})`;
    } else if (totalRisk >= 4.0) {
      riskLevel = 'MEDIUM';
      riskDisplayText = `MEDIUM(${Math.round(totalRisk * 10) / 10})`;
    } else if (totalRisk >= 0.1) {
      riskLevel = 'LOW';
      riskDisplayText = `LOW(${Math.round(totalRisk * 10) / 10})`;
    }
    
    return { totalRisk, riskLevel, riskDisplayText };
  };

  // 카테고리 추출 (임시로 description 기반)
  const getCategory = (server) => {
    const desc = (server.short_description || server.description || '').toLowerCase();
    if (desc.includes('database') || desc.includes('postgres') || desc.includes('mysql')) {
      return 'DATABASE';
    } else if (desc.includes('slack') || desc.includes('communication') || desc.includes('chat')) {
      return 'COMMUNICATION';
    } else if (desc.includes('github') || desc.includes('git') || desc.includes('repository')) {
      return 'CODE REPOSITORY';
    } else if (desc.includes('devops') || desc.includes('deploy') || desc.includes('docker')) {
      return 'DEVOPS';
    }
    return 'DEVOPS';
  };

  // Provider 추출 (임시로 name 기반)
  const getProvider = (server) => {
    // 실제로는 서버 데이터에 provider 필드가 있어야 함
    return 'modelcontextprotocol';
  };

  if (loading) {
    return (
      <section className="mcp-registry-section">
        <h1>MCP Registry</h1>
        <p>로딩 중...</p>
      </section>
    );
  }

  return (
    <section className="mcp-registry-section">
      <h1>MCP Registry</h1>
      {/* 검색 및 필터 섹션 */}
      <div className="mcp-registry-controls">
        <div className="search-container" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
          <svg className="search-icon" width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M7 12C9.76142 12 12 9.76142 12 7C12 4.23858 9.76142 2 7 2C4.23858 2 2 4.23858 2 7C2 9.76142 4.23858 12 7 12Z" stroke="currentColor" strokeWidth="1.5"/>
            <path d="M10 10L14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          <input
            type="text"
            className="search-input"
            placeholder="Search Servers"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          </div>
          <span style={{ color: '#666', fontSize: '0.9rem', whiteSpace: 'nowrap' }}>
            총 {totalServers}개
          </span>
        </div>

        <div className="controls-right">
          <div className="view-toggle">
            <button
              className={`view-btn ${viewMode === 'list' ? 'active' : ''}`}
              onClick={() => setViewMode('list')}
              title="List view"
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <rect x="2" y="3" width="12" height="1.5" fill="currentColor"/>
                <rect x="2" y="7.25" width="12" height="1.5" fill="currentColor"/>
                <rect x="2" y="11.5" width="12" height="1.5" fill="currentColor"/>
              </svg>
            </button>
            <button
              className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`}
              onClick={() => setViewMode('grid')}
              title="Grid view"
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <rect x="2" y="2" width="5" height="5" fill="currentColor"/>
                <rect x="9" y="2" width="5" height="5" fill="currentColor"/>
                <rect x="2" y="9" width="5" height="5" fill="currentColor"/>
                <rect x="9" y="9" width="5" height="5" fill="currentColor"/>
              </svg>
            </button>
          </div>

          <div className="sort-dropdown">
            <button 
              className="sort-button" 
              onClick={(e) => {
                e.stopPropagation();
                setSortMenuOpen(!sortMenuOpen);
              }}
            >
              Sorting
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
            {sortMenuOpen && (
              <>
                <div 
                  className="sort-menu-overlay"
                  onClick={() => setSortMenuOpen(false)}
                />
                <div className={`sort-menu ${sortMenuOpen ? 'open' : ''}`}>
                  <div className="sort-menu-header">Sorting</div>
                  <button 
                    className={`sort-option ${sortBy === 'newest' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('newest');
                      setSortMenuOpen(false);
                    }}
                  >
                    Newest first
                  </button>
                  <button 
                    className={`sort-option ${sortBy === 'oldest' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('oldest');
                      setSortMenuOpen(false);
                    }}
                  >
                    Oldest first
                  </button>
                  <button 
                    className={`sort-option ${sortBy === 'a-z' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('a-z');
                      setSortMenuOpen(false);
                    }}
                  >
                    A to Z
                  </button>
                  <button 
                    className={`sort-option ${sortBy === 'z-a' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('z-a');
                      setSortMenuOpen(false);
                    }}
                  >
                    Z to A
                  </button>
                  <button 
                    className={`sort-option ${sortBy === 'risk-low' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('risk-low');
                      setSortMenuOpen(false);
                    }}
                  >
                    Risk: Low to High
                  </button>
                  <button 
                    className={`sort-option ${sortBy === 'risk-high' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('risk-high');
                      setSortMenuOpen(false);
                    }}
                  >
                    Risk: High to Low
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* 서버 카드 그리드 또는 표 */}
      {viewMode === 'list' ? (
        <div className="mcp-table-container">
          <table className="mcp-table">
            <thead>
              <tr>
                <th>서버 이름</th>
                <th>설명</th>
                <th>작업</th>
              </tr>
            </thead>
            <tbody>
              {mcpServers.length === 0 ? (
                <tr>
                  <td colSpan="3" style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                    데이터가 없습니다.
                  </td>
                </tr>
              ) : (
                mcpServers.map((server) => (
                  <tr
                    key={server.id}
                    className={selectedServerId === server.id ? 'selected' : ''}
                    onClick={() => setSelectedServerId(server.id)}
                  >
                    <td className="server-name-cell">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span>{server.name}</span>
                        {serverRiskData[server.id]?.riskLevel && (
                          <span style={{
                            display: 'inline-block',
                            padding: '4px 12px',
                            borderRadius: '6px',
                            fontSize: '0.75rem',
                            fontWeight: '700',
                            color: '#ffffff',
                            backgroundColor: 
                              serverRiskData[server.id].riskLevel === 'CRITICAL' || serverRiskData[server.id].riskLevel === 'HIGH' ? '#dc2626' :
                              serverRiskData[server.id].riskLevel === 'MEDIUM' ? '#f97316' :
                              serverRiskData[server.id].riskLevel === 'LOW' ? '#fbbf24' : '#6b7280',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px'
                          }}>
                            {serverRiskData[server.id].riskLevel}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="server-description-cell">
                      {server.short_description || server.description || 'No description available.'}
                    </td>
                    <td>
                      <button 
                        className="table-view-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedServerId(server.id);
                        }}
                      >
                        상세보기
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="mcp-grid">
        {mcpServers.map((server) => (
          <div
            className="mcp-card"
            key={server.id}
            onClick={() => setSelectedServerId(server.id)}
          >
            <div className="card-top-row">
              <div className="card-icon">
                <div className="icon-placeholder">
                  {server.name.charAt(0).toUpperCase()}
                </div>
              </div>
              <div className="card-header" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '8px' }}>
                <button 
                  className="card-add-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedServerId(server.id);
                  }}
                  title="View details"
                  style={{ flexShrink: 0 }}
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M21 15V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V15" stroke="#003153" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M7 10L12 15L17 10" stroke="#003153" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M12 15V3" stroke="#003153" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </button>
                {serverRiskData[server.id]?.riskLevel && (
                  <span style={{
                    display: 'inline-block',
                    padding: '4px 12px',
                    borderRadius: '6px',
                    fontSize: '0.75rem',
                    fontWeight: '700',
                    color: '#ffffff',
                    backgroundColor: 
                      serverRiskData[server.id].riskLevel === 'CRITICAL' || serverRiskData[server.id].riskLevel === 'HIGH' ? '#dc2626' :
                      serverRiskData[server.id].riskLevel === 'MEDIUM' ? '#f97316' :
                      serverRiskData[server.id].riskLevel === 'LOW' ? '#fbbf24' : '#6b7280',
                    textTransform: 'uppercase',
                    letterSpacing: '0.5px',
                    whiteSpace: 'nowrap',
                    flexShrink: 0
                  }}>
                    {serverRiskData[server.id].riskLevel}
                  </span>
                )}
              </div>
            </div>

            <div className="card-content">
              <h2 className="card-title">{server.name}</h2>
              <p className="card-description">
                {server.short_description || server.description || 'No description available.'}
              </p>
            </div>
          </div>
        ))}
      </div>
      )}

      {/* 상세 페이지 모달 */}
      {selectedServerId && (
        <MCPRegistryDetail
          serverId={selectedServerId}
          onClose={() => setSelectedServerId(null)}
        />
      )}
    </section>
  );
};

export default MCPRegistry;
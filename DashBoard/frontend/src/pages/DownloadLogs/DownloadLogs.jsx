import React, { useState, useEffect, useCallback, useRef } from 'react';
import { API_BASE_URL } from '../../utils/api';
import './DownloadLogs.css';

const DownloadLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTeam, setSelectedTeam] = useState('all');
  const [teams, setTeams] = useState([]);
  const [teamMenuOpen, setTeamMenuOpen] = useState(false);
  const [sortColumn, setSortColumn] = useState(null);
  const [sortDirection, setSortDirection] = useState(null);
  const [isRotating, setIsRotating] = useState(false);
  const searchTimeoutRef = useRef(null);
  const isInitialLoad = useRef(true);

  const fetchLogs = useCallback(async (query, team = 'all') => {
    try {
      setLoading(true);
      
      const queryParams = new URLSearchParams();
      if (query) {
        queryParams.append('query', query);
      }
      if (team && team !== 'all') {
        queryParams.append('team', team);
      }
      queryParams.append('limit', '10000');
      
      const res = await fetch(`${API_BASE_URL}/file/download-logs?${queryParams}`);
      const data = await res.json();
      
      if (data.success) {
        const fetchedLogs = data.data || [];
        setLogs(fetchedLogs);
      } else {
        setLogs([]);
      }
      
    } catch (error) {
      console.error('다운로드 로그 조회 실패:', error);
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // 팀 목록 가져오기
  useEffect(() => {
    const fetchTeams = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await fetch('http://localhost:3001/api/users/teams', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        
        if (!res.ok) {
          throw new Error(`HTTP error! status: ${res.status}`);
        }
        
        const data = await res.json();
        if (data.success) {
          setTeams(data.data || []);
        } else {
          console.error('팀 목록 조회 실패:', data.message);
          setTeams([]);
        }
      } catch (error) {
        console.error('팀 목록 로드 실패:', error);
        setTeams([]);
      }
    };
    
    fetchTeams();
  }, []);

  // 초기 로드
  useEffect(() => {
    if (isInitialLoad.current) {
      isInitialLoad.current = false;
      fetchLogs('', selectedTeam);
    }
  }, [fetchLogs, selectedTeam]);

  // 검색어 변경 시 디바운싱 적용
  useEffect(() => {
    // 초기 로드는 무시
    if (isInitialLoad.current) {
      return;
    }

    // 기존 타이머 취소
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }

    // 디바운싱: 300ms 후 API 호출
    searchTimeoutRef.current = setTimeout(() => {
      fetchLogs(searchQuery, selectedTeam);
    }, 300);

    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current);
      }
    };
  }, [searchQuery, selectedTeam, fetchLogs]);

  // 팀 필터 변경 시
  useEffect(() => {
    if (isInitialLoad.current) {
      return;
    }
    fetchLogs(searchQuery, selectedTeam);
  }, [selectedTeam, searchQuery, fetchLogs]);

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    // SQLite datetime 문자열을 직접 파싱 (시간대 변환 없이)
    // 형식: 'YYYY-MM-DD HH:MM:SS'
    const match = dateString.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
    if (match) {
      const [, year, month, day, hours, minutes, seconds] = match;
      return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }
    // 파싱 실패 시 원본 반환
    return dateString;
  };

  const handleSort = (column) => {
    if (sortColumn === column) {
      if (sortDirection === 'desc') {
        setSortDirection('asc');
      } else if (sortDirection === 'asc') {
        // 정렬 해제
        setSortColumn(null);
        setSortDirection(null);
      }
    } else {
      setSortColumn(column);
      setSortDirection('desc');
    }
  };

  const sortedLogs = sortColumn && sortDirection ? [...logs].sort((a, b) => {
    let aValue = a[sortColumn];
    let bValue = b[sortColumn];

    // 날짜/시간 정렬
    if (sortColumn === 'downloaded_at') {
      if (!aValue && !bValue) return 0;
      if (!aValue) return 1;
      if (!bValue) return -1;
      
      // Date 객체로 변환하여 비교
      const dateA = new Date(aValue.replace(' ', 'T'));
      const dateB = new Date(bValue.replace(' ', 'T'));
      
      if (sortDirection === 'desc') {
        // 내림차순: 최신이 위 (더 큰 값이 앞)
        return dateB - dateA;
      } else {
        // 오름차순: 오래된 것이 위 (더 작은 값이 앞)
        return dateA - dateB;
      }
    }

    // 문자열 정렬
    aValue = (aValue || '').toString().toLowerCase();
    bValue = (bValue || '').toString().toLowerCase();
    
    if (sortDirection === 'asc') {
      return aValue.localeCompare(bValue);
    } else {
      return bValue.localeCompare(aValue);
    }
  }) : logs;

  const getSortIcon = (column) => {
    if (sortColumn !== column || !sortDirection) {
      return (
        <span className="sort-icon">
          <svg width="16" height="16" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M6 2L3 5H9L6 2Z" fill="#999"/>
            <path d="M6 10L9 7H3L6 10Z" fill="#999"/>
          </svg>
        </span>
      );
    }
    return (
      <span className="sort-icon active">
        {sortDirection === 'asc' ? (
          <svg width="16" height="16" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M6 2L3 5H9L6 2Z" fill="#666"/>
          </svg>
        ) : (
          <svg width="16" height="16" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M6 10L9 7H3L6 10Z" fill="#666"/>
          </svg>
        )}
      </span>
    );
  };

  return (
    <section className="download-logs">
      <h1>Download Logs</h1>

      <div className="download-logs-controls">
        <div className="search-and-filter-container">
          <div className="search-container">
            <svg className="search-icon" width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M7 12C9.76142 12 12 9.76142 12 7C12 4.23858 9.76142 2 7 2C4.23858 2 2 4.23858 2 7C2 9.76142 4.23858 12 7 12Z" stroke="currentColor" strokeWidth="1.5"/>
              <path d="M10 10L14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
            <input
              type="text"
              className="search-input"
              placeholder="사용자 이름, 사원번호, IP 주소 검색"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <div className="sort-dropdown">
            <button 
              className="sort-button" 
              onClick={(e) => {
                e.stopPropagation();
                setTeamMenuOpen(!teamMenuOpen);
              }}
            >
              {selectedTeam === 'all' ? '전체 팀' : selectedTeam}
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
            {teamMenuOpen && (
              <>
                <div 
                  className="sort-menu-overlay"
                  onClick={() => setTeamMenuOpen(false)}
                />
                <div className={`sort-menu ${teamMenuOpen ? 'open' : ''}`}>
                  <div className="sort-menu-header">팀 필터</div>
                  <button 
                    className={`sort-option ${selectedTeam === 'all' ? 'selected' : ''}`}
                    onClick={() => {
                      setSelectedTeam('all');
                      setTeamMenuOpen(false);
                    }}
                  >
                    전체 팀
                  </button>
                  {teams.map(team => (
                    <button 
                      key={team}
                      className={`sort-option ${selectedTeam === team ? 'selected' : ''}`}
                      onClick={() => {
                        setSelectedTeam(team);
                        setTeamMenuOpen(false);
                      }}
                    >
                      {team}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
        <button 
          onClick={() => {
            setIsRotating(true);
            fetchLogs(searchQuery, selectedTeam);
          }} 
          className="btn-refresh" 
          title="새로고침"
          style={{
            background: 'transparent',
            backgroundColor: 'transparent',
            backgroundImage: 'none',
            border: 'none',
            outline: 'none',
            boxShadow: 'none'
          }}
          onMouseEnter={(e) => {
            e.target.style.background = 'transparent';
            e.target.style.backgroundColor = 'transparent';
            e.target.style.backgroundImage = 'none';
          }}
          onMouseLeave={(e) => {
            e.target.style.background = 'transparent';
            e.target.style.backgroundColor = 'transparent';
            e.target.style.backgroundImage = 'none';
          }}
        >
          <svg 
            className={`refresh-icon ${isRotating ? 'rotating' : ''}`}
            onAnimationEnd={() => setIsRotating(false)}
            width="20" 
            height="20" 
            viewBox="0 0 24 24" 
            fill="none" 
            xmlns="http://www.w3.org/2000/svg"
          >
            <path d="M1 4V10H7" stroke="#003153" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M23 20V14H17" stroke="#003153" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10M23 14L18.36 18.36A9 9 0 0 1 3.51 15" stroke="#003153" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>
      </div>

      <div className="logs-table-container">
        {loading && logs.length === 0 ? (
          <div className="empty-state">로딩 중...</div>
        ) : sortedLogs.length === 0 ? (
          <div className="empty-state">다운로드 로그가 없습니다.</div>
        ) : (
          <table className="logs-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => handleSort('downloaded_at')}>
                  다운로드 시간
                  {getSortIcon('downloaded_at')}
                </th>
                <th>사용자</th>
                <th>사원번호</th>
                <th>팀</th>
                <th>MCP 서버</th>
                <th>파일명</th>
                <th>IP 주소</th>
              </tr>
            </thead>
            <tbody>
              {sortedLogs.map((log) => (
                <tr key={log.id}>
                  <td>{formatDate(log.downloaded_at)}</td>
                  <td>{log.username || '-'}</td>
                  <td>{log.employee_id || '-'}</td>
                  <td>{log.team || '-'}</td>
                  <td>{log.mcp_server_name || '-'}</td>
                  <td className="file-name-cell">{log.file_name || log.file_path || '-'}</td>
                  <td>{log.ip_address || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
};

export default DownloadLogs;

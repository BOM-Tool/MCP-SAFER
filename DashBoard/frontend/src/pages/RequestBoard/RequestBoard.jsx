import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL } from '../../utils/api';
import './RequestBoard.css';

const RequestBoard = () => {
  const navigate = useNavigate();
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [filter, setFilter] = useState('all'); // all, pending, approved, rejected
  const [reviewForm, setReviewForm] = useState({ status: '', comment: '', server_description: '', allowed_teams: [], tools: [] });
  const [user, setUser] = useState(null);
  const [scannedTools, setScannedTools] = useState([]);
  const [scanningTools, setScanningTools] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [analyzingRisk, setAnalyzingRisk] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState({ bomtori: 0, scanner: 0, toolVet: 0 });
  const [riskAnalysisResult, setRiskAnalysisResult] = useState(null);
  // localStorage에서 저장된 결과 불러오기
  const [riskAnalysisResults, setRiskAnalysisResults] = useState(() => {
    try {
      const saved = localStorage.getItem('riskAnalysisResults');
      return saved ? JSON.parse(saved) : {};
    } catch (error) {
      console.error('localStorage에서 riskAnalysisResults 불러오기 실패:', error);
      return {};
    }
  }); // request id별로 결과 저장
  const [analysisCompleted, setAnalysisCompleted] = useState(false);
  const [analysisError, setAnalysisError] = useState(null);
  const [sortColumn, setSortColumn] = useState(null);
  const [sortDirection, setSortDirection] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [currentScanId, setCurrentScanId] = useState(null);
  const [teams, setTeams] = useState([]); // DB에서 가져온 팀 목록
  const [isRotating, setIsRotating] = useState(false);
  const [requestCounts, setRequestCounts] = useState({ all: 0, pending: 0, approved: 0, rejected: 0 }); // 각 탭별 요청 개수

  // 서버 이름 정규화 함수 (백엔드와 동일한 로직)
  const normalizeServerName = (githubUrl, fallbackName = null) => {
    let name = null;
    
    // GitHub URL에서 추출
    if (githubUrl && githubUrl.includes('github.com')) {
      const match = githubUrl.match(/github\.com\/[^\/]+\/([^\/]+)/);
      if (match && match[1]) {
        name = match[1].replace(/\.git$/, ''); // .git 제거
      }
    }
    
    // GitHub URL에서 추출 실패 시 fallback 사용
    if (!name && fallbackName) {
      name = fallbackName;
    }
    
    // 기본값
    if (!name || name.trim() === '') {
      name = 'finding';
    }
    
    // 숫자만 있는 경우 방지
    if (/^\d+$/.test(name)) {
      name = `mcp_server_${name}`;
    }
    
    // 소문자로 변환하고 공백을 하이픈으로 변환 (일관된 형식)
    name = name
      .toLowerCase()
      .replace(/\s+/g, '-')
      .replace(/[^a-z0-9_-]/g, '-')
      .replace(/-{2,}/g, '-')
      .replace(/^-+|-$/g, '');
    
    return name;
  };

  // selectedRequest가 변경될 때 저장된 결과 복원
  useEffect(() => {
    if (selectedRequest) {
      const savedResult = riskAnalysisResults[selectedRequest.id];
      if (savedResult) {
        console.log('useEffect - 저장된 결과 복원:', savedResult, 'for request:', selectedRequest.id);
        setRiskAnalysisResult(savedResult);
        setCurrentScanId(savedResult.scanId);
        setAnalysisCompleted(true);
        setAnalyzingRisk(false);
        setAnalysisProgress({ bomtori: 100, scanner: 100, toolVet: 100 });
        
        // 위험도 분석 완료 후 DB에서 tool 정보 불러오기 (폴링)
        const loadToolsFromDB = async (retryCount = 0) => {
          try {
            console.log(`[useEffect 폴링 ${retryCount}] DB에서 tool 정보 불러오기 시도:`, selectedRequest.name);
            const res = await fetch(`${API_BASE_URL}/marketplace/tools?server_name=${encodeURIComponent(selectedRequest.name)}`);
            const data = await res.json();
            console.log(`[useEffect 폴링 ${retryCount}] DB tool 정보 응답:`, data);
            if (data.success && data.data && data.data.length > 0) {
              const tools = data.data.map(tool => ({
                name: tool.name,
                allowed_teams: []
              }));
              setScannedTools(tools);
              setReviewForm(prev => ({ ...prev, tools: tools }));
              console.log(`[useEffect 폴링 ${retryCount}] DB에서 tool 정보 불러오기 완료:`, tools);
            } else {
              // tool 정보가 아직 없으면 3초 후 재시도 (최대 5회)
              if (retryCount < 5) {
                console.log(`[useEffect 폴링 ${retryCount}] DB에 tool 정보가 없음, 3초 후 재시도...`);
                setTimeout(() => {
                  loadToolsFromDB(retryCount + 1);
                }, 3000);
              } else {
                console.log(`[useEffect 폴링 ${retryCount}] 최대 재시도 횟수 도달, tool 정보 없음`);
              }
            }
          } catch (error) {
            console.error(`[useEffect 폴링 ${retryCount}] DB에서 tool 정보 불러오기 실패:`, error);
            // 오류 발생 시에도 재시도 (최대 5회)
            if (retryCount < 5) {
              setTimeout(() => {
                loadToolsFromDB(retryCount + 1);
              }, 3000);
            }
          }
        };
        loadToolsFromDB(0);
        
        // selectedRequest.scanned를 1로 업데이트 (결과가 있으므로)
        if (selectedRequest.scanned !== 1 && selectedRequest.scanned !== '1' && selectedRequest.scanned !== true) {
          setSelectedRequest(prev => prev ? { ...prev, scanned: 1 } : prev);
        }
      } else {
        // 저장된 결과가 없으면 이전 서버의 결과 초기화
        // 단, handleViewDetail에서 이미 초기화했을 수 있으므로 확인 필요
        // analysis_timestamp가 없으면 확실히 초기화
        const hasAnalysisTimestamp = selectedRequest.analysis_timestamp && selectedRequest.analysis_timestamp.trim() !== '';
        if (!hasAnalysisTimestamp) {
          console.log('useEffect - 저장된 결과 없음, 이전 결과 초기화:', selectedRequest.id);
          setRiskAnalysisResult(null);
          setCurrentScanId(null);
          setAnalysisCompleted(false);
          setAnalyzingRisk(false);
          setAnalysisProgress({ bomtori: 0, scanner: 0, toolVet: 0 });
        }
      }
    } else {
      // selectedRequest가 null이면 결과 초기화하지 않음 (다시 열 때 복원하기 위해)
    }
  }, [selectedRequest?.id]); // riskAnalysisResults는 dependency에 포함하지 않음 (무한 루프 방지)

  // riskAnalysisResults가 변경될 때마다 localStorage에 저장
  useEffect(() => {
    try {
      localStorage.setItem('riskAnalysisResults', JSON.stringify(riskAnalysisResults));
    } catch (error) {
      console.error('localStorage에 riskAnalysisResults 저장 실패:', error);
    }
  }, [riskAnalysisResults]);

  useEffect(() => {
    // 로그인한 사용자 정보 가져오기
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  // 팀 목록 가져오기
  useEffect(() => {
    const fetchTeams = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await fetch(`${API_BASE_URL}/users/teams`, {
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

  useEffect(() => {
    fetchRequests();
  }, [filter]);

  // 각 탭별 요청 개수 가져오기
  useEffect(() => {
    const fetchRequestCounts = async () => {
      try {
        const token = localStorage.getItem('token');
        const headers = {
          'Content-Type': 'application/json'
        };
        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }
        
        // 각 상태별로 요청 개수 가져오기
        const [allRes, pendingRes, approvedRes, rejectedRes] = await Promise.all([
          fetch(`${API_BASE_URL}/marketplace/requests?limit=10000`, {
            headers
          }),
          fetch(`${API_BASE_URL}/marketplace/requests?status=pending&limit=10000`, {
            headers
          }),
          fetch(`${API_BASE_URL}/marketplace/requests?status=approved&limit=10000`, {
            headers
          }),
          fetch(`${API_BASE_URL}/marketplace/requests?status=rejected&limit=10000`, {
            headers
          })
        ]);
        
        const [allData, pendingData, approvedData, rejectedData] = await Promise.all([
          allRes.json(),
          pendingRes.json(),
          approvedRes.json(),
          rejectedRes.json()
        ]);
        
        const allCount = (allData.success ? (allData.pagination?.total || 0) : 0);
        const pendingCount = (pendingData.success ? (pendingData.pagination?.total || 0) : 0);
        const approvedCount = (approvedData.success ? (approvedData.pagination?.total || 0) : 0);
        const rejectedCount = (rejectedData.success ? (rejectedData.pagination?.total || 0) : 0);
        
        setRequestCounts({
          all: allCount,
          pending: pendingCount,
          approved: approvedCount,
          rejected: rejectedCount
        });
      } catch (error) {
        console.error('요청 개수 조회 실패:', error);
      }
    };
    
    fetchRequestCounts();
  }, []);

  // ESC 키로 상세보기 닫기
  useEffect(() => {
    if (!selectedRequest) return;

    const handleEscape = (e) => {
      if (e.key === 'Escape') {
        handleCloseDetail();
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => {
      window.removeEventListener('keydown', handleEscape);
    };
  }, [selectedRequest]);

  const fetchRequests = async () => {
    try {
      setLoading(true);
      
      const queryParams = new URLSearchParams();
      if (filter !== 'all') {
        queryParams.append('status', filter);
      }
      queryParams.append('limit', '10000');
      
      // JWT 토큰 가져오기
      const token = localStorage.getItem('token');
      const headers = {
        'Content-Type': 'application/json'
      };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const res = await fetch(`${API_BASE_URL}/marketplace/requests?${queryParams}`, {
        headers
      });
      
      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }
      
      const data = await res.json();
      
      let updatedRequests = [];
      if (data.success) {
        updatedRequests = data.data || [];
        setRequests(updatedRequests);
        
        // 현재 필터에 맞는 개수 업데이트
        const filteredCount = updatedRequests.length || 0;
        setRequestCounts(prev => ({
          ...prev,
          [filter]: filteredCount
        }));
        
        // selectedRequest가 있으면 최신 정보로 업데이트
        if (selectedRequest) {
          const latestRequest = updatedRequests.find(r => r.id === selectedRequest.id);
          if (latestRequest) {
            setSelectedRequest(latestRequest);
          }
        }
      } else {
        setRequests([]);
      }
      
      return updatedRequests;
    } catch (error) {
      console.error('등록 요청 목록 로드 실패:', error);
      setRequests([]);
      return [];
    } finally {
      setLoading(false);
    }
  };

  // 로딩 상태 없이 요청 목록만 가져오는 함수 (상세보기에서 사용)
  const fetchRequestsWithoutLoading = async () => {
    try {
      const queryParams = new URLSearchParams();
      if (filter !== 'all') {
        queryParams.append('status', filter);
      }
      queryParams.append('limit', '10000');
      
      // JWT 토큰 가져오기
      const token = localStorage.getItem('token');
      const headers = {
        'Content-Type': 'application/json'
      };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const res = await fetch(`${API_BASE_URL}/marketplace/requests?${queryParams}`, {
        headers
      });
      const data = await res.json();
      
      let updatedRequests = [];
      if (data.success) {
        updatedRequests = data.data || [];
        setRequests(updatedRequests);
      } else {
        setRequests([]);
      }
      
      return updatedRequests;
    } catch (error) {
      console.error('등록 요청 목록 로드 실패:', error);
      setRequests([]);
      return [];
    }
  };

  const handleViewDetail = async (request) => {
    // 최신 정보를 가져오기 위해 먼저 요청 목록을 새로고침
    // (scanned 상태가 업데이트되었을 수 있음)
    // 단, 로딩 상태는 설정하지 않음 (상세보기 패널이 가려지지 않도록)
    const updatedRequests = await fetchRequestsWithoutLoading();
    
    // 업데이트된 requests 배열에서 최신 정보 찾기
    let latestRequest = request;
    const latestFromList = updatedRequests.find(r => r.id === request.id);
    if (latestFromList) {
      latestRequest = latestFromList;
    }
    
    // selectedRequest가 이미 있고 scanned가 1이면 그것을 사용 (분석 완료 후 상태 유지)
    if (selectedRequest && selectedRequest.id === request.id && (selectedRequest.scanned === 1 || selectedRequest.scanned === '1' || selectedRequest.scanned === true)) {
      latestRequest = selectedRequest;
    }
    
    setSelectedRequest(latestRequest);
    setReviewForm({ status: '', comment: '', server_description: latestRequest.description || '', allowed_teams: [], tools: [] });
    setScannedTools([]);
    setScanResult(null);
    
    // 이전 서버의 결과 초기화 (항상 먼저 초기화)
    setRiskAnalysisResult(null);
    setCurrentScanId(null);
    setAnalysisCompleted(false);
    setAnalyzingRisk(false);
    setAnalysisProgress({ bomtori: 0, scanner: 0, toolVet: 0 });
    
    // analysis_timestamp가 있으면 항상 DB에서 최신 데이터를 조회 (저장된 결과가 있어도 최신 데이터로 갱신)
    const hasAnalysisTimestamp = latestRequest.analysis_timestamp && latestRequest.analysis_timestamp.trim() !== '';
    console.log('handleViewDetail - analysis_timestamp:', latestRequest.analysis_timestamp, 'hasAnalysisTimestamp:', hasAnalysisTimestamp);
    
    // 저장된 결과가 있고 analysis_timestamp가 없으면 저장된 결과 사용 (분석 중인 경우)
    const savedResult = riskAnalysisResults[request.id];
    if (savedResult && !hasAnalysisTimestamp) {
      // 저장된 결과가 있고 analysis_timestamp가 없으면 해당 결과만 사용 (분석 중)
      console.log('handleViewDetail - 저장된 결과 복원 (분석 중):', savedResult, 'for request:', request.id);
      // latestRequest의 scanned 상태를 1로 업데이트 (결과가 있으므로)
      if (latestRequest.scanned !== 1 && latestRequest.scanned !== '1' && latestRequest.scanned !== true) {
        latestRequest = { ...latestRequest, scanned: 1 };
      }
      setSelectedRequest(latestRequest);
      setRiskAnalysisResult(savedResult);
      setCurrentScanId(savedResult.scanId);
      setAnalysisCompleted(true);
      setAnalyzingRisk(false);
      setAnalysisProgress({ bomtori: 100, scanner: 100, toolVet: 100 });
      
      // 위험도 분석 완료 후 DB에서 tool 정보 불러오기 (폴링)
      const loadToolsFromDB = async (retryCount = 0) => {
        try {
          console.log(`[handleViewDetail 폴링 ${retryCount}] DB에서 tool 정보 불러오기 시도:`, latestRequest.name);
          const res = await fetch(`${API_BASE_URL}/marketplace/tools?server_name=${encodeURIComponent(latestRequest.name)}`);
          const data = await res.json();
          console.log(`[handleViewDetail 폴링 ${retryCount}] DB tool 정보 응답:`, data);
          if (data.success && data.data && data.data.length > 0) {
            const tools = data.data.map(tool => ({
              name: tool.name,
              allowed_teams: []
            }));
            setScannedTools(tools);
            setReviewForm(prev => ({ ...prev, tools: tools }));
            console.log(`[handleViewDetail 폴링 ${retryCount}] DB에서 tool 정보 불러오기 완료:`, tools);
          } else {
            // tool 정보가 아직 없으면 3초 후 재시도 (최대 5회)
            if (retryCount < 5) {
              console.log(`[handleViewDetail 폴링 ${retryCount}] DB에 tool 정보가 없음, 3초 후 재시도...`);
              setTimeout(() => {
                loadToolsFromDB(retryCount + 1);
              }, 3000);
            } else {
              console.log(`[handleViewDetail 폴링 ${retryCount}] 최대 재시도 횟수 도달, tool 정보 없음`);
              setScannedTools([]);
              setReviewForm(prev => ({ ...prev, tools: [] }));
            }
          }
        } catch (error) {
          console.error(`[handleViewDetail 폴링 ${retryCount}] DB에서 tool 정보 불러오기 실패:`, error);
          // 오류 발생 시에도 재시도 (최대 5회)
          if (retryCount < 5) {
            setTimeout(() => {
              loadToolsFromDB(retryCount + 1);
            }, 3000);
          } else {
            setScannedTools([]);
            setReviewForm(prev => ({ ...prev, tools: [] }));
          }
        }
      };
      loadToolsFromDB(0);
      
      // 저장된 결과가 있고 analysis_timestamp가 없으면 바로 반환 (분석 중이므로)
      return;
    }
    
    // analysis_timestamp가 있으면 항상 DB에서 최신 결과를 불러옴 (저장된 결과가 있어도 갱신)
    // analysis_timestamp가 있으면 분석이 완료된 것으로 간주
    if (hasAnalysisTimestamp) {
      // 분석이 완료된 상태이므로 진행 중 상태는 false로 설정
      setAnalyzingRisk(false);
      setAnalysisProgress({ bomtori: 100, scanner: 100, toolVet: 100 });
      
      const scanPath = latestRequest.github_link || latestRequest.file_path;
      console.log('handleViewDetail - scanPath:', scanPath);
      if (scanPath) {
        try {
          const token = localStorage.getItem('token');
          
          // 서버 이름 파라미터 추가 (서버별 데이터 필터링)
          // 정규화된 서버 이름 사용 (백엔드와 일치)
          const normalizedServerName = latestRequest?.name ? normalizeServerName(latestRequest.github_link, latestRequest.name) : null;
          const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';
          
          // Code 취약점 확인
          const codeRes = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });
          const codeData = await codeRes.json();
          
          // OSS 취약점 확인
          let ossVulns = 0;
          let scanId = null;
          
          if (codeData.success && codeData.data && codeData.data.length > 0) {
            scanId = codeData.data[0]?.scan_id || null;
          }
          const codeVulns = codeData.success ? (codeData.data?.length || 0) : 0;
            
          // OSS 취약점 조회 (scan_id가 있으면 scan_id로, 없으면 scan_path로)
              try {
            let ossRes;
            if (scanId) {
              ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                  headers: {
                    'Authorization': `Bearer ${token}`
                  }
                });
            } else {
              // scan_id가 없으면 scan_path로 직접 조회
              ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
                headers: {
                  'Authorization': `Bearer ${token}`
                }
              });
            }
                const ossData = await ossRes.json();
                if (ossData.success && ossData.data) {
                  ossVulns = ossData.data.length || 0;
              // scan_id가 없었는데 OSS 데이터에서 scan_id를 얻을 수 있으면 업데이트
              if (!scanId && ossData.data.length > 0 && ossData.data[0]?.scan_id) {
                scanId = ossData.data[0].scan_id;
              }
                }
              } catch (ossError) {
                console.error('OSS 취약점 조회 실패:', ossError);
              }
            
          // Tool 취약점 조회
          let toolVulns = 0;
          try {
            let toolRes;
            if (scanId) {
              toolRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                headers: {
                  'Authorization': `Bearer ${token}`
                }
              });
            } else {
              toolRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
                headers: {
                  'Authorization': `Bearer ${token}`
                }
              });
            }
            const toolData = await toolRes.json();
            if (toolData.success && toolData.data) {
              toolVulns = toolData.data.length || 0;
            }
            
            // DB에서 데이터가 없으면 localStorage의 캐시도 삭제
            if (toolData.success && (!toolData.data || toolData.data.length === 0)) {
              console.log('[handleViewDetail] DB에 Tool Validation 데이터 없음, localStorage 캐시 삭제');
              setRiskAnalysisResults(prev => {
                const updated = { ...prev };
                if (updated[latestRequest.id]) {
                  updated[latestRequest.id] = {
                    ...updated[latestRequest.id],
                    toolVulnerabilities: 0
                  };
                }
                return updated;
              });
            }
          } catch (toolError) {
            console.error('Tool 취약점 조회 실패:', toolError);
          }
            
          // 스캔 결과 설정
          const result = {
            ossVulnerabilities: ossVulns,
            codeVulnerabilities: codeVulns,
            toolVulnerabilities: toolVulns,
            scanId: scanId
          };
          console.log('handleViewDetail - 결과 설정:', result, 'request.id:', latestRequest.id);
          setRiskAnalysisResult(result);
          // request id별로 결과 저장 (패널을 닫고 다시 열어도 유지)
          setRiskAnalysisResults(prev => ({
            ...prev,
            [latestRequest.id]: result
          }));
          setCurrentScanId(scanId); // scanId를 별도 state에 저장
          setAnalysisCompleted(true);
        } catch (error) {
          console.error('스캔 결과 조회 실패:', error);
          // 조회 실패 시에도 스캔 완료로 표시 (scanned === 1이므로)
          const errorResult = {
            ossVulnerabilities: 0,
            codeVulnerabilities: 0,
            toolVulnerabilities: 0,
            scanId: null
          };
          setRiskAnalysisResult(errorResult);
          setRiskAnalysisResults(prev => ({
            ...prev,
            [latestRequest.id]: errorResult
          }));
          setAnalysisCompleted(true);
        }
      } else {
        // scanPath가 없어도 scanned === 1이면 기본값으로 결과 설정
        const defaultResult = {
          ossVulnerabilities: 0,
          codeVulnerabilities: 0,
          toolVulnerabilities: 0,
          scanId: null
        };
        setRiskAnalysisResult(defaultResult);
        setRiskAnalysisResults(prev => ({
          ...prev,
          [latestRequest.id]: defaultResult
        }));
        setAnalysisCompleted(true);
      }
    } else {
      // analysis_timestamp가 없으면 상태 초기화
      // 저장된 결과가 있으면 이미 위에서 처리했으므로 여기서는 초기화
      setAnalyzingRisk(false);
      setAnalysisProgress({ bomtori: 0, scanner: 0, toolVet: 0 });
      setAnalysisCompleted(false);
    }
  };

  const handleRunAnalysis = async () => {
    if (!selectedRequest?.github_link && !selectedRequest?.file_path) {
      alert('GitHub 링크 또는 파일 경로가 필요합니다.');
      return;
    }

    setAnalyzingRisk(true);
    setAnalysisProgress({ bomtori: 0, scanner: 0, toolVet: 0 });
    setRiskAnalysisResult(null);
    setAnalysisCompleted(false);
    setAnalysisError(null);

    try {
      const token = localStorage.getItem('token');
      
      // 스캔 시작
      const res = await fetch(`${API_BASE_URL}/risk-assessment/scan-code`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          github_url: selectedRequest.github_link || null,
          repository_path: selectedRequest.file_path || null,
          mcp_server_name: selectedRequest.name
        })
      });

      const data = await res.json();
      
      if (!data.success || !data.scan_id) {
        setAnalysisError(data.message || '스캔 시작 실패');
        setAnalyzingRisk(false);
        setAnalysisProgress({ bomtori: 0, scanner: 0, toolVet: 0 });
        return;
      }
      
      const scanId = data.scan_id;
      
      // 진행률 폴링
      const pollProgress = async () => {
        while (true) {
          try {
            const progressRes = await fetch(`${API_BASE_URL}/risk-assessment/scan-progress?scan_id=${scanId}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
            
            if (progressRes.ok) {
              const progressData = await progressRes.json();
              if (progressData.success && progressData.data) {
                const progress = progressData.data;
                
                // 진행률 업데이트 (오류가 있어도 진행률은 업데이트)
                const toolVetError = progress.toolVetError;
                const toolVetProgress = toolVetError
                  ? 100 // 실패 시에도 진행바는 100% (빨간/사선 스타일)
                  : (progress.toolVetCompleted ? 100 : (progress.toolVet !== null ? progress.toolVet : 0));
                
                // bomtori 진행률: 완료되었거나 오류가 있으면 100, 아니면 현재 진행률
                // null이거나 0이면 이전 진행률 유지 (99%에서 0%로 떨어지는 것 방지)
                setAnalysisProgress(prev => {
                  let bomtoriProgress;
                  if (progress.bomtoriCompleted || progress.bomtoriError) {
                    bomtoriProgress = 100;
                  } else if (progress.bomtori !== null && progress.bomtori !== undefined) {
                    bomtoriProgress = progress.bomtori;
                  } else {
                    // null이거나 undefined인 경우 이전 진행률 유지
                    bomtoriProgress = prev.bomtori !== undefined && prev.bomtori !== null ? prev.bomtori : 0;
                  }
                  
                  return {
                    bomtori: bomtoriProgress,
                    scanner: progress.scanner !== null && progress.scanner !== undefined ? progress.scanner : (prev.scanner || 0),
                    toolVet: toolVetProgress
                  };
                });
                
                // 개별 스캐너 오류 확인 (필수 스캔만 중단; TOOL-VET 실패는 허용)
                const errorMessages = [];
                if (progress.bomtoriError) {
                  errorMessages.push(progress.bomtoriError);
                }
                if (progress.scannerError) {
                  errorMessages.push(progress.scannerError);
                }
                
                // 오류 발생 확인 (필수 스캔 오류만 중단)
                if (progress.status === 'failed' || errorMessages.length > 0) {
                  const errorMessage = progress.error || errorMessages.join(' / ') || '스캔 중 오류가 발생했습니다.';
                  setAnalysisError(errorMessage);
                  setAnalyzingRisk(false);
                  // 진행률은 유지하되 오류 메시지 표시
                  break;
                }
                
                // 필수 스캔 완료 여부 확인 (TOOL-VET 실패는 허용)
                const scannerSuccess = progress.scannerCompleted && !progress.scannerError;
                const bomtoriSuccess = progress.bomtoriCompleted && !progress.bomtoriError;
                const hasBomtori = selectedRequest?.github_link && selectedRequest.github_link.includes('github.com');
                const hasRequiredSuccess = hasBomtori ? (scannerSuccess && bomtoriSuccess) : scannerSuccess;

                // 완료 처리: 백엔드 completed이거나 필수 스캔이 모두 성공하면 완료
                if (progress.status === 'completed' || hasRequiredSuccess) {
                  // 즉시 3개 모두 100%로 설정 (TOOL-VET 실패여도 진행바는 100%)
                  setAnalysisProgress({
                    bomtori: 100,
                    scanner: 100,
                    toolVet: 100
                  });
                  
                  // 3초 후에 결과 표시
                  setTimeout(async () => {
                  // 현재 selectedRequest의 ID를 저장 (클로저 문제 방지)
                  const currentRequestId = selectedRequest?.id;
                  
                  // 완료 후 취약점 개수 조회 (서버 이름을 함께 전달해 정확한 대상만 로드)
                  // 정규화된 서버 이름 사용 (백엔드와 일치)
                  const normalizedServerName = selectedRequest?.name ? normalizeServerName(selectedRequest.github_link, selectedRequest.name) : null;
                  const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';

                  try {
                    const vulnRes = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                      headers: {
                        'Authorization': `Bearer ${token}`
                      }
                    });
                    const vulnData = await vulnRes.json();
                    
                    const codeVulns = vulnData.success ? (vulnData.data?.length || 0) : 0;
                    
                    // OSS 취약점 개수 조회
                      let ossVulns = 0;
                    try {
                      const ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                        headers: {
                          'Authorization': `Bearer ${token}`
                        }
                      });
                      const ossData = await ossRes.json();
                        ossVulns = ossData.success ? (ossData.data?.length || 0) : 0;
                      } catch (error) {
                        console.error('OSS 취약점 개수 조회 실패:', error);
                      }
                      
                      // Tool 취약점 개수 조회
                      let toolVulns = 0;
                      try {
                        const toolRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                          headers: {
                            'Authorization': `Bearer ${token}`
                          }
                        });
                        const toolData = await toolRes.json();
                        toolVulns = toolData.success ? (toolData.data?.length || 0) : 0;
                    } catch (error) {
                        console.error('Tool 취약점 개수 조회 실패:', error);
                      }
                      
                      const result = {
                        ossVulnerabilities: ossVulns,
                        codeVulnerabilities: codeVulns,
                        toolVulnerabilities: toolVulns,
                        scanId: scanId
                      };
                      
                      // 결과 저장 및 상태 업데이트
                      setRiskAnalysisResult(result);
                      setCurrentScanId(scanId);
                      setAnalysisCompleted(true);
                      setAnalyzingRisk(false);
                      
                      // request id별로 결과 저장 (패널을 닫고 다시 열어도 유지)
                      if (currentRequestId) {
                        setRiskAnalysisResults(prev => ({
                          ...prev,
                          [currentRequestId]: result
                        }));
                      }
                      
                      // 스캔 완료 직후 selectedRequest를 즉시 scanned=1로 업데이트 (버튼이 사라지도록)
                      // 함수형 업데이트를 사용하여 클로저 문제 방지
                      setSelectedRequest(prev => {
                        if (prev && prev.id === currentRequestId) {
                          const updatedRequest = { ...prev, scanned: 1 };
                          console.log('✅ 분석 완료 - selectedRequest 즉시 업데이트 (scanned=1):', {
                            id: updatedRequest.id,
                            scanned: updatedRequest.scanned,
                            name: updatedRequest.name,
                            prevScanned: prev.scanned
                          });
                          return updatedRequest;
                        }
                        return prev;
                      });
                      
                      // 위험도 분석 완료 후 DB에서 tool 정보 불러오기 (폴링)
                      if (currentRequestId && selectedRequest?.name) {
                        const loadToolsFromDB = async (retryCount = 0) => {
                          try {
                            console.log(`[폴링 ${retryCount}] DB에서 tool 정보 불러오기 시도:`, selectedRequest.name);
                            const res = await fetch(`${API_BASE_URL}/marketplace/tools?server_name=${encodeURIComponent(selectedRequest.name)}`);
                            const data = await res.json();
                            console.log(`[폴링 ${retryCount}] DB tool 정보 응답:`, data);
                            if (data.success && data.data && data.data.length > 0) {
                              const tools = data.data.map(tool => ({
                                name: tool.name,
                                allowed_teams: []
                              }));
                              setScannedTools(tools);
                              setReviewForm(prev => ({ ...prev, tools: tools }));
                              console.log(`[폴링 ${retryCount}] DB에서 tool 정보 불러오기 완료:`, tools);
                            } else {
                              // tool 정보가 아직 없으면 3초 후 재시도 (최대 5회)
                              if (retryCount < 5) {
                                console.log(`[폴링 ${retryCount}] DB에 tool 정보가 없음, 3초 후 재시도...`);
                                setTimeout(() => {
                                  loadToolsFromDB(retryCount + 1);
                                }, 3000);
                              } else {
                                console.log(`[폴링 ${retryCount}] 최대 재시도 횟수 도달, tool 정보 없음`);
                                setScannedTools([]);
                                setReviewForm(prev => ({ ...prev, tools: [] }));
                              }
                            }
                          } catch (error) {
                            console.error(`[폴링 ${retryCount}] DB에서 tool 정보 불러오기 실패:`, error);
                            // 오류 발생 시에도 재시도 (최대 5회)
                            if (retryCount < 5) {
                              setTimeout(() => {
                                loadToolsFromDB(retryCount + 1);
                              }, 3000);
                            } else {
                              setScannedTools([]);
                              setReviewForm(prev => ({ ...prev, tools: [] }));
                            }
                          }
                        };
                        // 즉시 한 번 시도
                        loadToolsFromDB(0);
                      }
                      
                      // 스캔 완료 후 요청 목록을 다시 불러와서 DB의 scanned 필드 확인
                      // 백엔드에서 scanned=1로 업데이트된 후에 가져옴
                      const updatedRequests = await fetchRequests();
                      
                      // 업데이트된 requests에서 현재 선택된 요청 찾기 (ID로 찾기)
                      if (currentRequestId) {
                        const latestRequest = updatedRequests.find(r => r.id === currentRequestId);
                        if (latestRequest) {
                          // 함수형 업데이트로 scanned=1로 확실하게 설정
                          setSelectedRequest(prev => {
                            if (prev && prev.id === currentRequestId) {
                              const finalRequest = { ...latestRequest, scanned: 1 };
                              console.log('✅ 분석 완료 - selectedRequest 최종 업데이트 (DB 반영):', {
                                id: finalRequest.id,
                                scanned: finalRequest.scanned,
                                db_scanned: latestRequest.scanned,
                                name: finalRequest.name
                              });
                              return finalRequest;
                            }
                            return prev;
                          });
                        }
                      }
                  } catch (error) {
                    console.error('취약점 개수 조회 실패:', error);
                    // 조회 실패 시에도 기본값으로 결과 설정
                    const errorResult = {
                      ossVulnerabilities: 0,
                      codeVulnerabilities: 0,
                      toolVulnerabilities: 0,
                      scanId: scanId
                    };
                    setRiskAnalysisResult(errorResult);
                    if (currentRequestId) {
                      setRiskAnalysisResults(prev => ({
                        ...prev,
                        [currentRequestId]: errorResult
                      }));
                    }
                    setAnalysisCompleted(true);
                    setAnalyzingRisk(false);
                  }
                  }, 3000); // 3초 대기
                  
                    break;
                }
              }
            }
          } catch (error) {
            console.error('진행률 조회 오류:', error);
          }
          
          await new Promise(resolve => setTimeout(resolve, 1000)); // 1초마다 폴링
        }
      };
      
      // 진행률 폴링 시작
      pollProgress();
    } catch (error) {
      console.error('분석 오류:', error);
      setAnalysisError('분석 중 오류가 발생했습니다: ' + (error.message || '알 수 없는 오류'));
      setAnalyzingRisk(false);
      setAnalysisProgress({ bomtori: 0, scanner: 0, toolVet: 0 });
    }
  };

  const handleViewRiskDetail = async () => {
    if (!selectedRequest) return;
    
    const scanPath = selectedRequest.github_link || selectedRequest.file_path;
    if (!scanPath) {
      alert('스캔 경로가 없습니다.');
      return;
    }
    
    // scanId는 riskAnalysisResult 또는 currentScanId에서 가져옴
    let scanId = riskAnalysisResult?.scanId || currentScanId;
    
    // scanId가 없으면 다시 조회 (하지만 없어도 scan_path로 이동 가능)
    if (!scanId) {
      try {
        const token = localStorage.getItem('token');
        // 정규화된 서버 이름 사용 (백엔드와 일치)
        const normalizedServerName = selectedRequest.name ? normalizeServerName(selectedRequest.github_link, selectedRequest.name) : null;
        const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';
        const codeRes = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        const codeData = await codeRes.json();
        if (codeData.success && codeData.data && codeData.data.length > 0) {
          scanId = codeData.data[0]?.scan_id || null;
        }
      } catch (error) {
        console.error('scanId 조회 실패:', error);
        // scanId가 없어도 scan_path로 이동 가능하므로 계속 진행
      }
    }
    
    // Risk Assessment result 페이지로 이동 (Total Vulnerabilities 탭으로)
    // scanId가 있으면 저장, 없으면 scan_path로 이동
    if (scanId) {
      localStorage.setItem('riskAssessmentScanId', scanId);
    }
    localStorage.setItem('riskAssessmentScanPath', scanPath); // scan_path 저장
    localStorage.setItem('riskAssessmentGithubUrl', selectedRequest.github_link);
    // 정규화된 서버 이름 저장 (백엔드와 일치)
    const normalizedServerName = selectedRequest.name ? normalizeServerName(selectedRequest.github_link, selectedRequest.name) : null;
    localStorage.setItem('riskAssessmentServerName', normalizedServerName || selectedRequest.name || '');
    localStorage.setItem('riskAssessmentTab', 'Total Vulnerabilities'); // summary 탭으로 설정
    
    // Risk Assessment 페이지로 이동
    navigate('/risk-assessment');
  };
  
  const handleScanTools = async () => {
    // Sandbox 스캔만 사용
    setShowScanModal(true);
    setScanningTools(true);
    setScanResult(null);
    
    try {
      if (!selectedRequest?.github_link) {
        alert('GitHub 링크가 필요합니다.');
        setScanningTools(false);
        setShowScanModal(false);
        return;
      }
      
      const url = `${API_BASE_URL}/marketplace/scan-tools?request_id=${selectedRequest.id}&use_sandbox=true`;
      
      const res = await fetch(url);
      const data = await res.json();
      
      if (data.success) {
        setScanResult({
          ...data.data,
          method: data.data.method || 'unknown'
        });
        if (data.data.tools.length > 0) {
          const tools = data.data.tools.map(toolName => ({
            name: toolName,
            allowed_teams: []
          }));
          setScannedTools(tools);
          setReviewForm(prev => ({ ...prev, tools: tools }));
        }
      } else {
        setScanResult({
          tools: [],
          files: [],
          repository: null,
          branch: null,
          method: 'none',
          error: data.message || '스캔 실패'
        });
      }
    } catch (error) {
      console.error('Tool 스캔 오류:', error);
      setScanResult({
        tools: [],
        files: [],
        repository: null,
        branch: null,
        method: 'none',
        error: '스캔 중 오류가 발생했습니다.'
      });
    } finally {
      setScanningTools(false);
    }
  };
  
  const handleCloseScanModal = () => {
    setShowScanModal(false);
    setScanResult(null);
  };
  
  const handleApplyScanResults = () => {
    if (scanResult && scanResult.tools.length > 0) {
      const tools = scanResult.tools.map(toolName => ({
        name: toolName,
        allowed_teams: []
      }));
      setScannedTools(tools);
      setReviewForm(prev => ({ ...prev, tools: tools }));
      setShowScanModal(false);
    }
  };

  const handleCloseDetail = () => {
    setSelectedRequest(null);
    setReviewForm({ status: '', comment: '', server_description: '', allowed_teams: [], tools: [] });
    setScannedTools([]);
    setScanResult(null);
    setShowScanModal(false);
    // riskAnalysisResult와 currentScanId는 유지 (분석 완료 후 상태 유지)
    // setCurrentScanId(null); // scanId 초기화하지 않음
    // setRiskAnalysisResult(null); // 결과도 초기화하지 않음
  };

  const handleReview = async (statusOverride = null) => {
    const status = statusOverride || reviewForm.status;
    
    if (!status) {
      alert('승인 또는 거부를 선택해주세요.');
      return;
    }

    // 승인 시 서버 설명 필수 확인
    if (status === 'approved' && !reviewForm.server_description.trim()) {
      alert('승인 시 서버 설명은 필수입니다.');
      return;
    }

    try {
      const res = await fetch(`${API_BASE_URL}/marketplace/requests/${selectedRequest.id}/review`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: status,
          review_comment: reviewForm.comment || null,
          server_description: reviewForm.server_description || null,
          allowed_teams: reviewForm.allowed_teams.length > 0 ? reviewForm.allowed_teams : null,
          tools: reviewForm.tools.length > 0 ? reviewForm.tools : null
        })
      });

      const data = await res.json();
      if (data.success) {
        alert(data.message);
        fetchRequests();
        handleCloseDetail();
      } else {
        alert(data.message || '검토 처리 중 오류가 발생했습니다.');
      }
    } catch (error) {
      console.error('검토 처리 실패:', error);
      alert('검토 처리 중 오류가 발생했습니다.');
    }
  };

        // 관리자인지 확인
        const isAdmin = user && (
          (Array.isArray(user.roles) && user.roles.includes('admin')) || 
          user.role === 'admin'
        );

        // 백엔드에서 역할별 필터링을 처리하므로 클라이언트 사이드 필터링 불필요
        let filteredRequests = requests;
        
        // 검색어 필터링
        if (searchTerm) {
          filteredRequests = filteredRequests.filter(request => 
            request.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            request.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            request.description?.toLowerCase().includes(searchTerm.toLowerCase())
          );
        }

  // 정렬 핸들러
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

  // 정렬 아이콘 렌더링
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

  // 정렬 적용
  if (sortColumn && sortDirection) {
    filteredRequests = [...filteredRequests].sort((a, b) => {
      let aValue = a[sortColumn];
      let bValue = b[sortColumn];

      // 신청 시간 정렬
      if (sortColumn === 'created_at') {
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
    });
  }

  const getStatusBadge = (status) => {
    if (!status) return null;
    const statusMap = {
      'pending': { text: '대기중', color: '#856404', bgColor: '#fff3cd' },
      'approved': { text: '승인됨', color: '#155724', bgColor: '#d4edda' },
      'rejected': { text: '거부됨', color: '#721c24', bgColor: '#f8d7da' }
    };
    const statusInfo = statusMap[status] || { text: status, color: '#6b7280', bgColor: '#f3f4f6' };
    
    return (
      <span style={{
        display: 'inline-block',
        padding: '4px 12px',
        borderRadius: '6px',
        fontSize: '0.85rem',
        fontWeight: '600',
        color: statusInfo.color,
        backgroundColor: statusInfo.bgColor
      }}>
        {statusInfo.text}
      </span>
    );
  };

  const getStatusBadgeClass = (status) => {
    switch (status) {
      case 'pending': return 'status-pending';
      case 'approved': return 'status-approved';
      case 'rejected': return 'status-rejected';
      default: return '';
    }
  };

  const getStatusText = (status) => {
    switch (status) {
      case 'pending': return '대기중';
      case 'approved': return '승인됨';
      case 'rejected': return '거부됨';
      default: return status;
    }
  };

  if (loading) {
    return <div>로딩 중...</div>;
  }

  return (
    <div className="request-board-container">
      <div className="request-board-left">
    <section className="request-board">
      <div className="board-header">
        <h1>Request Board</h1>
        <div className="request-board-tabs">
          <button 
            className={`request-board-tab ${filter === 'all' ? 'active' : ''}`}
            onClick={() => setFilter('all')}
          >
            전체 ({requestCounts.all})
          </button>
          <button 
            className={`request-board-tab ${filter === 'pending' ? 'active' : ''}`}
            onClick={() => setFilter('pending')}
          >
            대기중 ({requestCounts.pending})
          </button>
          <button 
            className={`request-board-tab ${filter === 'approved' ? 'active' : ''}`}
            onClick={() => setFilter('approved')}
          >
            승인됨 ({requestCounts.approved})
          </button>
          <button 
            className={`request-board-tab ${filter === 'rejected' ? 'active' : ''}`}
            onClick={() => setFilter('rejected')}
          >
            거부됨 ({requestCounts.rejected})
          </button>
        </div>
      </div>

      <div className="list-page__controls">
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
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>
        <button 
          onClick={async () => {
            setIsRotating(true);
            await fetchRequests();
            // 새로고침 시 개수도 다시 가져오기
            const fetchRequestCounts = async () => {
              try {
                const token = localStorage.getItem('token');
                const headers = {
                  'Content-Type': 'application/json'
                };
                if (token) {
                  headers['Authorization'] = `Bearer ${token}`;
                }
                
                const [allRes, pendingRes, approvedRes, rejectedRes] = await Promise.all([
                  fetch(`${API_BASE_URL}/marketplace/requests?limit=10000`, { headers }),
                  fetch(`${API_BASE_URL}/marketplace/requests?status=pending&limit=10000`, { headers }),
                  fetch(`${API_BASE_URL}/marketplace/requests?status=approved&limit=10000`, { headers }),
                  fetch(`${API_BASE_URL}/marketplace/requests?status=rejected&limit=10000`, { headers })
                ]);
                
                const [allData, pendingData, approvedData, rejectedData] = await Promise.all([
                  allRes.json(),
                  pendingRes.json(),
                  approvedRes.json(),
                  rejectedRes.json()
                ]);
                
                setRequestCounts({
                  all: (allData.success ? (allData.pagination?.total || 0) : 0),
                  pending: (pendingData.success ? (pendingData.pagination?.total || 0) : 0),
                  approved: (approvedData.success ? (approvedData.pagination?.total || 0) : 0),
                  rejected: (rejectedData.success ? (rejectedData.pagination?.total || 0) : 0)
                });
              } catch (error) {
                console.error('요청 개수 조회 실패:', error);
              }
            };
            fetchRequestCounts();
          }} 
          className="btn-refresh" 
          title="새로고침"
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

      <div className="requests-table-container">
          <table className="requests-table">
            <thead>
              <tr>
                <th>요청자</th>
                <th className="sortable" onClick={(e) => { e.stopPropagation(); handleSort('created_at'); }} style={{ cursor: 'pointer', userSelect: 'none', position: 'relative', paddingRight: '24px' }}>
                  신청 시간
                  {getSortIcon('created_at')}
                </th>
                <th>제목</th>
                <th>상태</th>
                <th>작업</th>
              </tr>
            </thead>
            <tbody>
                {filteredRequests.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="empty-state">데이터가 없습니다.</td>
                  </tr>
                ) : (
                  filteredRequests.map(request => (
                    <tr 
                      key={request.id}
                      className={selectedRequest?.id === request.id ? 'selected' : ''}
                      onClick={() => handleViewDetail(request)}
                    >
                  <td>
                    {request.requester?.username || '알 수 없음'}
                    <br />
                    <span className="employee-id">({request.requester?.employee_id || '-'})</span>
                  </td>
                  <td>
                    {(() => {
                      if (!request.created_at) return '-';
                      // SQLite datetime 문자열을 직접 파싱 (시간대 변환 없이)
                      const match = request.created_at.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                      if (match) {
                        const [, year, month, day, hours, minutes, seconds] = match;
                        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
                      }
                      return request.created_at;
                    })()}
                  </td>
                  <td className="request-title-cell">
                    {request.title || request.name}
                  </td>
                  <td>
                    {getStatusBadge(request.status)}
                  </td>
                  <td>
                    <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViewDetail(request);
                          }}
                      className="btn-view-detail"
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
        </section>
      </div>

      {selectedRequest && (
        <div className={`request-detail-drawer is-open`}>
          <div 
            className="request-detail-drawer__backdrop"
            onClick={handleCloseDetail}
          />
          <aside className="request-detail-drawer__panel" role="dialog" aria-modal="true">
            <header className="request-detail-drawer__header">
              <div>
                <p className="request-detail-drawer__eyebrow">Server Request</p>
                <h2 className="request-detail-drawer__title">{selectedRequest.title || selectedRequest.name}</h2>
              </div>
              <button 
                type="button" 
                className="request-detail-drawer__close"
                onClick={handleCloseDetail}
                aria-label="Close details"
              >
                &times;
              </button>
            </header>
            <div className="request-detail-drawer__content">
              <section className="request-detail-drawer__section">
                <h3>요청 정보</h3>
                <div className="request-detail-drawer__info-grid">
                  <div className="request-detail-drawer__info-item">
                    <span className="request-detail-drawer__info-label">요청자</span>
                    <span className="request-detail-drawer__info-value">
                      {selectedRequest.requester?.username || '알 수 없음'}
                      {selectedRequest.requester?.employee_id && ` (${selectedRequest.requester.employee_id})`}
                    </span>
                  </div>
                  <div className="request-detail-drawer__info-item">
                    <span className="request-detail-drawer__info-label">팀</span>
                    <span className="request-detail-drawer__info-value">{selectedRequest.requester?.team || '-'}</span>
                  </div>
                  <div className="request-detail-drawer__info-item">
                    <span className="request-detail-drawer__info-label">직책</span>
                    <span className="request-detail-drawer__info-value">{selectedRequest.requester?.position || '-'}</span>
                  </div>
                  <div className="request-detail-drawer__info-item">
                    <span className="request-detail-drawer__info-label">요청일</span>
                    <span className="request-detail-drawer__info-value">
                      {(() => {
                        if (!selectedRequest.created_at) return '-';
                        // SQLite datetime 문자열을 직접 파싱 (시간대 변환 없이)
                        const match = selectedRequest.created_at.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                        if (match) {
                          const [, year, month, day, hours, minutes, seconds] = match;
                          return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
                        }
                        return selectedRequest.created_at;
                      })()}
                    </span>
                  </div>
                </div>
              </section>

              <section className="request-detail-drawer__section">
                <h3>서버 정보</h3>
                <div className="request-detail-drawer__info-grid">
                  <div className="request-detail-drawer__info-item">
                    <span className="request-detail-drawer__info-label">이름</span>
                    <span className="request-detail-drawer__info-value">{selectedRequest.name}</span>
                  </div>
                  {selectedRequest.description && (
                    <div className="request-detail-drawer__info-item" style={{ gridColumn: '1 / -1' }}>
                      <span className="request-detail-drawer__info-label">설명</span>
                      <span className="request-detail-drawer__info-value">{selectedRequest.description}</span>
                    </div>
                  )}
                  <div className="request-detail-drawer__info-item" style={{ gridColumn: '1 / -1' }}>
                    <span className="request-detail-drawer__info-label">GitHub URL</span>
                    <span className="request-detail-drawer__info-value">
                      {selectedRequest.github_link ? (
                        <a 
                          href={selectedRequest.github_link} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          style={{ 
                            color: '#0366d6', 
                            textDecoration: 'none',
                            wordBreak: 'break-all'
                          }}
                          onMouseEnter={(e) => e.target.style.textDecoration = 'underline'}
                          onMouseLeave={(e) => e.target.style.textDecoration = 'none'}
                        >
                          {selectedRequest.github_link}
                        </a>
                      ) : (
                        <span style={{ color: '#999', fontStyle: 'italic' }}>없음</span>
                      )}
                    </span>
                  </div>
                  {selectedRequest.connection_snippet && (
                    <div className="request-detail-drawer__info-item" style={{ gridColumn: '1 / -1' }}>
                      <span className="request-detail-drawer__info-label">Connection</span>
                      <div className="request-detail-drawer__code-box">
                        <pre><code>{selectedRequest.connection_snippet}</code></pre>
                      </div>
                    </div>
                  )}
                </div>
              </section>

              {selectedRequest.status === 'pending' && (
                <section className="request-detail-drawer__section">
                  <h3>위험도 분석</h3>
                  {/* analysis_timestamp가 없을 때만 Run Analysis 버튼 표시 */}
                  {(() => {
                    // analysis_timestamp가 없으면 버튼 표시
                    const hasAnalysisTimestamp = selectedRequest.analysis_timestamp && selectedRequest.analysis_timestamp.trim() !== '';
                    const shouldShowButton = !hasAnalysisTimestamp;
                    
                    console.log('Run Analysis 버튼 조건 - analysis_timestamp:', selectedRequest.analysis_timestamp, 'hasAnalysisTimestamp:', hasAnalysisTimestamp, 'shouldShowButton:', shouldShowButton);
                    
                    return shouldShowButton;
                  })() && (
                    <div style={{ marginBottom: '16px' }}>
                      {analysisError ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                          <div style={{ 
                            fontSize: '0.9rem', 
                            color: '#dc2626',
                            padding: '12px',
                            backgroundColor: '#fee2e2',
                            borderRadius: '6px',
                            border: '1px solid #fecaca'
                          }}>
                            {analysisError}
                          </div>
                          <button
                            onClick={() => {
                              setAnalysisError(null);
                              handleRunAnalysis();
                            }}
                            className="btn-refresh"
                            style={{ width: '100%' }}
                          >
                            다시 시도
                          </button>
                        </div>
                      ) : (
                        <>
                          <button
                            onClick={handleRunAnalysis}
                            className="btn-refresh"
                            disabled={analyzingRisk || (!selectedRequest.github_link && !selectedRequest.file_path)}
                            style={{ marginBottom: '16px' }}
                          >
                            {analyzingRisk ? 'Analyzing...' : 'Run Analysis'}
                          </button>
                          {analyzingRisk && (
                        <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                          {selectedRequest.github_link && selectedRequest.github_link.includes('github.com') && (
                            <div>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '0.85rem', color: '#666' }}>
                                <span>SBOM/SCA</span>
                                <span>{typeof analysisProgress === 'object' ? `${analysisProgress.bomtori || 0}%` : '0%'}</span>
                              </div>
                              <div style={{
                                width: '100%',
                                height: '8px',
                                backgroundColor: '#e0e0e0',
                                borderRadius: '4px',
                                overflow: 'hidden'
                              }}>
                                <div style={{
                                  width: `${typeof analysisProgress === 'object' ? (analysisProgress.bomtori || 0) : 0}%`,
                                  height: '100%',
                                  backgroundColor: '#17a2b8',
                                  transition: 'width 0.3s ease'
                                }}></div>
                              </div>
                            </div>
                          )}
                          <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '0.85rem', color: '#666' }}>
                              <span>Code Scanner</span>
                              <span>{typeof analysisProgress === 'object' ? `${analysisProgress.scanner || 0}%` : `${analysisProgress || 0}%`}</span>
                            </div>
                            <div style={{
                              width: '100%',
                              height: '8px',
                              backgroundColor: '#e0e0e0',
                              borderRadius: '4px',
                              overflow: 'hidden'
                            }}>
                              <div style={{
                                width: `${typeof analysisProgress === 'object' ? (analysisProgress.scanner || 0) : (analysisProgress || 0)}%`,
                                height: '100%',
                                backgroundColor: '#003153',
                                transition: 'width 0.3s ease'
                              }}></div>
                            </div>
                          </div>
                          {selectedRequest.github_link && selectedRequest.github_link.includes('github.com') && (
                            <div>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '0.85rem', color: '#666' }}>
                                <span>Tool Vetting</span>
                                <span>{typeof analysisProgress === 'object' ? `${analysisProgress.toolVet || 0}%` : '0%'}</span>
                              </div>
                              <div style={{
                                width: '100%',
                                height: '8px',
                                backgroundColor: '#e0e0e0',
                                borderRadius: '4px',
                                overflow: 'hidden'
                              }}>
                                <div style={{
                                  width: `${typeof analysisProgress === 'object' ? (analysisProgress.toolVet || 0) : 0}%`,
                                  height: '100%',
                                  backgroundColor: '#7c3aed',
                                  transition: 'width 0.3s ease'
                                }}></div>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                        </>
                      )}
                    </div>
                  )}
                </section>
              )}

              {/* analysis_timestamp가 있거나 해당 서버의 저장된 결과가 있으면 분석 결과 표시 (status와 관계없이 항상 표시) */}
              {(() => {
                // analysis_timestamp가 있으면 분석 완료
                const hasAnalysisTimestamp = selectedRequest.analysis_timestamp && selectedRequest.analysis_timestamp.trim() !== '';
                // 해당 서버의 저장된 결과 확인
                const savedResult = riskAnalysisResults[selectedRequest.id];
                // analysis_timestamp가 있거나 해당 서버의 저장된 결과가 있을 때만 표시
                const hasResult = hasAnalysisTimestamp || savedResult;
                
                console.log('렌더링 - analysis_timestamp:', selectedRequest.analysis_timestamp, 'hasAnalysisTimestamp:', hasAnalysisTimestamp, 'savedResult:', savedResult, 'hasResult:', hasResult);
                return hasResult;
              })() && (
                <section className="request-detail-drawer__section">
                  <h3>위험도 분석 결과</h3>
                  <div>
                      {/* 취약점 정보 표시 - riskAnalysisResult가 없어도 기본값(0) 표시 */}
                      <div style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(3, 1fr)',
                            gap: '16px',
                            marginBottom: '16px'
                          }}>
                            <div style={{
                              padding: '16px',
                              backgroundColor: '#f8f9fa',
                              borderRadius: '8px',
                              textAlign: 'center'
                            }}>
                              <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '8px' }}>OSS 취약점</div>
                              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#333' }}>
                            {(() => {
                              const savedResult = riskAnalysisResults[selectedRequest.id];
                              const result = riskAnalysisResult || savedResult;
                              return result?.ossVulnerabilities ?? 0;
                            })()}
                              </div>
                            </div>
                            <div style={{
                              padding: '16px',
                              backgroundColor: '#f8f9fa',
                              borderRadius: '8px',
                              textAlign: 'center'
                            }}>
                              <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '8px' }}>Code 취약점</div>
                              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#333' }}>
                            {(() => {
                              const savedResult = riskAnalysisResults[selectedRequest.id];
                              const result = riskAnalysisResult || savedResult;
                              return result?.codeVulnerabilities ?? 0;
                            })()}
                              </div>
                            </div>
                            <div style={{
                              padding: '16px',
                              backgroundColor: '#f8f9fa',
                              borderRadius: '8px',
                              textAlign: 'center'
                            }}>
                              <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '8px' }}>Tool 취약점</div>
                              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#333' }}>
                            {(() => {
                              const savedResult = riskAnalysisResults[selectedRequest.id];
                              const result = riskAnalysisResult || savedResult;
                              return result?.toolVulnerabilities ?? 0;
                            })()}
                              </div>
                            </div>
                          </div>
                      {/* scanned === 1이면 항상 상세보기 버튼 표시 */}
                      <button
                        onClick={handleViewRiskDetail}
                        className="btn-refresh"
                        style={{ width: '100%', marginBottom: '24px' }}
                      >
                        상세보기
                      </button>

                      {/* 분석 결과가 있을 때만 검토 폼 표시 */}
                      {isAdmin && (
                        <div className="review-form" style={{ marginTop: '24px', paddingTop: '24px', borderTop: '1px solid #ddd' }}>
                          <h3 style={{ marginBottom: '16px' }}>검토</h3>
                          <label>
                            <strong>서버 설명 (필수)</strong>
                            <textarea
                              value={reviewForm.server_description}
                              onChange={(e) => setReviewForm({ ...reviewForm, server_description: e.target.value })}
                              placeholder="MCP Registry에 표시될 서버 설명을 입력하세요..."
                              rows="5"
                              required
                            />
                          </label>
                          {selectedRequest.github_link && (
                            <label style={{ marginTop: '16px' }}>
                              <strong>GitHub 링크</strong>
                              <div style={{ marginTop: '8px', padding: '12px', backgroundColor: '#f8f9fa', borderRadius: '4px' }}>
                                <a 
                                  href={selectedRequest.github_link} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  style={{ color: '#003153', textDecoration: 'none', wordBreak: 'break-all' }}
                                >
                                  {selectedRequest.github_link}
                                </a>
                              </div>
                            </label>
                          )}
                          <label style={{ marginTop: '16px' }}>
                            <strong>접근 가능 팀 선택</strong>
                            <div className="team-checkboxes" style={{ marginTop: '8px' }}>
                              {/* 전체 팀 체크박스 */}
                              <label style={{ display: 'flex', alignItems: 'center', marginBottom: '12px', paddingBottom: '12px', borderBottom: '1px solid #e0e0e0' }}>
                                <input
                                  type="checkbox"
                                  checked={teams.length > 0 && reviewForm.allowed_teams.length === teams.length}
                                  onChange={(e) => {
                                    let newAllowedTeams;
                                    if (e.target.checked) {
                                      // 전체 팀 선택
                                      newAllowedTeams = [...teams];
                                    } else {
                                      // 전체 팀 해제
                                      newAllowedTeams = [];
                                    }
                                    
                                    // 접근 가능 팀 선택 시 모든 Tool의 allowed_teams에 자동으로 추가/제거
                                    const updatedTools = reviewForm.tools.map(tool => ({
                                      ...tool,
                                      allowed_teams: e.target.checked ? [...teams] : []
                                    }));
                                    
                                    // scannedTools도 동기화 (UI 표시용)
                                    const updatedScannedTools = scannedTools.map(tool => ({
                                      ...tool,
                                      allowed_teams: e.target.checked ? [...teams] : []
                                    }));
                                    
                                    setReviewForm({
                                      ...reviewForm,
                                      allowed_teams: newAllowedTeams,
                                      tools: updatedTools
                                    });
                                    setScannedTools(updatedScannedTools);
                                  }}
                                  style={{ marginRight: '8px' }}
                                />
                                <span style={{ fontWeight: '600' }}>전체 팀</span>
                              </label>
                              {/* 개별 팀 체크박스 */}
                              {teams.length > 0 ? (
                                teams.map(team => (
                                <label key={team} style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                                  <input
                                    type="checkbox"
                                    checked={reviewForm.allowed_teams.includes(team)}
                                    onChange={(e) => {
                                      let newAllowedTeams;
                                      if (e.target.checked) {
                                        newAllowedTeams = [...reviewForm.allowed_teams, team];
                                      } else {
                                        newAllowedTeams = reviewForm.allowed_teams.filter(t => t !== team);
                                      }
                                      
                                      // 접근 가능 팀 선택 시 모든 Tool의 allowed_teams에 자동으로 추가/제거
                                      const updatedTools = reviewForm.tools.map(tool => {
                                        if (e.target.checked) {
                                          // 체크 시: 해당 팀이 없으면 추가
                                          if (!tool.allowed_teams.includes(team)) {
                                            return { ...tool, allowed_teams: [...tool.allowed_teams, team] };
                                          }
                                        } else {
                                          // 체크 해제 시: Tool의 allowed_teams에서도 제거
                                          if (tool.allowed_teams.includes(team)) {
                                            return { ...tool, allowed_teams: tool.allowed_teams.filter(t => t !== team) };
                                          }
                                        }
                                        return tool;
                                      });
                                      
                                      // scannedTools도 동기화 (UI 표시용)
                                      const updatedScannedTools = scannedTools.map(tool => {
                                        if (e.target.checked) {
                                          if (!tool.allowed_teams.includes(team)) {
                                            return { ...tool, allowed_teams: [...tool.allowed_teams, team] };
                                          }
                                        } else {
                                          if (tool.allowed_teams.includes(team)) {
                                            return { ...tool, allowed_teams: tool.allowed_teams.filter(t => t !== team) };
                                          }
                                        }
                                        return tool;
                                      });
                                      
                                      setReviewForm({
                                        ...reviewForm,
                                        allowed_teams: newAllowedTeams,
                                        tools: updatedTools
                                      });
                                      setScannedTools(updatedScannedTools);
                                    }}
                                    style={{ marginRight: '8px' }}
                                  />
                                  <span>{team}</span>
                                </label>
                                ))
                              ) : (
                                <p style={{ fontSize: '0.85rem', color: '#999', marginTop: '8px' }}>팀 목록을 불러오는 중...</p>
                              )}
                            </div>
                          </label>
                          <label style={{ marginTop: '16px' }}>
                            <strong>Tool별 팀 권한 설정</strong>
                            <p style={{ marginTop: '4px', fontSize: '0.85rem', color: '#6c5d53' }}>
                              각 Tool에 접근 가능한 팀을 선택하세요. "접근 가능 팀 선택"과 독립적으로 설정할 수 있으며, 선택하지 않으면 서버 전체 설정을 따릅니다.
                            </p>
                            {scannedTools.length > 0 ? (
                              <div style={{ marginTop: '12px', maxHeight: '300px', overflowY: 'auto', border: '1px solid #ddd', borderRadius: '4px', padding: '12px' }}>
                                {scannedTools.map((tool, index) => (
                                  <div key={tool.name} style={{ marginBottom: '16px', paddingBottom: '16px', borderBottom: index < scannedTools.length - 1 ? '1px solid #eee' : 'none' }}>
                                    <div style={{ fontWeight: 'bold', marginBottom: '8px', color: '#6c5d53' }}>
                                      {tool.name}
                                    </div>
                                    <div className="team-checkboxes" style={{ marginLeft: '8px' }}>
                                      {teams.length > 0 ? (
                                        teams.map(team => (
                                          <label key={team} style={{ display: 'flex', alignItems: 'center', marginBottom: '6px' }}>
                                            <input
                                              type="checkbox"
                                              checked={tool.allowed_teams.includes(team)}
                                              onChange={(e) => {
                                                const updatedTools = [...reviewForm.tools];
                                                const toolIndex = updatedTools.findIndex(t => t.name === tool.name);
                                                if (toolIndex >= 0) {
                                                  if (e.target.checked) {
                                                    updatedTools[toolIndex].allowed_teams = [...updatedTools[toolIndex].allowed_teams, team];
                                                  } else {
                                                    updatedTools[toolIndex].allowed_teams = updatedTools[toolIndex].allowed_teams.filter(t => t !== team);
                                                  }
                                                  setReviewForm({ ...reviewForm, tools: updatedTools });
                                                  
                                                  // scannedTools도 동기화 (UI 표시용)
                                                  const updatedScannedTools = scannedTools.map(t => {
                                                    if (t.name === tool.name) {
                                                      return {
                                                        ...t,
                                                        allowed_teams: e.target.checked
                                                          ? [...t.allowed_teams, team]
                                                          : t.allowed_teams.filter(tt => tt !== team)
                                                      };
                                                    }
                                                    return t;
                                                  });
                                                  setScannedTools(updatedScannedTools);
                                                }
                                              }}
                                              style={{ marginRight: '6px' }}
                                            />
                                            <span style={{ fontSize: '0.9rem' }}>{team}</span>
                                          </label>
                                        ))
                                      ) : (
                                        <p style={{ fontSize: '0.85rem', color: '#999' }}>팀 목록을 불러오는 중...</p>
                                      )}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div style={{ marginTop: '12px', padding: '16px', backgroundColor: '#f5f5f5', borderRadius: '4px', textAlign: 'center' }}>
                                <p style={{ fontSize: '0.95rem', color: '#6c5d53', margin: 0 }}>
                                  위험도 분석을 진행해주세요.
                                </p>
                              </div>
                            )}
                          </label>
                          <label style={{ marginTop: '16px' }}>
                            <strong>검토 코멘트 (선택사항)</strong>
                            <textarea
                              value={reviewForm.comment}
                              onChange={(e) => setReviewForm({ ...reviewForm, comment: e.target.value })}
                              placeholder="검토 코멘트를 입력하세요..."
                              rows="4"
                            />
                          </label>
                          <div className="review-form-actions" style={{ marginTop: '20px', display: 'flex', gap: '12px' }}>
                            <button
                              className={`btn-review ${reviewForm.status === 'approved' ? 'btn-approve active' : 'btn-approve'}`}
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                if (!reviewForm.server_description.trim()) {
                                  alert('승인 시 서버 설명은 필수입니다.');
                                  return;
                                }
                                setReviewForm({ ...reviewForm, status: 'approved' });
                                handleReview('approved');
                              }}
                              style={{ flex: 1 }}
                            >
                              승인
                            </button>
                            <button
                              className={`btn-review ${reviewForm.status === 'rejected' ? 'btn-reject active' : 'btn-reject'}`}
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                setReviewForm({ ...reviewForm, status: 'rejected' });
                                handleReview('rejected');
                              }}
                              style={{ flex: 1 }}
                            >
                              거부
                            </button>
                            <button 
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                handleCloseDetail();
                              }}
                              className="btn-cancel-review"
                              style={{ flex: 1 }}
                            >
                              취소
                            </button>
                          </div>
                        </div>
                      )}
                  </div>
                </section>
              )}

              {selectedRequest.status === 'pending' && !isAdmin && (
                <section className="request-detail-drawer__section">
                  <h3>상태</h3>
                  <div className="request-detail-drawer__info-grid">
                    <div className="request-detail-drawer__info-item" style={{ gridColumn: '1 / -1' }}>
                      <span className="request-detail-drawer__info-label">현재 상태</span>
                      <span className="request-detail-drawer__info-value">
                        {getStatusBadge(selectedRequest.status)}
                        <p style={{ marginTop: '8px', color: '#6c5d53', fontWeight: 'normal' }}>
                          검토 대기 중입니다. 관리자가 검토 후 결과를 알려드립니다.
                        </p>
                      </span>
                    </div>
                  </div>
                </section>
              )}

              {selectedRequest.status !== 'pending' && (
                <section className="request-detail-drawer__section">
                  <h3>검토 결과</h3>
                  <div className="request-detail-drawer__info-grid">
                    <div className="request-detail-drawer__info-item">
                      <span className="request-detail-drawer__info-label">상태</span>
                      <span className="request-detail-drawer__info-value">
                        {getStatusBadge(selectedRequest.status)}
                      </span>
                    </div>
                    {selectedRequest.reviewer && (
                      <div className="request-detail-drawer__info-item">
                        <span className="request-detail-drawer__info-label">검토자</span>
                        <span className="request-detail-drawer__info-value">
                          {selectedRequest.reviewer?.username || '알 수 없음'}
                          {selectedRequest.reviewed_at && (
                            <span className="review-date" style={{ display: 'block', fontSize: '0.85rem', color: 'var(--muted)', marginTop: '4px' }}>
                              {(() => {
                                if (!selectedRequest.reviewed_at) return '';
                                // SQLite datetime 문자열을 직접 파싱 (시간대 변환 없이)
                                const match = selectedRequest.reviewed_at.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                                if (match) {
                                  const [, year, month, day, hours, minutes, seconds] = match;
                                  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
                                }
                                return selectedRequest.reviewed_at;
                              })()}
                            </span>
                          )}
                        </span>
                      </div>
                    )}
                    {selectedRequest.review_comment && (
                      <div className="request-detail-drawer__info-item" style={{ gridColumn: '1 / -1' }}>
                        <span className="request-detail-drawer__info-label">검토 코멘트</span>
                        <span className="request-detail-drawer__info-value" style={{ fontWeight: 'normal' }}>{selectedRequest.review_comment}</span>
                      </div>
                    )}
                  </div>
                  {/* 삭제 버튼 (관리자 또는 요청자 본인만) */}
                  {(() => {
                    const isAdmin = user && (
                      (Array.isArray(user.roles) && user.roles.includes('admin')) || 
                      user.role === 'admin'
                    );
                    const isOwner = user && selectedRequest.requester && user.id === selectedRequest.requester.id;
                    
                    if (isAdmin || isOwner) {
                      return (
                        <div className="detail-item" style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid #e0e0e0' }}>
                          <button
                            onClick={async () => {
                              if (!window.confirm('정말로 이 등록 요청을 삭제하시겠습니까? 승인된 요청인 경우 관련 MCP 서버도 함께 삭제됩니다.')) {
                                return;
                              }
                              
                              try {
                                const token = localStorage.getItem('token');
                                const res = await fetch(`${API_BASE_URL}/marketplace/requests/${selectedRequest.id}`, {
                                  method: 'DELETE',
                                  headers: {
                                    'Authorization': `Bearer ${token}`
                                  }
                                });
                                
                                const data = await res.json();
                                
                                if (data.success) {
                                  alert('등록 요청이 삭제되었습니다.');
                                  handleCloseDetail();
                                  fetchRequests();
                                } else {
                                  alert(data.message || '삭제 중 오류가 발생했습니다.');
                                }
                              } catch (error) {
                                console.error('삭제 오류:', error);
                                alert('삭제 중 오류가 발생했습니다.');
                              }
                            }}
                            className="btn-delete"
                            style={{
                              padding: '8px 16px',
                              backgroundColor: '#dc2626',
                              color: '#fff',
                              border: 'none',
                              borderRadius: '6px',
                              cursor: 'pointer',
                              fontSize: '0.9rem',
                              fontWeight: '500'
                            }}
                          >
                            삭제
                          </button>
                        </div>
                      );
                    }
                    return null;
                  })()}
                </section>
              )}
            </div>
          </aside>
        </div>
      )}

      {/* Tool 스캔 결과 모달 */}
      {showScanModal && (
        <div className="modal-overlay" onClick={handleCloseScanModal} style={{ zIndex: 1001 }}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '1200px', width: '95%', maxHeight: '80vh', overflowY: 'auto' }}>
            <div className="modal-header">
              <h2>🔍 Tool 스캔 결과</h2>
              <button className="btn-close" onClick={handleCloseScanModal}>×</button>
            </div>
            <div className="modal-body">
              {scanningTools ? (
                <div style={{ padding: '40px', textAlign: 'center' }}>
                  <p style={{ fontSize: '1.1rem', color: '#6c5d53' }}>스캔 중...</p>
                  <p style={{ fontSize: '0.9rem', color: '#999', marginTop: '8px' }}>GitHub 리포지토리를 분석하고 있습니다.</p>
                </div>
              ) : scanResult ? (
                <>
                  <div className="detail-section">
                    <h3>스캔 정보</h3>
                    <div className="detail-item">
                      <strong>리포지토리:</strong> {scanResult.repository || '-'}
                    </div>
                    <div className="detail-item">
                      <strong>브랜치:</strong> {scanResult.branch || '-'}
                    </div>
                    <div className="detail-item">
                      <strong>스캔된 파일:</strong> {scanResult.files.length > 0 ? scanResult.files.join(', ') : '-'}
                    </div>
                    {scanResult.commitSha && (
                      <div className="detail-item">
                        <strong>커밋 SHA:</strong> {scanResult.commitSha.substring(0, 8)}...
                      </div>
                    )}
                    {scanResult.runCommand && (
                      <div className="detail-item">
                        <strong>실행 명령어:</strong> {scanResult.runCommand} ({scanResult.runType || 'unknown'})
                      </div>
                    )}
                  </div>

                  {scanResult.error ? (
                    <div className="detail-section">
                      <div style={{ padding: '16px', backgroundColor: '#fff3cd', borderRadius: '4px', color: '#856404' }}>
                        <strong>오류:</strong> {scanResult.error}
                      </div>
                    </div>
                  ) : (
                    <div className="detail-section">
                      <h3>
                        발견된 Tool 목록
                        {scanResult.method && (
                          <span style={{ 
                            marginLeft: '12px', 
                            fontSize: '0.85rem', 
                            color: scanResult.method === 'sandbox_docker' ? '#007bff' : 
                                   scanResult.method === 'mcp_protocol' ? '#4a9b3a' : '#6c5d53',
                            fontWeight: 'normal'
                          }}>
                            ({scanResult.method === 'sandbox_docker' ? '🔒 Sandbox' : 
                              scanResult.method === 'mcp_protocol' ? '✅ MCP Protocol' : 
                              scanResult.method === 'code_scan' ? '📝 코드 스캔' : '❓ 알 수 없음'})
                          </span>
                        )}
                      </h3>
                      {scanResult.tools.length > 0 ? (
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '12px', marginTop: '12px' }}>
                          {scanResult.tools.map((tool, index) => (
                            <div
                              key={tool}
                              style={{
                                padding: '16px',
                                backgroundColor: '#f8f6f3',
                                border: '1px solid #c7b199',
                                borderRadius: '8px',
                                boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ fontSize: '1.2rem' }}>🔧</span>
                                <strong style={{ color: '#6c5d53' }}>{tool}</strong>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ padding: '16px', backgroundColor: '#f5f5f5', borderRadius: '4px', color: '#6c5d53' }}>
                          <p>Tool을 찾을 수 없습니다.</p>
                          <p style={{ fontSize: '0.85rem', marginTop: '8px', color: '#999' }}>
                            리포지토리에서 MCP Tool 정의를 찾을 수 없습니다. 수동으로 입력하거나 확인이 필요합니다.
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                  {scanResult.tools.length > 0 && (
                    <div style={{ marginTop: '20px', padding: '16px', backgroundColor: '#e8f5e9', borderRadius: '4px' }}>
                      <p style={{ fontSize: '0.9rem', color: '#2e7d32', marginBottom: '12px' }}>
                        ✅ {scanResult.tools.length}개의 Tool이 발견되었습니다. 적용하면 승인 폼에 자동으로 추가됩니다.
                      </p>
                      <button
                        onClick={handleApplyScanResults}
                        style={{
                          padding: '10px 20px',
                          backgroundColor: '#4a9b3a',
                          color: '#fff',
                          border: 'none',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          fontSize: '1rem',
                          fontWeight: 'bold'
                        }}
                      >
                        결과 적용
                      </button>
                    </div>
                  )}
                </>
              ) : null}
            </div>
            <div style={{ padding: '16px', borderTop: '1px solid #ddd', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={handleCloseScanModal}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#6c5d53',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                닫기
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RequestBoard;
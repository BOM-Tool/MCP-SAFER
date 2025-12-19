import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { API_BASE_URL } from '../../utils/api';
import './RiskAssessment.css';

const RiskAssessment = () => {
  const [viewMode, setViewMode] = useState('list'); // 'list' or 'result'
  const [selectedTab, setSelectedTab] = useState(() => {
    // localStorage에서 탭 정보 확인
    const savedTab = localStorage.getItem('riskAssessmentTab');
    return savedTab || 'Total Vulnerabilities';
  });
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [codeIssues, setCodeIssues] = useState([]);
  const [analysisUrl, setAnalysisUrl] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [mcpServers, setMcpServers] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [serverFilter, setServerFilter] = useState('not_analyzed'); // not_analyzed, analyzed
  const [statusFilter, setStatusFilter] = useState('all'); // all, pending, approved (analyzed 탭에서만 사용)
  const [serverCounts, setServerCounts] = useState({ not_analyzed: 0, analyzed: 0 });
  const [statusFilterMenuOpen, setStatusFilterMenuOpen] = useState(false);
  const [analyzingServers, setAnalyzingServers] = useState({}); // { serverId: true/false }
  const [analysisProgressServers, setAnalysisProgressServers] = useState({}); // { serverId: progress }
  const [scanErrors, setScanErrors] = useState({}); // { serverId: errorMessage }
  const [sortColumn, setSortColumn] = useState(null);
  const [sortDirection, setSortDirection] = useState(null);
  const [vulnerabilitySortColumn, setVulnerabilitySortColumn] = useState('severity'); // 기본값: severity
  const [vulnerabilitySortDirection, setVulnerabilitySortDirection] = useState('desc'); // 기본값: 높은 순
  const [serverName, setServerName] = useState('');
  const [ossIssues, setOssIssues] = useState([]);
  const [selectedOssIssue, setSelectedOssIssue] = useState(null);
  const [currentPathIndex, setCurrentPathIndex] = useState(0); // 현재 표시 중인 경로 인덱스
  const [sbomScannerData, setSbomScannerData] = useState([]);
  const [toolValidationIssues, setToolValidationIssues] = useState([]);
  const [showMcpInfoModal, setShowMcpInfoModal] = useState(false);
  const [packagesData, setPackagesData] = useState([]);
  const [toolValidationReport, setToolValidationReport] = useState(null); // Tool Validation 리포트 데이터 (tool 정보 포함)
  const [serverRiskData, setServerRiskData] = useState({}); // { serverId: { riskLevel, riskValue, language } }

  // 상태 뱃지 표시 함수
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

  // 스캔 결과를 Risk Assessment 형식으로 변환
  const formatScanResults = (findings) => {
    if (!findings || !Array.isArray(findings)) {
      return [];
    }

    // 파일 경로에서 artifacts/ 제거
    const removeArtifactsPrefix = (filePath) => {
      if (!filePath) return filePath;
      return filePath.replace(/^artifacts\//, '');
    };

    // 파일 확장자로 언어 추론
    const getLanguageFromFile = (filePath) => {
      if (!filePath) return 'Unknown';
      // artifacts/ 제거
      const cleanPath = removeArtifactsPrefix(filePath);
      
      // Dockerfile인지 확인
      const fileName = cleanPath.split('/').pop() || '';
      if (fileName.toLowerCase() === 'dockerfile' || fileName.toLowerCase().startsWith('dockerfile.')) {
        return 'Dockerfile';
      }
      
      const ext = cleanPath.split('.').pop()?.toLowerCase();
      const languageMap = {
        'js': 'JavaScript',
        'jsx': 'JavaScript',
        'ts': 'TypeScript',
        'tsx': 'TypeScript',
        'py': 'Python',
        'java': 'Java',
        'go': 'Go',
        'rb': 'Ruby',
        'php': 'PHP',
        'cpp': 'C++',
        'c': 'C',
        'cs': 'C#',
        'swift': 'Swift',
        'kt': 'Kotlin',
        'rs': 'Rust',
        'json': 'JSON',
        'md': 'MD',
        'yaml': 'YAML',
        'yml': 'YAML'
      };
      return languageMap[ext] || ext?.toUpperCase() || 'Unknown';
    };

    // rule_id에서 접두사 제거하고 취약점 이름 추출
    const extractVulnerabilityName = (ruleId) => {
      if (!ruleId) return 'Unknown Vulnerability';
      
      // 일반적인 보안 약어 목록 (모두 대문자로 표시)
      const acronyms = ['ssrf', 'sqli', 'sql', 'xss', 'csrf', 'xxe', 'rce', 'lfi', 'rfi', 'ssti', 'idor', 'authz', 'authn', 'api', 'jwt', 'oauth', 'saml', 'ldap', 'nosql', 'xml', 'json', 'http', 'https', 'tls', 'ssl', 'dns', 'ip', 'url', 'uri', 'cve', 'cwe', 'cvss', 'owasp', 'nist', 'pii', 'gdpr', 'pci', 'hipaa'];
      
      // go/, ts/, mcp/ 등의 접두사 제거
      const parts = ruleId.split('/');
      let vulnerabilityName;
      
      if (parts.length > 1) {
        // 접두사 제거 후 남은 부분을 취약점 이름으로 사용
        vulnerabilityName = parts.slice(1).join('/');
      } else {
        vulnerabilityName = ruleId;
      }
      
      // 하이픈을 공백으로 변환하고 각 단어 처리
      let formattedName = vulnerabilityName
        .split('-')
        .map(word => {
          const wordLower = word.toLowerCase();
          // 약어 목록에 있으면 모두 대문자로
          if (acronyms.includes(wordLower)) {
            return wordLower.toUpperCase();
          }
          // 그 외는 첫 글자만 대문자
          return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
        })
        .join(' ');
      
      // "Config Poisoning"으로 시작하는 경우 "Config Poisoning"까지만 표시
      if (formattedName.toLowerCase().startsWith('config poisoning')) {
        return 'Config Poisoning';
      }
      
      // "Advanced Tool Poisoning"으로 시작하는 경우 "Advanced Tool Poisoning"까지만 표시
      if (formattedName.toLowerCase().startsWith('advanced tool poisoning')) {
        return 'Advanced Tool Poisoning';
      }
      
      // "Tool Name Spoofing"으로 시작하는 경우 "Tool Name Spoofing"까지만 표시
      if (formattedName.toLowerCase().startsWith('tool name spoofing')) {
        return 'Tool Name Spoofing';
      }
      
      // "Tool Shadowing"으로 시작하는 경우 "Tool Shadowing"까지만 표시
      if (formattedName.toLowerCase().startsWith('tool shadowing')) {
        return 'Tool Shadowing';
      }
      
      // "Tool Poisoning"으로 시작하는 경우 "Tool Poisoning"까지만 표시
      if (formattedName.toLowerCase().startsWith('tool poisoning')) {
        return 'Tool Poisoning';
      }
      
      // "Schema Poisoning"으로 시작하는 경우 "Schema Poisoning"까지만 표시
      if (formattedName.toLowerCase().startsWith('schema poisoning')) {
        return 'Schema Poisoning';
      }
      
      // "Toxic Flow"로 시작하는 경우 "Toxic Flow"까지만 표시
      if (formattedName.toLowerCase().startsWith('toxic flow')) {
        return 'Toxic Flow';
      }
      
      return formattedName;
    };

    return findings.map((finding, index) => {
      // file에서 artifacts/ 제거
      const cleanFile = removeArtifactsPrefix(finding.file);
      
      // language 처리 (artifacts/ 제거 및 Dockerfile 처리)
      let language = finding.language;
      if (language) {
        // language에서 artifacts/ 제거
        language = removeArtifactsPrefix(language);
        // Dockerfile인지 확인
        const fileName = language.split('/').pop() || '';
        if (fileName.toLowerCase() === 'dockerfile' || fileName.toLowerCase().startsWith('dockerfile.')) {
          language = 'Dockerfile';
        }
      } else {
        language = getLanguageFromFile(finding.file);
      }
      
      return {
      id: index + 101,
      vulnerability: extractVulnerabilityName(finding.rule_id) || finding.message || 'Unknown Vulnerability',
      severity: finding.severity || 'unknown',
        language: language,
      reachability: 'Reachable',
        vulnerablePackage: cleanFile ? `${cleanFile}:${finding.line || 0}` : 'Unknown',
      description: finding.message || finding.description || 'No description available',
      references: {
        advisory: finding.cwe || 'Code Review',
        nvd: null
      },
        introducedThrough: cleanFile || 'Unknown',
      paths: 1,
      type: 'Code',
        // UI에서 사용할 필드들
      rule_id: finding.rule_id,
      cwe: finding.cwe,
        file: cleanFile,
      line: finding.line,
      column: finding.column,
      code_snippet: finding.code_snippet || '',
      pattern_type: finding.pattern_type || '',
      pattern: finding.pattern || '',
        confidence: finding.confidence || 1.0,
        risk_score: finding.risk_score || null
      };
    });
  };

  // 분석 시작 핸들러 (리스트 뷰에서 서버별 분석)
  const handleServerAnalysis = async (server) => {
    if (!server.github_link && !server.file_path) {
      alert('GitHub 링크 또는 파일 경로가 필요합니다.');
      return;
    }

    setAnalyzingServers(prev => ({ ...prev, [server.id]: true }));
    setAnalysisProgressServers(prev => ({ ...prev, [server.id]: { bomtori: 0, scanner: 0 } }));

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
          github_url: server.github_link || null,
          repository_path: server.file_path || null,
          mcp_server_name: server.name
        })
      });

      const data = await res.json();
      
      if (!data.success || !data.scan_id) {
        alert(data.message || '스캔 시작 실패');
        setAnalyzingServers(prev => {
          const newState = { ...prev };
          delete newState[server.id];
          return newState;
        });
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
                  ? 100 // 실패 시에도 진행바는 100% (빨간색/사선 스타일)
                  : (progress.toolVetCompleted ? 100 : (progress.toolVet !== null ? progress.toolVet : 0));
                
                // bomtori 진행률: 완료되었거나 오류가 있으면 100, 아니면 현재 진행률
                // null이거나 0이면 이전 진행률 유지 (99%에서 0%로 떨어지는 것 방지)
                setAnalysisProgressServers(prev => {
                  let bomtoriProgress;
                  if (progress.bomtoriCompleted || progress.bomtoriError) {
                    bomtoriProgress = 100;
                  } else if (progress.bomtori !== null && progress.bomtori !== undefined) {
                    bomtoriProgress = progress.bomtori;
                  } else {
                    // null이거나 undefined인 경우 이전 진행률 유지
                    const prevProgress = prev[server.id]?.bomtori;
                    bomtoriProgress = prevProgress !== undefined && prevProgress !== null ? prevProgress : 0;
                  }
                  
                  return {
                    ...prev,
                    [server.id]: {
                      bomtori: bomtoriProgress,
                      scanner: progress.scanner !== null && progress.scanner !== undefined ? progress.scanner : (prev[server.id]?.scanner || 0),
                      toolVet: toolVetProgress
                    }
                  };
                });
                
                // 개별 스캐너 오류 확인
                const errorMessages = [];
                if (progress.bomtoriError) {
                  errorMessages.push(progress.bomtoriError);
                }
                if (progress.scannerError) {
                  errorMessages.push(progress.scannerError);
                }
                
                // 오류 발생 확인 (status가 'failed'이거나 필수 스캔 오류가 있으면)
                if (progress.status === 'failed' || errorMessages.length > 0) {
                  // 오류 상태 설정
                  const errorMessage = progress.error || errorMessages.join(' / ') || '스캔 중 오류가 발생했습니다.';
                  setScanErrors(prev => ({
                    ...prev,
                    [server.id]: errorMessage
                  }));
                  setAnalyzingServers(prev => {
                    const newState = { ...prev };
                    delete newState[server.id];
                    return newState;
                  });
                  // 진행률은 유지하되 오류 메시지 표시
                  break;
                }
                
                // 필수 스캔 완료 여부 확인 (TOOL-VET 실패는 허용)
                const scannerSuccess = progress.scannerCompleted && !progress.scannerError;
                const bomtoriSuccess = progress.bomtoriCompleted && !progress.bomtoriError;
                const hasBomtori = server.github_link && server.github_link.includes('github.com');
                const hasRequiredSuccess = hasBomtori ? (scannerSuccess && bomtoriSuccess) : scannerSuccess;

                // 완료 처리: 백엔드 completed이거나 필수 스캔이 모두 성공하면 완료
                if (progress.status === 'completed' || hasRequiredSuccess) {
                  // 완료 후 결과 로드
                  // 서버 이름을 쿼리 파라미터로 추가하여 해당 서버의 데이터만 가져오도록 함
                  const normalizedServerName = server.name ? normalizeServerName(null, server.name) : null;
                  const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';
                  
                  try {
                    const vulnRes = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                      headers: {
                        'Authorization': `Bearer ${token}`
                      }
                    });
                    const vulnData = await vulnRes.json();
                    
                    if (vulnData.success && vulnData.data) {
                      const formattedIssues = formatScanResults(vulnData.data);
                      setCodeIssues(formattedIssues);
                    } else {
                      setCodeIssues([]);
                    }
                    
                    // OSS Vulnerabilities 로드
                    try {
                      const ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                        headers: {
                          'Authorization': `Bearer ${token}`
                        }
                      });
                      const ossData = await ossRes.json();
                      
                      if (ossData.success) {
                        // packages 배열도 저장 (license 정보 포함)
                        // packages가 없어도 빈 배열로 설정하여 취약점이 없는 패키지 필터링이 작동하도록 함
                        const packagesArray = Array.isArray(ossData.packages) ? ossData.packages : [];
                        // CDX dependencies 정보도 함께 저장
                        if (ossData.cdxDependencies && Array.isArray(ossData.cdxDependencies)) {
                          packagesArray.cdxDependencies = ossData.cdxDependencies;
                        }
                        setPackagesData(packagesArray);
                        
                        if (ossData.data) {
                        setOssIssues(ossData.data);
                      } else {
                        setOssIssues([]);
                        }
                      } else {
                        setOssIssues([]);
                        setPackagesData([]);
                      }
                    } catch (error) {
                      console.error('OSS 취약점 데이터 로드 실패:', error);
                      setOssIssues([]);
                      setPackagesData([]);
                    }
                    
                    // Tool Validation 데이터 로드
                    try {
                      const toolValidationRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                        headers: {
                          'Authorization': `Bearer ${token}`
                        }
                      });
                      const toolValidationData = await toolValidationRes.json();
                      
                      if (toolValidationData.success && toolValidationData.data) {
                        setToolValidationIssues(toolValidationData.data);
                      } else {
                    setToolValidationIssues([]);
                      }
                    } catch (error) {
                      console.error('Tool Validation 데이터 로드 실패:', error);
                      setToolValidationIssues([]);
                    }
                    
                    setSbomScannerData([]);
                    
                    // 결과 뷰로 전환
                    setAnalysisUrl(server.github_link || server.file_path || '');
                    setServerName(server.name || '');
                    setViewMode('result');
                    setSelectedTab('Total Vulnerabilities');
                    
                    // 서버 목록 새로고침
                    const loadMcpServers = async () => {
                      try {
                        const token = localStorage.getItem('token');
                        let statusParam = '?status=all';
                        
                        // 모든 서버를 가져오기 위해 limit를 매우 큰 값으로 설정
                        statusParam += statusParam.includes('?') ? '&limit=10000' : '?limit=10000';
                        
                        const res = await fetch(`${API_BASE_URL}/marketplace${statusParam}`, {
                          headers: {
                            'Authorization': `Bearer ${token}`
                          }
                        });
                        const data = await res.json();
                        if (data.success) {
                          setMcpServers(data.data || []);
                        }
                      } catch (error) {
                        console.error('MCP 서버 목록 로드 실패:', error);
                      }
                    };
                    
                    loadMcpServers();
                  } catch (error) {
                    console.error('결과 로드 실패:', error);
                  }
                  
                  // 상태 초기화
                  setTimeout(() => {
                    setAnalyzingServers(prev => {
                      const newState = { ...prev };
                      delete newState[server.id];
                      return newState;
                    });
                    setAnalysisProgressServers(prev => {
                      const newState = { ...prev };
                      delete newState[server.id];
                      return newState;
                    });
                    // 분석 완료 후 localStorage 클리어 (자동 결과 뷰 전환 방지)
                    // 이미 결과 뷰로 전환되었으므로 localStorage는 더 이상 필요 없음
                    localStorage.removeItem('riskAssessmentScanId');
                    localStorage.removeItem('riskAssessmentScanPath');
                    localStorage.removeItem('riskAssessmentGithubUrl');
                    localStorage.removeItem('riskAssessmentServerName');
                    localStorage.removeItem('riskAssessmentTab');
                  }, 1000);
                  
                  break;
                }
              }
            } else if (progressRes.status === 404) {
              // 진행률이 아직 생성되지 않았거나 일시적으로 없을 수 있음 (클라우드 환경에서 네트워크 지연)
              // 이전 진행률 유지 (0으로 초기화하지 않음)
              console.warn(`[진행률 폴링] 진행률 정보를 찾을 수 없음 (scan_id: ${scanId}), 이전 진행률 유지`);
              // 진행률을 업데이트하지 않고 이전 값 유지
            } else {
              // 기타 오류 (500 등)
              console.error(`[진행률 폴링] 오류 (status: ${progressRes.status})`);
              // 진행률을 업데이트하지 않고 이전 값 유지
            }
          } catch (error) {
            console.error('진행률 조회 오류:', error);
            // 네트워크 오류 등으로 인해 진행률을 가져올 수 없을 때도 이전 값 유지
          }
          
          await new Promise(resolve => setTimeout(resolve, 1000)); // 1초마다 폴링
        }
      };
      
      // 진행률 폴링 시작
      pollProgress();

      // 진행률 폴링이 완료되면 결과가 자동으로 로드됨
    } catch (error) {
      console.error('분석 오류:', error);
      alert('분석 중 오류가 발생했습니다.');
      setAnalyzingServers(prev => {
        const newState = { ...prev };
        delete newState[server.id];
        return newState;
      });
      setAnalysisProgressServers(prev => {
        const newState = { ...prev };
        delete newState[server.id];
        return newState;
      });
    }
  };

  // 분석 시작 핸들러 (기존 - 폼에서 사용)
  const handleStartAnalysis = async (e) => {
    e.preventDefault();
    if (!analysisUrl.trim()) {
      alert('GitHub URL을 입력해주세요.');
      return;
    }

    setAnalyzing(true);
    setAnalysisProgress(0);

    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE_URL}/risk-assessment/scan-code`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          github_url: analysisUrl
        })
      });

      const data = await res.json();
      
      if (data.success) {
        // scan_id로 취약점 데이터 로드
        const scanId = data.data?.scan_id || data.scan_id || null;
        if (scanId) {
          try {
            const vulnRes = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_id=${scanId}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
            const vulnData = await vulnRes.json();
            
            if (vulnData.success && vulnData.data) {
              const formattedIssues = formatScanResults(vulnData.data);
              setCodeIssues(formattedIssues);
            } else {
              setCodeIssues([]);
            }
            
            // OSS Vulnerabilities 로드
            try {
              const ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_id=${scanId}`, {
                headers: {
                  'Authorization': `Bearer ${token}`
                }
              });
              const ossData = await ossRes.json();
              
              if (ossData.success) {
                // packages 배열도 저장 (license 정보 포함)
                // packages가 없어도 빈 배열로 설정하여 취약점이 없는 패키지 필터링이 작동하도록 함
                const packagesArray = Array.isArray(ossData.packages) ? ossData.packages : [];
                // CDX dependencies 정보도 함께 저장
                if (ossData.cdxDependencies && Array.isArray(ossData.cdxDependencies)) {
                  packagesArray.cdxDependencies = ossData.cdxDependencies;
                }
                setPackagesData(packagesArray);
                
                if (ossData.data) {
                setOssIssues(ossData.data);
              } else {
                setOssIssues([]);
                }
              } else {
                setOssIssues([]);
                setPackagesData([]);
              }
            } catch (error) {
              console.error('OSS 취약점 데이터 로드 실패:', error);
              setOssIssues([]);
              setPackagesData([]);
            }
          } catch (error) {
            console.error('취약점 데이터 로드 실패:', error);
            setCodeIssues([]);
            setOssIssues([]);
            setPackagesData([]);
          }
        } else {
          setCodeIssues([]);
          setOssIssues([]);
          setPackagesData([]);
        }
        
        // Tool Validation 데이터 로드
        if (scanId) {
        try {
            // handleAnalyze는 수동 URL 입력이므로 serverName이 없을 수 있음 (옵셔널)
            const serverNameParam = serverName ? `&mcp_server_name=${encodeURIComponent(serverName)}` : '';
            const toolValidationRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });
          const toolValidationData = await toolValidationRes.json();
          
          if (toolValidationData.success && toolValidationData.data) {
            setToolValidationIssues(toolValidationData.data);
          } else {
        setToolValidationIssues([]);
          }
        } catch (error) {
          console.error('Tool Validation 데이터 로드 실패:', error);
            setToolValidationIssues([]);
          }
        } else {
          setToolValidationIssues([]);
        }
        
        setSbomScannerData([]);
        
        // 결과 뷰로 전환
        // 서버 이름 추출 (analysisUrl에서 또는 mcp_server_name에서)
        const serverNameFromUrl = analysisUrl.match(/github\.com\/[^\/]+\/([^\/]+)/)?.[1] || '';
        setServerName(serverNameFromUrl);
        setViewMode('result');
        setSelectedTab('Total Vulnerabilities');
      } else {
        alert(data.message || '분석 실패');
        // 실패 시 빈 배열로 설정
        setCodeIssues([]);
        setOssIssues([]);
        setToolValidationIssues([]);
        setSbomScannerData([]);
      }
    } catch (error) {
      console.error('분석 오류:', error);
      alert('분석 중 오류가 발생했습니다.');
    } finally {
      setAnalyzing(false);
      setAnalysisProgress(0);
    }
  };

  // 위험도 계산 함수 (Total_Risk 공식 사용)
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

  // MCP 서버 목록 로드 (필터 변경 시 실시간으로 가져오기)
  useEffect(() => {
    const loadMcpServers = async () => {
      try {
        const token = localStorage.getItem('token');
        
        // 모든 서버를 가져오기 위해 limit를 매우 큰 값으로 설정
        const res = await fetch(`${API_BASE_URL}/marketplace?status=all&limit=10000`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        const data = await res.json();
        if (data.success) {
          const allServers = data.data || [];
          
          // 분석 전/분석 후 서버 구분
          // analysis_timestamp가 있으면 분석 완료로 판단 (결과가 0이어도 분석 완료)
          const notAnalyzedServers = allServers.filter(server => {
            // analysis_timestamp가 없거나 빈 문자열이면 분석 전
            return !server.analysis_timestamp || server.analysis_timestamp.trim() === '';
          });
          
          const analyzedServers = allServers.filter(server => {
            // analysis_timestamp가 있으면 분석 후 (결과가 0이어도 분석 완료)
            return server.analysis_timestamp && server.analysis_timestamp.trim() !== '';
          });
          
          // 필터에 따라 서버 목록 설정
          if (serverFilter === 'not_analyzed') {
            setMcpServers(notAnalyzedServers);
          } else if (serverFilter === 'analyzed') {
            // 분석 후 서버에서 status 필터 적용
            let filtered = analyzedServers;
            if (statusFilter === 'pending') {
              filtered = analyzedServers.filter(server => server.status === 'pending');
            } else if (statusFilter === 'approved') {
              filtered = analyzedServers.filter(server => server.status === 'approved');
            }
            setMcpServers(filtered);
          }
          
          // 서버 개수 업데이트
          setServerCounts({
            not_analyzed: notAnalyzedServers.length,
            analyzed: analyzedServers.length
          });
        }
      } catch (error) {
        console.error('MCP 서버 목록 로드 실패:', error);
      }
    };
    
    if (viewMode === 'list') {
      loadMcpServers();
    }
  }, [viewMode, serverFilter, statusFilter]);

  // '분석 후' 탭에서 각 서버의 위험도와 언어 정보 로드
  useEffect(() => {
    const loadServerRiskData = async () => {
      if (viewMode !== 'list' || serverFilter !== 'analyzed' || mcpServers.length === 0) {
        return;
      }
      
      const token = localStorage.getItem('token');
      const riskDataMap = {};
      
      // 각 서버에 대해 위험도와 언어 정보 가져오기
      await Promise.all(mcpServers.map(async (server) => {
        try {
          const scanPath = server.github_link || server.file_path;
          if (!scanPath) return;
          
          const normalizedServerName = server.name ? normalizeServerName(server.github_link, server.name) : null;
          const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';
          
          // OSS 취약점 데이터 가져오기 (SCA_Risk 및 언어 정보용)
          let ossIssues = [];
          let language = '-';
          try {
            const ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
              headers: { 'Authorization': `Bearer ${token}` }
            });
            const ossData = await ossRes.json();
            if (ossData.success && ossData.data) {
              ossIssues = ossData.data;
              // 언어 정보는 packages의 ecosystem 정보 우선 사용
              // library, application 같은 값은 무시하고 실제 언어 정보만 사용
              if (ossData.packages && ossData.packages.length > 0) {
                // packages에서 ecosystem 정보로 프로젝트 타입 추론
                const ecosystems = new Set();
                ossData.packages.forEach(pkg => {
                  // ecosystem 필드 우선 확인
                  if (pkg.ecosystem) {
                    ecosystems.add(pkg.ecosystem);
                  } else if (pkg.purl) {
                    // PURL에서 언어 정보 추출 (예: pkg:npm/... -> npm)
                    const purlMatch = pkg.purl.match(/^pkg:([^\/]+)/);
                    if (purlMatch) {
                      ecosystems.add(purlMatch[1]);
                    }
                  }
                });
                
                const ecosystemToProjectType = {
                  'npm': 'npm',
                  'go': 'go',
                  'golang': 'go'
                };
                
                const projectTypes = Array.from(ecosystems).map(eco => {
                  return ecosystemToProjectType[eco.toLowerCase()] || eco.toLowerCase();
                });
                
                if (projectTypes.length > 0) {
                  language = projectTypes.join(', ');
                }
              }
              
              // packages에서 추출하지 못한 경우에만 projectType 확인 (library, application 제외)
              if (language === '-' && ossData.projectType && 
                  ossData.projectType !== 'library' && 
                  ossData.projectType !== 'application') {
                language = ossData.projectType;
              }
            }
          } catch (error) {
            console.error(`[${server.name}] OSS 데이터 로드 실패:`, error);
          }
          
          // Code 취약점 데이터 가져오기 (SAST_Risk용)
          let codeIssues = [];
          try {
            const codeRes = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
              headers: { 'Authorization': `Bearer ${token}` }
            });
            const codeData = await codeRes.json();
            if (codeData.success && codeData.data) {
              codeIssues = codeData.data.map(issue => formatScanResults([issue])[0]).filter(Boolean);
            }
          } catch (error) {
            console.error(`[${server.name}] Code 데이터 로드 실패:`, error);
          }
          
          // Tool Validation 통계 가져오기 (Tool_Risk용)
          let toolValidationStats = null;
          try {
            const toolRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
              headers: { 'Authorization': `Bearer ${token}` }
            });
            const toolData = await toolRes.json();
            if (toolData.success && toolData.data) {
              // 카테고리별 개수 계산
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
            language: language
          };
        } catch (error) {
          console.error(`[${server.name}] 위험도 계산 실패:`, error);
          riskDataMap[server.id] = {
            riskLevel: null,
            riskDisplayText: '-',
            language: '-'
          };
        }
      }));
      
      setServerRiskData(riskDataMap);
    };
    
    loadServerRiskData();
  }, [viewMode, serverFilter, mcpServers]);


  // localStorage에서 scanId 또는 scan_path를 읽어서 자동으로 결과 뷰로 전환
  useEffect(() => {
    const scanId = localStorage.getItem('riskAssessmentScanId');
    const scanPath = localStorage.getItem('riskAssessmentScanPath');
    const githubUrl = localStorage.getItem('riskAssessmentGithubUrl');
    const savedServerName = localStorage.getItem('riskAssessmentServerName');
    const savedTab = localStorage.getItem('riskAssessmentTab');
    
    // 저장된 탭이 있으면 설정
    if (savedTab) {
      setSelectedTab(savedTab);
    }
    
    // scanId가 있거나 scan_path가 있으면 결과 뷰로 전환
    // 단, 이미 결과 뷰에 있거나 분석 중이 아닐 때만 자동 전환 (분석 완료 후 자동 전환 방지)
    // 클라우드 환경에서 분석 완료 후 자동으로 결과 뷰로 전환되는 것을 방지
    const isAnalyzing = Object.keys(analyzingServers).length > 0;
    if ((scanId || scanPath) && (githubUrl || scanPath) && viewMode !== 'result' && !isAnalyzing) {
      // scanId 또는 scan_path로 취약점 데이터 로드
      const loadScanResults = async () => {
        try {
          const token = localStorage.getItem('token');
          
          // 서버 이름을 쿼리 파라미터로 추가하여 해당 서버의 데이터만 가져오도록 함
          // savedServerName을 정규화해서 사용 (백엔드와 일치)
          const normalizedServerName = savedServerName ? normalizeServerName(githubUrl || scanPath, savedServerName) : null;
          const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';
          console.log('[RiskAssessment useEffect] 서버 이름 파라미터:', {
            savedServerName,
            normalizedServerName,
            serverNameParam,
            scanId,
            scanPath
          });
          
          // Code Vulnerabilities 로드
          let codeRes;
          if (scanId) {
            codeRes = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else if (scanPath) {
            codeRes = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else {
            return;
          }
          
          const codeData = await codeRes.json();
          
          if (codeData.success && codeData.data) {
            const formattedIssues = formatScanResults(codeData.data);
            setCodeIssues(formattedIssues);
          } else {
            setCodeIssues([]);
          }
          
          // OSS Vulnerabilities 로드
          try {
            let ossRes;
            if (scanId) {
              ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                headers: {
                  'Authorization': `Bearer ${token}`
                }
              });
            } else if (scanPath) {
              ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
                headers: {
                  'Authorization': `Bearer ${token}`
                }
              });
            }
            
            if (ossRes) {
            const ossData = await ossRes.json();
            
            if (ossData.success && ossData.data) {
              setOssIssues(ossData.data);
                // packages 배열도 저장 (license 정보 포함)
                // packages가 없어도 빈 배열로 설정하여 취약점이 없는 패키지 필터링이 작동하도록 함
                const packagesArray = Array.isArray(ossData.packages) ? ossData.packages : [];
                // CDX dependencies 정보도 함께 저장
                if (ossData.cdxDependencies && Array.isArray(ossData.cdxDependencies)) {
                  packagesArray.cdxDependencies = ossData.cdxDependencies;
                }
                setPackagesData(packagesArray);
                console.log('OSS 데이터 로드:', {
                  취약점개수: ossData.data?.length || 0,
                  packages개수: Array.isArray(ossData.packages) ? ossData.packages.length : 0
                });
            } else {
              setOssIssues([]);
                setPackagesData([]);
              }
            }
          } catch (error) {
            console.error('OSS 취약점 데이터 로드 실패:', error);
            setOssIssues([]);
          }
          
          // Tool Validation 데이터 로드
          try {
            let toolValidationRes;
            if (scanId) {
              toolValidationRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                headers: {
                  'Authorization': `Bearer ${token}`
                }
              });
            } else if (scanPath) {
              toolValidationRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
                headers: {
                  'Authorization': `Bearer ${token}`
                }
              });
            }
            
            if (toolValidationRes) {
            const toolValidationData = await toolValidationRes.json();
            
            if (toolValidationData.success && toolValidationData.data) {
              setToolValidationIssues(toolValidationData.data);
              } else {
                setToolValidationIssues([]);
              }
            } else {
          setToolValidationIssues([]);
            }
          } catch (error) {
            console.error('Tool Validation 데이터 로드 실패:', error);
            setToolValidationIssues([]);
          }
          
          setSbomScannerData([]);
          
          setAnalysisUrl(githubUrl || scanPath);
          // 정규화된 서버 이름 저장 (백엔드와 일치)
          setServerName(normalizedServerName || savedServerName || '');
          setViewMode('result');
          // 저장된 탭이 있으면 사용, 없으면 'Total Vulnerabilities' 기본값
          setSelectedTab(savedTab || 'Total Vulnerabilities');
          
          // localStorage에서 제거
          localStorage.removeItem('riskAssessmentScanId');
          localStorage.removeItem('riskAssessmentScanPath');
          localStorage.removeItem('riskAssessmentGithubUrl');
          localStorage.removeItem('riskAssessmentServerName');
          localStorage.removeItem('riskAssessmentTab');
        } catch (error) {
          console.error('스캔 결과 로드 실패:', error);
          // 오류 발생 시 빈 배열로 설정
          setCodeIssues([]);
          setOssIssues([]);
          setToolValidationIssues([]);
          setSbomScannerData([]);
        }
      };
      
      loadScanResults();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const tabs = ['Total Vulnerabilities', 'OSS Vulnerabilities', 'Code Vulnerabilities', 'Tool Validation'];

  const getSeverityColor = (score) => {
    if (score >= 9.0) return '#dc3545'; // 빨간색
    if (score >= 7.0) return '#fd7e14'; // 주황색
    if (score >= 4.0) return '#ffc107'; // 노란색
    return '#28a745'; // 초록색
  };


  // ESC 키로 상세보기 닫기
  useEffect(() => {
    const handleEscape = (e) => {
      if (e.key === 'Escape') {
        if (selectedOssIssue) {
          setSelectedOssIssue(null);
          setCurrentPathIndex(0); // 경로 인덱스 초기화
        } else if (selectedIssue) {
        setSelectedIssue(null);
        }
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => {
      window.removeEventListener('keydown', handleEscape);
    };
  }, [selectedIssue, selectedOssIssue]);

  // Drawer 열릴 때 body에 drawer-open 클래스 추가
  useEffect(() => {
    if (selectedOssIssue) {
      document.body.classList.add('drawer-open');
    } else {
      document.body.classList.remove('drawer-open');
    }
    return () => {
      document.body.classList.remove('drawer-open');
    };
  }, [selectedOssIssue]);

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

  // Tool Validation 리포트 및 취약점 데이터 가져오기
  useEffect(() => {
    const fetchToolValidationData = async () => {
      // result 모드이고 Total Vulnerabilities 탭 또는 Tool Validation 탭에서만 데이터 로드
      if (viewMode === 'result' && (selectedTab === 'Total Vulnerabilities' || selectedTab === 'Tool Validation')) {
        try {
          const token = localStorage.getItem('token');
          let scanId = localStorage.getItem('riskAssessmentScanId');
          let scanPath = localStorage.getItem('riskAssessmentScanPath');
          const currentAnalysisUrl = analysisUrl || scanPath;
          
          // serverName이 없으면 analysisUrl(또는 scanPath)에서 서버 이름 추출
          // 정규화된 서버 이름 사용 (백엔드와 일치)
          let effectiveServerName = serverName ? normalizeServerName(null, serverName) : null;
          
          if (!effectiveServerName && currentAnalysisUrl) {
            effectiveServerName = normalizeServerName(currentAnalysisUrl, null);
            if (effectiveServerName) {
              console.log('[Tool Validation] analysisUrl에서 서버 이름 추출:', effectiveServerName);
              setServerName(effectiveServerName);
              try {
                localStorage.setItem('riskAssessmentServerName', effectiveServerName);
              } catch (e) {
                console.warn('riskAssessmentServerName 저장 실패:', e);
              }
            }
          }
          
          // 로컬에 저장된 scanId/scanPath가 다른 서버의 것이라면 무시하고 삭제
          // savedServerName도 정규화해서 비교해야 함
          const savedServerName = localStorage.getItem('riskAssessmentServerName');
          const normalizedSavedServerName = savedServerName ? normalizeServerName(null, savedServerName) : null;
          if (effectiveServerName && normalizedSavedServerName && normalizedSavedServerName !== effectiveServerName) {
            console.log('[Tool Validation] ⚠️ 서버 이름 변경 감지, 기존 scanId/scanPath 무시 및 삭제:', {
              savedServerName,
              normalizedSavedServerName,
              effectiveServerName,
              scanId,
              scanPath
            });
            scanId = null;
            scanPath = null;
            try {
              localStorage.removeItem('riskAssessmentScanId');
              localStorage.removeItem('riskAssessmentScanPath');
              localStorage.removeItem('riskAssessmentServerName');
            } catch (e) {
              console.warn('scanId/scanPath 제거 실패:', e);
            }
          } else if (effectiveServerName && normalizedSavedServerName && normalizedSavedServerName === effectiveServerName) {
            // 서버 이름이 일치하면 scanId 사용 가능
            console.log('[Tool Validation] 서버 이름 일치, scanId 사용 가능:', {
              effectiveServerName,
              scanId
            });
          }
          
          console.log('[Tool Validation] 데이터 로드 시작:', {
            viewMode,
            selectedTab,
            scanId,
            scanPath,
            analysisUrl,
            currentAnalysisUrl,
            serverName,
            effectiveServerName
          });
          
          // Tool Validation 리포트 및 취약점 데이터 로드
          const serverNameParam = effectiveServerName ? `&mcp_server_name=${encodeURIComponent(effectiveServerName)}` : '';
          console.log('[Tool Validation] serverNameParam:', serverNameParam);
          
          // 이전 데이터 초기화 (새로운 서버 데이터 로드 전)
          setToolValidationIssues([]);
          setToolValidationReport(null);
          
          // Tool Validation 리포트 로드
          let reportRes;
          if (scanId) {
            // scan_id가 있으면 우선 사용 (serverName이 있어도 없어도 상관없음)
            console.log('[Tool Validation Report] scan_id로 로드:', scanId);
            reportRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-reports?scan_id=${scanId}${serverNameParam}`, {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });
          } else if (currentAnalysisUrl) {
            // scan_id가 없으면 scan_path 사용 (serverName이 있어도 없어도 상관없음)
            console.log('[Tool Validation Report] scan_path로 로드:', currentAnalysisUrl);
            reportRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-reports?scan_path=${encodeURIComponent(currentAnalysisUrl)}${serverNameParam}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else if (effectiveServerName) {
            // scanId와 analysisUrl이 없지만 effectiveServerName이 있으면 effectiveServerName만으로 로드 시도
            console.log('[Tool Validation Report] effectiveServerName만으로 로드:', effectiveServerName);
            reportRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-reports?mcp_server_name=${encodeURIComponent(effectiveServerName)}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else {
            console.warn('[Tool Validation Report] scanId, analysisUrl, effectiveServerName 모두 없음 - 리포트 로드 건너뜀');
          }
          
          if (reportRes) {
          const reportData = await reportRes.json();
          
          if (reportData.success && reportData.data && reportData.data.length > 0) {
            // report_data가 문자열이면 파싱
            const report = reportData.data[0];
            if (typeof report.report_data === 'string') {
              report.report_data = JSON.parse(report.report_data);
            }
            setToolValidationReport(report);
            console.log('[Tool Validation Report] 로드 성공:', {
              total_tools: report.report_data?.total_tools,
              tools_length: report.report_data?.tools?.length
            });
          } else {
            setToolValidationReport(null);
            console.log('[Tool Validation Report] 데이터 없음');
          }
          } else {
          setToolValidationReport(null);
        }
          
          // Tool Validation 취약점 데이터 로드
          let vulnerabilitiesRes;
          if (scanId) {
            // scan_id가 있으면 우선 사용
            console.log('[Tool Validation Vulnerabilities] scan_id로 로드:', scanId);
            vulnerabilitiesRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else if (currentAnalysisUrl) {
            // scan_id가 없으면 scan_path 사용
            console.log('[Tool Validation Vulnerabilities] scan_path로 로드:', currentAnalysisUrl);
            vulnerabilitiesRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_path=${encodeURIComponent(currentAnalysisUrl)}${serverNameParam}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
      } else if (effectiveServerName) {
            // scanId와 analysisUrl이 없지만 effectiveServerName이 있으면 effectiveServerName만으로 로드 시도
            console.log('[Tool Validation Vulnerabilities] effectiveServerName만으로 로드:', effectiveServerName);
            vulnerabilitiesRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?mcp_server_name=${encodeURIComponent(effectiveServerName)}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else {
            console.warn('[Tool Validation Vulnerabilities] scanId, analysisUrl, effectiveServerName 모두 없음 - 취약점 데이터 로드 건너뜀');
            setToolValidationIssues([]);
          }
          
          if (vulnerabilitiesRes) {
            const vulnerabilitiesData = await vulnerabilitiesRes.json();
            
            console.log('[Tool Validation Vulnerabilities] API 응답:', {
              success: vulnerabilitiesData.success,
              dataLength: vulnerabilitiesData.data?.length || 0
            });
            
            if (vulnerabilitiesData.success && vulnerabilitiesData.data) {
              // 디버깅: 받은 데이터 확인
              console.log('[Tool Validation Vulnerabilities] 받은 데이터 샘플 (첫 3개):', 
                vulnerabilitiesData.data.slice(0, 3).map(d => ({
                  tool_name: d.tool_name,
                  host: d.host,
                  method: d.method,
                  path: d.path,
                  id: d.id
                }))
              );
              console.log('[Tool Validation Vulnerabilities] 첫 번째 데이터 전체:', vulnerabilitiesData.data[0]);
              setToolValidationIssues(vulnerabilitiesData.data);
              console.log('[Tool Validation Vulnerabilities] 로드 성공:', {
                취약점개수: vulnerabilitiesData.data?.length || 0,
                host가있는개수: vulnerabilitiesData.data.filter(d => d.host && d.host !== '').length,
                method가있는개수: vulnerabilitiesData.data.filter(d => d.method && d.method !== '').length,
                path가있는개수: vulnerabilitiesData.data.filter(d => d.path && d.path !== '').length
              });
            } else {
              setToolValidationIssues([]);
              console.log('[Tool Validation Vulnerabilities] 데이터 없음');
            }
          } else {
            setToolValidationIssues([]);
          }
        } catch (error) {
          console.error('Tool Validation 데이터 로드 실패:', error);
        setToolValidationReport(null);
          setToolValidationIssues([]);
        }
      } else if (viewMode === 'list') {
        // list 모드일 때는 데이터를 로드하지 않음
        setToolValidationIssues([]);
        setToolValidationReport(null);
      }
    };

    fetchToolValidationData();
  }, [selectedTab, analysisUrl, serverName, viewMode]);

  // Total Vulnerabilities 탭에서 OSS 데이터 로드
  useEffect(() => {
    console.log('[Total Vulnerabilities] useEffect 실행:', {
      selectedTab,
      analysisUrl,
      조건만족: selectedTab === 'Total Vulnerabilities' && analysisUrl
    });
    
    const fetchOssData = async () => {
      console.log('[Total Vulnerabilities] fetchOssData 시작:', {
        selectedTab,
        analysisUrl,
        조건만족: selectedTab === 'Total Vulnerabilities' && analysisUrl
      });
      
      // Total Vulnerabilities 탭이면 analysisUrl이 없어도 데이터 로드 시도
      if (selectedTab === 'Total Vulnerabilities') {
        try {
          const token = localStorage.getItem('token');
          const scanId = localStorage.getItem('riskAssessmentScanId');
          
          console.log('[Total Vulnerabilities] API 호출 준비:', {
            scanId,
            analysisUrl,
            token: token ? '있음' : '없음'
          });
          
          let ossRes;
          let apiUrl;
          const serverNameParam = serverName ? `&mcp_server_name=${encodeURIComponent(serverName)}` : '';
          
          // scan_id가 있으면 우선 사용, 없으면 scan_path 사용, 둘 다 없으면 모든 데이터 조회
          if (scanId) {
            apiUrl = `${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_id=${scanId}${serverNameParam}`;
            console.log('[Total Vulnerabilities] scan_id로 API 호출:', apiUrl);
            ossRes = await fetch(apiUrl, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else if (analysisUrl) {
            apiUrl = `${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_path=${encodeURIComponent(analysisUrl)}${serverNameParam}`;
            console.log('[Total Vulnerabilities] scan_path로 API 호출:', apiUrl);
            ossRes = await fetch(apiUrl, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else {
            // scan_id와 analysisUrl이 모두 없으면 API 호출하지 않음 (백엔드에서 scan_id 또는 scan_path 필수)
            console.log('[Total Vulnerabilities] scan_id와 analysisUrl이 없어서 OSS 취약점 조회 건너뜀');
            ossRes = null;
          }
          
          if (ossRes) {
          console.log('[Total Vulnerabilities] API 응답 상태:', {
            status: ossRes.status,
            statusText: ossRes.statusText,
            ok: ossRes.ok
          });
          
            const ossData = await ossRes.json();
            
            console.log('[Total Vulnerabilities] OSS API 응답:', {
              success: ossData.success,
              dataLength: ossData.data?.length || 0,
              packagesLength: ossData.packages?.length || 0,
              packagesType: Array.isArray(ossData.packages) ? 'array' : typeof ossData.packages,
              packagesSample: ossData.packages?.slice(0, 3) || '없음'
            });
            
            if (ossData.success && ossData.data) {
              setOssIssues(ossData.data);
              const packagesArray = Array.isArray(ossData.packages) ? ossData.packages : [];
              // CDX dependencies 정보도 함께 저장
              if (ossData.cdxDependencies && Array.isArray(ossData.cdxDependencies)) {
                packagesArray.cdxDependencies = ossData.cdxDependencies;
              }
              setPackagesData(packagesArray);
              console.log('[Total Vulnerabilities] OSS 데이터 로드 성공:', {
                취약점개수: ossData.data?.length || 0,
                packages개수: packagesArray.length,
                packagesSample: packagesArray.slice(0, 3)
              });
            } else {
              setOssIssues([]);
              setPackagesData([]);
              console.log('[Total Vulnerabilities] OSS 데이터 없음');
            }
          }
        } catch (error) {
          console.error('[Total Vulnerabilities] ❌ OSS 데이터 로드 실패:', error);
          console.error('[Total Vulnerabilities] 에러 상세:', {
            message: error.message,
            stack: error.stack
          });
          setOssIssues([]);
          setPackagesData([]);
        }
      } else {
        // Total Vulnerabilities 탭이 아니면 OSS 데이터를 로드하지 않음
        // (다른 탭에서는 필요할 때 별도로 로드함)
        console.log('[Total Vulnerabilities] OSS 데이터 로드 건너뜀:', {
          selectedTab,
          reason: selectedTab !== 'Total Vulnerabilities'
        });
      }
    };

    fetchOssData();
  }, [selectedTab, analysisUrl, serverName]);

  // Total Vulnerabilities 탭에서 Code Vulnerabilities 데이터 로드
  useEffect(() => {
    const fetchCodeData = async () => {
      // Total Vulnerabilities 탭이면 데이터 로드 시도
      if (selectedTab === 'Total Vulnerabilities') {
        try {
          const token = localStorage.getItem('token');
          const scanId = localStorage.getItem('riskAssessmentScanId');
          
          let codeRes;
          let apiUrl;
          const serverNameParam = serverName ? `&mcp_server_name=${encodeURIComponent(serverName)}` : '';
          
          // scan_id가 있으면 우선 사용, 없으면 scan_path 사용
          if (scanId) {
            apiUrl = `${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_id=${scanId}${serverNameParam}`;
            codeRes = await fetch(apiUrl, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else if (analysisUrl) {
            apiUrl = `${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_path=${encodeURIComponent(analysisUrl)}${serverNameParam}`;
            codeRes = await fetch(apiUrl, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
          } else {
            // scan_id와 analysisUrl이 모두 없으면 데이터 로드하지 않음
            return;
          }
          
          if (codeRes) {
            const codeData = await codeRes.json();
            
            if (codeData.success && codeData.data) {
              const formattedIssues = formatScanResults(codeData.data);
              setCodeIssues(formattedIssues);
            } else {
              setCodeIssues([]);
            }
          }
        } catch (error) {
          console.error('[Total Vulnerabilities] Code 데이터 로드 실패:', error);
          setCodeIssues([]);
        }
      }
    };

    fetchCodeData();
  }, [selectedTab, analysisUrl, serverName]);

  // 심각도 점수 계산 함수 (CVSS 점수 우선, 없으면 심각도 텍스트를 점수로 변환)
  const getSeverityScore = (severity, cvss) => {
    // CVSS 점수가 있으면 사용
    if (cvss !== null && cvss !== undefined) {
      return cvss;
    }
    
    // 심각도 텍스트를 점수로 변환
    const severityLower = (severity || 'unknown').toLowerCase();
    const severityMap = {
      'critical': 9.5,
      'high': 8.0,
      'medium': 6.0,
      'low': 4.0,
      'info': 2.0,
      'unknown': 0
    };
    return severityMap[severityLower] || 0;
  };

  const getCurrentIssues = () => {
    let issues = [];
    
    switch (selectedTab) {
      case 'OSS Vulnerabilities':
        // 취약점이 있는 항목만 표시 (하나의 패키지에 여러 취약점이 있으면 모두 표시)
        issues = ossIssues.map((issue, index) => {
          const pkgName = issue.package?.name;
          const vulnId = issue.vulnerability?.id;
          // packagesData에서 해당 패키지 찾기 (license 정보를 위해)
          const pkgData = packagesData.find(p => p.name === pkgName);
          
          return {
          ...issue,
            // 각 취약점마다 고유한 ID 생성 (패키지명 + 취약점 ID)
            id: issue.id || `oss-${index}-${pkgName}-${vulnId || index}`,
            severityScore: getSeverityScore(issue.vulnerability?.severity, issue.vulnerability?.cvss),
            // packagesData에서 license 정보 추가
            package: {
              ...issue.package,
              license: pkgData?.license || (Array.isArray(pkgData?.licenses) && pkgData.licenses[0]) || issue.package?.license || '',
              licenses: pkgData?.licenses || issue.package?.licenses || []
            }
          };
        });
        
        break;
      case 'Code Vulnerabilities':
        issues = codeIssues.map(issue => ({
          ...issue,
          severityScore: getSeverityScore(issue.severity, null)
        }));
        break;
      case 'Tool Validation':
        issues = toolValidationIssues;
        break;
      case 'Total Vulnerabilities':
        const ossWithScore = ossIssues.map((issue, index) => ({
          ...issue,
          id: issue.id || `oss-${index}-${issue.package?.name}-${issue.vulnerability?.id}`,
          severityScore: getSeverityScore(issue.vulnerability?.severity, issue.vulnerability?.cvss)
        }));
        const codeWithScore = codeIssues.map(issue => ({
          ...issue,
          severityScore: getSeverityScore(issue.severity, null)
        }));
        issues = [...ossWithScore, ...codeWithScore, ...toolValidationIssues];
        break;
      default:
        return [];
    }
    
    // 검색 필터 적용
    if (searchTerm && searchTerm.trim()) {
      const term = searchTerm.trim().toLowerCase();
      issues = issues.filter(issue => {
        // Tool Validation 검색
        if (selectedTab === 'Tool Validation') {
          const toolName = issue.tool_name || '';
          const host = issue.host || '';
          const method = issue.method || '';
          const path = issue.path || '';
          const categoryCode = issue.category_code || '';
          const categoryName = issue.category_name || '';
          const title = issue.title || '';
          const desc = issue.description || '';
          return (
            toolName.toLowerCase().includes(term) ||
            host.toLowerCase().includes(term) ||
            method.toLowerCase().includes(term) ||
            path.toLowerCase().includes(term) ||
            categoryCode.toLowerCase().includes(term) ||
            categoryName.toLowerCase().includes(term) ||
            title.toLowerCase().includes(term) ||
            desc.toLowerCase().includes(term)
          );
        }
        // OSS Vulnerabilities 검색
        if (selectedTab === 'OSS Vulnerabilities' || selectedTab === 'Total Vulnerabilities') {
          const pkgName = issue.package?.name || '';
          const vulnId = issue.vulnerability?.cve || issue.vulnerability?.id || '';
          const vulnTitle = issue.vulnerability?.title || '';
          const vulnDesc = issue.vulnerability?.description || '';
          const version = issue.package?.current_version || '';
          return (
            pkgName.toLowerCase().includes(term) ||
            vulnId.toLowerCase().includes(term) ||
            vulnTitle.toLowerCase().includes(term) ||
            vulnDesc.toLowerCase().includes(term) ||
            version.toLowerCase().includes(term)
          );
        }
        // Code Vulnerabilities 검색
        if (selectedTab === 'Code Vulnerabilities' || selectedTab === 'Total Vulnerabilities') {
          const vuln = issue.vulnerability || issue.rule_id || '';
          const desc = issue.description || issue.message || '';
          const file = issue.vulnerablePackage || issue.file || '';
          return (
            vuln.toString().toLowerCase().includes(term) ||
            desc.toLowerCase().includes(term) ||
            file.toLowerCase().includes(term)
          );
        }
        return true;
      });
    }
    
    // 정렬 적용
    if (vulnerabilitySortColumn && vulnerabilitySortDirection) {
      issues.sort((a, b) => {
        let aValue, bValue;
        
        if (vulnerabilitySortColumn === 'severity') {
          aValue = a.severityScore || 0;
          bValue = b.severityScore || 0;
        } else if (vulnerabilitySortColumn === 'cvss') {
          aValue = a.vulnerability?.cvss || a.cvss || 0;
          bValue = b.vulnerability?.cvss || b.cvss || 0;
        } else {
          aValue = a[vulnerabilitySortColumn] || '';
          bValue = b[vulnerabilitySortColumn] || '';
        }
        
        if (vulnerabilitySortDirection === 'desc') {
          return bValue > aValue ? 1 : bValue < aValue ? -1 : 0;
        } else {
          return aValue > bValue ? 1 : aValue < bValue ? -1 : 0;
        }
      });
    }
    
    return issues;
  };

  const renderSBOMScannerContent = () => {
    // CDX JSON의 dependencies를 기반으로 실제 depth 계산 함수 (개선된 버전)
    const calculateMaxDepthFromCDX = (packages, dependencies) => {
      if (!dependencies || !Array.isArray(dependencies) || dependencies.length === 0) {
        return { maxDepth: 0, packageDepthMap: new Map() };
      }

      console.log('[Depth 계산] 시작 - dependencies 개수:', dependencies.length, 'packages 개수:', packages?.length || 0);

      // 1. bom-ref를 key로 하는 의존성 그래프 구성
      const dependencyGraph = new Map(); // ref -> [dependsOn refs]
      const reverseGraph = new Map(); // ref -> [이 패키지를 의존하는 부모 refs]
      const refToNameMap = new Map(); // bom-ref -> 패키지 이름 맵
      const nameToRefMap = new Map(); // 패키지 이름 -> bom-ref 맵
      
      // 2. packages 배열에서 ref와 이름 매핑 생성
      if (packages && Array.isArray(packages)) {
        packages.forEach(pkg => {
          if (!pkg.name) return;
          
          // ref 찾기 (우선순위: bomRef > purl > purl_id)
          let ref = pkg.bomRef || pkg.purl || pkg.purl_id;
          
          // ref가 없으면 purl 형식으로 생성 시도
          if (!ref && pkg.name) {
            // npm 패키지
            if (pkg.name && !pkg.name.includes('/') && !pkg.name.startsWith('golang.org/') && !pkg.name.startsWith('github.com/')) {
              const version = pkg.version || '';
              ref = `pkg:npm/${pkg.name}${version ? '@' + version : ''}`;
            }
            // Go 패키지
            else if (pkg.name.startsWith('golang.org/') || pkg.name.startsWith('github.com/') || 
                     pkg.name.startsWith('go.uber.org/') || pkg.name.startsWith('google.golang.org/') ||
                     pkg.name.startsWith('gopkg.in/') || pkg.name.includes('/')) {
              const version = pkg.version || '';
              ref = `pkg:golang/${pkg.name}${version ? '@' + version : ''}`;
            }
          }
          
          if (ref) {
            refToNameMap.set(ref, pkg.name);
            nameToRefMap.set(pkg.name, ref);
          }
        });
      }
      
      // 3. dependencies 배열에서 ref와 이름 매핑 보완 및 그래프 구성
      dependencies.forEach(dep => {
        if (!dep.ref) return;
        
        // ref에서 패키지 이름 추출 (아직 매핑되지 않은 경우)
        if (!refToNameMap.has(dep.ref)) {
          // pkg:type/name@version 형식에서 name 추출
          const match = dep.ref.match(/pkg:[^/]+\/([^@]+)/);
          if (match) {
            const extractedName = match[1];
            refToNameMap.set(dep.ref, extractedName);
            if (!nameToRefMap.has(extractedName)) {
              nameToRefMap.set(extractedName, dep.ref);
            }
          }
        }
        
        // 의존성 그래프 구성
        if (dep.dependsOn && Array.isArray(dep.dependsOn) && dep.dependsOn.length > 0) {
          dependencyGraph.set(dep.ref, dep.dependsOn);
          
          // 역방향 그래프 구성 (부모 찾기용)
          dep.dependsOn.forEach(childRef => {
            if (!reverseGraph.has(childRef)) {
              reverseGraph.set(childRef, []);
            }
            reverseGraph.get(childRef).push(dep.ref);
          });
        }
      });

      console.log('[Depth 계산] 그래프 구성 완료 - 노드 수:', dependencyGraph.size);

      // 4. 루트 패키지 찾기 (의존성으로 참조되지 않는 패키지 = 메인 컴포넌트)
      const allDependents = new Set();
      dependencyGraph.forEach((deps) => {
        deps.forEach(dep => allDependents.add(dep));
      });
      
      // 루트는 dependencyGraph에 있지만 allDependents에 없는 노드
      const rootRefs = new Set();
      dependencyGraph.forEach((deps, ref) => {
        if (!allDependents.has(ref)) {
          rootRefs.add(ref);
        }
      });
      
      // 루트가 없으면 첫 번째 dependency를 루트로 사용
      if (rootRefs.size === 0 && dependencies.length > 0 && dependencies[0].ref) {
        rootRefs.add(dependencies[0].ref);
      }

      console.log('[Depth 계산] 루트 패키지 수:', rootRefs.size);

      // 5. 각 패키지의 depth 계산 (BFS 방식 - 정확한 depth 계산)
      const depthMap = new Map();
      
      // 루트 패키지들을 depth 0으로 초기화
      rootRefs.forEach(rootRef => {
        depthMap.set(rootRef, 0);
      });
      
      // BFS로 depth 계산: 부모의 depth + 1 = 자식의 depth
      // 변경이 없을 때까지 반복 (모든 노드의 depth가 안정화될 때까지)
      let changed = true;
      let iterations = 0;
      const maxIterations = 200; // 충분한 반복 허용 (깊은 의존성 체인 처리)
      
      while (changed && iterations < maxIterations) {
        changed = false;
        iterations++;
        
        // 모든 dependency 관계를 확인하여 depth 업데이트
        dependencyGraph.forEach((deps, parentRef) => {
          // 부모의 depth 가져오기 (루트는 0)
          const parentDepth = depthMap.get(parentRef);
          if (parentDepth === undefined) {
            // 부모의 depth가 아직 계산되지 않았으면 건너뛰기
            return;
          }
          
          // 자식들의 depth를 부모의 depth + 1로 설정
          deps.forEach(childRef => {
            const currentChildDepth = depthMap.get(childRef);
            const newChildDepth = parentDepth + 1;
            
            // 자식의 depth가 아직 설정되지 않았거나, 더 작은 값이면 업데이트
            // 최소 depth를 유지 (같은 패키지가 여러 경로에서 참조될 수 있음)
            if (currentChildDepth === undefined || newChildDepth < currentChildDepth) {
              depthMap.set(childRef, newChildDepth);
              changed = true;
            }
          });
        });
      }
      
      if (iterations >= maxIterations) {
        console.warn('[Depth 계산] 최대 반복 횟수 도달 - 일부 노드의 depth가 계산되지 않았을 수 있음');
      }
      
      // 모든 노드가 계산되었는지 확인하고, 누락된 노드 처리
      dependencyGraph.forEach((deps, ref) => {
        if (!depthMap.has(ref)) {
          // 이 노드를 의존하는 부모 노드들 중 최소 depth 찾기
          let minParentDepth = Infinity;
          const parents = reverseGraph.get(ref);
          if (parents && parents.length > 0) {
            parents.forEach(parentRef => {
              const parentDepth = depthMap.get(parentRef);
              if (parentDepth !== undefined && parentDepth < minParentDepth) {
                minParentDepth = parentDepth;
              }
            });
          }
          
          if (minParentDepth !== Infinity) {
            depthMap.set(ref, minParentDepth + 1);
          } else {
            // 부모를 찾을 수 없으면 depth 1로 설정 (직접 의존성으로 간주)
            depthMap.set(ref, 1);
          }
        }
      });
      
      console.log('[Depth 계산] BFS 완료 - 반복 횟수:', iterations, 'depthMap 크기:', depthMap.size);
      
      // 디버깅: depth가 5 이상인 패키지 확인 (실제 의존성 체인 확인용)
      const highDepthPackages = [];
      depthMap.forEach((d, ref) => {
        if (d >= 5) {
          highDepthPackages.push({ ref, depth: d });
        }
      });
      if (highDepthPackages.length > 0) {
        console.warn('[Depth 계산] ⚠️ 높은 depth 발견 (depth >= 5):', highDepthPackages.slice(0, 20));
        // 가장 깊은 패키지의 의존성 체인 추적
        const deepest = highDepthPackages.sort((a, b) => b.depth - a.depth)[0];
        if (deepest) {
          console.log('[Depth 계산] 가장 깊은 패키지:', deepest.ref, 'depth:', deepest.depth);
          // 이 패키지의 의존성 체인 추적 (루트부터)
          const traceChainToRoot = (ref, currentDepth, visited = new Set()) => {
            if (currentDepth <= 0 || visited.has(ref) || currentDepth > 10) {
              return [];
            }
            visited.add(ref);
            
            // 이 패키지를 의존하는 부모 패키지들 찾기
            const parents = reverseGraph.get(ref) || [];
            const chain = [];
            
            for (const parentRef of parents) {
              const parentDepth = depthMap.get(parentRef);
              if (parentDepth !== undefined && parentDepth === currentDepth - 1) {
                const parentChain = traceChainToRoot(parentRef, parentDepth, new Set(visited));
                if (parentChain.length > 0 || parentDepth === 0) {
                  chain.push({
                    ref: parentRef,
                    depth: parentDepth,
                    chain: parentChain
                  });
                }
              }
            }
            
            return chain;
          };
          
          // 가장 깊은 패키지부터 루트까지의 체인 추적
          const buildChain = (ref, depth) => {
            if (depth === 0) {
              return [{ ref, depth }];
            }
            const parents = reverseGraph.get(ref) || [];
            for (const parentRef of parents) {
              const parentDepth = depthMap.get(parentRef);
              if (parentDepth === depth - 1) {
                return [...buildChain(parentRef, parentDepth), { ref, depth }];
              }
            }
            return [{ ref, depth }];
          };
          
          const chain = buildChain(deepest.ref, deepest.depth);
          console.log('[Depth 계산] 의존성 체인 추적 (루트 → 가장 깊은 패키지):');
          chain.forEach((item, idx) => {
            console.log(`  depth ${item.depth}: ${item.ref}`);
          });
        }
      }
      
      // depth 분포 확인
      const depthDistribution = new Map();
      depthMap.forEach((d) => {
        depthDistribution.set(d, (depthDistribution.get(d) || 0) + 1);
      });
      console.log('[Depth 계산] Depth 분포:', Array.from(depthDistribution.entries()).sort((a, b) => a[0] - b[0]));
      
      // 6. 패키지 이름으로 depth 매핑
      const packageDepthMap = new Map();
      
      // packages 배열의 각 패키지에 대해 depth 찾기
      if (packages && Array.isArray(packages)) {
        packages.forEach(pkg => {
          if (!pkg.name) return;
          
          // ref 찾기
          let ref = pkg.bomRef || pkg.purl || pkg.purl_id || nameToRefMap.get(pkg.name);
          
          // ref가 없으면 생성 시도
          if (!ref) {
            if (pkg.name && !pkg.name.includes('/') && !pkg.name.startsWith('golang.org/') && !pkg.name.startsWith('github.com/')) {
              const version = pkg.version || '';
              ref = `pkg:npm/${pkg.name}${version ? '@' + version : ''}`;
            } else if (pkg.name.startsWith('golang.org/') || pkg.name.startsWith('github.com/') || 
                       pkg.name.startsWith('go.uber.org/') || pkg.name.startsWith('google.golang.org/') ||
                       pkg.name.startsWith('gopkg.in/') || pkg.name.includes('/')) {
              const version = pkg.version || '';
              ref = `pkg:golang/${pkg.name}${version ? '@' + version : ''}`;
            }
          }
          
          if (ref) {
            // 직접 매칭
            let depth = depthMap.get(ref);
            
            // 직접 매칭 실패 시 부분 매칭 시도 (버전 정보 제외)
            if (depth === undefined || depth === null) {
              for (const [depRef, depDepth] of depthMap.entries()) {
                // ref에서 패키지 이름 부분 추출하여 비교
                const refName = ref.replace(/^pkg:[^/]+\//, '').replace(/@.*$/, '');
                const depRefName = depRef.replace(/^pkg:[^/]+\//, '').replace(/@.*$/, '');
                
                if (refName === depRefName || depRef.includes(pkg.name) || ref.includes(pkg.name)) {
                  depth = depDepth;
                  break;
                }
              }
            }
            
            if (depth !== undefined && depth !== null) {
              packageDepthMap.set(pkg.name, depth);
            }
          }
        });
      }
      
      // 7. 최대 depth 계산
      let maxDepth = 0;
      depthMap.forEach((depth) => {
        if (depth > maxDepth) {
          maxDepth = depth;
        }
      });
      
      console.log('[Depth 계산] 완료 - 최대 depth:', maxDepth, '패키지 depth 매핑:', packageDepthMap.size);
      
      return { maxDepth, packageDepthMap };
    };

    // OSS Vulnerabilities 통계 계산
    const ossStats = (() => {
      // packagesData가 있으면 사용, 없으면 ossIssues에서 추론
      const allPackages = packagesData && packagesData.length > 0 ? packagesData : [];
      const hasPackagesData = allPackages.length > 0;
      
      // CDX JSON dependencies 정보 (별도 state나 packagesData에서 전달)
      // 백엔드에서 cdxDependencies를 별도로 전달하므로, 이는 별도 state로 관리하거나 packagesData의 속성으로 사용
      const cdxDependencies = packagesData?.cdxDependencies || null;
      
      console.log('[ossStats 계산 시작]', {
        packagesDataLength: packagesData?.length || 0,
        allPackagesLength: allPackages.length,
        hasPackagesData,
        ossIssuesLength: ossIssues?.length || 0,
        ossIssues: ossIssues?.slice(0, 3) // 처음 3개만 로그
      });
      
      if (!hasPackagesData && (!ossIssues || ossIssues.length === 0)) {
        console.log('[ossStats] 데이터 없음 - 빈 객체 반환');
        return {
          projectType: null,
          totalPackages: 0,
          directDependencies: 0,
          transitiveDependencies: 0,
          vulnerablePackages: 0,
          reachableVulnerabilities: 0,
          totalVulnerabilities: 0,
          externalPackages: 0,
          internalPackages: 0,
          maxDepth: 0
        };
      }

      // 프로젝트 타입 추론
      let projectType = null;
      if (hasPackagesData) {
        // packagesData에서 프로젝트 타입 추론
        const goPackages = allPackages.filter(pkg => 
          pkg.name && (
            pkg.name.startsWith('golang.org/') || 
            pkg.name.startsWith('github.com/') ||
            pkg.name.startsWith('go.uber.org/') ||
            pkg.name.startsWith('google.golang.org/') ||
            pkg.name.startsWith('gopkg.in/') ||
            pkg.purl && pkg.purl.startsWith('pkg:golang/')
          )
        );
        const npmPackages = allPackages.filter(pkg => 
          pkg.name && 
          !pkg.name.startsWith('golang.org/') && 
          !pkg.name.startsWith('github.com/') && 
          !pkg.name.startsWith('go.uber.org/') &&
          !pkg.name.startsWith('google.golang.org/') &&
          !pkg.name.startsWith('gopkg.in/') &&
          !pkg.name.includes('/') &&
          (!pkg.purl || pkg.purl.startsWith('pkg:npm/'))
        );
        
        if (goPackages.length > npmPackages.length && goPackages.length > 0) {
          projectType = 'Go';
        } else if (npmPackages.length > 0) {
          projectType = 'NPM';
        }
      } else {
        // ossIssues에서 프로젝트 타입 추론
        const goPackages = ossIssues.filter(issue => 
          issue.package_name && (
            issue.package_name.startsWith('golang.org/') || 
            issue.package_name.startsWith('github.com/') ||
            issue.package_name.startsWith('go.uber.org/') ||
            issue.package_name.startsWith('google.golang.org/') ||
            issue.package_name.startsWith('gopkg.in/')
          )
        );
        const npmPackages = ossIssues.filter(issue => 
          issue.package_name && 
          !issue.package_name.startsWith('golang.org/') && 
          !issue.package_name.startsWith('github.com/') && 
          !issue.package_name.startsWith('go.uber.org/') &&
          !issue.package_name.startsWith('google.golang.org/') &&
          !issue.package_name.startsWith('gopkg.in/') &&
          !issue.package_name.includes('/')
        );
        
        if (goPackages.length > npmPackages.length && goPackages.length > 0) {
          projectType = 'Go';
        } else if (npmPackages.length > 0) {
          projectType = 'NPM';
        }
      }

      // 패키지별로 그룹화 (중복 제거, 메인 패키지 제외)
      const uniquePackages = new Set();
      const directDeps = new Set();
      const transitiveDeps = new Set();
      const vulnerablePkgs = new Set();
      const externalPackages = new Set(); // 외부 패키지 (github.com, golang.org 등)
      const internalPackages = new Set(); // 내부 패키지
      const depthMap = new Map(); // 패키지별 depth
      let reachableCount = 0;
      let totalVulnCount = 0;
      let maxDepth = 0;

      // CDX dependencies로 depth 계산 (한 번만 실행)
      let calculatedPackageDepthMap = null;
      let calculatedMaxDepthFromCDX = 0;
      if (cdxDependencies && Array.isArray(cdxDependencies) && cdxDependencies.length > 0) {
        console.log('[ossStats] CDX dependencies로 depth 계산 시작...');
        const result = calculateMaxDepthFromCDX(allPackages, cdxDependencies);
        calculatedPackageDepthMap = result.packageDepthMap;
        calculatedMaxDepthFromCDX = result.maxDepth;
        console.log('[ossStats] CDX dependencies로 계산된 최대 depth:', calculatedMaxDepthFromCDX);
      }

      // packagesData에서 전체 패키지 정보 수집
      if (hasPackagesData) {
        console.log('[ossStats] packagesData 처리 시작, 총 패키지 수:', allPackages.length);
        let processedCount = 0;
        let skippedCount = 0;
        
        allPackages.forEach(pkg => {
          if (!pkg.name) {
            skippedCount++;
            return;
          }
          
          // 메인 패키지 제외: dependency_type이 null이거나 빈 값인 경우 제외
          if (!pkg.dependency_type || pkg.dependency_type === '') {
            skippedCount++;
            return; // 메인 패키지는 제외
          }

          processedCount++;
          uniquePackages.add(pkg.name);
          
          // 외부/내부 패키지 구분
          const isExternal = pkg.name.includes('.') && 
                            (pkg.name.startsWith('github.com/') ||
                             pkg.name.startsWith('golang.org/') ||
                             pkg.name.startsWith('go.uber.org/') ||
                             pkg.name.startsWith('google.golang.org/') ||
                             pkg.name.startsWith('gopkg.in/') ||
                             pkg.name.includes('/'));
          
          if (isExternal) {
            externalPackages.add(pkg.name);
          } else {
            internalPackages.add(pkg.name);
          }
          
          if (pkg.dependency_type === 'direct') {
            directDeps.add(pkg.name);
          } else if (pkg.dependency_type === 'transitive') {
            transitiveDeps.add(pkg.name);
          }

          // Depth 계산: 우선순위 1) packagePath, 2) CDX dependencies, 3) fallback
          let depth = 0;
          let depthSource = 'none';
          
          // 1. npm 패키지의 경우 packagePath에서 depth 계산 (가장 정확)
          if (pkg.properties && Array.isArray(pkg.properties)) {
            const packagePathProp = pkg.properties.find(prop => prop.name === 'npm:packagePath');
            if (packagePathProp && packagePathProp.value) {
              const packagePath = packagePathProp.value;
              // node_modules가 몇 번 나타나는지 세기
              // node_modules/package = depth 1
              // node_modules/package/node_modules/package2 = depth 2
              const nodeModulesCount = (packagePath.match(/\/node_modules\//g) || []).length;
              if (nodeModulesCount > 0) {
                // npm:packagePath에서 depth 계산: node_modules가 N번 나타나면 depth N
                // 예: node_modules/package = depth 1
                //     node_modules/package/node_modules/package2 = depth 2
                depth = nodeModulesCount;
                depthSource = 'packagePath';
              }
            }
          }
          
          // 2. packagePath로 계산되지 않았으면 CDX dependencies에서 계산된 depth 사용
          if (depth === 0 && calculatedPackageDepthMap) {
            const calculatedDepth = calculatedPackageDepthMap.get(pkg.name);
            if (calculatedDepth !== undefined && calculatedDepth !== null && calculatedDepth > 0) {
              depth = calculatedDepth;
              depthSource = 'cdxDependencies';
            }
          }
          
          // 3. CDX dependencies로 계산되지 않았으면 패키지 데이터의 depth 필드 확인
          if (depth === 0) {
            if (pkg.dependency_depth !== undefined && pkg.dependency_depth !== null) {
              depth = parseInt(pkg.dependency_depth) || 0;
              depthSource = 'dependency_depth';
            } else if (pkg.depth !== undefined && pkg.depth !== null) {
              depth = parseInt(pkg.depth) || 0;
              depthSource = 'depth';
            } else {
              // depth 정보가 없으면 dependency_type으로 추정 (fallback)
              if (pkg.dependency_type === 'direct') {
                depth = 1;
                depthSource = 'dependency_type_direct';
              } else if (pkg.dependency_type === 'transitive') {
                depth = 2; // 최소값, 실제로는 더 깊을 수 있음
                depthSource = 'dependency_type_transitive';
              }
            }
          }
          
          // 디버깅: depth가 10 이상이면 로그 출력
          if (depth >= 10) {
            console.warn(`[Depth 계산] 높은 depth 발견:`, {
              packageName: pkg.name,
              depth,
              depthSource,
              packagePath: pkg.properties?.find(prop => prop.name === 'npm:packagePath')?.value,
              calculatedDepth: calculatedPackageDepthMap?.get(pkg.name),
              dependency_type: pkg.dependency_type
            });
          }
          
          if (depth > maxDepth) {
            maxDepth = depth;
          }
          if (!depthMap.has(pkg.name) || depthMap.get(pkg.name) < depth) {
            depthMap.set(pkg.name, depth);
          }
        });
        console.log('[ossStats] packagesData 처리 완료:', {
          processedCount,
          skippedCount,
          uniquePackages: uniquePackages.size,
          directDeps: directDeps.size,
          transitiveDeps: transitiveDeps.size
        });
      }

      // ossIssues에서 취약점 정보 수집
      if (ossIssues && ossIssues.length > 0) {
        console.log('[ossStats] ossIssues 처리 시작, 총 이슈 수:', ossIssues.length);
        let processedIssues = 0;
        let skippedIssues = 0;
        let packageNameIssues = 0;
        
        // 처음 5개 패키지의 dependency_type 확인
        const sampleIssues = ossIssues.slice(0, 5).filter(issue => issue.package_name);
        console.log('[ossStats] 샘플 패키지 dependency_type:', sampleIssues.map(issue => ({
          package_name: issue.package_name,
          package_dependency_type: issue.package_dependency_type,
          package_dependency_depth: issue.package_dependency_depth
        })));
        
        ossIssues.forEach(issue => {
          if (issue.package_name) {
            packageNameIssues++;
            
            // package_dependency_type 확인
            const depType = issue.package_dependency_type;
            
            // 메인 패키지 제외: package_dependency_type이 null이거나 빈 값인 경우 제외
            // 하지만 stdlib은 제외하지 않음 (stdlib도 의존성으로 간주)
            if (depType === null || depType === '' || depType === undefined) {
              // stdlib은 제외하지 않음
              if (issue.package_name && !issue.package_name.includes('stdlib') && !issue.package_name.startsWith('crypto/') && !issue.package_name.startsWith('net/')) {
                skippedIssues++;
                return; // 메인 패키지는 제외
              }
            }

            processedIssues++;
            // packagesData가 없으면 uniquePackages에도 추가
            if (!hasPackagesData) {
              uniquePackages.add(issue.package_name);
              
              // 외부/내부 패키지 구분
              const isExternal = issue.package_name.includes('.') && 
                                (issue.package_name.startsWith('github.com/') ||
                                 issue.package_name.startsWith('golang.org/') ||
                                 issue.package_name.startsWith('go.uber.org/') ||
                                 issue.package_name.startsWith('google.golang.org/') ||
                                 issue.package_name.startsWith('gopkg.in/') ||
                                 issue.package_name.includes('/'));
              
              if (isExternal) {
                externalPackages.add(issue.package_name);
              } else {
                internalPackages.add(issue.package_name);
              }
              
              if (issue.package_dependency_type === 'direct') {
                directDeps.add(issue.package_name);
              } else if (issue.package_dependency_type === 'transitive') {
                transitiveDeps.add(issue.package_name);
              }

              // Depth 정보 수집
              const depth = issue.package_dependency_depth || issue.depth || 0;
              if (depth > maxDepth) {
                maxDepth = depth;
              }
              if (!depthMap.has(issue.package_name) || depthMap.get(issue.package_name) < depth) {
                depthMap.set(issue.package_name, depth);
              }
            }

            if (issue.vulnerability_id || issue.vulnerability_cve) {
              vulnerablePkgs.add(issue.package_name);
              totalVulnCount++;
              
              // reachable 정보 확인 (vulnerability 레벨 또는 functions 배열에서)
              const isReachable = issue.reachable === 1 || issue.reachable === true || issue.reachable === '1' ||
                                 (issue.functions && Array.isArray(issue.functions) && issue.functions.some(f => f.reachable === true));
              if (isReachable) {
                reachableCount++;
              }
            }
          }
        });
        console.log('[ossStats] ossIssues 처리 완료:', {
          packageNameIssues,
          processedIssues,
          skippedIssues,
          uniquePackages: uniquePackages.size,
          directDeps: directDeps.size,
          transitiveDeps: transitiveDeps.size,
          vulnerablePkgs: vulnerablePkgs.size,
          reachableCount,
          totalVulnCount,
          externalPackages: externalPackages.size,
          internalPackages: internalPackages.size
        });
      }

      // 최종 maxDepth 계산: 
      // 1. packagesData에서 계산된 maxDepth 사용 (실제 패키지 데이터 기반)
      // 2. CDX dependencies로 계산된 depth는 참고용으로만 사용 (모든 서버 데이터가 섞일 수 있음)
      // Total Vulnerabilities 탭에서는 실제 packagesData의 maxDepth만 사용
      let finalMaxDepth = maxDepth;
      
      // CDX dependencies로 계산된 depth가 있고, packagesData에서 계산된 depth가 0이면 CDX 결과 사용
      // (packagesData가 없거나 depth 정보가 없는 경우에만 fallback)
      if (finalMaxDepth === 0 && calculatedMaxDepthFromCDX > 0) {
        finalMaxDepth = calculatedMaxDepthFromCDX;
        console.log('[ossStats] packagesData에서 depth를 계산할 수 없어 CDX dependencies 결과 사용:', calculatedMaxDepthFromCDX);
      } else {
        console.log('[ossStats] packagesData에서 계산된 depth 사용:', maxDepth, '(CDX 결과:', calculatedMaxDepthFromCDX, '는 참고용)');
      }

      const result = {
        projectType,
        totalPackages: uniquePackages.size,
        directDependencies: directDeps.size,
        transitiveDependencies: transitiveDeps.size,
        vulnerablePackages: vulnerablePkgs.size,
        reachableVulnerabilities: reachableCount,
        totalVulnerabilities: totalVulnCount,
        externalPackages: externalPackages.size,
        internalPackages: internalPackages.size,
        maxDepth: finalMaxDepth
      };
      
      console.log('[ossStats] 최종 계산 결과:', {
        ...result,
        calculatedMaxDepthFromCDX,
        originalMaxDepth: maxDepth,
        finalMaxDepth
      });
      return result;
    })();

    // Code Vulnerabilities 통계 계산
    const codeStats = (() => {
      if (!codeIssues || codeIssues.length === 0) {
        return { 
          vulnerabilityTypes: [], 
          scannedFiles: 0, 
          totalFiles: 0,
          generalFindings: 0,
          mcpFindings: 0
        };
      }

      const vulnCount = {};
      const scannedFilesSet = new Set(); // 스캔한 파일들
      let generalFindings = 0;
      let mcpFindings = 0;
      
      codeIssues.forEach(issue => {
        // 스캔한 파일 수집 (artifacts/ 제거)
        if (issue.file) {
          scannedFilesSet.add(issue.file.replace(/^artifacts\//, ''));
        }
        
        // rule_id로 MCP 특화 취약점 구분 (mcp/로 시작하면 MCP 특화)
        const isMcpFinding = issue.rule_id && issue.rule_id.startsWith('mcp/');
        if (isMcpFinding) {
          mcpFindings++;
        } else {
          generalFindings++;
        }
        
        // vulnerability 필드를 우선 사용, 없으면 rule_id에서 추출
        let vulnerabilityName = issue.vulnerability;
        
        if (!vulnerabilityName && issue.rule_id) {
          // 일반적인 보안 약어 목록 (모두 대문자로 표시)
          const acronyms = ['ssrf', 'sqli', 'sql', 'xss', 'csrf', 'xxe', 'rce', 'lfi', 'rfi', 'ssti', 'idor', 'authz', 'authn', 'api', 'jwt', 'oauth', 'saml', 'ldap', 'nosql', 'xml', 'json', 'http', 'https', 'tls', 'ssl', 'dns', 'ip', 'url', 'uri', 'cve', 'cwe', 'cvss', 'owasp', 'nist', 'pii', 'gdpr', 'pci', 'hipaa'];
          
          // rule_id에서 접두사 제거하고 취약점 이름 추출
          const parts = issue.rule_id.split('/');
          let nameFromRule;
          
          if (parts.length > 1) {
            nameFromRule = parts.slice(1).join('/');
          } else {
            nameFromRule = issue.rule_id;
          }
          
          vulnerabilityName = nameFromRule
              .split('-')
            .map(word => {
              const wordLower = word.toLowerCase();
              // 약어 목록에 있으면 모두 대문자로
              if (acronyms.includes(wordLower)) {
                return wordLower.toUpperCase();
              }
              // 그 외는 첫 글자만 대문자
              return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
            })
              .join(' ');
        }
        
        if (!vulnerabilityName) {
          vulnerabilityName = issue.message || 'Unknown Vulnerability';
        }
        
        // "Config Poisoning"으로 시작하는 경우 "Config Poisoning"까지만 표시
        if (vulnerabilityName && vulnerabilityName.toLowerCase().startsWith('config poisoning')) {
          vulnerabilityName = 'Config Poisoning';
        }
        
        // "Advanced Tool Poisoning"으로 시작하는 경우 "Advanced Tool Poisoning"까지만 표시
        if (vulnerabilityName && vulnerabilityName.toLowerCase().startsWith('advanced tool poisoning')) {
          vulnerabilityName = 'Advanced Tool Poisoning';
        }
        
        // "Tool Name Spoofing"으로 시작하는 경우 "Tool Name Spoofing"까지만 표시
        if (vulnerabilityName && vulnerabilityName.toLowerCase().startsWith('tool name spoofing')) {
          vulnerabilityName = 'Tool Name Spoofing';
        }
        
        // "Tool Shadowing"으로 시작하는 경우 "Tool Shadowing"까지만 표시
        if (vulnerabilityName && vulnerabilityName.toLowerCase().startsWith('tool shadowing')) {
          vulnerabilityName = 'Tool Shadowing';
        }
        
        // "Tool Poisoning"으로 시작하는 경우 "Tool Poisoning"까지만 표시
        if (vulnerabilityName && vulnerabilityName.toLowerCase().startsWith('tool poisoning')) {
          vulnerabilityName = 'Tool Poisoning';
        }
        
        // "Schema Poisoning"으로 시작하는 경우 "Schema Poisoning"까지만 표시
        if (vulnerabilityName && vulnerabilityName.toLowerCase().startsWith('schema poisoning')) {
          vulnerabilityName = 'Schema Poisoning';
        }
        
        // "Toxic Flow"로 시작하는 경우 "Toxic Flow"까지만 표시
        if (vulnerabilityName && vulnerabilityName.toLowerCase().startsWith('toxic flow')) {
          vulnerabilityName = 'Toxic Flow';
        }
        
        vulnCount[vulnerabilityName] = (vulnCount[vulnerabilityName] || 0) + 1;
      });

      return {
        vulnerabilityTypes: Object.entries(vulnCount).map(([name, value]) => ({
          name,
          value
        })),
        scannedFiles: scannedFilesSet.size,
        totalFiles: scannedFilesSet.size, // 전체 파일 개수는 스캔한 파일 개수로 추정 (실제 전체 파일 개수는 별도 API 필요)
        generalFindings: generalFindings,
        mcpFindings: mcpFindings
      };
    })();

    // Tool Validation 통계 계산
    const toolValidationStats = (() => {
      if (!toolValidationIssues || toolValidationIssues.length === 0) {
        return { 
          categoryCounts: [], 
          externalHosts: [], 
          totalEndpoints: 0, 
          externalEndpoints: 0, 
          internalEndpoints: 0,
          toolsWithRisk: 0
        };
      }

      const categoryCount = {};
      const externalHostsSet = new Set();
      const endpointsSet = new Set(); // (host, method, path) 조합
      const externalEndpointsSet = new Set();
      const internalEndpointsSet = new Set();
      const toolsWithRiskSet = new Set(); // risk가 발견된 tool들
      
      toolValidationIssues.forEach(issue => {
        const categoryCode = issue.category_code || 'Unknown';
        categoryCount[categoryCode] = (categoryCount[categoryCode] || 0) + 1;
        
        // risk가 발견된 tool 추적
        if (issue.tool_name) {
          toolsWithRiskSet.add(issue.tool_name);
        }
        
        if (issue.host) {
          // 외부 host 판단 (localhost, 127.0.0.1, ::1 등이 아니면 외부)
          const isInternal = issue.host === 'localhost' || 
                            issue.host === '127.0.0.1' || 
                            issue.host === '::1' ||
                            issue.host.startsWith('192.168.') ||
                            issue.host.startsWith('10.') ||
                            issue.host.startsWith('172.');
          
          if (!isInternal) {
            externalHostsSet.add(issue.host);
          }
          
          // Endpoint 추적
          const endpointKey = `${issue.host}|${issue.method || 'GET'}|${issue.path || ''}`;
          endpointsSet.add(endpointKey);
          
          if (isInternal) {
            internalEndpointsSet.add(endpointKey);
          } else {
            externalEndpointsSet.add(endpointKey);
          }
        }
      });

      return {
        categoryCounts: Object.entries(categoryCount).map(([name, value]) => ({
          name,
          value
        })),
        externalHosts: Array.from(externalHostsSet),
        totalEndpoints: endpointsSet.size,
        externalEndpoints: externalEndpointsSet.size,
        internalEndpoints: internalEndpointsSet.size,
        toolsWithRisk: toolsWithRiskSet.size
      };
    })();

    // 차트 색상 정의 (고정 색상 팔레트)
    const COLORS = {
      'MCP-01': '#1e3a8a', // 가장 위험 - 진한 파란색
      'MCP-02': '#1e40af', // 위험 - 진한 파란색
      'MCP-03': '#2563eb', // 중간 위험 - 중간 파란색
      'MCP-04': '#3b82f6', // 덜 위험 - 밝은 파란색
      'go': '#1e40af',
      'npm': '#2563eb',
      'ts': '#3b82f6',
      'js': '#60a5fa',
      'py': '#3b82f6'
    };

    // 고정 색상 팔레트 (어두운 파란색 계열, 위험도에 따라 진하게)
    const FIXED_COLOR_PALETTE = [
      '#1e3a8a', // 가장 진한 파란색 (가장 위험)
      '#1e40af', // 진한 파란색 (위험)
      '#2563eb', // 중간 파란색 (중간 위험)
      '#3b82f6', // 밝은 파란색 (덜 위험)
      '#60a5fa', // 더 밝은 파란색 (안전)
      '#93c5fd', // 매우 밝은 파란색 (안전)
      '#1e3a8a', // 반복
      '#1e40af',
      '#2563eb',
      '#3b82f6',
      '#60a5fa',
      '#93c5fd'
    ];

    const getColor = (name, index = 0) => {
      // COLORS에 정의된 색상이 있으면 사용
      if (COLORS[name]) {
        return COLORS[name];
      }
      // 없으면 고정 색상 팔레트에서 순환 사용
      return FIXED_COLOR_PALETTE[index % FIXED_COLOR_PALETTE.length];
    };

    // OSS Issues에 대한 Reachable 개수 계산
    const totalOssIssues = ossIssues.length;
    const reachableOssIssues = ossIssues.filter(issue => 
      issue.reachable === 1 || issue.reachable === true || issue.reachable === '1'
    ).length;
    const unreachableOssIssues = totalOssIssues - reachableOssIssues;

    // 도넛 그래프용 보라색 계열 색상 팔레트 
    const DONUT_COLOR_PALETTE = [
      '#4c1d95', // 가장 진한 보라색 (가장 위험)
      '#5b21b6', // 진한 보라색 (위험)
      '#6d28d9', // 중간 보라색 (중간 위험)
      '#7c3aed', // 밝은 보라색 (덜 위험)
      '#8b5cf6', // 더 밝은 보라색 (안전)
      '#a78bfa', // 매우 밝은 보라색 (안전)
      '#4c1d95', // 반복
      '#5b21b6',
      '#6d28d9',
      '#7c3aed',
      '#8b5cf6', 
      '#a78bfa'
    ];

    const getDonutColor = (name, index = 0) => {
      // Unreachable은 특정 색상 사용
      if (name === 'Unreachable') return '#a78bfa';
      // COLORS에 정의된 색상이 있으면 파란색 계열로 변환
      if (COLORS[name]) {
        // MCP 카테고리에 따라 파란색 계열 매핑
        if (name === 'MCP-01') return '#4c1d95';
        if (name === 'MCP-02') return '#5b21b6';
        if (name === 'MCP-03') return '#7c3aed';
        if (name === 'MCP-04') return '#8b5cf6';
      }
      // 없으면 파란색 팔레트에서 순환 사용
      return DONUT_COLOR_PALETTE[index % DONUT_COLOR_PALETTE.length];
    };

    // OSS Vulnerabilities 원 그래프 데이터 (전체 OSS Issues vs Reachable OSS Issues)
    const ossCombinedChartData = [
      { 
        name: 'Reachable', 
        value: reachableOssIssues
      },
      { 
        name: 'Unreachable', 
        value: unreachableOssIssues
      }
    ].filter(item => item.value > 0);

    // 디버깅: OSS 데이터 확인
    console.log('[Total Vulnerabilities] OSS Stats:', ossStats);
    console.log('[Total Vulnerabilities] OSS Issues count:', ossIssues.length);
    console.log('[Total Vulnerabilities] Packages Data count:', packagesData?.length || 0);
    console.log('[Total Vulnerabilities] Reachable OSS Issues:', reachableOssIssues);
    console.log('[Total Vulnerabilities] Unreachable OSS Issues:', unreachableOssIssues);
    console.log('[Total Vulnerabilities] OSS Chart Data:', ossCombinedChartData);
    console.log('[Total Vulnerabilities] ossStats.totalPackages:', ossStats.totalPackages);
    console.log('[Total Vulnerabilities] ossStats.directDependencies:', ossStats.directDependencies);
    console.log('[Total Vulnerabilities] ossStats.transitiveDependencies:', ossStats.transitiveDependencies);

    // Tool 전체 개수 계산
    // 1. report_data.total_tools 우선 사용
    // 2. 없으면 report_data.tools 배열 길이 사용
    // 3. 그것도 없으면 toolValidationIssues에서 고유한 tool_name 개수 사용
    const totalTools = toolValidationReport?.report_data?.total_tools || 
                      toolValidationReport?.report_data?.tools?.length || 
                      (toolValidationIssues && toolValidationIssues.length > 0 
                        ? new Set(toolValidationIssues.map(issue => issue.tool_name).filter(Boolean)).size 
                        : 0);
    
    // 디버깅: Tool 개수 계산 확인
    console.log('[Total Vulnerabilities] Tool Count Debug:', {
      total_tools: toolValidationReport?.report_data?.total_tools,
      tools_length: toolValidationReport?.report_data?.tools?.length,
      unique_tool_names: toolValidationIssues && toolValidationIssues.length > 0 
        ? new Set(toolValidationIssues.map(issue => issue.tool_name).filter(Boolean)).size 
        : 0,
      toolValidationIssues_count: toolValidationIssues?.length,
      final_totalTools: totalTools
    });

    // Bar 차트를 위한 헬퍼 함수
    const renderBarChart = (label, value, maxValue, color = '#2563eb', isLast = false) => {
      const percentage = maxValue > 0 ? (value / maxValue) * 100 : 0;
    return (
        <div style={{ marginBottom: isLast ? '0px' : '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
            <span style={{ fontSize: '0.875rem', color: '#6b7280' }}>{label}</span>
            <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2233' }}>{value}</span>
          </div>
          <div style={{ width: '100%', height: '8px', background: '#e5e7eb', borderRadius: '4px', overflow: 'hidden' }}>
            <div 
              style={{ 
                width: `${percentage}%`, 
                height: '100%', 
                background: color, 
                borderRadius: '4px',
                transition: 'width 0.3s ease'
              }} 
            />
          </div>
          </div>
      );
    };

    // 스택 바 차트를 위한 헬퍼 함수 (여러 값을 하나의 바에 표시)
    const renderStackedBarChart = (label, segments, maxValue, isLast = false) => {
      const totalValue = segments.reduce((sum, seg) => sum + seg.value, 0);
      // segments의 합을 기준으로 비율 계산 (totalValue 기준)
      const displayMax = Math.max(maxValue, totalValue);
      
      return (
        <div style={{ marginBottom: isLast ? '0px' : '16px', width: '100%', boxSizing: 'border-box', overflow: 'visible' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', width: '100%', boxSizing: 'border-box' }}>
            <span style={{ fontSize: '0.875rem', color: '#6b7280' }}>{label}</span>
            <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2233' }}>
              {totalValue}
            </span>
        </div>
          <div style={{ width: '100%', height: '8px', background: '#e5e7eb', borderRadius: '4px', overflow: 'hidden', display: 'flex', boxSizing: 'border-box', position: 'relative', margin: 0, padding: 0 }}>
            {segments.map((segment, index) => {
              // 각 segment의 비율을 displayMax 기준으로 계산
              const percentage = displayMax > 0 ? (segment.value / displayMax) * 100 : 0;
              // 0보다 작거나 100보다 큰 경우 방지
              const safePercentage = Math.max(0, Math.min(100, percentage));
              
              // 이전 segment들의 누적 합 계산
              const previousSum = segments.slice(0, index).reduce((sum, seg) => {
                const prevPercentage = displayMax > 0 ? (seg.value / displayMax) * 100 : 0;
                return sum + Math.max(0, Math.min(100, prevPercentage));
              }, 0);
              
              // 마지막 segment인 경우 나머지 공간을 정확히 채우도록 조정
              const isLastSegment = index === segments.length - 1;
              let finalPercentage = safePercentage;
              
              if (isLastSegment) {
                // 마지막 segment는 나머지 공간을 정확히 채우도록 (반올림 오차 방지)
                const remaining = 100 - previousSum;
                finalPercentage = Math.max(0, Math.min(100, remaining));
              }
              
              return (
                <div
                  key={index}
                  style={{
                    width: `${finalPercentage}%`,
                    height: '100%',
                    background: segment.color,
                    transition: 'width 0.3s ease',
                    flexShrink: 0,
                    flexGrow: 0,
                    boxSizing: 'border-box',
                    margin: 0,
                    padding: 0,
                    border: 'none',
                    outline: 'none'
                  }}
                  title={`${segment.label}: ${segment.value}`}
                />
              );
            })}
          </div>
          <div style={{ display: 'flex', gap: '12px', marginTop: '4px', fontSize: '0.75rem', color: '#6b7280' }}>
            {segments.map((segment, index) => (
              <span key={index} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ width: '8px', height: '8px', background: segment.color, borderRadius: '2px' }} />
                <span>{segment.label}: {segment.value}</span>
              </span>
            ))}
          </div>
        </div>
      );
    };

    // 총 취약점 개수 계산 (OSS + Code + Tool Validation)
    const totalVulnerabilities = (ossIssues?.length || 0) + (codeIssues?.length || 0) + (toolValidationIssues?.length || 0);
    
    // SCA 위험도 계산 (사진의 공식 사용)
    // SCA_Risk = CVSS * (1 + ReachableWeight * Reachable)
    // ReachableWeight 기본값: 0.5
    // Reachable: 1 (Reachable) 또는 0 (Unreachable)
    const ReachableWeight = 0.5; // 기본값
    let scaRisk = 0;
    let maxScaRisk = 0; // 최대 SCA_Risk 값
    
    if (ossIssues && ossIssues.length > 0) {
      ossIssues.forEach(issue => {
        // CVSS 점수 가져오기
        const cvss = issue.vulnerability?.cvss || issue.cvss || 0;
        
        // Reachable 정보 확인 (1 또는 0)
        const reachable = (issue.reachable === 1 || issue.reachable === true || issue.reachable === '1' || 
                          issue.reachable === 'Reachable' || 
                          (issue.functions && Array.isArray(issue.functions) && issue.functions.some(f => f.reachable === true))) ? 1 : 0;
        
        // SCA_Risk 계산
        const scaRiskValue = cvss * (1 + ReachableWeight * reachable);
        scaRisk += scaRiskValue;
        maxScaRisk = Math.max(maxScaRisk, scaRiskValue);
      });
      
      // 평균 SCA_Risk 계산 (선택적)
      // scaRisk = scaRisk / ossIssues.length;
    }
    
    // SAST (Code Vulnerability) 위험도 계산 (사진의 공식 사용)
    // SAST_Risk = severityWeight(severity) × confidence
    // severityWeight: Info=1, Low=2, Medium=4, High=7, Critical=10
    // confidence: Info=0.1, Low=0.3, Medium=0.6, High=0.9, Critical=1.0
    // 최소값: 0.1, 최대값: 10
    const severityWeights = {
      'info': 1,
      'low': 2,
      'medium': 4,
      'high': 7,
      'critical': 10
    };
    
    const confidenceValues = {
      'info': 0.1,
      'low': 0.3,
      'medium': 0.6,
      'high': 0.9,
      'critical': 1.0
    };
    
    let sastRisk = 0;
    let maxSastRisk = 0; // 최대 SAST_Risk 값
    
    if (codeIssues && codeIssues.length > 0) {
      codeIssues.forEach(issue => {
        // severity 가중치 가져오기
        const severity = (issue.severity || 'unknown').toLowerCase();
        const severityWeight = severityWeights[severity] || 1;
        
        // confidence 값 가져오기 (이미 숫자이거나 문자열로 저장되어 있을 수 있음)
        let confidence = issue.confidence;
        if (confidence === null || confidence === undefined) {
          // confidence가 없으면 severity 기반으로 추정
          confidence = confidenceValues[severity] || 0.6; // 기본값: Medium
        } else if (typeof confidence === 'string') {
          // 문자열인 경우 confidenceValues에서 찾기
          confidence = confidenceValues[confidence.toLowerCase()] || parseFloat(confidence) || 0.6;
        } else {
          // 숫자인 경우 그대로 사용 (0.1 ~ 1.0 범위 확인)
          confidence = Math.max(0.1, Math.min(1.0, confidence));
        }
        
        // SAST_Risk 계산
        const sastRiskValue = Math.max(0.1, Math.min(10, severityWeight * confidence));
        sastRisk += sastRiskValue;
        maxSastRisk = Math.max(maxSastRisk, sastRiskValue);
      });
    }
    
    // Tool Vet 위험도 계산 (사진의 공식 사용)
    // Tool_Risk = (T1 * 0.2) + (T2 * 0.3) + (T3 * 0.3) + (T4 * 0.2)
    // T1: MCP-01 (Tool 선택 오류), T2: MCP-02 (Context Injection), T3: MCP-03 (Autonomous Execution), T4: MCP-04 (Tool Combination)
    let toolRisk = 0;
    if (toolValidationStats.categoryCounts && toolValidationStats.categoryCounts.length > 0) {
      const categoryMap = {};
      toolValidationStats.categoryCounts.forEach(cat => {
        categoryMap[cat.name] = cat.value > 0 ? 1 : 0; // 존재하면 1, 없으면 0
      });
      
      const T1 = categoryMap['MCP-01'] || 0; // Tool 선택 오류
      const T2 = categoryMap['MCP-02'] || 0; // Context Injection
      const T3 = categoryMap['MCP-03'] || 0; // Autonomous Execution
      const T4 = categoryMap['MCP-04'] || 0; // Tool Combination
      
      toolRisk = (T1 * 0.2) + (T2 * 0.3) + (T3 * 0.3) + (T4 * 0.2);
    }
    
    // 전체 위험도 계산 (Total_Risk 공식 사용)
    // Total_Risk = (SCA_Risk * SCA_Weight) + (SAST_Risk * SAST_Weight) + (Tool_Risk * Tool_Weight)
    // SCA_Weight = 0.6, SAST_Weight = 0.2, Tool_Weight = 0.2 (합계 = 1.0)
    const SCA_Weight = 0.6;
    const SAST_Weight = 0.2;
    const Tool_Weight = 0.2;
    
    // 각 위험도의 평균값 또는 최대값 사용 (최대값 사용)
    // SCA_Risk는 이미 maxScaRisk로 계산됨
    // SAST_Risk는 maxSastRisk로 계산됨
    // Tool_Risk는 이미 계산됨 (0.0 ~ 1.0 범위)
    
    // Tool_Risk를 0-10 스케일로 변환 (SAST_Risk와 동일한 스케일)
    const toolRiskScaled = toolRisk * 10; // Tool_Risk는 0.0-1.0이므로 10을 곱해 0-10 스케일로 변환
    
    // Total_Risk 계산
    const totalRisk = (maxScaRisk * SCA_Weight) + (maxSastRisk * SAST_Weight) + (toolRiskScaled * Tool_Weight);
    
    // 위험도 배지 결정
    // Total_Risk를 기준으로 위험도 결정
    // Critical: 9.0-10.0, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9
    let riskLevel = null;
    let riskColor = '#ffffff'; // 텍스트 색상 (흰색)
    let riskBgColor = '#fbbf24'; // 배경 색상 (노란색)
    let riskDisplayText = ''; // 배지에 표시할 텍스트 (예: Critical(9.2))
    
    if (totalVulnerabilities === 0 && totalRisk === 0) {
      // 취약점이 없으면 배지 표시 안 함
      riskLevel = null;
    } else {
      // Total_Risk를 소수점 첫째 자리까지 반올림
      const roundedTotalRisk = Math.round(totalRisk * 10) / 10;
      
      if (totalRisk >= 9.0) {
        riskLevel = 'CRITICAL';
        riskColor = '#ffffff'; // 텍스트 색상 (흰색)
        riskBgColor = '#dc2626'; // 배경 색상 (빨간색)
        riskDisplayText = `Critical(${roundedTotalRisk})`;
      } else if (totalRisk >= 7.0) {
        riskLevel = 'HIGH';
        riskColor = '#ffffff'; // 텍스트 색상 (흰색)
        riskBgColor = '#fd7e14'; // 배경 색상 (주황색)
        riskDisplayText = `HIGH(${roundedTotalRisk})`;
      } else if (totalRisk >= 4.0) {
        riskLevel = 'MEDIUM';
        riskColor = '#000000'; // 텍스트 색상 (검은색, 노란색 배경에서 가독성 향상)
        riskBgColor = '#ffc107'; // 배경 색상 (노란색)
        riskDisplayText = `MEDIUM(${roundedTotalRisk})`;
      } else if (totalRisk >= 0.1) {
        riskLevel = 'LOW';
        riskColor = '#ffffff'; // 텍스트 색상 (흰색)
        riskBgColor = '#28a745'; // 배경 색상 (초록색)
        riskDisplayText = `LOW(${roundedTotalRisk})`;
      } else {
        riskLevel = null;
      }
    }

    return (
      <div className="total-vulnerabilities-content">
        {/* 첫 줄: 프로젝트 타입, 위험도 (Risk 발견된 Tool) */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px', marginBottom: '32px' }}>
          <div className="stat-card" style={{ padding: '20px', background: '#fff', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '8px' }}>프로젝트 타입</div>
            <div style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2233' }}>
              {ossStats.projectType || '-'}
            </div>
          </div>
          <div className="stat-card" style={{ padding: '20px', background: '#fff', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '8px' }}>위험도</div>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              {riskLevel ? (
                <span style={{
                  display: 'inline-block',
                  padding: '6px 16px',
                  borderRadius: '6px',
                  fontSize: '0.875rem',
                  fontWeight: '700',
                  color: riskColor,
                  backgroundColor: riskBgColor,
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px'
                }}>
                  {riskDisplayText || riskLevel}
                </span>
              ) : (
                <span style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2233' }}>-</span>
              )}
            </div>
          </div>
        </div>

        {/* 두 번째 줄: 통계 Bar + 원 그래프 (합침) */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px', marginBottom: '40px', alignItems: 'stretch' }}>
          {/* OSS 통계 + 원 그래프 */}
          <div style={{ padding: '20px', background: '#fff', borderRadius: '8px', border: '1px solid #e5e7eb', display: 'flex', flexDirection: 'column', height: '100%', overflow: 'visible', boxSizing: 'border-box' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '20px', color: '#1f2233' }}>
              OSS Vulnerabilities
            </h3>
            {(ossStats.totalPackages > 0 || packagesData?.length > 0 || ossIssues?.length > 0) ? (
              <>
                <div style={{ marginBottom: '12px', height: '160px', display: 'flex', flexDirection: 'column', justifyContent: 'flex-start' }}>
                  {ossStats.totalPackages > 0 && renderStackedBarChart('전체 패키지 수', [
                    { label: '직접 의존성', value: ossStats.directDependencies || 0, color: '#1e3a8a' },
                    { label: '전이 의존성', value: ossStats.transitiveDependencies || 0, color: '#60a5fa' }
                  ], ossStats.totalPackages, false)}
                  {ossStats.maxDepth > 0 && (
                    <div style={{ marginTop: '1px' }}>
                      {renderBarChart(`SBOM Depth (${ossStats.maxDepth})`, ossStats.maxDepth, Math.max(ossStats.maxDepth, 10), '#1e3a8a', true)}
                    </div>
                  )}
                </div>
                {ossCombinedChartData.length > 0 && (
                  <div style={{ marginTop: '4px', borderTop: '1px solid #e5e7eb', paddingTop: '4px', position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ flex: '1', position: 'relative', height: '250px', maxWidth: '60%' }}>
                      <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                          <Pie
                            data={ossCombinedChartData}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            label={false}
                            outerRadius={80}
                            innerRadius={50}
                            fill="#8884d8"
                            dataKey="value"
                          >
                            {ossCombinedChartData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={getDonutColor(entry.name, index)} />
                            ))}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                      <div style={{ 
                        position: 'absolute', 
                        top: '50%', 
                        left: '50%', 
                        transform: 'translate(-50%, -50%)',
                        textAlign: 'center',
                        pointerEvents: 'none'
                      }}>
                        <div style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2233' }}>
                          {ossCombinedChartData.reduce((sum, entry) => sum + entry.value, 0)}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '4px' }}>
                          Total
                        </div>
                      </div>
                    </div>
                    <div style={{ paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'flex-start', minWidth: '150px' }}>
                      {ossCombinedChartData.map((entry, index) => (
                        <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem' }}>
                          <div style={{ width: '12px', height: '12px', backgroundColor: getDonutColor(entry.name, index), borderRadius: '2px', flexShrink: 0 }} />
                          <span style={{ color: '#1f2233', whiteSpace: 'nowrap' }}>{entry.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>발견된 Risk 및 Vulnerability 없음</div>
            )}
          </div>

          {/* Code 통계 + 원 그래프 */}
          <div style={{ padding: '20px', background: '#fff', borderRadius: '8px', border: '1px solid #e5e7eb', display: 'flex', flexDirection: 'column', height: '100%' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '20px', color: '#1f2233' }}>
              Code Vulnerabilities
            </h3>
            {codeStats.scannedFiles > 0 || codeStats.generalFindings > 0 || codeStats.mcpFindings > 0 ? (
              <>
                <div style={{ marginBottom: '12px', height: '160px', display: 'flex', flexDirection: 'column', justifyContent: 'flex-start' }}>
                  {renderBarChart('일반 취약점', codeStats.generalFindings, Math.max(codeStats.generalFindings, codeStats.mcpFindings, 1), '#1e3a8a', false)}
                  <div style={{ marginTop: '20px' }}>
                    {renderBarChart('MCP 특화 취약점', codeStats.mcpFindings, Math.max(codeStats.generalFindings, codeStats.mcpFindings, 1), '#1e3a8a', true)}
                  </div>
                </div>
                {codeStats.vulnerabilityTypes.length > 0 && (
                  <div style={{ marginTop: '4px', borderTop: '1px solid #e5e7eb', paddingTop: '4px', position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ flex: '1', position: 'relative', height: '250px', maxWidth: '60%' }}>
                      <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                          <Pie
                            data={codeStats.vulnerabilityTypes}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            label={false}
                            outerRadius={80}
                            innerRadius={50}
                            fill="#8884d8"
                            dataKey="value"
                          >
                            {codeStats.vulnerabilityTypes.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={getDonutColor(entry.name, index)} />
                            ))}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                      <div style={{ 
                        position: 'absolute', 
                        top: '50%', 
                        left: '50%', 
                        transform: 'translate(-50%, -50%)',
                        textAlign: 'center',
                        pointerEvents: 'none'
                      }}>
                        <div style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2233' }}>
                          {codeStats.vulnerabilityTypes.reduce((sum, entry) => sum + entry.value, 0)}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '4px' }}>
                          Total
                        </div>
                      </div>
                    </div>
                    <div style={{ paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'flex-start', minWidth: '150px' }}>
                      {codeStats.vulnerabilityTypes.map((entry, index) => (
                        <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem' }}>
                          <div style={{ width: '12px', height: '12px', backgroundColor: getDonutColor(entry.name, index), borderRadius: '2px', flexShrink: 0 }} />
                          <span style={{ color: '#1f2233', whiteSpace: 'nowrap' }}>{entry.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>발견된 Risk 및 Vulnerability 없음</div>
            )}
          </div>

          {/* Tool 통계 + 원 그래프 */}
          <div style={{ padding: '20px', background: '#fff', borderRadius: '8px', border: '1px solid #e5e7eb', display: 'flex', flexDirection: 'column', height: '100%' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '20px', color: '#1f2233' }}>
              Tool Validation
            </h3>
            {(toolValidationStats.categoryCounts.length > 0 || toolValidationIssues?.length > 0 || toolValidationStats.totalEndpoints > 0) ? (
              <>
                <div style={{ marginBottom: '12px', height: '160px', display: 'flex', flexDirection: 'column', justifyContent: 'flex-start' }}>
                  {toolValidationStats.totalEndpoints > 0 && renderStackedBarChart('API Endpoint', [
                    { label: '외부', value: toolValidationStats.externalEndpoints, color: '#1e3a8a' },
                    { label: '내부', value: toolValidationStats.internalEndpoints, color: '#60a5fa' }
                  ], toolValidationStats.totalEndpoints, false)}
                  {totalTools > 0 && renderStackedBarChart('Tool Risk', [
                    { label: 'Risk 발견', value: toolValidationStats.toolsWithRisk, color: '#1e3a8a' },
                    { label: 'Risk 없음', value: Math.max(0, totalTools - toolValidationStats.toolsWithRisk), color: '#60a5fa' }
                  ], totalTools, true)}
                </div>
                {toolValidationStats.categoryCounts.length > 0 && (
                  <div style={{ marginTop: '4px', borderTop: '1px solid #e5e7eb', paddingTop: '4px', position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ flex: '1', position: 'relative', height: '250px', maxWidth: '60%' }}>
                      <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                          <Pie
                            data={toolValidationStats.categoryCounts}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            label={false}
                            outerRadius={80}
                            innerRadius={50}
                            fill="#8884d8"
                            dataKey="value"
                          >
                            {toolValidationStats.categoryCounts.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={getDonutColor(entry.name, index)} />
                            ))}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                      <div style={{ 
                        position: 'absolute', 
                        top: '50%', 
                        left: '50%', 
                        transform: 'translate(-50%, -50%)',
                        textAlign: 'center',
                        pointerEvents: 'none'
                      }}>
                        <div style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2233' }}>
                          {toolValidationStats.categoryCounts.reduce((sum, entry) => sum + entry.value, 0)}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '4px' }}>
                          Total
                        </div>
                      </div>
                    </div>
                    <div style={{ paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'flex-start', minWidth: '150px' }}>
                      {toolValidationStats.categoryCounts.map((entry, index) => (
                        <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem' }}>
                          <div style={{ width: '12px', height: '12px', backgroundColor: getDonutColor(entry.name, index), borderRadius: '2px', flexShrink: 0 }} />
                          <span style={{ color: '#1f2233', whiteSpace: 'nowrap' }}>{entry.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {toolValidationStats.categoryCounts.length === 0 && toolValidationIssues?.length === 0 && (
                  <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>발견된 Risk 및 Vulnerability 없음</div>
                )}
              </>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>발견된 Risk 및 Vulnerability 없음</div>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderIssuesTable = () => {
    const issues = getCurrentIssues();
    
    // Tool Validation 탭은 별도 처리
    if (selectedTab === 'Tool Validation') {
      // 디버깅: issues 데이터 확인
      if (issues.length > 0) {
        console.log('[Tool Validation Table] 렌더링할 issues 샘플 (첫 3개):', 
          issues.slice(0, 3).map(i => ({
            tool_name: i.tool_name,
            host: i.host,
            method: i.method,
            path: i.path
          }))
        );
      }
    return (
        <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', padding: '24px' }}>
          <div className="issues-table tool-validation-table">
            <table>
              <thead>
                <tr>
                  <th>도구</th>
                  <th className="tool-validation-host">호스트</th>
                  <th className="tool-validation-method">메서드</th>
                  <th className="tool-validation-path">경로</th>
                  <th>취약점</th>
                  <th>View Detail</th>
                </tr>
              </thead>
              <tbody>
                {issues.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                      데이터가 없습니다.
                    </td>
                  </tr>
                ) : (
                  (() => {
                    // Endpoint별로 그룹화 (tool_name, host, method, path가 모두 같은 것)
                    const endpointMap = new Map();
                    issues.forEach(issue => {
                      // 디버깅: issue 데이터 확인
                      if (issues.indexOf(issue) < 2) {
                        console.log('[Tool Validation Table] issue 데이터:', {
                          tool_name: issue.tool_name,
                          host: issue.host,
                          method: issue.method,
                          path: issue.path,
                          id: issue.id
                        });
                      }
                      const key = `${issue.tool_name || ''}|${issue.host || ''}|${issue.method || ''}|${issue.path || ''}`;
                      if (!endpointMap.has(key)) {
                        endpointMap.set(key, []);
                      }
                      endpointMap.get(key).push(issue);
                    });
                    
                    // Tool별로 다시 그룹화 (시각적 그룹화를 위해)
                    const groupedByTool = {};
                    endpointMap.forEach((endpointIssues, key) => {
                      const toolName = endpointIssues[0].tool_name || 'Unknown';
                      if (!groupedByTool[toolName]) {
                        groupedByTool[toolName] = [];
                      }
                      groupedByTool[toolName].push(endpointIssues);
                    });
                    
                    const rows = [];
                    Object.entries(groupedByTool).forEach(([toolName, endpointGroups], toolIndex) => {
                      endpointGroups.forEach((endpointIssues, endpointIndex) => {
                        const isFirstInTool = endpointIndex === 0;
                        const firstIssue = endpointIssues[0];
                        const allCategoryCodes = endpointIssues.map(i => i.category_code).filter(Boolean);
                        const uniqueCategoryCodes = [...new Set(allCategoryCodes)];
                        
                        rows.push(
                          <tr
                            key={`${firstIssue.tool_name}-${firstIssue.host}-${firstIssue.method}-${firstIssue.path}-${firstIssue.id}`}
                            className={selectedIssue && endpointIssues.some(i => i.id === selectedIssue.id) ? 'selected' : ''}
                            onClick={() => {
                              // 첫 번째 이슈를 선택하되, 모든 취약점 정보를 포함
                              setSelectedIssue({
                                ...firstIssue,
                                _allVulnerabilities: endpointIssues // 모든 취약점 정보 저장
                              });
                            }}
                          >
                            <td 
                              className="package-name" 
                              style={{ 
                                verticalAlign: 'middle',
                                fontWeight: isFirstInTool ? 600 : 400,
                                color: isFirstInTool ? '#333' : 'transparent',
                                paddingTop: isFirstInTool ? '12px' : '0',
                                paddingBottom: isFirstInTool ? '12px' : '0',
                                fontSize: '0.75rem',
                                fontFamily: 'monospace'
                              }}
                            >
                              {isFirstInTool ? toolName : ''}
                            </td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{firstIssue.host || '-'}</td>
                            <td>
                              <span style={{
                                padding: '4px 8px',
                                borderRadius: '4px',
                                backgroundColor: firstIssue.method === 'GET' ? '#28a745' : 
                                               firstIssue.method === 'POST' ? '#007bff' :
                                               firstIssue.method === 'PUT' ? '#ffc107' :
                                               firstIssue.method === 'DELETE' ? '#dc3545' : '#6c757d',
                                color: '#fff',
                                fontSize: '0.75rem',
                                fontWeight: 600
                              }}>
                                {firstIssue.method || '-'}
                              </span>
                            </td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.8rem', whiteSpace: 'normal', wordBreak: 'break-word', overflowWrap: 'break-word' }}>{firstIssue.path || '-'}</td>
                            <td>
                              {uniqueCategoryCodes.length > 0 ? (
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', justifyContent: 'center' }}>
                                  {uniqueCategoryCodes.map((code, idx) => (
                                    <span
                                      key={idx}
                                      style={{
                                        padding: '4px 8px',
                                        borderRadius: '4px',
                                        backgroundColor: code === 'MCP-01' ? '#dc3545' :
                                                       code === 'MCP-02' ? '#fd7e14' :
                                                       code === 'MCP-03' ? '#ffc107' :
                                                       code === 'MCP-04' ? '#20c997' : '#6c757d',
                                        color: '#fff',
                                        fontSize: '0.75rem',
                                        fontWeight: 600
                                      }}
                                    >
                                      {code}
                                    </span>
                                  ))}
                                </div>
                              ) : (
                                <div style={{ textAlign: 'center' }}>-</div>
                              )}
                            </td>
                            <td>
                              <button 
                                className="oss-detail-btn"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedIssue({
                                    ...firstIssue,
                                    _allVulnerabilities: endpointIssues
                                  });
                                }}
                              >
                                View Detail
                              </button>
                            </td>
                          </tr>
                        );
                      });
                    });
                    
                    return rows;
                  })()
                )}
              </tbody>
            </table>
          </div>
        </div>
      );
    }
    
    return (
      <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', padding: '24px' }}>
        <div className="issues-table">
          <table>
          <thead>
            <tr>
              {selectedTab === 'Code Vulnerabilities' || selectedTab === 'Total Vulnerabilities' ? (
                <>
                  <th style={{ width: '13%' }}>취약점</th>
                  <th className="sortable" onClick={(e) => { e.stopPropagation(); handleVulnerabilitySort('severity'); }} style={{ cursor: 'pointer', userSelect: 'none', position: 'relative', paddingRight: '24px', width: '10%' }}>
                    위험도
                    {getVulnerabilitySortIcon('severity')}
                  </th>
                  {selectedTab === 'Code Vulnerabilities' ? (
                    <>
                      <th style={{ textAlign: 'left', width: '10%' }}>CWE</th>
                      <th style={{ width: '12%' }}>분석 방법</th>
                      <th style={{ width: '10%' }}>언어</th>
                      <th style={{ width: '35%' }}>취약한 코드</th>
                      <th style={{ width: '10%' }}>View Detail</th>
                    </>
                  ) : (
                    <>
                      <th>유형</th>
                      <th>취약 패키지</th>
                      <th>View Detail</th>
                    </>
                  )}
                </>
              ) : (
                <>
                  <th>취약점 ID</th>
                  <th className="sortable" onClick={(e) => { e.stopPropagation(); handleVulnerabilitySort('cvss'); }} style={{ cursor: 'pointer', userSelect: 'none', position: 'relative', paddingRight: '24px' }}>
                    CVSS
                    {getVulnerabilitySortIcon('cvss')}
                  </th>
                  <th>도달 가능성</th>
                  <th>패키지</th>
                  <th>버전</th>
                  <th>수정 버전</th>
                  <th>의존성</th>
                  <th>라이선스</th>
                  <th>View Detail</th>
                </>
              )}
            </tr>
          </thead>
          <tbody>
            {issues.length === 0 ? (
              <tr>
                <td colSpan={selectedTab === 'OSS Vulnerabilities' ? 9 : (selectedTab === 'Code Vulnerabilities' ? 7 : 5)} style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                  데이터가 없습니다.
                </td>
              </tr>
            ) : (
              issues.map(issue => {
                const getSeverityColor = (severity) => {
                  const severityLower = (severity || 'unknown').toLowerCase();
                  if (severityLower === 'critical') return '#dc3545';
                  if (severityLower === 'high') return '#fd7e14';
                  if (severityLower === 'medium') return '#ffc107';
                  if (severityLower === 'low') return '#28a745';
                  if (severityLower === 'info') return '#6c757d';
                  return '#6c757d';
                };
                
                if (selectedTab === 'Code Vulnerabilities' || selectedTab === 'Total Vulnerabilities') {
                  // Code Vulnerabilities 또는 Total Vulnerabilities 테이블 구조
                  const isOssIssue = issue.package && issue.vulnerability;
                  const severity = isOssIssue ? issue.vulnerability?.severity : issue.severity;
                  const severityScore = issue.severityScore || 0;
                  
                  return (
                    <tr
                      key={issue.id}
                      className={selectedIssue?.id === issue.id ? 'selected' : ''}
                      onClick={() => setSelectedIssue(issue)}
                    >
                      <td style={{ width: '13%' }}>
                        {isOssIssue 
                          ? (issue.vulnerability?.title || issue.vulnerability?.cve || issue.vulnerability?.id || 'Unknown Vulnerability')
                          : issue.vulnerability
                        }
                      </td>
                      <td style={{ width: '10%' }}>
                        <span style={{
                          padding: '4px 8px',
                          borderRadius: '4px',
                          backgroundColor: getSeverityColor(severity),
                          color: '#fff',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          textTransform: 'uppercase'
                        }}>
                          {severity || 'unknown'}
                        </span>
                      </td>
                      {selectedTab === 'Code Vulnerabilities' && (
                        <>
                          <td style={{ textAlign: 'left', width: '10%' }}>
                          {issue.cwe || '-'}
                        </td>
                          <td style={{ width: '12%' }}>
                            {(() => {
                              const conf = issue.confidence !== undefined && issue.confidence !== null ? issue.confidence : null;
                              if (conf === null || conf === undefined) {
                                return <span style={{ color: '#6c757d' }}>-</span>;
                              }
                              
                              let label = 'Pattern Match Only';
                              let className = 'analysis-method-pill analysis-method-pill--pattern-match';
                              
                              // CRITICAL (1.0)만 Taint Reached, HIGH (0.9)는 Partial Taint
                              if (conf >= 1.0) {
                                label = 'Taint Reached';
                                className = 'analysis-method-pill analysis-method-pill--taint-reached';
                              } else if (conf >= 0.6) {
                                label = 'Partial Taint';
                                className = 'analysis-method-pill analysis-method-pill--partial-taint';
                              }
                              
                              return (
                                <span className={className}>
                                  {label}
                                </span>
                              );
                            })()}
                          </td>
                        </>
                      )}
                      <td style={{ width: selectedTab === 'Code Vulnerabilities' ? '10%' : 'auto' }}>
                        {selectedTab === 'Total Vulnerabilities' ? (
                          <span style={{
                            padding: '4px 8px',
                            borderRadius: '4px',
                            backgroundColor: isOssIssue ? '#17a2b8' : '#6c757d',
                            color: '#fff',
                            fontSize: '0.75rem',
                            fontWeight: 600
                          }}>
                            {isOssIssue ? 'OSS' : 'Code'}
                          </span>
                        ) : (
                          (() => {
                            if (!issue.language) return 'Unknown';
                            let lang = issue.language.replace(/^artifacts\//, '');
                            // Dockerfile인지 확인
                            const fileName = lang.split('/').pop() || '';
                            if (fileName.toLowerCase() === 'dockerfile' || fileName.toLowerCase().startsWith('dockerfile.')) {
                              return 'Dockerfile';
                            }
                            return lang;
                          })()
                        )}
                      </td>
                      <td className="package-name" style={{ width: '35%', wordBreak: 'break-word' }}>
                        {isOssIssue 
                          ? `${issue.package?.name || 'Unknown'}${issue.package?.current_version ? ` (${issue.package.current_version})` : ''}`
                          : issue.vulnerablePackage ? issue.vulnerablePackage.replace(/^artifacts\//, '') : 'Unknown'
                        }
                      </td>
                      <td style={{ width: selectedTab === 'Code Vulnerabilities' ? '10%' : 'auto' }}>
                        <button 
                          className="oss-detail-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedIssue(issue);
                          }}
                        >
                          View Detail
                        </button>
                      </td>
                    </tr>
                  );
                } else {
                  // OSS Vulnerabilities 테이블 구조 (detail.js 참고)
                  const pkg = issue.package || {};
                  const vuln = issue.vulnerability || {};
                  
                  // 취약점이 없는 패키지 처리
                  if (!vuln || !vuln.id) {
                    return (
                      <tr
                        key={issue.id || `pkg-${pkg.name}`}
                        className={selectedIssue?.id === issue.id ? 'selected' : ''}
                      >
                        <td>-</td>
                        <td><span style={{ color: '#6c757d' }}>-</span></td>
                        <td><span style={{ color: '#6c757d' }}>-</span></td>
                        <td className="package-name">{pkg.name || 'Unknown'}</td>
                        <td>
                          {pkg.current_version ? (
                            <span className="oss-table__value" title={pkg.current_version}>
                              {pkg.current_version}
                            </span>
                          ) : (
                            <span style={{ color: '#6c757d' }}>-</span>
                          )}
                        </td>
                        <td><span style={{ color: '#6c757d' }}>-</span></td>
                        <td>
                          {(() => {
                            const depType = (pkg.dependency_type || '').toLowerCase();
                            let label = 'Unknown';
                            let className = 'dependency-pill dependency-pill--unknown';
                            
                            if (depType === 'direct') {
                              label = 'Direct';
                              className = 'dependency-pill dependency-pill--direct';
                            } else if (depType === 'transitive') {
                              label = 'Transitive';
                              className = 'dependency-pill dependency-pill--transitive';
                            } else if (depType === 'stdlib') {
                              label = 'Stdlib';
                              className = 'dependency-pill dependency-pill--stdlib';
                            } else if (depType) {
                              label = depType.charAt(0).toUpperCase() + depType.slice(1);
                              className = `dependency-pill dependency-pill--${depType}`;
                            }
                            
                            return (
                              <span className={className}>
                                {label}
                              </span>
                            );
                          })()}
                        </td>
                        <td>
                          {(() => {
                            const license = pkg.license || (Array.isArray(pkg.licenses) && pkg.licenses[0]) || '';
                            return license ? (
                              <span className="oss-table__value" title={license}>
                                {license}
                              </span>
                            ) : (
                              <span style={{ color: '#6c757d' }}>-</span>
                            );
                          })()}
                        </td>
                        <td>-</td>
                      </tr>
                    );
                  }
                  
                  const cvss = vuln.cvss || 0;
                  const severity = vuln.severity || 'unknown';
                  
                  // CVSS 점수에 따른 색상 클래스 (detail.js 참고)
                  const getCvssSeverityClass = (score) => {
                    if (score === null || score === undefined || isNaN(score)) return '';
                    if (score >= 9) return 'cvss-pill--critical';
                    if (score >= 7) return 'cvss-pill--high';
                    if (score >= 4) return 'cvss-pill--medium';
                    return 'cvss-pill--low';
                  };
                  
                  const cvssSeverityClass = getCvssSeverityClass(cvss);
                  
                  // Dependency type 라벨 및 클래스
                  const dependencyType = (pkg.dependency_type || '').toLowerCase();
                  let dependencyTypeLabel = 'Unknown';
                  let dependencyTypeClass = 'dependency-pill dependency-pill--unknown';
                  
                  if (dependencyType === 'direct') {
                    dependencyTypeLabel = 'Direct';
                    dependencyTypeClass = 'dependency-pill dependency-pill--direct';
                  } else if (dependencyType === 'transitive') {
                    dependencyTypeLabel = 'Transitive';
                    dependencyTypeClass = 'dependency-pill dependency-pill--transitive';
                  } else if (dependencyType === 'stdlib') {
                    dependencyTypeLabel = 'Stdlib';
                    dependencyTypeClass = 'dependency-pill dependency-pill--stdlib';
                  } else if (dependencyType) {
                    // 기타 dependency_type이 있으면 그대로 표시 (첫 글자 대문자)
                    dependencyTypeLabel = dependencyType.charAt(0).toUpperCase() + dependencyType.slice(1);
                    dependencyTypeClass = `dependency-pill dependency-pill--${dependencyType}`;
                  }
                  
                  // Reachability 상태
                  let reachabilityStatus = 'unknown';
                  let reachabilityBadge = '';
                  if (issue.reachable === true) {
                    reachabilityStatus = 'reachable';
                    reachabilityBadge = '↺ Reachable';
                  } else if (issue.reachable === false) {
                    reachabilityStatus = 'unreachable';
                    reachabilityBadge = 'Ø Unreachable';
                  }
                  
                  // License 추출 (package 객체에서 직접 가져오거나, packages 배열에서 찾기)
                  let license = pkg.license || (Array.isArray(pkg.licenses) && pkg.licenses[0]) || '';
                  if (!license && pkg.name) {
                    // packages 배열에서 license 정보 찾기
                    const pkgData = packagesData.find(p => p.name === pkg.name);
                    if (pkgData) {
                      license = pkgData.license || (Array.isArray(pkgData.licenses) && pkgData.licenses[0]) || '';
                    }
                  }
                  
                  return (
                    <tr
                      key={issue.id || `${pkg.name}-${vuln.id}`}
                      className={selectedIssue?.id === issue.id ? 'selected' : ''}
                      onClick={() => {
                        // 취약점이 있는 경우에만 상세보기 배너 열기
                        if (vuln && vuln.id) {
                          setSelectedOssIssue(issue);
                          setCurrentPathIndex(0); // 경로 인덱스 초기화
                        }
                      }}
                    >
                      <td>
                        <div className="vuln-cell">
                          {vuln.cve || vuln.id || '-'}
                        </div>
                      </td>
                      <td>
                        {Number.isFinite(cvss) && cvss > 0 ? (
                          <span className={`cvss-pill ${cvssSeverityClass}`}>
                            {cvss.toFixed(1)}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        {reachabilityStatus !== 'unknown' ? (
                          <span className={`reachability-badge reachability-badge--${reachabilityStatus}`}>
                            {reachabilityBadge}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td className="package-name">{pkg.name || 'Unknown'}</td>
                      <td>
                        {pkg.current_version ? (
                          <span className="oss-table__value" title={pkg.current_version}>
                            {pkg.current_version}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td>
                        {pkg.fixed_version || (Array.isArray(pkg.all_fixed_versions) && pkg.all_fixed_versions.length > 0) ? (
                          <span className="oss-table__value" style={{ color: '#28a745', fontWeight: 600 }} title={pkg.fixed_version || pkg.all_fixed_versions[0]}>
                            {pkg.fixed_version || pkg.all_fixed_versions[0]}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td>
                        <span className={dependencyTypeClass}>
                          {dependencyTypeLabel}
                        </span>
                      </td>
                      <td>
                        {license ? (
                          <span className="oss-table__value" title={license}>
                            {license}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td>
                        <button 
                          className="oss-detail-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedOssIssue(issue);
                            setCurrentPathIndex(0); // 경로 인덱스 초기화
                          }}
                        >
                          View Detail
                        </button>
                      </td>
                    </tr>
                  );
                }
              })
            )}
          </tbody>
        </table>
        </div>
      </div>
    );
  };

  // 정렬 핸들러 (서버 리스트용)
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

  // 취약점 정렬 핸들러
  const handleVulnerabilitySort = (column) => {
    if (vulnerabilitySortColumn === column) {
      if (vulnerabilitySortDirection === 'desc') {
        setVulnerabilitySortDirection('asc');
      } else if (vulnerabilitySortDirection === 'asc') {
        // 기본값으로 리셋 (높은 순)
        setVulnerabilitySortDirection('desc');
      }
    } else {
      setVulnerabilitySortColumn(column);
      setVulnerabilitySortDirection('desc');
    }
  };

  // 취약점 정렬 아이콘 표시 (Download Logs와 동일한 형식)
  const getVulnerabilitySortIcon = (column) => {
    if (vulnerabilitySortColumn !== column || !vulnerabilitySortDirection) {
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
        {vulnerabilitySortDirection === 'asc' ? (
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

  // 리스트 뷰 렌더링
  const renderListView = () => {
    // 서버 필터링은 백엔드에서 처리되므로, 검색어만 클라이언트에서 필터링
    let filteredServers = mcpServers.filter(server => 
      server.name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    // 정렬 적용
    if (sortColumn && sortDirection) {
      filteredServers = [...filteredServers].sort((a, b) => {
        // 위험도 정렬
        if (sortColumn === 'risk') {
          const aRiskData = serverRiskData[a.id];
          const bRiskData = serverRiskData[b.id];
          
          // 위험도 값 추출 (괄호 안의 숫자)
          const getRiskValue = (riskData) => {
            if (!riskData || !riskData.riskDisplayText) return -1;
            const match = riskData.riskDisplayText.match(/\(([\d.]+)\)/);
            return match ? parseFloat(match[1]) : -1;
          };
          
          const aRiskValue = getRiskValue(aRiskData);
          const bRiskValue = getRiskValue(bRiskData);
          
          // 위험도 레벨 우선순위 (CRITICAL > HIGH > MEDIUM > LOW)
          const getRiskLevelPriority = (riskData) => {
            if (!riskData || !riskData.riskLevel) return 0;
            const levelMap = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
            return levelMap[riskData.riskLevel] || 0;
          };
          
          const aLevelPriority = getRiskLevelPriority(aRiskData);
          const bLevelPriority = getRiskLevelPriority(bRiskData);
          
          // 먼저 레벨로 정렬, 같으면 숫자 값으로 정렬
          if (aLevelPriority !== bLevelPriority) {
            if (sortDirection === 'desc') {
              return bLevelPriority - aLevelPriority;
            } else {
              return aLevelPriority - bLevelPriority;
            }
          }
          
          // 레벨이 같으면 숫자 값으로 정렬
          if (sortDirection === 'desc') {
            return bRiskValue - aRiskValue;
          } else {
            return aRiskValue - bRiskValue;
          }
        }

        // 분석 시간 정렬
        if (sortColumn === 'analysis_timestamp') {
          const aValue = a[sortColumn];
          const bValue = b[sortColumn];
          if (!aValue && !bValue) return 0;
          if (!aValue || aValue === '-') return 1;
          if (!bValue || bValue === '-') return -1;
          
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
        let aValue = a[sortColumn];
        let bValue = b[sortColumn];
        aValue = (aValue || '').toString().toLowerCase();
        bValue = (bValue || '').toString().toLowerCase();
        
        if (sortDirection === 'asc') {
          return aValue.localeCompare(bValue);
        } else {
          return bValue.localeCompare(aValue);
        }
      });
    }

    // 모든 서버 표시 (페이지네이션 제거)
    const totalServers = filteredServers.length;

    return (
      <div className="risk-assessment-container">
        <div className="risk-assessment-left" style={{ padding: '25px', minHeight: 'calc(100vh - 64px)', display: 'flex', flexDirection: 'column' }}>
          <div className="risk-assessment-header" style={{ flexShrink: 0, padding: '0 0 8px 0', marginBottom: '8px', borderBottom: '1px solid var(--divider)' }}>
            <h1 style={{ margin: '0 0 8px 0' }}>Risk Assessment</h1>
          </div>

          <section className="list-page__controls-row" style={{ flexShrink: 0, marginTop: '0px' }}>
            <div className="list-page__header">
              <div>
                <h2>MCP Server List</h2>
              </div>
              <div style={{ display: 'flex', gap: '8px', marginTop: '16px', alignItems: 'center' }}>
                <button
                  className={`request-board-tab ${serverFilter === 'not_analyzed' ? 'active' : ''}`}
                  onClick={() => {
                    setServerFilter('not_analyzed');
                    setStatusFilter('all');
                  }}
                  style={{ padding: '8px 16px', fontSize: '0.9rem' }}
                >
                  분석 전 서버 ({serverCounts.not_analyzed})
                </button>
                <button
                  className={`request-board-tab ${serverFilter === 'analyzed' ? 'active' : ''}`}
                  onClick={() => setServerFilter('analyzed')}
                  style={{ padding: '8px 16px', fontSize: '0.9rem' }}
                >
                  분석 후 서버 ({serverCounts.analyzed})
                </button>
              </div>
            </div>
            <div className="list-page__controls" style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              {serverFilter === 'analyzed' && (
                <div className="sort-dropdown">
                <button
                    className="sort-button" 
                    onClick={(e) => {
                      e.stopPropagation();
                      setStatusFilterMenuOpen(!statusFilterMenuOpen);
                    }}
                  >
                    {statusFilter === 'all' ? '전체 상태' : statusFilter === 'pending' ? '대기중' : '승인됨'}
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                      <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  </button>
                  {statusFilterMenuOpen && (
                    <>
                      <div 
                        className="sort-menu-overlay"
                        onClick={() => setStatusFilterMenuOpen(false)}
                      />
                      <div className={`sort-menu ${statusFilterMenuOpen ? 'open' : ''}`}>
                        <div className="sort-menu-header">상태 필터</div>
                        <button 
                          className={`sort-option ${statusFilter === 'all' ? 'selected' : ''}`}
                          onClick={() => {
                            setStatusFilter('all');
                            setStatusFilterMenuOpen(false);
                          }}
                        >
                          전체 상태
                        </button>
                        <button 
                          className={`sort-option ${statusFilter === 'pending' ? 'selected' : ''}`}
                          onClick={() => {
                            setStatusFilter('pending');
                            setStatusFilterMenuOpen(false);
                          }}
                        >
                          대기중
                        </button>
                        <button 
                          className={`sort-option ${statusFilter === 'approved' ? 'selected' : ''}`}
                          onClick={() => {
                            setStatusFilter('approved');
                            setStatusFilterMenuOpen(false);
                          }}
                        >
                          승인됨
                </button>
              </div>
                    </>
                  )}
            </div>
              )}
              <div className="search-container">
                <svg className="search-icon" width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M7 12C9.76142 12 12 9.76142 12 7C12 4.23858 9.76142 2 7 2C4.23858 2 2 4.23858 2 7C2 9.76142 4.23858 12 7 12Z" stroke="currentColor" strokeWidth="1.5"/>
                  <path d="M10 10L14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
                <input
                  type="text"
                  className="search-input"
                  placeholder="Search servers"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
            </div>
          </section>

          <div className="table-wrapper" style={{ flex: 1, overflowY: 'auto', maxHeight: 'calc(100vh - 300px)', minHeight: 0, marginTop: '0px', marginBottom: '12px' }}>
            <table className="requests-table">
              <thead>
                <tr>
                  <th>MCP 서버</th>
                  <th>상태</th>
                  {serverFilter === 'analyzed' && (
                    <>
                      <th className="sortable" onClick={() => handleSort('risk')} style={{ cursor: 'pointer', userSelect: 'none', position: 'relative', paddingRight: '24px' }}>
                        위험도
                        {getSortIcon('risk')}
                      </th>
                      <th>언어</th>
                  <th className="sortable" onClick={() => handleSort('analysis_timestamp')} style={{ cursor: 'pointer', userSelect: 'none', position: 'relative', paddingRight: '24px' }}>
                    분석 시간
                    {getSortIcon('analysis_timestamp')}
                  </th>
                    </>
                  )}
                  <th>위험도 산정</th>
                  {serverFilter === 'analyzed' && <th>작업</th>}
                </tr>
              </thead>
              <tbody>
                {filteredServers.length === 0 ? (
                  <tr>
                    <td colSpan={serverFilter === 'analyzed' ? 7 : 3} style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                      {searchTerm ? '검색 결과가 없습니다.' : 'MCP 서버가 없습니다.'}
                    </td>
                  </tr>
                ) : (
                  filteredServers.map(server => {
                    const isAnalyzing = analyzingServers[server.id] || false;
                    const progressData = analysisProgressServers[server.id];
                    const progress = typeof progressData === 'object' 
                      ? (progressData.bomtori !== null && progressData.bomtori !== undefined 
                          ? Math.round((progressData.bomtori + progressData.scanner + (progressData.toolVet || 0)) / 3)
                          : progressData.scanner || 0)
                      : (progressData || 0);
                    const bomtoriProgress = typeof progressData === 'object' ? (progressData.bomtori !== null ? progressData.bomtori : 0) : 0;
                    const scannerProgress = typeof progressData === 'object' ? (progressData.scanner || 0) : (progressData || 0);
                    const toolVetProgress = typeof progressData === 'object' ? (progressData.toolVet !== null && progressData.toolVet !== undefined ? progressData.toolVet : 0) : 0;
                    const hasBomtori = server.github_link && server.github_link.includes('github.com');
                    
                    return (
                      <tr key={server.id} className="system-row">
                        <td>
                          <div className="system-row__title">{server.name}</div>
                        </td>
                        <td>
                          {getStatusBadge(server.status)}
                        </td>
                        {serverFilter === 'analyzed' && (
                          <>
                            <td>
                              {serverRiskData[server.id]?.riskDisplayText ? (
                                <span style={{
                                  display: 'inline-block',
                                  padding: '4px 12px',
                                  borderRadius: '6px',
                                  fontSize: '0.75rem',
                                  fontWeight: '700',
                                  color: serverRiskData[server.id].riskLevel === 'MEDIUM' ? '#000000' : '#ffffff',
                                  backgroundColor: 
                                    serverRiskData[server.id].riskLevel === 'CRITICAL' ? '#dc2626' :
                                    serverRiskData[server.id].riskLevel === 'HIGH' ? '#fd7e14' :
                                    serverRiskData[server.id].riskLevel === 'MEDIUM' ? '#ffc107' :
                                    serverRiskData[server.id].riskLevel === 'LOW' ? '#28a745' : '#6b7280',
                                  textTransform: 'uppercase',
                                  letterSpacing: '0.5px'
                                }}>
                                  {serverRiskData[server.id].riskDisplayText}
                                </span>
                              ) : (
                                <span style={{ color: '#6b7280' }}>-</span>
                              )}
                            </td>
                            <td>
                              <span style={{ color: '#1f2233' }}>
                                {serverRiskData[server.id]?.language || '-'}
                              </span>
                        </td>
                        <td className="system-row__timestamp">
                          {server.analysis_timestamp 
                            ? (() => {
                                const match = server.analysis_timestamp.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                                if (match) {
                                  const [, year, month, day, hours, minutes, seconds] = match;
                                  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
                                }
                                return server.analysis_timestamp;
                              })()
                            : '-'}
                        </td>
                          </>
                        )}
                        <td className="system-row__analysis">
                          {scanErrors[server.id] ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
                              <div style={{ 
                                fontSize: '0.75rem', 
                                color: '#dc2626',
                                padding: '8px',
                                backgroundColor: '#fee2e2',
                                borderRadius: '4px',
                                border: '1px solid #fecaca'
                              }}>
                                {scanErrors[server.id]}
                              </div>
                              <button
                                onClick={() => {
                                  setScanErrors(prev => {
                                    const newState = { ...prev };
                                    delete newState[server.id];
                                    return newState;
                                  });
                                  handleServerAnalysis(server);
                                }}
                                style={{
                                  padding: '6px 12px',
                                  fontSize: '0.75rem',
                                  backgroundColor: '#003153',
                                  color: '#fff',
                                  border: 'none',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  fontWeight: '500'
                                }}
                              >
                                다시 시도
                              </button>
                            </div>
                          ) : isAnalyzing ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', width: '100%' }}>
                              {hasBomtori && (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#666' }}>
                                    <span>SBOM/SCA</span>
                                    <span>{bomtoriProgress}%</span>
                                  </div>
                                  <div style={{
                                    width: '100%',
                                    height: '4px',
                                    backgroundColor: '#e0e0e0',
                                    borderRadius: '2px',
                                    overflow: 'hidden'
                                  }}>
                                    <div style={{
                                      width: `${bomtoriProgress}%`,
                                      height: '100%',
                                      backgroundColor: '#17a2b8',
                                      transition: 'width 0.3s ease'
                                    }}></div>
                                  </div>
                                </div>
                              )}
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#666' }}>
                                  <span>Code Scanner</span>
                                  <span>{scannerProgress}%</span>
                                </div>
                                <div style={{
                                  width: '100%',
                                  height: '4px',
                                  backgroundColor: '#e0e0e0',
                                  borderRadius: '2px',
                                  overflow: 'hidden'
                                }}>
                                  <div style={{
                                    width: `${scannerProgress}%`,
                                    height: '100%',
                                    backgroundColor: '#003153',
                                    transition: 'width 0.3s ease'
                                  }}></div>
                                </div>
                              </div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#666' }}>
                                  <span>Tool Vetting</span>
                                  <span>{toolVetProgress}%</span>
                                </div>
                                <div style={{
                                  width: '100%',
                                  height: '4px',
                                  backgroundColor: '#e0e0e0',
                                  borderRadius: '2px',
                                  overflow: 'hidden'
                                }}>
                                  <div style={{
                                    width: `${toolVetProgress}%`,
                                    height: '100%',
                                    backgroundColor: '#7c3aed',
                                    transition: 'width 0.3s ease'
                                  }}></div>
                                </div>
                              </div>
                            </div>
                          ) : (
                            <button
                              className="btn-refresh"
                              onClick={() => handleServerAnalysis(server)}
                              style={{ 
                                padding: '6px 12px', 
                                fontSize: '0.85rem',
                                width: '100%',
                                backgroundColor: '#003153',
                                color: '#fff',
                                border: 'none',
                                borderRadius: '6px',
                                fontWeight: '500',
                                cursor: 'pointer'
                              }}
                            >
                              Run Analysis
                            </button>
                          )}
                        </td>
                        {serverFilter === 'analyzed' && (
                        <td className="system-row__link">
                            {/* 분석 후 서버 탭에서는 항상 상세보기 버튼 표시 */}
                            {server.analysis_timestamp && server.analysis_timestamp.trim() !== '' ? (
                          <button 
                            onClick={async () => {
                              const scanPath = server.github_link || server.file_path;
                              if (!scanPath) {
                                alert('스캔 경로가 없습니다.');
                                return;
                              }
                                
                                // 이전 서버의 데이터 초기화
                                setCodeIssues([]);
                                setOssIssues([]);
                                setToolValidationIssues([]);
                                setPackagesData([]);
                                setSbomScannerData([]);
                                setToolValidationReport(null);
                              
                              try {
                                const token = localStorage.getItem('token');
                                
                                // scan_path로 최신 스캔 결과 조회
                                const res = await fetch(`${API_BASE_URL}/risk-assessment/code-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}`, {
                                  headers: {
                                    'Authorization': `Bearer ${token}`
                                  }
                                });
                                const data = await res.json();
                                
                                if (data.success && data.data && data.data.length > 0) {
                                  // 취약점 데이터가 있으면 포맷팅하여 설정
                                  const formattedIssues = formatScanResults(data.data);
                                  setCodeIssues(formattedIssues);
                                  
                                  // scan_id 추출 (첫 번째 취약점에서)
                                  const scanId = data.data[0]?.scan_id || null;
                                  
                                  // OSS Vulnerabilities 로드
                                  if (scanId) {
                                    try {
                                        const normalizedServerName = server.name ? normalizeServerName(server.github_link, server.name) : null;
                                        const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';
                                        const ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_id=${scanId}${serverNameParam}`, {
                                        headers: {
                                          'Authorization': `Bearer ${token}`
                                        }
                                      });
                                      const ossData = await ossRes.json();
                                      
                                        if (ossData.success) {
                                          const packagesArray = Array.isArray(ossData.packages) ? ossData.packages : [];
                                          if (ossData.cdxDependencies && Array.isArray(ossData.cdxDependencies)) {
                                            packagesArray.cdxDependencies = ossData.cdxDependencies;
                                          }
                                          setPackagesData(packagesArray);
                                          
                                          if (ossData.data) {
                                        setOssIssues(ossData.data);
                                      } else {
                                        setOssIssues([]);
                                          }
                                        } else {
                                          setOssIssues([]);
                                          setPackagesData([]);
                                      }
                                    } catch (error) {
                                      console.error('OSS 취약점 데이터 로드 실패:', error);
                                      setOssIssues([]);
                                        setPackagesData([]);
                                    }
                                  } else {
                                    // scan_path로 OSS 취약점 조회
                                    try {
                                        const normalizedServerName = server.name ? normalizeServerName(server.github_link, server.name) : null;
                                        const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';
                                        const ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
                                        headers: {
                                          'Authorization': `Bearer ${token}`
                                        }
                                      });
                                      const ossData = await ossRes.json();
                                      
                                        if (ossData.success) {
                                          const packagesArray = Array.isArray(ossData.packages) ? ossData.packages : [];
                                          if (ossData.cdxDependencies && Array.isArray(ossData.cdxDependencies)) {
                                            packagesArray.cdxDependencies = ossData.cdxDependencies;
                                          }
                                          setPackagesData(packagesArray);
                                          
                                          if (ossData.data) {
                                        setOssIssues(ossData.data);
                                      } else {
                                        setOssIssues([]);
                                          }
                                        } else {
                                          setOssIssues([]);
                                          setPackagesData([]);
                                      }
                                    } catch (error) {
                                      console.error('OSS 취약점 데이터 로드 실패:', error);
                                      setOssIssues([]);
                                    }
                                  }
                                } else {
                                  // 취약점 데이터가 없으면 빈 배열로 설정
                                  setCodeIssues([]);
                                  
                                  // scan_path로 OSS 취약점 조회 시도
                                  try {
                                      const normalizedServerName = server.name ? normalizeServerName(server.github_link, server.name) : null;
                                      const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';
                                      const ossRes = await fetch(`${API_BASE_URL}/risk-assessment/oss-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
                                      headers: {
                                        'Authorization': `Bearer ${token}`
                                      }
                                    });
                                    const ossData = await ossRes.json();
                                    
                                    if (ossData.success && ossData.data) {
                                      setOssIssues(ossData.data);
                                      // packages 배열도 저장 (license 정보 포함)
                                      // packages가 없어도 빈 배열로 설정하여 취약점이 없는 패키지 필터링이 작동하도록 함
                                      setPackagesData(Array.isArray(ossData.packages) ? ossData.packages : []);
                                      console.log('OSS 데이터 로드 (scan_path):', {
                                        취약점개수: ossData.data?.length || 0,
                                        packages개수: Array.isArray(ossData.packages) ? ossData.packages.length : 0
                                      });
                                    } else {
                                      setOssIssues([]);
                                      setPackagesData([]);
                                    }
                                  } catch (error) {
                                    console.error('OSS 취약점 데이터 로드 실패:', error);
                                    setOssIssues([]);
                                  }
                                }
                                
                                  setSbomScannerData([]);
                                  
                                  // 결과 뷰로 전환
                                  setAnalysisUrl(scanPath);
                                  const normalizedServerName = server.name ? normalizeServerName(server.github_link, server.name) : null;
                                  setServerName(normalizedServerName || '');
                                  setViewMode('result');
                                  setSelectedTab('Total Vulnerabilities');
                                  
                                  // Tool Validation 데이터 로드 (serverName 설정 후)
                                  try {
                                    const serverNameParam = normalizedServerName ? `&mcp_server_name=${encodeURIComponent(normalizedServerName)}` : '';
                                    console.log('[상세보기] Tool Validation 데이터 로드:', {
                                      serverName: server.name,
                                      normalizedServerName,
                                      serverNameParam,
                                      scanPath
                                    });
                                    
                                    // Tool Validation 리포트 로드
                                    const reportRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-reports?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
                                      headers: {
                                        'Authorization': `Bearer ${token}`
                                      }
                                    });
                                    
                                    if (reportRes) {
                                      const reportData = await reportRes.json();
                                      if (reportData.success && reportData.data && reportData.data.length > 0) {
                                        const report = reportData.data[0];
                                        if (typeof report.report_data === 'string') {
                                          report.report_data = JSON.parse(report.report_data);
                                        }
                                        setToolValidationReport(report);
                                        console.log('[상세보기] Tool Validation 리포트 로드 성공:', {
                                          serverName: server.name,
                                          total_tools: report.report_data?.total_tools
                                        });
                                      } else {
                                        setToolValidationReport(null);
                                        console.log('[상세보기] Tool Validation 리포트 없음:', {
                                          serverName: server.name
                                        });
                                      }
                                    }
                                    
                                    // Tool Validation 취약점 데이터 로드
                                    const toolValidationRes = await fetch(`${API_BASE_URL}/risk-assessment/tool-validation-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}${serverNameParam}`, {
                                    headers: {
                                      'Authorization': `Bearer ${token}`
                                    }
                                  });
                                  const toolValidationData = await toolValidationRes.json();
                                    
                                    console.log('[상세보기] Tool Validation API 응답:', {
                                      success: toolValidationData.success,
                                      dataLength: toolValidationData.data?.length || 0,
                                      serverName: server.name
                                    });
                                  
                                  if (toolValidationData.success && toolValidationData.data) {
                                    setToolValidationIssues(toolValidationData.data);
                                      console.log('[상세보기] Tool Validation 데이터 로드 성공:', {
                                        취약점개수: toolValidationData.data?.length || 0,
                                        serverName: server.name
                                    });
                                  } else {
                                setToolValidationIssues([]);
                                      console.log('[상세보기] Tool Validation 데이터 없음:', {
                                        serverName: server.name
                                      });
                                  }
                                } catch (error) {
                                    console.error('[상세보기] Tool Validation 데이터 로드 실패:', error);
                                  setToolValidationIssues([]);
                                    setToolValidationReport(null);
                                  }
                              } catch (error) {
                                console.error('스캔 결과 로드 실패:', error);
                                alert('스캔 결과를 불러오는 중 오류가 발생했습니다.');
                              }
                            }}
                              style={{
                                padding: '6px 12px',
                                fontSize: '0.85rem',
                                backgroundColor: '#003153',
                                color: '#fff',
                                border: 'none',
                                borderRadius: '8px',
                                cursor: 'pointer',
                                fontWeight: 'bold',
                                whiteSpace: 'nowrap',
                                width: '100%'
                              }}
                            >
                              상세보기
                          </button>
                            ) : (
                              <span style={{ color: '#999', fontSize: '0.85rem' }}>-</span>
                            )}
                        </td>
                        )}
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // 결과 뷰 렌더링
  const renderResultView = () => {
    return (
      <div className="risk-assessment-container">
        <div className="risk-assessment-left">
          {/* Breadcrumb */}
          <div className="risk-assessment-breadcrumb">
            <button 
              className="breadcrumb-link"
              onClick={() => {
                setViewMode('list');
                setSelectedIssue(null);
                setAnalysisUrl('');
              }}
            >
              Analysis
            </button>
            <span className="breadcrumb-separator"> &gt; </span>
            <span className="breadcrumb-current">Result</span>
          </div>

          <div className="risk-assessment-header">
            <h1>{serverName ? `Risk Assessment: ${serverName}` : 'Risk Assessment'}</h1>
            <div className="risk-assessment-tabs">
              {tabs.map(tab => (
                <button
                  key={tab}
                  className={`risk-assessment-tab ${selectedTab === tab ? 'active' : ''}`}
                  onClick={() => {
                    setSelectedTab(tab);
                    setSelectedIssue(null);
                  }}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>
          <div className="risk-assessment-summary">
            <span className="results-count">
              {(() => {
                const issues = getCurrentIssues();
                // 취약점이 있는 항목만 카운트 (vulnerability가 있는 경우)
                const vulnerabilityCount = issues.filter(issue => {
                  if (selectedTab === 'OSS Vulnerabilities') {
                    return issue.vulnerability && issue.vulnerability.id;
                  }
                  return true;
                }).length;
                return `${vulnerabilityCount} ${selectedTab === 'Total Vulnerabilities' ? 'total vulnerabilities' : 'vulnerabilities'}`;
              })()}
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <input
                type="search"
                placeholder="Search vulnerabilities..."
                className="risk-assessment-search"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            <select className="filter-dropdown">
              <option>Filter by Application: All</option>
            </select>
            </div>
          </div>
          {selectedTab === 'Total Vulnerabilities' ? renderSBOMScannerContent() : renderIssuesTable()}
        </div>

        {selectedIssue && (
          <div className={`detail-drawer ${selectedIssue ? 'is-open' : ''}`}>
            <div 
              className="detail-drawer__backdrop"
              onClick={() => setSelectedIssue(null)}
            />
            <aside className="detail-drawer__panel" role="dialog" aria-modal="true">
              <header className="detail-drawer__header">
                  <div>
                  <p className="detail-drawer__eyebrow">{selectedTab === 'Tool Validation' ? 'Tool Validation' : 'Code Vulnerability'}</p>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                    {selectedTab === 'Tool Validation' && selectedIssue.tool_name ? (() => {
                      // 모든 취약점의 category_name 가져오기
                      const allVulns = selectedIssue._allVulnerabilities || [];
                      const categoryNames = [];
                      
                      if (allVulns.length > 0) {
                        // 중복 제거하면서 category_name 수집
                        const seen = new Set();
                        allVulns.forEach(vuln => {
                          if (vuln.category_name && !seen.has(vuln.category_name)) {
                            seen.add(vuln.category_name);
                            categoryNames.push({
                              category_name: vuln.category_name,
                              category_code: vuln.category_code
                            });
                          }
                        });
                      } else if (selectedIssue.category_name) {
                        // _allVulnerabilities가 없으면 selectedIssue에서 가져오기
                        categoryNames.push({
                          category_name: selectedIssue.category_name,
                          category_code: selectedIssue.category_code
                        });
                      }
                      
                      return categoryNames.length > 0 ? (
                        <>
                          <h2 className="detail-drawer__title" style={{ margin: 0 }}>
                            {categoryNames.map((cat, idx) => (
                              <span key={idx}>
                                {cat.category_name}
                                {idx < categoryNames.length - 1 && <span style={{ color: '#999', margin: '0 8px' }}>•</span>}
                              </span>
                            ))}
                          </h2>
                          {categoryNames.map((cat, idx) => (
                            <span
                              key={idx}
                              style={{
                                padding: '4px 8px',
                                borderRadius: '4px',
                                backgroundColor: cat.category_code === 'MCP-01' ? '#dc3545' :
                                                 cat.category_code === 'MCP-02' ? '#fd7e14' :
                                                 cat.category_code === 'MCP-03' ? '#ffc107' :
                                                 cat.category_code === 'MCP-04' ? '#20c997' : '#6c757d',
                                color: '#fff',
                                fontSize: '0.75rem',
                                fontWeight: 600
                              }}
                            >
                              {cat.category_code}
                            </span>
                          ))}
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setShowMcpInfoModal(true);
                            }}
                            style={{
                              background: '#fff',
                              border: '2px solid #003153',
                              cursor: 'pointer',
                              padding: '6px',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              borderRadius: '50%',
                              width: '24px',
                              height: '24px',
                              color: '#003153',
                              fontSize: '12px',
                              fontWeight: 700,
                              transition: 'all 0.2s ease'
                            }}
                            onMouseEnter={(e) => {
                              e.target.style.transform = 'scale(1.1)';
                              e.target.style.backgroundColor = '#f0f4f7';
                            }}
                            onMouseLeave={(e) => {
                              e.target.style.transform = 'scale(1)';
                              e.target.style.backgroundColor = '#fff';
                            }}
                            title="MCP 취약점 카테고리 설명 보기"
                          >
                            i
                          </button>
                        </>
                      ) : (
                        <h2 className="detail-drawer__title">Tool Validation Issue</h2>
                      );
                    })() : (
                      <h2 className="detail-drawer__title">
                        {selectedIssue.vulnerability || 'Code Vulnerability'}
                      </h2>
                    )}
                  </div>
                </div>
                <button 
                  className="detail-drawer__close"
                  onClick={() => setSelectedIssue(null)}
                  aria-label="Close"
                >
                  &times;
                </button>
              </header>
              <div className="detail-drawer__content">
              <div className="vulnerability-details">
              {selectedTab === 'Tool Validation' && selectedIssue.tool_name ? (
                // Tool Validation 상세보기 (OSS Vulnerabilities 스타일)
                <>
                  {/* Tool Information Section */}
                  <section className="oss-detail-drawer__section">
                    <h3>Tool Information</h3>
                    <div className="oss-detail-drawer__info-grid">
                      <div className="oss-detail-drawer__info-item">
                        <span className="oss-detail-drawer__info-label">Tool Name</span>
                        <span className="oss-detail-drawer__info-value" style={{ fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                          {selectedIssue.tool_name || '-'}
                        </span>
              </div>
                      {(() => {
                        // 리포트 데이터에서 tool 설명 찾기
                        const toolInfo = toolValidationReport?.report_data?.tools?.find(t => t.name === selectedIssue.tool_name);
                        return toolInfo?.description ? (
                          <div className="oss-detail-drawer__info-item" style={{ gridColumn: '1 / -1' }}>
                            <span className="oss-detail-drawer__info-label">Tool Description</span>
                            <span className="oss-detail-drawer__info-value">
                              {toolInfo.description}
                            </span>
                          </div>
                        ) : null;
                      })()}
                      <div className="oss-detail-drawer__info-item">
                        <span className="oss-detail-drawer__info-label">Host</span>
                        <span className="oss-detail-drawer__info-value" style={{ fontFamily: 'monospace' }}>
                          {selectedIssue.host || '-'}
                        </span>
                      </div>
                      <div className="oss-detail-drawer__info-item">
                        <span className="oss-detail-drawer__info-label">Method</span>
                        <span className="oss-detail-drawer__info-value">
                          <span style={{
                            padding: '4px 8px',
                            borderRadius: '4px',
                            backgroundColor: selectedIssue.method === 'GET' ? '#28a745' : 
                                           selectedIssue.method === 'POST' ? '#007bff' :
                                           selectedIssue.method === 'PUT' ? '#ffc107' :
                                           selectedIssue.method === 'DELETE' ? '#dc3545' : '#6c757d',
                            color: '#fff',
                            fontSize: '0.85rem',
                            fontWeight: 600
                          }}>
                            {selectedIssue.method || '-'}
                          </span>
                        </span>
                      </div>
                      <div className="oss-detail-drawer__info-item" style={{ gridColumn: '1 / -1' }}>
                        <span className="oss-detail-drawer__info-label">Path</span>
                        <span className="oss-detail-drawer__info-value" style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                          {selectedIssue.path || '-'}
                        </span>
                      </div>
                    </div>
                  </section>

                  {/* Vulnerabilities Section */}
                  <section className="oss-detail-drawer__section">
                    <h3 style={{ marginBottom: '20px' }}>Vulnerabilities ({selectedIssue._allVulnerabilities ? selectedIssue._allVulnerabilities.length : 1})</h3>
                    {selectedIssue._allVulnerabilities ? (
                      selectedIssue._allVulnerabilities.map((vuln, idx) => (
                        <div key={idx} style={{ 
                          border: '1px solid rgba(31, 34, 51, 0.08)', 
                          borderRadius: '12px', 
                          padding: '24px',
                          marginBottom: '20px',
                          backgroundColor: '#fff',
                          boxShadow: '0 1px 3px rgba(0, 0, 0, 0.05)',
                          transition: 'all 0.2s ease'
                        }}>
                          {/* Category Header */}
                          <div style={{ 
                            display: 'flex', 
                            alignItems: 'center', 
                            gap: '12px',
                            marginBottom: '20px',
                            paddingBottom: '16px',
                            borderBottom: '1px solid rgba(31, 34, 51, 0.08)'
                          }}>
                            <span style={{
                              padding: '6px 12px',
                              borderRadius: '6px',
                              backgroundColor: vuln.category_code === 'MCP-01' ? '#dc3545' :
                                             vuln.category_code === 'MCP-02' ? '#fd7e14' :
                                             vuln.category_code === 'MCP-03' ? '#ffc107' :
                                             vuln.category_code === 'MCP-04' ? '#20c997' : '#6c757d',
                              color: '#fff',
                              fontSize: '0.875rem',
                              fontWeight: 700,
                              letterSpacing: '0.02em'
                            }}>
                              {vuln.category_code || '-'}
                            </span>
                            {vuln.category_name && (
                              <span style={{
                                fontSize: '0.95rem',
                                fontWeight: 600,
                                color: '#333',
                                flex: 1
                              }}>
                                {vuln.category_name}
                              </span>
                            )}
                          </div>

                          {/* Title */}
                          {vuln.title && (
                            <div style={{ marginBottom: '16px' }}>
                              <h4 style={{ 
                                margin: 0,
                                fontSize: '1rem',
                                fontWeight: 600,
                                color: '#333',
                                lineHeight: 1.5
                              }}>
                                {vuln.title}
                              </h4>
                            </div>
                          )}

                          {/* Description */}
                          {vuln.description && (
                            <div style={{ 
                              marginBottom: '20px'
                            }}>
                              <div style={{
                                fontSize: '0.875rem',
                                lineHeight: 1.7,
                                color: '#555',
                                whiteSpace: 'normal',
                                wordBreak: 'break-word'
                              }}>
                                {vuln.description}
                              </div>
                            </div>
                          )}
                          {/* Evidence */}
                          {vuln.evidence && (() => {
                            // Evidence 파싱: 동적 경로나 도구 목록 추출
                            const evidence = vuln.evidence;
                            
                            // tool-API 연관성 패턴: "tool-API 연관성: ..." 또는 "[패턴 기반 탐지] tool-API 연관성: ..."
                            const toolApiMatch = evidence.match(/(?:\[패턴 기반 탐지\]\s*)?tool-API 연관성[:\s]*(.+)/);
                            
                            // 동적 경로 패턴: "동적 경로 사용: POST /path, GET /path2" 또는 "동적 경로 사용: POST /repos/..."
                            const dynamicPathMatch = evidence.match(/동적 경로 사용[:\s]*(.+)/);
                            const weakToolMatch = evidence.match(/약한 검증 도구[:\s]*\[(.+?)\]/);
                            
                            // tool-API 연관성이 있는 경우
                            if (toolApiMatch) {
                              const associationsText = toolApiMatch[1].trim();
                              // 연관성들을 파싱 (쉼표로 구분)
                              const associations = associationsText.split(',').map(a => a.trim()).filter(a => a);
                              
                              // 각 연관성을 파싱: "tool.param → METHOD /path"
                              const parsedAssociations = associations.map(assoc => {
                                const match = assoc.match(/^([^\s→]+)\s*→\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$/i);
                                if (match) {
                                  return {
                                    toolParam: match[1].trim(),
                                    method: match[2].toUpperCase(),
                                    path: match[3].trim()
                                  };
                                }
                                return null;
                              }).filter(a => a !== null);
                              
                              if (parsedAssociations.length > 0) {
                                // tool별로 그룹화
                                const groupedByTool = {};
                                parsedAssociations.forEach(assoc => {
                                  const toolName = assoc.toolParam.split('.')[0];
                                  if (!groupedByTool[toolName]) {
                                    groupedByTool[toolName] = [];
                                  }
                                  groupedByTool[toolName].push(assoc);
                                });
                                
                                return (
                                  <div style={{ marginBottom: '20px' }}>
                                    <div style={{
                                      fontSize: '0.875rem',
                                      fontWeight: 600,
                                      color: '#333',
                                      marginBottom: '12px'
                                    }}>
                                      Evidence: tool-API 연관성 ({parsedAssociations.length}개)
                                    </div>
                                    <div style={{
                                      display: 'flex',
                                      flexDirection: 'column',
                                      gap: '16px',
                                      maxHeight: '400px',
                                      overflowY: 'auto',
                                      padding: '12px',
                                      backgroundColor: '#fff',
                                      borderRadius: '8px',
                                      border: '1px solid rgba(31, 34, 51, 0.12)'
                                    }}>
                                      {Object.entries(groupedByTool).map(([toolName, toolAssocs]) => (
                                        <div key={toolName} style={{
                                          backgroundColor: '#fff',
                                          borderRadius: '8px',
                                          border: '1px solid rgba(31, 34, 51, 0.08)',
                                          overflow: 'hidden'
                                        }}>
                                          <div style={{
                                            padding: '10px 14px',
                                            backgroundColor: '#f0f4f8',
                                            borderBottom: '1px solid rgba(31, 34, 51, 0.08)',
                                            fontSize: '0.875rem',
                                            fontWeight: 600,
                                            color: '#333',
                                            fontFamily: 'monospace'
                                          }}>
                                            {toolName}
                                          </div>
                                          <div style={{
                                            display: 'flex',
                                            flexDirection: 'column',
                                            gap: '8px',
                                            padding: '12px'
                                          }}>
                                            {toolAssocs.map((assoc, assocIdx) => (
                                              <div key={assocIdx} style={{
                                                display: 'flex',
                                                alignItems: 'center',
                                                gap: '12px',
                                                padding: '10px 12px',
                                                backgroundColor: '#fafbfc',
                                                borderRadius: '6px',
                                                border: '1px solid rgba(31, 34, 51, 0.06)',
                                                transition: 'all 0.15s ease'
                                              }}
                                              onMouseEnter={(e) => {
                                                e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.12)';
                                                e.currentTarget.style.backgroundColor = '#fff';
                                              }}
                                              onMouseLeave={(e) => {
                                                e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.06)';
                                                e.currentTarget.style.backgroundColor = '#fafbfc';
                                              }}>
                                                <span style={{
                                                  padding: '4px 10px',
                                                  backgroundColor: '#e3e8ef',
                                                  borderRadius: '4px',
                                                  fontSize: '0.75rem',
                                                  fontWeight: 500,
                                                  color: '#4a5568',
                                                  fontFamily: 'monospace',
                                                  whiteSpace: 'nowrap'
                                                }}>
                                                  {assoc.toolParam.split('.').slice(1).join('.') || 'param'}
                                                </span>
                                                <span style={{ color: '#999', fontSize: '0.875rem' }}>→</span>
                                                <span style={{
                                                  padding: '5px 10px',
                                                  borderRadius: '5px',
                                                  backgroundColor: assoc.method === 'GET' ? '#28a745' : 
                                                                 assoc.method === 'POST' ? '#007bff' :
                                                                 assoc.method === 'PUT' ? '#ffc107' :
                                                                 assoc.method === 'DELETE' ? '#dc3545' : '#6c757d',
                                                  color: '#fff',
                                                  fontSize: '0.75rem',
                                                  fontWeight: 700,
                                                  whiteSpace: 'nowrap',
                                                  minWidth: '65px',
                                                  textAlign: 'center',
                                                  letterSpacing: '0.02em'
                                                }}>
                                                  {assoc.method}
                                                </span>
                                                <span style={{ 
                                                  flex: 1, 
                                                  wordBreak: 'break-all',
                                                  color: '#333',
                                                  lineHeight: 1.5,
                                                  fontFamily: 'monospace',
                                                  fontSize: '0.875rem'
                                                }}>
                                                  {assoc.path}
                                                </span>
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                );
                              }
                            }
                            
                            // 동적 경로가 있는 경우
                            if (dynamicPathMatch) {
                              const pathsText = dynamicPathMatch[1].trim();
                              // 경로들을 파싱 (쉼표나 줄바꿈으로 구분)
                              const paths = pathsText.split(/[,\n]/).map(p => p.trim()).filter(p => p);
                              
                              return (
                                <div style={{ marginBottom: '20px' }}>
                                  <div style={{
                                    fontSize: '0.875rem',
                                    fontWeight: 600,
                                    color: '#333',
                                    marginBottom: '12px'
                                  }}>
                                    Evidence: 동적 경로 사용 ({paths.length}개)
                                  </div>
                                  <div style={{
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: '10px',
                                    maxHeight: '350px',
                                    overflowY: 'auto',
                                    padding: '12px',
                                    backgroundColor: '#fff',
                                    borderRadius: '8px',
                                    border: '1px solid rgba(31, 34, 51, 0.12)'
                                  }}>
                                    {paths.map((path, pathIdx) => {
                                      // HTTP 메서드와 경로 분리
                                      const methodMatch = path.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$/i);
                                      const method = methodMatch ? methodMatch[1].toUpperCase() : null;
                                      const pathOnly = methodMatch ? methodMatch[2] : path;
                                      
                                      return (
                                        <div key={pathIdx} style={{
                                          display: 'flex',
                                          alignItems: 'center',
                                          gap: '12px',
                                          padding: '12px 14px',
                                          backgroundColor: '#fff',
                                          borderRadius: '6px',
                                          border: '1px solid rgba(31, 34, 51, 0.08)',
                                          fontFamily: 'monospace',
                                          fontSize: '0.875rem',
                                          transition: 'all 0.15s ease'
                                        }}
                                        onMouseEnter={(e) => {
                                          e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.15)';
                                          e.currentTarget.style.boxShadow = '0 2px 4px rgba(0, 0, 0, 0.05)';
                                        }}
                                        onMouseLeave={(e) => {
                                          e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.08)';
                                          e.currentTarget.style.boxShadow = 'none';
                                        }}>
                                          {method && (
                                            <span style={{
                                              padding: '5px 10px',
                                              borderRadius: '5px',
                                              backgroundColor: method === 'GET' ? '#28a745' : 
                                                             method === 'POST' ? '#007bff' :
                                                             method === 'PUT' ? '#ffc107' :
                                                             method === 'DELETE' ? '#dc3545' : '#6c757d',
                                              color: '#fff',
                                              fontSize: '0.75rem',
                                              fontWeight: 700,
                                              whiteSpace: 'nowrap',
                                              minWidth: '65px',
                                              textAlign: 'center',
                                              letterSpacing: '0.02em'
                                            }}>
                                              {method}
                                            </span>
                                          )}
                                          <span style={{ 
                                            flex: 1, 
                                            wordBreak: 'break-all',
                                            color: '#333',
                                            lineHeight: 1.5
                                          }}>
                                            {pathOnly}
                                          </span>
                                        </div>
                                      );
                                    })}
                                  </div>
                                </div>
                              );
                            }
                            
                            // 약한 검증 도구가 있는 경우
                            if (weakToolMatch) {
                              const toolsText = weakToolMatch[1];
                              const tools = toolsText.split(',').map(t => t.trim().replace(/['"]/g, '')).filter(t => t);
                              
                              return (
                                <div style={{ marginBottom: '20px' }}>
                                  <div style={{
                                    fontSize: '0.875rem',
                                    fontWeight: 600,
                                    color: '#333',
                                    marginBottom: '12px'
                                  }}>
                                    Evidence: 약한 검증 도구 ({tools.length}개)
                                  </div>
                                  <div style={{
                                    display: 'flex',
                                    flexWrap: 'wrap',
                                    gap: '10px',
                                    padding: '12px',
                                    backgroundColor: '#fff',
                                    borderRadius: '8px',
                                    border: '1px solid rgba(31, 34, 51, 0.12)'
                                  }}>
                                    {tools.map((tool, toolIdx) => (
                                      <span key={toolIdx} style={{
                                        padding: '8px 14px',
                                        backgroundColor: '#fff',
                                        borderRadius: '6px',
                                        border: '1px solid rgba(31, 34, 51, 0.08)',
                                        fontFamily: 'monospace',
                                        fontSize: '0.875rem',
                                        color: '#333',
                                        fontWeight: 500,
                                        transition: 'all 0.15s ease'
                                      }}
                                      onMouseEnter={(e) => {
                                        e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.15)';
                                        e.currentTarget.style.boxShadow = '0 2px 4px rgba(0, 0, 0, 0.05)';
                                      }}
                                      onMouseLeave={(e) => {
                                        e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.08)';
                                        e.currentTarget.style.boxShadow = 'none';
                                      }}>
                                        {tool}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              );
                            }
                            
                            // 일반 텍스트인 경우 - 구조화된 패턴 파싱 시도
                            // "수정/삭제 작업: PATCH/PUT: 1개" 같은 패턴
                            const workPatternMatch = evidence.match(/수정\/삭제 작업:\s*([^:]+):\s*(\d+)개/);
                            
                            if (workPatternMatch) {
                              const methods = workPatternMatch[1].trim();
                              const count = workPatternMatch[2];
                              
                              return (
                                <div style={{ marginBottom: '20px' }}>
                                  <div style={{
                                    fontSize: '0.875rem',
                                    fontWeight: 600,
                                    color: '#333',
                                    marginBottom: '12px'
                                  }}>
                                    Evidence
                                  </div>
                                  <div style={{
                                    padding: '12px',
                                    backgroundColor: '#fff',
                                    borderRadius: '8px',
                                    border: '1px solid rgba(31, 34, 51, 0.12)'
                                  }}>
                                    <div style={{
                                      display: 'flex',
                                      flexDirection: 'column',
                                      gap: '12px'
                                    }}>
                                      <div style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '12px'
                                      }}>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          fontWeight: 600,
                                          color: '#666',
                                          minWidth: '100px'
                                        }}>
                                          작업 유형:
                                        </span>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          color: '#333'
                                        }}>
                                          수정/삭제 작업
                                        </span>
                                      </div>
                                      <div style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '12px',
                                        flexWrap: 'wrap'
                                      }}>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          fontWeight: 600,
                                          color: '#666',
                                          minWidth: '100px'
                                        }}>
                                          HTTP 메서드:
                                        </span>
                                        <div style={{
                                          display: 'flex',
                                          gap: '8px',
                                          flexWrap: 'wrap'
                                        }}>
                                          {methods.split('/').map((method, idx) => (
                                            <span key={idx} style={{
                                              padding: '5px 10px',
                                              borderRadius: '5px',
                                              backgroundColor: method.trim() === 'GET' ? '#28a745' : 
                                                             method.trim() === 'POST' ? '#007bff' :
                                                             method.trim() === 'PUT' ? '#ffc107' :
                                                             method.trim() === 'PATCH' ? '#6c757d' :
                                                             method.trim() === 'DELETE' ? '#dc3545' : '#6c757d',
                                              color: '#fff',
                                              fontSize: '0.75rem',
                                              fontWeight: 700,
                                              whiteSpace: 'nowrap',
                                              letterSpacing: '0.02em'
                                            }}>
                                              {method.trim()}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                      <div style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '12px'
                                      }}>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          fontWeight: 600,
                                          color: '#666',
                                          minWidth: '100px'
                                        }}>
                                          개수:
                                        </span>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          color: '#333',
                                          fontWeight: 600
                                        }}>
                                          {count}개
                                        </span>
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              );
                            }
                            
                            // 일반 텍스트인 경우 (파싱 실패)
                            return (
                              <div style={{ marginBottom: '20px' }}>
                                <div style={{
                                  fontSize: '0.875rem',
                                  fontWeight: 600,
                                  color: '#333',
                                  marginBottom: '12px'
                                }}>
                                  Evidence
                                </div>
                                <div style={{
                                  padding: '16px',
                                  backgroundColor: '#fff',
                                  borderRadius: '8px',
                                  border: '1px solid rgba(31, 34, 51, 0.12)',
                                  fontFamily: 'monospace',
                                  fontSize: '0.875rem',
                                  lineHeight: 1.7,
                                  color: '#333',
                                  whiteSpace: 'pre-wrap',
                                  wordBreak: 'break-word'
                                }}>
                                  {vuln.evidence}
                                </div>
                              </div>
                            );
                          })()}

                          {/* Recommendation */}
                          {vuln.recommendation && (
                            <div style={{ 
                              marginTop: '20px',
                              paddingTop: '20px',
                              borderTop: '1px solid rgba(31, 34, 51, 0.08)'
                            }}>
                              <div style={{
                                fontSize: '0.875rem',
                                fontWeight: 600,
                                color: '#333',
                                marginBottom: '12px'
                              }}>
                                Recommendation
                              </div>
                              <div style={{
                                fontSize: '0.875rem',
                                lineHeight: 1.7,
                                color: '#2e7d32',
                                whiteSpace: 'normal',
                                wordBreak: 'break-word'
                              }}>
                                {vuln.recommendation}
                              </div>
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div style={{ 
                        border: '1px solid rgba(31, 34, 51, 0.08)', 
                        borderRadius: '12px', 
                        padding: '24px',
                        backgroundColor: '#fff',
                        boxShadow: '0 1px 3px rgba(0, 0, 0, 0.05)'
                      }}>
                        {/* Category Header */}
                        <div style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          gap: '12px',
                          marginBottom: '20px',
                          paddingBottom: '16px',
                          borderBottom: '1px solid rgba(31, 34, 51, 0.08)'
                        }}>
                          {selectedIssue.category_code && (
                            <span style={{
                              padding: '6px 12px',
                              borderRadius: '6px',
                              backgroundColor: selectedIssue.category_code === 'MCP-01' ? '#dc3545' :
                                             selectedIssue.category_code === 'MCP-02' ? '#fd7e14' :
                                             selectedIssue.category_code === 'MCP-03' ? '#ffc107' :
                                             selectedIssue.category_code === 'MCP-04' ? '#20c997' : '#6c757d',
                              color: '#fff',
                              fontSize: '0.875rem',
                              fontWeight: 700,
                              letterSpacing: '0.02em'
                            }}>
                              {selectedIssue.category_code}
                            </span>
                          )}
                          {selectedIssue.category_name && (
                            <span style={{
                              fontSize: '0.95rem',
                              fontWeight: 600,
                              color: '#333',
                              flex: 1
                            }}>
                              {selectedIssue.category_name}
                            </span>
                          )}
                        </div>

                        {/* Title */}
                        {selectedIssue.title && (
                          <div style={{ marginBottom: '16px' }}>
                            <h4 style={{ 
                              margin: 0,
                              fontSize: '1rem',
                              fontWeight: 600,
                              color: '#333',
                              lineHeight: 1.5
                            }}>
                              {selectedIssue.title}
                            </h4>
                          </div>
                        )}

                        {/* Description */}
                        {selectedIssue.description && (
                          <div style={{ 
                            marginBottom: '20px'
                          }}>
                            <div style={{
                              fontSize: '0.875rem',
                              lineHeight: 1.7,
                              color: '#555',
                              whiteSpace: 'normal',
                              wordBreak: 'break-word'
                            }}>
                              {selectedIssue.description}
                            </div>
                          </div>
                        )}
                        {/* Evidence */}
                        {selectedIssue.evidence && (() => {
                            // Evidence 파싱: 동적 경로나 도구 목록 추출
                            const evidence = selectedIssue.evidence;
                            
                            // tool-API 연관성 패턴: "tool-API 연관성: ..." 또는 "[패턴 기반 탐지] tool-API 연관성: ..."
                            const toolApiMatch = evidence.match(/(?:\[패턴 기반 탐지\]\s*)?tool-API 연관성[:\s]*(.+)/);
                            
                            // 동적 경로 패턴: "동적 경로 사용: POST /path, GET /path2" 또는 "동적 경로 사용: POST /repos/..."
                            const dynamicPathMatch = evidence.match(/동적 경로 사용[:\s]*(.+)/);
                            const weakToolMatch = evidence.match(/약한 검증 도구[:\s]*\[(.+?)\]/);
                            
                            // tool-API 연관성이 있는 경우
                            if (toolApiMatch) {
                              const associationsText = toolApiMatch[1].trim();
                              // 연관성들을 파싱 (쉼표로 구분)
                              const associations = associationsText.split(',').map(a => a.trim()).filter(a => a);
                              
                              // 각 연관성을 파싱: "tool.param → METHOD /path"
                              const parsedAssociations = associations.map(assoc => {
                                const match = assoc.match(/^([^\s→]+)\s*→\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$/i);
                                if (match) {
                                  return {
                                    toolParam: match[1].trim(),
                                    method: match[2].toUpperCase(),
                                    path: match[3].trim()
                                  };
                                }
                                return null;
                              }).filter(a => a !== null);
                              
                              if (parsedAssociations.length > 0) {
                                // tool별로 그룹화
                                const groupedByTool = {};
                                parsedAssociations.forEach(assoc => {
                                  const toolName = assoc.toolParam.split('.')[0];
                                  if (!groupedByTool[toolName]) {
                                    groupedByTool[toolName] = [];
                                  }
                                  groupedByTool[toolName].push(assoc);
                                });
                                
                                return (
                                  <div style={{ marginBottom: '20px' }}>
                                    <div style={{
                                      fontSize: '0.875rem',
                                      fontWeight: 600,
                                      color: '#333',
                                      marginBottom: '12px'
                                    }}>
                                      Evidence: tool-API 연관성 ({parsedAssociations.length}개)
                                    </div>
                                    <div style={{
                                      display: 'flex',
                                      flexDirection: 'column',
                                      gap: '16px',
                                      maxHeight: '400px',
                                      overflowY: 'auto',
                                      padding: '12px',
                                      backgroundColor: '#fff',
                                      borderRadius: '8px',
                                      border: '1px solid rgba(31, 34, 51, 0.12)'
                                    }}>
                                      {Object.entries(groupedByTool).map(([toolName, toolAssocs]) => (
                                        <div key={toolName} style={{
                                          backgroundColor: '#fff',
                                          borderRadius: '8px',
                                          border: '1px solid rgba(31, 34, 51, 0.08)',
                                          overflow: 'hidden'
                                        }}>
                                          <div style={{
                                            padding: '10px 14px',
                                            backgroundColor: '#f0f4f8',
                                            borderBottom: '1px solid rgba(31, 34, 51, 0.08)',
                                            fontSize: '0.875rem',
                                            fontWeight: 600,
                                            color: '#333',
                                            fontFamily: 'monospace'
                                          }}>
                                            {toolName}
                                          </div>
                                          <div style={{
                                            display: 'flex',
                                            flexDirection: 'column',
                                            gap: '8px',
                                            padding: '12px'
                                          }}>
                                            {toolAssocs.map((assoc, assocIdx) => (
                                              <div key={assocIdx} style={{
                                                display: 'flex',
                                                alignItems: 'center',
                                                gap: '12px',
                                                padding: '10px 12px',
                                                backgroundColor: '#fafbfc',
                                                borderRadius: '6px',
                                                border: '1px solid rgba(31, 34, 51, 0.06)',
                                                transition: 'all 0.15s ease'
                                              }}
                                              onMouseEnter={(e) => {
                                                e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.12)';
                                                e.currentTarget.style.backgroundColor = '#fff';
                                              }}
                                              onMouseLeave={(e) => {
                                                e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.06)';
                                                e.currentTarget.style.backgroundColor = '#fafbfc';
                                              }}>
                                                <span style={{
                                                  padding: '4px 10px',
                                                  backgroundColor: '#e3e8ef',
                                                  borderRadius: '4px',
                                                  fontSize: '0.75rem',
                                                  fontWeight: 500,
                                                  color: '#4a5568',
                                                  fontFamily: 'monospace',
                                                  whiteSpace: 'nowrap'
                                                }}>
                                                  {assoc.toolParam.split('.').slice(1).join('.') || 'param'}
                                                </span>
                                                <span style={{ color: '#999', fontSize: '0.875rem' }}>→</span>
                                                <span style={{
                                                  padding: '5px 10px',
                                                  borderRadius: '5px',
                                                  backgroundColor: assoc.method === 'GET' ? '#28a745' : 
                                                                 assoc.method === 'POST' ? '#007bff' :
                                                                 assoc.method === 'PUT' ? '#ffc107' :
                                                                 assoc.method === 'DELETE' ? '#dc3545' : '#6c757d',
                                                  color: '#fff',
                                                  fontSize: '0.75rem',
                                                  fontWeight: 700,
                                                  whiteSpace: 'nowrap',
                                                  minWidth: '65px',
                                                  textAlign: 'center',
                                                  letterSpacing: '0.02em'
                                                }}>
                                                  {assoc.method}
                                                </span>
                                                <span style={{ 
                                                  flex: 1, 
                                                  wordBreak: 'break-all',
                                                  color: '#333',
                                                  lineHeight: 1.5,
                                                  fontFamily: 'monospace',
                                                  fontSize: '0.875rem'
                                                }}>
                                                  {assoc.path}
                                                </span>
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                );
                              }
                            }
                            
                            // 동적 경로가 있는 경우
                            if (dynamicPathMatch) {
                              const pathsText = dynamicPathMatch[1].trim();
                              // 경로들을 파싱 (쉼표나 줄바꿈으로 구분)
                              const paths = pathsText.split(/[,\n]/).map(p => p.trim()).filter(p => p);
                              
                              return (
                                <div style={{ marginBottom: '20px' }}>
                                  <div style={{
                                    fontSize: '0.875rem',
                                    fontWeight: 600,
                                    color: '#333',
                                    marginBottom: '12px'
                                  }}>
                                    Evidence: 동적 경로 사용 ({paths.length}개)
                                  </div>
                                  <div style={{
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: '10px',
                                    maxHeight: '350px',
                                    overflowY: 'auto',
                                    padding: '12px',
                                    backgroundColor: '#fff',
                                    borderRadius: '8px',
                                    border: '1px solid rgba(31, 34, 51, 0.12)'
                                  }}>
                                    {paths.map((path, pathIdx) => {
                                      // HTTP 메서드와 경로 분리
                                      const methodMatch = path.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$/i);
                                      const method = methodMatch ? methodMatch[1].toUpperCase() : null;
                                      const pathOnly = methodMatch ? methodMatch[2] : path;
                                      
                                      return (
                                        <div key={pathIdx} style={{
                                          display: 'flex',
                                          alignItems: 'center',
                                          gap: '12px',
                                          padding: '12px 14px',
                                          backgroundColor: '#fff',
                                          borderRadius: '6px',
                                          border: '1px solid rgba(31, 34, 51, 0.08)',
                                          fontFamily: 'monospace',
                                          fontSize: '0.875rem',
                                          transition: 'all 0.15s ease'
                                        }}
                                        onMouseEnter={(e) => {
                                          e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.15)';
                                          e.currentTarget.style.boxShadow = '0 2px 4px rgba(0, 0, 0, 0.05)';
                                        }}
                                        onMouseLeave={(e) => {
                                          e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.08)';
                                          e.currentTarget.style.boxShadow = 'none';
                                        }}>
                                          {method && (
                                            <span style={{
                                              padding: '5px 10px',
                                              borderRadius: '5px',
                                              backgroundColor: method === 'GET' ? '#28a745' : 
                                                             method === 'POST' ? '#007bff' :
                                                             method === 'PUT' ? '#ffc107' :
                                                             method === 'DELETE' ? '#dc3545' : '#6c757d',
                                              color: '#fff',
                                              fontSize: '0.75rem',
                                              fontWeight: 700,
                                              whiteSpace: 'nowrap',
                                              minWidth: '65px',
                                              textAlign: 'center',
                                              letterSpacing: '0.02em'
                                            }}>
                                              {method}
                                            </span>
                                          )}
                                          <span style={{ 
                                            flex: 1, 
                                            wordBreak: 'break-all',
                                            color: '#333',
                                            lineHeight: 1.5
                                          }}>
                                            {pathOnly}
                                          </span>
                                        </div>
                                      );
                                    })}
                                  </div>
                                </div>
                              );
                            }
                            
                            // 약한 검증 도구가 있는 경우
                            if (weakToolMatch) {
                              const toolsText = weakToolMatch[1];
                              const tools = toolsText.split(',').map(t => t.trim().replace(/['"]/g, '')).filter(t => t);
                              
                              return (
                                <div style={{ marginBottom: '20px' }}>
                                  <div style={{
                                    fontSize: '0.875rem',
                                    fontWeight: 600,
                                    color: '#333',
                                    marginBottom: '12px'
                                  }}>
                                    Evidence: 약한 검증 도구 ({tools.length}개)
                                  </div>
                                  <div style={{
                                    display: 'flex',
                                    flexWrap: 'wrap',
                                    gap: '10px',
                                    padding: '12px',
                                    backgroundColor: '#fff',
                                    borderRadius: '8px',
                                    border: '1px solid rgba(31, 34, 51, 0.12)'
                                  }}>
                                    {tools.map((tool, toolIdx) => (
                                      <span key={toolIdx} style={{
                                        padding: '8px 14px',
                                        backgroundColor: '#fff',
                                        borderRadius: '6px',
                                        border: '1px solid rgba(31, 34, 51, 0.08)',
                                        fontFamily: 'monospace',
                                        fontSize: '0.875rem',
                                        color: '#333',
                                        fontWeight: 500,
                                        transition: 'all 0.15s ease'
                                      }}
                                      onMouseEnter={(e) => {
                                        e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.15)';
                                        e.currentTarget.style.boxShadow = '0 2px 4px rgba(0, 0, 0, 0.05)';
                                      }}
                                      onMouseLeave={(e) => {
                                        e.currentTarget.style.borderColor = 'rgba(31, 34, 51, 0.08)';
                                        e.currentTarget.style.boxShadow = 'none';
                                      }}>
                                        {tool}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              );
                            }
                            
                            // 일반 텍스트인 경우 - 구조화된 패턴 파싱 시도
                            // "수정/삭제 작업: PATCH/PUT: 1개" 같은 패턴
                            const workPatternMatch = evidence.match(/수정\/삭제 작업:\s*([^:]+):\s*(\d+)개/);
                            
                            if (workPatternMatch) {
                              const methods = workPatternMatch[1].trim();
                              const count = workPatternMatch[2];
                              
                              return (
                                <div style={{ marginBottom: '20px' }}>
                                  <div style={{
                                    fontSize: '0.875rem',
                                    fontWeight: 600,
                                    color: '#333',
                                    marginBottom: '12px'
                                  }}>
                                    Evidence
                                  </div>
                                  <div style={{
                                    padding: '12px',
                                    backgroundColor: '#fff',
                                    borderRadius: '8px',
                                    border: '1px solid rgba(31, 34, 51, 0.12)'
                                  }}>
                                    <div style={{
                                      display: 'flex',
                                      flexDirection: 'column',
                                      gap: '12px'
                                    }}>
                                      <div style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '12px'
                                      }}>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          fontWeight: 600,
                                          color: '#666',
                                          minWidth: '100px'
                                        }}>
                                          작업 유형:
                                        </span>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          color: '#333'
                                        }}>
                                          수정/삭제 작업
                                        </span>
                                      </div>
                                      <div style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '12px',
                                        flexWrap: 'wrap'
                                      }}>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          fontWeight: 600,
                                          color: '#666',
                                          minWidth: '100px'
                                        }}>
                                          HTTP 메서드:
                                        </span>
                                        <div style={{
                                          display: 'flex',
                                          gap: '8px',
                                          flexWrap: 'wrap'
                                        }}>
                                          {methods.split('/').map((method, idx) => (
                                            <span key={idx} style={{
                                              padding: '5px 10px',
                                              borderRadius: '5px',
                                              backgroundColor: method.trim() === 'GET' ? '#28a745' : 
                                                             method.trim() === 'POST' ? '#007bff' :
                                                             method.trim() === 'PUT' ? '#ffc107' :
                                                             method.trim() === 'PATCH' ? '#6c757d' :
                                                             method.trim() === 'DELETE' ? '#dc3545' : '#6c757d',
                                              color: '#fff',
                                              fontSize: '0.75rem',
                                              fontWeight: 700,
                                              whiteSpace: 'nowrap',
                                              letterSpacing: '0.02em'
                                            }}>
                                              {method.trim()}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                      <div style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '12px'
                                      }}>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          fontWeight: 600,
                                          color: '#666',
                                          minWidth: '100px'
                                        }}>
                                          개수:
                                        </span>
                                        <span style={{
                                          fontSize: '0.875rem',
                                          color: '#333',
                                          fontWeight: 600
                                        }}>
                                          {count}개
                                        </span>
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              );
                            }
                            
                            // 일반 텍스트인 경우 (파싱 실패)
                            return (
                              <div style={{ marginBottom: '20px' }}>
                                <div style={{
                                  fontSize: '0.875rem',
                                  fontWeight: 600,
                                  color: '#333',
                                  marginBottom: '12px'
                                }}>
                                  Evidence
                                </div>
                                <div style={{
                                  fontSize: '0.875rem',
                                  lineHeight: 1.7,
                                  color: '#333',
                                  whiteSpace: 'pre-wrap',
                                  wordBreak: 'break-word',
                                  fontFamily: 'monospace'
                                }}>
                                  {selectedIssue.evidence}
                                </div>
                              </div>
                            );
                          })()}

                        {/* Recommendation */}
                        {selectedIssue.recommendation && (
                          <div style={{ 
                            marginTop: '20px',
                            paddingTop: '20px',
                            borderTop: '1px solid rgba(31, 34, 51, 0.08)'
                          }}>
                            <div style={{
                              fontSize: '0.875rem',
                              fontWeight: 600,
                              color: '#666',
                              marginBottom: '12px',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '8px'
                            }}>
                              <span style={{ 
                                width: '4px',
                                height: '4px',
                                borderRadius: '50%',
                                backgroundColor: '#28a745',
                                display: 'inline-block'
                              }}></span>
                              Recommendation
                            </div>
                            <div style={{
                              padding: '16px',
                              backgroundColor: '#e8f5e9',
                              borderRadius: '8px',
                              border: '1px solid rgba(40, 167, 69, 0.2)',
                              fontSize: '0.875rem',
                              lineHeight: 1.7,
                              color: '#2e7d32',
                              whiteSpace: 'normal',
                              wordBreak: 'break-word'
                            }}>
                              {selectedIssue.recommendation}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </section>
                </>
              ) : (
                // Code Vulnerabilities 상세보기
                <>
                  <div className="vulnerability-info">
                    <div className="info-section" style={{ flexWrap: 'wrap', gap: '16px' }}>
                      <div className="severity-box" style={{ 
                        backgroundColor: (() => {
                          const severity = (selectedIssue.severity || 'unknown').toLowerCase();
                          if (severity === 'critical') return '#dc3545'; // 빨간색
                          if (severity === 'high') return '#f97316'; // 주황색
                          if (severity === 'medium') return '#ffc107'; // 노란색
                          if (severity === 'low') return '#28a745'; // 초록색
                          if (severity === 'info') return '#6c757d'; // 회색
                          return '#6c757d';
                        })()
                      }}>
                            {(selectedIssue.severity || 'unknown').toUpperCase()}
                      </div>
                      <div className="info-item" style={{ flex: '1', minWidth: '200px' }}>
                        <strong>Rule ID</strong>
                        <code>{selectedIssue.rule_id || 'N/A'}</code>
                        </div>
                      {selectedIssue.file && (
                        <div className="info-item" style={{ flex: '1 1 100%', minWidth: '200px' }}>
                          <strong>File</strong>
                          <code style={{ display: 'block', marginTop: '4px' }}>
                            {selectedIssue.file.replace(/^artifacts\//, '')}
                          </code>
                        </div>
                      )}
                      {selectedIssue.line && (
                        <div className="info-item" style={{ flex: '1', minWidth: '150px' }}>
                          <strong>Line</strong>
                          <code>{selectedIssue.line}{selectedIssue.column && ` (Column: ${selectedIssue.column})`}</code>
                        </div>
                      )}
                        </div>

                    <div className="description-box">
                      <strong>Description</strong>
                      <p>{selectedIssue.description || selectedIssue.message || 'No description available'}</p>
                        </div>

                      {selectedIssue.cwe && (
                      <div className="description-box">
                        <strong>CWE</strong>
                        <p>{selectedIssue.cwe}</p>
                        </div>
                      )}

                    {selectedIssue.code_snippet && (
                      <div className="description-box" style={{ marginTop: '16px' }}>
                        <strong>Code Snippet</strong>
                        <pre className="code-snippet">
                          {selectedIssue.code_snippet}
                        </pre>
                    </div>
                    )}

                    <div className="info-section" style={{ marginTop: '16px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                      {selectedIssue.pattern_type && (
                        <div className="info-item">
                          <strong>Pattern Type</strong>
                          <code>{selectedIssue.pattern_type}</code>
                          </div>
                      )}
                      {selectedIssue.pattern && (
                        <div className="info-item">
                          <strong>Pattern</strong>
                          <code>{selectedIssue.pattern}</code>
                      </div>
                    )}
                      {selectedIssue.language && (
                        <div className="info-item">
                          <strong>Language</strong>
                          <code>
                            {(() => {
                              let lang = selectedIssue.language.replace(/^artifacts\//, '');
                              // Dockerfile인지 확인
                              const fileName = lang.split('/').pop() || '';
                              if (fileName.toLowerCase() === 'dockerfile' || fileName.toLowerCase().startsWith('dockerfile.')) {
                                return 'Dockerfile';
                              }
                              return lang;
                            })()}
                          </code>
                      </div>
                    )}
                      {selectedIssue.confidence !== undefined && selectedIssue.confidence !== null && (
                        <div className="info-item">
                          <strong>Taint Reached</strong>
                          <div style={{ marginTop: '-5px' }}>
                            <div style={{ 
                              display: 'flex', 
                              justifyContent: 'flex-end', 
                              alignItems: 'center',
                              marginBottom: '4px'
                            }}>
                              <span style={{ fontSize: '0.75rem', color: '#6b7280' }}>
                                {(() => {
                                  const conf = selectedIssue.confidence || 0;
                                  // CRITICAL (1.0)만 Taint Reached, HIGH (0.9)는 Partial Taint
                                  if (conf >= 1.0) return 'Taint Reached';
                                  if (conf >= 0.6) return 'Partial Taint';
                                  return 'Pattern Match Only';
                                })()}
                              </span>
                            </div>
                            <div style={{ 
                              width: '100%', 
                              height: '10px', 
                              background: '#e5e7eb', 
                              borderRadius: '8px', 
                              overflow: 'hidden',
                              position: 'relative'
                            }}>
                              <div 
                                style={{ 
                                  width: `${((selectedIssue.confidence || 0) * 100)}%`, 
                                  height: '100%', 
                                  background: (() => {
                                    const conf = selectedIssue.confidence || 0;
                                    // CRITICAL (1.0)만 Taint Reached, HIGH (0.9)는 Partial Taint
                                    if (conf >= 1.0) return '#007bff'; // Blue (Taint Reached)
                                    if (conf >= 0.6) return '#5dade2'; // Light Blue (Partial Taint)
                                    return '#aed6f1'; // Lighter Blue (Pattern Match Only)
                                  })(),
                                  transition: 'width 0.3s ease'
                                }}
                              />
                            </div>
                          </div>
                      </div>
                    )}
                    </div>

                      <div className="description-box" style={{ marginTop: '24px' }}>
                        <strong>Raw Finding Data</strong>
                      <pre style={{
                        background: '#f5f5f5',
                        padding: '16px',
                          borderRadius: '6px',
                        overflow: 'auto',
                        fontSize: '0.8rem',
                          marginTop: '12px',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        maxHeight: '400px',
                        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                        lineHeight: '1.5',
                          border: '1px solid #e0e0e0'
                      }}>
                      {JSON.stringify({
                        rule_id: selectedIssue.rule_id,
                        severity: selectedIssue.severity,
                        message: selectedIssue.description || selectedIssue.message,
                        cwe: selectedIssue.cwe,
                        file: selectedIssue.file ? selectedIssue.file.replace(/^artifacts\//, '') : null,
                        line: selectedIssue.line,
                        column: selectedIssue.column,
                        code_snippet: selectedIssue.code_snippet,
                        pattern_type: selectedIssue.pattern_type,
                        pattern: selectedIssue.pattern,
                        confidence: selectedIssue.confidence,
                        risk_score: selectedIssue.risk_score,
                        language: (() => {
                          if (!selectedIssue.language) return null;
                          let lang = selectedIssue.language.replace(/^artifacts\//, '');
                          const fileName = lang.split('/').pop() || '';
                          if (fileName.toLowerCase() === 'dockerfile' || fileName.toLowerCase().startsWith('dockerfile.')) {
                            return 'Dockerfile';
                          }
                          return lang;
                        })()
                      }, null, 2)}
                      </pre>
                      </div>
                  </div>
                </>
              )}
              </div>
              </div>
              </aside>
          </div>
        )}

        {/* OSS Vulnerabilities Detail Drawer */}
        {selectedOssIssue && (
          <div className={`oss-detail-drawer ${selectedOssIssue ? 'is-open' : ''}`}>
            <div 
              className="oss-detail-drawer__backdrop"
              onClick={() => {
                setSelectedOssIssue(null);
                setCurrentPathIndex(0); // 경로 인덱스 초기화
              }}
            />
            <aside className="oss-detail-drawer__panel" role="dialog" aria-modal="true">
              <header className="oss-detail-drawer__header">
                <div>
                  <p className="oss-detail-drawer__eyebrow">OSS Vulnerability</p>
                  <h2 className="oss-detail-drawer__title">
                    {selectedOssIssue.vulnerability?.cve || selectedOssIssue.vulnerability?.id || 'Unknown'}
                  </h2>
      </div>
                <button 
                  type="button" 
                  className="oss-detail-drawer__close"
                  onClick={() => {
                    setSelectedOssIssue(null);
                    setCurrentPathIndex(0); // 경로 인덱스 초기화
                  }}
                  aria-label="Close details"
                >
                  &times;
                </button>
              </header>
              <div className="oss-detail-drawer__content">
                <section className="oss-detail-drawer__section">
                  <h3>Vulnerability Information</h3>
                  <div className="oss-detail-drawer__info-grid">
                    <div className="oss-detail-drawer__info-item">
                      <span className="oss-detail-drawer__info-label">Severity</span>
                      <span className="oss-detail-drawer__info-value">
                        <span className={`severity-pill severity-pill--${(selectedOssIssue.vulnerability?.severity || 'unknown').toLowerCase()}`}>
                          {(selectedOssIssue.vulnerability?.severity || 'unknown').toUpperCase()}
                        </span>
                      </span>
                    </div>
                    <div className="oss-detail-drawer__info-item">
                      <span className="oss-detail-drawer__info-label">Vulnerable Package</span>
                      <span className="oss-detail-drawer__info-value">
                        {selectedOssIssue.package?.name || 'Unknown'}
                      </span>
                    </div>
                    <div className="oss-detail-drawer__info-item">
                      <span className="oss-detail-drawer__info-label">Current Version</span>
                      <span className="oss-detail-drawer__info-value">
                        {selectedOssIssue.package?.current_version || '-'}
                      </span>
                    </div>
                    <div className="oss-detail-drawer__info-item">
                      <span className="oss-detail-drawer__info-label">CVSS Score</span>
                      <span className="oss-detail-drawer__info-value">
                        {selectedOssIssue.vulnerability?.cvss ? selectedOssIssue.vulnerability.cvss.toFixed(1) : '-'}
                      </span>
                    </div>
                    <div className="oss-detail-drawer__info-item">
                      <span className="oss-detail-drawer__info-label">Fix Version</span>
                      <span className="oss-detail-drawer__info-value" style={{ color: '#28a745', fontWeight: 600 }}>
                        {selectedOssIssue.package?.fixed_version || 
                         (Array.isArray(selectedOssIssue.package?.all_fixed_versions) && selectedOssIssue.package.all_fixed_versions.length > 0
                          ? selectedOssIssue.package.all_fixed_versions[0]
                          : '-')}
                      </span>
                    </div>
                    <div className="oss-detail-drawer__info-item">
                      <span className="oss-detail-drawer__info-label">Dependency Type</span>
                      <span className="oss-detail-drawer__info-value">
                        {(() => {
                          const depType = (selectedOssIssue.package?.dependency_type || '').toLowerCase();
                          let label = 'Unknown';
                          let className = 'dependency-pill dependency-pill--unknown';
                          
                          if (depType === 'direct') {
                            label = 'Direct';
                            className = 'dependency-pill dependency-pill--direct';
                          } else if (depType === 'transitive') {
                            label = 'Transitive';
                            className = 'dependency-pill dependency-pill--transitive';
                          } else if (depType === 'stdlib') {
                            label = 'Stdlib';
                            className = 'dependency-pill dependency-pill--stdlib';
                          } else if (depType) {
                            label = depType.charAt(0).toUpperCase() + depType.slice(1);
                            className = `dependency-pill dependency-pill--${depType}`;
                          }
                          
                          return (
                            <span className={className}>
                              {label}
                            </span>
                          );
                        })()}
                      </span>
                    </div>
                  </div>
                  
                  {(() => {
                    // vulnerability.title을 우선적으로 사용 (헤더에 있던 내용)
                    let displayText = selectedOssIssue.vulnerability?.title || '';
                    
                    // title이 없으면 summary 사용
                    if (!displayText) {
                      displayText = selectedOssIssue.vulnerability?.summary || '';
                    }
                    
                    // summary도 없으면 description에서 Summary 섹션 추출
                    if (!displayText && selectedOssIssue.vulnerability?.description) {
                      const description = selectedOssIssue.vulnerability.description;
                      // "## Summary" 또는 "### Summary" 섹션 추출
                      const summaryMatch = description.match(/#{1,3}\s*Summary\s*\n\n([\s\S]*?)(?=\n##|\n###|$)/i);
                      if (summaryMatch && summaryMatch[1]) {
                        displayText = summaryMatch[1].trim();
                      } else {
                        // Summary 섹션이 없으면 전체 description 사용
                        displayText = description;
                      }
                    }
                    
                    if (!displayText) return null;
                    
                    // summarizeDescription 함수: 첫 문장만 추출 (180자 제한)
                    const summarizeDescription = (text) => {
                      if (!text) return '';
                      const cleaned = String(text)
                        .replace(/\r/g, '')
                        .split(/\n+/)
                        .map(line => line.trim())
                        .filter(Boolean)
                        .join(' ')
                        .replace(/\s+/g, ' ');
                      
                      if (!cleaned) return '';
                      
                      const sentenceMatch = cleaned.match(/.+?[.!?](?:\s|$)/);
                      const firstSentence = sentenceMatch ? sentenceMatch[0].trim() : cleaned;
                      
                      if (firstSentence.length <= 180) return firstSentence;
                      return `${firstSentence.slice(0, 177)}…`;
                    };
                    
                    const finalText = summarizeDescription(displayText);
                    
                    return (
                      <div className="oss-detail-drawer__description-info">
                        <div className="oss-detail-drawer__info-item oss-detail-drawer__info-item--description">
                          <span className="oss-detail-drawer__info-label">Description</span>
                          <div 
                            className="oss-detail-drawer__info-value" 
                            style={{ 
                              width: '100%', 
                              display: 'block', 
                              wordWrap: 'break-word', 
                              overflowWrap: 'break-word',
                              whiteSpace: 'normal',
                              overflow: 'visible',
                              overflowX: 'visible',
                              overflowY: 'visible',
                              maxWidth: 'none',
                              minWidth: 0,
                              boxSizing: 'border-box',
                              textOverflow: 'clip',
                              wordBreak: 'break-word'
                            }}
                          >
                            {finalText}
                          </div>
                        </div>
      </div>
    );
                  })()}

                  {selectedOssIssue.vulnerability?.reference_url && (
                    <div className="oss-detail-drawer__info-grid oss-detail-drawer__info-grid--bottom">
                      <div className="oss-detail-drawer__info-item oss-detail-drawer__info-item--reference">
                        <span className="oss-detail-drawer__info-label">Reference</span>
                        <span className="oss-detail-drawer__info-value">
                          <a 
                            href={selectedOssIssue.vulnerability.reference_url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="oss-detail-drawer__reference-link"
                          >
                            {selectedOssIssue.vulnerability.reference_url}
                          </a>
                        </span>
                      </div>
                    </div>
                  )}
                </section>

                <section className="oss-detail-drawer__section">
                  <h3>Reachability Analysis</h3>
                  <div className="oss-detail-drawer__reachability-container">
                    {selectedOssIssue.reachable ? (
                      <div className="reachability-alert reachability-alert--reachable">
                        <span>↺ The vulnerable package is reachable in this service{(() => {
                          const rawData = selectedOssIssue.rawData || selectedOssIssue;
                          const functions = rawData.functions || [];
                          const reachablePaths = functions
                            .filter(f => f.reachable === true && f.reachability_path && f.reachability_path.length > 0)
                            .flatMap(f => f.reachability_path || []);
                          const pathCount = reachablePaths.length;
                          return pathCount > 0 ? ` through ${pathCount} path${pathCount > 1 ? 's' : ''}` : '';
                        })()}.</span>
                      </div>
                    ) : selectedOssIssue.reachable === false ? (
                      <div className="reachability-alert reachability-alert--safe">
                        <span>Ø No reachable path found in this service.</span>
                      </div>
                    ) : (
                      <div className="reachability-alert">
                        <span>Reachability information is not available.</span>
                      </div>
                    )}
                    {/* Reachability Path 표시 */}
                    {(() => {
                      const rawData = selectedOssIssue.rawData || selectedOssIssue;
                      const functions = rawData.functions || [];
                      
                      // buildReachabilityInfo와 동일한 로직
                      const paths = [];
                      functions.forEach(fn => {
                        const pathList = Array.isArray(fn.reachability_path) ? fn.reachability_path : [];
                        pathList.forEach(path => {
                          if (!Array.isArray(path) || !path.length) return;
                          const steps = path.map(node => {
                            // functionName 추출: ::로 분리된 마지막 부분만
                            let functionName = node.function || node.method || '';
                            if (functionName.includes('::')) {
                              const parts = functionName.split('::');
                              functionName = parts[parts.length - 1];
                            }
                            
                            // packageName 추출: node.file에서 실제 패키지명 추출
                            let packageName = '';
                            const file = node.file || '';
                            
                            // node.file에서 node_modules/ 패키지명 추출
                            if (file.includes('node_modules/')) {
                              const match = file.match(/node_modules\/([^/]+)/);
                              if (match) {
                                packageName = match[1];
                              }
                            }
                            
                            // node.file에 패키지명이 없으면 node.package에서 추출 시도
                            if (!packageName) {
                              const rawPackage = node.package || node.module || '';
                              if (rawPackage) {
                                // @notionhq/notion-mcp-server -> notion-mcp-server
                                if (rawPackage.startsWith('@')) {
                                  const parts = rawPackage.split('/');
                                  if (parts.length > 1) {
                                    packageName = parts[parts.length - 1];
                                  } else {
                                    packageName = rawPackage;
                                  }
                                } else {
                                  packageName = rawPackage;
                                }
                              }
                            }
                            
                            return {
                              functionName: functionName,
                              file: file,
                              packageName: packageName,
                              module: node.module || '',
                              service: node.service || '',
                              type: node.type || ''
                            };
                          });
                          paths.push({
                            reachable: fn.reachable === true,
                            steps
                          });
                        });
                      });
                      
                      if (paths.length === 0) return null;
                      
                      const targetPackage = selectedOssIssue.package?.name || '';
                      
                      // inferReachabilityStepType 함수
                      const inferStepType = (step, index, total) => {
                        const normalizedTarget = targetPackage.toLowerCase();
                        const packageName = step.packageName ? step.packageName.toLowerCase() : '';
                        
                        if (index === total - 1) {
                          return { label: 'Vulnerable package', marker: 'vulnerable' };
                        }
                        
                        if (normalizedTarget && packageName && packageName === normalizedTarget) {
                          return { label: 'Direct package', marker: 'package' };
                        }
                        
                        if (index === 0) {
                          return { label: 'Entry point', marker: 'entry' };
                        }
                        
                        if (step.packageName) {
                          return { label: 'Direct package', marker: 'package' };
                        }
                        
                        return { label: 'Call', marker: 'call' };
                      };
                      
                      // 현재 인덱스의 path 표시
                      const currentPath = paths[currentPathIndex] || paths[0];
                      if (!currentPath || !currentPath.steps || currentPath.steps.length === 0) return null;
                      
                      const totalPaths = paths.length;
                      const canGoPrev = currentPathIndex > 0;
                      const canGoNext = currentPathIndex < totalPaths - 1;
                      
                      return (
                        <div className="reachability-view" style={{ marginTop: '24px' }}>
                          {/* Reachable functions와 경로 네비게이션 버튼 */}
                          <div className="reachability-view__header">
                            {selectedOssIssue.reachable_functions !== undefined && (
                              <div className="reachability-view__functions-count">
                                Reachable functions: {selectedOssIssue.reachable_functions} / {selectedOssIssue.functions_count || 0}
                              </div>
                            )}
                            {totalPaths > 1 && (
                              <div className="reachability-view__navigation">
                                <button
                                  onClick={() => setCurrentPathIndex(prev => Math.max(0, prev - 1))}
                                  disabled={!canGoPrev}
                                >
                                  &lt;
                                </button>
                                <span>
                                  {currentPathIndex + 1} / {totalPaths}
                                </span>
                                <button
                                  onClick={() => setCurrentPathIndex(prev => Math.min(totalPaths - 1, prev + 1))}
                                  disabled={!canGoNext}
                                >
                                  &gt;
                                </button>
                              </div>
                            )}
                          </div>
                          <ol className="reachability-steps">
                            {currentPath.steps.map((step, idx) => {
                              const typeInfo = inferStepType(step, idx, currentPath.steps.length);
                              // 제목은 함수명만 표시 (이미 steps 생성 시 추출됨)
                              const title = step.functionName || 'Anonymous function';
                              
                              // 메타 정보: 파일 경로와 실제 패키지명
                              const metaParts = [];
                              if (step.file) {
                                metaParts.push(step.file);
                              }
                              // packageName은 항상 표시 (중간 단계에도 패키지명 표시)
                              if (step.packageName) {
                                metaParts.push(step.packageName);
                              }
                              
                              return (
                                <li key={`step-${idx}`} className="reachability-step">
                                  <div className="reachability-step__timeline">
                                    <span className={`reachability-step__marker reachability-step__marker--${typeInfo.marker}`}></span>
                                    {idx < currentPath.steps.length - 1 && <span className="reachability-step__line"></span>}
                                  </div>
                                  <div className="reachability-step__content">
                                    <span className={`reachability-step__badge reachability-step__badge--${typeInfo.marker}`}>
                                      {typeInfo.label}
                                    </span>
                                    <span className="reachability-step__title">{title}</span>
                                    {metaParts.length > 0 && (
                                      <span className="reachability-step__meta">
                                        {metaParts.map((part, i) => (
                                          <span key={i}>
                                            {part}
                                            {i < metaParts.length - 1 && <span className="reachability-step__meta-separator">•</span>}
                                          </span>
                                        ))}
                                      </span>
                                    )}
                                  </div>
                                </li>
                              );
                            })}
                          </ol>
                        </div>
                      );
                    })()}
                  </div>
                </section>
              </div>
              </aside>
            </div>
          )}

      {/* MCP 취약점 카테고리 설명 모달 */}
      {showMcpInfoModal && (
        <div 
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 3000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: 'rgba(0, 0, 0, 0.5)'
          }}
          onClick={() => setShowMcpInfoModal(false)}
        >
          <div 
            style={{
              backgroundColor: '#fff',
              borderRadius: '12px',
              padding: '32px',
              maxWidth: '800px',
              width: '90%',
              maxHeight: '90vh',
              overflowY: 'auto',
              boxShadow: '0 20px 60px rgba(0, 0, 0, 0.3)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <h2 style={{ margin: 0, fontSize: '24px', fontWeight: 700, color: '#333' }}>MCP AI Agent Tool Risk</h2>
              <button
                onClick={() => setShowMcpInfoModal(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  fontSize: '28px',
                  cursor: 'pointer',
                  color: '#666',
                  padding: '0',
                  width: '32px',
                  height: '32px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  borderRadius: '6px',
                  transition: 'all 0.15s ease'
                }}
                onMouseEnter={(e) => {
                  e.target.style.backgroundColor = '#f0f0f0';
                  e.target.style.color = '#333';
                }}
                onMouseLeave={(e) => {
                  e.target.style.backgroundColor = 'transparent';
                  e.target.style.color = '#666';
                }}
              >
                &times;
              </button>
            </div>
            

            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* MCP-01 */}
              <div style={{ border: '1px solid #e0e0e0', borderRadius: '8px', padding: '20px', backgroundColor: '#fff' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                  <span style={{
                    padding: '6px 12px',
                    borderRadius: '4px',
                    backgroundColor: '#dc3545',
                    color: '#fff',
                    fontSize: '0.875rem',
                    fontWeight: 600
                  }}>
                    MCP-01
                  </span>
                  <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: '#333' }}>AI Tool Selection Risk</h3>
                </div>
                <div>
                  <strong style={{ color: '#666', fontSize: '14px' }}>설명:</strong>
                  <p style={{ margin: '4px 0 0 0', fontSize: '14px', lineHeight: '1.6', color: '#666' }}>
                    위험한 작업(delete, remove, destroy 등)을 수행하는 도구가 일반 도구와 섞여 있고, 경고 문구가 없는 경우 잘못된 도구를 선택할 위험이 있습니다.
                  </p>
                </div>
              </div>

              {/* MCP-02 */}
              <div style={{ border: '1px solid #e0e0e0', borderRadius: '8px', padding: '20px', backgroundColor: '#fff' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                  <span style={{
                    padding: '6px 12px',
                    borderRadius: '4px',
                    backgroundColor: '#fd7e14',
                    color: '#fff',
                    fontSize: '0.875rem',
                    fontWeight: 600
                  }}>
                    MCP-02
                  </span>
                  <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: '#333' }}>Context Injection Risk</h3>
                </div>
                <div>
                  <strong style={{ color: '#666', fontSize: '14px' }}>설명:</strong>
                  <p style={{ margin: '4px 0 0 0', fontSize: '14px', lineHeight: '1.6', color: '#666' }}>
                    사용자 입력이 검증 없이 API 경로나 파라미터로 직접 사용될 경우 보안 위험이 발생할 수 있습니다.
                  </p>
                </div>
              </div>

              {/* MCP-03 */}
              <div style={{ border: '1px solid #e0e0e0', borderRadius: '8px', padding: '20px', backgroundColor: '#fff' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                  <span style={{
                    padding: '6px 12px',
                    borderRadius: '4px',
                    backgroundColor: '#ffc107',
                    color: '#fff',
                    fontSize: '0.875rem',
                    fontWeight: 600
                  }}>
                    MCP-03
                  </span>
                  <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: '#333' }}>Autonomous Execution Risk</h3>
                </div>
                <div>
                  <strong style={{ color: '#666', fontSize: '14px' }}>설명:</strong>
                  <p style={{ margin: '4px 0 0 0', fontSize: '14px', lineHeight: '1.6', color: '#666' }}>
                    사용자 확인 없이 수정/삭제 작업(DELETE, PATCH, PUT)을 수행할 수 있는 API가 많은 경우 위험합니다.
                  </p>
                </div>
              </div>

              {/* MCP-04 */}
              <div style={{ border: '1px solid #e0e0e0', borderRadius: '8px', padding: '20px', backgroundColor: '#fff' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                  <span style={{
                    padding: '6px 12px',
                    borderRadius: '4px',
                    backgroundColor: '#20c997',
                    color: '#fff',
                    fontSize: '0.875rem',
                    fontWeight: 600
                  }}>
                    MCP-04
                  </span>
                  <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: '#333' }}>Tool Combination Risk</h3>
                </div>
                <div>
                  <strong style={{ color: '#666', fontSize: '14px' }}>설명:</strong>
                  <p style={{ margin: '4px 0 0 0', fontSize: '14px', lineHeight: '1.6', color: '#666' }}>
                    정보를 읽는 도구와 수정/삭제하는 도구가 함께 제공될 경우, 정보 수집 후 악용할 위험이 있습니다.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
      </div>
    );
  };

  return viewMode === 'list' ? renderListView() : renderResultView();
};

export default RiskAssessment;



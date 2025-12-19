import React, { useState, useEffect } from 'react';
import { apiGet, apiPut, apiPost, apiDelete } from '../../utils/api';
import './Settings.css';

const Settings = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('profile'); // 'profile', 'password', or 'api-keys'
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [message, setMessage] = useState({ type: '', text: '' });
  const [apiKeys, setApiKeys] = useState([]);
  const [mcpServers, setMcpServers] = useState([]);
  const [apiKeyForm, setApiKeyForm] = useState({
    mcp_server_name: '',
    field_name: '',
    field_value: ''
  });
  const [editingKey, setEditingKey] = useState(null);
  const [showCustomServerInput, setShowCustomServerInput] = useState(false);

  useEffect(() => {
    fetchUserInfo();
  }, []);

  useEffect(() => {
    if (activeTab === 'api-keys') {
      fetchApiKeys();
      fetchMcpServers();
    }
  }, [activeTab]);

  const fetchUserInfo = async () => {
    try {
      setLoading(true);
      const savedUser = localStorage.getItem('user');
      if (savedUser) {
        const userData = JSON.parse(savedUser);
        setUser(userData);
      }
      
      // 서버에서 최신 정보 가져오기
      try {
        const res = await apiGet(`/users/me`);
        if (res.success && res.data) {
          setUser(res.data);
        } else {
          console.warn('사용자 정보 응답 형식 오류:', res);
        }
      } catch (apiError) {
        console.error('API 호출 오류:', apiError);
        // API 실패해도 localStorage의 사용자 정보는 표시
        if (!savedUser) {
          setMessage({ type: 'error', text: '사용자 정보를 불러오는데 실패했습니다.' });
        }
      }
    } catch (error) {
      console.error('사용자 정보 로드 실패:', error);
      setMessage({ type: 'error', text: '사용자 정보를 불러오는데 실패했습니다.' });
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setMessage({ type: '', text: '' });

    // 유효성 검사
    if (!passwordForm.currentPassword || !passwordForm.newPassword || !passwordForm.confirmPassword) {
      setMessage({ type: 'error', text: '모든 필드를 입력해주세요.' });
      return;
    }

    if (passwordForm.newPassword.length < 4) {
      setMessage({ type: 'error', text: '새 비밀번호는 최소 4자 이상이어야 합니다.' });
      return;
    }

    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setMessage({ type: 'error', text: '새 비밀번호와 확인 비밀번호가 일치하지 않습니다.' });
      return;
    }

    if (passwordForm.currentPassword === passwordForm.newPassword) {
      setMessage({ type: 'error', text: '현재 비밀번호와 새 비밀번호가 같습니다.' });
      return;
    }

    try {
      const res = await apiPut(`/users/me/password`, {
        currentPassword: passwordForm.currentPassword,
        newPassword: passwordForm.newPassword
      });

      if (res.success) {
        setMessage({ type: 'success', text: '비밀번호가 성공적으로 변경되었습니다.' });
        setPasswordForm({
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        });
      } else {
        setMessage({ type: 'error', text: res.message || '비밀번호 변경에 실패했습니다.' });
      }
    } catch (error) {
      console.error('비밀번호 변경 실패:', error);
      setMessage({ type: 'error', text: '비밀번호 변경 중 오류가 발생했습니다.' });
    }
  };

  const fetchApiKeys = async () => {
    try {
      const res = await apiGet('/users/me/api-keys');
      if (res.success && res.data) {
        setApiKeys(res.data || []);
      }
    } catch (error) {
      console.error('API 키 조회 실패:', error);
      setMessage({ type: 'error', text: 'API 키 목록을 불러오는데 실패했습니다.' });
    }
  };

  const fetchMcpServers = async () => {
    try {
      // 승인된 서버 목록 가져오기
      const serversRes = await apiGet('/marketplace');
      const approvedServers = serversRes.success && serversRes.data 
        ? (serversRes.data || []).filter(server => server.status === 'approved')
        : [];
      
      // 등록 요청 중인 서버 목록 가져오기
      const requestsRes = await apiGet('/marketplace/requests?status=pending');
      const pendingRequests = requestsRes.success && requestsRes.data 
        ? (requestsRes.data || []).map(request => ({
            id: request.id,
            name: request.name,
            description: request.description || request.title || '',
            status: 'pending'
          }))
        : [];
      
      // 승인된 서버와 등록 요청 중인 서버를 합치기
      const allServers = [
        ...approvedServers.map(s => ({ ...s, status: 'approved' })),
        ...pendingRequests
      ];
      
      // 중복 제거 (같은 이름이 있으면 승인된 것을 우선)
      const uniqueServers = [];
      const seenNames = new Set();
      [...approvedServers, ...pendingRequests].forEach(server => {
        if (!seenNames.has(server.name)) {
          seenNames.add(server.name);
          uniqueServers.push(server);
        }
      });
      
      setMcpServers(uniqueServers);
    } catch (error) {
      console.error('MCP 서버 목록 조회 실패:', error);
    }
  };

  const handleApiKeySubmit = async (e) => {
    e.preventDefault();
    setMessage({ type: '', text: '' });

    if (!apiKeyForm.mcp_server_name || !apiKeyForm.field_name || !apiKeyForm.field_value) {
      setMessage({ type: 'error', text: 'MCP 서버, 필드명, 필드값은 필수입니다.' });
      return;
    }

    try {
      if (editingKey) {
        // 수정
        const res = await apiPut(`/users/me/api-keys/${editingKey.id}`, apiKeyForm);
        if (res.success) {
          setMessage({ type: '', text: '' });
          setApiKeyForm({
            mcp_server_name: '',
            field_name: '',
            field_value: ''
          });
          setEditingKey(null);
          fetchApiKeys();
        } else {
          setMessage({ type: 'error', text: res.message || 'API 키 수정에 실패했습니다.' });
        }
      } else {
        // 생성
        try {
          const res = await apiPost('/users/me/api-keys', apiKeyForm);
          if (res.success) {
            setMessage({ type: 'success', text: res.message || 'API 키가 등록되었습니다.' });
            setApiKeyForm({
              mcp_server_name: '',
              field_name: '',
              field_value: ''
            });
            fetchApiKeys();
          } else {
            setMessage({ type: 'error', text: res.message || 'API 키 등록에 실패했습니다.' });
          }
        } catch (apiError) {
          // apiPost에서 발생한 에러 처리
          console.error('API POST 오류 상세:', apiError);
          const errorMessage = apiError.message || (apiError.responseText ? JSON.parse(apiError.responseText).message : null) || 'API 키 등록 중 오류가 발생했습니다.';
          setMessage({ type: 'error', text: errorMessage });
          throw apiError; // 상위 catch로 전달
        }
      }
    } catch (error) {
      console.error('API 키 등록/수정 실패:', error);
      // 실제 에러 메시지 표시 (백엔드에서 반환한 메시지 또는 네트워크 오류)
      const errorMessage = error.message || error.responseText || 'API 키 등록/수정 중 오류가 발생했습니다.';
      setMessage({ type: 'error', text: errorMessage });
    }
  };

  const handleEditApiKey = (key) => {
    setEditingKey(key);
    setShowCustomServerInput(false);
    setApiKeyForm({
      mcp_server_name: key.mcp_server_name,
      field_name: key.field_name,
      field_value: '' // 보안상 빈 값으로 설정 (사용자가 다시 입력)
    });
  };

  const handleDeleteApiKey = async (id) => {
    if (!window.confirm('정말로 이 API 키를 삭제하시겠습니까?')) {
      return;
    }

    try {
      const res = await apiDelete(`/users/me/api-keys/${id}`);
      if (res.success) {
        setMessage({ type: '', text: '' });
        fetchApiKeys();
      } else {
        setMessage({ type: 'error', text: res.message || 'API 키 삭제에 실패했습니다.' });
      }
    } catch (error) {
      console.error('API 키 삭제 실패:', error);
      setMessage({ type: 'error', text: 'API 키 삭제 중 오류가 발생했습니다.' });
    }
  };

  if (loading) {
    return (
      <section className="settings">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>로딩 중...</p>
        </div>
      </section>
    );
  }

  if (!user) {
    return (
      <section className="settings">
        <div className="error-message">사용자 정보를 불러올 수 없습니다.</div>
      </section>
    );
  }

  return (
    <section className="settings">
      <h1>Settings</h1>
      
      <div className="settings-container">
        <div className="settings-tabs">
          <button
            className={`settings-tab ${activeTab === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveTab('profile')}
          >
            내 정보
          </button>
          <button
            className={`settings-tab ${activeTab === 'password' ? 'active' : ''}`}
            onClick={() => setActiveTab('password')}
          >
            비밀번호 변경
          </button>
          <button
            className={`settings-tab ${activeTab === 'api-keys' ? 'active' : ''}`}
            onClick={() => setActiveTab('api-keys')}
          >
            API 키 등록
          </button>
        </div>

        <div className="settings-content">
          {activeTab === 'profile' && (
            <div className="profile-section">
              <h2>내 정보</h2>
              <div className="info-card">
                <div className="info-row">
                  <span className="info-label">사용자명</span>
                  <span className="info-value">{user.username || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">사원번호</span>
                  <span className="info-value">{user.employee_id || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">이메일</span>
                  <span className="info-value">{user.email || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">팀</span>
                  <span className="info-value">{user.team || '미지정'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">직책</span>
                  <span className="info-value">{user.position || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">역할</span>
                  <span className="info-value">
                    {user.roles && user.roles.length > 0 ? (
                      <div className="role-badges">
                        {user.roles.map((role, index) => (
                          <span key={index} className={`role-badge ${role === 'admin' ? 'admin' : ''}`}>
                            {role}
                          </span>
                        ))}
                      </div>
                    ) : (
                      '-'
                    )}
                  </span>
                </div>
                <div className="info-row">
                  <span className="info-label">IP 주소</span>
                  <span className="info-value">{user.ip_address || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">계정 상태</span>
                  <span className={`status-badge ${user.is_active ? 'status-active' : 'status-inactive'}`}>
                    {user.is_active ? '활성' : '비활성'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'password' && (
            <div className="password-section">
              <h2>비밀번호 변경</h2>
              <form onSubmit={handlePasswordChange} className="password-form">
                {message.text && (
                  <div className={`message ${message.type}`}>
                    {message.text}
                  </div>
                )}
                <div className="form-group">
                  <label htmlFor="currentPassword">현재 비밀번호</label>
                  <input
                    type="password"
                    id="currentPassword"
                    value={passwordForm.currentPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
                    placeholder="현재 비밀번호를 입력하세요"
                    required
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="newPassword">새 비밀번호</label>
                  <input
                    type="password"
                    id="newPassword"
                    value={passwordForm.newPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
                    placeholder="새 비밀번호를 입력하세요"
                    required
                    minLength={4}
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="confirmPassword">새 비밀번호 확인</label>
                  <input
                    type="password"
                    id="confirmPassword"
                    value={passwordForm.confirmPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })}
                    placeholder="새 비밀번호를 다시 입력하세요"
                    required
                    minLength={4}
                  />
                </div>
                <div className="form-actions">
                  <button type="submit" className="btn-save">비밀번호 변경</button>
                </div>
              </form>
            </div>
          )}

          {activeTab === 'api-keys' && (
            <div className="api-keys-section">
              <h2>API 키 등록</h2>

              {message.text && (
                <div className={`message ${message.type}`} style={{ marginBottom: '20px' }}>
                  {message.text}
                </div>
              )}

              <form onSubmit={handleApiKeySubmit} className="api-key-form">
                <div className="form-group">
                  <label htmlFor="mcp_server_name">MCP 서버</label>
                  {!showCustomServerInput ? (
                    <>
                      <select
                        id="mcp_server_name"
                        value={apiKeyForm.mcp_server_name}
                        onChange={(e) => {
                          const value = e.target.value;
                          if (value === '__custom__') {
                            setShowCustomServerInput(true);
                            setApiKeyForm({ ...apiKeyForm, mcp_server_name: '' });
                          } else {
                            setApiKeyForm({ ...apiKeyForm, mcp_server_name: value });
                          }
                        }}
                        required
                        className="form-select"
                      >
                        <option value="">서버를 선택하세요</option>
                        {mcpServers.map(server => (
                          <option key={server.id || `pending-${server.name}`} value={server.name}>
                            {server.name} 
                            {server.status === 'pending' ? ' (승인 대기 중)' : ''}
                            {server.description ? ` - ${server.description}` : ''}
                          </option>
                        ))}
                        <option value="__custom__">+ 직접 입력</option>
                      </select>
                    </>
                  ) : (
                    <>
                      <input
                        type="text"
                        id="mcp_server_name"
                        placeholder="MCP 서버 이름을 입력하세요"
                        value={apiKeyForm.mcp_server_name}
                        onChange={(e) => setApiKeyForm({ ...apiKeyForm, mcp_server_name: e.target.value })}
                        required
                        className="form-group input"
                      />
                      <button
                        type="button"
                        onClick={() => {
                          setShowCustomServerInput(false);
                          setApiKeyForm({ ...apiKeyForm, mcp_server_name: '' });
                        }}
                        style={{
                          marginTop: '8px',
                          padding: '6px 12px',
                          background: '#f3f4f6',
                          border: '1px solid #d1d5db',
                          borderRadius: '6px',
                          fontSize: '0.85rem',
                          cursor: 'pointer'
                        }}
                      >
                        목록에서 선택
                      </button>
                    </>
                  )}
                </div>

                <div className="form-group">
                  <label htmlFor="field_name">필드명</label>
                  <input
                    type="text"
                    id="field_name"
                    value={apiKeyForm.field_name}
                    onChange={(e) => setApiKeyForm({ ...apiKeyForm, field_name: e.target.value })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="field_value">필드값</label>
                  <input
                    type="text"
                    id="field_value"
                    value={apiKeyForm.field_value}
                    onChange={(e) => setApiKeyForm({ ...apiKeyForm, field_value: e.target.value })}
                    required
                  />
                </div>

                <div className="form-actions">
                  {editingKey && (
                    <button
                      type="button"
                      className="btn-cancel"
                      onClick={() => {
                        setEditingKey(null);
                        setShowCustomServerInput(false);
                        setApiKeyForm({
                          mcp_server_name: '',
                          field_name: '',
                          field_value: ''
                        });
                      }}
                    >
                      취소
                    </button>
                  )}
                  <button type="submit" className="btn-save">
                    {editingKey ? '수정' : '+ 추가하기'}
                  </button>
                </div>
              </form>

              <div className="api-keys-list" style={{ marginTop: '32px' }}>
                <h3 style={{ marginBottom: '16px', fontSize: '1.1rem', fontWeight: '600' }}>등록된 API 키</h3>
                {apiKeys.length === 0 ? (
                  <p style={{ color: '#6b7280', textAlign: 'center', padding: '24px' }}>등록된 API 키가 없습니다.</p>
                ) : (
                  <div className="api-keys-table">
                    {apiKeys.map(key => (
                      <div key={key.id} className="api-key-item">
                        <div className="api-key-info">
                          <div><strong>{key.mcp_server_name}</strong></div>
                          <div style={{ fontSize: '0.9rem', color: '#6b7280' }}>
                            {key.field_name}: {key.field_value}
                          </div>
                        </div>
                        <div className="api-key-actions">
                          <button
                            className="btn-edit"
                            onClick={() => handleEditApiKey(key)}
                          >
                            수정
                          </button>
                          <button
                            className="btn-delete"
                            onClick={() => handleDeleteApiKey(key.id)}
                          >
                            삭제
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};

export default Settings;


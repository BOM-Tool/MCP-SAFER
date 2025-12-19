import React, { useState, useEffect } from 'react';
import { apiPost, API_BASE_URL } from '../../utils/api';
import './ServerRequest.css';

const ServerRequest = () => {
  const [form, setForm] = useState({ 
    name: '', 
    description: '', 
    connection: '', 
    github: '', 
    file: null,
    image: null,
    auth_tokens: [{ field_name: '', field_value: '' }],
    execution_args: ['']
  });
  const [imagePreview, setImagePreview] = useState(null);
  const [showRequestForm, setShowRequestForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // ESC 키로 모달 닫기
  useEffect(() => {
    if (!showRequestForm) return;

    const handleEscape = (e) => {
      if (e.key === 'Escape' && !submitting) {
        setShowRequestForm(false);
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => {
      window.removeEventListener('keydown', handleEscape);
    };
  }, [showRequestForm, submitting]);

  const onChange = (e) => {
    const { name, value, files } = e.target;
    if (name === 'image' && files && files[0]) {
      const file = files[0];
      setForm((prev) => ({ ...prev, [name]: file }));
      // 이미지 미리보기 생성
      const reader = new FileReader();
      reader.onloadend = () => {
        setImagePreview(reader.result);
      };
      reader.readAsDataURL(file);
    } else {
      setForm((prev) => ({ ...prev, [name]: files ? files[0] : value }));
    }
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    
    // 유효성 검사
    if (!form.name.trim()) {
      alert('MCP Server Name은 필수입니다.');
      return;
    }
    
    if (!form.description.trim()) {
      alert('MCP Server Description은 필수입니다.');
      return;
    }
    
    if (!form.connection.trim()) {
      alert('Connection은 필수입니다.');
      return;
    }
    
    // GitHub 링크나 파일 중 하나는 반드시 있어야 함
    if (!form.github.trim() && !form.file) {
      alert('Github Link 또는 File 중 하나는 반드시 입력해야 합니다.');
      return;
    }
    
    try {
      // localStorage에서 사용자 정보 가져오기
      const savedUser = localStorage.getItem('user');
      if (!savedUser) {
        alert('로그인이 필요합니다.');
        return;
      }
      const user = JSON.parse(savedUser);

      setSubmitting(true);

      const formData = new FormData();
      formData.append('name', form.name);
      formData.append('description', form.description);
      formData.append('connection', form.connection || '');
      formData.append('github', form.github);
      formData.append('user_id', user.id);
      
      // 토큰 배열 처리 (값이 있는 것만 전송)
      const validTokens = form.auth_tokens.filter(token => token.field_name && token.field_value);
      if (validTokens.length > 0) {
        // 첫 번째 토큰은 기존 방식으로도 전송 (하위 호환성)
        formData.append('auth_field_name', validTokens[0].field_name);
        formData.append('auth_field_value', validTokens[0].field_value);
        // 여러 개인 경우 JSON으로 전송
        if (validTokens.length > 1) {
          formData.append('auth_tokens', JSON.stringify(validTokens));
        }
      }
      
      // 실행 인자 배열 처리 (값이 있는 것만 공백으로 합쳐서 전송)
      const validArgs = form.execution_args.filter(arg => arg.trim());
      if (validArgs.length > 0) {
        formData.append('execution_args', validArgs.join(' '));
      }
      if (form.file) {
        formData.append('file', form.file);
      }
      if (form.image) {
        formData.append('image', form.image);
      }

      const res = await fetch(`${API_BASE_URL}/marketplace/request`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: formData
      });

      // 응답이 JSON인지 확인
      const contentType = res.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await res.text();
        throw new Error(`서버 오류 (${res.status}): ${text.substring(0, 200)}`);
      }

      const data = await res.json();
      if (data.success) {
        alert(data.message || '등록 요청이 접수되었습니다.');
        setShowRequestForm(false);
        setForm({ name: '', description: '', connection: '', github: '', file: null, image: null, auth_tokens: [{ field_name: '', field_value: '' }], execution_args: [''] });
        setImagePreview(null);
      } else {
        alert(data.message || '등록 요청 실패');
      }
    } catch (error) {
      console.error('등록 요청 오류:', error);
      // 네트워크 오류인 경우
      if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
        alert('서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.');
      } else {
        alert(`등록 요청 중 오류가 발생했습니다: ${error.message || error.toString()}`);
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="server-request-section">
      <div className="server-request-header">
        <h1>MCP Server Request</h1>
        <button 
          className="btn-primary request-button"
          onClick={() => setShowRequestForm(true)}
        >
          + New Server Request
        </button>
      </div>

      <div className="server-request-info">
        <div className="info-card">
          <h3>서버 신청 안내</h3>
          <ul>
            <li>새로운 MCP 서버를 등록하고 싶으시면 아래 "New Server Request" 버튼을 클릭하세요.</li>
            <li>서버 이름, 설명, 연결 방법, GitHub 링크 등을 입력해주세요.</li>
            <li>관리자 검토 후 승인되면 MCP Registry에 등록됩니다.</li>
            <li>신청 상태는 "Register Board"에서 확인할 수 있습니다.</li>
          </ul>
        </div>
      </div>

      {/* Bottom Sheet Modal */}
      {showRequestForm && (
        <div className="sheet-overlay" onClick={() => !submitting && setShowRequestForm(false)}>
          <div className="sheet" onClick={(e) => e.stopPropagation()}>
            <form className="request-form" onSubmit={onSubmit}>
              <h2>MCP Server Request</h2>
              <label className="file-field image-field">
                <span>Server Image (선택사항)</span>
                <input 
                  type="file" 
                  name="image" 
                  accept="image/*"
                  onChange={onChange}
                  disabled={submitting}
                />
                {imagePreview && (
                  <div className="image-preview">
                    <img src={imagePreview} alt="Preview" />
                    <button 
                      type="button" 
                      className="remove-image"
                      onClick={() => {
                        setForm(prev => ({ ...prev, image: null }));
                        setImagePreview(null);
                      }}
                      disabled={submitting}
                    >
                      ×
                    </button>
                  </div>
                )}
              </label>
              <label>
                <span>MCP Server Name</span>
                <input 
                  name="name" 
                  value={form.name} 
                  onChange={onChange} 
                  placeholder="ex) Github MCP Server" 
                  required 
                  disabled={submitting}
                />
              </label>
              <label>
                <span>MCP Server Description</span>
                <textarea 
                  name="description" 
                  value={form.description} 
                  onChange={onChange} 
                  placeholder="서버에 대한 간단한 설명을 입력해주세요" 
                  rows={5} 
                  required 
                  disabled={submitting}
                />
              </label>
              <label>
                <span>Connection</span>
                <textarea 
                  name="connection" 
                  value={form.connection} 
                  onChange={onChange} 
                  placeholder="mcp.json 연결 방법" 
                  rows={5}
                  required
                  disabled={submitting}
                />
              </label>
              <label>
                <span>Github Link</span>
                <input 
                  name="github" 
                  value={form.github} 
                  onChange={onChange} 
                  placeholder="https://github.com/..." 
                  disabled={submitting}
                />
                <small style={{ display: 'block', marginTop: '4px', color: '#666', fontSize: '0.85rem' }}>
                  Github Link 또는 File Upload 중 하나는 필수입니다.
                </small>
              </label>
              <label className="file-field">
                <span>File Upload</span>
                <input 
                  type="file" 
                  name="file" 
                  onChange={onChange}
                  disabled={submitting}
                />
                <small style={{ display: 'block', marginTop: '4px', color: '#666', fontSize: '0.85rem' }}>
                  Github Link 또는 File Upload 중 하나는 필수입니다.
                </small>
              </label>
              <label>
                <span>Authentication Token (Optional)</span>
                {form.auth_tokens.map((token, index) => (
                  <div key={index} style={{ marginTop: index > 0 ? '16px' : '8px', padding: '12px', border: '1px solid #e5e7eb', borderRadius: '8px', backgroundColor: '#f9fafb' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '0.9rem', fontWeight: '500', color: '#374151' }}>토큰 {index + 1}</span>
                      {form.auth_tokens.length > 1 && (
                        <button
                          type="button"
                          onClick={() => {
                            const newTokens = form.auth_tokens.filter((_, i) => i !== index);
                            setForm({ ...form, auth_tokens: newTokens });
                          }}
                          disabled={submitting}
                          style={{ 
                            padding: '4px 8px', 
                            fontSize: '0.75rem', 
                            color: '#dc2626', 
                            background: 'transparent', 
                            border: '1px solid #dc2626', 
                            borderRadius: '4px',
                            cursor: 'pointer'
                          }}
                        >
                          삭제
                        </button>
                      )}
                    </div>
                    <div style={{ marginBottom: '8px' }}>
                      <label style={{ display: 'block', marginBottom: '4px', fontSize: '0.9rem', color: '#666' }}>
                        필드명
                      </label>
                      <input
                        type="text"
                        value={token.field_name}
                        onChange={(e) => {
                          const newTokens = [...form.auth_tokens];
                          newTokens[index].field_name = e.target.value;
                          setForm({ ...form, auth_tokens: newTokens });
                        }}
                        placeholder="예: GITHUB_PERSONAL_ACCESS_TOKEN"
                        disabled={submitting}
                        style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                      />
                    </div>
                    <div>
                      <label style={{ display: 'block', marginBottom: '4px', fontSize: '0.9rem', color: '#666' }}>
                        필드값
                      </label>
                      <input
                        type="password"
                        value={token.field_value}
                        onChange={(e) => {
                          const newTokens = [...form.auth_tokens];
                          newTokens[index].field_value = e.target.value;
                          setForm({ ...form, auth_tokens: newTokens });
                        }}
                        placeholder="토큰 값을 입력하세요"
                        disabled={submitting}
                        style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                      />
                    </div>
                  </div>
                ))}
                <button
                  type="button"
                  onClick={() => {
                    setForm({ ...form, auth_tokens: [...form.auth_tokens, { field_name: '', field_value: '' }] });
                  }}
                  disabled={submitting}
                  style={{ 
                    marginTop: '12px', 
                    padding: '8px 16px', 
                    fontSize: '0.9rem', 
                    color: '#374151', 
                    background: 'transparent', 
                    border: '1px solid #d1d5db', 
                    borderRadius: '6px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  <span>+</span> 토큰 추가
                </button>
              </label>
              <label>
                <span>Execution Arguments (Optional)</span>
                {form.execution_args.map((arg, index) => (
                  <div key={index} style={{ marginTop: index > 0 ? '12px' : '8px', display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
                    <input
                      type="text"
                      value={arg}
                      onChange={(e) => {
                        const newArgs = [...form.execution_args];
                        newArgs[index] = e.target.value;
                        setForm({ ...form, execution_args: newArgs });
                      }}
                      placeholder="예: --toolsets all"
                      disabled={submitting}
                      style={{ flex: 1, padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                    />
                    {form.execution_args.length > 1 && (
                      <button
                        type="button"
                        onClick={() => {
                          const newArgs = form.execution_args.filter((_, i) => i !== index);
                          setForm({ ...form, execution_args: newArgs });
                        }}
                        disabled={submitting}
                        style={{ 
                          padding: '8px 12px', 
                          fontSize: '0.9rem', 
                          color: '#dc2626', 
                          background: 'transparent', 
                          border: '1px solid #dc2626', 
                          borderRadius: '4px',
                          cursor: 'pointer',
                          whiteSpace: 'nowrap'
                        }}
                      >
                        삭제
                      </button>
                    )}
                  </div>
                ))}
                <button
                  type="button"
                  onClick={() => {
                    setForm({ ...form, execution_args: [...form.execution_args, ''] });
                  }}
                  disabled={submitting}
                  style={{ 
                    marginTop: '12px', 
                    padding: '8px 16px', 
                    fontSize: '0.9rem', 
                    color: '#374151', 
                    background: 'transparent', 
                    border: '1px solid #d1d5db', 
                    borderRadius: '6px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  <span>+</span> 인자 추가
                </button>
                <small style={{ display: 'block', marginTop: '8px', color: '#666', fontSize: '0.85rem' }}>
                  MCP 서버 실행 시 추가할 인자를 입력하세요. 여러 개 입력 시 공백으로 구분되어 전달됩니다.
                </small>
              </label>
              <div className="request-actions">
                <button 
                  type="button" 
                  className="btn-secondary" 
                  onClick={() => setShowRequestForm(false)}
                  disabled={submitting}
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  className="btn-primary"
                  disabled={submitting}
                >
                  {submitting ? 'Submitting...' : 'Submit'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
};

export default ServerRequest;


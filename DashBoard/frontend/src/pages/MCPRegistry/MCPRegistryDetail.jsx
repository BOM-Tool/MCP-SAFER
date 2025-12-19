import React, { useState, useEffect } from 'react';
import { apiGet, API_BASE_URL } from '../../utils/api';
import './MCPRegistry.css';

const MCPRegistryDetail = ({ serverId, onClose }) => {
  const [item, setItem] = useState(null);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);

  useEffect(() => {
    // 로그인한 사용자 정보 가져오기
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }

    const fetchServerDetail = async () => {
      if (!serverId) {
        console.error('serverId가 없습니다.');
        setItem(null);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        
        // serverId 처리: "server_1" 형식이면 숫자만 추출, 아니면 그대로 사용
        let serverIdNum = serverId;
        if (typeof serverId === 'string' && serverId.startsWith('server_')) {
          serverIdNum = parseInt(serverId.replace('server_', ''), 10);
        } else if (typeof serverId === 'string') {
          serverIdNum = parseInt(serverId, 10);
        }
        
        console.log('서버 상세 정보 요청:', { serverId, serverIdNum, type: typeof serverId });
        
        if (isNaN(serverIdNum)) {
          console.error('유효하지 않은 serverId:', serverId);
          setItem(null);
          setLoading(false);
          return;
        }
        
        const data = await apiGet(`/marketplace/${serverIdNum}`);
        console.log('서버 상세 정보 응답:', data);
        
        if (data.success && data.data) {
          console.log('서버 데이터 설정:', data.data);
          setItem(data.data);
        } else {
          console.error('서버 상세 정보 로드 실패:', data.message || '알 수 없는 오류', data);
          setItem(null);
        }
      } catch (error) {
        console.error('서버 상세 정보 로드 실패:', error);
        console.error('에러 상세:', error.message, error.stack);
        setItem(null);
      } finally {
        setLoading(false);
      }
    };

    fetchServerDetail();
  }, [serverId]);

  // ESC 키로 모달 닫기
  useEffect(() => {
    const handleEscape = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => {
      window.removeEventListener('keydown', handleEscape);
    };
  }, [onClose]);

  const handleDelete = async () => {
    if (!window.confirm('정말로 이 서버를 삭제하시겠습니까?')) {
      return;
    }

    try {
      const { apiDelete } = await import('../../utils/api');
      const data = await apiDelete(`/marketplace/server/${serverId}`);
      
      if (data.success) {
        alert('서버가 삭제되었습니다.');
        onClose();
        // 페이지 새로고침 필요할 수 있음
        window.location.reload();
      } else {
        alert(data.message || '삭제 중 오류가 발생했습니다.');
      }
    } catch (error) {
      console.error('서버 삭제 실패:', error);
      alert('서버 삭제 중 오류가 발생했습니다.');
    }
  };

  const isAdmin = user && (
    (Array.isArray(user.roles) && user.roles.includes('admin')) || 
    user.role === 'admin'
  );

  if (loading) {
    return (
      <div className="detail-modal-overlay" onClick={onClose}>
        <div className="detail-modal" onClick={(e) => e.stopPropagation()}>
          <div>로딩 중...</div>
        </div>
      </div>
    );
  }

  if (!item) {
    return (
      <div className="detail-modal-overlay" onClick={onClose}>
        <div className="detail-modal" onClick={(e) => e.stopPropagation()}>
          <div>해당 MCP 정보를 찾을 수 없습니다.</div>
        </div>
      </div>
    );
  }

  return (
    <div className="detail-modal-overlay" onClick={onClose}>
      <div className="detail-modal" onClick={(e) => e.stopPropagation()}>
        <div className="detail-modal-header">
          <h1>{item.name || item.title}</h1>
          <div className="detail-modal-actions">
        {isAdmin && (
          <button onClick={handleDelete} className="btn-delete-server">
            삭제
          </button>
        )}
            <button onClick={onClose} className="btn-close-modal">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                <path d="M15 5L5 15M5 5L15 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              </svg>
            </button>
          </div>
      </div>

        <div className="detail-wrap">
      <div className="detail-card">
        <h2>Description</h2>
        <div className="description-box">
              <p>{item.description || item.short_description || '설명이 없습니다.'}</p>
        </div>
      </div>

      <div className="detail-card">
        <h2>Connection</h2>
        <div className="code-box">
              <pre><code>{item.connection_snippet || item.connectionSnippet || '연결 정보가 없습니다.'}</code></pre>
        </div>
      </div>

      <div className="detail-card">
        <h2>Download</h2>
        <div className="download-box">
          {item.file_path ? (
            <a 
              href={`${API_BASE_URL}/file/download/${item.id}?type=server${user ? `&user_id=${user.id}` : ''}`}
              download
              style={{ 
                display: 'inline-block',
                padding: '8px 16px',
                backgroundColor: '#003153',
                color: '#fff',
                textDecoration: 'none',
                borderRadius: '4px'
              }}
            >
              파일 다운로드
            </a>
          ) : (
            '[   ]  파일이 없습니다'
          )}
        </div>
      </div>
        </div>
      </div>
    </div>
  );
};

export default MCPRegistryDetail;
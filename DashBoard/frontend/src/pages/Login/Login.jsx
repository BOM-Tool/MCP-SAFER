import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiPost } from '../../utils/api';
import './Login.css';
import userIcon from '../../assets/login/user.png';
import pinIcon from '../../assets/login/pin.png';
import passwordIcon from '../../assets/login/password.png';

const Login = ({ onLogin }) => {
  const navigate = useNavigate();
  const [form, setForm] = useState({ username: '', employee_id: '', password: '' });
  const [error, setError] = useState('');
  
  // 컴포넌트 마운트 시 이전 localStorage 데이터 클리어 (클라우드 환경에서 이전 값 제거)
  React.useEffect(() => {
    // 로그인 페이지 진입 시 이전 스캔 관련 데이터만 클리어 (토큰과 사용자 정보는 유지하여 자동 로그인 가능)
    localStorage.removeItem('riskAnalysisResults');
    localStorage.removeItem('riskAssessmentScanId');
    localStorage.removeItem('riskAssessmentScanPath');
    localStorage.removeItem('riskAssessmentGithubUrl');
    localStorage.removeItem('riskAssessmentServerName');
    localStorage.removeItem('riskAssessmentTab');
  }, []);

  const onChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Username과 사원번호 모두 필수
    if (!form.username || !form.employee_id) {
      setError('Username과 사원번호를 모두 입력해주세요.');
      return;
    }

    try {
      const data = await apiPost('/auth/login', {
        username: form.username || null,
        employee_id: form.employee_id || null,
        password: form.password
      });

      if (data.success) {
        // JWT 토큰 저장
        if (data.token) {
          localStorage.setItem('token', data.token);
        }
        // 사용자 정보 저장
        localStorage.setItem('user', JSON.stringify(data.user));
        onLogin(data.user);
      } else {
        setError(data.message || '로그인 실패');
      }
    } catch (err) {
      // 에러 메시지 설정 (api.js에서 이미 상세한 메시지를 제공)
      let errorMessage = err.message || '서버 연결 오류가 발생했습니다.';
      
      // 401 에러인 경우 로그인 페이지로 리다이렉트
      if (err.status === 401) {
        window.location.href = '/';
        return;
      }
      
      // 네트워크 오류인 경우 추가 정보 표시
      if (err.url) {
        errorMessage += `\n\n요청 URL: ${err.url}`;
      }
      
      // 상태 코드가 있는 경우 추가 정보 표시
      if (err.status) {
        errorMessage += `\n상태 코드: ${err.status} ${err.statusText || ''}`;
      }
      
      setError(errorMessage);
      console.error('로그인 오류:', {
        message: err.message,
        status: err.status,
        statusText: err.statusText,
        url: err.url,
        originalError: err.originalError,
        error: err
      });
    }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h1>MCP Safer</h1>
        <form onSubmit={onSubmit}>
          <label>
            <span>Username</span>
            <div className="input-wrapper">
              <img src={userIcon} alt="user" className="input-icon" />
              <input
                type="text"
                name="username"
                value={form.username}
                onChange={onChange}
                placeholder="username"
                required
              />
            </div>
          </label>
          <label>
            <span>Employee number</span>
            <div className="input-wrapper">
              <img src={pinIcon} alt="pin" className="input-icon" />
              <input
                type="text"
                name="employee_id"
                value={form.employee_id}
                onChange={onChange}
                placeholder="Employee number"
                required
              />
            </div>
          </label>
          <label>
            <span>Password</span>
            <div className="input-wrapper">
              <img src={passwordIcon} alt="password" className="input-icon" />
              <input
                type="password"
                name="password"
                value={form.password}
                onChange={onChange}
                placeholder="password"
                required
              />
            </div>
          </label>
          {error && <div className="error-message">{error}</div>}
          <button type="submit" className="login-button">Login</button>
          <button 
            type="button" 
            className="register-link-button" 
            onClick={() => navigate('/register')}
          >
            Don't have an account? Sign up
          </button>
        </form>
      </div>
    </div>
  );
};

export default Login;


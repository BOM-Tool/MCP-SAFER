import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Register.css';

const Register = () => {
  const navigate = useNavigate();
  const [form, setForm] = useState({ 
    username: '', 
    employee_id: '', 
    password: '', 
    confirmPassword: '', 
    email: '', 
    team: '', 
    position: '' 
  });
  const [error, setError] = useState('');

  const onChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // 비밀번호 확인
    if (form.password !== form.confirmPassword) {
      setError('비밀번호가 일치하지 않습니다.');
      return;
    }

    // 간단한 유효성 검사
    if (form.password.length < 4) {
      setError('비밀번호는 최소 4자 이상이어야 합니다.');
      return;
    }

    try {
      const res = await fetch('http://localhost:3001/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: form.username,
          employee_id: form.employee_id,
          password: form.password,
          email: form.email,
          team: form.team || null,
          position: form.position || null
        })
      });

      const data = await res.json();

      if (data.success) {
        alert('회원가입이 완료되었습니다. 로그인해주세요.');
        navigate('/');
      } else {
        setError(data.message || '회원가입 실패');
      }
    } catch (err) {
      setError('서버 연결 오류');
    }
  };

  return (
    <div className="register-container">
      <div className="register-box">
        <h1>Sign Up</h1>
        <form onSubmit={onSubmit}>
          <label>
            <span>Username</span>
            <input
              type="text"
              name="username"
              value={form.username}
              onChange={onChange}
              placeholder="username"
              required
            />
          </label>
          <label>
            <span>Employee number</span>
            <input
              type="text"
              name="employee_id"
              value={form.employee_id}
              onChange={onChange}
              placeholder="EMP001"
              required
            />
          </label>
          <label>
            <span>Email</span>
            <input
              type="email"
              name="email"
              value={form.email}
              onChange={onChange}
              placeholder="email@example.com"
              required
            />
          </label>
          <label>
            <span>Team (optional)</span>
            <select
              name="team"
              value={form.team}
              onChange={onChange}
            >
              <option value="">선택하세요</option>
              <option value="Developer">Developer</option>
              <option value="Security">Security</option>
              <option value="Management">Management</option>
              <option value="HR">HR</option>
            </select>
          </label>
          <label>
            <span>Position (optional)</span>
            <input
              type="text"
              name="position"
              value={form.position}
              onChange={onChange}
              placeholder="ex: Developer, Manager"
            />
          </label>
          <label>
            <span>Password</span>
            <input
              type="password"
              name="password"
              value={form.password}
              onChange={onChange}
              placeholder="password"
              required
            />
          </label>
          <label>
            <span>Confirm Password</span>
            <input
              type="password"
              name="confirmPassword"
              value={form.confirmPassword}
              onChange={onChange}
              placeholder="Confirm password"
              required
            />
          </label>
          {error && <div className="error-message">{error}</div>}
          <button type="submit" className="register-button">Sign Up</button>
          <button 
            type="button" 
            className="login-link-button" 
            onClick={() => navigate('/login')}
          >
            Already have an account? Log in
          </button>
        </form>
      </div>
    </div>
  );
};

export default Register;


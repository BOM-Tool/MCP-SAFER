import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink, Navigate, useNavigate } from 'react-router-dom';
import './App.css';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import UserManagement from './pages/UserManagement';
import RequestBoard from './pages/RequestBoard';
import DownloadLogs from './pages/DownloadLogs';
import RiskAssessment from './pages/RiskAssessment';
import AnomalyDetection from './pages/AnomalyDetection';
import MCPRegistry from './pages/MCPRegistry';
import MCPRegistryDetail from './pages/MCPRegistry/MCPRegistryDetail';
import ServerRequest from './pages/ServerRequest/ServerRequest';
import Settings from './pages/Settings';
import DbTables from './pages/DbTables';

// 아이콘 import
import dashboardIcon from './assets/tab/dashboard.png';
import marketplaceIcon from './assets/tab/marketplace.png';
import requestServerIcon from './assets/tab/request_server.png';
import userIcon from './assets/tab/user.png';
import registerBoardIcon from './assets/tab/register_board.png';
import downloadLogsIcon from './assets/tab/download_logs.png';
import riskAssessmentIcon from './assets/tab/risk_assessment.png';
import dlpIcon from './assets/tab/dlp.png';
import settingIcon from './assets/tab/setting.png';

function Header() {
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const handleLogout = () => {
    // 모든 localStorage 데이터 클리어
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('riskAnalysisResults');
    localStorage.removeItem('riskAssessmentScanId');
    localStorage.removeItem('riskAssessmentScanPath');
    localStorage.removeItem('riskAssessmentGithubUrl');
    localStorage.removeItem('riskAssessmentServerName');
    localStorage.removeItem('riskAssessmentTab');
    window.location.href = '/';
  };

  const handleLogoClick = () => {
    if (user) {
      navigate('/marketplace');
    }
  };

  return (
    <header className="header">
      <div className="header-logo" onClick={handleLogoClick}>
        <span className="workspace">MCP Safer</span>
      </div>
      {user && (
        <div className="header-user">
          <span>{user.username}</span>
          <button onClick={handleLogout} className="logout-button">Logout</button>
        </div>
      )}
    </header>
  );
}

function Sidebar() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);  

  // 일반 사용자는 Dashboard 접근 불가
  const menuItems = [
    { path: '/marketplace', label: 'MCP Registry', icon: dashboardIcon, adminOnly: false },
    { path: '/server-request', label: 'Server Request', icon: requestServerIcon, adminOnly: false },
    { path: '/request-board', label: 'Request Board', icon: registerBoardIcon, adminOnly: false },
    { path: '/risk-assessment', label: 'Risk Assessment', icon: riskAssessmentIcon, adminOnly: true },
    { path: '/anomaly-detection', label: 'Anomaly Detection', icon: dlpIcon, adminOnly: true },
    { path: '/download-logs', label: 'Download Logs', icon: downloadLogsIcon, adminOnly: true }
  ];

  const userManagementItem = { path: '/user-management', label: 'User Management', icon: userIcon, adminOnly: true };
  const settingsItem = { path: '/settings', label: 'Settings', icon: settingIcon, adminOnly: false };

  // roles 배열에 'admin'이 포함되어 있는지 확인
  // user.roles가 배열이면 includes로 확인, 아니면 user.role로 확인 (하위 호환성)
  const isAdmin = user && (
    (Array.isArray(user.roles) && user.roles.includes('admin')) || 
    user.role === 'admin'
  );
  
  // 관리자는 모든 메뉴, 일반 사용자는 MarketPlace, Server Request, Request Board만
  const visibleItems = isAdmin 
    ? menuItems 
    : menuItems.filter(item => !item.adminOnly && (item.path === '/marketplace' || item.path === '/server-request' || item.path === '/request-board'));

  // Settings는 항상 표시
  const showSettings = true;

  return (
    <aside className="sidebar">
      <nav className="sidebar-menu">
        <div className="sidebar-menu-top">
        {visibleItems.map(item => {
          return (
            <NavLink 
              key={item.path} 
              to={item.path} 
              className={({ isActive }) => isActive ? 'active' : ''}
              title={item.label}
            >
              <div className="menu-item-wrapper">
                <img src={item.icon} alt={item.label} className="menu-icon" />
                <span className="menu-label">{item.label}</span>
              </div>
            </NavLink>
          );
        })}
        </div>
        <div className="sidebar-menu-bottom">
          {isAdmin && (
            <NavLink 
              to={userManagementItem.path} 
              className={({ isActive }) => isActive ? 'active' : ''}
              title={userManagementItem.label}
            >
              <img src={userManagementItem.icon} alt={userManagementItem.label} className="menu-icon" />
              <span className="menu-label">{userManagementItem.label}</span>
            </NavLink>
          )}
          {showSettings && (
            <NavLink 
              to={settingsItem.path} 
              className={({ isActive }) => isActive ? 'active' : ''}
              title={settingsItem.label}
            >
              <img src={settingsItem.icon} alt={settingsItem.label} className="menu-icon" />
              <span className="menu-label">{settingsItem.label}</span>
            </NavLink>
          )}
        </div>
      </nav>
    </aside>
  );
}

function ProtectedRoute({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function AdminRoute({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  
  // roles 배열에 'admin'이 포함되어 있는지 확인 (하위 호환성: user.role도 체크)
  const isAdmin = user.roles?.includes('admin') || user.role === 'admin';
  if (!isAdmin) return <Navigate to="/marketplace" replace />;
  return children;
}

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
  };

  if (loading) return null;

  if (!user) {
    return (
      <Router>
        <Routes>
          <Route path="/register" element={<Register />} />
          <Route path="*" element={<Login onLogin={handleLogin} />} />
        </Routes>
      </Router>
    );
  }

  return (
    <Router>
      <div className="app-layout">
        <Header />
        <div className="content-row">
          <Sidebar />
          <div className="main-content">
            <Routes>
              <Route 
                path="/user-management" 
                element={
                  <AdminRoute>
                    <UserManagement />
                  </AdminRoute>
                } 
              />
              <Route 
                path="/server-request" 
                element={
                  <ProtectedRoute>
                    <ServerRequest />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/request-board" 
                element={
                  <ProtectedRoute>
                    <RequestBoard />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/download-logs" 
                element={
                  <AdminRoute>
                    <DownloadLogs />
                  </AdminRoute>
                } 
              />
              <Route path="/risk-assessment" element={<ProtectedRoute><RiskAssessment /></ProtectedRoute>} />
              <Route path="/sbom-sca" element={<Navigate to="/risk-assessment" replace />} />
              <Route path="/scanner" element={<Navigate to="/risk-assessment" replace />} />
              <Route path="/anomaly-detection" element={<ProtectedRoute><AnomalyDetection /></ProtectedRoute>} />
              <Route path="/marketplace" element={<ProtectedRoute><MCPRegistry /></ProtectedRoute>} />
              <Route path="/marketplace/:id" element={<ProtectedRoute><MCPRegistryDetail /></ProtectedRoute>} />
              <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
              <Route path="/db-tables" element={<ProtectedRoute><DbTables /></ProtectedRoute>} />
              <Route path="/login" element={<Navigate to="/marketplace" replace />} />
              <Route path="/register" element={<Navigate to="/marketplace" replace />} />
              <Route path="*" element={<Navigate to="/marketplace" replace />} />
            </Routes>
          </div>
        </div>
      </div>
    </Router>
  );
}

export default App;

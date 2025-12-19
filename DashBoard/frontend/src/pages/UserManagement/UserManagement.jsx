import React, { useState, useEffect } from 'react';
import { apiGet, apiPut, apiPost, apiDelete } from '../../utils/api';
import './UserManagement.css';

const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingUser, setEditingUser] = useState(null);
  const [form, setForm] = useState({ team: '', position: '', ip_address: '', roles: [] });
  const [roles, setRoles] = useState([]);
  const [positions, setPositions] = useState([]);
  const [selectedTeam, setSelectedTeam] = useState('Total');
  const [teams, setTeams] = useState([]);
  const [teamMenuOpen, setTeamMenuOpen] = useState(false);
  const [newTeamName, setNewTeamName] = useState('');
  const [showAddTeam, setShowAddTeam] = useState(false);

  useEffect(() => {
    fetchRoles();
    fetchTeams();
    fetchPositions();
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [selectedTeam]);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const queryParams = new URLSearchParams();
      queryParams.append('limit', '10000');

      const data = await apiGet(`/users?${queryParams}`);
      console.log('사용자 목록 응답:', data);
      if (data.success) {
        const userList = data.data || [];
        console.log('설정할 사용자 목록:', userList);
        setUsers(userList);
      } else {
        console.error('사용자 목록 로드 실패: success가 false', data);
      }
    } catch (error) {
      console.error('사용자 목록 로드 실패:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchRoles = async () => {
    try {
      const data = await apiGet('/debug/roles');
      if (data.success) {
        setRoles(data.data);
      }
    } catch (error) {
      console.error('역할 목록 로드 실패:', error);
    }
  };

  const fetchTeams = async () => {
    try {
      console.log('팀 목록 요청 중...');
      const data = await apiGet('/users/teams');
      console.log('팀 목록 응답:', data);
      if (data.success) {
        const teamList = data.data || [];
        console.log('설정할 팀 목록:', teamList);
        setTeams(teamList);
      } else {
        console.error('팀 목록 로드 실패: success가 false', data);
      }
    } catch (error) {
      console.error('팀 목록 로드 실패:', error);
    }
  };

  const fetchPositions = async () => {
    try {
      console.log('직책 목록 요청 중...');
      const data = await apiGet('/users/positions');
      console.log('직책 목록 응답:', data);
      if (data.success) {
        const positionList = data.data || [];
        console.log('설정할 직책 목록:', positionList);
        setPositions(positionList);
      } else {
        console.error('직책 목록 로드 실패: success가 false', data);
      }
    } catch (error) {
      console.error('직책 목록 로드 실패:', error);
    }
  };

  const handleEdit = (user) => {
    setEditingUser(user);
    setForm({
      team: user.team || '',
      position: user.position || '',
      ip_address: user.ip_address || '',
      roles: user.roles || []
    });
  };

  const handleCancel = () => {
    setEditingUser(null);
    setForm({ team: '', position: '', ip_address: '', roles: [] });
  };

  const handleSave = async () => {
    try {
      // 사용자 정보 업데이트
      await apiPut(`/users/${editingUser.id}`, {
        team: form.team || null,
        position: form.position || null,
        ip_address: form.ip_address || null
      });

      // 역할 업데이트
      const currentRoles = editingUser.roles || [];
      
      // 추가할 역할
      const rolesToAdd = form.roles.filter(role => !currentRoles.includes(role));
      for (const roleName of rolesToAdd) {
        await apiPost(`/users/${editingUser.id}/roles`, { roleName });
      }

      // 제거할 역할
      const rolesToRemove = currentRoles.filter(role => !form.roles.includes(role));
      for (const roleName of rolesToRemove) {
        const role = roles.find(r => r.name === roleName);
        if (role) {
          try {
            await apiDelete(`/users/${editingUser.id}/roles/${role.id}`);
          } catch (err) {
            console.error(`역할 ${roleName} 제거 실패:`, err);
          }
        }
      }

      alert('사용자 정보가 업데이트되었습니다.');
      fetchUsers();
      handleCancel();
    } catch (error) {
      console.error('업데이트 실패:', error);
      alert('업데이트 중 오류가 발생했습니다.');
    }
  };

  const toggleUserStatus = async (userId, isActive) => {
    try {
      await apiPut(`/users/${userId}/status`, { is_active: !isActive });
      alert(`사용자가 ${!isActive ? '활성화' : '비활성화'}되었습니다.`);
      fetchUsers();
    } catch (error) {
      console.error('상태 변경 실패:', error);
      alert('상태 변경 중 오류가 발생했습니다.');
    }
  };

  const handleAddTeam = () => {
    if (newTeamName.trim() && !teams.includes(newTeamName.trim())) {
      setTeams([...teams, newTeamName.trim()]);
      setNewTeamName('');
      setShowAddTeam(false);
    }
  };

  const handleTeamFilterChange = (team) => {
    setSelectedTeam(team);
  };

  // 팀별로 사용자 그룹화
  const groupUsersByTeam = () => {
    const grouped = {};
    users.forEach(user => {
      const team = user.team || '미지정';
      if (!grouped[team]) {
        grouped[team] = [];
      }
      grouped[team].push(user);
    });
    return grouped;
  };

  const groupedUsers = groupUsersByTeam();
  
  // 사용자 목록에서 실제로 존재하는 팀 목록 추출
  const actualTeams = Object.keys(groupedUsers).filter(team => team !== '미지정');
  const allTeams = selectedTeam === 'Total' 
    ? [...new Set([...actualTeams, ...teams, '미지정'])] 
    : [selectedTeam];
  
  // 선택된 팀에 따라 필터링
  const getFilteredTeams = () => {
    if (selectedTeam === 'Total') {
      // Total 선택 시: 실제 사용자가 있는 모든 팀 표시
      return Object.keys(groupedUsers).length > 0 
        ? Object.keys(groupedUsers) 
        : ['미지정'];
    }
    return [selectedTeam];
  };

  const filteredTeams = getFilteredTeams();
  const totalUsers = users.length;
  
  console.log('디버깅 정보:', {
    users: users.length,
    groupedUsers,
    filteredTeams,
    selectedTeam,
    teams,
    actualTeams
  });

  return (
    <section className="user-management">
      <div className="user-management-header">
        <h1>User Management</h1>
        <div className="team-filter-section">
          <div className="team-filter-wrapper">
            <label htmlFor="team-filter">Filter by Team:</label>
            <div className="sort-dropdown">
              <button 
                className="sort-button" 
                onClick={(e) => {
                  e.stopPropagation();
                  setTeamMenuOpen(!teamMenuOpen);
                }}
              >
                {selectedTeam === 'Total' ? `Total (${totalUsers})` : `${selectedTeam} (${(groupedUsers[selectedTeam] || []).length})`}
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
                      className={`sort-option ${selectedTeam === 'Total' ? 'selected' : ''}`}
                      onClick={() => {
                        handleTeamFilterChange('Total');
                        setTeamMenuOpen(false);
                      }}
                    >
                      Total ({totalUsers})
                    </button>
                    {teams.map(team => {
                      const teamUsers = groupedUsers[team] || [];
                      return (
                        <button 
                          key={team}
                          className={`sort-option ${selectedTeam === team ? 'selected' : ''}`}
                          onClick={() => {
                            handleTeamFilterChange(team);
                            setTeamMenuOpen(false);
                          }}
                        >
                          {team} ({teamUsers.length})
                        </button>
                      );
                    })}
                    {groupedUsers['미지정'] && groupedUsers['미지정'].length > 0 && (
                      <button 
                        className={`sort-option ${selectedTeam === '미지정' ? 'selected' : ''}`}
                        onClick={() => {
                          handleTeamFilterChange('미지정');
                          setTeamMenuOpen(false);
                        }}
                      >
                        미지정 ({groupedUsers['미지정'].length})
                      </button>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
          <div className="add-team-section">
            {showAddTeam ? (
              <div className="add-team-input-wrapper">
                <input
                  type="text"
                  className="add-team-input"
                  placeholder="Enter team name"
                  value={newTeamName}
                  onChange={(e) => setNewTeamName(e.target.value)}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      handleAddTeam();
                    }
                  }}
                />
                <button onClick={handleAddTeam} className="btn-add-team-confirm">Add</button>
                <button onClick={() => { setShowAddTeam(false); setNewTeamName(''); }} className="btn-add-team-cancel">Cancel</button>
              </div>
            ) : (
              <button onClick={() => setShowAddTeam(true)} className="btn-add-team">+ Add Team</button>
            )}
          </div>
        </div>
      </div>
      
      {filteredTeams.length === 0 && users.length > 0 ? (
        // 팀 정보가 없어도 사용자 표시
        <div className="team-section">
          <h2 className="team-header">전체 ({users.length})</h2>
          <div className="user-table-container">
            <table className="user-table">
              <thead>
                <tr>
                  <th>사용자명</th>
                  <th>사원번호</th>
                  <th>이메일</th>
                  <th>팀</th>
                  <th>직책</th>
                  <th>IP 주소</th>
                  <th>역할</th>
                  <th>상태</th>
                  <th>작업</th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => (
                  <tr key={user.id}>
                    {editingUser?.id === user.id ? (
                      <>
                        <td>{user.username}</td>
                        <td>{user.employee_id}</td>
                        <td>{user.email}</td>
                        <td>
                          <select
                            value={form.team}
                            onChange={(e) => setForm({ ...form, team: e.target.value })}
                            style={{ minWidth: '120px' }}
                          >
                            <option value="">미지정</option>
                            {teams.map(teamOption => (
                              <option key={teamOption} value={teamOption}>{teamOption}</option>
                            ))}
                          </select>
                        </td>
                        <td>
                          <select
                            value={form.position}
                            onChange={(e) => setForm({ ...form, position: e.target.value })}
                            style={{ minWidth: '150px' }}
                          >
                            <option value="">미지정</option>
                            {positions.map(positionOption => (
                              <option key={positionOption} value={positionOption}>{positionOption}</option>
                            ))}
                          </select>
                        </td>
                        <td>
                          <input
                            type="text"
                            value={form.ip_address}
                            onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
                            placeholder="ex: 192.168.1.100"
                            style={{ minWidth: '150px', padding: '4px 8px' }}
                          />
                        </td>
                        <td>
                          <div className="role-checkboxes">
                            {roles.map(role => (
                              <label key={role.id} className="role-checkbox">
                                <input
                                  type="checkbox"
                                  checked={form.roles.includes(role.name)}
                                  onChange={(e) => {
                                    if (e.target.checked) {
                                      setForm({
                                        ...form,
                                        roles: [...form.roles, role.name]
                                      });
                                    } else {
                                      setForm({
                                        ...form,
                                        roles: form.roles.filter(r => r !== role.name)
                                      });
                                    }
                                  }}
                                />
                                <span>{role.name}</span>
                              </label>
                            ))}
                          </div>
                        </td>
                        <td>
                          <span className={`status-badge ${user.is_active ? 'status-active' : 'status-inactive'}`}>
                            {user.is_active ? '활성' : '비활성'}
                          </span>
                        </td>
                        <td>
                          <div className="action-buttons">
                            <button onClick={handleSave} className="btn-save">저장</button>
                            <button onClick={handleCancel} className="btn-cancel">취소</button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        <td>{user.username}</td>
                        <td>{user.employee_id}</td>
                        <td>{user.email}</td>
                        <td>{user.team || '미지정'}</td>
                        <td>{user.position || '-'}</td>
                        <td>{user.ip_address || '-'}</td>
                        <td>
                          <div className="role-badges">
                            {(user.roles || []).map(role => (
                              <span key={role} className={`role-badge ${role === 'admin' ? 'admin' : ''}`}>{role}</span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <span className={`status-badge ${user.is_active ? 'status-active' : 'status-inactive'}`}>
                            {user.is_active ? '활성' : '비활성'}
                          </span>
                        </td>
                        <td>
                          <div className="action-buttons">
                            <button onClick={() => handleEdit(user)} className="btn-edit">편집</button>
                            <button 
                              onClick={() => toggleUserStatus(user.id, user.is_active)}
                              className={`btn-status ${user.is_active ? 'btn-deactivate' : 'btn-activate'}`}
                            >
                              {user.is_active ? '비활성화' : '활성화'}
                            </button>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        filteredTeams.map(team => {
          const teamUsers = groupedUsers[team] || [];
          if (teamUsers.length === 0 && selectedTeam !== 'Total') return null;

          return (
            <div key={team} className="team-section">
              <h2 className="team-header">{team} ({teamUsers.length})</h2>
            <div className="user-table-container">
              <table className="user-table">
                <thead>
                  <tr>
                    <th>사용자명</th>
                    <th>사원번호</th>
                    <th>이메일</th>
                    <th>팀</th>
                    <th>직책</th>
                    <th>IP 주소</th>
                    <th>역할</th>
                    <th>상태</th>
                    <th>작업</th>
                  </tr>
                </thead>
                <tbody>
                  {teamUsers.map(user => (
              <tr key={user.id}>
                {editingUser?.id === user.id ? (
                  <>
                    <td>{user.username}</td>
                    <td>{user.employee_id}</td>
                    <td>{user.email}</td>
                    <td>
                      <select
                        value={form.team}
                        onChange={(e) => setForm({ ...form, team: e.target.value })}
                        style={{ minWidth: '120px' }}
                      >
                        <option value="">미지정</option>
                        {teams.map(teamOption => (
                          <option key={teamOption} value={teamOption}>{teamOption}</option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <select
                        value={form.position}
                        onChange={(e) => setForm({ ...form, position: e.target.value })}
                        style={{ minWidth: '150px' }}
                      >
                        <option value="">미지정</option>
                        {positions.map(positionOption => (
                          <option key={positionOption} value={positionOption}>{positionOption}</option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <input
                        type="text"
                        value={form.ip_address}
                        onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
                        placeholder="ex: 192.168.1.100"
                        style={{ minWidth: '150px', padding: '4px 8px' }}
                      />
                    </td>
                    <td>
                      <div className="role-checkboxes">
                        {roles.map(role => (
                          <label key={role.id} className="role-checkbox">
                            <input
                              type="checkbox"
                              checked={form.roles.includes(role.name)}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setForm({
                                    ...form,
                                    roles: [...form.roles, role.name]
                                  });
                                } else {
                                  setForm({
                                    ...form,
                                    roles: form.roles.filter(r => r !== role.name)
                                  });
                                }
                              }}
                            />
                            <span>{role.name}</span>
                          </label>
                        ))}
                      </div>
                    </td>
                    <td>
                      <span className={`status-badge ${user.is_active ? 'status-active' : 'status-inactive'}`}>
                        {user.is_active ? '활성' : '비활성'}
                      </span>
                    </td>
                    <td>
                      <div className="action-buttons">
                        <button onClick={handleSave} className="btn-save">저장</button>
                        <button onClick={handleCancel} className="btn-cancel">취소</button>
                      </div>
                    </td>
                  </>
                ) : (
                  <>
                    <td>{user.username}</td>
                    <td>{user.employee_id}</td>
                    <td>{user.email}</td>
                    <td>{user.team || '미지정'}</td>
                    <td>{user.position || '-'}</td>
                    <td>{user.ip_address || '-'}</td>
                    <td>
                      <div className="role-badges">
                        {(user.roles || []).map(role => (
                          <span key={role} className={`role-badge ${role === 'admin' ? 'admin' : ''}`}>{role}</span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <span className={`status-badge ${user.is_active ? 'status-active' : 'status-inactive'}`}>
                        {user.is_active ? '활성' : '비활성'}
                      </span>
                    </td>
                    <td>
                      <div className="action-buttons">
                        <button onClick={() => handleEdit(user)} className="btn-edit">편집</button>
                        <button 
                          onClick={() => toggleUserStatus(user.id, user.is_active)}
                          className={`btn-status ${user.is_active ? 'btn-deactivate' : 'btn-activate'}`}
                        >
                          {user.is_active ? '비활성화' : '활성화'}
                        </button>
                      </div>
                    </td>
                  </>
                )}
                  </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
        })
      )}
    </section>
  );
};

export default UserManagement;


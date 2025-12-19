const userModel = require('../models/user');
const { generateToken } = require('../utils/jwt');

const authController = {
  login: (req, res) => {
    try {
      const { username, employee_id, password } = req.body;

      // 필수 필드 검증
      if (!username || !employee_id || !password) {
        return res.status(400).json({
          success: false,
          message: '사용자명, 사원번호, 비밀번호를 모두 입력해주세요.'
        });
      }

      // DB에서 사용자 조회 (사용자명과 사원번호 모두 일치해야 함)
      const user = userModel.findByUsername(username);
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: '사용자명 또는 비밀번호가 잘못되었습니다.'
        });
      }

      // 사원번호 일치 확인
      if (user.employee_id !== employee_id) {
        return res.status(401).json({
          success: false,
          message: '사용자명 또는 비밀번호가 잘못되었습니다.'
        });
      }

      // 비밀번호 확인 (현재는 평문 비교, 추후 bcrypt 등으로 암호화 권장)
      if (user.password !== password) {
        return res.status(401).json({
          success: false,
          message: '사용자명 또는 비밀번호가 잘못되었습니다.'
        });
      }

      // 사용자 활성화 상태 확인
      if (!user.is_active) {
        return res.status(403).json({
          success: false,
          message: '비활성화된 계정입니다.'
        });
      }

      // 역할을 배열로 변환 (role 이름만 추출)
      const roleNames = (user.roles || []).map(role => role.name || role);

      // JWT 토큰 발급
      const token = generateToken({
        id: user.id,
        username: user.username,
        employee_id: user.employee_id,
        email: user.email,
        team: user.team,
        roles: roleNames
      });

      res.json({
        success: true,
        message: '로그인 성공',
        token: token,
        user: {
          id: user.id,
          username: user.username,
          employee_id: user.employee_id,
          email: user.email,
          team: user.team,
          roles: roleNames
        }
      });
    } catch (error) {
      console.error('로그인 오류:', error);
      res.status(500).json({
        success: false,
        message: '로그인 중 오류가 발생했습니다.'
      });
    }
  },

  logout: (req, res) => {
    // 추후 세션/토큰 무효화 로직 추가
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  },

  register: async (req, res) => {
    try {
      const { username, password, email, employee_id, team, position } = req.body;

      // 필수 필드 검증
      if (!username || !password || !email || !employee_id) {
        return res.status(400).json({
          success: false,
          message: '사용자명, 사원번호, 이메일, 비밀번호를 모두 입력해주세요.'
        });
      }

      // 중복 사용자 확인
      const existingUserByUsername = userModel.findByUsername(username);
      const existingUserByEmail = userModel.findByEmail(email);
      const existingUserByEmployeeId = userModel.findByEmployeeId(employee_id);

      if (existingUserByUsername) {
        return res.status(409).json({
          success: false,
          message: '이미 존재하는 사용자명입니다.'
        });
      }

      if (existingUserByEmail) {
        return res.status(409).json({
          success: false,
          message: '이미 존재하는 이메일입니다.'
        });
      }

      if (existingUserByEmployeeId) {
        return res.status(409).json({
          success: false,
          message: '이미 존재하는 사원번호입니다.'
        });
      }

      // 비밀번호 길이 검증
      if (password.length < 4) {
        return res.status(400).json({
          success: false,
          message: '비밀번호는 최소 4자 이상이어야 합니다.'
        });
      }

      // 새 사용자 생성
      const newUser = userModel.create(
        username,
        employee_id,
        email,
        password,
        team || null,
        position || null
      );

      // 기본 역할 할당 (user 역할)
      const db = require('../config/db');
      const userRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('user');
      if (userRole) {
        userModel.assignRole(newUser.id, userRole.id);
      }

      res.json({
        success: true,
        message: '회원가입이 완료되었습니다.',
        user: {
          id: newUser.id,
          username: newUser.username,
          employee_id: newUser.employee_id,
          email: newUser.email,
          team: newUser.team,
          position: newUser.position
        }
      });
    } catch (error) {
      console.error('회원가입 오류:', error);
      res.status(500).json({
        success: false,
        message: '회원가입 중 오류가 발생했습니다.'
      });
    }
  }
};

module.exports = authController;


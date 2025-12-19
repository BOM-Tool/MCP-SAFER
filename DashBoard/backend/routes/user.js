const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { jwtAuth } = require('../middleware/jwtAuth');

// 모든 사용자 조회 (관리자용)
router.get('/', userController.getAllUsers);

// 내 정보 조회 (현재 로그인한 사용자)
router.get('/me', jwtAuth, userController.getMyInfo);

// 비밀번호 변경 (현재 로그인한 사용자)
router.put('/me/password', jwtAuth, userController.changePassword);

// 모든 팀 목록 조회 (:id 라우트보다 먼저 정의해야 함)
router.get('/teams', userController.getAllTeams);

// 모든 직책 목록 조회 (:id 라우트보다 먼저 정의해야 함)
router.get('/positions', userController.getAllPositions);

// API 키 관리 (현재 로그인한 사용자)
router.get('/me/api-keys', jwtAuth, userController.getMyApiKeys);
router.post('/me/api-keys', jwtAuth, userController.createApiKey);
router.put('/me/api-keys/:id', jwtAuth, userController.updateApiKey);
router.delete('/me/api-keys/:id', jwtAuth, userController.deleteApiKey);

// 사용자 상세 정보 조회 (와일드카드 라우트는 마지막에)
router.get('/:id', userController.getUserById);

// 비밀번호 변경 (특정 사용자 ID로)
router.put('/:id/password', jwtAuth, (req, res) => {
  // 자신의 비밀번호만 변경 가능하도록 확인
  if (parseInt(req.params.id) !== req.user.id) {
    return res.status(403).json({
      success: false,
      message: '자신의 비밀번호만 변경할 수 있습니다.'
    });
  }
  // req.params.id를 req.user.id로 설정하여 changePassword에서 사용
  req.user.id = parseInt(req.params.id);
  userController.changePassword(req, res);
});

// 사용자 정보 수정
router.put('/:id', userController.updateUser);

// 사용자 역할 할당/제거
router.post('/:id/roles', userController.assignRole);
router.delete('/:id/roles/:roleId', userController.removeRole);

// 사용자 비활성화/활성화
router.put('/:id/status', userController.toggleUserStatus);

module.exports = router;


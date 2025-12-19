const express = require('express');
const router = express.Router();
const ipMappingController = require('../controllers/ipMappingController');

// IP 매핑 목록 조회
router.get('/', ipMappingController.getAllMappings);

// 특정 IP 매핑 조회
router.get('/:ip', ipMappingController.getMappingByIP);

// IP 매핑 생성 또는 업데이트
router.post('/', ipMappingController.createOrUpdateMapping);
router.put('/:ip', ipMappingController.createOrUpdateMapping);

// IP 매핑 삭제
router.delete('/:ip', ipMappingController.deleteMapping);

module.exports = router;


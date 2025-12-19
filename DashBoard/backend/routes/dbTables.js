const express = require('express');
const router = express.Router();
const dbTablesController = require('../controllers/dbTablesController');

// 모든 테이블 목록 조회
router.get('/', dbTablesController.getAllTables);

// 특정 테이블의 데이터 조회
router.get('/:tableName', dbTablesController.getTableData);

// 특정 테이블의 스키마 정보 조회
router.get('/:tableName/schema', dbTablesController.getTableSchema);

module.exports = router;


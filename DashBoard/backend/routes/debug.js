const express = require('express');
const router = express.Router();
const db = require('../config/db');

// 개발용: DB 내용 확인 (프로덕션에서는 제거 권장)
router.get('/users', (req, res) => {
  const users = db.prepare('SELECT id, username, email, role, created_at FROM users').all();
  res.json({ success: true, data: users });
});

router.get('/mcp-servers', (req, res) => {
  const servers = db.prepare('SELECT * FROM mcp_servers').all();
  res.json({ success: true, data: servers });
});

router.get('/mcp-requests', (req, res) => {
  const requests = db.prepare('SELECT * FROM mcp_register_requests').all();
  res.json({ success: true, data: requests });
});

router.get('/roles', (req, res) => {
  const roles = db.prepare('SELECT * FROM roles').all();
  res.json({ success: true, data: roles });
});

module.exports = router;


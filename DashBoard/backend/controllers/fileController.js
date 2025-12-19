const path = require('path');
const fs = require('fs');
const db = require('../config/db');
const userModel = require('../models/user');

const fileController = {
  // 파일 다운로드
  downloadFile: (req, res) => {
    try {
      const { id } = req.params; // mcp_server_id 또는 request_id
      const { type } = req.query; // 'server' or 'request'
      
      let filePath = null;
      
      if (type === 'server') {
        // MCP 서버 파일
        const server = db.prepare('SELECT file_path, name FROM mcp_servers WHERE id = ?').get(id);
        if (!server || !server.file_path) {
          return res.status(404).json({
            success: false,
            message: '파일을 찾을 수 없습니다.'
          });
        }
        filePath = server.file_path;
      } else if (type === 'request') {
        // 등록 요청 파일
        const request = db.prepare('SELECT file_path, name FROM mcp_register_requests WHERE id = ?').get(id);
        if (!request || !request.file_path) {
          return res.status(404).json({
            success: false,
            message: '파일을 찾을 수 없습니다.'
          });
        }
        filePath = request.file_path;
      } else {
        return res.status(400).json({
          success: false,
          message: '타입을 지정해주세요. (type=server or type=request)'
        });
      }

      // 실제 파일 경로 (uploads 폴더 기준)
      const uploadsDir = path.join(__dirname, '..', 'uploads');
      const fullPath = path.join(uploadsDir, path.basename(filePath));
      
      // 파일 존재 확인
      if (!fs.existsSync(fullPath)) {
        return res.status(404).json({
          success: false,
          message: '파일이 서버에 존재하지 않습니다.'
        });
      }

      // 다운로드 로그 기록
      // 쿼리 파라미터 또는 헤더에서 사용자 ID 가져오기
      const userId = req.query.user_id || req.headers['x-user-id'] || null;
      
      if (userId) {
        const logStmt = db.prepare(`
          INSERT INTO download_logs (user_id, file_path, file_name, mcp_server_id, ip_address)
          VALUES (?, ?, ?, ?, ?)
        `);
        const fileName = path.basename(fullPath);
        const mcpServerId = type === 'server' ? parseInt(id) : null;
        const ipAddress = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
        logStmt.run(parseInt(userId), filePath, fileName, mcpServerId, ipAddress);
      }

      // 파일 전송
      res.download(fullPath, (err) => {
        if (err) {
          console.error('파일 다운로드 오류:', err);
          if (!res.headersSent) {
            res.status(500).json({
              success: false,
              message: '파일 다운로드 중 오류가 발생했습니다.'
            });
          }
        }
      });
    } catch (error) {
      console.error('파일 다운로드 처리 오류:', error);
      res.status(500).json({
        success: false,
        message: '파일 다운로드 처리 중 오류가 발생했습니다.'
      });
    }
  },

  // 파일 업로드 (MCP 서버 등록 요청용)
  uploadFile: (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: '파일이 업로드되지 않았습니다.'
        });
      }

      const filePath = `/uploads/${req.file.filename}`;
      
      res.json({
        success: true,
        message: '파일이 업로드되었습니다.',
        data: {
          file_path: filePath,
          original_name: req.file.originalname,
          file_name: req.file.filename,
          file_size: req.file.size,
          mimetype: req.file.mimetype
        }
      });
    } catch (error) {
      console.error('파일 업로드 처리 오류:', error);
      res.status(500).json({
        success: false,
        message: '파일 업로드 처리 중 오류가 발생했습니다.'
      });
    }
  },

  // 다운로드 로그 조회 (관리자용)
  getDownloadLogs: (req, res) => {
    try {
      const { username, query, team, page = 1, limit = 20 } = req.query;
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      const offset = (pageNum - 1) * limitNum;
      
      // query 파라미터가 있으면 그것을 사용하고, 없으면 username 파라미터 사용 (하위 호환성)
      const searchTerm = query || username;
      
      let countQuery = 'SELECT COUNT(*) as total FROM download_logs dl LEFT JOIN users u ON dl.user_id = u.id WHERE 1=1';
      let dataQuery = 'SELECT dl.*, u.username, u.employee_id, u.team, ms.name as mcp_server_name FROM download_logs dl LEFT JOIN users u ON dl.user_id = u.id LEFT JOIN mcp_servers ms ON dl.mcp_server_id = ms.id WHERE 1=1';
      const params = [];
      
      if (searchTerm) {
        // 사용자 이름, 사원번호, IP 주소 모두에서 검색
        countQuery += ' AND (u.username LIKE ? OR u.employee_id LIKE ? OR dl.ip_address LIKE ?)';
        dataQuery += ' AND (u.username LIKE ? OR u.employee_id LIKE ? OR dl.ip_address LIKE ?)';
        const searchPattern = `%${searchTerm}%`;
        params.push(searchPattern, searchPattern, searchPattern);
      }
      
      if (team && team !== 'all') {
        countQuery += ' AND u.team = ?';
        dataQuery += ' AND u.team = ?';
        params.push(team);
      }
      
      dataQuery += ' ORDER BY dl.downloaded_at DESC LIMIT ? OFFSET ?';
      const dataParams = [...params, limitNum, offset];

      const totalResult = db.prepare(countQuery).get(...params);
      const total = totalResult.total;
      const logs = db.prepare(dataQuery).all(...dataParams);
      
      res.json({
        success: true,
        data: logs,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total: total,
          totalPages: Math.ceil(total / limitNum)
        }
      });
    } catch (error) {
      console.error('다운로드 로그 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '로그 조회 중 오류가 발생했습니다.'
      });
    }
  }
};

module.exports = fileController;


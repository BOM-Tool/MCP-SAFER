const db = require('../config/db');

const dbTablesController = {
  // 모든 테이블 목록 조회
  getAllTables: (req, res) => {
    try {
      const tables = db.prepare(`
        SELECT name 
        FROM sqlite_master 
        WHERE type='table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name
      `).all();

      // 각 테이블의 행 수와 컬럼 정보도 함께 반환
      const tablesWithInfo = tables.map(table => {
        const rowCount = db.prepare(`SELECT COUNT(*) as count FROM ${table.name}`).get();
        const columns = db.prepare(`PRAGMA table_info(${table.name})`).all();
        
        return {
          name: table.name,
          rowCount: rowCount.count,
          columnCount: columns.length,
          columns: columns.map(col => ({
            name: col.name,
            type: col.type,
            notNull: col.notnull === 1,
            defaultValue: col.dflt_value,
            primaryKey: col.pk === 1
          }))
        };
      });

      res.json({
        success: true,
        data: tablesWithInfo
      });
    } catch (error) {
      console.error('테이블 목록 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '테이블 목록 조회 중 오류가 발생했습니다.',
        error: error.message
      });
    }
  },

  // 특정 테이블의 데이터 조회
  getTableData: (req, res) => {
    try {
      const { tableName } = req.params;
      const { limit = 100, offset = 0 } = req.query;

      // 테이블 존재 여부 확인
      const tableExists = db.prepare(`
        SELECT name 
        FROM sqlite_master 
        WHERE type='table' AND name = ?
      `).get(tableName);

      if (!tableExists) {
        return res.status(404).json({
          success: false,
          message: `테이블 '${tableName}'을 찾을 수 없습니다.`
        });
      }

      // 테이블 스키마 정보
      const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
      
      // 전체 행 수
      const totalCount = db.prepare(`SELECT COUNT(*) as count FROM ${tableName}`).get();

      // 데이터 조회 (LIMIT, OFFSET 적용)
      const data = db.prepare(`
        SELECT * FROM ${tableName} 
        LIMIT ? OFFSET ?
      `).all(parseInt(limit), parseInt(offset));

      res.json({
        success: true,
        data: {
          tableName,
          columns: columns.map(col => ({
            name: col.name,
            type: col.type,
            notNull: col.notnull === 1,
            defaultValue: col.dflt_value,
            primaryKey: col.pk === 1
          })),
          totalCount: totalCount.count,
          limit: parseInt(limit),
          offset: parseInt(offset),
          rows: data
        }
      });
    } catch (error) {
      console.error('테이블 데이터 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '테이블 데이터 조회 중 오류가 발생했습니다.',
        error: error.message
      });
    }
  },

  // 특정 테이블의 스키마 정보만 조회
  getTableSchema: (req, res) => {
    try {
      const { tableName } = req.params;

      // 테이블 존재 여부 확인
      const tableExists = db.prepare(`
        SELECT name 
        FROM sqlite_master 
        WHERE type='table' AND name = ?
      `).get(tableName);

      if (!tableExists) {
        return res.status(404).json({
          success: false,
          message: `테이블 '${tableName}'을 찾을 수 없습니다.`
        });
      }

      // 테이블 스키마 정보
      const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
      
      // CREATE TABLE 문 조회
      const createTable = db.prepare(`
        SELECT sql 
        FROM sqlite_master 
        WHERE type='table' AND name = ?
      `).get(tableName);

      res.json({
        success: true,
        data: {
          tableName,
          columns: columns.map(col => ({
            name: col.name,
            type: col.type,
            notNull: col.notnull === 1,
            defaultValue: col.dflt_value,
            primaryKey: col.pk === 1
          })),
          createTableSQL: createTable ? createTable.sql : null
        }
      });
    } catch (error) {
      console.error('테이블 스키마 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '테이블 스키마 조회 중 오류가 발생했습니다.',
        error: error.message
      });
    }
  }
};

module.exports = dbTablesController;


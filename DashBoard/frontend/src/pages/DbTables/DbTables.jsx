import React, { useState, useEffect } from 'react';
import { apiGet } from '../../utils/api';
import './DbTables.css';

const DbTables = () => {
  const [tables, setTables] = useState([]);
  const [selectedTable, setSelectedTable] = useState(null);
  const [tableData, setTableData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [dataLoading, setDataLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [limit] = useState(50);

  useEffect(() => {
    fetchTables();
  }, []);

  useEffect(() => {
    if (selectedTable) {
      fetchTableData(selectedTable, currentPage);
    }
  }, [selectedTable, currentPage]);

  const fetchTables = async () => {
    try {
      setLoading(true);
      const response = await apiGet('/db-tables');
      if (response.success) {
        setTables(response.data);
      }
    } catch (error) {
      console.error('테이블 목록 조회 실패:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchTableData = async (tableName, page = 1) => {
    try {
      setDataLoading(true);
      const offset = (page - 1) * limit;
      const response = await apiGet(`/db-tables/${tableName}?limit=${limit}&offset=${offset}`);
      if (response.success) {
        setTableData(response.data);
      }
    } catch (error) {
      console.error('테이블 데이터 조회 실패:', error);
      setTableData(null);
    } finally {
      setDataLoading(false);
    }
  };

  const handleTableClick = (tableName) => {
    setSelectedTable(tableName);
    setCurrentPage(1);
  };

  const formatValue = (value) => {
    if (value === null || value === undefined) {
      return <span className="null-value">NULL</span>;
    }
    if (typeof value === 'object') {
      return JSON.stringify(value, null, 2);
    }
    if (typeof value === 'string' && value.length > 100) {
      return (
        <span title={value}>
          {value.substring(0, 100)}...
        </span>
      );
    }
    return String(value);
  };

  const totalPages = tableData ? Math.ceil(tableData.totalCount / limit) : 1;

  if (loading) {
    return (
      <section className="db-tables">
        <div className="loading">로딩 중...</div>
      </section>
    );
  }

  return (
    <section className="db-tables">
      <h1>Database Tables</h1>

      <div className="db-tables-container">
        <div className="tables-sidebar">
          <h2>Tables</h2>
          <div className="tables-list">
            {tables.map((table) => (
              <div
                key={table.name}
                className={`table-item ${selectedTable === table.name ? 'active' : ''}`}
                onClick={() => handleTableClick(table.name)}
              >
                <div className="table-name">{table.name}</div>
                <div className="table-info">
                  <span className="row-count">{table.rowCount} rows</span>
                  <span className="column-count">{table.columnCount} cols</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="table-content">
          {selectedTable ? (
            <>
              <div className="table-header">
                <h2>{selectedTable}</h2>
                {tableData && (
                  <div className="table-meta">
                    <span>Total: {tableData.totalCount} rows</span>
                    <span>Showing: {tableData.rows.length} rows</span>
                  </div>
                )}
              </div>

              {dataLoading ? (
                <div className="loading">데이터 로딩 중...</div>
              ) : tableData ? (
                <>
                  <div className="table-data-container">
                    <table className="data-table">
                      <thead>
                        <tr>
                          {tableData.columns.map((col) => (
                            <th key={col.name} className={col.primaryKey ? 'primary-key' : ''}>
                              {col.name}
                              {col.primaryKey && <span className="pk-badge">PK</span>}
                              <div className="column-type">{col.type}</div>
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {tableData.rows.length === 0 ? (
                          <tr>
                            <td colSpan={tableData.columns.length} className="empty-cell">
                              데이터가 없습니다.
                            </td>
                          </tr>
                        ) : (
                          tableData.rows.map((row, idx) => (
                            <tr key={idx}>
                              {tableData.columns.map((col) => (
                                <td key={col.name} className={col.primaryKey ? 'primary-key' : ''}>
                                  {formatValue(row[col.name])}
                                </td>
                              ))}
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>

                  {totalPages > 1 && (
                    <div className="pagination">
                      <button
                        onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                        disabled={currentPage === 1}
                        className="pagination-btn"
                      >
                        이전
                      </button>
                      <span className="pagination-info">
                        {currentPage} / {totalPages}
                      </span>
                      <button
                        onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                        disabled={currentPage === totalPages}
                        className="pagination-btn"
                      >
                        다음
                      </button>
                    </div>
                  )}
                </>
              ) : (
                <div className="empty-state">데이터를 불러올 수 없습니다.</div>
              )}
            </>
          ) : (
            <div className="empty-state">테이블을 선택하세요.</div>
          )}
        </div>
      </div>
    </section>
  );
};

export default DbTables;


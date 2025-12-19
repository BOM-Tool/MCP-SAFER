import React from 'react';
import './Pagination.css';

const Pagination = ({ currentPage, totalPages, onPageChange, totalItems, itemsPerPage }) => {
  // 항목 범위 계산
  const startItem = totalItems > 0 ? ((currentPage - 1) * itemsPerPage) + 1 : 0;
  const endItem = Math.min(currentPage * itemsPerPage, totalItems);
  
  // totalPages가 0이거나 undefined인 경우 숨김
  if (!totalPages || totalPages === 0) {
    return null;
  }

  return (
    <div className="pagination-wrapper">
    <div className="pagination">
      <button
          className="pagination-btn pagination-btn-icon"
          onClick={() => onPageChange(1)}
        disabled={currentPage === 1}
          title="첫 페이지"
      >
          «
      </button>
        <button
          className="pagination-btn pagination-btn-icon"
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage === 1}
          title="이전 페이지"
        >
          ‹
        </button>
        <span className="pagination-info">
          Page {currentPage} of {totalPages}
        </span>
      <button
          className="pagination-btn pagination-btn-icon"
        onClick={() => onPageChange(currentPage + 1)}
        disabled={currentPage === totalPages}
          title="다음 페이지"
        >
          ›
        </button>
        <button
          className="pagination-btn pagination-btn-icon"
          onClick={() => onPageChange(totalPages)}
          disabled={currentPage === totalPages}
          title="마지막 페이지"
        >
          »
      </button>
      </div>
    </div>
  );
};

export default Pagination;


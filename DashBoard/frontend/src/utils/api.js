/**
 * API 요청 유틸리티 함수
 * JWT 토큰을 자동으로 포함하여 요청합니다.
 */

// 환경 변수에서 API URL 가져오기 (Vite는 import.meta.env 사용)
// VITE_API_BASE_URL이 설정되지 않으면 기본값 사용
const getApiBaseUrl = () => {
  const envUrl = import.meta.env.VITE_API_BASE_URL;
  const isBrowser = typeof window !== 'undefined';
  const hostname = isBrowser ? window.location.hostname : null;
  const protocol = isBrowser ? window.location.protocol : 'http:';

  // 환경 변수가 설정된 경우 우선 적용하되,
  // 로컬 주소가 설정돼 있고 실제 접속 호스트가 로컬이 아니면 자동으로 서버 호스트를 사용
  if (envUrl) {
    const envIsLocal = envUrl.includes('localhost') || envUrl.includes('127.0.0.1');
    const hostIsLocal = hostname === 'localhost' || hostname === '127.0.0.1';
    
    if (envIsLocal && isBrowser && !hostIsLocal) {
      return `${protocol}//${hostname}:3001/api`;
    }
    
    return envUrl;
  }
  
  // 브라우저 환경에서만 실행
  if (isBrowser) {
    const hostIsLocal = hostname === 'localhost' || hostname === '127.0.0.1';
    if (hostIsLocal) {
      return 'http://localhost:3001/api';
    }
    // EC2나 다른 서버인 경우 같은 호스트의 3001 포트 사용
    return `${protocol}//${hostname}:3001/api`;
  }
  
  // 기본값 (서버 사이드 렌더링 등)
  return 'http://localhost:3001/api';
};

const API_BASE_URL = getApiBaseUrl();

// API_BASE_URL을 export하여 다른 파일에서도 사용 가능하도록 함
export { API_BASE_URL };

/**
 * localStorage에서 토큰 가져오기
 */
function getToken() {
  return localStorage.getItem('token');
}

/**
 * 토큰이 포함된 headers 생성
 */
function getHeaders(additionalHeaders = {}) {
  const token = getToken();
  return {
    'Content-Type': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` }),
    ...additionalHeaders
  };
}

/**
 * HTTP 상태 코드별 에러 메시지 생성
 */
function getStatusErrorMessage(status, statusText, url) {
  const statusMessages = {
    400: '잘못된 요청입니다. 입력한 정보를 확인해주세요.',
    401: '인증이 필요합니다. 다시 로그인해주세요.',
    403: '접근 권한이 없습니다. 관리자에게 문의하세요.',
    404: `요청한 리소스를 찾을 수 없습니다. (${url})`,
    405: '허용되지 않은 요청 방법입니다.',
    408: '요청 시간이 초과되었습니다. 네트워크 연결을 확인해주세요.',
    409: '요청이 충돌했습니다. 이미 존재하는 데이터일 수 있습니다.',
    422: '처리할 수 없는 요청입니다. 입력 데이터를 확인해주세요.',
    429: '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.',
    500: '서버 내부 오류가 발생했습니다. 잠시 후 다시 시도해주세요.',
    502: '서버 게이트웨이 오류가 발생했습니다. 서버 상태를 확인해주세요.',
    503: '서비스를 일시적으로 사용할 수 없습니다. 잠시 후 다시 시도해주세요.',
    504: '서버 응답 시간이 초과되었습니다. 네트워크 연결을 확인해주세요.'
  };

  return statusMessages[status] || `서버 오류가 발생했습니다. (상태 코드: ${status} ${statusText})`;
}

/**
 * 네트워크 오류 메시지 생성
 */
function getNetworkErrorMessage(error, url) {
  console.error('API 요청 실패:', {
    url,
    error: error.message,
    name: error.name,
    stack: error.stack
  });

  if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
    // CORS 오류 가능성
    if (error.message.includes('CORS')) {
      return `CORS 오류: 서버(${url})에서 요청을 허용하지 않습니다. 서버 설정을 확인해주세요.`;
    }
    
    // 네트워크 연결 실패
    return `서버에 연결할 수 없습니다.\n\n` +
           `요청 URL: ${url}\n` +
           `가능한 원인:\n` +
           `- 백엔드 서버가 실행 중이 아닙니다\n` +
           `- 네트워크 연결 문제\n` +
           `- 방화벽 또는 보안 설정\n` +
           `- 잘못된 서버 주소\n\n` +
           `브라우저 개발자 도구(F12)의 Network 탭에서 자세한 정보를 확인할 수 있습니다.`;
  }

  if (error.name === 'AbortError') {
    return '요청이 취소되었습니다.';
  }

  return `네트워크 오류: ${error.message || '알 수 없는 오류가 발생했습니다.'}`;
}

/**
 * API 요청 래퍼 함수
 */
async function apiRequest(url, options = {}) {
  const fullUrl = url.startsWith('http') ? url : `${API_BASE_URL}${url}`;
  
  try {
    console.log(`[API] 요청: ${options.method || 'GET'} ${fullUrl}`);
    
    const response = await fetch(fullUrl, {
      ...options,
      headers: getHeaders(options.headers)
    });

    // 응답이 성공적이지 않은 경우
    if (!response.ok) {
      let errorMessage = getStatusErrorMessage(response.status, response.statusText, fullUrl);
      
      // 응답 본문에서 에러 메시지 추출 시도
      try {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          const errorData = await response.json();
          if (errorData.message) {
            errorMessage = errorData.message;
          } else if (errorData.error) {
            errorMessage = errorData.error;
          }
          // 서버에서 제공한 상세 정보가 있으면 추가
          if (errorData.details) {
            errorMessage += `\n\n상세 정보: ${JSON.stringify(errorData.details, null, 2)}`;
          }
        } else {
          const text = await response.text();
          if (text) {
            errorMessage += `\n\n서버 응답: ${text.substring(0, 500)}`;
          }
        }
      } catch (parseError) {
        console.warn('응답 본문 파싱 실패:', parseError);
      }

      // 401 Unauthorized: 토큰 만료 또는 유효하지 않음
      if (response.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        // 로그인 페이지로 리다이렉트는 호출하는 쪽에서 처리하도록 함
      }

      const apiError = new Error(errorMessage);
      apiError.status = response.status;
      apiError.statusText = response.statusText;
      apiError.url = fullUrl;
      throw apiError;
    }

    console.log(`[API] 성공: ${options.method || 'GET'} ${fullUrl} (${response.status})`);
    return response;
  } catch (error) {
    // 이미 처리된 API 에러인 경우 그대로 throw
    if (error.status) {
      throw error;
    }

    // 네트워크 오류 처리
    const networkError = new Error(getNetworkErrorMessage(error, fullUrl));
    networkError.originalError = error;
    networkError.url = fullUrl;
    throw networkError;
  }
}

/**
 * GET 요청
 */
export async function apiGet(url, options = {}) {
  try {
    const response = await apiRequest(url, {
      method: 'GET',
      ...options
    });
    return await response.json();
  } catch (error) {
    console.error('[API GET] 오류:', error);
    throw error;
  }
}

/**
 * POST 요청
 */
export async function apiPost(url, data, options = {}) {
  try {
    const response = await apiRequest(url, {
      method: 'POST',
      body: JSON.stringify(data),
      ...options
    });
    
    // 응답이 JSON인지 확인
    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      const text = await response.text();
      const error = new Error(
        `서버가 JSON 형식이 아닌 응답을 반환했습니다.\n\n` +
        `응답 내용: ${text.substring(0, 500)}\n` +
        `Content-Type: ${contentType || '없음'}`
      );
      error.status = response.status;
      error.responseText = text;
      throw error;
    }
    
    return await response.json();
  } catch (error) {
    console.error('[API POST] 오류:', error);
    throw error;
  }
}

/**
 * PUT 요청
 */
export async function apiPut(url, data, options = {}) {
  try {
    const response = await apiRequest(url, {
      method: 'PUT',
      body: JSON.stringify(data),
      ...options
    });
    
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }
    
    // 응답 본문이 없는 경우 (204 No Content 등)
    if (response.status === 204 || response.status === 200) {
      return { success: true };
    }
    
    const text = await response.text();
    return text ? JSON.parse(text) : { success: true };
  } catch (error) {
    console.error('[API PUT] 오류:', error);
    throw error;
  }
}

/**
 * DELETE 요청
 */
export async function apiDelete(url, options = {}) {
  try {
    const response = await apiRequest(url, {
      method: 'DELETE',
      ...options
    });
    
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }
    
    // 응답 본문이 없는 경우
    if (response.status === 204 || response.status === 200) {
      return { success: true };
    }
    
    const text = await response.text();
    return text ? JSON.parse(text) : { success: true };
  } catch (error) {
    console.error('[API DELETE] 오류:', error);
    throw error;
  }
}

/**
 * POST 요청 (FormData)
 */
export async function apiPostForm(url, formData, options = {}) {
  try {
    const token = getToken();
    const fullUrl = url.startsWith('http') ? url : `${API_BASE_URL}${url}`;
    
    const response = await fetch(fullUrl, {
      method: 'POST',
      headers: {
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers
      },
      body: formData,
      ...options
    });

    // 응답이 성공적이지 않은 경우
    if (!response.ok) {
      let errorMessage = getStatusErrorMessage(response.status, response.statusText, fullUrl);
      
      // 응답 본문에서 에러 메시지 추출 시도
      try {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          const errorData = await response.json();
          if (errorData.message) {
            errorMessage = errorData.message;
          } else if (errorData.error) {
            errorMessage = errorData.error;
          }
        } else {
          const text = await response.text();
          if (text) {
            errorMessage += `\n\n서버 응답: ${text.substring(0, 500)}`;
          }
        }
      } catch (parseError) {
        console.warn('응답 본문 파싱 실패:', parseError);
      }

      // 401 Unauthorized: 토큰 만료 또는 유효하지 않음
      if (response.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
      }

      const apiError = new Error(errorMessage);
      apiError.status = response.status;
      apiError.statusText = response.statusText;
      apiError.url = fullUrl;
      throw apiError;
    }

    // 응답이 JSON인지 확인
    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      const text = await response.text();
      const error = new Error(
        `서버가 JSON 형식이 아닌 응답을 반환했습니다.\n\n` +
        `응답 내용: ${text.substring(0, 500)}\n` +
        `Content-Type: ${contentType || '없음'}`
      );
      error.status = response.status;
      error.responseText = text;
      throw error;
    }
    
    return await response.json();
  } catch (error) {
    console.error('[API POST Form] 오류:', error);
    throw error;
  }
}

// 내부 함수 export (필요시 사용)
export { getToken, getHeaders };







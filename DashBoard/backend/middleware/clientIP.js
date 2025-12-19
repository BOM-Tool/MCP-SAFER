/**
 * 클라이언트 IP 추출 미들웨어
 * MCP Proxy 요청에서 실제 클라이언트 IP를 추출
 */

/**
 * IP 주소 정규화
 * - IPv6 매핑 IPv4 처리 (::ffff:192.168.1.1)
 * - IPv6 대괄호 제거
 * - 포트 제거
 */
function normalizeIP(ip) {
  if (!ip) return null;

  // IPv6 매핑 IPv4 처리
  if (ip.startsWith('::ffff:')) {
    ip = ip.replace('::ffff:', '');
  }

  // IPv6 대괄호 제거 ([2001:db8::1]:8080 -> 2001:db8::1)
  if (ip.startsWith('[') && ip.includes(']')) {
    ip = ip.slice(1, ip.indexOf(']'));
  }

  // 포트 제거 (IPv4: 192.168.1.1:8080 -> 192.168.1.1)
  if (ip.includes(':') && !ip.includes('::')) {
    // IPv6가 아닌 경우 (IPv4:포트)
    const parts = ip.split(':');
    if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      ip = parts[0];
    }
  }

  return ip.trim();
}

/**
 * 로컬 IP 확인
 */
function isLocalIP(ip) {
  if (!ip) return false;

  const normalized = normalizeIP(ip);

  // 로컬호스트
  if (normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost') {
    return true;
  }

  // 로컬 네트워크는 허용 (같은 서버가 아닐 수 있음)
  // 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12는 허용
  return false;
}

/**
 * 클라이언트 IP 추출
 * 우선순위:
 * 1. X-Original-Client-IP (MCP Proxy가 직접 설정)
 * 2. X-Forwarded-For 첫 번째 IP (프록시를 통한 경우)
 * 3. X-Real-IP
 * 4. RemoteAddr
 */
function extractClientIP(req) {
  // 1. X-Original-Client-IP (MCP Proxy 요청)
  const originalIP = req.headers['x-original-client-ip'];
  if (originalIP) {
    return normalizeIP(originalIP);
  }

  // 2. X-Forwarded-For (프록시 체인)
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    // 여러 IP가 쉼표로 구분될 수 있음 (첫 번째가 원본 클라이언트)
    const ips = xff.split(',').map(ip => ip.trim());
    if (ips.length > 0) {
      return normalizeIP(ips[0]);
    }
  }

  // 3. X-Real-IP
  const xri = req.headers['x-real-ip'];
  if (xri) {
    return normalizeIP(xri);
  }

  // 4. RemoteAddr (직접 연결)
  const remoteAddr = req.socket.remoteAddress || req.connection?.remoteAddress;
  if (remoteAddr) {
    return normalizeIP(remoteAddr);
  }

  return null;
}

/**
 * 클라이언트 IP 추출 미들웨어
 * req.clientIP에 클라이언트 IP 설정
 */
function clientIPMiddleware(req, res, next) {
  const clientIP = extractClientIP(req);
  req.clientIP = clientIP;
  req.isLocalIP = clientIP ? isLocalIP(clientIP) : false;
  
  // 디버깅용 로그 (MCP Proxy 요청만)
  if (req.headers['x-mcp-proxy-request'] === 'true') {
    console.log('🔍 IP 추출 미들웨어:', {
      'x-original-client-ip': req.headers['x-original-client-ip'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-real-ip': req.headers['x-real-ip'],
      'remote-address': req.socket.remoteAddress,
      'extracted-ip': clientIP
    });
  }
  
  next();
}

module.exports = {
  extractClientIP,
  normalizeIP,
  isLocalIP,
  clientIPMiddleware
};


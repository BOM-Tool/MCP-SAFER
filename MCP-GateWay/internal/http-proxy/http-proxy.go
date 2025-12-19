// http-proxy.go
package httpproxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"

	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"mcp-gateway/internal/policy"
	"mcp-gateway/internal/policy/core"
	"mcp-gateway/internal/policy/processing"
	"mcp-gateway/internal/util"

	// Generated protobuf code
	cursor_grpc "mcp-gateway/github.com/mcp-gateway/cursor-grpc"

	"google.golang.org/protobuf/proto"
)

// Config HTTP Proxy 설정
type Config struct {
	LogDir         string
	Port           string
	CACertFile     string // CA 인증서 파일 경로
	CAKeyFile      string // CA 개인키 파일 경로
	EnableMITM     bool   // MITM SSL 인터셉션 활성화
	VerboseLogging bool   // 상세 로깅(헤더 등)
	AIOnly         bool   // AI 서비스만 로깅(cursor.sh 포함 여부)
	DecodeProtobuf bool   // 프로토버프 문자열 추출(경량 정규식)
	ForceHTTP11    bool   // HTTP/1.1 강제

	// 새 옵션
	HeadersOnly bool  // 본문 미수집(요청/응답 헤더만 로깅)
	AllowPorts  []int // 허용 포트(기본: 80, 443)

	// DLP 백엔드 설정
	BackendAPIURL string // DLP 로그 전송 백엔드 URL
	DLPAPIKey     string // DLP API 키
}

type Server struct {
	config    *Config
	logMutex  sync.Mutex
	logFile   *os.File
	logger    *util.NDJSON
	caCert    *x509.Certificate           // CA 인증서
	caKey     *rsa.PrivateKey             // CA 개인키
	certCache map[string]*tls.Certificate // 호스트별 인증서 캐시
	certMutex sync.RWMutex                // 인증서 캐시 뮤텍스

	seq                   uint64          // Fiddler 스타일 출력용 시퀀스 번호
	bidiBodySaved         bool            // BidiAppend 바디가 이미 저장되었는지 여부
	sseConnectionsStarted map[string]bool // 클라이언트별 SSE 연결 시작 여부 추적
	sseMu                 sync.RWMutex    // SSE 연결 추적용 뮤텍스
	bidiAppendCounters    map[string]int  // 클라이언트별 BidiAppend 카운터 (프롬프트당 첫 번째만 처리)
	bidiAppendMu          sync.RWMutex    // BidiAppend 카운터용 뮤텍스
}

func NewServer(config *Config) (*Server, error) {
	if err := os.MkdirAll(config.LogDir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}

	logFile, err := os.OpenFile(
		filepath.Join(config.LogDir, "http-proxy.ndjson"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0o644,
	)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	if len(config.AllowPorts) == 0 {
		config.AllowPorts = []int{80, 443}
	}

	server := &Server{
		config:                config,
		logFile:               logFile,
		logger:                util.NewNDJSON(logFile),
		certCache:             make(map[string]*tls.Certificate),
		sseConnectionsStarted: make(map[string]bool),
		bidiAppendCounters:    make(map[string]int),
	}

	if config.EnableMITM && config.CACertFile != "" && config.CAKeyFile != "" {
		if err := server.loadCA(); err != nil {
			return nil, fmt.Errorf("load CA certificate: %w", err)
		}
		fmt.Printf("[proxy] MITM SSL interception enabled with CA: %s\n", config.CACertFile)
	}

	return server, nil
}

// CA 로드
func (s *Server) loadCA() error {
	caCertPEM, err := os.ReadFile(s.config.CACertFile)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}
	caKeyPEM, err := os.ReadFile(s.config.CAKeyFile)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}
	s.caCert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		if keyInterface, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err2 == nil {
			if k, ok := keyInterface.(*rsa.PrivateKey); ok {
				s.caKey = k
				return nil
			}
			return fmt.Errorf("CA key is not RSA private key")
		}
		return fmt.Errorf("parse CA key: %w", err)
	}
	s.caKey = key
	return nil
}

func (s *Server) getCertificateForHost(host string) (*tls.Certificate, error) {
	s.certMutex.RLock()
	if cert, ok := s.certCache[host]; ok {
		s.certMutex.RUnlock()
		return cert, nil
	}
	s.certMutex.RUnlock()

	s.certMutex.Lock()
	defer s.certMutex.Unlock()

	if cert, ok := s.certCache[host]; ok {
		return cert, nil
	}

	cert, err := s.generateCertificate(host)
	if err != nil {
		return nil, err
	}
	s.certCache[host] = cert
	return cert, nil
}

func (s *Server) generateCertificate(host string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"MCP Gateway MITM"},
		},
		DNSNames:    []string{host},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, &priv.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("create TLS certificate: %w", err)
	}
	return &cert, nil
}

// analyzeOriginalText - BidiAppend에서 원문을 분석하는 함수 (파일 저장 없이)
func (s *Server) analyzeOriginalText(protobufMsg string) {
	// 분석 기능 비활성화
}

// extractTextFromJSON - JSON에서 실제 텍스트만 추출하는 함수
func (s *Server) extractTextFromJSON(jsonStr string) string {
	// "text":"실제텍스트" 패턴 찾기
	textPattern := regexp.MustCompile(`"text":"([^"]+)"`)
	matches := textPattern.FindAllStringSubmatch(jsonStr, -1)

	var texts []string
	for _, match := range matches {
		if len(match) > 1 {
			texts = append(texts, match[1])
		}
	}

	return strings.Join(texts, " ")
}

// extractLatestPromptJSON - 최신 프롬프트 JSON을 추출하는 함수
// 반환값: (성공여부, 에러)
func (s *Server) extractLatestPromptJSON(decodedFile, timestamp string) (bool, error) {
	// decoded 파일 읽기
	content, err := os.ReadFile(decodedFile)
	if err != nil {
		return false, fmt.Errorf("failed to read decoded file: %w", err)
	}

	// JSON 패턴 찾기 ({"root":{"children":...)
	contentStr := string(content)

	// 더 정확한 방법: {"root":{"children":로 시작하는 완전한 JSON 패턴만 찾기
	var matches []string
	startPattern := `{"root":{"children":`
	startIdx := 0

	for {
		idx := strings.Index(contentStr[startIdx:], startPattern)
		if idx == -1 {
			break
		}

		actualIdx := startIdx + idx
		// 중괄호 균형을 맞춰서 JSON 끝 찾기
		jsonEnd := s.findJSONEnd(contentStr[actualIdx:])
		if jsonEnd > 0 {
			jsonStr := contentStr[actualIdx : actualIdx+jsonEnd]
			// JSON이 유효한지 간단히 확인 (children 배열이 있는지)
			if strings.Contains(jsonStr, `"children":[`) && strings.Contains(jsonStr, `"text":`) {
				matches = append(matches, jsonStr)
			}
		}

		startIdx = actualIdx + 1
	}

	if len(matches) == 0 {
		return false, nil
	}

	// 가장 마지막(최신) JSON 추출
	latestJSON := matches[len(matches)-1]

	// JSON 파일로 저장 (예쁘게 포맷팅)
	jsonFile := fmt.Sprintf("./logs/bidi_latest_prompt_%s.json", timestamp)
	prettyJSON := s.prettyFormatJSON(latestJSON)
	if err := os.WriteFile(jsonFile, []byte(prettyJSON), 0644); err != nil {
		return false, fmt.Errorf("failed to save latest prompt JSON: %w", err)
	}

	// JSON에서 실제 텍스트 추출
	extractedText := s.extractTextFromJSON(latestJSON)
	if extractedText != "" {
		textFile := fmt.Sprintf("./logs/bidi_latest_text_%s.txt", timestamp)
		_ = os.WriteFile(textFile, []byte(extractedText), 0644)
	}

	return true, nil
}

// ----- 공용 유틸 -----

func newHTTPTransport() *http.Transport {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	// HTTP/1.1만 사용: HTTP/2 비활성화
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}

	return transport
}

func (s *Server) isAllowedPort(hostport string) bool {
	_, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		// URL.Host에 포트가 없는 경우(거의 없음) — 보수적으로 통과
		return true
	}
	for _, p := range s.config.AllowPorts {
		if fmt.Sprintf("%d", p) == portStr {
			return true
		}
	}
	return false
}

// ----- HTTP 핸들러 -----

func (s *Server) CreateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			// MCP Proxy 요청은 MITM 우회 (직접 터널링)
			if s.isMCPProxyRequest(r) {
				s.handleHTTPSTunnel(w, r)
				return
			}
			if s.config.EnableMITM && s.caCert != nil {
				s.handleHTTPSMITM(w, r)
				return
			}
			s.handleHTTPSTunnel(w, r)
			return
		}
		s.handleHTTP(w, r)
	}
}

func (s *Server) handleHTTPSTunnel(w http.ResponseWriter, r *http.Request) {
	isMCP := s.isMCPProxyRequest(r)
	s.logConnection("HTTPS-TUNNEL", r.Host, r.RemoteAddr, nil)

	// MCP Proxy 요청은 포트 체크 우회
	if !isMCP && !s.isAllowedPort(r.Host) {
		http.Error(w, "CONNECT to this port is not allowed", http.StatusForbidden)
		s.logConnection("HTTPS-TUNNEL", r.Host, r.RemoteAddr, fmt.Errorf("port not allowed"))
		return
	}

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Failed to connect to destination", http.StatusServiceUnavailable)
		s.logConnection("HTTPS-TUNNEL", r.Host, r.RemoteAddr, err)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = destConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		_ = destConn.Close()
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}

	// RFC: HTTP/1.1 고정으로 200 Established 직접 송신
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 콘솔 한 줄 출력 (Fiddler 스타일)
	s.printTunnelLine(r.Host)

	errc := make(chan error, 2)
	go func() {
		_, e := io.Copy(destConn, clientConn)
		if tcp, ok := destConn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		errc <- e
	}()
	go func() {
		_, e := io.Copy(clientConn, destConn)
		if tcp, ok := clientConn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		errc <- e
	}()

	<-errc
	_ = destConn.Close()
	_ = clientConn.Close()
}

func (s *Server) handleHTTPSMITM(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}

	if !s.isAllowedPort(r.Host) {
		http.Error(w, "CONNECT to this port is not allowed (MITM)", http.StatusForbidden)
		return
	}

	// 200 Established 직접 송신 후 하이잭
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		s.logConnection("HTTPS-MITM", r.Host, r.RemoteAddr, fmt.Errorf("hijack: %w", err))
		return
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert, err := s.getCertificateForHost(host)
	if err != nil {
		s.logConnection("HTTPS-MITM", r.Host, r.RemoteAddr, fmt.Errorf("get cert: %w", err))
		return
	}

	// HTTP/1.1만 지원
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"}, // HTTP/1.1만 지원
	}
	tlsClientConn := tls.Server(clientConn, tlsCfg)
	defer tlsClientConn.Close()

	if err := tlsClientConn.Handshake(); err != nil {
		s.logConnection("HTTPS-MITM", r.Host, r.RemoteAddr, fmt.Errorf("TLS handshake: %w", err))
		return
	}

	// HTTP/1.1만 처리
	// fmt.Printf("🚀 Starting HTTP/1.1 server for %s\n", host) // 디버그 출력 제거
	transport := newHTTPTransport()

	// TLS 연결의 실제 클라이언트 주소 저장 (getClientIP에서 사용)
	actualClientAddr := tlsClientConn.RemoteAddr().String()

	for {
		reader := bufio.NewReader(tlsClientConn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			break
		}

		// HTTP/1.1 강제
		req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.1", 1, 1
		req.URL.Scheme = "https"
		req.URL.Host = host
		req.RequestURI = ""

		// TLS 연결의 실제 클라이언트 주소를 req.RemoteAddr에 설정
		// 이렇게 하면 getClientIP에서 올바른 IP를 추출할 수 있음
		req.RemoteAddr = actualClientAddr

		// 🚀 AI 채팅 관련 요청만 필터링 🚀
		if !s.isAIChatRequest(req) {
			// AI 채팅 관련이 아닌 요청은 단순히 전달만
			resp, err := transport.RoundTrip(req)
			if err != nil {
				_ = (&http.Response{
					StatusCode: http.StatusBadGateway,
					Status:     "502 Bad Gateway",
					Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Header: make(http.Header),
					Body:   io.NopCloser(strings.NewReader("Failed to reach destination")),
				}).Write(tlsClientConn)
				continue
			}

			// 응답을 클라이언트로 전달
			if err := resp.Write(tlsClientConn); err != nil {
				break
			}
			continue
		}

		// === 🚀 MITM 인터셉트를 위한 핵심 로직 🚀 ===
		var reqBodyRaw []byte
		originalBody := req.Body // 원래 req.Body 저장

		if s.config.HeadersOnly {
			s.logHeadersOnly(req, r.RemoteAddr)
		} else if req.Body != nil {
			// (1) 원본 body 읽기
			reqBodyRaw, _ = io.ReadAll(req.Body)
			_ = req.Body.Close()

			// (2) StreamUnifiedChatWithToolsSSE 요청인지 확인하여 SSE 연결 시작 플래그 설정
			if strings.Contains(req.URL.Path, "StreamUnifiedChatWithToolsSSE") {
				clientIP := s.getClientIP(req)
				sseKey := fmt.Sprintf("%s_sse_started", clientIP)
				counterKey := fmt.Sprintf("%s_bidi_counter", clientIP)

				// SSE 연결 시작 플래그 설정
				s.sseMu.Lock()
				s.sseConnectionsStarted[sseKey] = true
				s.sseMu.Unlock()

				// 🔍 SSE 연결 시작 시 카운터 리셋 (SSE 연결 후 첫 번째 BidiAppend를 처리하기 위해)
				s.bidiAppendMu.Lock()
				s.bidiAppendCounters[counterKey] = 0
				s.bidiAppendMu.Unlock()

			}

			// (2-1) BidiAppend 요청인지 확인하고 미리 처리
			if strings.Contains(req.URL.Path, "BidiAppend") {
				// BidiAppend 요청 처리 및 수정
				modifiedBody, err := s.processBidiAppendRequestWithMasking(reqBodyRaw, req)
				if err != nil {
					// 수정 실패시 원본 사용
					req.Body = io.NopCloser(bytes.NewReader(reqBodyRaw))
				} else {
					// 수정된 body 사용
					req.Body = io.NopCloser(bytes.NewReader(modifiedBody))
					// Content-Length 헤더 업데이트 (중요!)
					req.ContentLength = int64(len(modifiedBody))
					req.Header.Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))
				}
			} else {
				// 다른 요청은 원본 그대로 사용
				req.Body = io.NopCloser(bytes.NewReader(reqBodyRaw))
			}
		}

		// (3) ★★★ transport.RoundTrip 실행 ★★★
		// 이제 수정된 body로 서버에 요청 전송

		// 실제 전송되는 body 확인
		if req.Body != nil {
			bodyBytes, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// 실제 전송된 body를 파일로 저장 (디버깅용) - 비활성화
			// actualSentFile := fmt.Sprintf("./logs/actual_sent_%s.bin", time.Now().Format("20060102_150405"))
			// if err := os.WriteFile(actualSentFile, bodyBytes, 0644); err == nil {
			//	fmt.Printf("💾 Actual sent body saved to: %s\n", actualSentFile)
			// }
		}

		resp, err := transport.RoundTrip(req)

		// (4) req.Body를 원래대로 복원 (필수!)
		req.Body = originalBody

		if err != nil {
			s.logRequest(req, nil, nil, nil, err)
			_ = (&http.Response{
				StatusCode: http.StatusBadGateway,
				Status:     "502 Bad Gateway",
				Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header),
				Body:   io.NopCloser(strings.NewReader("Failed to reach destination")),
			}).Write(tlsClientConn)
			continue
		}

		// (5) ★★★ RoundTrip 이후 로깅 (일반 요청) ★★★
		if !s.config.HeadersOnly {
			// 일반적인 로깅 (BidiAppend는 이미 위에서 처리됨)
			if len(reqBodyRaw) > 0 && !strings.Contains(req.URL.Path, "BidiAppend") {
				// 다른 요청들에 대한 로깅
				s.logRequest(req, resp, nil, nil, nil)
			}
		}

		if s.config.HeadersOnly {
			s.logRespHeadersOnly(req, resp, r.RemoteAddr)

			// 헤더 전송 후 본문 파이프
			if err := s.writeResponseHeaders(tlsClientConn, resp); err != nil {
				_ = resp.Body.Close()
				break
			}
			// 콘솔 한 줄 출력
			s.printFromReqResp(req, resp)

			_, _ = io.Copy(tlsClientConn, resp.Body)
			_ = resp.Body.Close()
		} else {
			// 기존 상세 로깅 경로
			isStreaming := s.isStreamingRequest(req) || s.isStreamingResponse(resp)
			if isStreaming {
				s.logStreamingRequest(req, resp, r.RemoteAddr)

				if err := s.writeResponseHeaders(tlsClientConn, resp); err != nil {
					_ = resp.Body.Close()
					break
				}

				buf := make([]byte, 8*1024)
				var streamBuffer bytes.Buffer
				isBidiAppend := strings.Contains(req.URL.Path, "BidiAppend")
				isSSE := strings.Contains(req.URL.Path, "StreamUnifiedChatWithToolsSSE")

				// 🔍 SSE 연결 시작 시 플래그 설정 (요청 처리에서 이미 설정했으므로 여기서는 리셋하지 않음)
				// 주의: handleHTTP에서 이미 SSE 연결을 감지하고 카운터를 리셋했으므로,
				// 여기서는 중복 리셋을 방지하기 위해 플래그만 확인
				if isSSE {
					clientIP := s.getClientIP(req)
					sseKey := fmt.Sprintf("%s_sse_started", clientIP)

					// SSE 연결 시작 플래그 확인 (이미 설정되어 있을 수 있음)
					s.sseMu.RLock()
					alreadyStarted := s.sseConnectionsStarted[sseKey]
					s.sseMu.RUnlock()

					// 플래그가 설정되지 않았다면 설정 (요청 처리에서 놓친 경우 대비)
					if !alreadyStarted {
						s.sseMu.Lock()
						s.sseConnectionsStarted[sseKey] = true
						s.sseMu.Unlock()
					}
					// 카운터는 요청 처리에서 이미 리셋했으므로 여기서는 리셋하지 않음
				}

				// BidiAppend 또는 SSE 스트리밍 응답 처리
				if isBidiAppend || isSSE {
					// TeeReader로 스트림을 복사하면서 읽기
					teeReader := io.TeeReader(resp.Body, &streamBuffer)
					resp.Body = io.NopCloser(teeReader)
				}

				totalRead := 0
				var sseDataBuffer bytes.Buffer // SSE 데이터를 직접 저장 (TeeReader 실패 대비)
				var sseToolNameExtracted bool  // 도구 이름이 이미 추출되었는지 확인
				var ssePermissionChecked bool  // 권한 체크가 완료되었는지 확인
				var ssePermissionAllowed bool  // 권한이 허용되었는지 확인
				var sseLogFile *os.File        // SSE 로그 파일 (실시간 기록용)

				// SSE 스트림인 경우 로그 파일 미리 생성 (도구 이름 추출용)
				if isSSE {
					timestamp := time.Now().Format("20060102_150405")
					sseLogPath := fmt.Sprintf("./logs/sse_stream_%s.txt", timestamp)
					var err error
					sseLogFile, err = os.Create(sseLogPath)
					if err == nil {
						// 헤더 작성
						sseLogFile.WriteString(fmt.Sprintf("=== SSE Stream Log ===\n"))
						sseLogFile.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05")))
						sseLogFile.WriteString(fmt.Sprintf("Client IP: %s\n", s.getClientIP(req)))
						sseLogFile.WriteString(fmt.Sprintf("Path: %s\n", req.URL.Path))
						sseLogFile.WriteString(fmt.Sprintf("\n--- Stream Data ---\n\n"))
					}
				}

				// defer로 파일 닫기 보장
				defer func() {
					if sseLogFile != nil {
						sseLogFile.Close()
					}
				}()

				for {
					n, readErr := resp.Body.Read(buf)
					if n > 0 {
						totalRead += n
						if isSSE {
							// SSE 데이터를 직접 버퍼에 저장
							sseDataBuffer.Write(buf[:n])

							// 실시간으로 로그 파일에 기록 (파일만, 터미널 출력 없음)
							if sseLogFile != nil {
								// 청크 정보와 데이터 기록
								sseLogFile.WriteString(fmt.Sprintf("[Chunk %d bytes, Total: %d bytes]\n", n, totalRead))
								sseLogFile.WriteString(fmt.Sprintf("Hex: %s\n", hex.EncodeToString(buf[:n])))
								sseLogFile.WriteString(fmt.Sprintf("Text: %s\n", string(buf[:n])))
								sseLogFile.WriteString(fmt.Sprintf("\n"))
								sseLogFile.Sync() // 즉시 디스크에 쓰기
							}

							// 실시간으로 도구 이름 추출 및 권한 체크 (청크 단위)
							// 각 청크마다 추출 시도 (여러 도구 호출이 있을 수 있음)
							if sseDataBuffer.Len() > 100 {
								// 현재 청크에서 도구 이름 추출 시도
								if toolName := s.extractToolNameFromSSEChunk(buf[:n], req); toolName != "" {
									// 이미 체크한 도구는 다시 체크하지 않음
									if !sseToolNameExtracted {
										sseToolNameExtracted = true
										clientIP := s.getClientIP(req)

										// 로그 파일에도 기록
										if sseLogFile != nil {
											sseLogFile.WriteString(fmt.Sprintf("\n=== TOOL NAME EXTRACTED ===\n"))
											sseLogFile.WriteString(fmt.Sprintf("Tool Name: %s\n", toolName))
											sseLogFile.WriteString(fmt.Sprintf("Client IP: %s\n", clientIP))
											sseLogFile.WriteString(fmt.Sprintf("Extracted at: %s\n", time.Now().Format("2006-01-02 15:04:05")))
											sseLogFile.Sync()
										}

										// 도구 사용 권한 체크 (동기적으로 수행)
										allowed, err := s.checkToolPermission(clientIP, toolName)
										ssePermissionChecked = true
										if err != nil {
											// 웹서버 통신 실패 시 차단 (안전을 위해 거부)
											ssePermissionAllowed = false
											if sseLogFile != nil {
												sseLogFile.WriteString(fmt.Sprintf("\n=== TOOL PERMISSION CHECK FAILED ===\n"))
												sseLogFile.WriteString(fmt.Sprintf("Client IP: %s\n", clientIP))
												sseLogFile.WriteString(fmt.Sprintf("Tool Name: %s\n", toolName))
												sseLogFile.WriteString(fmt.Sprintf("Error: %v\n", err))
												sseLogFile.WriteString(fmt.Sprintf("Action: SSE stream blocked (webserver communication failed)\n"))
												sseLogFile.Sync()
											}

											// RBAC 위반 정보를 웹서버에 전송 시도
											_ = s.sendRBACViolation(clientIP, toolName)

											// SSE 스트림 차단: 에러 메시지를 SSE 형식으로 전송
											errorMessage := fmt.Sprintf("도구 사용 불가능: 권한 확인 중 오류가 발생했습니다. (%s)", toolName)
											errorEvent := fmt.Sprintf("event: error\ndata: %s\n\n", errorMessage)
											_, _ = tlsClientConn.Write([]byte(errorEvent))
											_ = resp.Body.Close()
											return // 스트림 차단 후 종료
										} else if !allowed {
											// 권한이 없으면 스트림 차단 및 RBAC 위반 정보 전송
											ssePermissionAllowed = false
											if sseLogFile != nil {
												sseLogFile.WriteString(fmt.Sprintf("\n=== TOOL ACCESS DENIED ===\n"))
												sseLogFile.WriteString(fmt.Sprintf("Client IP: %s\n", clientIP))
												sseLogFile.WriteString(fmt.Sprintf("Tool Name: %s\n", toolName))
												sseLogFile.WriteString(fmt.Sprintf("Action: SSE stream blocked\n"))
												sseLogFile.Sync()
											}

											// RBAC 위반 정보를 웹서버에 전송
											if err := s.sendRBACViolation(clientIP, toolName); err != nil {
												// 에러는 로그 파일에만 기록
											}

											// SSE 스트림 차단: 에러 메시지를 SSE 형식으로 전송
											errorMessage := fmt.Sprintf("도구 사용 불가능: %s 도구에 대한 권한이 없습니다.", toolName)
											// SSE 형식의 에러 이벤트 전송
											errorEvent := fmt.Sprintf("event: error\ndata: %s\n\n", errorMessage)
											_, _ = tlsClientConn.Write([]byte(errorEvent))
											_ = resp.Body.Close()
											return // 스트림 차단 후 종료
										} else {
											// 권한이 있으면 데이터 전송 허용
											ssePermissionAllowed = true
											if sseLogFile != nil {
												sseLogFile.WriteString(fmt.Sprintf("✅ Permission granted\n"))
												sseLogFile.Sync()
											}
										}
									}
								}
							}
						}

						// 권한 체크가 완료되었고 권한이 없으면 데이터를 전송하지 않음
						// 권한 체크가 아직 안 되었거나 권한이 있으면 데이터 전송
						if !ssePermissionChecked || ssePermissionAllowed {
							if _, writeErr := tlsClientConn.Write(buf[:n]); writeErr != nil {
								break
							}
						} else {
							// 권한이 없어서 스트림이 차단된 경우, 더 이상 데이터를 읽지 않음
							_ = resp.Body.Close()
							break
						}
					}
					if readErr != nil {
						break
					}
				}
				_ = resp.Body.Close()

				// SSE 데이터가 있으면 streamBuffer에 복사 (TeeReader 실패 대비)
				if isSSE && sseDataBuffer.Len() > 0 && streamBuffer.Len() == 0 {
					streamBuffer = sseDataBuffer
				}

				// BidiAppend 스트리밍 응답 처리 (스트림 완료 후)
				if isBidiAppend && streamBuffer.Len() > 0 {
					s.processBidiAppendStreamingResponseData(streamBuffer.Bytes(), req)
				}

				// SSE 스트림 완료 후 도구 이름 추출 재시도 (실시간 추출 실패 시)
				if isSSE && !sseToolNameExtracted && sseDataBuffer.Len() > 0 {
					if toolName := s.extractToolNameFromSSEChunk(sseDataBuffer.Bytes(), req); toolName != "" {
						sseToolNameExtracted = true
						clientIP := s.getClientIP(req)
						allowed, err := s.checkToolPermission(clientIP, toolName)
						if err != nil || !allowed {
							// 권한이 없거나 체크 실패 시 이미 스트림이 전송되었으므로 로그만 기록
							_ = s.sendRBACViolation(clientIP, toolName)
						}
					}
				}
			} else {
				respBodyRaw, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				respBodyDecomp := s.decompressGzip(respBodyRaw)

				// BidiAppend 응답 처리 (도구 선택 정보 확인)
				// Content-Length가 0이어도 처리 (빈 응답일 수 있음)
				if strings.Contains(req.URL.Path, "BidiAppend") {
					s.processBidiAppendResponse(respBodyRaw, respBodyDecomp, req)
				}

				s.logOutboundRequest(req, resp, respBodyRaw, respBodyDecomp, r.RemoteAddr)
				s.logRequest(req, resp, nil, respBodyDecomp, nil)

				resp.Body = io.NopCloser(bytes.NewReader(respBodyRaw))
				if err := resp.Write(tlsClientConn); err != nil {
					break
				}
			}
		}

		if strings.EqualFold(resp.Header.Get("Connection"), "close") {
			break
		}
	}
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", http.StatusBadRequest)
		return
	}
	if !s.isAllowedPort(r.URL.Host) {
		http.Error(w, "Only ports 80/443 are allowed", http.StatusForbidden)
		return
	}

	// X-Forwarded-For 보강
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			ip = strings.Join(prior, ", ") + ", " + ip
		}
		r.Header.Set("X-Forwarded-For", ip)
	}

	// 프록시 관련 헤더 제거
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Connection")

	// HTTP/1.1 강제
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/1.1", 1, 1
	transport := newHTTPTransport()

	if s.config.HeadersOnly {
		if s.config.VerboseLogging {
			s.logHeadersOnly(r, r.RemoteAddr)
		}

		resp, err := transport.RoundTrip(r)
		if err != nil {
			http.Error(w, "Failed to reach destination", http.StatusServiceUnavailable)
			s.logRequest(r, nil, nil, nil, err)
			return
		}
		defer resp.Body.Close()

		if s.config.VerboseLogging {
			s.logRespHeadersOnly(r, resp, r.RemoteAddr)
		}

		// 콘솔 한 줄 출력
		s.printFromReqResp(r, resp)

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	// === HeadersOnly 가 아닐 때: 기존 로깅 경로 유지 ===
	var reqBodyRaw, reqBodyDecomp []byte
	if r.Body != nil {
		reqBodyRaw, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		reqBodyDecomp = s.decompressGzip(reqBodyRaw)
		r.Body = io.NopCloser(bytes.NewReader(reqBodyRaw))
	}

	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "Failed to reach destination", http.StatusServiceUnavailable)
		s.logRequest(r, nil, reqBodyDecomp, nil, err)
		return
	}
	defer resp.Body.Close()

	isStreaming := s.isStreamingRequest(r) || s.isStreamingResponse(resp)
	if isStreaming {
		s.logStreamingRequest(r, resp, r.RemoteAddr)
		// 콘솔 한 줄 출력
		s.printFromReqResp(r, resp)

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					break
				}
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
			}
			if err != nil {
				break
			}
		}
	} else {
		respBodyRaw, _ := io.ReadAll(resp.Body)
		respBodyDecomp := s.decompressGzip(respBodyRaw)

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBodyRaw)

		s.logRequest(r, resp, reqBodyDecomp, respBodyDecomp, nil)

		// 콘솔 한 줄 출력
		s.printFromReqResp(r, resp)
	}
}

// ----- 로깅/유틸 -----

func (s *Server) logConnection(protocol, target, remoteAddr string, err error) {
	s.logMutex.Lock()
	defer s.logMutex.Unlock()
	entry := map[string]any{
		"timestamp":   time.Now().Format(time.RFC3339),
		"protocol":    protocol,
		"target":      target,
		"remote_addr": remoteAddr,
		"status":      "success",
	}
	if err != nil {
		entry["status"] = "failed"
		entry["error"] = err.Error()
	}
	_ = s.logger.WriteLine(entry)
}

func (s *Server) logHeadersOnly(r *http.Request, remote string) {
	if s.config.AIOnly && !s.isAIServiceRequest(r) {
		return
	}
	s.logMutex.Lock()
	defer s.logMutex.Unlock()
	entry := map[string]any{
		"timestamp":      time.Now().Format(time.RFC3339),
		"event":          "request_headers",
		"remote_addr":    remote,
		"proto":          r.Proto,
		"method":         r.Method,
		"url":            r.URL.String(),
		"host":           r.Host,
		"headers":        r.Header,
		"content_length": r.ContentLength,
	}
	_ = s.logger.WriteLine(entry)
}

func (s *Server) logRespHeadersOnly(req *http.Request, resp *http.Response, remote string) {
	if s.config.AIOnly && !s.isAIServiceRequest(req) {
		return
	}
	s.logMutex.Lock()
	defer s.logMutex.Unlock()
	entry := map[string]any{
		"timestamp":         time.Now().Format(time.RFC3339),
		"event":             "response_headers",
		"remote_addr":       remote,
		"request_url":       req.URL.String(),
		"status":            resp.Status,
		"status_code":       resp.StatusCode,
		"proto":             resp.Proto,
		"headers":           resp.Header,
		"content_length":    resp.ContentLength,
		"transfer_encoding": resp.TransferEncoding,
	}
	_ = s.logger.WriteLine(entry)
}

func (s *Server) logRequest(r *http.Request, resp *http.Response, requestBodyDecomp []byte, responseBodyDecomp []byte, err error) {
	if s.config.AIOnly && !s.isAIServiceRequest(r) {
		return
	}
	if s.config.HeadersOnly {
		// HeadersOnly 모드에서는 본문 로깅 안 함
		return
	}

	s.logMutex.Lock()
	defer s.logMutex.Unlock()

	entry := map[string]any{
		"timestamp":   time.Now().Format(time.RFC3339),
		"protocol":    r.Proto,
		"method":      r.Method,
		"url":         r.URL.String(),
		"remote_addr": r.RemoteAddr,
		"status":      "success",
	}

	if s.config.VerboseLogging {
		entry["headers"] = r.Header
	}

	if len(requestBodyDecomp) > 0 {
		entry["request_body_size"] = len(requestBodyDecomp)
		if s.config.DecodeProtobuf {
			if texts := s.extractTextFromProtobuf(requestBodyDecomp); len(texts) > 0 {
				entry["decoded_request_texts"] = texts
				if s.containsUserPrompt(texts) {
					entry["contains_prompt"] = true
				}
			}
		}
		max := 50 * 1024
		if len(requestBodyDecomp) > max {
			entry["request_body"] = string(requestBodyDecomp[:max]) + "... (truncated)"
		} else {
			entry["request_body"] = string(requestBodyDecomp)
		}
	}

	if resp != nil {
		entry["status_code"] = resp.StatusCode
		if s.config.VerboseLogging {
			entry["response_headers"] = resp.Header
		}
		if len(responseBodyDecomp) > 0 {
			entry["response_body_size"] = len(responseBodyDecomp)
			max := 50 * 1024
			if len(responseBodyDecomp) > max {
				entry["response_body"] = string(responseBodyDecomp[:max]) + "... (truncated)"
			} else {
				entry["response_body"] = string(responseBodyDecomp)
			}
		}
	}

	if err != nil {
		entry["status"] = "failed"
		entry["error"] = err.Error()
	}

	_ = s.logger.WriteLine(entry)
}

func (s *Server) decompressGzip(data []byte) []byte {
	if len(data) < 10 {
		return data
	}
	if data[0] != 0x1f || data[1] != 0x8b {
		return data
	}
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data
	}
	defer gr.Close()
	out, err := io.ReadAll(gr)
	if err != nil {
		return data
	}
	return out
}

func (s *Server) compressGzip(data []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return data
	}
	if err := gz.Close(); err != nil {
		return data
	}
	return buf.Bytes()
}

// textToHex - 텍스트를 hex 문자열로 변환
func (s *Server) textToHex(text string) string {
	return hex.EncodeToString([]byte(text))
}

// encodeToProtobuf - 바이너리 데이터를 protobuf 형식으로 인코딩
func (s *Server) encodeToProtobuf(data []byte) []byte {
	// 간단한 protobuf 인코딩 (field 1, wire type 2)
	var buf bytes.Buffer

	// Field 1, Wire Type 2 (length-delimited)
	fieldTag := (1 << 3) | 2 // field 1, wire type 2
	buf.WriteByte(byte(fieldTag))

	// Length (varint)
	length := len(data)
	for length >= 0x80 {
		buf.WriteByte(byte(length) | 0x80)
		length >>= 7
	}
	buf.WriteByte(byte(length))

	// Data
	buf.Write(data)

	return buf.Bytes()
}

// Connect-es 프레이밍: 1바이트 flags + 4바이트 big-endian length + payload
func (s *Server) parseConnectProtocol(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	flags := data[0]
	msgLen := int(binary.BigEndian.Uint32(data[1:5]))
	if msgLen <= 0 || 5+msgLen > len(data) {
		return ""
	}

	msgData := data[5 : 5+msgLen]

	// 프레임 내부 압축 여부: flags bit0 또는 gzip 헤더 체킹
	compressed := (flags & 0x01) == 0x01
	if compressed || (len(msgData) >= 2 && msgData[0] == 0x1f && msgData[1] == 0x8b) {
		if gr, err := gzip.NewReader(bytes.NewReader(msgData)); err == nil {
			defer gr.Close()
			if dec, e := io.ReadAll(gr); e == nil {
				msgData = dec
			}
		}
	}

	decodedMsg := s.decodeProtobufMessage(msgData)
	if decodedMsg != "" {
		return decodedMsg
	}

	return fmt.Sprintf("Connect msg (%dB, flags=0x%02x)", msgLen, flags)
}

// Connect 프로토콜 스트림을 프레임 단위로 파싱하는 함수
func (s *Server) parseConnectStreamFrames(reader io.Reader) ([]byte, error) {
	var allFrames []byte
	bufReader := bufio.NewReader(reader)

	for {
		// Connect 프레임 헤더 (5바이트) 읽기
		header := make([]byte, 5)
		_, err := io.ReadFull(bufReader, header)
		if err != nil {
			if err == io.EOF {
				break // 스트림 정상 종료
			}
			return allFrames, fmt.Errorf("failed to read frame header: %w", err)
		}

		msgLen := int(binary.BigEndian.Uint32(header[1:5]))

		if msgLen <= 0 {
			return allFrames, fmt.Errorf("invalid message length: %d", msgLen)
		}

		// 페이로드 읽기
		payload := make([]byte, msgLen)
		_, err = io.ReadFull(bufReader, payload)
		if err != nil {
			return allFrames, fmt.Errorf("failed to read payload: %w", err)
		}

		// 전체 프레임 데이터 (헤더 + 페이로드) 저장
		fullFrame := append(header, payload...)
		allFrames = append(allFrames, fullFrame...)
	}

	return allFrames, nil
}

// Connect 스트림의 첫 번째 프레임만 읽는 함수
func (s *Server) readFirstConnectFrame(reader io.Reader) ([]byte, error) {
	bufReader := bufio.NewReader(reader)

	// Connect 프레임 헤더 (5바이트) 읽기
	header := make([]byte, 5)
	_, err := io.ReadFull(bufReader, header)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame header: %w", err)
	}

	msgLen := int(binary.BigEndian.Uint32(header[1:5]))

	if msgLen <= 0 {
		return nil, fmt.Errorf("invalid message length: %d", msgLen)
	}

	// 페이로드 읽기
	payload := make([]byte, msgLen)
	_, err = io.ReadFull(bufReader, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}

	// 전체 프레임 데이터 (헤더 + 페이로드) 반환
	fullFrame := append(header, payload...)

	return fullFrame, nil
}

// Connect 프로토콜 스트림을 프레임 단위로 파싱하고 "로그만" 찍는 함수
func (s *Server) parseConnectStreamFramesAndLog(reader io.Reader) error {
	return nil
}

// Connect/gRPC-web 스트리밍 요청인지 확인하는 함수
func (s *Server) isConnectStreamingRequest(req *http.Request) bool {
	return false
}

func (s *Server) decodeProtobufMessage(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// StreamUnifiedChatWithToolsRequest로 디코딩 시도
	var request cursor_grpc.StreamUnifiedChatWithToolsRequest
	if err := proto.Unmarshal(data, &request); err == nil {
		return s.formatStreamRequest(&request)
	}

	// StreamUnifiedChatWithToolsResponse로 디코딩 시도
	var response cursor_grpc.StreamUnifiedChatWithToolsResponse
	if err := proto.Unmarshal(data, &response); err == nil {
		return s.formatStreamResponse(&response)
	}

	// BidiAppendRequest는 별도 메시지가 아닐 수 있으므로 수동 파싱으로 fallback
	return s.decodeProtobufMessageManual(data)
}

// formatStreamRequest StreamUnifiedChatWithToolsRequest 포맷팅
func (s *Server) formatStreamRequest(req *cursor_grpc.StreamUnifiedChatWithToolsRequest) string {
	var parts []string

	switch payload := req.RequestPayload.(type) {
	case *cursor_grpc.StreamUnifiedChatWithToolsRequest_InitialRequest:
		parts = append(parts, "InitialRequest:")
		if payload.InitialRequest != nil {
			parts = append(parts, fmt.Sprintf("  Messages: %d", len(payload.InitialRequest.Messages)))
			parts = append(parts, fmt.Sprintf("  Tools: %d", len(payload.InitialRequest.Tools)))
		}
	case *cursor_grpc.StreamUnifiedChatWithToolsRequest_ToolResult:
		parts = append(parts, "ToolResult:")
		if payload.ToolResult != nil {
			parts = append(parts, fmt.Sprintf("  ToolCallId: %s", payload.ToolResult.ToolCallId))
			parts = append(parts, fmt.Sprintf("  IsError: %v", payload.ToolResult.IsError))
		}
	case *cursor_grpc.StreamUnifiedChatWithToolsRequest_UserMessage:
		parts = append(parts, "UserMessage:")
		if payload.UserMessage != nil && payload.UserMessage.Message != nil {
			parts = append(parts, fmt.Sprintf("  Role: %v", payload.UserMessage.Message.Role))
			parts = append(parts, fmt.Sprintf("  Parts: %d", len(payload.UserMessage.Message.Parts)))

			// 사용자 메시지 텍스트 추출
			for _, part := range payload.UserMessage.Message.Parts {
				if textPart := part.GetText(); textPart != "" {
					parts = append(parts, fmt.Sprintf("  Text: %s", textPart))
				}
			}
		}
	}

	return strings.Join(parts, "\n")
}

// formatStreamResponse StreamUnifiedChatWithToolsResponse 포맷팅
func (s *Server) formatStreamResponse(resp *cursor_grpc.StreamUnifiedChatWithToolsResponse) string {
	var parts []string

	if resp.Part != nil {
		switch content := resp.Part.Content.(type) {
		case *cursor_grpc.ResponsePart_MessagePart:
			if content.MessagePart != nil {
				parts = append(parts, "ResponsePart:")
				parts = append(parts, fmt.Sprintf("  Text: %s", content.MessagePart.Text))
				if content.MessagePart.Metadata != nil {
					parts = append(parts, fmt.Sprintf("  Metadata: %v", content.MessagePart.Metadata))
				}
			}
		case *cursor_grpc.ResponsePart_BubbleId:
			parts = append(parts, fmt.Sprintf("BubbleId: %s", content.BubbleId))
		case *cursor_grpc.ResponsePart_ToolCall:
			if content.ToolCall != nil {
				parts = append(parts, "ToolCall:")
				parts = append(parts, fmt.Sprintf("  ToolName: %s", content.ToolCall.ToolName))
				parts = append(parts, fmt.Sprintf("  ToolCallId: %s", content.ToolCall.ToolCallId))
			}
		case *cursor_grpc.ResponsePart_FinalResponse:
			if content.FinalResponse != nil {
				parts = append(parts, "FinalResponse:")
				parts = append(parts, fmt.Sprintf("  StopReason: %v", content.FinalResponse.StopReason))
			}
		}
	}

	return strings.Join(parts, "\n")
}

// decodeProtobufMessageManual 수동 protobuf 파싱 (fallback)
func (s *Server) decodeProtobufMessageManual(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// 16진수 문자열로 저장된 경우 디코딩
	if len(data) > 2 {
		hexStr := string(data)
		isHex := true
		for _, c := range hexStr[:min(100, len(hexStr))] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ' ' || c == '\n') {
				isHex = false
				break
			}
		}
		if isHex {
			// 공백 제거 후 디코딩 시도
			cleanHex := ""
			for _, c := range hexStr {
				if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
					cleanHex += string(c)
				}
			}
			if decoded, err := hex.DecodeString(cleanHex); err == nil && len(decoded) > 0 {
				data = decoded
			}
		}
	}

	var fields []string
	var userMessages []string
	offset := 0

	for offset < len(data) && len(fields) < 1000 {
		if offset >= len(data) {
			break
		}

		// varint 읽기 (field tag + wire type)
		tag, newOffset := s.readVarint(data, offset)
		if newOffset == -1 {
			if len(fields) == 0 {
				return ""
			}
			break
		}

		fieldNum := tag >> 3
		wireType := tag & 0x07
		offset = newOffset

		// wire type에 따른 데이터 읽기
		switch wireType {
		case 0: // varint
			val, newOffset := s.readVarint(data, offset)
			if newOffset == -1 {
				return ""
			}
			fields = append(fields, fmt.Sprintf("Field %d, Wire Type 0: varint: %d", fieldNum, val))
			offset = newOffset

		case 1: // fixed64
			if offset+8 > len(data) {
				return ""
			}
			fields = append(fields, fmt.Sprintf("Field %d, Wire Type 1: fixed64", fieldNum))
			offset += 8

		case 2: // length-delimited (string, bytes, message)
			length, newOffset := s.readVarint(data, offset)
			if newOffset == -1 || newOffset+int(length) > len(data) {
				fields = append(fields, fmt.Sprintf("Field %d, Wire Type 2: length too large", fieldNum))
				break
			}
			fieldData := data[newOffset : newOffset+int(length)]

			if len(fieldData) == 0 {
				fields = append(fields, fmt.Sprintf("Field %d, Wire Type 2: bytes: (empty)", fieldNum))
			} else if s.isPrintableString(fieldData) {
				str := string(fieldData)
				// 사용자 메시지로 보이는 문자열
				if len(str) > 10 && (s.containsUserMessage(str) || len(str) > 50) {
					fields = append(fields, fmt.Sprintf("Field %d, Wire Type 2: string: %s", fieldNum, str))
					userMessages = append(userMessages, str)
				} else {
					// 짧은 문자열도 hex로 표시
					fields = append(fields, fmt.Sprintf("Field %d, Wire Type 2: string (hex): %x", fieldNum, fieldData))
				}
			} else {
				// 바이너리 데이터는 hex로 표시 (최대 32바이트)
				hexStr := hex.EncodeToString(fieldData[:min(32, len(fieldData))])
				fields = append(fields, fmt.Sprintf("Field %d, Wire Type 2: bytes: %s", fieldNum, hexStr))
			}
			offset = newOffset + int(length)

		case 3: // start group (deprecated)
			fields = append(fields, fmt.Sprintf("Field %d, Wire Type 3: start group (deprecated)", fieldNum))

		case 4: // end group (deprecated)
			fields = append(fields, fmt.Sprintf("Field %d, Wire Type 4: end group (deprecated)", fieldNum))

		case 5: // fixed32
			if offset+4 > len(data) {
				return ""
			}
			val := uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
			fields = append(fields, fmt.Sprintf("Field %d, Wire Type 5: fixed32: %d", fieldNum, val))
			offset += 4

		default:
			fields = append(fields, fmt.Sprintf("Field %d, Wire Type %d: unknown wire type", fieldNum, wireType))
		}
	}

	if len(userMessages) > 0 {
		return fmt.Sprintf("Protobuf Decoded Content:\n==================================================\n%s\n\n--- User Messages ---\n%s",
			strings.Join(fields, "\n"), strings.Join(userMessages, "\n\n"))
	}

	return strings.Join(fields, "\n")
}

// tryHexDecode hex 인코딩된 문자열을 디코딩 시도
func (s *Server) tryHexDecode(data []byte) []byte {
	// hex 문자열인지 확인 (0-9, a-f, A-F만 포함)
	hexStr := string(data)
	if len(hexStr) < 2 || len(hexStr)%2 != 0 {
		return nil
	}

	// hex 문자 비율 확인 (70% 이상이 hex 문자여야 함)
	hexCount := 0
	for _, c := range hexStr {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hexCount++
		}
	}
	if float64(hexCount)/float64(len(hexStr)) < 0.7 {
		return nil
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil
	}
	return decoded
}

func (s *Server) containsUserMessage(str string) bool {
	// 사용자 메시지로 보이는 패턴들
	userPatterns := []string{
		"test", "prompt", "message", "question", "help", "code", "function", "class",
		"이", "안녕", "테스트", "질문", "도움", "코드", "함수", "클래스",
	}

	lowerStr := strings.ToLower(str)
	for _, pattern := range userPatterns {
		if strings.Contains(lowerStr, pattern) {
			return true
		}
	}
	return false
}

func (s *Server) isPrintableString(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// UTF-8 유효성 검사
	if !utf8.Valid(data) {
		return false
	}

	// 바이너리 데이터가 아닌지 확인 (제어 문자 최소화)
	printableCount := 0
	for _, b := range data {
		if b >= 32 && b <= 126 { // ASCII printable
			printableCount++
		} else if b >= 0xc0 { // UTF-8 continuation or start byte
			// UTF-8 멀티바이트는 허용
		}
	}

	// 최소 50% 이상이 printable이거나 UTF-8 문자가 있어야 함
	return float64(printableCount) >= float64(len(data))*0.3
}

func (s *Server) analyzeProtobuf(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// protobuf wire format 분석
	var fields []string
	offset := 0

	for offset < len(data) {
		if offset >= len(data) {
			break
		}

		// varint 읽기 (field tag + wire type)
		tag, newOffset := s.readVarint(data, offset)
		if newOffset == -1 {
			break
		}

		fieldNum := tag >> 3
		wireType := tag & 0x07

		offset = newOffset

		// wire type에 따른 데이터 읽기
		var fieldData []byte
		var fieldValue string

		switch wireType {
		case 0: // varint
			val, newOffset := s.readVarint(data, offset)
			if newOffset == -1 {
				return ""
			}
			fieldValue = fmt.Sprintf("varint:%d", val)
			offset = newOffset

		case 2: // length-delimited (string, bytes, message)
			length, newOffset := s.readVarint(data, offset)
			if newOffset == -1 || newOffset+int(length) > len(data) {
				return ""
			}
			fieldData = data[newOffset : newOffset+int(length)]
			fieldValue = fmt.Sprintf("string(%d):%s", length, string(fieldData))
			offset = newOffset + int(length)

		case 5: // fixed32
			if offset+4 > len(data) {
				return ""
			}
			val := uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
			fieldValue = fmt.Sprintf("fixed32:%d", val)
			offset += 4

		default:
			return fmt.Sprintf("Unknown wire type %d at field %d", wireType, fieldNum)
		}

		fields = append(fields, fmt.Sprintf("field%d(%d):%s", fieldNum, wireType, fieldValue))

		// 너무 많은 필드면 중단
		if len(fields) > 10 {
			fields = append(fields, "...")
			break
		}
	}

	if len(fields) > 0 {
		return fmt.Sprintf("Protobuf: %s", strings.Join(fields, " | "))
	}

	return ""
}

func (s *Server) readVarint(data []byte, offset int) (uint64, int) {
	var result uint64
	var shift uint

	for {
		if offset >= len(data) {
			return 0, -1
		}

		b := data[offset]
		offset++

		result |= uint64(b&0x7F) << shift

		if (b & 0x80) == 0 {
			break
		}

		shift += 7
		if shift >= 64 {
			return 0, -1
		}
	}

	return result, offset
}

func (s *Server) extractTextFromProtobuf(data []byte) []string {
	var texts []string
	stringRegex := regexp.MustCompile(`\x12[\x00-\x1f]?([^\x00-\x1f]{3,})`)
	matches := stringRegex.FindAllSubmatch(data, -1)
	for _, m := range matches {
		if len(m) > 1 && len(m[1]) > 0 {
			t := string(m[1])
			if s.containsReadableText(t) {
				texts = append(texts, t)
			}
		}
	}
	jsonRegex := regexp.MustCompile(`"[^"]{3,}"`)
	for _, m := range jsonRegex.FindAll(data, -1) {
		t := strings.Trim(string(m), `"`)
		if s.containsReadableText(t) {
			texts = append(texts, t)
		}
	}
	return s.removeDuplicates(texts)
}

func (s *Server) removeDuplicates(texts []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, t := range texts {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) containsReadableText(text string) bool {
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || (r >= '가' && r <= '힣') ||
			strings.ContainsRune(" .,!?:;-_", r) {
			return true
		}
	}
	return false
}

func (s *Server) isAIServiceRequest(req *http.Request) bool {
	host := req.URL.Host
	return strings.HasSuffix(host, "cursor.sh") ||
		strings.HasSuffix(host, ".cursor.sh")
}

func (s *Server) containsUserPrompt(texts []string) bool {
	promptKeywords := []string{
		"안녕하세요", "테스트", "질문", "도움", "코드", "프로그래밍",
		"hello", "test", "help", "code", "programming", "question",
		"하이", "hi", "안녕", "좋은", "좋은하루",
	}
	for _, text := range texts {
		lowerText := strings.ToLower(text)
		for _, keyword := range promptKeywords {
			if strings.Contains(lowerText, keyword) {
				return true
			}
		}
	}
	return false
}

func (s *Server) logInboundRequest(req *http.Request, compressedBody, decompressedBody []byte, remoteAddr string) {
	// 🚀 AI 채팅 관련 요청만 로깅 🚀
	if !s.isAIChatRequest(req) {
		return // AI 채팅 관련이 아닌 요청은 로깅하지 않음
	}

	// 필터링: 특정 패킷만 상세 로깅
	path := req.URL.Path
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}

	if s.shouldLogPath(path) {
		fmt.Printf("\n═══════════════════════════════════════════════════════════════════\n")
		fmt.Printf("📥 [REQUEST] %s %s\n", req.Method, req.URL.String())
		fmt.Printf("⏰ %s\n", time.Now().Format("2006-01-02 15:04:05.000"))
		fmt.Printf("🌐 Host: %s\n", req.Host)
		fmt.Printf("📋 Headers:\n")
		for k, v := range req.Header {
			fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
		}

		if len(decompressedBody) > 0 {
			// 간결한 바이너리 데이터 표시 (4바이트만)
			debugLen := 4
			if len(decompressedBody) < debugLen {
				debugLen = len(decompressedBody)
			}
			// Body를 파일로 저장
			timestamp := time.Now().Format("20060102_150405")
			filename := fmt.Sprintf("./logs/bidi_body_%s_%d.bin", timestamp, len(decompressedBody))
			_ = os.WriteFile(filename, decompressedBody, 0644)

			// BidiService는 hex 인코딩된 문자열일 수 있으므로 먼저 hex 디코딩 시도
			if hexDecoded := s.tryHexDecode(decompressedBody); hexDecoded != nil {
				if protobufMsg := s.decodeProtobufMessage(hexDecoded); protobufMsg != "" {
					// Message decoded
				}
			} else {
				if protobufMsg := s.decodeProtobufMessage(decompressedBody); protobufMsg != "" {
					// Message decoded
				} else {
					// Connect Protocol 시도 (flags+len 프레임)
					if connectMsg := s.parseConnectProtocol(decompressedBody); connectMsg != "" {
						fmt.Printf("💬 Message: %s\n", connectMsg)
					} else {
						fmt.Printf("💬 Message: Raw protobuf data (manual parsing needed)\n")
					}
				}
			}

			fmt.Printf("═══════════════════════════════════════════════════════════════════\n\n")
		}
	}
}

func (s *Server) logOutboundRequest(req *http.Request, resp *http.Response, compressedBody, decompressedBody []byte, remoteAddr string) {
	// (MITM + 상세모드에서만 사용)
}

// 스트리밍 판별/로깅
func (s *Server) isStreamingResponse(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	transferEncoding := resp.Header.Get("Transfer-Encoding")

	if strings.Contains(contentType, "text/event-stream") {
		return true
	}
	if strings.Contains(transferEncoding, "chunked") && resp.ContentLength == -1 {
		return true
	}
	if strings.Contains(contentType, "application/x-ndjson") {
		return true
	}
	// BidiAppend 응답은 Content-Length가 0이어도 스트리밍일 수 있음
	if strings.Contains(contentType, "application/proto") && resp.ContentLength == 0 {
		return true
	}
	return false
}

func (s *Server) isStreamingRequest(req *http.Request) bool {
	url := req.URL.String()
	path := req.URL.Path
	if strings.Contains(path, "StreamUnifiedChatWithToolsSSE") {
		return true
	}
	if strings.Contains(path, "StreamSSE") {
		return true
	}
	if strings.Contains(url, "SSE") {
		return true
	}
	return false
}

func (s *Server) writeResponseHeaders(w io.Writer, resp *http.Response) error {
	// 항상 HTTP/1.1 사용
	proto := "HTTP/1.1"
	statusLine := fmt.Sprintf("%s %s\r\n", proto, resp.Status)
	if _, err := w.Write([]byte(statusLine)); err != nil {
		return err
	}
	if err := resp.Header.Write(w); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\r\n")); err != nil {
		return err
	}
	return nil
}

func (s *Server) logStreamingRequest(req *http.Request, resp *http.Response, remoteAddr string) {
	// (콘솔 한 줄 출력은 printFromReqResp가 담당)
}

// ------- 콘솔 출력 공통 헬퍼 -------

// Fiddler 스타일 단일 라인 출력
// ex) " 12  200  HTTPS  api2.cursor.sh          /aiserver.v1.Repository/..."
func (s *Server) printTxnLine(status int, scheme, host, path string) {
	// 필터링: 특정 패킷만 표시
	if !s.shouldLogPath(path) {
		return
	}

	id := atomic.AddUint64(&s.seq, 1)
	if path == "" {
		path = "/"
	}
	// 고정폭 정렬: 번호, 상태, 프로토콜, 호스트
	fmt.Printf("%3d  %3d  %-6s %-24s %s\n", id, status, scheme, host, path)
}

// CONNECT 터널 라인 출력
// ex) " 13  200  HTTP   Tunnel to  api2.cursor.sh:443"
func (s *Server) printTunnelLine(hostport string) {
	id := atomic.AddUint64(&s.seq, 1)
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	fmt.Printf("%3d  %3d  %-6s Tunnel to  %s:443\n", id, 200, "HTTP", host)
}

// 특정 패킷만 로깅할지 결정하는 함수
func (s *Server) shouldLogPath(path string) bool {
	// 모든 경로 로깅 (필터링 제거)
	return true
}

// 요청/응답에서 필드 뽑아 한 줄 출력
func (s *Server) printFromReqResp(req *http.Request, resp *http.Response) {
	// scheme
	scheme := "HTTP"
	if strings.EqualFold(req.URL.Scheme, "https") || req.TLS != nil {
		scheme = "HTTPS"
	}
	// host
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	// path + query
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	// status
	status := 0
	if resp != nil {
		status = resp.StatusCode
	} else {
		status = 200
	}

	s.printTxnLine(status, scheme, host, path)
}

func (s *Server) Start() error {
	handler := s.CreateHandler()
	server := &http.Server{
		Addr:    s.config.Port,
		Handler: handler,
		// 서버측 HTTP/2 비활성
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	protocolMsg := "HTTP/1.1 (forced)"
	fmt.Printf("HTTP/HTTPS Proxy server starting on %s (protocol: %s)\n", s.config.Port, protocolMsg)
	s.logMutex.Lock()
	_ = s.logger.WriteLine(map[string]any{
		"timestamp": time.Now().Format(time.RFC3339),
		"event":     "proxy_started",
		"port":      s.config.Port,
		"protocol":  protocolMsg,
	})
	s.logMutex.Unlock()

	return server.ListenAndServe()
}

func (s *Server) Close() error {
	if s.logFile != nil {
		return s.logFile.Close()
	}
	return nil
}

// isAIChatRequest AI 채팅 관련 요청인지 확인
// isMCPProxyRequest MCP Proxy 요청인지 확인
func (s *Server) isMCPProxyRequest(req *http.Request) bool {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// URL 경로 확인 (가장 확실한 방법)
	path := req.URL.Path
	if strings.Contains(path, "/stdio/") || strings.Contains(path, "/mcp/") || strings.Contains(path, "/sse/") {
		return true
	}

	// 호스트 패턴 확인
	return strings.Contains(host, "52.78.65.106") ||
		strings.Contains(host, ":8081") ||
		strings.Contains(host, "mcp-gateway") ||
		strings.Contains(host, "ip-172-31-1-245")
}

func (s *Server) isAIChatRequest(req *http.Request) bool {
	// MCP Proxy 요청은 제외 (직접 통과)
	if s.isMCPProxyRequest(req) {
		return false
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Cursor 서버 요청만 처리
	return strings.HasSuffix(host, "cursor.sh") ||
		strings.Contains(host, ".cursor.sh") ||
		strings.Contains(host, "api2.cursor.sh") ||
		strings.Contains(host, "api3.cursor.sh")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extractReadableStrings protobuf 바이너리에서 읽을 수 있는 문자열을 추출
func (s *Server) extractReadableStrings(protobufContent []byte) string {
	if len(protobufContent) == 0 {
		return ""
	}

	// "bidi_protobuf_*.txt" 파일 내용을 읽어서 "Field X, Wire Type 2: string: " 뒤의 문자열 추출
	content := string(protobufContent)

	// "Field X, Wire Type 2: string: " 패턴 찾기
	lines := strings.Split(content, "\n")
	var decodedStrings []string

	for _, line := range lines {
		// "Wire Type 2: string: " 뒤의 hex 문자열 추출
		idx := strings.Index(line, "Wire Type 2: string: ")
		if idx != -1 {
			hexStr := strings.TrimSpace(line[idx+len("Wire Type 2: string: "):])
			// 빈 문자열이면 건너뛰기
			if len(hexStr) == 0 {
				continue
			}

			// hex 문자열이면 디코딩 시도
			if decoded, err := hex.DecodeString(hexStr); err == nil && len(decoded) > 0 {
				// UTF-8로 디코딩 가능한지 확인
				if utf8.Valid(decoded) {
					str := string(decoded)
					// 모든 디코딩된 문자열 저장 (길이 제한 없음)
					decodedStrings = append(decodedStrings, fmt.Sprintf("=== String %d (length: %d) ===\n%s\n\n", len(decodedStrings)+1, len(str), str))
				}
			}
		}
	}

	return strings.Join(decodedStrings, "")
}

func (s *Server) extractHexStringsWithPython(protobufFile string) error {
	// 기본 출력 파일명 생성
	timestamp := time.Now().Format("20060102_150405")
	outputFile := fmt.Sprintf("./logs/bidi_decoded_%s.txt", timestamp)

	return s.extractHexStringsWithPythonToFile(protobufFile, outputFile)
}

func (s *Server) extractHexStringsWithPythonToFile(protobufFile, outputFile string) error {
	absIn, err := filepath.Abs(protobufFile)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	absOut, err := filepath.Abs(outputFile)
	if err != nil {
		return fmt.Errorf("failed to get absolute output path: %w", err)
	}

	// 출력 파일 경로는 이미 지정됨

	// 파이썬 스크립트는 문자열 그대로 전달하고, 경로는 argv로 넘깁니다.
	py := `
import re, sys, os
inp = sys.argv[1]
outp = sys.argv[2]

# 안전하게 읽기 (초대형 파일 대비)
with open(inp, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

def uniq(seq):
    seen = set(); out = []
    for x in seq:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

cands = []
# 1) 수동 파서 포맷: fieldX(2):string(36):<hex> 또는 fieldX(2):string:<hex>
cands += re.findall(r'field\d+\(2\):string(?:\(\d+\))?:(0x[0-9a-fA-F]+|[0-9a-fA-F]+)', content)
# 2) 기존 포맷: Field X, Wire Type 2: string: <hex>
cands += re.findall(r'Field \d+, Wire Type 2: string: (0x[0-9a-fA-F]+|[0-9a-fA-F]+)', content, flags=re.IGNORECASE)
# 3) JSON 안의 0x... 형식
cands += re.findall(r'"0x([0-9a-fA-F]+)"', content)
# 4) 보험: 매우 긴 순수 hex 런
cands += re.findall(r'\b[0-9a-fA-F]{40,}\b', content)

norm = []
for h in cands:
    if isinstance(h, tuple):
        h = h[0]
    h = h.strip()
    if h.startswith(('0x','0X')):
        h = h[2:]
    if len(h) % 2 == 1:  # 홀수 길이는 앞에 0 패딩
        h = '0' + h
    if re.fullmatch(r'[0-9a-fA-F]{2,}', h):
        norm.append(h)

norm = uniq(norm)

decoded_blocks = []
for i, h in enumerate(norm, 1):
    try:
        raw = bytes.fromhex(h)
        txt = raw.decode('utf-8', errors='ignore')
        # 너무 짧은 잡음은 제외하되, 더 관대한 기준 적용 (전체 내용 확인을 위해)
        if len(txt.strip()) < 4 and len(raw) < 32:
            continue
        decoded_blocks.append(f'=== Candidate {i} (hexLen: {len(h)}, bytes: {len(raw)}) ===\n{txt}\n\n')
    except Exception:
        pass

os.makedirs(os.path.dirname(outp), exist_ok=True)
with open(outp, 'w', encoding='utf-8') as f:
    if decoded_blocks:
        f.write(''.join(decoded_blocks))
    else:
        f.write('# No decodable strings found.\n')

# Logging removed
`

	cmd := exec.Command("python3", "-c", py, absIn, absOut)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("python execution failed: %w", err)
	}
	return nil
}

// findJSONEnd는 JSON 문자열의 끝 위치를 찾습니다 (중괄호 균형을 맞춰서)
func (s *Server) findJSONEnd(jsonStr string) int {
	braceCount := 0
	inString := false
	escapeNext := false

	for i, char := range jsonStr {
		if escapeNext {
			escapeNext = false
			continue
		}

		if char == '\\' {
			escapeNext = true
			continue
		}

		if char == '"' && !escapeNext {
			inString = !inString
			continue
		}

		if !inString {
			if char == '{' {
				braceCount++
			} else if char == '}' {
				braceCount--
				if braceCount == 0 {
					return i + 1
				}
			}
		}
	}

	return -1 // JSON이 완전하지 않음
}

// prettyFormatJSON - JSON을 예쁘게 포맷팅하는 함수
func (s *Server) prettyFormatJSON(jsonStr string) string {
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonObj); err != nil {
		// JSON 파싱 실패시 원본 반환
		return jsonStr
	}

	prettyBytes, err := json.MarshalIndent(jsonObj, "", "  ")
	if err != nil {
		// 포맷팅 실패시 원본 반환
		return jsonStr
	}

	return string(prettyBytes)
}

// processTextMasking - 비활성화됨 (masker.go에서 처리)
func (s *Server) processTextMasking(decodedFile, timestamp string) {
	// 한글 마스킹은 masker.go에서 처리하므로 비활성화
}

// processBidiAppendRequestWithMasking - BidiAppend 요청을 처리하고 마스킹된 body를 반환하는 함수
func (s *Server) processBidiAppendRequestWithMasking(reqBodyRaw []byte, req *http.Request) ([]byte, error) {
	// 새로운 BidiAppend 요청이므로 플래그 리셋
	s.bidiBodySaved = false

	clientIP := s.getClientIP(req)
	sseKey := fmt.Sprintf("%s_sse_started", clientIP)
	counterKey := fmt.Sprintf("%s_bidi_counter", clientIP)

	// 🔍 SSE 연결이 이미 시작되었는지 확인
	s.sseMu.RLock()
	sseStarted := s.sseConnectionsStarted[sseKey]
	s.sseMu.RUnlock()

	// 🔍 클라이언트별 BidiAppend 카운터 증가 (SSE 연결 여부와 관계없이)
	s.bidiAppendMu.Lock()
	counter := s.bidiAppendCounters[counterKey]
	counter++
	s.bidiAppendCounters[counterKey] = counter
	s.bidiAppendMu.Unlock()

	// 🔍 SSE 연결 후의 첫 번째 BidiAppend만 처리
	if sseStarted {
		if counter == 1 {
			// 계속 처리 진행
		} else {
			return reqBodyRaw, nil
		}
	} else {
		// SSE 연결 전의 첫 번째 BidiAppend만 처리
		if counter == 1 {
			// 계속 처리 진행
		} else {
			return reqBodyRaw, nil
		}
	}

	timestamp := time.Now().Format("20060102_150405")

	// 임시 파일들을 저장할 디렉토리 생성
	tempDir := fmt.Sprintf("./logs/temp_%s", timestamp)
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir) // 처리 완료 후 임시 디렉토리 삭제

	// 1단계: 원문 body 저장 (임시)
	tempRawFile := fmt.Sprintf("%s/raw.bin", tempDir)
	if err := os.WriteFile(tempRawFile, reqBodyRaw, 0644); err != nil {
		return nil, fmt.Errorf("failed to save raw body: %w", err)
	}

	// 2단계: Gzip 압축 해제
	reqBodyDecomp := s.decompressGzip(reqBodyRaw)
	isCompressed := len(reqBodyDecomp) > 0 && len(reqBodyDecomp) != len(reqBodyRaw)

	var decompressedData []byte
	if isCompressed {
		decompressedData = reqBodyDecomp
		// 압축 해제된 데이터 저장 (임시)
		tempDecompFile := fmt.Sprintf("%s/decomp.bin", tempDir)
		if err := os.WriteFile(tempDecompFile, decompressedData, 0644); err != nil {
			return nil, fmt.Errorf("failed to save decompressed data: %w", err)
		}
	} else {
		decompressedData = reqBodyRaw
	}

	// 3단계: Protobuf 디코딩 및 ToolCall 추출
	var toolName string
	protobufMsg := ""
	if len(decompressedData) > 0 {
		// 먼저 Protobuf 구조체로 직접 디코딩 시도 (도구 목록 및 ToolCall 추출용)
		toolName = s.extractToolNameFromProtobuf(decompressedData)

		// 요청에서 도구 목록 확인 (InitialRequest의 Tools 필드)
		s.checkToolsListInRequest(decompressedData, timestamp, req)

		// 로깅용 텍스트 디코딩
		protobufMsg = s.decodeProtobufMessage(decompressedData)
		if len(protobufMsg) == 0 {
			protobufMsg = s.decodeProtobufMessageManual(decompressedData)
		}
	}

	// Protobuf에서 추출 실패 시 hex 디코딩된 텍스트에서 추출 시도
	if toolName == "" && len(protobufMsg) > 0 {
		// 임시로 hex 디코딩하여 도구 이름 추출 시도
		tempProtobufFile := fmt.Sprintf("%s/protobuf.txt", tempDir)
		if err := os.WriteFile(tempProtobufFile, []byte(protobufMsg), 0644); err == nil {
			finalLogFile := fmt.Sprintf("./logs/bidi_decoded_%s.txt", timestamp)
			_ = s.extractHexStringsWithPythonToFile(tempProtobufFile, finalLogFile)

			if decodedContent, err := os.ReadFile(finalLogFile); err == nil {
				decodedText := string(decodedContent)

				// 응답 패턴 확인 ({"error":"..."}가 있으면 응답이므로 스킵)
				if strings.Contains(decodedText, `{"error"`) {
					// 응답 패킷인 경우 스킵
				} else {
					// 요청 패킷인 경우에만 도구 이름 추출 시도
					toolName = s.extractToolName(decodedText)
				}
			}
		}
	}

	// 🔍 3-1단계: MCP 도구 호출 감지 및 도구 이름 추출 로그 저장
	if toolName != "" {
		// 도구 이름 추출 로그 저장 제거 (SSE 실시간 추출로 대체)
		// tool_extraction_*.txt 파일은 더 이상 생성하지 않음

		// 4,5,6 과정: 권한 확인 및 차단 (주석처리 - 테스트용)
		/*
			allowed, err := s.checkToolPermission(clientIP, toolName)
			if err != nil {
				// 권한 확인 실패 시 기본적으로 허용 (에러 로그만)
				fmt.Printf("⚠️ Failed to check tool permission for %s: %v\n", toolName, err)
			} else if !allowed {
				// 권한이 없으면 요청 차단 (커서 서버로 전달하지 않음)
				fmt.Printf("🚫 Tool access denied: IP=%s, Tool=%s - Request blocked\n", clientIP, toolName)
				return nil, fmt.Errorf("tool access denied: IP=%s, Tool=%s", clientIP, toolName)
			} else {
				fmt.Printf("✅ Tool access allowed: IP=%s, Tool=%s\n", clientIP, toolName)
			}
		*/
	}

	if len(protobufMsg) > 0 {
		// 🔍 빠른 프롬프트 체크: Protobuf 메시지에서 간단한 패턴으로 사용자 프롬프트 존재 여부 확인
		// Hex 디코딩 전에 먼저 체크하여 불필요한 처리 방지
		// Protobuf 메시지에 사용자 입력을 나타내는 패턴이 있는지 확인
		// {"root":{"children":[...]}} 패턴이나 일반적인 한글/영문 텍스트 패턴 확인
		mightHaveUserPrompt := strings.Contains(protobufMsg, `{"root"`) ||
			strings.Contains(protobufMsg, `"text"`) ||
			s.isPrintableString([]byte(protobufMsg))

		// 사용자 프롬프트가 있을 가능성이 없는 경우 Hex 디코딩 스킵 (부하 감소)
		if !mightHaveUserPrompt {
			return reqBodyRaw, nil
		}

		// 사용자 프롬프트가 있을 가능성이 있는 경우에만 Hex 디코딩 및 DLP 처리 진행
		// Protobuf 디코딩된 데이터 저장 (임시)
		tempProtobufFile := fmt.Sprintf("%s/protobuf.txt", tempDir)
		if err := os.WriteFile(tempProtobufFile, []byte(protobufMsg), 0644); err != nil {
			return nil, fmt.Errorf("failed to save protobuf data: %w", err)
		}

		// 원본 protobuf 디코딩 결과를 logs 디렉토리에 저장
		protobufLogFile := fmt.Sprintf("./logs/bidi_protobuf_%s.txt", timestamp)
		if err := os.WriteFile(protobufLogFile, []byte(protobufMsg), 0644); err != nil {
			// 실패해도 계속 진행
		}

		// 4단계: Hex 디코딩 (Python 스크립트 사용) - 최종 로그만 저장
		finalLogFile := fmt.Sprintf("./logs/bidi_decoded_%s.txt", timestamp)
		_ = s.extractHexStringsWithPythonToFile(tempProtobufFile, finalLogFile)

		// 🔍 4-1단계: decoded 파일 읽기
		decodedContent, err := os.ReadFile(finalLogFile)
		if err != nil {
			return reqBodyRaw, nil
		}
		decodedText := string(decodedContent)

		// 🔍 4-3단계: 최초 사용자 입력 BidiAppend인지 확인
		// JSON 구조를 분석하여 실제 사용자가 엔터를 눌러 입력한 텍스트가 있는지 확인
		isInitialUserInput := s.isInitialUserInputBidiAppend(decodedText, protobufMsg)

		if !isInitialUserInput {
			// 최초 사용자 입력이 아니면 DLP 처리 스킵
			return reqBodyRaw, nil
		}

		// 사용자 프롬프트 추출
		userPrompt := s.extractUserPrompt(decodedText)
		if userPrompt == "" {
			// 프롬프트 추출 실패시 스킵
			return reqBodyRaw, nil
		}

		previewLen := 50
		if len(userPrompt) < previewLen {
			previewLen = len(userPrompt)
		}

		// 사용자 프롬프트가 있는 경우에만 DLP 처리 수행
		// 5단계: 평문에서 이름 마스킹 처리
		s.processTextMasking(finalLogFile, timestamp)

		// 6단계: 마스킹된 내용을 원본 요청에 적용
		// clientIP 추출 (실제 요청 클라이언트 IP)
		clientIP := s.getClientIP(req)
		modifiedBody, err := s.applyMaskingToRequest(reqBodyRaw, finalLogFile, timestamp, clientIP)
		if err != nil {
			// 마스킹 실패시 원본 사용
			return reqBodyRaw, nil
		}

		// 최신 프롬프트 JSON 추출 및 저장
		success, _ := s.extractLatestPromptJSON(finalLogFile, timestamp)
		if !success {
			// JSON 패턴이 없어도 decoded 파일은 유지 (로그 목적)
		}

		// 최초 프롬프트 처리 완료
		// 카운터는 이미 위에서 증가했으므로 이후 BidiAppend는 스킵됨

		return modifiedBody, nil
	}

	// Protobuf 디코딩 실패시 원본 반환
	return reqBodyRaw, nil
}

// processBidiAppendResponse - BidiAppend 응답을 처리하여 도구 선택 정보 확인
func (s *Server) processBidiAppendResponse(respBodyRaw []byte, respBodyDecomp []byte, req *http.Request) {
	timestamp := time.Now().Format("20060102_150405")

	// 응답 형식 분석
	respFormatLog := fmt.Sprintf("./logs/bidi_response_format_%s.txt", timestamp)
	formatInfo := fmt.Sprintf("=== BidiAppend Response Format Analysis ===\n")
	formatInfo += fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	formatInfo += fmt.Sprintf("Raw Body Size: %d bytes\n", len(respBodyRaw))
	formatInfo += fmt.Sprintf("Decompressed Size: %d bytes\n", len(respBodyDecomp))

	// Connect Protocol 체크 (5바이트 헤더: 1바이트 flags + 4바이트 length)
	if len(respBodyRaw) >= 5 {
		flags := respBodyRaw[0]
		msgLen := int(binary.BigEndian.Uint32(respBodyRaw[1:5]))
		formatInfo += fmt.Sprintf("\n--- Connect Protocol Check ---\n")
		formatInfo += fmt.Sprintf("First byte (flags): 0x%02x\n", flags)
		formatInfo += fmt.Sprintf("Message length (bytes 1-4): %d\n", msgLen)
		formatInfo += fmt.Sprintf("Total frame size: %d bytes\n", 5+msgLen)
		if len(respBodyRaw) >= 5+msgLen {
			formatInfo += fmt.Sprintf("✅ Matches Connect Protocol format\n")
			// Connect Protocol 페이로드 추출
			if msgLen > 0 && msgLen < len(respBodyRaw)-5 {
				connectPayload := respBodyRaw[5 : 5+msgLen]
				// Connect 페이로드를 Protobuf로 디코딩 시도
				var response cursor_grpc.StreamUnifiedChatWithToolsResponse
				if err := proto.Unmarshal(connectPayload, &response); err == nil {
					formatInfo += fmt.Sprintf("✅ Connect payload is valid Protobuf\n")
					if response.Part != nil {
						switch content := response.Part.Content.(type) {
						case *cursor_grpc.ResponsePart_ToolCall:
							if content.ToolCall != nil {
								formatInfo += fmt.Sprintf("✅ Found ToolCall: %s\n", content.ToolCall.ToolName)
							}
						}
					}
				} else {
					formatInfo += fmt.Sprintf("❌ Connect payload is NOT valid Protobuf: %v\n", err)
				}
			}
		} else {
			formatInfo += fmt.Sprintf("❌ Not Connect Protocol (frame incomplete)\n")
		}
	}

	// 일반 Protobuf 체크 (Connect 헤더 없이 바로 Protobuf)
	var response cursor_grpc.StreamUnifiedChatWithToolsResponse
	if err := proto.Unmarshal(respBodyRaw, &response); err == nil {
		formatInfo += fmt.Sprintf("\n--- Direct Protobuf Check ---\n")
		formatInfo += fmt.Sprintf("✅ Raw body is valid Protobuf (StreamUnifiedChatWithToolsResponse)\n")
		if response.Part != nil {
			switch content := response.Part.Content.(type) {
			case *cursor_grpc.ResponsePart_ToolCall:
				if content.ToolCall != nil {
					formatInfo += fmt.Sprintf("✅ Found ToolCall: %s\n", content.ToolCall.ToolName)
				}
			}
		}
	} else {
		formatInfo += fmt.Sprintf("\n--- Direct Protobuf Check ---\n")
		formatInfo += fmt.Sprintf("❌ Raw body is NOT valid Protobuf: %v\n", err)
	}

	formatInfo += fmt.Sprintf("\n=== End of Analysis ===\n")
	_ = os.WriteFile(respFormatLog, []byte(formatInfo), 0644)
	fmt.Printf("📋 Response format analysis saved to %s\n", respFormatLog)

	// 응답 body 저장
	respLogFile := fmt.Sprintf("./logs/bidi_response_%s.bin", timestamp)
	_ = os.WriteFile(respLogFile, respBodyRaw, 0644)

	// 압축 해제된 응답 처리
	var decompressedData []byte
	if len(respBodyDecomp) > 0 && len(respBodyDecomp) != len(respBodyRaw) {
		decompressedData = respBodyDecomp
	} else {
		decompressedData = respBodyRaw
	}

	// Connect Protocol 처리 (5바이트 헤더가 있는 경우)
	var protobufPayload []byte
	if len(decompressedData) >= 5 {
		flags := decompressedData[0]
		msgLen := int(binary.BigEndian.Uint32(decompressedData[1:5]))
		if msgLen > 0 && msgLen <= len(decompressedData)-5 {
			// Connect Protocol 프레임에서 페이로드 추출
			protobufPayload = decompressedData[5 : 5+msgLen]
			fmt.Printf("🔍 Detected Connect Protocol: flags=0x%02x, payload_len=%d\n", flags, msgLen)
		} else {
			// Connect Protocol이 아니거나 불완전한 경우, 전체를 Protobuf로 시도
			protobufPayload = decompressedData
		}
	} else {
		// 5바이트 미만이면 바로 Protobuf로 시도
		protobufPayload = decompressedData
	}

	// Protobuf 디코딩
	protobufMsg := ""
	if len(protobufPayload) > 0 {
		protobufMsg = s.decodeProtobufMessage(protobufPayload)
		if len(protobufMsg) == 0 {
			protobufMsg = s.decodeProtobufMessageManual(protobufPayload)
		}
	}

	// Protobuf 디코딩 결과 저장
	if len(protobufMsg) > 0 {
		protobufRespFile := fmt.Sprintf("./logs/bidi_response_protobuf_%s.txt", timestamp)
		_ = os.WriteFile(protobufRespFile, []byte(protobufMsg), 0644)

		// Hex 디코딩
		tempProtobufFile := fmt.Sprintf("./logs/temp_resp_%s/protobuf.txt", timestamp)
		os.MkdirAll(filepath.Dir(tempProtobufFile), 0755)
		if err := os.WriteFile(tempProtobufFile, []byte(protobufMsg), 0644); err == nil {
			finalRespLogFile := fmt.Sprintf("./logs/bidi_response_decoded_%s.txt", timestamp)
			_ = s.extractHexStringsWithPythonToFile(tempProtobufFile, finalRespLogFile)
			os.RemoveAll(filepath.Dir(tempProtobufFile))

			// 응답에서 도구 선택 정보 확인
			if decodedContent, err := os.ReadFile(finalRespLogFile); err == nil {
				decodedText := string(decodedContent)

				// Response에서 ToolCall 찾기 (Connect Protocol 페이로드 또는 직접 Protobuf)
				var response cursor_grpc.StreamUnifiedChatWithToolsResponse
				if err := proto.Unmarshal(protobufPayload, &response); err == nil {
					if response.Part != nil {
						switch content := response.Part.Content.(type) {
						case *cursor_grpc.ResponsePart_ToolCall:
							if content.ToolCall != nil && content.ToolCall.ToolName != "" {
								toolName := content.ToolCall.ToolName
								clientIP := s.getClientIP(req)

								// 응답에서 도구 이름 추출 로그 저장
								respToolLogFile := fmt.Sprintf("./logs/tool_extraction_response_%s.txt", timestamp)
								logContent := fmt.Sprintf("=== Tool Name Extraction from Response ===\n")
								logContent += fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
								logContent += fmt.Sprintf("Client IP: %s\n", clientIP)
								logContent += fmt.Sprintf("Tool Name: %s\n", toolName)
								logContent += fmt.Sprintf("Tool Call ID: %s\n", content.ToolCall.ToolCallId)
								logContent += fmt.Sprintf("Extraction Method: Protobuf Response Parsing\n")
								logContent += fmt.Sprintf("\n=== End of Log ===\n")

								_ = os.WriteFile(respToolLogFile, []byte(logContent), 0644)
								fmt.Printf("📝 Tool name from response: %s (saved to %s)\n", toolName, respToolLogFile)
							}
						}
					}
				}

				// Hex 디코딩된 텍스트에서도 확인
				if strings.Contains(decodedText, "tool_") && !strings.Contains(decodedText, `{"error"`) {
					toolName := s.extractToolName(decodedText)
					if toolName != "" {
						clientIP := s.getClientIP(req)

						respToolLogFile := fmt.Sprintf("./logs/tool_extraction_response_%s.txt", timestamp)
						logContent := fmt.Sprintf("=== Tool Name Extraction from Response (Fallback) ===\n")
						logContent += fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
						logContent += fmt.Sprintf("Client IP: %s\n", clientIP)
						logContent += fmt.Sprintf("Tool Name: %s\n", toolName)
						logContent += fmt.Sprintf("Extraction Method: Hex Decoded Text Parsing\n")
						logContent += fmt.Sprintf("\n=== End of Log ===\n")

						_ = os.WriteFile(respToolLogFile, []byte(logContent), 0644)
						fmt.Printf("📝 Tool name from response (fallback): %s (saved to %s)\n", toolName, respToolLogFile)
					}
				}
			}
		}
	}

	// 응답에서는 요청의 도구 목록을 확인할 필요 없음 (이미 요청 처리에서 확인됨)
}

// checkToolsListInRequest - 요청 패킷에서 도구 목록 확인
func (s *Server) checkToolsListInRequest(data []byte, timestamp string, req *http.Request) {
	var request cursor_grpc.StreamUnifiedChatWithToolsRequest
	if err := proto.Unmarshal(data, &request); err == nil {
		switch payload := request.RequestPayload.(type) {
		case *cursor_grpc.StreamUnifiedChatWithToolsRequest_InitialRequest:
			if payload.InitialRequest != nil && len(payload.InitialRequest.Tools) > 0 {
				clientIP := s.getClientIP(req)
				toolsLogFile := fmt.Sprintf("./logs/tools_list_%s.txt", timestamp)
				logContent := fmt.Sprintf("=== Available Tools List (from Request) ===\n")
				logContent += fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
				logContent += fmt.Sprintf("Client IP: %s\n", clientIP)
				logContent += fmt.Sprintf("Total Tools: %d\n\n", len(payload.InitialRequest.Tools))

				for i, tool := range payload.InitialRequest.Tools {
					if tool != nil {
						logContent += fmt.Sprintf("Tool %d:\n", i+1)
						logContent += fmt.Sprintf("  Name: %s\n", tool.Name)
						logContent += fmt.Sprintf("  Description: %s\n", tool.Description)
						if tool.InputSchema != nil {
							logContent += fmt.Sprintf("  Input Schema: %v\n", tool.InputSchema)
						}
						logContent += fmt.Sprintf("\n")
					}
				}
				logContent += fmt.Sprintf("=== End of Log ===\n")

				_ = os.WriteFile(toolsLogFile, []byte(logContent), 0644)
				fmt.Printf("📋 Found %d available tools in request (saved to %s)\n", len(payload.InitialRequest.Tools), toolsLogFile)
			}
		}
	}
}

// processBidiAppendStreamingResponseData - BidiAppend 스트리밍 응답 데이터 처리
func (s *Server) processBidiAppendStreamingResponseData(data []byte, req *http.Request) {
	timestamp := time.Now().Format("20060102_150405")

	fmt.Printf("📥 Processing BidiAppend streaming response: %d bytes\n", len(data))

	streamLogFile := fmt.Sprintf("./logs/bidi_response_streaming_%s.bin", timestamp)
	_ = os.WriteFile(streamLogFile, data, 0644)
	fmt.Printf("📦 Streaming response saved to %s (%d bytes)\n", streamLogFile, len(data))

	// processBidiAppendResponse와 동일한 로직 사용
	respBodyDecomp := s.decompressGzip(data)
	s.processBidiAppendResponse(data, respBodyDecomp, req)

	// 압축 해제 시도
	decompressedData := s.decompressGzip(data)
	if len(decompressedData) == len(data) {
		decompressedData = data
	}

	// Protobuf 디코딩 시도
	var response cursor_grpc.StreamUnifiedChatWithToolsResponse
	if err := proto.Unmarshal(decompressedData, &response); err == nil {
		if response.Part != nil {
			switch content := response.Part.Content.(type) {
			case *cursor_grpc.ResponsePart_ToolCall:
				if content.ToolCall != nil && content.ToolCall.ToolName != "" {
					toolName := content.ToolCall.ToolName
					clientIP := s.getClientIP(req)

					respToolLogFile := fmt.Sprintf("./logs/tool_extraction_response_streaming_%s.txt", timestamp)
					logContent := fmt.Sprintf("=== Tool Name from Streaming Response ===\n")
					logContent += fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
					logContent += fmt.Sprintf("Client IP: %s\n", clientIP)
					logContent += fmt.Sprintf("Tool Name: %s\n", toolName)
					logContent += fmt.Sprintf("Tool Call ID: %s\n", content.ToolCall.ToolCallId)
					logContent += fmt.Sprintf("Extraction Method: Streaming Protobuf Parsing\n")
					logContent += fmt.Sprintf("Response Size: %d bytes\n", len(data))
					logContent += fmt.Sprintf("\n=== End of Log ===\n")

					_ = os.WriteFile(respToolLogFile, []byte(logContent), 0644)
					fmt.Printf("📝 Tool name from streaming response: %s (saved to %s)\n", toolName, respToolLogFile)
				}
			}
		}
	} else {
		// Protobuf 디코딩 실패 시 텍스트로 저장
		textLogFile := fmt.Sprintf("./logs/bidi_response_streaming_text_%s.txt", timestamp)
		_ = os.WriteFile(textLogFile, decompressedData, 0644)
		fmt.Printf("⚠️ Streaming response Protobuf decode failed, saved as text to %s\n", textLogFile)
	}
}

// extractToolNameFromSSEChunk - SSE 청크에서 실시간으로 도구 이름 추출
// LLM이 선택한 도구 이름을 텍스트 패턴 매칭과 Protobuf 메시지에서 추출
func (s *Server) extractToolNameFromSSEChunk(data []byte, req *http.Request) string {
	if len(data) == 0 {
		return ""
	}

	// 1단계: 텍스트에서 직접 도구 이름 패턴 추출
	// mcpR 다음에 나오는 실제 도구 이름 (예: list_issues, search_repositories)
	// 이 이름이 DB에 저장되는 이름과 일치해야 함
	text := string(data)

	// 패턴 1: mcpR 다음에 JSON 파라미터가 오고, 그 다음에 실제 도구 이름이 나옴
	// mcpR<, mcpR!, mcpRA 등 다양한 형식 지원
	// Hex를 보면: mcpR + (<|!|A 등) + JSON + 제어문자들 + \x0a (10) + 도구이름 + \x12 (18) + 도구설명
	// 예: "mcpR<{"owner":...}...\x0alist_issues\x12..." 또는 "mcpRA{"owner":...}...\x0aget_file_contents\x12..."
	// 바이너리 데이터에서 직접 패턴 매칭
	mcpRIndex := bytes.Index(data, []byte("mcpR"))
	if mcpRIndex >= 0 {
		// mcpR 이후 데이터에서 찾기 (mcpR + 1바이트(<|!|A 등) + JSON)
		afterMcpR := data[mcpRIndex+4:]

		// JSON 시작 찾기 ({ 문자) - mcpR 다음에 <, !, A 등이 올 수 있음
		jsonStart := bytes.IndexByte(afterMcpR, '{')
		if jsonStart >= 0 {
			// JSON 시작부터 찾기
			jsonData := afterMcpR[jsonStart:]

			// JSON 끝 찾기 (} 문자) - 중첩된 JSON도 고려
			braceCount := 0
			jsonEnd := -1
			for i, b := range jsonData {
				if b == '{' {
					braceCount++
				} else if b == '}' {
					braceCount--
					if braceCount == 0 {
						jsonEnd = i
						break
					}
				}
			}

			if jsonEnd >= 0 {
				// JSON 이후 데이터에서 도구 이름 찾기
				afterJson := jsonData[jsonEnd+1:]

				// \x0a (10) 다음에 나오는 도구 이름 찾기
				newlineIndex := bytes.IndexByte(afterJson, 0x0a)
				if newlineIndex >= 0 {
					// \x0a 다음에 나오는 텍스트 찾기
					afterNewline := afterJson[newlineIndex+1:]

					// 도구 이름 패턴 찾기 (대소문자, 언더스코어, 하이픈 포함, 3-50자)
					// 예: list_issues, API-update-a-database, get_file_contents 등
					toolNamePattern := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_-]{2,49})`)
					matches := toolNamePattern.FindSubmatch(afterNewline)
					if len(matches) > 1 {
						toolName := string(matches[1])
						// 유효한 도구 이름인지 확인 (일반적인 도구 이름 패턴)
						// mcp_notion_ 또는 mcp_github_ 접두사가 있으면 제거
						if strings.HasPrefix(toolName, "mcp_notion_") {
							toolName = strings.TrimPrefix(toolName, "mcp_notion_")
						} else if strings.HasPrefix(toolName, "mcp_github_") {
							toolName = strings.TrimPrefix(toolName, "mcp_github_")
						}

						// 유효한 도구 이름 패턴 확인
						isValid := strings.Contains(toolName, "_") || strings.Contains(toolName, "-") ||
							strings.HasPrefix(toolName, "list_") || strings.HasPrefix(toolName, "search_") ||
							strings.HasPrefix(toolName, "create_") || strings.HasPrefix(toolName, "get_") ||
							strings.HasPrefix(toolName, "update_") || strings.HasPrefix(toolName, "delete_") ||
							strings.HasPrefix(toolName, "read_") || strings.HasPrefix(toolName, "write_") ||
							strings.HasPrefix(toolName, "API-")

						if isValid {
							clientIP := s.getClientIP(req)
							timestamp := time.Now().Format("20060102_150405")
							sseToolLogFile := fmt.Sprintf("./logs/tool_extraction_sse_realtime_%s.txt", timestamp)
							logContent := fmt.Sprintf("=== Tool Name from SSE Response (mcpR Pattern) ===\n")
							logContent += fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
							logContent += fmt.Sprintf("Client IP: %s\n", clientIP)
							logContent += fmt.Sprintf("Tool Name: %s\n", toolName)
							logContent += fmt.Sprintf("Extraction Method: SSE Binary Pattern Matching (mcpR + JSON + \\x0a + tool name)\n")
							logContent += fmt.Sprintf("Chunk Size: %d bytes\n", len(data))
							logContent += fmt.Sprintf("mcpR Position: %d\n", mcpRIndex)
							logContent += fmt.Sprintf("\n=== End of Log ===\n")

							_ = os.WriteFile(sseToolLogFile, []byte(logContent), 0644)
							return toolName
						}
					}
				}
			}
		}
	}

	// 패턴 2: tool_xxx 다음에 오는 도구 이름 (더 정확한 패턴)
	// 예: "tool_73cbf9dd-9825-47aa-b573-4703a927b69" 다음에 "mcp_github_list_issues" 또는 "mcp_notion_API-update-a-database"가 옴
	// Hex에서 보면: tool_xxx + 0x1a (26) + 길이 + "mcp_github_list_issues" 또는 "mcp_notion_API-update-a-database"
	toolIdWithNamePattern := regexp.MustCompile(`tool_[a-f0-9-]+[^\x00-\x1f]*(mcp_(?:github|notion)_[A-Za-z0-9_-]+)`)
	matches := toolIdWithNamePattern.FindStringSubmatch(text)
	if len(matches) > 1 {
		// 전체 도구 이름 (mcp_github_xxx 또는 mcp_notion_xxx)
		fullToolName := matches[1]
		// 제어 문자나 공백에서 자르기
		for i, r := range fullToolName {
			if r < 32 || r == ' ' || r == '\n' || r == '\r' {
				fullToolName = fullToolName[:i]
				break
			}
		}
		if len(fullToolName) > 10 { // "mcp_github_" 또는 "mcp_notion_"는 최소 11자
			// mcp_ 접두사 제거하여 실제 도구 이름만 추출
			toolName := fullToolName
			if strings.HasPrefix(toolName, "mcp_notion_") {
				toolName = strings.TrimPrefix(toolName, "mcp_notion_")
			} else if strings.HasPrefix(toolName, "mcp_github_") {
				toolName = strings.TrimPrefix(toolName, "mcp_github_")
			}

			clientIP := s.getClientIP(req)
			timestamp := time.Now().Format("20060102_150405")
			sseToolLogFile := fmt.Sprintf("./logs/tool_extraction_sse_realtime_%s.txt", timestamp)
			logContent := fmt.Sprintf("=== Tool Name from SSE Response (TEXT PATTERN) ===\n")
			logContent += fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
			logContent += fmt.Sprintf("Client IP: %s\n", clientIP)
			logContent += fmt.Sprintf("Tool Name: %s (extracted from: %s)\n", toolName, fullToolName)
			logContent += fmt.Sprintf("Extraction Method: SSE Text Pattern Matching (tool_* + mcp_github_* or mcp_notion_*)\n")
			logContent += fmt.Sprintf("Chunk Size: %d bytes\n", len(data))
			logContent += fmt.Sprintf("\n=== End of Log ===\n")

			_ = os.WriteFile(sseToolLogFile, []byte(logContent), 0644)
			return toolName
		}
	}

	// 2단계: Protobuf 메시지에서 추출 시도 (fallback)
	// Connect Protocol 체크 (5바이트 헤더: flags + length)
	if len(data) >= 5 {
		msgLen := int(binary.BigEndian.Uint32(data[1:5]))
		if msgLen > 0 && msgLen <= len(data)-5 {
			payload := data[5 : 5+msgLen]
			if toolName := s.extractToolNameFromProtobufMessage(payload, req, len(data)); toolName != "" {
				return toolName
			}
		}
	}

	// 직접 Protobuf 디코딩 시도
	if toolName := s.extractToolNameFromProtobufMessage(data, req, len(data)); toolName != "" {
		return toolName
	}

	return ""
}

// extractToolNameFromProtobufMessage - Protobuf 메시지에서 도구 이름 추출
// LLM이 선택한 도구 이름을 StreamUnifiedChatWithToolsResponse.Part.ToolCall.ToolName에서 추출
func (s *Server) extractToolNameFromProtobufMessage(data []byte, req *http.Request, chunkSize int) string {
	if len(data) == 0 {
		return ""
	}

	// StreamUnifiedChatWithToolsResponse로 디코딩 시도
	var response cursor_grpc.StreamUnifiedChatWithToolsResponse
	if err := proto.Unmarshal(data, &response); err == nil {
		if response.Part != nil {
			// GetToolCall() 메서드를 사용하여 안전하게 ToolCall 추출
			if toolCall := response.Part.GetToolCall(); toolCall != nil {
				if toolCall.ToolName != "" {
					toolName := toolCall.ToolName
					clientIP := s.getClientIP(req)
					timestamp := time.Now().Format("20060102_150405")

					sseToolLogFile := fmt.Sprintf("./logs/tool_extraction_sse_realtime_%s.txt", timestamp)
					logContent := fmt.Sprintf("=== Tool Name from SSE Response (REAL-TIME) ===\n")
					logContent += fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
					logContent += fmt.Sprintf("Client IP: %s\n", clientIP)
					logContent += fmt.Sprintf("Tool Name: %s\n", toolName)
					logContent += fmt.Sprintf("Tool Call ID: %s\n", toolCall.ToolCallId)
					logContent += fmt.Sprintf("Extraction Method: Real-time SSE Protobuf Parsing\n")
					logContent += fmt.Sprintf("Chunk Size: %d bytes\n", chunkSize)
					logContent += fmt.Sprintf("Protobuf Size: %d bytes\n", len(data))
					logContent += fmt.Sprintf("\n=== End of Log ===\n")

					_ = os.WriteFile(sseToolLogFile, []byte(logContent), 0644)
					return toolName
				}
			}

			// Content 타입 확인 (디버깅용 - ToolCall이 아닌 경우)
			if response.Part.Content != nil {
				switch response.Part.Content.(type) {
				case *cursor_grpc.ResponsePart_MessagePart:
					// MessagePart는 일반 텍스트 응답
				case *cursor_grpc.ResponsePart_BubbleId:
					// BubbleId는 청크 ID
				case *cursor_grpc.ResponsePart_MetadataMarker:
					// MetadataMarker는 메타데이터
				case *cursor_grpc.ResponsePart_FinalResponse:
					// FinalResponse는 최종 응답
				case *cursor_grpc.ResponsePart_ErrorDetails:
					// ErrorDetails는 에러 정보
				}
			}
		}
	}

	return ""
}

// processSSEResponse - 제거됨 (실시간 추출로 대체)
// 이 함수는 더 이상 사용되지 않으며, extractToolNameFromSSEChunk로 대체됨

// ProtobufField - Protobuf field 정보를 저장하는 구조체
type ProtobufField struct {
	Number   int
	WireType int
	Data     []byte
	Offset   int
	Length   int
}

// applyMaskingToRequest - 마스킹된 내용을 원본 요청에 적용하는 함수
func (s *Server) applyMaskingToRequest(originalBody []byte, decodedFile, timestamp string, clientIP string) ([]byte, error) {
	// 1. 압축 여부 확인
	isCompressed := len(originalBody) >= 10 && originalBody[0] == 0x1f && originalBody[1] == 0x8b
	// 2. 압축 해제
	var decompressedData []byte
	if isCompressed {
		decompressedData = s.decompressGzip(originalBody)
	} else {
		decompressedData = originalBody
	}

	// 3. Protobuf 안의 hex 인코딩된 텍스트를 찾아서 디코딩 → 마스킹 → 인코딩
	// Protobuf 데이터를 순회하면서 hex 인코딩된 텍스트 필드를 찾아 마스킹
	maskedData, masked := s.maskHexEncodedTextInProtobuf(decompressedData, clientIP)

	if masked {
		// 마스킹된 데이터를 다시 압축
		var finalBody []byte
		if isCompressed {
			finalBody = s.compressGzip(maskedData)
		} else {
			finalBody = maskedData
		}

		return finalBody, nil
	} else {
		return originalBody, nil
	}
}

// maskHexEncodedTextInProtobuf - Protobuf 안의 hex 인코딩된 텍스트를 마스킹
func (s *Server) maskHexEncodedTextInProtobuf(data []byte, clientIP string) ([]byte, bool) {
	dataStr := string(data)
	originalStr := dataStr

	// DLP 로그를 저장할 슬라이스
	var dlpDetections []struct {
		original string
		masked   string
		category string
		level    core.ConfidenceLevel // severity 결정을 위한 level 정보
	}

	// hex 인코딩된 텍스트를 찾는 범용 패턴 (최소 8바이트 이상의 hex 문자열)
	// 영문, 숫자, 한글, 특수문자가 포함된 텍스트를 찾음
	hexPattern := regexp.MustCompile(`[0-9a-f]{16,}`)

	dataStr = hexPattern.ReplaceAllStringFunc(dataStr, func(match string) string {
		// 길이가 홀수면 스킵
		if len(match)%2 != 0 {
			return match
		}

		// hex 디코딩 시도
		decodedHex, err := hex.DecodeString(match)
		if err != nil {
			return match
		}

		decodedText := string(decodedHex)

		// 출력 가능한 텍스트인지 확인 (영문, 숫자, 한글, 일반 특수문자)
		if !s.isPrintableText(decodedText) {
			return match
		}

		// 🚀 사용자 프롬프트만 추출 (AI 부하 감소)
		userPrompt := s.extractUserPrompt(decodedText)
		if userPrompt == "" {
			// 프롬프트를 찾을 수 없으면 스킵 (기존 텍스트는 그대로 유지)
			return match
		}

		// Detection을 통한 ML 기반 DLP 처리 (사용자 프롬프트만)

		// Detection 호출 (ML 모델 적용) - 프롬프트만 전달
		detected, err := s.processDLPWithDetection(userPrompt)
		if err != nil {
			// ML 실패시 기존 방식으로 폴백
			detected = s.processDLPDirectly(userPrompt)
		}

		// Detection 결과를 로깅용 형식으로 변환
		// processDLPWithDetection에서 실제 level 정보 가져오기
		_, detectedInfos := policy.ProcessSensitiveInfo(userPrompt)

		for i, detection := range detected {
			// detectedInfos에서 해당하는 level 찾기
			level := core.Low
			if i < len(detectedInfos) {
				level = detectedInfos[i].Level
			} else if len(detectedInfos) > 0 {
				// 마지막 info의 level 사용
				level = detectedInfos[len(detectedInfos)-1].Level
			}

			dlpDetections = append(dlpDetections, struct {
				original string
				masked   string
				category string
				level    core.ConfidenceLevel
			}{
				original: detection.Original,
				masked:   detection.Masked,
				category: detection.Category,
				level:    level,
			})
		}

		// 마스킹된 프롬프트 추출
		maskedPrompt := userPrompt
		if len(detected) > 0 {
			maskedPrompt = detected[len(detected)-1].Masked
		}

		// 원본 텍스트에서 사용자 프롬프트만 교체
		maskedText := decodedText
		if maskedPrompt != userPrompt {
			// 프롬프트가 decodedText에 포함되어 있는지 확인하고 교체
			if strings.Contains(decodedText, userPrompt) {
				maskedText = strings.Replace(decodedText, userPrompt, maskedPrompt, 1)
				// Replaced user prompt in decoded text
			} else {
				// 프롬프트가 정확히 일치하지 않으면 전체 텍스트에 마스킹 적용
				maskedText, _ = policy.ProcessSensitiveInfo(decodedText)
			}
		}

		// 마스킹이 적용되었으면 hex 인코딩해서 반환
		if maskedText != decodedText {
			maskedHex := hex.EncodeToString([]byte(maskedText))
			// DLP masked hex text
			return maskedHex
		}

		return match
	})

	// DLP 탐지가 있으면 로그 파일에 저장 및 웹서버로 전송
	if len(dlpDetections) > 0 {
		// 웹서버로 DLP 로그 전송
		if s.config.BackendAPIURL != "" {
			// 원문과 마스킹 결과 추출
			firstOriginal := dlpDetections[0].original
			lastMasked := dlpDetections[len(dlpDetections)-1].masked

			// JSON 구조 추출 (originalStr에서 {"root":{...}} 부분만)
			originalJSON := s.extractJSONStructure(originalStr)

			// violation_type 결정 (첫 번째 detection의 category 사용)
			violationType := "personal_info"
			if len(dlpDetections) > 0 {
				category := dlpDetections[0].category
				if strings.Contains(strings.ToLower(category), "financial") {
					violationType = "financial_info"
				} else if strings.Contains(strings.ToLower(category), "auth") {
					violationType = "auth_info"
				} else if strings.Contains(strings.ToLower(category), "system") {
					violationType = "system_info"
				}
			}

			// severity 결정 (가장 높은 level 찾기)
			maxLevel := core.Low
			for _, detection := range dlpDetections {
				if detection.level > maxLevel {
					maxLevel = detection.level
				}
			}

			severity := "low"
			if maxLevel == core.High {
				severity = "high"
			} else if maxLevel == core.Medium {
				severity = "medium"
			}

			// severity가 "low"가 아닐 때만 백엔드 서버로 전송
			if severity != "low" {
				// original_text, masked_text 추출 (읽기 가능한 텍스트만)
				originalText := s.extractReadableText(firstOriginal)
				if originalText == "" {
					originalText = firstOriginal
				}
				maskedText := s.extractReadableText(lastMasked)
				if maskedText == "" {
					maskedText = lastMasked
				}

				s.sendDLPViolationLog(clientIP, violationType, severity, originalText, maskedText, originalJSON)
			}
		}

		timestamp := time.Now().Format("20060102_150405")
		dlpLogFile := fmt.Sprintf("./logs/dlp_detection_%s.txt", timestamp)

		var logContent strings.Builder
		logContent.WriteString("=== DLP Detection Log ===\n")
		logContent.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05")))
		logContent.WriteString(fmt.Sprintf("Total Detections: %d\n\n", len(dlpDetections)))

		// DLP 탐지 결과를 깔끔하게 저장
		if len(dlpDetections) > 0 {
			// 원문과 마스킹 결과 추출
			firstOriginal := dlpDetections[0].original
			lastMasked := dlpDetections[len(dlpDetections)-1].masked

			// 원문 저장 (읽기 가능한 텍스트만)
			logContent.WriteString("=== BEFORE (Original) ===\n")
			originalText := s.extractReadableText(firstOriginal)
			if originalText == "" {
				originalText = firstOriginal // 읽기 가능한 텍스트가 없으면 원본 사용
			}
			logContent.WriteString(originalText)
			logContent.WriteString("\n\n")

			// 마스킹 결과 저장 (읽기 가능한 텍스트만)
			logContent.WriteString("=== AFTER (Masked) ===\n")
			maskedText := s.extractReadableText(lastMasked)
			if maskedText == "" {
				maskedText = lastMasked // 읽기 가능한 텍스트가 없으면 원본 사용
			}
			logContent.WriteString(maskedText)
			logContent.WriteString("\n\n")

			// 탐지 세부사항 저장
			logContent.WriteString("=== Detection Details ===\n")
			for i, detection := range dlpDetections {
				logContent.WriteString(fmt.Sprintf("%d. Category: %s\n", i+1, detection.category))
			}
		}

		logContent.WriteString("\n=== End of DLP Detection Log ===\n")

		if err := os.WriteFile(dlpLogFile, []byte(logContent.String()), 0644); err != nil {
			// Failed to save DLP log
		}
	}

	if originalStr != dataStr {
		return []byte(dataStr), true
	}

	return data, false
}

// isPrintableText - 출력 가능한 텍스트인지 확인
func (s *Server) isPrintableText(text string) bool {
	if len(text) < 3 {
		return false
	}

	printableCount := 0
	for _, r := range text {
		// 영문, 숫자, 한글, 일반 특수문자, 공백
		if (r >= 32 && r <= 126) || (r >= 0xAC00 && r <= 0xD7A3) || r == '\n' || r == '\r' || r == '\t' {
			printableCount++
		}
	}

	// 70% 이상이 출력 가능한 문자면 텍스트로 간주
	return float64(printableCount)/float64(len([]rune(text))) > 0.7
}

// truncateText - 텍스트를 지정된 길이로 자르기
func (s *Server) truncateText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen] + "..."
}

// DetectionResult - DLP 탐지 결과 구조체
type DetectionResult struct {
	Original string
	Masked   string
	Category string
}

// processDLPWithDetection - ML 기반 DLP 처리
func (s *Server) processDLPWithDetection(text string) ([]DetectionResult, error) {
	// Policy 패키지의 ProcessSensitiveInfo 호출 (ML 서버 사용)
	maskedText, detected := policy.ProcessSensitiveInfo(text)

	var results []DetectionResult

	// Detection 결과를 내부 형식으로 변환
	for _, info := range detected {
		if info.Level == core.High {
			// HIGH 확실성만 마스킹 결과에 포함
			results = append(results, DetectionResult{
				Original: text,
				Masked:   maskedText,
				Category: string(info.Category),
			})
		}
	}

	// 마스킹이 적용되지 않았으면 원본 반환
	if len(results) == 0 {
		results = append(results, DetectionResult{
			Original: text,
			Masked:   text,
			Category: "No Detection",
		})
	}

	return results, nil
}

// processDLPDirectly - 기존 직접 마스킹 방식 (폴백)
func (s *Server) processDLPDirectly(text string) []DetectionResult {
	var results []DetectionResult
	maskedText := text
	originalText := text

	// 1. 개인정보 마스킹
	maskedText = processing.MaskPersonalInfo(maskedText)
	if maskedText != originalText {
		results = append(results, DetectionResult{
			Original: originalText,
			Masked:   maskedText,
			Category: "Personal Info",
		})
		originalText = maskedText
	}

	// 2. 재무정보 마스킹
	maskedText = processing.MaskFinancialInfo(maskedText)
	if maskedText != originalText {
		results = append(results, DetectionResult{
			Original: originalText,
			Masked:   maskedText,
			Category: "Financial Info",
		})
		originalText = maskedText
	}

	// 3. 인증정보 마스킹
	maskedText = processing.MaskAuthInfo(maskedText)
	if maskedText != originalText {
		results = append(results, DetectionResult{
			Original: originalText,
			Masked:   maskedText,
			Category: "Auth Info",
		})
		originalText = maskedText
	}

	// 4. 시스템정보 마스킹
	maskedText = processing.MaskSystemInfo(maskedText)
	if maskedText != originalText {
		results = append(results, DetectionResult{
			Original: originalText,
			Masked:   maskedText,
			Category: "System Info",
		})
	}

	// 마스킹이 적용되지 않았으면 원본 반환
	if len(results) == 0 {
		results = append(results, DetectionResult{
			Original: text,
			Masked:   text,
			Category: "No Detection",
		})
	}

	return results
}

// extractUserPrompt - decodedText에서 사용자 프롬프트만 추출
// JSON 구조 {"root":{"children":[...]}}에서 가장 마지막에 추가된 root 패턴의 text 필드 추출
// 엔터를 쳤을 때 가장 마지막에 추가된 프롬프트만 추출
func (s *Server) extractUserPrompt(decodedText string) string {
	// 가장 마지막에 추가된 {"root" 패턴 찾기 (끝에서부터 검색)
	lastRootStart := strings.LastIndex(decodedText, `{"root"`)
	if lastRootStart == -1 {
		// JSON 구조가 없으면 텍스트 끝부분에서 프롬프트 추출 시도
		// 프롬프트는 보통 패킷의 끝에 추가되므로 끝에서부터 찾기
		return s.extractPromptFromPlainText(decodedText)
	}

	// 가장 마지막 root 패턴부터 JSON 구조 추출
	braceCount := 0
	jsonStart := lastRootStart
	jsonEnd := -1

	for i := lastRootStart; i < len(decodedText); i++ {
		if decodedText[i] == '{' {
			braceCount++
		} else if decodedText[i] == '}' {
			braceCount--
			if braceCount == 0 {
				jsonEnd = i + 1
				break
			}
		}
	}

	if jsonStart != -1 && jsonEnd != -1 {
		jsonStr := decodedText[jsonStart:jsonEnd]

		// JSON 파싱
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &jsonData); err == nil {
			// root.children 배열에서 가장 마지막 text 추출
			if root, ok := jsonData["root"].(map[string]interface{}); ok {
				if children, ok := root["children"].([]interface{}); ok && len(children) > 0 {
					// 가장 마지막 children부터 역순으로 탐색
					for i := len(children) - 1; i >= 0; i-- {
						if child, ok := children[i].(map[string]interface{}); ok {
							// children[].children[].text 경로 확인
							if childChildren, ok := child["children"].([]interface{}); ok && len(childChildren) > 0 {
								for j := len(childChildren) - 1; j >= 0; j-- {
									if grandChild, ok := childChildren[j].(map[string]interface{}); ok {
										if textVal, ok := grandChild["text"].(string); ok && textVal != "" {
											// 한글이나 자연어가 포함된 텍스트만 프롬프트로 간주
											if s.isValidUserPrompt(textVal) {
												return textVal
											}
										}
									}
								}
							}
							// 직접 text 필드 확인
							if textVal, ok := child["text"].(string); ok && textVal != "" {
								if s.isValidUserPrompt(textVal) {
									return textVal
								}
							}
						}
					}
				}
			}
		}
	}

	// JSON에서 추출 실패시 평문에서 추출
	return s.extractPromptFromPlainText(decodedText)
}

// extractPromptFromPlainText - 평문에서 프롬프트 추출 (텍스트 끝부분)
func (s *Server) extractPromptFromPlainText(text string) string {
	// 프롬프트는 보통 텍스트 끝부분에 있으므로 끝에서부터 찾기
	// 한글이나 자연어가 포함된 텍스트 찾기
	lines := strings.Split(text, "\n")

	// 끝에서부터 역순으로 탐색
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if len(line) > 10 && s.isValidUserPrompt(line) {
			return line
		}
	}

	// 줄 단위로 찾지 못하면 전체 텍스트에서 한글이나 자연어 포함 부분 찾기
	// 마지막 500자 정도에서 찾기
	searchLen := 500
	if len(text) < searchLen {
		searchLen = len(text)
	}
	lastPart := text[len(text)-searchLen:]

	// 한글 또는 자연어 패턴 찾기
	hasKorean := false
	wordCount := 0
	for _, r := range lastPart {
		if r >= 0xAC00 && r <= 0xD7A3 {
			hasKorean = true
		}
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			wordCount++
		}
	}

	if hasKorean || wordCount > 10 {
		// 공백이나 줄바꿈 기준으로 문장 추출
		sentences := regexp.MustCompile(`[.!?。！？]\s*`).Split(lastPart, -1)
		if len(sentences) > 0 {
			lastSentence := strings.TrimSpace(sentences[len(sentences)-1])
			if len(lastSentence) > 10 {
				return lastSentence
			}
		}
		return lastPart
	}

	return ""
}

// isInitialUserInputBidiAppend - 최초 사용자 입력 BidiAppend인지 확인
// JSON 구조를 분석하여 실제 사용자가 엔터를 눌러 입력한 텍스트가 있는지 확인
func (s *Server) isInitialUserInputBidiAppend(decodedText, protobufMsg string) bool {
	// 1. 가장 마지막 {"root" 패턴 찾기
	lastRootStart := strings.LastIndex(decodedText, `{"root"`)
	if lastRootStart == -1 {
		return false
	}

	// 2. JSON 구조 추출
	braceCount := 0
	jsonStart := lastRootStart
	jsonEnd := -1

	for i := lastRootStart; i < len(decodedText); i++ {
		if decodedText[i] == '{' {
			braceCount++
		} else if decodedText[i] == '}' {
			braceCount--
			if braceCount == 0 {
				jsonEnd = i + 1
				break
			}
		}
	}

	if jsonStart == -1 || jsonEnd == -1 {
		return false
	}

	jsonStr := decodedText[jsonStart:jsonEnd]

	// 3. JSON 파싱하여 실제 사용자 입력 텍스트 확인
	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonData); err != nil {
		return false
	}

	// 4. root.children 구조에서 실제 사용자 입력 텍스트 추출
	if root, ok := jsonData["root"].(map[string]interface{}); ok {
		if children, ok := root["children"].([]interface{}); ok && len(children) > 0 {
			// 가장 마지막 children부터 역순으로 탐색
			for i := len(children) - 1; i >= 0; i-- {
				if child, ok := children[i].(map[string]interface{}); ok {
					// children[].children[].text 경로 확인
					if childChildren, ok := child["children"].([]interface{}); ok && len(childChildren) > 0 {
						for j := len(childChildren) - 1; j >= 0; j-- {
							if grandChild, ok := childChildren[j].(map[string]interface{}); ok {
								if textVal, ok := grandChild["text"].(string); ok && textVal != "" {
									// 실제 사용자 입력인지 확인 (자연어, 한글 포함)
									if s.isNaturalLanguageText(textVal) {
										return true
									}
								}
							}
						}
					}
					// 직접 text 필드 확인
					if textVal, ok := child["text"].(string); ok && textVal != "" {
						if s.isNaturalLanguageText(textVal) {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// isNaturalLanguageText - 자연어 텍스트인지 확인 (코드/정규식 제외)
func (s *Server) isNaturalLanguageText(text string) bool {
	if len(text) < 5 {
		return false
	}

	// 한글 포함 여부 확인
	hasKorean := false
	hasEnglish := false
	letterCount := 0
	spaceCount := 0

	for _, r := range text {
		if r >= 0xAC00 && r <= 0xD7A3 {
			hasKorean = true
		}
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			hasEnglish = true
			letterCount++
		}
		if r == ' ' {
			spaceCount++
		}
	}

	// 한글이 포함되어 있으면 자연어로 간주
	if hasKorean {
		return true
	}

	// 영어만 있는 경우: 공백이 있고 단어가 여러 개인 경우 자연어로 간주
	if hasEnglish && letterCount > 10 && spaceCount >= 2 {
		return true
	}

	return false
}

// isValidUserPrompt - 사용자 입력 프롬프트인지 검증 (한글, 자연어 포함 여부)
func (s *Server) isValidUserPrompt(text string) bool {
	return s.isNaturalLanguageText(text)
}

// getClientIP - HTTP 요청에서 실제 클라이언트 IP 추출
// X-Forwarded-For 헤더 우선 확인, 없으면 RemoteAddr 사용
func (s *Server) getClientIP(req *http.Request) string {
	if req == nil {
		return "127.0.0.1"
	}

	// 1. X-Forwarded-For 헤더 확인 (프록시를 통한 경우)
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For는 여러 IP가 쉼표로 구분될 수 있음 (가장 첫 번째가 원본 클라이언트)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return clientIP
			}
		}
	}

	// 2. X-Real-IP 헤더 확인
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 3. RemoteAddr 사용 (직접 연결인 경우)
	if req.RemoteAddr != "" {
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err == nil {
			return ip
		}
		// 포트가 없는 경우 그대로 반환
		if net.ParseIP(req.RemoteAddr) != nil {
			return req.RemoteAddr
		}
	}

	// 4. 기본값 (fallback)
	return "127.0.0.1"
}

// extractReadableText - 텍스트에서 읽을 수 있는 부분만 추출
func (s *Server) extractReadableText(text string) string {
	// JSON에서 "text" 필드 추출 시도
	if strings.Contains(text, `"text"`) {
		// JSON 파싱 시도
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(text), &jsonData); err == nil {
			if textValue, ok := jsonData["text"].(string); ok && textValue != "" {
				return textValue
			}
		}
	}

	// JSON이 아니면 프롬프트 패턴 찾기
	promptPatterns := []string{
		`"text":"([^"]+)"`,
		`"content":"([^"]+)"`,
		`"message":"([^"]+)"`,
		`"prompt":"([^"]+)"`,
	}

	for _, pattern := range promptPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(text)
		if len(matches) > 1 && len(matches[1]) > 10 {
			return matches[1]
		}
	}

	// 패턴이 없으면 출력 가능한 문자들만 추출
	var result strings.Builder
	for _, r := range text {
		// 영문, 숫자, 한글, 일반 특수문자, 공백만 포함
		if (r >= 32 && r <= 126) || (r >= 0xAC00 && r <= 0xD7A3) || r == '\n' || r == ' ' {
			result.WriteRune(r)
		}
	}

	extracted := result.String()
	// 너무 짧거나 의미없는 텍스트면 원본 반환
	if len(extracted) < 20 {
		return text
	}
	return extracted
}

// extractJSONStructure - 텍스트에서 {"root":{...}} JSON 구조만 추출
func (s *Server) extractJSONStructure(text string) string {
	// {"root": 로 시작하는 JSON 구조 찾기
	rootStart := strings.Index(text, `{"root"`)
	if rootStart == -1 {
		return ""
	}

	// JSON의 끝을 찾기 위해 중괄호 매칭
	braceCount := 0
	jsonStart := -1
	jsonEnd := -1

	for i := rootStart; i < len(text); i++ {
		if text[i] == '{' {
			if jsonStart == -1 {
				jsonStart = i
			}
			braceCount++
		} else if text[i] == '}' {
			braceCount--
			if braceCount == 0 && jsonStart != -1 {
				jsonEnd = i + 1
				break
			}
		}
	}

	if jsonStart != -1 && jsonEnd != -1 {
		jsonStr := text[jsonStart:jsonEnd]
		// JSON 유효성 검증
		var testMap map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &testMap); err == nil {
			// root 키가 있는지 확인
			if _, ok := testMap["root"]; ok {
				return jsonStr
			}
		}
	}

	return ""
}

// sendDLPViolationLog - 대시보드로 DLP 위반 로그 전송
func (s *Server) sendDLPViolationLog(clientIP, violationType, severity, originalText, maskedText, originalJSON string) {
	if s.config.BackendAPIURL == "" {
		fmt.Printf("⚠️ Failed to send DLP log to backend: backend API URL not configured\n")
		return
	}

	// API URL 구성
	apiURL := s.config.BackendAPIURL
	// URL이 이미 전체 경로가 아닌 경우 /api/dlp/violation 추가
	if !strings.Contains(apiURL, "/api/dlp/violation") {
		if !strings.HasSuffix(apiURL, "/") {
			apiURL += "/"
		}
		apiURL += "api/dlp/violation"
	}

	// 요청 본문 구성
	requestBody := map[string]string{
		"source_ip":      clientIP,
		"action_type":    "data_transmission",
		"violation_type": violationType,
		"severity":       severity,
		"original_text":  originalText,
		"masked_text":    maskedText,
		"original_json":  originalJSON,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return
	}

	// HTTP 요청 생성
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return
	}

	// 헤더 설정
	req.Header.Set("Content-Type", "application/json")
	if s.config.DLPAPIKey != "" {
		req.Header.Set("x-api-key", s.config.DLPAPIKey)
	}

	// HTTP 클라이언트 생성 및 요청 전송
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	fmt.Printf("[DLP] Sending violation log to webserver: IP=%s, Type=%s, Severity=%s\n", clientIP, violationType, severity)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[DLP] Failed to send violation log: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// 응답 본문 읽기
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		fmt.Printf("[DLP] Violation log sent successfully (status: %d)\n", resp.StatusCode)
	} else {
		fmt.Printf("[DLP] Violation log send failed (status: %d, response: %s)\n", resp.StatusCode, string(bodyBytes))
	}
}

// isMCPToolCall - MCP 도구 호출인지 확인 (개발 과정과 구별)
func (s *Server) isMCPToolCall(decodedText string) bool {
	// 개발 과정 패턴 (제외)
	devPatterns := []string{
		"Wrote contents to",
		"print(",
		"def ",
		"class ",
		"import ",
		"function ",
		"const ",
		"let ",
		"var ",
	}

	// 개발 과정 패턴이 있으면 도구 호출이 아님
	for _, pattern := range devPatterns {
		if strings.Contains(decodedText, pattern) {
			return false
		}
	}

	// MCP 도구 호출 패턴
	// 1. tool_xxx 패턴 (tool ID) - 가장 확실한 지표
	if strings.Contains(decodedText, "tool_") {
		return true
	}

	// 2. 도구 이름 패턴 추출 시도 (동적)
	// 예: "list_issues{" 또는 "create_file(" 같은 패턴
	toolNamePattern := regexp.MustCompile(`([a-z][a-z0-9_]{2,})\s*[{(]`)
	matches := toolNamePattern.FindAllStringSubmatch(decodedText, -1)
	for _, match := range matches {
		if len(match) > 1 {
			toolName := match[1]
			// 개발 키워드가 아니고, 도구 이름처럼 보이는 경우
			if !s.isDevelopmentKeyword(toolName) && len(toolName) >= 3 {
				return true
			}
		}
	}

	return false
}

// extractToolNameFromProtobuf - Protobuf 바이너리에서 직접 도구 이름 추출 (요청 패킷만)
// BidiAppend는 요청이므로 StreamUnifiedChatWithToolsRequest만 확인
func (s *Server) extractToolNameFromProtobuf(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// StreamUnifiedChatWithToolsRequest로 디코딩 시도 (BidiAppend는 요청)
	var request cursor_grpc.StreamUnifiedChatWithToolsRequest
	if err := proto.Unmarshal(data, &request); err == nil {
		// RequestPayload 타입 확인
		switch request.RequestPayload.(type) {
		case *cursor_grpc.StreamUnifiedChatWithToolsRequest_ToolResult:
			// ToolResult는 도구 실행 결과이므로 여기서는 도구 이름을 찾을 수 없음
		case *cursor_grpc.StreamUnifiedChatWithToolsRequest_UserMessage:
			// UserMessage는 사용자 메시지이므로 도구 호출이 아님
		case *cursor_grpc.StreamUnifiedChatWithToolsRequest_InitialRequest:
			// InitialRequest는 초기 요청이므로 도구 호출이 아님
		}
	}

	// 요청 패킷에는 직접적인 ToolCall이 없으므로 빈 문자열 반환
	// 실제 도구 이름은 hex 디코딩된 텍스트에서 추출해야 함
	return ""
}

// extractToolName - decodedText에서 MCP 도구 이름 동적으로 추출 (fallback)
func (s *Server) extractToolName(decodedText string) string {
	// 패턴 1: 도구이름{"error":"..."}(tool_xxx 패턴 찾기
	// 예: "list_issues{"error":"fetch failed"}(tool_be7dda5e-f43e-4d6b-8423-fa71c6e94f2"
	// 또는: "search_repositories{"error":"fetch failed"}(tool_50ea66d9-b485-413b-be65-89c33b3c7bd"
	toolCallPattern := regexp.MustCompile(`([a-z][a-z0-9_]+)\s*\{[^}]*\}\s*\(tool_[a-f0-9-]+`)
	matches := toolCallPattern.FindStringSubmatch(decodedText)
	if len(matches) > 1 {
		toolName := matches[1]
		// 도구 이름은 최소 3자 이상, 언더스코어나 알파벳으로만 구성
		if len(toolName) >= 3 && regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(toolName) {
			return toolName
		}
	}

	// 패턴 2: tool_xxx 패턴 앞의 도구 이름 찾기 (더 관대한 패턴)
	toolIDPattern := regexp.MustCompile(`tool_[a-f0-9-]+`)
	toolIDMatch := toolIDPattern.FindString(decodedText)
	if toolIDMatch != "" {
		// tool_xxx 앞의 텍스트에서 도구 이름 추출
		toolIDIdx := strings.Index(decodedText, toolIDMatch)
		if toolIDIdx > 0 {
			beforeToolID := decodedText[:toolIDIdx]
			// JSON 객체나 괄호 앞의 도구 이름 찾기
			// 예: "list_issues{" 또는 "list_issues("
			toolNamePattern := regexp.MustCompile(`([a-z][a-z0-9_]+)\s*[{(]`)
			matches := toolNamePattern.FindStringSubmatch(beforeToolID)
			if len(matches) > 1 {
				toolName := matches[1]
				// 도구 이름은 최소 3자 이상, 언더스코어나 알파벳으로만 구성
				if len(toolName) >= 3 && regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(toolName) {
					return toolName
				}
			}
		}
	}

	// 패턴 2: JSON 구조에서 도구 이름 찾기
	// 예: {"tool_name": "list_issues"} 또는 "tool_name":"list_issues"
	jsonToolPattern := regexp.MustCompile(`"tool_name"\s*:\s*"([^"]+)"`)
	jsonMatches := jsonToolPattern.FindStringSubmatch(decodedText)
	if len(jsonMatches) > 1 {
		return jsonMatches[1]
	}

	// 패턴 3: 일반적인 도구 호출 패턴
	// 예: "list_issues{" 또는 "create_file("
	generalToolPattern := regexp.MustCompile(`([a-z][a-z0-9_]{2,})\s*[{(]`)
	generalMatches := generalToolPattern.FindAllStringSubmatch(decodedText, -1)
	if len(generalMatches) > 0 {
		// 가장 긴 매칭을 선택 (더 구체적인 도구 이름일 가능성)
		longestMatch := ""
		for _, match := range generalMatches {
			if len(match) > 1 && len(match[1]) > len(longestMatch) {
				// 개발 과정 키워드가 아닌 경우만
				if !s.isDevelopmentKeyword(match[1]) {
					longestMatch = match[1]
				}
			}
		}
		if longestMatch != "" {
			return longestMatch
		}
	}

	return ""
}

// isDevelopmentKeyword - 개발 과정 키워드인지 확인
func (s *Server) isDevelopmentKeyword(word string) bool {
	devKeywords := []string{
		"print", "def", "class", "import", "function", "const", "let", "var",
		"return", "if", "else", "for", "while", "try", "catch", "finally",
		"async", "await", "async", "await", "public", "private", "protected",
		"static", "final", "abstract", "interface", "extends", "implements",
	}
	for _, keyword := range devKeywords {
		if word == keyword {
			return true
		}
	}
	return false
}

// PermissionResponse는 권한 확인 API 응답 구조체입니다
type PermissionResponse struct {
	Success bool   `json:"success"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
	User    struct {
		ID         int    `json:"id"`
		Username   string `json:"username"`
		EmployeeID string `json:"employee_id"`
		Team       string `json:"team"`
	} `json:"user,omitempty"`
}

// checkToolPermission - 웹서버에 도구 사용 권한 확인 요청
func (s *Server) checkToolPermission(clientIP, toolName string) (bool, error) {
	if s.config.BackendAPIURL == "" {
		return true, nil // 백엔드 URL이 없으면 기본적으로 허용
	}

	// API URL 구성: /api/mcp/check-permission 사용
	apiURL := s.config.BackendAPIURL
	if !strings.Contains(apiURL, "/api/mcp/check-permission") {
		if !strings.HasSuffix(apiURL, "/") {
			apiURL += "/"
		}
		apiURL += "api/mcp/check-permission"
	}

	// 요청 본문 구성
	// 웹서버는 mcp_server_id 또는 server_name 중 하나를 필수로 요구
	// http-proxy에서는 mcp_server_id를 알 수 없으므로 server_name을 사용
	requestBody := map[string]interface{}{
		"tool_name":   toolName,
		"server_name": "http-proxy", // http-proxy를 통해 들어온 요청임을 표시
		"client_ip":   clientIP,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return true, err // 마샬링 실패 시 기본적으로 허용
	}

	// HTTP 요청 생성
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return true, err
	}

	// 헤더 설정
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", clientIP)
	req.Header.Set("X-Original-Client-IP", clientIP)
	req.Header.Set("X-MCP-Proxy-Request", "true")
	if s.config.DLPAPIKey != "" {
		req.Header.Set("X-API-Key", s.config.DLPAPIKey)
	}

	// HTTP 클라이언트 생성 및 요청 전송
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		// 네트워크 오류 시 차단 (안전을 위해)
		fmt.Printf("   ⚠️ Failed to connect to webserver: %v\n", err)
		return false, fmt.Errorf("failed to connect to webserver: %w", err)
	}
	defer resp.Body.Close()

	// 응답 본문 읽기
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	// HTTP 상태 코드 확인 (400, 403, 404 등은 권한 없음으로 처리)
	if resp.StatusCode != http.StatusOK {
		// 400, 403, 404는 명확한 권한 거부로 처리
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return false, fmt.Errorf("backend returned status %d (permission denied)", resp.StatusCode)
		}
		// 기타 에러도 차단 (안전을 위해)
		return false, fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// 응답 파싱
	var permissionResp PermissionResponse
	if err := json.Unmarshal(bodyBytes, &permissionResp); err != nil {
		// JSON 파싱 실패 시 차단
		return false, fmt.Errorf("failed to parse permission response: %w, body: %s", err, string(bodyBytes))
	}

	// allowed 필드 확인
	return permissionResp.Allowed, nil
}

// sendRBACViolation - RBAC 위반 정보를 웹서버에 전송 (권한 체크 API를 통해 처리)
// 실제로는 권한 체크 API에서 이미 위반 정보를 처리하므로, 이 함수는 로깅용으로만 사용
func (s *Server) sendRBACViolation(clientIP, toolName string) error {
	// 권한 체크 API에서 이미 위반 정보를 처리하므로 별도 전송 불필요
	// 로그만 출력
	fmt.Printf("📤 [RBAC] Tool access denied: IP=%s, Tool=%s\n", clientIP, toolName)
	return nil
}

// decodeVarint - Protobuf varint 디코딩
func (s *Server) decodeVarint(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	size := 0

	for i := 0; i < len(data) && i < 10; i++ {
		b := data[i]
		result |= uint64(b&0x7f) << shift
		size++

		if b&0x80 == 0 {
			return result, size
		}

		shift += 7
	}

	return 0, 0
}

// isHexEncodedText - hex 인코딩된 텍스트인지 확인
func (s *Server) isHexEncodedText(data []byte) bool {
	// 모든 바이트가 hex 문자(0-9, a-f)인지 확인
	if len(data) < 4 || len(data)%2 != 0 {
		return false
	}

	for _, b := range data {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return false
		}
	}

	return true
}

// hexDecode - hex 문자열을 바이트로 디코딩
func (s *Server) hexDecode(hexData []byte) string {
	result := make([]byte, len(hexData)/2)

	for i := 0; i < len(hexData); i += 2 {
		var b byte

		// 첫 번째 hex 문자
		if hexData[i] >= '0' && hexData[i] <= '9' {
			b = (hexData[i] - '0') << 4
		} else if hexData[i] >= 'a' && hexData[i] <= 'f' {
			b = (hexData[i] - 'a' + 10) << 4
		} else if hexData[i] >= 'A' && hexData[i] <= 'F' {
			b = (hexData[i] - 'A' + 10) << 4
		}

		// 두 번째 hex 문자
		if hexData[i+1] >= '0' && hexData[i+1] <= '9' {
			b |= hexData[i+1] - '0'
		} else if hexData[i+1] >= 'a' && hexData[i+1] <= 'f' {
			b |= hexData[i+1] - 'a' + 10
		} else if hexData[i+1] >= 'A' && hexData[i+1] <= 'F' {
			b |= hexData[i+1] - 'A' + 10
		}

		result[i/2] = b
	}

	return string(result)
}

// hexEncode - 문자열을 hex로 인코딩
func (s *Server) hexEncode(text string) []byte {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(text)*2)

	for i, b := range []byte(text) {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0xf]
	}

	return result
}

// applyDLPMasking - DLP 마스킹 적용
func (s *Server) applyDLPMasking(text string) string {
	masked := text

	// 1. 개인정보 마스킹
	masked = processing.MaskPersonalInfo(masked)

	// 2. 재무정보 마스킹
	masked = processing.MaskFinancialInfo(masked)

	// 3. 인증정보 마스킹
	masked = processing.MaskAuthInfo(masked)

	// 4. 시스템정보 마스킹
	masked = processing.MaskSystemInfo(masked)

	return masked
}

// parseProtobufFields - Protobuf 데이터를 field들로 파싱하는 함수
func (s *Server) parseProtobufFields(data []byte) ([]ProtobufField, error) {
	var fields []ProtobufField
	offset := 0

	for offset < len(data) {
		// Tag 읽기 (varint)
		tag, newOffset, err := s.readVarintWithOffset(data, offset)
		if err != nil {
			break
		}

		// Wire type 추출
		wireType := int(tag & 0x07)
		fieldNumber := int(tag >> 3)

		// Length 읽기 (wire type 2인 경우)
		if wireType == 2 { // length-delimited
			length, newOffset, err := s.readVarintWithOffset(data, newOffset)
			if err != nil {
				break
			}

			// Data 읽기
			if newOffset+int(length) > len(data) {
				break
			}
			fieldData := data[newOffset : newOffset+int(length)]

			fields = append(fields, ProtobufField{
				Number:   fieldNumber,
				WireType: wireType,
				Data:     fieldData,
				Offset:   offset,
				Length:   int(length),
			})

			offset = newOffset + int(length)
		} else {
			// 다른 wire type 처리 (varint, fixed32, fixed64 등)
			offset = newOffset
		}
	}

	return fields, nil
}

// readVarintWithOffset - Varint을 읽는 함수 (offset 포함)
func (s *Server) readVarintWithOffset(data []byte, offset int) (uint64, int, error) {
	var result uint64
	var shift uint

	for i := offset; i < len(data); i++ {
		b := data[i]
		result |= uint64(b&0x7F) << shift

		if b&0x80 == 0 {
			return result, i + 1, nil
		}

		shift += 7
		if shift >= 64 {
			return 0, 0, fmt.Errorf("varint too long")
		}
	}

	return 0, 0, fmt.Errorf("unexpected end of data")
}

// findTextFields - 텍스트가 있는 field들을 찾는 함수
func (s *Server) findTextFields(fields []ProtobufField) []int {
	var textFieldIndices []int

	for i, field := range fields {
		// UTF-8 텍스트인지 확인
		if s.isUTF8Text(field.Data) {
			textFieldIndices = append(textFieldIndices, i)
		}
	}

	return textFieldIndices
}

// isUTF8Text - UTF-8 텍스트인지 확인하는 함수
func (s *Server) isUTF8Text(data []byte) bool {
	// 최소 길이 체크
	if len(data) < 3 {
		return false
	}

	// UTF-8 유효성 검사
	return utf8.Valid(data)
}

// replaceTextInField - Field에서 텍스트를 교체하는 함수
func (s *Server) replaceTextInField(field *ProtobufField, original, replacement string) bool {
	originalBytes := []byte(original)
	replacementBytes := []byte(replacement)

	// 1. 먼저 직접 바이트 교체 시도
	if bytes.Contains(field.Data, originalBytes) {
		field.Data = bytes.ReplaceAll(field.Data, originalBytes, replacementBytes)
		field.Length = len(field.Data)
		return true
	}

	// 2. Hex 디코딩 후 교체 시도
	hexStr := string(field.Data)
	originalHex := hex.EncodeToString(originalBytes)
	replacementHex := hex.EncodeToString(replacementBytes)

	if strings.Contains(hexStr, originalHex) {
		// Hex에서 교체
		modifiedHex := strings.ReplaceAll(hexStr, originalHex, replacementHex)

		// Hex를 다시 바이너리로 변환
		modifiedData, err := hex.DecodeString(modifiedHex)

		if err != nil {
			return false
		}

		// 길이 보정: 원본 길이와 맞추기 위해 패딩 추가
		lengthDiff := len(field.Data) - len(modifiedData)
		if lengthDiff > 0 {
			// 패딩 추가 (공백으로)
			padding := make([]byte, lengthDiff)
			modifiedData = append(modifiedData, padding...)
		}

		field.Data = modifiedData
		field.Length = len(field.Data)
		return true
	}

	return false
}

// reconstructProtobuf - 수정된 field들로 Protobuf를 재구성하는 함수
func (s *Server) reconstructProtobuf(fields []ProtobufField) []byte {
	var result []byte

	for _, field := range fields {
		// Tag + Length + Data
		tag := uint64((field.Number << 3) | field.WireType)

		// Tag (varint)
		result = append(result, s.encodeVarint(tag)...)

		// Length (varint)
		result = append(result, s.encodeVarint(uint64(field.Length))...)

		// Data
		result = append(result, field.Data...)
	}

	return result
}

// encodeVarint - Varint을 인코딩하는 함수
func (s *Server) encodeVarint(value uint64) []byte {
	var result []byte

	for value >= 0x80 {
		result = append(result, byte(value)|0x80)
		value >>= 7
	}
	result = append(result, byte(value))

	return result
}

// replaceTextInBody - 바이너리 body에서 텍스트를 직접 교체하는 함수
func (s *Server) replaceTextInBody(body []byte, original, replacement string) []byte {
	// UTF-8 바이트로 변환
	originalBytes := []byte(original)
	replacementBytes := []byte(replacement)

	// 원본에서 텍스트가 있는지 확인
	originalCount := bytes.Count(body, originalBytes)

	if originalCount == 0 {
		return body
	}

	// 바이너리에서 직접 교체
	modifiedBody := bytes.ReplaceAll(body, originalBytes, replacementBytes)

	return modifiedBody
}

// tryMultipleEncodings - 다양한 인코딩으로 텍스트 교체를 시도하는 함수
func (s *Server) tryMultipleEncodings(data []byte, original, replacement string) []byte {
	// 다양한 인코딩 방식으로 시도
	encodings := []string{"utf-8", "utf-16", "latin-1", "cp1252"}

	for _, encoding := range encodings {
		// 인코딩된 바이트로 변환
		var originalBytes, replacementBytes []byte

		switch encoding {
		case "utf-8":
			originalBytes = []byte(original)
			replacementBytes = []byte(replacement)
		case "utf-16":
			originalBytes = s.encodeUTF16(original)
			replacementBytes = s.encodeUTF16(replacement)
		case "latin-1":
			originalBytes = s.encodeLatin1(original)
			replacementBytes = s.encodeLatin1(replacement)
		case "cp1252":
			originalBytes = s.encodeCP1252(original)
			replacementBytes = s.encodeCP1252(replacement)
		}

		// 교체 시도
		if bytes.Contains(data, originalBytes) {
			modified := bytes.ReplaceAll(data, originalBytes, replacementBytes)
			return modified
		}
	}

	return data
}

// encodeUTF16 - UTF-16 인코딩
func (s *Server) encodeUTF16(text string) []byte {
	runes := []rune(text)
	var result []byte
	for _, r := range runes {
		// Little-endian UTF-16
		result = append(result, byte(r&0xFF))
		result = append(result, byte((r>>8)&0xFF))
	}
	return result
}

// encodeLatin1 - Latin-1 인코딩
func (s *Server) encodeLatin1(text string) []byte {
	var result []byte
	for _, r := range text {
		if r < 256 {
			result = append(result, byte(r))
		}
	}
	return result
}

// encodeCP1252 - CP1252 인코딩
func (s *Server) encodeCP1252(text string) []byte {
	// 간단한 CP1252 매핑 (주요 문자만)
	cp1252Map := map[rune]byte{
		'이': 0xEC, '민': 0xB9, '혁': 0x81,
		'*': 0x2A,
	}

	var result []byte
	for _, r := range text {
		if b, exists := cp1252Map[r]; exists {
			result = append(result, b)
		} else if r < 256 {
			result = append(result, byte(r))
		}
	}
	return result
}

// blockSSEStreamWithError - SSE 스트림을 차단하고 에러 메시지를 클라이언트에 전송
func (s *Server) blockSSEStreamWithError(conn net.Conn, errorMessage string) {
	// SSE 형식의 에러 메시지 생성
	errorResponse := fmt.Sprintf("event: error\ndata: %s\n\n", errorMessage)

	// HTTP 응답 헤더 작성
	headers := "HTTP/1.1 403 Forbidden\r\n"
	headers += "Content-Type: text/event-stream\r\n"
	headers += fmt.Sprintf("Content-Length: %d\r\n", len(errorResponse))
	headers += "Cache-Control: no-cache\r\n"
	headers += "Connection: close\r\n"
	headers += "\r\n"

	// 헤더와 본문 전송
	_, _ = conn.Write([]byte(headers))
	_, _ = conn.Write([]byte(errorResponse))
}

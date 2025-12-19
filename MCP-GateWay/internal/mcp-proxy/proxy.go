package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"mcp-gateway/internal/config"
	"mcp-gateway/internal/util"
)

// ServerConfig는 MCP 서버 설정입니다
type ServerConfig struct {
	ID          string
	Type        string // "local", "ssh", "http"
	Command     string
	Args        []string
	Env         map[string]string
	MCPServerID int // 웹서버 DB의 mcp_servers.id

	// SSH 설정
	SSHHost string
	SSHUser string
	SSHKey  string
}

// Proxy는 MCP 프록시 서버입니다
type Proxy struct {
	config      *config.Config
	logMutex    sync.Mutex
	logger      *util.NDJSON
	logFile     *os.File
	sessions    map[string]*Session // session_id -> session
	sessionsMu  sync.RWMutex
	serversMu   sync.RWMutex             // 서버 목록 보호
	serverCache map[string]*ServerConfig // DB에서 조회한 서버 설정 캐시
}

// Session은 하나의 클라이언트-MCP Server 세션을 나타냅니다
type Session struct {
	ID           string
	ServerCfg    *ServerConfig
	ServerCmd    *exec.Cmd
	ServerStdin  io.WriteCloser
	ServerStdout io.ReadCloser
	Created      time.Time
	mu           sync.Mutex
}

// NewProxy는 새로운 MCP 프록시 인스턴스를 생성합니다
func NewProxy(cfg *config.Config) (*Proxy, error) {
	logDir := cfg.Gateway.LogDir
	if logDir == "" {
		logDir = "./logs"
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}

	logPath := filepath.Join(logDir, "mcp-proxy.ndjson")
	logFile, err := os.OpenFile(
		logPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0o644,
	)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	// 서버 맵 초기화 (설정 파일에서 로드된 서버들)
	servers := make(map[string]*ServerConfig)
	for _, server := range cfg.Servers {
		serverCfg := &ServerConfig{
			ID:          server.ID,
			Type:        server.Type,
			Command:     server.Command,
			Args:        server.Args,
			Env:         server.Env,
			MCPServerID: server.MCPServerID,
			SSHHost:     server.RemoteIP,
		}
		servers[server.ID] = serverCfg
	}

	proxy := &Proxy{
		config:      cfg,
		logger:      util.NewNDJSON(logFile),
		logFile:     logFile,
		sessions:    make(map[string]*Session),
		serverCache: make(map[string]*ServerConfig),
	}

	// 초기화 로그 (프로세스 시작 확인용)
	proxy.logMessage("proxy_init", "", map[string]interface{}{
		"pid":      os.Getpid(),
		"log_file": logPath,
		"servers":  len(servers),
	})

	return proxy, nil
}

// Start는 프록시를 시작합니다 (Gateway.Listen 사용)
func (p *Proxy) Start() error {
	listenAddr := p.config.Gateway.Listen
	if listenAddr == "" {
		listenAddr = ":8081"
	}
	return p.StartHTTP(listenAddr)
}

// StartHTTP는 HTTP 서버 모드로 프록시를 시작합니다
func (p *Proxy) StartHTTP(listen string) error {
	http.HandleFunc("/health", p.handleHealth)
	http.HandleFunc("/sse/", p.handleSSE)         // SSE 스트리밍
	http.HandleFunc("/stdio/", p.handleStdioHTTP) // Streamable HTTP (stdio over HTTP)
	http.HandleFunc("/mcp/", p.handleMCP)         // 일반 HTTP JSON-RPC

	fmt.Printf("MCP Proxy HTTP server starting on %s\n", listen)
	fmt.Printf("Endpoints:\n")
	fmt.Printf("  - GET/POST /health\n")
	fmt.Printf("  - GET /sse/{server_id} - SSE streaming\n")
	fmt.Printf("  - POST /stdio/{server_id} - Streamable HTTP\n")
	fmt.Printf("  - POST /mcp/{server_id} - JSON-RPC over HTTP\n")

	return http.ListenAndServe(listen, nil)
}

// StartStdioMode는 stdio 모드로 프록시를 시작합니다 (MCP 클라이언트가 직접 실행)
func (p *Proxy) StartStdioMode(serverCfg *ServerConfig) error {
	// 시작 로그
	p.logMessage("proxy_start", "", map[string]interface{}{
		"mode":      "stdio",
		"server_id": serverCfg.ID,
	})

	// 세션 생성
	sessionID := fmt.Sprintf("stdio-%d", time.Now().UnixNano())
	session, err := p.createSession(sessionID, serverCfg)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// 클라이언트 stdin/stdout과 MCP Server 간 메시지 중계 (NDJSON 형식)
	go func() {
		// 클라이언트 -> MCP Server
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			var msg map[string]interface{}
			if err := json.Unmarshal(line, &msg); err == nil {
				p.logMessage("request", sessionID, msg)
			}

			// MCP Server로 전달 (줄바꿈 포함)
			session.mu.Lock()
			if _, err := session.ServerStdin.Write(append(line, '\n')); err != nil {
				session.mu.Unlock()
				break
			}
			session.mu.Unlock()
		}
	}()

	// MCP Server -> 클라이언트
	reader := bufio.NewReader(session.ServerStdout)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}

		// 로깅
		var msg map[string]interface{}
		if err := json.Unmarshal(bytes.TrimSpace(line), &msg); err == nil {
			p.logMessage("response", sessionID, msg)
		}

		// 클라이언트로 전달
		if _, err := os.Stdout.Write(line); err != nil {
			break
		}
	}

	// 프로세스 종료 대기
	session.ServerCmd.Wait()
	return nil
}

// createSession은 새로운 MCP Server 세션을 생성합니다
func (p *Proxy) createSession(sessionID string, serverCfg *ServerConfig) (*Session, error) {
	var cmd *exec.Cmd

	// SSH 타입 서버인 경우
	if serverCfg.Type == "ssh" || serverCfg.Type == "remote" {
		if serverCfg.SSHHost == "" {
			return nil, fmt.Errorf("SSH host not specified for server %s (type=%s)", serverCfg.ID, serverCfg.Type)
		}
		if serverCfg.Command == "" {
			return nil, fmt.Errorf("command not specified for SSH server %s", serverCfg.ID)
		}

		// SSH 사용자 및 키 경로 확인
		sshUser := serverCfg.SSHUser
		if sshUser == "" {
			sshUser = p.config.SSH.User
		}
		if sshUser == "" {
			sshUser = "ubuntu" // 기본값
		}

		sshKey := serverCfg.SSHKey
		if sshKey == "" {
			sshKey = p.config.SSH.KeyPath
		}
		if sshKey == "" {
			return nil, fmt.Errorf("SSH key not specified")
		}

		// SSH 명령어 구성
		sshArgs := []string{
			"-i", sshKey,
			"-T",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "LogLevel=ERROR",
		}

		// 원격 명령어 구성 (환경 변수 설정 포함)
		// SSH 비대화형 셸에서 bash -c를 사용하여 환경 변수를 확실하게 전달
		var remoteCmd string

		// 명령어와 인수 구성
		cmdParts := []string{serverCfg.Command}
		cmdParts = append(cmdParts, serverCfg.Args...)
		cmdStr := strings.Join(cmdParts, " ")

		// "go run"을 "/usr/local/go/bin/go run"으로 치환하는 헬퍼 함수
		replaceGoRun := func(s string) string {
			// 이미 /usr/local/go/bin/go가 포함되어 있으면 치환하지 않음
			if strings.Contains(s, "/usr/local/go/bin/go") {
				return s
			}
			// 정규식으로 "go run"을 "/usr/local/go/bin/go run"으로 치환
			// 단어 경계를 사용하여 "go run"만 정확히 매칭 (예: "gogo run"은 매칭 안 됨)
			re := regexp.MustCompile(`\bgo\s+run\b`)
			return re.ReplaceAllString(s, "/usr/local/go/bin/go run")
		}

		// 내부 명령어 (환경 변수와 결합할 때 사용)
		var innerCmd string

		// sh -c 또는 bash -c 패턴 감지: "sh -c" 또는 "bash -c"로 시작하고 그 뒤에 명령어가 있으면
		// -c 뒤의 모든 내용을 따옴표로 감싸야 함
		needsQuote := false
		if (serverCfg.Command == "sh" || serverCfg.Command == "bash") && len(serverCfg.Args) > 0 && serverCfg.Args[0] == "-c" {
			// sh -c "command" 또는 bash -c "command" 형태
			// -c 뒤의 모든 args를 하나의 문자열로 결합
			if len(serverCfg.Args) > 1 {
				// -c 뒤의 명령어들을 하나로 결합
				commandArg := strings.Join(serverCfg.Args[1:], " ")
				// "go run"을 "/usr/local/go/bin/go run"으로 치환
				commandArg = replaceGoRun(commandArg)
				// 내부 명령어 저장 (환경 변수와 결합할 때 사용)
				innerCmd = commandArg
				cmdStr = fmt.Sprintf("%s -c '%s'", serverCfg.Command, strings.ReplaceAll(commandArg, "'", "'\"'\"'"))
				needsQuote = false // 이미 따옴표로 감싸져 있음
			}
		} else if strings.Contains(cmdStr, "&&") || strings.Contains(cmdStr, "||") || strings.HasPrefix(strings.TrimSpace(cmdStr), "cd ") {
			// 복합 명령어 (&&, || 포함) 또는 cd로 시작하는 명령어는 bash -c로 감싸야 함
			// "go run"을 "/usr/local/go/bin/go run"으로 치환
			cmdStr = replaceGoRun(cmdStr)
			innerCmd = cmdStr
			needsQuote = true
		} else {
			// 단순 명령어도 "go run"이 포함될 수 있음
			cmdStr = replaceGoRun(cmdStr)
			innerCmd = cmdStr
		}

		if len(serverCfg.Env) > 0 {
			fmt.Fprintf(os.Stderr, "[SSH] Creating command with %d env vars\n", len(serverCfg.Env))
			// 환경 변수가 있는 경우: export를 사용하여 환경 변수를 설정하고 명령어 실행
			// base64 인코딩된 값을 디코딩하여 전달
			envExports := make([]string, 0, len(serverCfg.Env))
			for k, v := range serverCfg.Env {
				// 값을 base64로 인코딩하여 특수문자 문제 완전히 방지
				encoded := base64.StdEncoding.EncodeToString([]byte(v))
				// 원격에서 디코딩: echo 'encoded' | base64 -d
				// export VAR=$(echo '...' | base64 -d) 형태
				envExports = append(envExports, fmt.Sprintf("export %s=$(echo '%s' | base64 -d)", k, encoded))
				if k == "GITHUB_PERSONAL_ACCESS_TOKEN" {
					fmt.Fprintf(os.Stderr, "[SSH] Token encoded length: %d, original length: %d\n", len(encoded), len(v))
				}
			}

			// export 명령어들을 &&로 연결
			exportCmds := strings.Join(envExports, " && ")

			// export 명령어들과 내부 명령어를 &&로 연결
			// npm run dev 같은 명령어의 경우, npm의 출력 메시지를 stderr로 리다이렉트
			// 실제 MCP 서버의 JSON 출력만 stdout으로 받기 위해
			// npm run dev >&2: npm의 stdout을 stderr로 리다이렉트
			// 하지만 npm run dev 자체의 출력도 stderr로 가므로, 실제로는 npm의 출력을 필터링해야 함
			// 더 나은 방법: npm run --silent dev 또는 npm run dev 2>&1 | grep -v "^>"
			// 하지만 가장 간단한 방법은 npm의 출력을 stderr로 리다이렉트하는 것
			// innerCmd에 "npm run"이 포함되어 있으면 --silent 플래그 추가
			// npm run dev는 tsx watch를 사용하는데, watch 모드도 초기 출력을 보내므로 그대로 사용
			// 단, npm의 실행 메시지를 줄이기 위해 --silent 플래그 추가
			processedInnerCmd := innerCmd
			if strings.Contains(innerCmd, "npm run") && !strings.Contains(innerCmd, "--silent") {
				// npm run dev -> npm run --silent dev
				processedInnerCmd = strings.Replace(innerCmd, "npm run ", "npm run --silent ", 1)
			}
			combinedCmd := fmt.Sprintf("%s && %s", exportCmds, processedInnerCmd)
			// bash -c로 감싸기 (작은따옴표 이스케이프)
			combinedCmdEscaped := strings.ReplaceAll(combinedCmd, "'", "'\"'\"'")
			remoteCmd = fmt.Sprintf("bash -c '%s'", combinedCmdEscaped)

			fmt.Fprintf(os.Stderr, "[SSH] Command includes env vars, remoteCmd length: %d\n", len(remoteCmd))
		} else {
			// 환경 변수가 없으면
			if needsQuote && !strings.HasPrefix(cmdStr, "sh -c") && !strings.HasPrefix(cmdStr, "bash -c") {
				// 복합 명령어를 bash -c로 감싸기
				bashCmdEscaped := strings.ReplaceAll(cmdStr, "'", "'\"'\"'")
				remoteCmd = fmt.Sprintf("bash -c '%s'", bashCmdEscaped)
			} else if strings.HasPrefix(cmdStr, "sh -c") || strings.HasPrefix(cmdStr, "bash -c") {
				// 이미 sh -c 또는 bash -c로 감싸져 있으면 그대로 사용
				remoteCmd = cmdStr
			} else {
				// 단순 명령어는 그대로 사용
				remoteCmd = cmdStr
			}
		}

		sshArgs = append(sshArgs, fmt.Sprintf("%s@%s", sshUser, serverCfg.SSHHost), remoteCmd)
		cmd = exec.Command("ssh", sshArgs...)

		fmt.Fprintf(os.Stderr, "[SSH] Connecting to %s@%s via SSH key %s\n", sshUser, serverCfg.SSHHost, sshKey)
		fmt.Fprintf(os.Stderr, "[SSH] Remote command: %s\n", remoteCmd)
	} else {
		// 로컬 명령어 실행
		if serverCfg.Command == "" {
			return nil, fmt.Errorf("command not specified for local server %s", serverCfg.ID)
		}
		parts := strings.Fields(serverCfg.Command)
		if len(parts) == 0 {
			return nil, fmt.Errorf("empty command for server %s", serverCfg.ID)
		}

		cmd = exec.Command(parts[0], append(parts[1:], serverCfg.Args...)...)

		// 환경 변수 설정
		if len(serverCfg.Env) > 0 {
			cmd.Env = os.Environ()
			for k, v := range serverCfg.Env {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
			}
		}
	}

	// 표준 입출력 파이프 설정
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// SSH의 경우 stderr를 캡처하여 디버깅 정보 확인
	var stderr io.ReadCloser
	if serverCfg.Type == "ssh" || serverCfg.Type == "remote" {
		stderr, err = cmd.StderrPipe()
		if err != nil {
			stdin.Close()
			stdout.Close()
			return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
		}

		// stderr를 별도로 읽어서 디버깅 정보 출력
		go func() {
			buf := make([]byte, 1024)
			totalBytes := 0
			for {
				n, err := stderr.Read(buf)
				if n > 0 {
					totalBytes += n
					fmt.Fprintf(os.Stderr, "[SSH stderr] (session=%s, total=%d) %s", sessionID, totalBytes, string(buf[:n]))
				}
				if err != nil {
					if err != io.EOF {
						fmt.Fprintf(os.Stderr, "[SSH stderr] (session=%s) Read error: %v\n", sessionID, err)
					} else {
						fmt.Fprintf(os.Stderr, "[SSH stderr] (session=%s) EOF reached (total bytes: %d)\n", sessionID, totalBytes)
					}
					break
				}
			}
			fmt.Fprintf(os.Stderr, "[SSH stderr] (session=%s) Closed (total bytes read: %d)\n", sessionID, totalBytes)
		}()
	}

	// 프로세스 시작
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		if stderr != nil {
			stderr.Close()
		}
		return nil, fmt.Errorf("failed to start MCP server: %w", err)
	}

	session := &Session{
		ID:           sessionID,
		ServerCfg:    serverCfg,
		ServerCmd:    cmd,
		ServerStdin:  stdin,
		ServerStdout: stdout,
		Created:      time.Now(),
	}

	// 세션 저장
	p.sessionsMu.Lock()
	p.sessions[sessionID] = session
	p.sessionsMu.Unlock()

	// 프로세스 종료 감지 및 상태 모니터링
	go func() {
		err := cmd.Wait()
		exitCode := 0
		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode = exitError.ExitCode()
			}
			fmt.Fprintf(os.Stderr, "[Session] Process exited (session=%s, pid=%d, exit_code=%d, err=%v)\n",
				sessionID, cmd.Process.Pid, exitCode, err)
		} else {
			fmt.Fprintf(os.Stderr, "[Session] Process exited normally (session=%s, pid=%d)\n",
				sessionID, cmd.Process.Pid)
		}
		p.sessionsMu.Lock()
		delete(p.sessions, sessionID)
		p.sessionsMu.Unlock()
	}()

	// 프로세스 상태 확인 (1초 후)
	go func() {
		time.Sleep(1 * time.Second)
		if cmd.Process != nil {
			// 프로세스가 여전히 실행 중인지 확인
			if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
				fmt.Fprintf(os.Stderr, "[Session] Process check failed (session=%s, pid=%d): %v\n",
					sessionID, cmd.Process.Pid, err)
			} else {
				fmt.Fprintf(os.Stderr, "[Session] Process is running (session=%s, pid=%d)\n",
					sessionID, cmd.Process.Pid)
			}
		}
	}()

	fmt.Printf("Created session %s for server %s (PID: %d)\n", sessionID, serverCfg.ID, cmd.Process.Pid)
	return session, nil
}

// handleHealth는 헬스 체크 엔드포인트를 처리합니다
func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleSSE는 SSE 스트리밍 요청을 처리합니다
func (p *Proxy) handleSSE(w http.ResponseWriter, r *http.Request) {
	// 경로 파싱: /sse/{server_id}
	path := strings.TrimPrefix(r.URL.Path, "/sse/")
	serverID := strings.Split(path, "/")[0]

	// 서버 설정 파싱 (query parameter 또는 header에서)
	serverCfg := p.parseServerConfigFromRequest(r, serverID)
	if serverCfg == nil {
		http.Error(w, "Server config required (use ?command=... or X-Server-Command header)", http.StatusBadRequest)
		return
	}

	// SSE 헤더 설정
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = fmt.Sprintf("sse-%d", time.Now().UnixNano())
	}

	session, err := p.getOrCreateSession(sessionID, serverCfg)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create session: %v", err), http.StatusInternalServerError)
		return
	}

	// 클라이언트로부터 초기화 메시지 읽기 (있다면)
	if r.Method == http.MethodPost {
		var initMsg map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&initMsg); err == nil {
			p.forwardToServer(session, initMsg)
		}
	}

	// MCP Server의 응답을 SSE로 스트리밍
	p.streamServerResponseSSE(w, session)
}

// handleStdioHTTP는 Streamable HTTP (stdio over HTTP) 요청을 처리합니다
func (p *Proxy) handleStdioHTTP(w http.ResponseWriter, r *http.Request) {
	// 경로 파싱: /stdio/{server_id}
	path := strings.TrimPrefix(r.URL.Path, "/stdio/")
	serverID := strings.Split(path, "/")[0]

	// 서버 설정 파싱
	serverCfg := p.parseServerConfigFromRequest(r, serverID)
	if serverCfg == nil {
		http.Error(w, "Server config required (use ?command=... or X-Server-Command header)", http.StatusBadRequest)
		return
	}

	// Session ID는 server_id 기준으로 고정 (동일한 서버는 항상 같은 세션 사용)
	// 이렇게 해야 initialize 후 initialized 알림이 같은 세션에서 처리됨
	sessionID := fmt.Sprintf("stdio-http-%s", serverID)

	session, err := p.getOrCreateSession(sessionID, serverCfg)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create session: %v", err), http.StatusInternalServerError)
		return
	}

	// 요청 본문 읽기
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Tool 호출 요청인지 확인 및 권한 체크
	_, toolName, isToolCall := extractToolInfo(req)
	if isToolCall {
		// 클라이언트 IP 추출
		clientIP := extractClientIP(r)

		// 권한 확인
		permissionResp, err := p.checkToolPermission(clientIP, toolName, serverID)
		if err != nil {
			p.logPermissionCheck(serverID, toolName, clientIP, false, fmt.Sprintf("Permission check error: %v", err))
			http.Error(w, fmt.Sprintf("Permission check failed: %v", err), http.StatusInternalServerError)
			return
		}

		if !permissionResp.Allowed {
			p.logPermissionCheck(serverID, toolName, clientIP, false, permissionResp.Reason)
			http.Error(w, permissionResp.Reason, http.StatusForbidden)
			return
		}

		// 권한이 있으면 로그 기록
		p.logPermissionCheck(serverID, toolName, clientIP, true, "")
	}

	// Notification인지 확인 (id 필드가 없으면 notification)
	_, hasID := req["id"]
	method, _ := req["method"].(string)
	isNotification := !hasID && method != ""

	// MCP Server로 전송
	if err := p.forwardToServer(session, req); err != nil {
		http.Error(w, fmt.Sprintf("Failed to send message: %v", err), http.StatusInternalServerError)
		return
	}

	// Notification인 경우 응답 없이 즉시 반환 (204 No Content)
	if isNotification {
		p.logMessage("notification", session.ID, req)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Session-ID", sessionID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 응답 읽기 (타임아웃 적용) - MCP 서버 시작 시간을 고려하여 60초로 증가
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	response, err := p.readFromServer(ctx, session)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read response: %v", err), http.StatusInternalServerError)
		return
	}

	// initialize 응답인 경우, initialized 알림을 즉시 전송
	// HTTP over STDIO 모드에서 프록시가 initialized 알림을 자동 전송
	if method == "initialize" {
		if _, hasError := response["error"]; !hasError {
			// initialize가 성공했으면 initialized 알림을 즉시 전송 (응답 반환 전)
			initializedNotification := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "notifications/initialized",
			}
			// STDIO 서버로 initialized 알림 전송 (동기적으로, 응답 반환 전)
			if err := p.forwardToServer(session, initializedNotification); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to send initialized notification: %v\n", err)
			} else {
				// 로그에 출력 (notifications/* 메시지는 logMessage에서 필터링되므로 직접 출력)
				fmt.Fprintf(os.Stderr, "Sent initialized notification to server\n")
			}
		}
	}

	// 응답 반환
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Session-ID", sessionID)
	json.NewEncoder(w).Encode(response)
}

// handleMCP는 일반 JSON-RPC 요청을 처리합니다
func (p *Proxy) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 경로 파싱: /mcp/{server_id}
	path := strings.TrimPrefix(r.URL.Path, "/mcp/")
	serverID := strings.Split(path, "/")[0]

	// 서버 설정 파싱
	serverCfg := p.parseServerConfigFromRequest(r, serverID)
	if serverCfg == nil {
		http.Error(w, "Server config required (use ?command=... or X-Server-Command header)", http.StatusBadRequest)
		return
	}

	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = fmt.Sprintf("http-%d", time.Now().UnixNano())
	}

	session, err := p.getOrCreateSession(sessionID, serverCfg)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create session: %v", err), http.StatusInternalServerError)
		return
	}

	// 요청 본문 읽기
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// MCP Server로 전송
	if err := p.forwardToServer(session, req); err != nil {
		http.Error(w, fmt.Sprintf("Failed to send message: %v", err), http.StatusInternalServerError)
		return
	}

	// 응답 읽기
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := p.readFromServer(ctx, session)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read response: %v", err), http.StatusInternalServerError)
		return
	}

	// 응답 반환
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Session-ID", sessionID)
	json.NewEncoder(w).Encode(response)
}

// getOrCreateSession은 세션을 가져오거나 새로 생성합니다
func (p *Proxy) getOrCreateSession(sessionID string, serverCfg *ServerConfig) (*Session, error) {
	p.sessionsMu.RLock()
	if session, exists := p.sessions[sessionID]; exists {
		p.sessionsMu.RUnlock()
		return session, nil
	}
	p.sessionsMu.RUnlock()

	// 새 세션 생성
	return p.createSession(sessionID, serverCfg)
}

// forwardToServer는 메시지를 MCP Server로 전송합니다
func (p *Proxy) forwardToServer(session *Session, message map[string]interface{}) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	// MCP 프로토콜에 없는 비표준 필드 제거 (_meta 등)
	// 클라이언트(Cursor 등)가 추가한 필드는 서버로 전달하지 않음
	cleanMessage := make(map[string]interface{})
	for k, v := range message {
		// 표준 MCP 필드만 복사
		if k == "jsonrpc" || k == "id" || k == "method" || k == "params" || k == "result" || k == "error" {
			cleanMessage[k] = v
		}
	}

	// params 내부의 _meta 필드도 제거
	if params, ok := cleanMessage["params"].(map[string]interface{}); ok {
		cleanParams := make(map[string]interface{})
		for k, v := range params {
			if k != "_meta" {
				cleanParams[k] = v
			}
		}
		cleanMessage["params"] = cleanParams
	}

	// JSON 인코딩
	data, err := json.Marshal(cleanMessage)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// NDJSON 형식으로 전송 (줄바꿈 추가)
	data = append(data, '\n')

	method, _ := message["method"].(string)
	id, _ := message["id"]
	fmt.Fprintf(os.Stderr, "[Forward] Sending to server (session=%s, method=%s, id=%v, data_len=%d): %s\n",
		session.ID, method, id, len(data), string(data[:min(len(data), 200)]))

	if _, err := session.ServerStdin.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "[Forward] ERROR: Failed to write to server: %v\n", err)
		return fmt.Errorf("failed to write to server: %w", err)
	}

	// 로깅 (원본 메시지 로깅)
	p.logMessage("request", session.ID, message)

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// readFromServer는 MCP Server로부터 응답을 읽습니다
func (p *Proxy) readFromServer(ctx context.Context, session *Session) (map[string]interface{}, error) {
	fmt.Fprintf(os.Stderr, "[Read] Waiting for response from server (session=%s)...\n", session.ID)

	// 타임아웃 처리를 위한 채널
	resultChan := make(chan struct {
		response map[string]interface{}
		err      error
	}, 1)

	go func() {
		session.mu.Lock()
		defer session.mu.Unlock()

		fmt.Fprintf(os.Stderr, "[Read] Starting to read from server stdout (session=%s)...\n", session.ID)

		// 한 줄 읽기 (NDJSON 형식)
		reader := bufio.NewReader(session.ServerStdout)

		// 빈 줄을 건너뛰고 유효한 JSON 라인을 찾기
		var line []byte
		var err error
		maxEmptyLines := 50 // npm run dev가 시작하는 데 시간이 걸릴 수 있으므로 증가
		emptyLineCount := 0
		totalBytesRead := 0

		for {
			// 10줄마다 진행 상황 로그
			if emptyLineCount > 0 && emptyLineCount%10 == 0 {
				fmt.Fprintf(os.Stderr, "[Read] Still waiting for response (session=%s, skipped_lines=%d, total_bytes=%d)...\n",
					session.ID, emptyLineCount, totalBytesRead)
			}

			line, err = reader.ReadBytes('\n')
			if err != nil {
				fmt.Fprintf(os.Stderr, "[Read] ERROR: Failed to read from server: %v (total_bytes=%d, skipped_lines=%d)\n",
					err, totalBytesRead, emptyLineCount)
				resultChan <- struct {
					response map[string]interface{}
					err      error
				}{nil, fmt.Errorf("failed to read from server: %w", err)}
				return
			}

			totalBytesRead += len(line)
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				fmt.Fprintf(os.Stderr, "[Read] Received %d bytes (hex): %x, (string): %q\n",
					len(line), line[:min(len(line), 50)], string(trimmed[:min(len(trimmed), 100)]))
			}

			// 빈 줄이면 건너뛰기
			if len(trimmed) == 0 {
				emptyLineCount++
				if emptyLineCount%5 == 0 {
					fmt.Fprintf(os.Stderr, "[Read] Skipping empty line (%d/%d, total_bytes=%d)\n",
						emptyLineCount, maxEmptyLines, totalBytesRead)
				}
				if emptyLineCount >= maxEmptyLines {
					fmt.Fprintf(os.Stderr, "[Read] ERROR: Too many empty lines, giving up (total_bytes=%d)\n", totalBytesRead)
					resultChan <- struct {
						response map[string]interface{}
						err      error
					}{nil, fmt.Errorf("server sent too many empty lines")}
					return
				}
				continue
			}

			// 유효한 JSON인지 확인
			var testJSON map[string]interface{}
			if err := json.Unmarshal(trimmed, &testJSON); err != nil {
				fmt.Fprintf(os.Stderr, "[Read] WARNING: Line is not valid JSON, skipping: %v, content: %q\n",
					err, string(trimmed[:min(len(trimmed), 200)]))
				emptyLineCount++
				if emptyLineCount >= maxEmptyLines {
					fmt.Fprintf(os.Stderr, "[Read] ERROR: Too many invalid lines, giving up (total_bytes=%d)\n", totalBytesRead)
					resultChan <- struct {
						response map[string]interface{}
						err      error
					}{nil, fmt.Errorf("server sent too many invalid JSON lines")}
					return
				}
				continue
			}

			// 유효한 JSON을 찾았음
			fmt.Fprintf(os.Stderr, "[Read] Found valid JSON after skipping %d lines (total_bytes=%d)\n",
				emptyLineCount, totalBytesRead)
			break
		}

		var response map[string]interface{}
		if err := json.Unmarshal(bytes.TrimSpace(line), &response); err != nil {
			fmt.Fprintf(os.Stderr, "[Read] ERROR: Failed to unmarshal response: %v, raw: %s\n", err, string(line))
			resultChan <- struct {
				response map[string]interface{}
				err      error
			}{nil, fmt.Errorf("failed to unmarshal response: %w", err)}
			return
		}

		method, _ := response["method"].(string)
		id, hasID := response["id"]
		fmt.Fprintf(os.Stderr, "[Read] Successfully parsed response (session=%s, method=%s, id=%v, has_id=%v)\n",
			session.ID, method, id, hasID)

		// 로깅
		p.logMessage("response", session.ID, response)

		resultChan <- struct {
			response map[string]interface{}
			err      error
		}{response, nil}
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintf(os.Stderr, "[Read] ERROR: Timeout waiting for response (session=%s): %v\n", session.ID, ctx.Err())
		return nil, ctx.Err()
	case result := <-resultChan:
		if result.err != nil {
			fmt.Fprintf(os.Stderr, "[Read] ERROR: %v\n", result.err)
		} else {
			fmt.Fprintf(os.Stderr, "[Read] Successfully received response (session=%s)\n", session.ID)
		}
		return result.response, result.err
	}
}

// streamServerResponseSSE는 MCP Server의 응답을 SSE로 스트리밍합니다
func (p *Proxy) streamServerResponseSSE(w http.ResponseWriter, session *Session) {
	reader := bufio.NewReader(session.ServerStdout)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(w, "data: {\"error\":\"%s\"}\n\n", err.Error())
			break
		}

		var msg map[string]interface{}
		if err := json.Unmarshal(bytes.TrimSpace(line), &msg); err != nil {
			continue
		}

		// 로깅
		p.logMessage("response", session.ID, msg)

		// SSE 형식으로 전송
		data, _ := json.Marshal(msg)
		fmt.Fprintf(w, "data: %s\n\n", data)

		// Flush
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}

// parseServerConfigFromRequest는 HTTP 요청에서 서버 설정을 파싱합니다
// 1. DB에서 조회 (웹서버 URL이 설정된 경우) - SSH 연결 정보만, 환경 변수는 제외
// 2. 설정 파일에서 등록된 서버 확인
// 3. 요청 파라미터에서 파싱
// 요청에서 전달된 환경 변수가 있으면 DB/설정 파일의 환경 변수를 덮어씀
func (p *Proxy) parseServerConfigFromRequest(r *http.Request, serverID string) *ServerConfig {
	var serverCfg *ServerConfig

	// 1. DB에서 조회 (웹서버 URL이 설정된 경우)
	if p.config.MCPProxy.WebServerURL != "" {
		dbConfig := p.fetchServerFromDB(r, serverID)
		if dbConfig != nil {
			serverCfg = dbConfig
			// DB에서 가져온 환경 변수를 기본값으로 유지 (요청에서 덮어쓸 수 있음)
			if serverCfg.Env == nil {
				serverCfg.Env = make(map[string]string)
			}
			fmt.Fprintf(os.Stderr, "[Config] Loaded server config from DB for %s (type=%s, command=%s, ssh_host=%s, ssh_key=%s, env vars: %d, will merge with request)\n",
				serverID, serverCfg.Type, serverCfg.Command, serverCfg.SSHHost, serverCfg.SSHKey, len(serverCfg.Env))
		}
	}

	// 2. DB에 없으면 설정 파일에서 등록된 서버 확인
	if serverCfg == nil {
		p.serversMu.RLock()
		var registeredServer *ServerConfig
		for _, server := range p.config.Servers {
			if server.ID == serverID {
				registeredServer = &ServerConfig{
					ID:          server.ID,
					Type:        server.Type,
					Command:     server.Command,
					Args:        server.Args,
					Env:         make(map[string]string), // 기본값으로 빈 맵 생성
					MCPServerID: server.MCPServerID,
					SSHHost:     server.RemoteIP,
				}
				// 설정 파일의 환경 변수 복사
				if server.Env != nil {
					registeredServer.Env = make(map[string]string)
					for k, v := range server.Env {
						registeredServer.Env[k] = v
					}
				}
				break
			}
		}
		p.serversMu.RUnlock()

		if registeredServer != nil {
			serverCfg = &ServerConfig{
				ID:          registeredServer.ID,
				Type:        registeredServer.Type,
				Command:     registeredServer.Command,
				MCPServerID: registeredServer.MCPServerID,
				SSHHost:     registeredServer.SSHHost,
				Env:         make(map[string]string), // 기본값으로 빈 맵 생성
			}
			// Args 복사
			if registeredServer.Args != nil {
				serverCfg.Args = make([]string, len(registeredServer.Args))
				copy(serverCfg.Args, registeredServer.Args)
			}
			// 환경 변수 복사
			if registeredServer.Env != nil {
				for k, v := range registeredServer.Env {
					serverCfg.Env[k] = v
				}
			}
			fmt.Fprintf(os.Stderr, "[Config] Loaded server config from file for %s (env vars: %d, will merge with request)\n", serverID, len(serverCfg.Env))
		}
	}

	// 3. 서버 설정이 없으면 요청 파라미터에서 완전히 새로 파싱
	if serverCfg == nil {
		// Query parameter에서 command 읽기
		command := r.URL.Query().Get("command")
		if command == "" {
			// Header에서 읽기
			command = r.Header.Get("X-Server-Command")
		}
		if command == "" {
			return nil
		}

		serverCfg = &ServerConfig{
			ID:      serverID,
			Command: command,
			Env:     make(map[string]string),
		}

		// Args 파싱 (query parameter 또는 header)
		argsStr := r.URL.Query().Get("args")
		if argsStr == "" {
			argsStr = r.Header.Get("X-Server-Args")
		}
		if argsStr != "" {
			argsParts := strings.Split(argsStr, ",")
			for i := range argsParts {
				argsParts[i] = strings.TrimSpace(argsParts[i])
			}
			serverCfg.Args = argsParts
		}
	}

	// serverCfg가 nil이면 에러
	if serverCfg == nil {
		return nil
	}

	// 추가 args 파싱 (URL 파라미터로 DB/설정 파일의 args에 추가 가능)
	// DB/설정 파일에서 args를 가져온 경우에만 추가로 병합
	additionalArgsStr := r.URL.Query().Get("args")
	if additionalArgsStr != "" && len(serverCfg.Args) > 0 {
		argsParts := strings.Split(additionalArgsStr, ",")
		for i := range argsParts {
			argsParts[i] = strings.TrimSpace(argsParts[i])
		}
		// 기존 args에 추가 (뒤에 추가)
		serverCfg.Args = append(serverCfg.Args, argsParts...)
		fmt.Fprintf(os.Stderr, "[Config] Added %d additional args from request to existing args\n", len(argsParts))
	}

	// 환경 변수 파싱 (요청에서 전달된 환경 변수가 DB/설정 파일보다 우선)
	// DB/설정 파일의 환경 변수는 이미 serverCfg.Env에 있음
	// 요청에서 받은 환경 변수로 덮어쓰기 또는 추가

	requestEnvCount := 0

	// 형식 1: env=KEY1:VALUE1,KEY2:VALUE2 (쿼리 파라미터)
	envStr := r.URL.Query().Get("env")
	if envStr != "" {
		// KEY1:VALUE1,KEY2:VALUE2 형식 파싱
		pairs := strings.Split(envStr, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				serverCfg.Env[key] = val
				requestEnvCount++
				if key == "GITHUB_PERSONAL_ACCESS_TOKEN" {
					fmt.Fprintf(os.Stderr, "[Config] Found GitHub token in request query param (length=%d)\n", len(val))
				}
			}
		}
	}

	// 형식 2: X-Env-* 헤더
	for headerName, headerValue := range r.Header {
		if strings.HasPrefix(strings.ToLower(headerName), "x-env-") {
			key := strings.TrimPrefix(strings.ToLower(headerName), "x-env-")
			serverCfg.Env[key] = headerValue[0] // 첫 번째 값 사용
			requestEnvCount++
			if key == "github_personal_access_token" {
				fmt.Fprintf(os.Stderr, "[Config] Found GitHub token in request header (length=%d)\n", len(headerValue[0]))
			}
		}
	}

	if len(serverCfg.Env) > 0 {
		fmt.Fprintf(os.Stderr, "[Config] Total env vars: %d (from DB/config: %d, from request: %d)\n",
			len(serverCfg.Env), len(serverCfg.Env)-requestEnvCount, requestEnvCount)
	} else {
		fmt.Fprintf(os.Stderr, "[Config] No env vars found\n")
	}

	// 최종 설정 요약 로그
	fmt.Fprintf(os.Stderr, "[Config] Final config for %s: type=%s, command=%s, ssh_host=%s, ssh_key=%s, args=%v, env_count=%d\n",
		serverID, serverCfg.Type, serverCfg.Command, serverCfg.SSHHost, serverCfg.SSHKey, serverCfg.Args, len(serverCfg.Env))

	return serverCfg
}

// fetchServerFromDB는 웹서버 API에서 서버 정보를 조회합니다
func (p *Proxy) fetchServerFromDB(r *http.Request, serverID string) *ServerConfig {
	if p.config.MCPProxy.WebServerURL == "" {
		return nil
	}

	// 캐시 확인
	p.serversMu.RLock()
	if cached, exists := p.serverCache[serverID]; exists {
		p.serversMu.RUnlock()
		return cached
	}
	p.serversMu.RUnlock()

	// 클라이언트 IP 추출 (헤더 전달용)
	clientIP := extractClientIP(r)

	// API 호출
	url := fmt.Sprintf("%s/api/mcp/servers/%s", p.config.MCPProxy.WebServerURL, serverID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DB Lookup] Failed to create request: %v\n", err)
		return nil
	}

	// 헤더 설정
	req.Header.Set("X-MCP-Proxy-Request", "true")
	req.Header.Set("X-Original-Client-IP", clientIP)
	req.Header.Set("X-Forwarded-For", clientIP)
	if p.config.MCPProxy.APIKey != "" {
		req.Header.Set("X-API-Key", p.config.MCPProxy.APIKey)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	// HTTP Proxy 우회 설정
	if p.config.MCPProxy.BypassProxy {
		client.Transport = &http.Transport{
			Proxy: nil,
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DB Lookup] Failed to fetch server config: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "[DB Lookup] Server config not found: status %d\n", resp.StatusCode)
		return nil
	}

	var dbResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&dbResp); err != nil {
		fmt.Fprintf(os.Stderr, "[DB Lookup] Failed to decode response: %v\n", err)
		return nil
	}

	// DB 응답을 ServerConfig로 변환
	serverCfg := &ServerConfig{
		ID:          serverID,
		MCPServerID: 0,                       // 기본값
		Env:         make(map[string]string), // 환경 변수 맵 초기화
	}

	// command 파싱 (null 체크 포함)
	if command, ok := dbResp["command"].(string); ok && command != "" {
		serverCfg.Command = command
	} else {
		// command가 null이거나 비어있으면 에러
		fmt.Fprintf(os.Stderr, "[DB Lookup] ERROR: command is null or empty for server %s (type=%v)\n", serverID, dbResp["command"])
		return nil
	}

	if args, ok := dbResp["args"].([]interface{}); ok {
		serverCfg.Args = make([]string, len(args))
		for i, arg := range args {
			if argStr, ok := arg.(string); ok {
				serverCfg.Args[i] = argStr
			}
		}
	}

	// 환경 변수 파싱 (DB에서 여러 환경 변수 지원)
	if env, ok := dbResp["env"].(map[string]interface{}); ok {
		for k, v := range env {
			if val, ok := v.(string); ok {
				serverCfg.Env[k] = val
				// 환경 변수 값 로깅 (토큰의 경우 일부만 표시)
				if k == "GITHUB_PERSONAL_ACCESS_TOKEN" {
					if len(val) > 10 {
						fmt.Fprintf(os.Stderr, "[DB Lookup] Found env var %s=%s... (length=%d)\n", k, val[:10], len(val))
					} else {
						fmt.Fprintf(os.Stderr, "[DB Lookup] Found env var %s=%s (length=%d)\n", k, val, len(val))
					}
				} else {
					fmt.Fprintf(os.Stderr, "[DB Lookup] Found env var %s=%s\n", k, val)
				}
			}
		}
		fmt.Fprintf(os.Stderr, "[DB Lookup] Total env vars: %d\n", len(serverCfg.Env))
	} else {
		fmt.Fprintf(os.Stderr, "[DB Lookup] No env vars found in DB response\n")
	}

	// SSH 설정 파싱
	if serverType, ok := dbResp["type"].(string); ok {
		serverCfg.Type = serverType
	}
	if sshHost, ok := dbResp["ssh_host"].(string); ok {
		serverCfg.SSHHost = sshHost
	}
	if sshUser, ok := dbResp["ssh_user"].(string); ok {
		serverCfg.SSHUser = sshUser
	} else if p.config.SSH.User != "" {
		// Fallback to proxy config's SSH user
		serverCfg.SSHUser = p.config.SSH.User
	}
	if sshKey, ok := dbResp["ssh_key"].(string); ok {
		serverCfg.SSHKey = sshKey
	} else if p.config.SSH.KeyPath != "" {
		// Fallback to proxy config's SSH key path
		serverCfg.SSHKey = p.config.SSH.KeyPath
	}

	// MCPServerID 설정 (권한 체크용)
	if mcpServerID, ok := dbResp["mcp_server_id"].(float64); ok {
		serverCfg.MCPServerID = int(mcpServerID)
	}

	// 캐시에 저장
	p.serversMu.Lock()
	p.serverCache[serverID] = serverCfg
	p.serversMu.Unlock()

	fmt.Fprintf(os.Stderr, "[DB Lookup] Successfully fetched server config for %s (mcp_server_id=%d, type=%s, command=%s, args=%v, ssh_host=%s)\n",
		serverID, serverCfg.MCPServerID, serverCfg.Type, serverCfg.Command, serverCfg.Args, serverCfg.SSHHost)

	// DB 조회 성공 로그 기록
	p.logMessage("server_lookup", serverID, map[string]interface{}{
		"source":        "db",
		"status":        "success",
		"mcp_server_id": serverCfg.MCPServerID,
	})

	return serverCfg
}

// logMessage는 메시지를 로깅합니다
func (p *Proxy) logMessage(direction, sessionID string, message map[string]interface{}) {
	// notification 메시지는 로그에서 제외 (선택적)
	if method, ok := message["method"].(string); ok {
		// notifications/* 메시지는 로그하지 않음 (일반적으로 응답이 없는 알림)
		if strings.HasPrefix(method, "notifications/") {
			return
		}
	}

	p.logMutex.Lock()
	defer p.logMutex.Unlock()

	entry := map[string]interface{}{
		"timestamp":  time.Now().Format(time.RFC3339),
		"direction":  direction,
		"session_id": sessionID,
		"message":    message,
	}

	if err := p.logger.WriteLine(entry); err != nil {
		// 로그 쓰기 실패 시 stderr로 출력 (최소한의 디버깅)
		fmt.Fprintf(os.Stderr, "Failed to write log: %v\n", err)
	}

	// 즉시 flush
	if p.logFile != nil {
		if err := p.logFile.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to sync log file: %v\n", err)
		}
	}
}

// Close는 프록시 서버를 종료합니다
func (p *Proxy) Close() error {
	p.sessionsMu.Lock()
	defer p.sessionsMu.Unlock()

	// 모든 세션 종료
	for _, session := range p.sessions {
		if session.ServerStdin != nil {
			session.ServerStdin.Close()
		}
		if session.ServerStdout != nil {
			session.ServerStdout.Close()
		}
		if session.ServerCmd != nil && session.ServerCmd.Process != nil {
			session.ServerCmd.Process.Kill()
			session.ServerCmd.Wait()
		}
	}

	if p.logFile != nil {
		return p.logFile.Close()
	}
	return nil
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

// normalizeIP IP 주소 정규화 (IPv6, 포트 제거)
func normalizeIP(ip string) string {
	// IPv6 주소 처리: [::1]:54321 -> ::1
	if strings.HasPrefix(ip, "[") {
		ip = strings.TrimPrefix(ip, "[")
		ip = strings.TrimSuffix(ip, "]")
		if idx := strings.LastIndex(ip, "]:"); idx != -1 {
			ip = ip[:idx+1]
		}
	}

	// IPv6-mapped IPv4: ::ffff:192.168.1.1 -> 192.168.1.1
	ip = strings.TrimPrefix(ip, "::ffff:")

	// IPv4 포트 제거: 192.168.1.100:54321 -> 192.168.1.100
	if strings.Contains(ip, ":") && !strings.Contains(ip, "::") {
		parts := strings.Split(ip, ":")
		if len(parts) > 0 {
			ip = parts[0]
		}
	}

	return strings.TrimSpace(ip)
}

// extractClientIP HTTP 요청에서 클라이언트 IP 추출
func extractClientIP(r *http.Request) string {
	// 1. X-Forwarded-For 헤더 확인 (프록시를 통한 경우)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For는 여러 IP가 쉼표로 구분될 수 있음 (가장 첫 번째가 원본 클라이언트)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return normalizeIP(clientIP)
			}
		}
	}

	// 2. X-Real-IP 헤더 확인
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return normalizeIP(strings.TrimSpace(xri))
	}

	// 3. RemoteAddr 사용 (직접 연결인 경우)
	if r.RemoteAddr != "" {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			return normalizeIP(ip)
		}
		// 포트가 없는 경우 그대로 반환
		if net.ParseIP(r.RemoteAddr) != nil {
			return normalizeIP(r.RemoteAddr)
		}
	}

	// 4. 기본값 (fallback)
	return "127.0.0.1"
}

// extractToolInfo MCP 요청에서 Tool 정보 추출
func extractToolInfo(req map[string]interface{}) (method string, toolName string, ok bool) {
	method, _ = req["method"].(string)
	if method != "tools/call" {
		return method, "", false
	}

	params, ok := req["params"].(map[string]interface{})
	if !ok {
		return method, "", false
	}

	toolName, _ = params["name"].(string)
	return method, toolName, toolName != ""
}

// checkToolPermission 웹서버로 Tool 권한 확인 요청 (IP 기반)
func (p *Proxy) checkToolPermission(clientIP, toolName, serverID string) (*PermissionResponse, error) {
	if !p.config.MCPProxy.IPAuthEnabled {
		// IP 기반 인증 비활성화 시 항상 허용
		fmt.Fprintf(os.Stderr, "[Permission Check] IP auth disabled, allowing %s/%s for %s\n", serverID, toolName, clientIP)
		return &PermissionResponse{Allowed: true}, nil
	}

	// 서버 설정에서 mcp_server_id 가져오기
	var mcpServerID int
	p.serversMu.RLock()
	// 캐시에서 확인
	if serverCfg, exists := p.serverCache[serverID]; exists {
		mcpServerID = serverCfg.MCPServerID
	} else {
		// 설정 파일에서 확인
		for _, server := range p.config.Servers {
			if server.ID == serverID {
				mcpServerID = server.MCPServerID
				break
			}
		}
	}
	p.serversMu.RUnlock()

	if mcpServerID == 0 {
		// mcp_server_id가 없으면 권한 체크 스킵
		fmt.Fprintf(os.Stderr, "[Permission Check] mcp_server_id is 0 for %s, skipping web server check, allowing %s/%s for %s\n", serverID, serverID, toolName, clientIP)
		return &PermissionResponse{Allowed: true}, nil
	}

	fmt.Fprintf(os.Stderr, "[Permission Check] Sending request to web server: server=%s, tool=%s, client_ip=%s, mcp_server_id=%d, url=%s/api/mcp/check-permission\n",
		serverID, toolName, clientIP, mcpServerID, p.config.MCPProxy.WebServerURL)

	// 요청 본문 구성
	reqBody := map[string]interface{}{
		"tool_name":     toolName,
		"mcp_server_id": mcpServerID,
		"client_ip":     clientIP,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// HTTP 요청 생성
	apiURL := fmt.Sprintf("%s/api/mcp/check-permission", p.config.MCPProxy.WebServerURL)
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 헤더 설정
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", clientIP)      // 실제 클라이언트 IP
	req.Header.Set("X-Original-Client-IP", clientIP) // 추가 보험
	req.Header.Set("X-MCP-Proxy-Request", "true")    // MCP Proxy 요청임을 표시

	if p.config.MCPProxy.APIKey != "" {
		req.Header.Set("X-API-Key", p.config.MCPProxy.APIKey)
	}

	// HTTP 클라이언트 생성
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// HTTP Proxy 우회 설정 (BypassProxy 옵션)
	if p.config.MCPProxy.BypassProxy {
		client.Transport = &http.Transport{
			Proxy: nil, // 프록시 사용 안 함 (직접 연결)
		}
	}

	// 요청 전송
	fmt.Fprintf(os.Stderr, "[Permission Check] HTTP Request: POST %s\n", apiURL)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Permission Check] HTTP Request failed: %v\n", err)
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Fprintf(os.Stderr, "[Permission Check] HTTP Response: status=%d\n", resp.StatusCode)

	// 응답 본문 읽기 (디버깅용)
	respBodyBytes, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(os.Stderr, "[Permission Check] HTTP Response body: %s\n", string(respBodyBytes))

	// 응답 파싱
	var permissionResp PermissionResponse
	if err := json.Unmarshal(respBodyBytes, &permissionResp); err != nil {
		fmt.Fprintf(os.Stderr, "[Permission Check] Failed to decode response: %v\n", err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "[Permission Check] Permission check failed: status=%d, allowed=%v, reason=%s\n",
			resp.StatusCode, permissionResp.Allowed, permissionResp.Reason)
		return &permissionResp, fmt.Errorf("permission check failed: status=%d", resp.StatusCode)
	}

	fmt.Fprintf(os.Stderr, "[Permission Check] Permission granted: allowed=%v, reason=%s\n",
		permissionResp.Allowed, permissionResp.Reason)
	return &permissionResp, nil
}

// logPermissionCheck 권한 확인 결과 로깅
func (p *Proxy) logPermissionCheck(serverID, toolName, clientIP string, allowed bool, reason string) {
	p.logMutex.Lock()
	defer p.logMutex.Unlock()

	entry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"event":     "tool_permission_check",
		"server_id": serverID,
		"tool_name": toolName,
		"client_ip": clientIP,
		"allowed":   allowed,
	}

	if reason != "" {
		entry["reason"] = reason
	}

	if err := p.logger.WriteLine(entry); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write permission log: %v\n", err)
	}

	// 즉시 flush
	if p.logFile != nil {
		if err := p.logFile.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to sync log file: %v\n", err)
		}
	}
}

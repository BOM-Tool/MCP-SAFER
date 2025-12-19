package core

import "regexp"

// InitSensitivePatterns: 민감정보 패턴 초기화 (exported)
func InitSensitivePatterns() map[SensitiveCategory][]*regexp.Regexp {
	patterns := make(map[SensitiveCategory][]*regexp.Regexp)

	// 개인정보 패턴들
	patterns[CategoryPersonalInfo] = []*regexp.Regexp{
		// HIGH 확실성: Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		// 주민등록번호 (완벽한 패턴)
		regexp.MustCompile(`(?i)(\d{6}[-]\d{7})`), // 010101-3456789
		regexp.MustCompile(`(?i)(\d{6}\s\d{7})`),  // 010101 3456789

		// 여권번호 (완벽한 패턴)
		regexp.MustCompile(`(?i)([AM]\d{8,9})`), // M12345678, A1234567

		// 운전면허번호 (완벽한 패턴)
		regexp.MustCompile(`(?i)((?:01|11|12|13|14|15|16|17|18|19|20|21|22|23|24)[-]\d{2}[-]\d{6}[-]\d{2})`), // 12-34-567890

		// 전화번호 (완벽한 패턴)
		regexp.MustCompile(`(?i)(010[-]\d{4}[-]\d{4})`),  // 010-1234-5678
		regexp.MustCompile(`(?i)(010\s\d{4}\s\d{4})`),    // 010 1234 5678
		regexp.MustCompile(`(?i)(010\d{8})`),             // 01012345678
		regexp.MustCompile(`(?i)(02[-]\d{3,4}[-]\d{4})`), // 02-123-4567

		// 이메일 (완벽한 패턴)
		regexp.MustCompile(`(?i)([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`), // user@example.com

		// MEDIUM 확실성: Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		// 13자리 숫자 (주민등록번호 유사)
		regexp.MustCompile(`(?i)(\d{13})`), // 1234567890123

		// 운전면허번호 유사 패턴
		regexp.MustCompile(`(?i)(\d{2}[-]\d{2}[-]\d{6}[-]\d{2})`), // 12-34-567890

		// 전화번호 유사 패턴
		regexp.MustCompile(`(?i)(0\d{1,2}[-]\d{3,4}[-]\d{4})`), // 031-123-4567

		// 이메일 유사 문자열
		regexp.MustCompile(`(?i)([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)`), // user@company

		// 키워드 포함 패턴
		regexp.MustCompile(`(?i)(비밀번호[:]\s*[^\s]{6,})`),     // 비밀번호: mySecret123
		regexp.MustCompile(`(?i)(password[:]\s*[^\s]{6,})`), // password: mySecret123
		regexp.MustCompile(`(?i)(고객\s*DB)`),                 // 고객 DB
		regexp.MustCompile(`(?i)(계약\s*초안)`),                 // 계약 초안
		regexp.MustCompile(`(?i)(사내\s*문서)`),                 // 사내 문서
	}

	// 재무/결제 정보 패턴들
	patterns[CategoryFinancial] = []*regexp.Regexp{
		// HIGH 확실성: Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		// 은행 계좌번호 (완벽한 패턴)
		regexp.MustCompile(`(?i)(\d{3}[-]\d{2,4}[-]\d{6})`), // 123-456-789012
		regexp.MustCompile(`(?i)(\d{3}\s\d{2,4}\s\d{6})`),   // 123 456 789012

		// 카드번호 (완벽한 패턴)
		regexp.MustCompile(`(?i)(\d{4}[-]\d{4}[-]\d{4}[-]\d{4})`), // 1234-5678-9012-3456
		regexp.MustCompile(`(?i)(\d{4}\s\d{4}\s\d{4}\s\d{4})`),    // 1234 5678 9012 3456

		// CVV/CVC (완벽한 패턴)
		regexp.MustCompile(`(?i)(CVV[:]\s*\d{3,4})`), // CVV: 123
		regexp.MustCompile(`(?i)(CVC[:]\s*\d{3,4})`), // CVC: 123

		// 카드 만료일 (완벽한 패턴) - 키워드와 함께만 탐지하도록 제거
		// regexp.MustCompile(`(?i)(\d{2}[/]\d{2})`), // 12/25 - 너무 광범위
		// regexp.MustCompile(`(?i)(\d{2}[-]\d{2})`), // 12-25 - 너무 광범위
		// regexp.MustCompile(`(?i)(\d{2}[.]\d{2})`), // 12.25 - 너무 광범위
		// regexp.MustCompile(`(?i)(\d{2}\s\d{2})`), // 12 25 - 너무 광범위

		// 키워드와 함께 나오는 금융 정보 (완벽한 패턴)
		regexp.MustCompile(`(?i)(계좌번호[:]\s*\d{3}[-]\d{2,4}[-]\d{6})`),       // 계좌번호: 123-456-789012
		regexp.MustCompile(`(?i)(카드번호[:]\s*\d{4}[-]\d{4}[-]\d{4}[-]\d{4})`), // 카드번호: 1234-5678-9012-3456
		regexp.MustCompile(`(?i)(은행계좌[:]\s*\d{3}[-]\d{2,4}[-]\d{6})`),       // 은행계좌: 123-456-789012
		regexp.MustCompile(`(?i)(만료일[:]\s*\d{2}[/\-\.]\d{2})`),              // 만료일: 12/25
		regexp.MustCompile(`(?i)(expiry[:]\s*\d{2}[/\-\.]\d{2})`),           // expiry: 12/25

		// MEDIUM 확실성: Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		// 카드번호 유사 패턴
		regexp.MustCompile(`(?i)(\d{16})`), // 1234567890123456

		// CVV/CVC 유사 패턴
		regexp.MustCompile(`(?i)(\b\d{3,4}\b)`), // 단독 3-4자리

		// 금융 관련 키워드
		regexp.MustCompile(`(?i)(계좌\s*정보)`), // 계좌 정보
		regexp.MustCompile(`(?i)(카드\s*정보)`), // 카드 정보
		regexp.MustCompile(`(?i)(결제\s*정보)`), // 결제 정보
		regexp.MustCompile(`(?i)(금융\s*정보)`), // 금융 정보
	}

	// 인증/보안 정보 패턴들
	patterns[CategoryAuth] = []*regexp.Regexp{
		// HIGH 확실성: Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		// API Key (완벽한 패턴)
		regexp.MustCompile(`(?i)(ghp_[a-zA-Z0-9]{36})`),     // GitHub Personal Access Token
		regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9]{48})`),      // OpenAI API Key
		regexp.MustCompile(`(?i)(sk_test_[a-zA-Z0-9]{24})`), // Stripe Test Key
		regexp.MustCompile(`(?i)(sk_live_[a-zA-Z0-9]{24})`), // Stripe Live Key
		regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),        // AWS Access Key ID
		regexp.MustCompile(`(?i)(AIza[0-9A-Za-z-_]{35})`),   // Google API Key
		regexp.MustCompile(`(?i)(ya29\.[0-9A-Za-z-_]+)`),    // Google OAuth Token

		// JWT 토큰 (완벽한 패턴)
		regexp.MustCompile(`(?i)(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)`), // JWT Token

		// 세션 ID (완벽한 패턴)
		regexp.MustCompile(`(?i)(sess_[a-zA-Z0-9]{20})`),         // Session ID
		regexp.MustCompile(`(?i)(session_[a-zA-Z0-9]{20})`),      // Session ID
		regexp.MustCompile(`(?i)(PHPSESSID=[a-zA-Z0-9]{26,32})`), // PHP Session ID

		// SSH 키 (완벽한 패턴)
		regexp.MustCompile(`(?i)(ssh-rsa\s+AAAAB3NzaC1yc2E)`),           // SSH RSA Public Key
		regexp.MustCompile(`(?i)(ssh-ed25519\s+AAAAC3NzaC1lZDI1NTE5)`),  // SSH Ed25519 Public Key
		regexp.MustCompile(`(?i)(-----BEGIN OPENSSH PRIVATE KEY-----)`), // SSH Private Key
		regexp.MustCompile(`(?i)(-----BEGIN RSA PRIVATE KEY-----)`),     // RSA Private Key
		regexp.MustCompile(`(?i)(-----BEGIN PRIVATE KEY-----)`),         // Private Key

		// 클라우드 액세스 키 (완벽한 패턴)
		regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),      // AWS Access Key ID
		regexp.MustCompile(`(?i)([0-9A-Za-z+/]{40})`),     // AWS Secret Access Key
		regexp.MustCompile(`(?i)(AIza[0-9A-Za-z-_]{35})`), // Google Cloud API Key
		regexp.MustCompile(`(?i)(ya29\.[0-9A-Za-z-_]+)`),  // Google OAuth Token

		// 키워드와 함께 나오는 인증 정보 (완벽한 패턴)
		regexp.MustCompile(`(?i)(API[_-]?KEY[:]\s*[a-zA-Z0-9_-]{20,})`),       // API KEY: xxxxx
		regexp.MustCompile(`(?i)(TOKEN[:]\s*[a-zA-Z0-9_-]{20,})`),             // TOKEN: xxxxx
		regexp.MustCompile(`(?i)(SECRET[:]\s*[a-zA-Z0-9_-]{20,})`),            // SECRET: xxxxx
		regexp.MustCompile(`(?i)(ACCESS[_-]?KEY[:]\s*[a-zA-Z0-9_-]{20,})`),    // ACCESS KEY: xxxxx
		regexp.MustCompile(`(?i)(CLIENT[_-]?ID[:]\s*[a-zA-Z0-9_-]{20,})`),     // CLIENT ID: xxxxx
		regexp.MustCompile(`(?i)(CLIENT[_-]?SECRET[:]\s*[a-zA-Z0-9_-]{20,})`), // CLIENT SECRET: xxxxx

		// MEDIUM 확실성: Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		// 비밀번호 유사 패턴 (길이와 복잡성 기반)
		regexp.MustCompile(`(?i)(password[:]\s*[^\s]{8,})`), // password: mySecret123
		regexp.MustCompile(`(?i)(pwd[:]\s*[^\s]{8,})`),      // pwd: mySecret123
		regexp.MustCompile(`(?i)(pass[:]\s*[^\s]{8,})`),     // pass: mySecret123

		// OAuth 관련 키워드
		regexp.MustCompile(`(?i)(OAuth[_-]?CLIENT[_-]?ID)`),     // OAuth Client ID
		regexp.MustCompile(`(?i)(OAuth[_-]?CLIENT[_-]?SECRET)`), // OAuth Client Secret
		regexp.MustCompile(`(?i)(OAUTH[_-]?TOKEN)`),             // OAuth Token

		// 인증 관련 키워드
		regexp.MustCompile(`(?i)(AUTH[_-]?TOKEN)`),    // Auth Token
		regexp.MustCompile(`(?i)(BEARER[_-]?TOKEN)`),  // Bearer Token
		regexp.MustCompile(`(?i)(ACCESS[_-]?TOKEN)`),  // Access Token
		regexp.MustCompile(`(?i)(REFRESH[_-]?TOKEN)`), // Refresh Token

		// 클라우드 관련 키워드
		regexp.MustCompile(`(?i)(AWS[_-]?ACCESS[_-]?KEY)`),      // AWS Access Key
		regexp.MustCompile(`(?i)(AWS[_-]?SECRET[_-]?KEY)`),      // AWS Secret Key
		regexp.MustCompile(`(?i)(GCP[_-]?SERVICE[_-]?ACCOUNT)`), // GCP Service Account
		regexp.MustCompile(`(?i)(AZURE[_-]?CLIENT[_-]?ID)`),     // Azure Client ID
		regexp.MustCompile(`(?i)(AZURE[_-]?CLIENT[_-]?SECRET)`), // Azure Client Secret

		// SSH 관련 키워드
		regexp.MustCompile(`(?i)(SSH[_-]?PRIVATE[_-]?KEY)`), // SSH Private Key
		regexp.MustCompile(`(?i)(SSH[_-]?PUBLIC[_-]?KEY)`),  // SSH Public Key
		regexp.MustCompile(`(?i)(PRIVATE[_-]?KEY)`),         // Private Key
		regexp.MustCompile(`(?i)(PUBLIC[_-]?KEY)`),          // Public Key
	}

	// 내부 시스템 정보 패턴들
	patterns[CategorySystem] = []*regexp.Regexp{
		// HIGH 확실성: Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		// 내부 IP 주소 (완벽한 패턴)
		regexp.MustCompile(`(?i)(192\.168\.\d{1,3}\.\d{1,3})`),                    // 192.168.x.x
		regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3})`),                 // 10.x.x.x
		regexp.MustCompile(`(?i)(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})`), // 172.16-31.x.x
		regexp.MustCompile(`(?i)(127\.0\.0\.1)`),                                  // localhost
		regexp.MustCompile(`(?i)(::1)`),                                           // IPv6 localhost
		regexp.MustCompile(`(?i)(localhost)`),                                     // localhost

		// 포트 번호 (완벽한 패턴)
		regexp.MustCompile(`(?i)(:\d{1,5})`),                   // :포트번호
		regexp.MustCompile(`(?i)(:80|:443|:8080|:3000|:5000)`), // 일반 포트
		regexp.MustCompile(`(?i)(:3306|:5432|:6379|:27017)`),   // 데이터베이스 포트
		regexp.MustCompile(`(?i)(:22|:21|:25|:53)`),            // 서비스 포트

		// 네트워크 토폴로지 (완벽한 패턴)
		regexp.MustCompile(`(?i)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})`),            // 서브넷 CIDR
		regexp.MustCompile(`(?i)(192\.168\.\d{1,3}\.\d{1,3}/\d{1,2})`),                    // 192.168.x.x/24
		regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})`),                 // 10.x.x.x/8
		regexp.MustCompile(`(?i)(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}/\d{1,2})`), // 172.16-31.x.x/16

		// 게이트웨이 IP (완벽한 패턴)
		regexp.MustCompile(`(?i)(192\.168\.\d{1,3}\.1)`),                    // 192.168.x.1
		regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.1)`),                 // 10.x.x.1
		regexp.MustCompile(`(?i)(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.1)`), // 172.16-31.x.1

		// DNS 서버 (완벽한 패턴)
		regexp.MustCompile(`(?i)(8\.8\.8\.8)`),        // Google DNS
		regexp.MustCompile(`(?i)(1\.1\.1\.1)`),        // Cloudflare DNS
		regexp.MustCompile(`(?i)(208\.67\.222\.222)`), // OpenDNS

		// 키워드와 함께 나오는 시스템 정보 (완벽한 패턴)
		regexp.MustCompile(`(?i)(SERVER[_-]?IP[:]\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`), // SERVER IP: x.x.x.x
		regexp.MustCompile(`(?i)(DATABASE[_-]?URL[:]\s*[^\s]+)`),                          // DATABASE URL: xxxxx
		regexp.MustCompile(`(?i)(REDIS[_-]?URL[:]\s*[^\s]+)`),                             // REDIS URL: xxxxx
		regexp.MustCompile(`(?i)(MONGODB[_-]?URL[:]\s*[^\s]+)`),                           // MONGODB URL: xxxxx
		regexp.MustCompile(`(?i)(POSTGRES[_-]?URL[:]\s*[^\s]+)`),                          // POSTGRES URL: xxxxx
		regexp.MustCompile(`(?i)(MYSQL[_-]?URL[:]\s*[^\s]+)`),                             // MYSQL URL: xxxxx

		// MEDIUM 확실성: Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		// 호스트명/서버명 키워드
		regexp.MustCompile(`(?i)(server[_-]?\d+)`),    // server-01, server_01
		regexp.MustCompile(`(?i)(db[_-]?prod)`),       // db-prod, db_prod
		regexp.MustCompile(`(?i)(api[_-]?gateway)`),   // api-gateway, api_gateway
		regexp.MustCompile(`(?i)(web[_-]?server)`),    // web-server, web_server
		regexp.MustCompile(`(?i)(load[_-]?balancer)`), // load-balancer, load_balancer

		// 환경 변수 키워드
		regexp.MustCompile(`(?i)(DATABASE[_-]?HOST)`),     // DATABASE HOST
		regexp.MustCompile(`(?i)(DATABASE[_-]?PORT)`),     // DATABASE PORT
		regexp.MustCompile(`(?i)(DATABASE[_-]?NAME)`),     // DATABASE NAME
		regexp.MustCompile(`(?i)(DATABASE[_-]?USER)`),     // DATABASE USER
		regexp.MustCompile(`(?i)(DATABASE[_-]?PASSWORD)`), // DATABASE PASSWORD
		regexp.MustCompile(`(?i)(REDIS[_-]?HOST)`),        // REDIS HOST
		regexp.MustCompile(`(?i)(REDIS[_-]?PORT)`),        // REDIS PORT
		regexp.MustCompile(`(?i)(REDIS[_-]?PASSWORD)`),    // REDIS PASSWORD

		// 네트워크 관련 키워드
		regexp.MustCompile(`(?i)(INTERNAL[_-]?IP)`),   // INTERNAL IP
		regexp.MustCompile(`(?i)(PRIVATE[_-]?IP)`),    // PRIVATE IP
		regexp.MustCompile(`(?i)(SUBNET[_-]?MASK)`),   // SUBNET MASK
		regexp.MustCompile(`(?i)(GATEWAY[_-]?IP)`),    // GATEWAY IP
		regexp.MustCompile(`(?i)(DNS[_-]?SERVER)`),    // DNS SERVER
		regexp.MustCompile(`(?i)(PROXY[_-]?SERVER)`),  // PROXY SERVER
		regexp.MustCompile(`(?i)(LOAD[_-]?BALANCER)`), // LOAD BALANCER

		// 서비스 관련 키워드
		regexp.MustCompile(`(?i)(WEB[_-]?SERVER)`),    // WEB SERVER
		regexp.MustCompile(`(?i)(API[_-]?SERVER)`),    // API SERVER
		regexp.MustCompile(`(?i)(AUTH[_-]?SERVER)`),   // AUTH SERVER
		regexp.MustCompile(`(?i)(CACHE[_-]?SERVER)`),  // CACHE SERVER
		regexp.MustCompile(`(?i)(QUEUE[_-]?SERVER)`),  // QUEUE SERVER
		regexp.MustCompile(`(?i)(WORKER[_-]?SERVER)`), // WORKER SERVER

		// 인프라 관련 키워드
		regexp.MustCompile(`(?i)(KUBERNETES[_-]?CLUSTER)`), // KUBERNETES CLUSTER
		regexp.MustCompile(`(?i)(DOCKER[_-]?CONTAINER)`),   // DOCKER CONTAINER
		regexp.MustCompile(`(?i)(POD[_-]?IP)`),             // POD IP
		regexp.MustCompile(`(?i)(SERVICE[_-]?IP)`),         // SERVICE IP
		regexp.MustCompile(`(?i)(INGRESS[_-]?IP)`),         // INGRESS IP
		regexp.MustCompile(`(?i)(NODE[_-]?IP)`),            // NODE IP
	}

	return patterns
}

package processing

import (
	"mcp-gateway/internal/policy/core"
	"regexp"
)

// GetSensitiveType: 민감정보 유형 결정
func GetSensitiveType(category core.SensitiveCategory, value string) string {
	switch category {
	case core.CategoryPersonalInfo:
		if matched, _ := regexp.MatchString(`\d{6}[-]\d{7}`, value); matched {
			return "주민등록번호"
		}
		if matched, _ := regexp.MatchString(`\d{6}\s\d{7}`, value); matched {
			return "주민등록번호"
		}
		if matched, _ := regexp.MatchString(`[AM]\d{8,9}`, value); matched {
			return "여권번호"
		}
		if matched, _ := regexp.MatchString(`(?:01|11|12|13|14|15|16|17|18|19|20|21|22|23|24)[-]\d{2}[-]\d{6}[-]\d{2}`, value); matched {
			return "운전면허번호"
		}
		if matched, _ := regexp.MatchString(`010[-]\d{4}[-]\d{4}`, value); matched {
			return "휴대폰 번호"
		}
		if matched, _ := regexp.MatchString(`010\s\d{4}\s\d{4}`, value); matched {
			return "휴대폰 번호"
		}
		if matched, _ := regexp.MatchString(`010\d{8}`, value); matched {
			return "휴대폰 번호"
		}
		if matched, _ := regexp.MatchString(`02[-]\d{3,4}[-]\d{4}`, value); matched {
			return "서울 전화번호"
		}
		if matched, _ := regexp.MatchString(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, value); matched {
			return "이메일"
		}
		if matched, _ := regexp.MatchString(`\d{13}`, value); matched {
			return "13자리 숫자"
		}
		if matched, _ := regexp.MatchString(`\d{2}[-]\d{2}[-]\d{6}[-]\d{2}`, value); matched {
			return "운전면허번호 유사"
		}
		if matched, _ := regexp.MatchString(`0\d{1,2}[-]\d{3,4}[-]\d{4}`, value); matched {
			return "지역 전화번호"
		}
		if matched, _ := regexp.MatchString(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+`, value); matched {
			return "이메일 유사"
		}
		if matched, _ := regexp.MatchString(`비밀번호는\s*[^\s]{6,}`, value); matched {
			return "비밀번호 키워드"
		}
		if matched, _ := regexp.MatchString(`고객\s*DB`, value); matched {
			return "고객 DB"
		}
		if matched, _ := regexp.MatchString(`계약\s*초안`, value); matched {
			return "계약 초안"
		}
		if matched, _ := regexp.MatchString(`사내\s*문서`, value); matched {
			return "사내 문서"
		}
		return "개인정보"

	case core.CategoryFinancial:
		if matched, _ := regexp.MatchString(`\d{3}[-]\d{2,4}[-]\d{6}`, value); matched {
			return "계좌번호"
		}
		if matched, _ := regexp.MatchString(`계좌번호|은행계좌`, value); matched {
			return "계좌번호"
		}
		if matched, _ := regexp.MatchString(`\d{4}[-]\d{4}[-]\d{4}[-]\d{4}`, value); matched {
			return "카드번호"
		}
		if matched, _ := regexp.MatchString(`\d{16}`, value); matched {
			return "카드번호"
		}
		if matched, _ := regexp.MatchString(`카드번호`, value); matched {
			return "카드번호"
		}
		if matched, _ := regexp.MatchString(`CVV|CVC`, value); matched {
			return "CVV/CVC"
		}
		if matched, _ := regexp.MatchString(`\d{2}[/-.]\d{2}`, value); matched {
			return "만료일"
		}
		if matched, _ := regexp.MatchString(`만료일|expiry`, value); matched {
			return "만료일"
		}
		if matched, _ := regexp.MatchString(`계좌\s*정보`, value); matched {
			return "계좌 정보"
		}
		if matched, _ := regexp.MatchString(`카드\s*정보`, value); matched {
			return "카드 정보"
		}
		if matched, _ := regexp.MatchString(`결제\s*정보`, value); matched {
			return "결제 정보"
		}
		if matched, _ := regexp.MatchString(`금융\s*정보`, value); matched {
			return "금융 정보"
		}
		return "금융정보"

	case core.CategoryAuth:
		if matched, _ := regexp.MatchString(`ghp_[a-zA-Z0-9]{36}`, value); matched {
			return "GitHub API Key"
		}
		if matched, _ := regexp.MatchString(`sk-[a-zA-Z0-9]{48}`, value); matched {
			return "OpenAI API Key"
		}
		if matched, _ := regexp.MatchString(`sk_test_[a-zA-Z0-9]{24}`, value); matched {
			return "Stripe Test Key"
		}
		if matched, _ := regexp.MatchString(`sk_live_[a-zA-Z0-9]{24}`, value); matched {
			return "Stripe Live Key"
		}
		if matched, _ := regexp.MatchString(`AKIA[0-9A-Z]{16}`, value); matched {
			return "AWS Access Key"
		}
		if matched, _ := regexp.MatchString(`AIza[0-9A-Za-z-_]{35}`, value); matched {
			return "Google API Key"
		}
		if matched, _ := regexp.MatchString(`ya29\.[0-9A-Za-z-_]+`, value); matched {
			return "Google OAuth Token"
		}
		if matched, _ := regexp.MatchString(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`, value); matched {
			return "JWT Token"
		}
		if matched, _ := regexp.MatchString(`sess_[a-zA-Z0-9]{20}`, value); matched {
			return "Session ID"
		}
		if matched, _ := regexp.MatchString(`session_[a-zA-Z0-9]{20}`, value); matched {
			return "Session ID"
		}
		if matched, _ := regexp.MatchString(`PHPSESSID=[a-zA-Z0-9]{26,32}`, value); matched {
			return "PHP Session ID"
		}
		if matched, _ := regexp.MatchString(`ssh-rsa\s+AAAAB3NzaC1yc2E`, value); matched {
			return "SSH RSA Public Key"
		}
		if matched, _ := regexp.MatchString(`ssh-ed25519\s+AAAAC3NzaC1lZDI1NTE5`, value); matched {
			return "SSH Ed25519 Public Key"
		}
		if matched, _ := regexp.MatchString(`-----BEGIN OPENSSH PRIVATE KEY-----`, value); matched {
			return "SSH Private Key"
		}
		if matched, _ := regexp.MatchString(`-----BEGIN RSA PRIVATE KEY-----`, value); matched {
			return "RSA Private Key"
		}
		if matched, _ := regexp.MatchString(`-----BEGIN PRIVATE KEY-----`, value); matched {
			return "Private Key"
		}
		if matched, _ := regexp.MatchString(`API[_-]?KEY[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return "API Key"
		}
		if matched, _ := regexp.MatchString(`TOKEN[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return "Token"
		}
		if matched, _ := regexp.MatchString(`SECRET[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return "Secret"
		}
		if matched, _ := regexp.MatchString(`ACCESS[_-]?KEY[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return "Access Key"
		}
		if matched, _ := regexp.MatchString(`CLIENT[_-]?ID[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return "Client ID"
		}
		if matched, _ := regexp.MatchString(`CLIENT[_-]?SECRET[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return "Client Secret"
		}
		if matched, _ := regexp.MatchString(`password[:]\s*[^\s]{8,}`, value); matched {
			return "Password"
		}
		if matched, _ := regexp.MatchString(`pwd[:]\s*[^\s]{8,}`, value); matched {
			return "Password"
		}
		if matched, _ := regexp.MatchString(`pass[:]\s*[^\s]{8,}`, value); matched {
			return "Password"
		}
		if matched, _ := regexp.MatchString(`OAuth[_-]?CLIENT[_-]?ID`, value); matched {
			return "OAuth Client ID"
		}
		if matched, _ := regexp.MatchString(`OAuth[_-]?CLIENT[_-]?SECRET`, value); matched {
			return "OAuth Client Secret"
		}
		if matched, _ := regexp.MatchString(`OAUTH[_-]?TOKEN`, value); matched {
			return "OAuth Token"
		}
		if matched, _ := regexp.MatchString(`AUTH[_-]?TOKEN`, value); matched {
			return "Auth Token"
		}
		if matched, _ := regexp.MatchString(`BEARER[_-]?TOKEN`, value); matched {
			return "Bearer Token"
		}
		if matched, _ := regexp.MatchString(`ACCESS[_-]?TOKEN`, value); matched {
			return "Access Token"
		}
		if matched, _ := regexp.MatchString(`REFRESH[_-]?TOKEN`, value); matched {
			return "Refresh Token"
		}
		if matched, _ := regexp.MatchString(`AWS[_-]?ACCESS[_-]?KEY`, value); matched {
			return "AWS Access Key"
		}
		if matched, _ := regexp.MatchString(`AWS[_-]?SECRET[_-]?KEY`, value); matched {
			return "AWS Secret Key"
		}
		if matched, _ := regexp.MatchString(`GCP[_-]?SERVICE[_-]?ACCOUNT`, value); matched {
			return "GCP Service Account"
		}
		if matched, _ := regexp.MatchString(`AZURE[_-]?CLIENT[_-]?ID`, value); matched {
			return "Azure Client ID"
		}
		if matched, _ := regexp.MatchString(`AZURE[_-]?CLIENT[_-]?SECRET`, value); matched {
			return "Azure Client Secret"
		}
		if matched, _ := regexp.MatchString(`SSH[_-]?PRIVATE[_-]?KEY`, value); matched {
			return "SSH Private Key"
		}
		if matched, _ := regexp.MatchString(`SSH[_-]?PUBLIC[_-]?KEY`, value); matched {
			return "SSH Public Key"
		}
		if matched, _ := regexp.MatchString(`PRIVATE[_-]?KEY`, value); matched {
			return "Private Key"
		}
		if matched, _ := regexp.MatchString(`PUBLIC[_-]?KEY`, value); matched {
			return "Public Key"
		}
		return "인증정보"

	case core.CategorySystem:
		if matched, _ := regexp.MatchString(`192\.168\.\d{1,3}\.\d{1,3}`, value); matched {
			return "내부 IP (192.168.x.x)"
		}
		if matched, _ := regexp.MatchString(`10\.\d{1,3}\.\d{1,3}\.\d{1,3}`, value); matched {
			return "내부 IP (10.x.x.x)"
		}
		if matched, _ := regexp.MatchString(`172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}`, value); matched {
			return "내부 IP (172.16-31.x.x)"
		}
		if matched, _ := regexp.MatchString(`127\.0\.0\.1`, value); matched {
			return "Localhost IP"
		}
		if matched, _ := regexp.MatchString(`::1`, value); matched {
			return "IPv6 Localhost"
		}
		if matched, _ := regexp.MatchString(`localhost`, value); matched {
			return "Localhost"
		}
		if matched, _ := regexp.MatchString(`:\d{1,5}`, value); matched {
			return "포트 번호"
		}
		if matched, _ := regexp.MatchString(`:80|:443|:8080|:3000|:5000`, value); matched {
			return "웹 포트"
		}
		if matched, _ := regexp.MatchString(`:3306|:5432|:6379|:27017`, value); matched {
			return "데이터베이스 포트"
		}
		if matched, _ := regexp.MatchString(`:22|:21|:25|:53`, value); matched {
			return "시스템 포트"
		}
		if matched, _ := regexp.MatchString(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}`, value); matched {
			return "서브넷 CIDR"
		}
		if matched, _ := regexp.MatchString(`192\.168\.\d{1,3}\.\d{1,3}/\d{1,2}`, value); matched {
			return "내부 서브넷 (192.168.x.x/24)"
		}
		if matched, _ := regexp.MatchString(`10\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}`, value); matched {
			return "내부 서브넷 (10.x.x.x/8)"
		}
		if matched, _ := regexp.MatchString(`172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}/\d{1,2}`, value); matched {
			return "내부 서브넷 (172.16-31.x.x/16)"
		}
		if matched, _ := regexp.MatchString(`192\.168\.\d{1,3}\.1`, value); matched {
			return "게이트웨이 IP (192.168.x.1)"
		}
		if matched, _ := regexp.MatchString(`10\.\d{1,3}\.\d{1,3}\.1`, value); matched {
			return "게이트웨이 IP (10.x.x.1)"
		}
		if matched, _ := regexp.MatchString(`172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.1`, value); matched {
			return "게이트웨이 IP (172.16-31.x.1)"
		}
		if matched, _ := regexp.MatchString(`8\.8\.8\.8`, value); matched {
			return "Google DNS"
		}
		if matched, _ := regexp.MatchString(`1\.1\.1\.1`, value); matched {
			return "Cloudflare DNS"
		}
		if matched, _ := regexp.MatchString(`208\.67\.222\.222`, value); matched {
			return "OpenDNS"
		}
		if matched, _ := regexp.MatchString(`SERVER[_-]?IP[:]\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, value); matched {
			return "서버 IP"
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?URL[:]\s*[^\s]+`, value); matched {
			return "데이터베이스 URL"
		}
		if matched, _ := regexp.MatchString(`REDIS[_-]?URL[:]\s*[^\s]+`, value); matched {
			return "Redis URL"
		}
		if matched, _ := regexp.MatchString(`MONGODB[_-]?URL[:]\s*[^\s]+`, value); matched {
			return "MongoDB URL"
		}
		if matched, _ := regexp.MatchString(`POSTGRES[_-]?URL[:]\s*[^\s]+`, value); matched {
			return "PostgreSQL URL"
		}
		if matched, _ := regexp.MatchString(`MYSQL[_-]?URL[:]\s*[^\s]+`, value); matched {
			return "MySQL URL"
		}
		if matched, _ := regexp.MatchString(`server[_-]?\d+`, value); matched {
			return "서버 호스트명"
		}
		if matched, _ := regexp.MatchString(`db[_-]?prod`, value); matched {
			return "데이터베이스 호스트명"
		}
		if matched, _ := regexp.MatchString(`api[_-]?gateway`, value); matched {
			return "API 게이트웨이 호스트명"
		}
		if matched, _ := regexp.MatchString(`web[_-]?server`, value); matched {
			return "웹 서버 호스트명"
		}
		if matched, _ := regexp.MatchString(`load[_-]?balancer`, value); matched {
			return "로드밸런서 호스트명"
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?HOST`, value); matched {
			return "데이터베이스 호스트"
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?PORT`, value); matched {
			return "데이터베이스 포트"
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?NAME`, value); matched {
			return "데이터베이스 이름"
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?USER`, value); matched {
			return "데이터베이스 사용자"
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?PASSWORD`, value); matched {
			return "데이터베이스 비밀번호"
		}
		if matched, _ := regexp.MatchString(`REDIS[_-]?HOST`, value); matched {
			return "Redis 호스트"
		}
		if matched, _ := regexp.MatchString(`REDIS[_-]?PORT`, value); matched {
			return "Redis 포트"
		}
		if matched, _ := regexp.MatchString(`REDIS[_-]?PASSWORD`, value); matched {
			return "Redis 비밀번호"
		}
		if matched, _ := regexp.MatchString(`INTERNAL[_-]?IP`, value); matched {
			return "내부 IP"
		}
		if matched, _ := regexp.MatchString(`PRIVATE[_-]?IP`, value); matched {
			return "프라이빗 IP"
		}
		if matched, _ := regexp.MatchString(`SUBNET[_-]?MASK`, value); matched {
			return "서브넷 마스크"
		}
		if matched, _ := regexp.MatchString(`GATEWAY[_-]?IP`, value); matched {
			return "게이트웨이 IP"
		}
		if matched, _ := regexp.MatchString(`DNS[_-]?SERVER`, value); matched {
			return "DNS 서버"
		}
		if matched, _ := regexp.MatchString(`PROXY[_-]?SERVER`, value); matched {
			return "프록시 서버"
		}
		if matched, _ := regexp.MatchString(`LOAD[_-]?BALANCER`, value); matched {
			return "로드밸런서"
		}
		if matched, _ := regexp.MatchString(`WEB[_-]?SERVER`, value); matched {
			return "웹 서버"
		}
		if matched, _ := regexp.MatchString(`API[_-]?SERVER`, value); matched {
			return "API 서버"
		}
		if matched, _ := regexp.MatchString(`AUTH[_-]?SERVER`, value); matched {
			return "인증 서버"
		}
		if matched, _ := regexp.MatchString(`CACHE[_-]?SERVER`, value); matched {
			return "캐시 서버"
		}
		if matched, _ := regexp.MatchString(`QUEUE[_-]?SERVER`, value); matched {
			return "큐 서버"
		}
		if matched, _ := regexp.MatchString(`WORKER[_-]?SERVER`, value); matched {
			return "워커 서버"
		}
		if matched, _ := regexp.MatchString(`KUBERNETES[_-]?CLUSTER`, value); matched {
			return "Kubernetes 클러스터"
		}
		if matched, _ := regexp.MatchString(`DOCKER[_-]?CONTAINER`, value); matched {
			return "Docker 컨테이너"
		}
		if matched, _ := regexp.MatchString(`POD[_-]?IP`, value); matched {
			return "Pod IP"
		}
		if matched, _ := regexp.MatchString(`SERVICE[_-]?IP`, value); matched {
			return "Service IP"
		}
		if matched, _ := regexp.MatchString(`INGRESS[_-]?IP`, value); matched {
			return "Ingress IP"
		}
		if matched, _ := regexp.MatchString(`NODE[_-]?IP`, value); matched {
			return "Node IP"
		}
		return "시스템정보"

	default:
		return "기타"
	}
}

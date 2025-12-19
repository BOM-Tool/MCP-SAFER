package processing

import (
	"mcp-gateway/internal/policy/core"
	"regexp"
)

// GetConfidenceLevel: 패턴과 값에 따라 확실성 수준 결정
func GetConfidenceLevel(category core.SensitiveCategory, value string) core.ConfidenceLevel {
	switch category {
	case core.CategoryPersonalInfo:
		// HIGH: Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		if matched, _ := regexp.MatchString(`\d{6}[-]\d{7}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`\d{6}\s\d{7}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`[AM]\d{8,9}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`(?:01|11|12|13|14|15|16|17|18|19|20|21|22|23|24)[-]\d{2}[-]\d{6}[-]\d{2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`010[-]\d{4}[-]\d{4}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`010\s\d{4}\s\d{4}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`010\d{8}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`02[-]\d{3,4}[-]\d{4}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, value); matched {
			return core.High
		}

		// MEDIUM: Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		if matched, _ := regexp.MatchString(`\d{13}`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`\d{2}[-]\d{2}[-]\d{6}[-]\d{2}`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`0\d{1,2}[-]\d{3,4}[-]\d{4}`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`비밀번호는\s*[^\s]{6,}`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`고객\s*DB`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`계약\s*초안`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`사내\s*문서`, value); matched {
			return core.Medium
		}
		return core.Low

	case core.CategoryFinancial:
		// HIGH: Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		if matched, _ := regexp.MatchString(`\d{3}[-]\d{2,4}[-]\d{6}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`\d{3}\s\d{2,4}\s\d{6}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`\d{4}[-]\d{4}[-]\d{4}[-]\d{4}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`\d{4}\s\d{4}\s\d{4}\s\d{4}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`CVV[:]\s*\d{3,4}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`CVC[:]\s*\d{3,4}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`\d{2}[/]\d{2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`\d{2}[-]\d{2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`\d{2}[.]\d{2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`\d{2}\s\d{2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`계좌번호[:]\s*\d{3}[-]\d{2,4}[-]\d{6}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`카드번호[:]\s*\d{4}[-]\d{4}[-]\d{4}[-]\d{4}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`은행계좌[:]\s*\d{3}[-]\d{2,4}[-]\d{6}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`만료일[:]\s*\d{2}[/-.]\d{2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`expiry[:]\s*\d{2}[/-.]\d{2}`, value); matched {
			return core.High
		}

		// MEDIUM: Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		if matched, _ := regexp.MatchString(`\d{16}`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`\b\d{3,4}\b`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`계좌\s*정보`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`카드\s*정보`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`결제\s*정보`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`금융\s*정보`, value); matched {
			return core.Medium
		}
		return core.Low

	case core.CategoryAuth:
		// HIGH: Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		if matched, _ := regexp.MatchString(`ghp_[a-zA-Z0-9]{36}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`sk-[a-zA-Z0-9]{48}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`sk_test_[a-zA-Z0-9]{24}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`sk_live_[a-zA-Z0-9]{24}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`AKIA[0-9A-Z]{16}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`AIza[0-9A-Za-z-_]{35}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`ya29\.[0-9A-Za-z-_]+`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`sess_[a-zA-Z0-9]{20}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`session_[a-zA-Z0-9]{20}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`PHPSESSID=[a-zA-Z0-9]{26,32}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`ssh-rsa\s+AAAAB3NzaC1yc2E`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`ssh-ed25519\s+AAAAC3NzaC1lZDI1NTE5`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`-----BEGIN OPENSSH PRIVATE KEY-----`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`-----BEGIN RSA PRIVATE KEY-----`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`-----BEGIN PRIVATE KEY-----`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`API[_-]?KEY[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`TOKEN[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`SECRET[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`ACCESS[_-]?KEY[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`CLIENT[_-]?ID[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`CLIENT[_-]?SECRET[:]\s*[a-zA-Z0-9_-]{20,}`, value); matched {
			return core.High
		}

		// MEDIUM: Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		if matched, _ := regexp.MatchString(`password[:]\s*[^\s]{8,}`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`pwd[:]\s*[^\s]{8,}`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`pass[:]\s*[^\s]{8,}`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`OAuth[_-]?CLIENT[_-]?ID`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`OAuth[_-]?CLIENT[_-]?SECRET`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`OAUTH[_-]?TOKEN`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`AUTH[_-]?TOKEN`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`BEARER[_-]?TOKEN`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`ACCESS[_-]?TOKEN`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`REFRESH[_-]?TOKEN`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`AWS[_-]?ACCESS[_-]?KEY`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`AWS[_-]?SECRET[_-]?KEY`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`GCP[_-]?SERVICE[_-]?ACCOUNT`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`AZURE[_-]?CLIENT[_-]?ID`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`AZURE[_-]?CLIENT[_-]?SECRET`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`SSH[_-]?PRIVATE[_-]?KEY`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`SSH[_-]?PUBLIC[_-]?KEY`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`PRIVATE[_-]?KEY`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`PUBLIC[_-]?KEY`, value); matched {
			return core.Medium
		}
		return core.Low

	case core.CategorySystem:
		// HIGH: Regex 완벽 일치 → 즉시 마스킹/차단 → 모델 X
		if matched, _ := regexp.MatchString(`192\.168\.\d{1,3}\.\d{1,3}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`10\.\d{1,3}\.\d{1,3}\.\d{1,3}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`127\.0\.0\.1`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`::1`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`localhost`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`:\d{1,5}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`:80|:443|:8080|:3000|:5000`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`:3306|:5432|:6379|:27017`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`:22|:21|:25|:53`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`192\.168\.\d{1,3}\.\d{1,3}/\d{1,2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`10\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}/\d{1,2}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`192\.168\.\d{1,3}\.1`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`10\.\d{1,3}\.\d{1,3}\.1`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.1`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`8\.8\.8\.8`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`1\.1\.1\.1`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`208\.67\.222\.222`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`SERVER[_-]?IP[:]\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?URL[:]\s*[^\s]+`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`REDIS[_-]?URL[:]\s*[^\s]+`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`MONGODB[_-]?URL[:]\s*[^\s]+`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`POSTGRES[_-]?URL[:]\s*[^\s]+`, value); matched {
			return core.High
		}
		if matched, _ := regexp.MatchString(`MYSQL[_-]?URL[:]\s*[^\s]+`, value); matched {
			return core.High
		}

		// MEDIUM: Regex 유사 패턴/키워드 포함 → DLP 모델 호출 → 추가 판단
		if matched, _ := regexp.MatchString(`server[_-]?\d+`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`db[_-]?prod`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`api[_-]?gateway`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`web[_-]?server`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`load[_-]?balancer`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?HOST`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?PORT`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?NAME`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?USER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`DATABASE[_-]?PASSWORD`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`REDIS[_-]?HOST`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`REDIS[_-]?PORT`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`REDIS[_-]?PASSWORD`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`INTERNAL[_-]?IP`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`PRIVATE[_-]?IP`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`SUBNET[_-]?MASK`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`GATEWAY[_-]?IP`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`DNS[_-]?SERVER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`PROXY[_-]?SERVER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`LOAD[_-]?BALANCER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`WEB[_-]?SERVER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`API[_-]?SERVER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`AUTH[_-]?SERVER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`CACHE[_-]?SERVER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`QUEUE[_-]?SERVER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`WORKER[_-]?SERVER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`KUBERNETES[_-]?CLUSTER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`DOCKER[_-]?CONTAINER`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`POD[_-]?IP`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`SERVICE[_-]?IP`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`INGRESS[_-]?IP`, value); matched {
			return core.Medium
		}
		if matched, _ := regexp.MatchString(`NODE[_-]?IP`, value); matched {
			return core.Medium
		}
		return core.Low

	default:
		return core.Low
	}
}

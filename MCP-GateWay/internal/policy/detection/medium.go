package detection

import (
	"fmt"
	"mcp-gateway/internal/policy/core"
	"regexp"
)

// DetectMediumConfidenceInfo: MEDIUM 확실성 민감정보 탐지
// HIGH는 확실하지만 MEDIUM은 추가 검증이 필요한 패턴들
func DetectMediumConfidenceInfo(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo

	// 개인정보 - MEDIUM 확실성
	personalMedium := detectPersonalMedium(text)
	detected = append(detected, personalMedium...)

	// 금융정보 - MEDIUM 확실성
	financialMedium := detectFinancialMedium(text)
	detected = append(detected, financialMedium...)

	// 인증정보 - MEDIUM 확실성
	authMedium := detectAuthMedium(text)
	detected = append(detected, authMedium...)

	// 시스템정보 - MEDIUM 확실성
	systemMedium := detectSystemMedium(text)
	detected = append(detected, systemMedium...)

	// 중복 제거: 같은 위치의 탐지 제거
	return removeDuplicateDetections(detected)
}

// DetectMediumConfidenceInfoWithExclusion: HIGH와 겹치지 않는 MEDIUM 확실성 탐지
func DetectMediumConfidenceInfoWithExclusion(text string, highPositions map[int]int) []core.SensitiveInfo {
	var detected []core.SensitiveInfo

	// 개인정보 - MEDIUM 확실성 (HIGH 제외)
	personalMedium := detectPersonalMediumWithExclusion(text, highPositions)
	detected = append(detected, personalMedium...)

	// 금융정보 - MEDIUM 확실성 (HIGH 제외)
	financialMedium := detectFinancialMediumWithExclusion(text, highPositions)
	detected = append(detected, financialMedium...)

	// 인증정보 - MEDIUM 확실성 (HIGH 제외)
	authMedium := detectAuthMediumWithExclusion(text, highPositions)
	detected = append(detected, authMedium...)

	// 시스템정보 - MEDIUM 확실성 (HIGH 제외)
	systemMedium := detectSystemMediumWithExclusion(text, highPositions)
	detected = append(detected, systemMedium...)

	// 중복 제거: 같은 위치의 탐지 제거
	return removeDuplicateDetections(detected)
}

// removeDuplicateDetections: 중복 탐지 제거 (같은 위치의 탐지 제거)
func removeDuplicateDetections(detections []core.SensitiveInfo) []core.SensitiveInfo {
	seen := make(map[string]bool)
	var result []core.SensitiveInfo
	
	for _, det := range detections {
		// 위치와 값으로 중복 확인
		key := fmt.Sprintf("%d-%s", det.Position, det.Value)
		if !seen[key] {
			seen[key] = true
			result = append(result, det)
		}
	}
	
	return result
}

// detectPersonalMedium: 개인정보 MEDIUM 확실성 탐지
func detectPersonalMedium(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo

	// 1. 전화번호 - 하이픈 없는 11자리 숫자 (01012345678)
	phoneNoHyphenPattern := regexp.MustCompile(`010\d{8}`)
	if matches := phoneNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryPersonalInfo,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    value,
				Position: match[0],
			})
		}
	}

	// 2. 전화번호 - 공백으로 구분된 형태 (010 1234 5678)
	phoneSpacePattern := regexp.MustCompile(`010\s\d{4}\s\d{4}`)
	if matches := phoneSpacePattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryPersonalInfo,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    value,
				Position: match[0],
			})
		}
	}

	// 3. 지역번호 전화번호 - 하이픈 없는 형태 (0212345678)
	regionPhonePattern := regexp.MustCompile(`0\d{1,2}\d{7,8}`)
	if matches := regionPhonePattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			// 010으로 시작하지 않는 지역번호만
			if !regexp.MustCompile(`^010`).MatchString(value) {
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 4. 주민등록번호 - 하이픈 없는 13자리 숫자
	rrnNoHyphenPattern := regexp.MustCompile(`\d{13}`)
	if matches := rrnNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryPersonalInfo,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    value,
				Position: match[0],
			})
		}
	}

	// 5. 이메일 - 도메인 없는 형태 (user@domain)
	emailNoDomainPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+`)
	if matches := emailNoDomainPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			// .com, .co.kr 등이 없는 경우만
			if !regexp.MustCompile(`\.[a-zA-Z]{2,}$`).MatchString(value) {
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 6. 여권번호 - 하이픈 없는 형태 (M12345678)
	passportNoHyphenPattern := regexp.MustCompile(`[AM]\d{8,9}`)
	if matches := passportNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryPersonalInfo,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    value,
				Position: match[0],
			})
		}
	}

	// 7. 운전면허번호 - 하이픈 없는 형태 (123456789012)
	licenseNoHyphenPattern := regexp.MustCompile(`\d{12}`)
	if matches := licenseNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryPersonalInfo,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    value,
				Position: match[0],
			})
		}
	}

	return detected
}

// detectPersonalMediumWithExclusion: 개인정보 MEDIUM 확실성 탐지 (HIGH 제외)
func detectPersonalMediumWithExclusion(text string, highPositions map[int]int) []core.SensitiveInfo {
	var detected []core.SensitiveInfo

	// 1. 전화번호 - 하이픈 없는 11자리 숫자 (01012345678)
	phoneNoHyphenPattern := regexp.MustCompile(`010\d{8}`)
	if matches := phoneNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			// HIGH와 겹치는지 확인
			if !isOverlappingWithHigh(match[0], match[1], highPositions) {
				value := text[match[0]:match[1]]
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 2. 전화번호 - 공백으로 구분된 형태 (010 1234 5678)
	phoneSpacePattern := regexp.MustCompile(`010\s\d{4}\s\d{4}`)
	if matches := phoneSpacePattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			if !isOverlappingWithHigh(match[0], match[1], highPositions) {
				value := text[match[0]:match[1]]
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 3. 지역번호 전화번호 - 하이픈 없는 형태 (0212345678)
	regionPhonePattern := regexp.MustCompile(`0\d{1,2}\d{7,8}`)
	if matches := regionPhonePattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			// 010으로 시작하지 않는 지역번호만
			if !regexp.MustCompile(`^010`).MatchString(value) && !isOverlappingWithHigh(match[0], match[1], highPositions) {
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 4. 주민등록번호 - 하이픈 없는 13자리 숫자
	rrnNoHyphenPattern := regexp.MustCompile(`\d{13}`)
	if matches := rrnNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			if !isOverlappingWithHigh(match[0], match[1], highPositions) {
				value := text[match[0]:match[1]]
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 5. 이메일 - 도메인 없는 형태 (user@domain)
	emailNoDomainPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+`)
	if matches := emailNoDomainPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			// .com, .co.kr 등이 없는 경우만
			if !regexp.MustCompile(`\.[a-zA-Z]{2,}$`).MatchString(value) && !isOverlappingWithHigh(match[0], match[1], highPositions) {
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 6. 여권번호 - 하이픈 없는 형태 (M12345678)
	passportNoHyphenPattern := regexp.MustCompile(`[AM]\d{8,9}`)
	if matches := passportNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			if !isOverlappingWithHigh(match[0], match[1], highPositions) {
				value := text[match[0]:match[1]]
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 7. 운전면허번호 - 하이픈 없는 형태 (123456789012)
	licenseNoHyphenPattern := regexp.MustCompile(`\d{12}`)
	if matches := licenseNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			if !isOverlappingWithHigh(match[0], match[1], highPositions) {
				value := text[match[0]:match[1]]
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryPersonalInfo,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	return detected
}

// isOverlappingWithHigh: HIGH 탐지 영역과 겹치는지 확인
func isOverlappingWithHigh(start, end int, highPositions map[int]int) bool {
	for i := start; i < end; i++ {
		if highPositions[i] == 1 {
			return true
		}
	}
	return false
}

// detectFinancialMedium: 금융정보 MEDIUM 확실성 탐지
func detectFinancialMedium(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo

	// 1. 카드번호 - 하이픈 없는 16자리 숫자
	cardNoHyphenPattern := regexp.MustCompile(`\d{16}`)
	if matches := cardNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryFinancial,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    value,
				Position: match[0],
			})
		}
	}

	// 2. 계좌번호 - 하이픈 없는 형태 (123456789012)
	accountNoHyphenPattern := regexp.MustCompile(`\d{10,15}`)
	if matches := accountNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			// 16자리가 아닌 경우만 (카드번호와 구분)
			if len(value) != 16 {
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategoryFinancial,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 3. CVV - 3-4자리 숫자만
	cvvOnlyPattern := regexp.MustCompile(`\b\d{3,4}\b`)
	if matches := cvvOnlyPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryFinancial,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    value,
				Position: match[0],
			})
		}
	}

	// 4. 만료일 - 하이픈 없는 형태 (1225)
	expiryNoHyphenPattern := regexp.MustCompile(`\d{4}`)
	if matches := expiryNoHyphenPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			// MM/YY 형태로 해석 가능한 4자리
			if len(value) == 4 {
				month := value[:2]
				year := value[2:]
				if month >= "01" && month <= "12" && year >= "00" && year <= "99" {
					detected = append(detected, core.SensitiveInfo{
						Category: core.CategoryFinancial,
						Level:    core.Medium,
						Type:     "불명확",
						Value:    value,
						Position: match[0],
					})
				}
			}
		}
	}

	// 5. 금융 관련 키워드
	financialKeywords := []string{
		"계좌정보", "카드정보", "결제정보", "금융정보", "은행계좌", "신용카드", "체크카드",
		"계좌번호", "카드번호", "비밀번호", "PIN번호", "OTP", "인증번호",
	}
	
	for _, keyword := range financialKeywords {
		if regexp.MustCompile(keyword).MatchString(text) {
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryFinancial,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    keyword,
				Position: regexp.MustCompile(keyword).FindStringIndex(text)[0],
			})
		}
	}

	return detected
}

// detectAuthMedium: 인증정보 MEDIUM 확실성 탐지
func detectAuthMedium(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo

	// 1. 비밀번호 관련 키워드
	passwordKeywords := []string{
		"비밀번호", "패스워드", "password", "pwd", "pass", "비번",
		"암호", "secret", "key", "token", "인증키", "API키",
	}
	
	for _, keyword := range passwordKeywords {
		if regexp.MustCompile(keyword).MatchString(text) {
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryAuth,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    keyword,
				Position: regexp.MustCompile(keyword).FindStringIndex(text)[0],
			})
		}
	}

	// 2. OAuth 관련 키워드
	oauthKeywords := []string{
		"OAuth", "OAUTH", "oauth", "client_id", "client_secret", "access_token",
		"refresh_token", "bearer_token", "jwt", "JWT", "토큰", "세션",
	}
	
	for _, keyword := range oauthKeywords {
		if regexp.MustCompile(keyword).MatchString(text) {
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryAuth,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    keyword,
				Position: regexp.MustCompile(keyword).FindStringIndex(text)[0],
			})
		}
	}

	// 3. 클라우드 서비스 키워드
	cloudKeywords := []string{
		"AWS", "GCP", "Azure", "Google Cloud", "Amazon Web Services",
		"access_key", "secret_key", "service_account", "credentials",
		"API_KEY", "SECRET_KEY", "ACCESS_KEY", "CLIENT_ID", "CLIENT_SECRET",
	}
	
	for _, keyword := range cloudKeywords {
		if regexp.MustCompile(keyword).MatchString(text) {
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryAuth,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    keyword,
				Position: regexp.MustCompile(keyword).FindStringIndex(text)[0],
			})
		}
	}

	// 4. SSH 관련 키워드
	sshKeywords := []string{
		"ssh", "SSH", "private_key", "public_key", "id_rsa", "id_ed25519",
		"-----BEGIN", "-----END", "RSA", "DSA", "ECDSA", "ED25519",
	}
	
	for _, keyword := range sshKeywords {
		if regexp.MustCompile(keyword).MatchString(text) {
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategoryAuth,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    keyword,
				Position: regexp.MustCompile(keyword).FindStringIndex(text)[0],
			})
		}
	}

	return detected
}

// detectSystemMedium: 시스템정보 MEDIUM 확실성 탐지
func detectSystemMedium(text string) []core.SensitiveInfo {
	var detected []core.SensitiveInfo

	// 1. IP 주소 - 하이픈 없는 형태 (1921681100)
	ipNoDotPattern := regexp.MustCompile(`\d{10,11}`)
	if matches := ipNoDotPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			// 10-11자리 숫자 (IP 주소로 해석 가능)
			if len(value) >= 10 && len(value) <= 11 {
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategorySystem,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 2. 포트 번호 - 4-5자리 숫자
	portPattern := regexp.MustCompile(`\d{4,5}`)
	if matches := portPattern.FindAllStringIndex(text, -1); matches != nil {
		for _, match := range matches {
			value := text[match[0]:match[1]]
			// 4-5자리 포트 번호
			if len(value) >= 4 && len(value) <= 5 {
				detected = append(detected, core.SensitiveInfo{
					Category: core.CategorySystem,
					Level:    core.Medium,
					Type:     "불명확",
					Value:    value,
					Position: match[0],
				})
			}
		}
	}

	// 3. 시스템 관련 키워드
	systemKeywords := []string{
		"서버", "server", "SERVER", "데이터베이스", "database", "DATABASE",
		"DB", "db", "Redis", "REDIS", "MongoDB", "MONGODB", "MySQL", "MYSQL",
		"PostgreSQL", "POSTGRES", "내부", "internal", "INTERNAL", "사내",
		"로컬", "local", "LOCAL", "개발", "dev", "DEV", "테스트", "test", "TEST",
	}
	
	for _, keyword := range systemKeywords {
		if regexp.MustCompile(keyword).MatchString(text) {
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategorySystem,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    keyword,
				Position: regexp.MustCompile(keyword).FindStringIndex(text)[0],
			})
		}
	}

	// 4. 네트워크 관련 키워드
	networkKeywords := []string{
		"네트워크", "network", "NETWORK", "라우터", "router", "ROUTER",
		"스위치", "switch", "SWITCH", "게이트웨이", "gateway", "GATEWAY",
		"방화벽", "firewall", "FIREWALL", "프록시", "proxy", "PROXY",
		"로드밸런서", "loadbalancer", "LOADBALANCER", "클러스터", "cluster", "CLUSTER",
	}
	
	for _, keyword := range networkKeywords {
		if regexp.MustCompile(keyword).MatchString(text) {
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategorySystem,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    keyword,
				Position: regexp.MustCompile(keyword).FindStringIndex(text)[0],
			})
		}
	}

	// 5. 컨테이너/클라우드 관련 키워드
	containerKeywords := []string{
		"도커", "docker", "DOCKER", "컨테이너", "container", "CONTAINER",
		"쿠버네티스", "kubernetes", "KUBERNETES", "k8s", "K8S",
		"파드", "pod", "POD", "서비스", "service", "SERVICE",
		"인그레스", "ingress", "INGRESS", "노드", "node", "NODE",
	}
	
	for _, keyword := range containerKeywords {
		if regexp.MustCompile(keyword).MatchString(text) {
			detected = append(detected, core.SensitiveInfo{
				Category: core.CategorySystem,
				Level:    core.Medium,
				Type:     "불명확",
				Value:    keyword,
				Position: regexp.MustCompile(keyword).FindStringIndex(text)[0],
			})
		}
	}

	return detected
}

// detectFinancialMediumWithExclusion: 금융정보 MEDIUM 확실성 탐지 (HIGH 제외)
func detectFinancialMediumWithExclusion(text string, highPositions map[int]int) []core.SensitiveInfo {
	var detected []core.SensitiveInfo
	// HIGH와 겹치지 않는 부분만 탐지
	financialMedium := detectFinancialMedium(text)
	for _, info := range financialMedium {
		if !isOverlappingWithHigh(info.Position, info.Position+len(info.Value), highPositions) {
			detected = append(detected, info)
		}
	}
	return detected
}

// detectAuthMediumWithExclusion: 인증정보 MEDIUM 확실성 탐지 (HIGH 제외)
func detectAuthMediumWithExclusion(text string, highPositions map[int]int) []core.SensitiveInfo {
	var detected []core.SensitiveInfo
	// HIGH와 겹치지 않는 부분만 탐지
	authMedium := detectAuthMedium(text)
	for _, info := range authMedium {
		if !isOverlappingWithHigh(info.Position, info.Position+len(info.Value), highPositions) {
			detected = append(detected, info)
		}
	}
	return detected
}

// detectSystemMediumWithExclusion: 시스템정보 MEDIUM 확실성 탐지 (HIGH 제외)
func detectSystemMediumWithExclusion(text string, highPositions map[int]int) []core.SensitiveInfo {
	var detected []core.SensitiveInfo
	// HIGH와 겹치지 않는 부분만 탐지
	systemMedium := detectSystemMedium(text)
	for _, info := range systemMedium {
		if !isOverlappingWithHigh(info.Position, info.Position+len(info.Value), highPositions) {
			detected = append(detected, info)
		}
	}
	return detected
}
package processing

import (
	"log"
	"regexp"
	"strings"
)

// MaskPersonalInfo: 개인정보 마스킹 처리
func MaskPersonalInfo(text string) string {
	//log.Printf("MaskPersonalInfo called with: %s", text)
	masked := text

	// 주민등록번호 마스킹: 010101-3456789 → 010101-3******
	re := regexp.MustCompile(`(\d{6})[-]\d{7}`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, "-")
		if len(parts) == 2 {
			return parts[0] + "-" + parts[1][:1] + "******"
		}
		return match
	})

	// 주민등록번호 마스킹 (공백): 010101 3456789 → 010101 3******
	re = regexp.MustCompile(`(\d{6})\s\d{7}`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, " ")
		if len(parts) == 2 {
			return parts[0] + " " + parts[1][:1] + "******"
		}
		return match
	})

	// 여권번호 마스킹: M12345678 → M******78
	re = regexp.MustCompile(`([AM])\d{6,7}(\d{2})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		if len(match) >= 8 {
			return string(match[0]) + "******" + match[len(match)-2:]
		}
		return match
	})

	// 운전면허번호 마스킹: 12-34-567890 → 12-**-*****0
	re = regexp.MustCompile(`(\d{2})[-](\d{2})[-](\d{6})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, "-")
		if len(parts) == 3 {
			return parts[0] + "-**-" + "*****" + parts[2][len(parts[2])-1:]
		}
		return match
	})

	// 전화번호 마스킹: 010-1234-5678 → 010-****-5678 (바이트 길이 보존)
	re = regexp.MustCompile(`(010)[-]\d{4}[-](\d{4})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, "-")
		if len(parts) == 3 {
			masked := parts[0] + "-****-" + parts[2]
			// 바이트 길이 보존 확인 및 조정
			if len(masked) != len(match) {
				log.Printf("⚠️  Phone masking size mismatch: '%s' (%d) -> '%s' (%d)", match, len(match), masked, len(masked))
				// DLP를 위해 길이를 맞춤
				if len(masked) < len(match) {
					// 부족한 바이트만큼 공백으로 패딩
					padding := strings.Repeat(" ", len(match)-len(masked))
					masked = masked + padding
				} else {
					// 초과하는 경우는 잘라냄
					masked = masked[:len(match)]
				}
				log.Printf("🔧 Adjusted phone masking: '%s' (%d bytes)", masked, len(masked))
			}
			log.Printf("🔍 Phone masking: '%s' -> '%s' (%d bytes)", match, masked, len(masked))
			return masked
		}
		return match
	})

	// 전화번호 마스킹 (공백): 010 1234 5678 → 010 **** 5678 (바이트 길이 보존)
	re = regexp.MustCompile(`(010)\s\d{4}\s(\d{4})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, " ")
		if len(parts) == 3 {
			masked := parts[0] + " **** " + parts[2]
			// 바이트 길이 보존 확인 및 조정
			if len(masked) != len(match) {
				if len(masked) < len(match) {
					masked = masked + strings.Repeat(" ", len(match)-len(masked))
				} else {
					masked = masked[:len(match)]
				}
			}
			return masked
		}
		return match
	})

	// 전화번호 마스킹 (연속): 01012345678 → 010****5678
	re = regexp.MustCompile(`(010)\d{4}(\d{4})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		if len(match) == 11 {
			return match[:3] + "****" + match[7:]
		}
		return match
	})

	// 서울 전화번호 마스킹: 02-123-4567 → 02-***-4567
	re = regexp.MustCompile(`(02)[-]\d{3,4}[-](\d{4})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, "-")
		if len(parts) == 3 {
			return parts[0] + "-***-" + parts[2]
		}
		return match
	})

	// 이메일 마스킹: user@example.com → u***@example.com (바이트 길이 보존)
	re = regexp.MustCompile(`([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, "@")
		if len(parts) == 2 {
			username := parts[0]
			domain := parts[1]

			// 바이트 길이 보존: username을 * 로 채움
			maskedUsername := ""
			if len(username) > 1 {
				// 첫 글자만 남기고 나머지는 *로 채움
				maskedUsername = string(username[0]) + strings.Repeat("*", len(username)-1)
			} else {
				maskedUsername = "*"
			}

			result := maskedUsername + "@" + domain

			// 바이트 길이 확인
			if len(result) != len(match) {
				log.Printf("⚠️  Email masking size mismatch: '%s' (%d) -> '%s' (%d)", match, len(match), result, len(result))
				return match // 길이가 다르면 원본 반환
			}

			return result
		}
		return match
	})

	return masked
}

// MaskFinancialInfo: 재무/결제 정보 마스킹 처리
func MaskFinancialInfo(text string) string {
	masked := text

	// 계좌번호 마스킹: 123-456-789012 → 123-***-*****2 (바이트 길이 보존)
	re := regexp.MustCompile(`(\d{3})[-](\d{2,4})[-](\d{6})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, "-")
		if len(parts) == 3 {
			masked := parts[0] + "-***-" + "*****" + parts[2][len(parts[2])-1:]
			// 바이트 길이 보존 확인 및 조정
			if len(masked) != len(match) {
				if len(masked) < len(match) {
					masked = masked + strings.Repeat(" ", len(match)-len(masked))
				} else {
					masked = masked[:len(match)]
				}
			}
			return masked
		}
		return match
	})

	// 카드번호 마스킹: 1234-5678-9012-3456 → 1234-****-****-3456 (바이트 길이 보존)
	re = regexp.MustCompile(`(\d{4})-(\d{4})-(\d{4})-(\d{4})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, "-")
		if len(parts) == 4 {
			masked := parts[0] + "-****-****-" + parts[3]
			// 바이트 길이 보존 확인 및 조정
			if len(masked) != len(match) {
				if len(masked) < len(match) {
					masked = masked + strings.Repeat(" ", len(match)-len(masked))
				} else {
					masked = masked[:len(match)]
				}
			}
			return masked
		}
		return match
	})

	// CVV 마스킹: CVV: 123 → CVV: *** (바이트 길이 보존)
	re = regexp.MustCompile(`(CVV[:]\s*)\d{3,4}`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		masked := strings.Replace(match, match[strings.Index(match, ":")+1:], " ***", 1)
		// 바이트 길이 보존 확인 및 조정
		if len(masked) != len(match) {
			if len(masked) < len(match) {
				masked = masked + strings.Repeat(" ", len(match)-len(masked))
			} else {
				masked = masked[:len(match)]
			}
		}
		return masked
	})

	// CVC 마스킹: CVC: 123 → CVC: *** (바이트 길이 보존)
	re = regexp.MustCompile(`(CVC[:]\s*)\d{3,4}`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		masked := strings.Replace(match, match[strings.Index(match, ":")+1:], " ***", 1)
		// 바이트 길이 보존 확인 및 조정
		if len(masked) != len(match) {
			if len(masked) < len(match) {
				masked = masked + strings.Repeat(" ", len(match)-len(masked))
			} else {
				masked = masked[:len(match)]
			}
		}
		return masked
	})

	// 만료일 마스킹: 12/25 → ***** (바이트 길이 보존)
	re = regexp.MustCompile(`\d{2}[/\-\.]\d{2}`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		originalLen := len(match)
		// 원본 길이를 그대로 유지
		return strings.Repeat("*", originalLen)
	})

	return masked
}

// MaskAuthInfo: 인증/보안 정보 마스킹 처리
func MaskAuthInfo(text string) string {
	masked := text

	// 비밀번호 마스킹: P@ssw0rd! → ********** (바이트 길이 보존)
	re := regexp.MustCompile(`(password[:]\s*)([^\s]{8,})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, ":")
		if len(parts) == 2 {
			password := strings.TrimSpace(parts[1])
			masked := parts[0] + " " + strings.Repeat("*", len(password))
			// 바이트 길이 보존 확인 및 조정
			if len(masked) != len(match) {
				if len(masked) < len(match) {
					masked = masked + strings.Repeat(" ", len(match)-len(masked))
				} else {
					masked = masked[:len(match)]
				}
			}
			return masked
		}
		return match
	})

	// API Key 마스킹: AKIAIOSFODNN7EXAMPLE → AKIA****EXAMPLE
	re = regexp.MustCompile(`(AKIA[0-9A-Z]{4})[0-9A-Z]{12}([0-9A-Z]{6})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		if len(match) >= 20 {
			return match[:4] + "****" + match[len(match)-6:]
		}
		return match
	})

	// OAuth Secret 마스킹: s3cr3tV@lue → s3**t****ue
	re = regexp.MustCompile(`(OAuth[_-]?CLIENT[_-]?SECRET[:]\s*)([^\s]{8,})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, ":")
		if len(parts) == 2 {
			secret := strings.TrimSpace(parts[1])
			if len(secret) > 4 {
				return parts[0] + " " + secret[:2] + "**" + secret[4:6] + "****" + secret[len(secret)-2:]
			}
		}
		return match
	})

	// GitHub API Key 마스킹: ghp_1234567890abcdef1234567890abcdef12345678 → ghp_**** (바이트 길이 보존)
	re = regexp.MustCompile(`(ghp_[a-zA-Z0-9]+)`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		masked := "ghp_****"
		// 바이트 길이 보존 확인 및 조정
		if len(masked) != len(match) {
			if len(masked) < len(match) {
				masked = masked + strings.Repeat(" ", len(match)-len(masked))
			} else {
				masked = masked[:len(match)]
			}
		}
		return masked
	})

	// JWT 토큰 마스킹: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... → [JWT_TOKEN] (바이트 길이 보존)
	re = regexp.MustCompile(`(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		masked := "[JWT_TOKEN]"
		// 바이트 길이 보존 확인 및 조정
		if len(masked) != len(match) {
			if len(masked) < len(match) {
				masked = masked + strings.Repeat(" ", len(match)-len(masked))
			} else {
				masked = masked[:len(match)]
			}
		}
		return masked
	})

	// SSH Key 마스킹: ----BEGIN RSA PRIVATE KEY---- → [PRIVATE KEY]
	re = regexp.MustCompile(`-----BEGIN [A-Z\s]+PRIVATE KEY-----`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		return "[PRIVATE KEY]"
	})

	// 클라우드 액세스 키 마스킹: AKIA.../secret → AKIA**** / ****
	re = regexp.MustCompile(`(AKIA[0-9A-Z]{4})[0-9A-Z]{12}`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		if len(match) >= 20 {
			return match[:4] + "****"
		}
		return match
	})

	return masked
}

// MaskSystemInfo: 내부 시스템 정보 마스킹 처리
func MaskSystemInfo(text string) string {
	masked := text

	// 내부 IP 마스킹: 192.168.1.25 → 192.168.*.** (바이트 길이 보존)
	re := regexp.MustCompile(`(192\.168\.\d{1,3}\.\d{1,3})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, ".")
		if len(parts) == 4 {
			// 각 옥텟의 자릿수만큼 *로 채움
			maskedThird := strings.Repeat("*", len(parts[2]))
			maskedFourth := strings.Repeat("*", len(parts[3]))
			result := parts[0] + "." + parts[1] + "." + maskedThird + "." + maskedFourth

			// 바이트 길이 확인
			if len(result) != len(match) {
				log.Printf("⚠️  Internal IP masking size mismatch: '%s' (%d) -> '%s' (%d)", match, len(match), result, len(result))
				return match
			}
			return result
		}
		return match
	})

	re = regexp.MustCompile(`(10\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, ".")
		if len(parts) == 4 {
			// 각 옥텟의 자릿수만큼 *로 채움
			maskedSecond := strings.Repeat("*", len(parts[1]))
			maskedThird := strings.Repeat("*", len(parts[2]))
			maskedFourth := strings.Repeat("*", len(parts[3]))
			result := parts[0] + "." + maskedSecond + "." + maskedThird + "." + maskedFourth

			// 바이트 길이 확인
			if len(result) != len(match) {
				log.Printf("⚠️  Internal IP masking size mismatch: '%s' (%d) -> '%s' (%d)", match, len(match), result, len(result))
				return match
			}
			return result
		}
		return match
	})

	re = regexp.MustCompile(`(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, ".")
		if len(parts) == 4 {
			// 각 옥텟의 자릿수만큼 *로 채움
			maskedThird := strings.Repeat("*", len(parts[2]))
			maskedFourth := strings.Repeat("*", len(parts[3]))
			result := parts[0] + "." + parts[1] + "." + maskedThird + "." + maskedFourth

			// 바이트 길이 확인
			if len(result) != len(match) {
				log.Printf("⚠️  Internal IP masking size mismatch: '%s' (%d) -> '%s' (%d)", match, len(match), result, len(result))
				return match
			}
			return result
		}
		return match
	})

	// 퍼블릭 IP 부분 마스킹: 127.0.0.1 → 127.0.*.1 (바이트 길이 보존)
	re = regexp.MustCompile(`(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, ".")
		if len(parts) == 4 {
			// 내부 IP가 아닌 경우만 부분 마스킹
			if !strings.HasPrefix(match, "192.168.") &&
				!strings.HasPrefix(match, "10.") &&
				!strings.HasPrefix(match, "172.") {
				// 3번째 옥텟을 *로 마스킹 (바이트 길이 보존)
				thirdOctet := parts[2]
				maskedThirdOctet := strings.Repeat("*", len(thirdOctet))

				result := parts[0] + "." + parts[1] + "." + maskedThirdOctet + "." + parts[3]

				// 바이트 길이 확인
				if len(result) != len(match) {
					log.Printf("⚠️  IP masking size mismatch: '%s' (%d) -> '%s' (%d)", match, len(match), result, len(result))
					return match // 길이가 다르면 원본 반환
				}

				return result
			}
		}
		return match
	})

	// 포트 정보 비공개: :8080 → :**** (바이트 길이 보존)
	re = regexp.MustCompile(`:(\d{2,5})`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		// 콜론 제외하고 숫자 부분만 마스킹
		port := match[1:] // : 제외
		maskedPort := strings.Repeat("*", len(port))
		result := ":" + maskedPort

		// 바이트 길이 확인
		if len(result) != len(match) {
			log.Printf("⚠️  Port masking size mismatch: '%s' (%d) -> '%s' (%d)", match, len(match), result, len(result))
			return match // 길이가 다르면 원본 반환
		}

		return result
	})

	// DB 스키마 마스킹: users(id,name,email,password) → users
	re = regexp.MustCompile(`(\w+)\([^)]+\)`)
	masked = re.ReplaceAllStringFunc(masked, func(match string) string {
		parts := strings.Split(match, "(")
		if len(parts) == 2 {
			return parts[0]
		}
		return match
	})

	//log.Printf("MaskPersonalInfo result: %s", masked)
	return masked
}

// MaskAllSensitiveInfo: 모든 민감정보를 통합 마스킹 처리
func MaskAllSensitiveInfo(text string) string {
	masked := text

	// 1. 개인정보 마스킹
	masked = MaskPersonalInfo(masked)

	// 2. 재무정보 마스킹
	masked = MaskFinancialInfo(masked)

	// 3. 인증정보 마스킹
	masked = MaskAuthInfo(masked)

	// 4. 시스템정보 마스킹
	masked = MaskSystemInfo(masked)

	return masked
}

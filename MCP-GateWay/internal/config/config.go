// internal/config/config.go
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config는 전체 Gateway 설정을 담습니다
type Config struct {
	Gateway   GatewayConfig   `yaml:"gateway"`
	HTTPProxy HTTPProxyConfig `yaml:"http_proxy"`
	MCPProxy  MCPProxyConfig  `yaml:"mcp_proxy"`
	SSH       SSHConfig       `yaml:"ssh"`
	Servers   []MCPServer     `yaml:"mcp_servers"`
}

// GatewayConfig는 Gateway 기본 설정
type GatewayConfig struct {
	Listen string `yaml:"listen"`
	LogDir string `yaml:"log_dir"`
}

// HTTPProxyConfig는 HTTP Proxy 설정
type HTTPProxyConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Port           string `yaml:"port"`
	LogDir         string `yaml:"log_dir"`
	EnableMITM     bool   `yaml:"enable_mitm"`
	CACertFile     string `yaml:"ca_cert_file"`
	CAKeyFile      string `yaml:"ca_key_file"`
	ForceHTTP11    bool   `yaml:"force_http_1_1"`
	VerboseLogging bool   `yaml:"verbose_logging"`
	AIOnly         bool   `yaml:"ai_only"`
	DecodeProtobuf bool   `yaml:"decode_protobuf"`
	BackendAPIURL  string `yaml:"backend_api_url"` // DLP 로그 전송 백엔드 URL
	DLPAPIKey      string `yaml:"dlp_api_key"`     // DLP API 키
}

// MCPProxyConfig는 MCP Proxy 설정
type MCPProxyConfig struct {
	Allow           string `yaml:"allow"`
	ScrubEmail      bool   `yaml:"scrub_email"`
	ScrubPhone      bool   `yaml:"scrub_phone"`
	RequireRawQuery bool   `yaml:"require_raw_query"`

	// IP 기반 인증 설정
	WebServerURL  string `yaml:"webserver_url"`   // 웹서버 API URL
	IPAuthEnabled bool   `yaml:"ip_auth_enabled"` // IP 기반 인증 활성화
	APIKey        string `yaml:"api_key"`         // 웹서버 API 키 (선택적)
	BypassProxy   bool   `yaml:"bypass_proxy"`    // HTTP Proxy 우회
}

// SSHConfig는 SSH 연결 설정
type SSHConfig struct {
	KeyPath string `yaml:"key_path"`
	User    string `yaml:"user"`
}

// MCPServer는 개별 MCP Server 설정
type MCPServer struct {
	ID          string            `yaml:"id"`
	Type        string            `yaml:"type"` // "remote" 또는 "local"
	RemoteIP    string            `yaml:"remote_ip,omitempty"`
	Command     string            `yaml:"command"`
	Args        []string          `yaml:"args,omitempty"`
	Env         map[string]string `yaml:"env,omitempty"`
	MCPServerID int               `yaml:"mcp_server_id"` // 웹서버 DB의 mcp_servers.id
}

// LoadConfig는 YAML 파일에서 설정을 로드합니다
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// 기본값 설정
	if cfg.Gateway.Listen == "" {
		cfg.Gateway.Listen = ":8081"
	}
	if cfg.Gateway.LogDir == "" {
		cfg.Gateway.LogDir = "./logs"
	}
	if cfg.HTTPProxy.Port == "" {
		cfg.HTTPProxy.Port = ":8082"
	}
	if cfg.MCPProxy.Allow == "" {
		cfg.MCPProxy.Allow = "*"
	}
	if cfg.SSH.User == "" {
		cfg.SSH.User = "ubuntu"
	}

	return &cfg, nil
}

// LoadHTTPProxyConfig는 HTTP Proxy 전용 YAML 파일에서 설정을 로드합니다
func LoadHTTPProxyConfig(path string) (*HTTPProxyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// 전체 Config 구조로 먼저 읽기 (http_proxy 섹션만 사용)
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// HTTP Proxy 설정만 반환
	proxyCfg := &cfg.HTTPProxy

	// 기본값 설정
	if proxyCfg.Port == "" {
		proxyCfg.Port = ":8082"
	}
	if proxyCfg.LogDir == "" {
		proxyCfg.LogDir = "./logs"
	}

	return proxyCfg, nil
}

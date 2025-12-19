package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"mcp-gateway/internal/config"
	httpproxy "mcp-gateway/internal/http-proxy"
)

func main() {
	var (
		configFile     = flag.String("config", "", "YAML config file path (if provided, overrides other flags)")
		port           = flag.String("port", ":8082", "HTTP proxy listen port")
		logDir         = flag.String("logdir", "./logs", "log directory")
		enableMITM     = flag.Bool("mitm", false, "enable MITM SSL interception")
		caCertFile     = flag.String("ca-cert", "", "CA certificate file path")
		caKeyFile      = flag.String("ca-key", "", "CA private key file path")
		verboseLogging = flag.Bool("verbose", false, "enable verbose logging")
		aiOnly         = flag.Bool("ai-only", false, "log only AI service requests")
		headersOnly    = flag.Bool("headers-only", false, "log only headers, not body")
		backendAPIURL  = flag.String("backend-api-url", "", "DLP log backend API URL")
		dlpAPIKey      = flag.String("dlp-api-key", "", "DLP API key")
	)
	flag.Parse()

	var cfg *httpproxy.Config

	// YAML 설정 파일이 제공되면 우선 사용
	if *configFile != "" {
		yamlCfg, err := config.LoadHTTPProxyConfig(*configFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		// YAML 설정을 httpproxy.Config로 변환
		cfg = &httpproxy.Config{
			LogDir:         yamlCfg.LogDir,
			Port:           yamlCfg.Port,
			CACertFile:     yamlCfg.CACertFile,
			CAKeyFile:      yamlCfg.CAKeyFile,
			EnableMITM:     yamlCfg.EnableMITM,
			VerboseLogging: yamlCfg.VerboseLogging,
			AIOnly:         yamlCfg.AIOnly,
			DecodeProtobuf: yamlCfg.DecodeProtobuf,
			HeadersOnly:    false, // YAML에 없음
			AllowPorts:     []int{80, 443},
			BackendAPIURL:  yamlCfg.BackendAPIURL,
			DLPAPIKey:      yamlCfg.DLPAPIKey,
		}
	} else {
		// 플래그 방식 사용
		cfg = &httpproxy.Config{
			LogDir:         *logDir,
			Port:           *port,
			CACertFile:     *caCertFile,
			CAKeyFile:      *caKeyFile,
			EnableMITM:     *enableMITM,
			VerboseLogging: *verboseLogging,
			AIOnly:         *aiOnly,
			DecodeProtobuf: true,
			HeadersOnly:    *headersOnly,
			AllowPorts:     []int{80, 443},
			BackendAPIURL:  *backendAPIURL,
			DLPAPIKey:      *dlpAPIKey,
		}
	}

	// 로그 디렉토리 생성
	if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	server, err := httpproxy.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create HTTP proxy server: %v", err)
	}

	fmt.Printf("Starting HTTP proxy server on %s\n", cfg.Port)
	fmt.Printf("Log directory: %s\n", cfg.LogDir)
	if cfg.EnableMITM {
		fmt.Printf("MITM SSL interception: enabled\n")
	}
	if cfg.AIOnly {
		fmt.Printf("AI-only logging: enabled\n")
	}
	if cfg.HeadersOnly {
		fmt.Printf("Headers-only logging: enabled\n")
	}

	if err := server.Start(); err != nil {
		log.Fatalf("HTTP proxy server failed: %v", err)
	}
}

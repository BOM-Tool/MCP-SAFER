package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"mcp-gateway/internal/config"
	mcpproxy "mcp-gateway/internal/mcp-proxy"
)

func main() {
	configPath := flag.String("config", "config-cursor-mitm.yaml", "Path to configuration file")
	flag.Parse()

	// 설정 로드
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 프록시 생성
	p, err := mcpproxy.NewProxy(cfg)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// 시그널 핸들링 (graceful shutdown)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down MCP Proxy...")
		if err := p.Close(); err != nil {
			log.Printf("Error closing proxy: %v", err)
		}
		os.Exit(0)
	}()

	// 프록시 시작
	if err := p.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}

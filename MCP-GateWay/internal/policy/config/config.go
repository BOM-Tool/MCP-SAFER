package config

import (
	"os"
	"strconv"
	"time"
)

// MLConfig ML 서버 설정
type MLConfig struct {
	ServerAddress    string        `json:"server_address"`
	Timeout          time.Duration `json:"timeout"`
	MaxRetries       int           `json:"max_retries"`
	BatchSize        int           `json:"batch_size"`
	CacheEnabled     bool          `json:"cache_enabled"`
	CacheTTL         time.Duration `json:"cache_ttl"`
	ConnectionPool   int           `json:"connection_pool"`
	KeepAlive        time.Duration `json:"keep_alive"`
	MaxMessageSize   int           `json:"max_message_size"`
}

// PolicyConfig 정책 설정
type PolicyConfig struct {
	EnableMLDetection bool `json:"enable_ml_detection"`
	EnableCaching     bool `json:"enable_caching"`
	EnableMetrics     bool `json:"enable_metrics"`
	RegexOnlyMode     bool `json:"regex_only_mode"`
	MLHybridMode      bool `json:"ml_hybrid_mode"`
}

// CacheConfig 캐시 설정
type CacheConfig struct {
	RedisAddress     string        `json:"redis_address"`
	RedisPassword    string        `json:"redis_password"`
	RedisDB          int           `json:"redis_db"`
	MemoryCacheSize  int           `json:"memory_cache_size"`
	MemoryCacheTTL   time.Duration `json:"memory_cache_ttl"`
	RedisCacheTTL    time.Duration `json:"redis_cache_ttl"`
}

// MetricsConfig 메트릭 설정
type MetricsConfig struct {
	PrometheusEnabled bool   `json:"prometheus_enabled"`
	PrometheusPort    int    `json:"prometheus_port"`
	HealthCheckPort   int    `json:"health_check_port"`
	MetricsPath       string `json:"metrics_path"`
	HealthPath        string `json:"health_path"`
	ReadyPath         string `json:"ready_path"`
}

// LoadConfig 설정 로드
func LoadConfig() (*MLConfig, *PolicyConfig, *CacheConfig, *MetricsConfig) {
	return &MLConfig{
		ServerAddress:   getEnv("ML_SERVER_ADDRESS", "localhost:50051"),
		Timeout:        time.Duration(getEnvInt("ML_TIMEOUT", 5)) * time.Second,
		MaxRetries:     getEnvInt("ML_MAX_RETRIES", 3),
		BatchSize:      getEnvInt("ML_BATCH_SIZE", 10),
		CacheEnabled:   getEnvBool("ML_CACHE_ENABLED", true),
		CacheTTL:       time.Duration(getEnvInt("ML_CACHE_TTL", 300)) * time.Second,
		ConnectionPool: getEnvInt("ML_CONNECTION_POOL", 10),
		KeepAlive:      time.Duration(getEnvInt("ML_KEEP_ALIVE", 30)) * time.Second,
		MaxMessageSize: getEnvInt("ML_MAX_MESSAGE_SIZE", 4*1024*1024), // 4MB
	}, &PolicyConfig{
		EnableMLDetection: getEnvBool("ENABLE_ML_DETECTION", true),
		EnableCaching:     getEnvBool("ENABLE_CACHING", true),
		EnableMetrics:     getEnvBool("ENABLE_METRICS", true),
		RegexOnlyMode:     getEnvBool("REGEX_ONLY_MODE", false),
		MLHybridMode:      getEnvBool("ML_HYBRID_MODE", true),
	}, &CacheConfig{
		RedisAddress:     getEnv("REDIS_ADDRESS", "localhost:6379"),
		RedisPassword:    getEnv("REDIS_PASSWORD", ""),
		RedisDB:          getEnvInt("REDIS_DB", 0),
		MemoryCacheSize:  getEnvInt("MEMORY_CACHE_SIZE", 1000),
		MemoryCacheTTL:   time.Duration(getEnvInt("MEMORY_CACHE_TTL", 60)) * time.Second,
		RedisCacheTTL:    time.Duration(getEnvInt("REDIS_CACHE_TTL", 600)) * time.Second,
	}, &MetricsConfig{
		PrometheusEnabled: getEnvBool("PROMETHEUS_ENABLED", true),
		PrometheusPort:    getEnvInt("PROMETHEUS_PORT", 9090),
		HealthCheckPort:   getEnvInt("HEALTH_CHECK_PORT", 8080),
		MetricsPath:       getEnv("METRICS_PATH", "/metrics"),
		HealthPath:        getEnv("HEALTH_PATH", "/health"),
		ReadyPath:         getEnv("READY_PATH", "/ready"),
	}
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}


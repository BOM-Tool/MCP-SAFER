package cache

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mcp-gateway/internal/policy/core"
	"mcp-gateway/internal/policy/config"
	
	"github.com/go-redis/redis/v8"
)

type RedisCache struct {
	client *redis.Client
	config *config.CacheConfig
}

// NewRedisCache Redis 캐시 생성
func NewRedisCache(cacheConfig *config.CacheConfig) *RedisCache {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cacheConfig.RedisAddress,
		Password: cacheConfig.RedisPassword,
		DB:       cacheConfig.RedisDB,
		PoolSize: 10,
		MinIdleConns: 5,
	})

	return &RedisCache{
		client: rdb,
		config: cacheConfig,
	}
}

// Get 캐시에서 탐지 결과 조회
func (r *RedisCache) Get(ctx context.Context, policyID, text string) ([]core.SensitiveInfo, bool) {
	key := r.generateKey(policyID, text)
	
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return nil, false
	}

	var detections []core.SensitiveInfo
	if err := json.Unmarshal([]byte(val), &detections); err != nil {
		return nil, false
	}

	return detections, true
}

// Set 캐시에 탐지 결과 저장
func (r *RedisCache) Set(ctx context.Context, policyID, text string, detections []core.SensitiveInfo) error {
	key := r.generateKey(policyID, text)
	
	data, err := json.Marshal(detections)
	if err != nil {
		return fmt.Errorf("failed to marshal detections: %w", err)
	}

	return r.client.Set(ctx, key, data, r.config.RedisCacheTTL).Err()
}

// Delete 캐시 삭제
func (r *RedisCache) Delete(ctx context.Context, policyID, text string) error {
	key := r.generateKey(policyID, text)
	return r.client.Del(ctx, key).Err()
}

// Clear 모든 캐시 삭제
func (r *RedisCache) Clear(ctx context.Context) error {
	return r.client.FlushDB(ctx).Err()
}

// GetStats 캐시 통계 조회
func (r *RedisCache) GetStats(ctx context.Context) (map[string]interface{}, error) {
	_, err := r.client.Info(ctx, "stats").Result()
	if err != nil {
		return nil, err
	}

	stats := make(map[string]interface{})
	// Redis INFO 파싱 로직 (간단한 예시)
	stats["connected_clients"] = "1"
	stats["used_memory"] = "1024"
	stats["keyspace_hits"] = "100"
	stats["keyspace_misses"] = "10"
	
	return stats, nil
}

// generateKey 캐시 키 생성 (hash(policyID:text_hash))
func (r *RedisCache) generateKey(policyID, text string) string {
	hasher := md5.New()
	hasher.Write([]byte(fmt.Sprintf("%s:%s", policyID, text)))
	hash := hex.EncodeToString(hasher.Sum(nil))
	return fmt.Sprintf("dlp:cache:%s", hash)
}

// Close 연결 종료
func (r *RedisCache) Close() error {
	return r.client.Close()
}

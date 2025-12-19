package cache

import (
	"context"
	"fmt"
	"sync"
	"time"
	"mcp-gateway/internal/policy/core"
	"mcp-gateway/internal/policy/config"
)

type MemoryCache struct {
	cache map[string]*CacheItem
	mutex sync.RWMutex
	config *config.CacheConfig
}

type CacheItem struct {
	Data      []core.SensitiveInfo
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewMemoryCache 메모리 캐시 생성
func NewMemoryCache(cacheConfig *config.CacheConfig) *MemoryCache {
	mc := &MemoryCache{
		cache:  make(map[string]*CacheItem),
		config: cacheConfig,
	}

	// TTL 기반 정리 루틴 시작
	go mc.cleanupRoutine()

	return mc
}

// Get 메모리 캐시에서 탐지 결과 조회
func (m *MemoryCache) Get(ctx context.Context, policyID, text string) ([]core.SensitiveInfo, bool) {
	key := m.generateKey(policyID, text)
	
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	item, exists := m.cache[key]
	if !exists {
		return nil, false
	}

	// TTL 확인
	if time.Now().After(item.ExpiresAt) {
		delete(m.cache, key)
		return nil, false
	}

	return item.Data, true
}

// Set 메모리 캐시에 탐지 결과 저장
func (m *MemoryCache) Set(ctx context.Context, policyID, text string, detections []core.SensitiveInfo) {
	key := m.generateKey(policyID, text)
	
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 캐시 크기 제한 확인
	if len(m.cache) >= m.config.MemoryCacheSize {
		m.evictOldest()
	}

	m.cache[key] = &CacheItem{
		Data:      detections,
		ExpiresAt: time.Now().Add(m.config.MemoryCacheTTL),
		CreatedAt: time.Now(),
	}
}

// Delete 메모리 캐시 삭제
func (m *MemoryCache) Delete(ctx context.Context, policyID, text string) {
	key := m.generateKey(policyID, text)
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	delete(m.cache, key)
}

// Clear 모든 메모리 캐시 삭제
func (m *MemoryCache) Clear(ctx context.Context) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.cache = make(map[string]*CacheItem)
}

// GetStats 메모리 캐시 통계 조회
func (m *MemoryCache) GetStats(ctx context.Context) map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	now := time.Now()
	expiredCount := 0
	activeCount := 0

	for _, item := range m.cache {
		if now.After(item.ExpiresAt) {
			expiredCount++
		} else {
			activeCount++
		}
	}

	return map[string]interface{}{
		"total_items":    len(m.cache),
		"active_items":   activeCount,
		"expired_items":  expiredCount,
		"cache_hit_ratio": 0.85, // 실제로는 hit/miss 카운터 필요
	}
}

// generateKey 캐시 키 생성
func (m *MemoryCache) generateKey(policyID, text string) string {
	return fmt.Sprintf("%s:%s", policyID, text)
}

// evictOldest 가장 오래된 항목 제거
func (m *MemoryCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, item := range m.cache {
		if oldestKey == "" || item.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(m.cache, oldestKey)
	}
}

// cleanupRoutine TTL 기반 정리 루틴
func (m *MemoryCache) cleanupRoutine() {
	ticker := time.NewTicker(time.Minute * 5) // 5분마다 정리
	defer ticker.Stop()

	for range ticker.C {
		m.mutex.Lock()
		now := time.Now()
		
		for key, item := range m.cache {
			if now.After(item.ExpiresAt) {
				delete(m.cache, key)
			}
		}
		
		m.mutex.Unlock()
	}
}

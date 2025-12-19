package metrics

import (
	"time"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ML 탐지 관련 메트릭
	MLDetectionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dlp_ml_detection_duration_seconds",
			Help:    "Time spent on ML detection",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"category", "confidence_level", "source"},
	)

	MLDetectionAccuracy = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dlp_ml_detection_accuracy",
			Help: "ML detection accuracy by category",
		},
		[]string{"category"},
	)

	MLServerHealth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "dlp_ml_server_health",
			Help: "ML server health status (1=healthy, 0=unhealthy)",
		},
	)

	// ML 호출 횟수 추적
	MLServerCalls = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dlp_ml_server_calls_total",
			Help: "Total number of calls to ML server",
		},
	)

	MLServerCallFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dlp_ml_server_call_failures_total",
			Help: "Total number of failed ML server calls",
		},
	)

	// Regex 탐지 관련 메트릭
	RegexDetectionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dlp_regex_detection_duration_seconds",
			Help:    "Time spent on Regex detection",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"category", "confidence_level"},
	)

	// 캐시 관련 메트릭
	CacheHitRatio = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dlp_cache_hit_ratio",
			Help: "Cache hit ratio by cache type",
		},
		[]string{"cache_type"},
	)

	CacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dlp_cache_size",
			Help: "Cache size by cache type",
		},
		[]string{"cache_type"},
	)

	// 전체 탐지 관련 메트릭
	TotalDetections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dlp_total_detections",
			Help: "Total number of detections",
		},
		[]string{"category", "confidence_level", "source"},
	)

	DetectionLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dlp_detection_latency_seconds",
			Help:    "Total detection latency",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0},
		},
		[]string{"detection_type"},
	)

	// 에러 관련 메트릭
	DetectionErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dlp_detection_errors_total",
			Help: "Total number of detection errors",
		},
		[]string{"error_type", "component"},
	)

	// 배치 처리 관련 메트릭
	BatchProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dlp_batch_processing_duration_seconds",
			Help:    "Time spent on batch processing",
			Buckets: prometheus.DefBuckets,
		},
	)

	BatchSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dlp_batch_size",
			Help:    "Size of processed batches",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
		},
	)
)

// RecordMLDetection ML 탐지 메트릭 기록
func RecordMLDetection(category, confidenceLevel, source string, duration time.Duration) {
	MLDetectionDuration.WithLabelValues(category, confidenceLevel, source).Observe(duration.Seconds())
	TotalDetections.WithLabelValues(category, confidenceLevel, source).Inc()
}

// RecordMLServerCall ML 서버 호출 메트릭 기록
func RecordMLServerCall() {
	MLServerCalls.Inc()
}

// RecordMLServerCallFailure ML 서버 호출 실패 메트릭 기록
func RecordMLServerCallFailure() {
	MLServerCallFailures.Inc()
}

// RecordRegexDetection Regex 탐지 메트릭 기록
func RecordRegexDetection(category, confidenceLevel string, duration time.Duration) {
	RegexDetectionDuration.WithLabelValues(category, confidenceLevel).Observe(duration.Seconds())
	TotalDetections.WithLabelValues(category, confidenceLevel, "regex").Inc()
}

// RecordCacheHit 캐시 히트 메트릭 기록
func RecordCacheHit(cacheType string) {
	CacheHitRatio.WithLabelValues(cacheType).Add(1)
}

// RecordCacheMiss 캐시 미스 메트릭 기록
func RecordCacheMiss(cacheType string) {
	CacheHitRatio.WithLabelValues(cacheType).Add(0)
}

// RecordDetectionLatency 전체 탐지 지연시간 기록
func RecordDetectionLatency(detectionType string, duration time.Duration) {
	DetectionLatency.WithLabelValues(detectionType).Observe(duration.Seconds())
}

// RecordError 에러 메트릭 기록
func RecordError(errorType, component string) {
	DetectionErrors.WithLabelValues(errorType, component).Inc()
}

// RecordBatchProcessing 배치 처리 메트릭 기록
func RecordBatchProcessing(duration time.Duration, batchSize int) {
	BatchProcessingDuration.Observe(duration.Seconds())
	BatchSize.Observe(float64(batchSize))
}

// SetMLServerHealth ML 서버 상태 설정
func SetMLServerHealth(healthy bool) {
	if healthy {
		MLServerHealth.Set(1)
	} else {
		MLServerHealth.Set(0)
	}
}

// SetCacheSize 캐시 크기 설정
func SetCacheSize(cacheType string, size float64) {
	CacheSize.WithLabelValues(cacheType).Set(size)
}

// SetMLAccuracy ML 정확도 설정
func SetMLAccuracy(category string, accuracy float64) {
	MLDetectionAccuracy.WithLabelValues(category).Set(accuracy)
}


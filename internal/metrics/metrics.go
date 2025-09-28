package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reg = prometheus.NewRegistry()

	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "http_requests_total", Help: "Total HTTP requests"},
		[]string{"method", "path", "status"},
	)
	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Request duration",
			Buckets: prometheus.ExponentialBuckets(0.005, 2, 10),
		},
		[]string{"method", "path", "status_code"},
	)
	RateLimitRejectedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "rate_limiter_rejected_total", Help: "Requests rejected by rate limiter"},
	)
	BlocklistSizeGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "blocklist_domains", Help: "Current number of blocklisted domains"},
	)
	AllowlistSizeGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "allowlist_domains", Help: "Current number of allowlisted domains"},
	)
	BlocklistAppendsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "blocklist_appends_total", Help: "Number of blocklist domains appended"},
	)
	BlocklistDuplicatesSkippedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "blocklist_duplicates_skipped_total", Help: "Duplicate blocklist domains skipped during append"},
	)
	PSLRefreshSuccessTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "psl_refresh_success_total", Help: "Successful PSL refreshes"},
	)
	PSLRefreshFailureTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "psl_refresh_failure_total", Help: "Failed PSL refresh attempts"},
	)
	PSLLastRefreshUnix = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "psl_last_refresh_unixtime", Help: "Unix timestamp of last successful refresh"},
	)
	PSLConsecutiveFailures = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "psl_consecutive_failures", Help: "Number of consecutive failed PSL refresh attempts"},
	)
	PSLSizeDeltaWarningsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "psl_size_delta_warnings_total", Help: "PSL refreshes with significant size delta"},
	)
	AdminAuthFailuresTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "admin_auth_failures_total", Help: "Total failed admin authentication attempts"},
	)
	AdminAuthSuccessTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "admin_auth_success_total", Help: "Total successful admin authentication attempts"},
	)
)

var registered atomic.Bool

func Register() {
	if registered.Swap(true) {
		return
	}
	reg.MustRegister(HTTPRequestsTotal, HTTPRequestDuration, RateLimitRejectedTotal, BlocklistSizeGauge, AllowlistSizeGauge, BlocklistAppendsTotal, BlocklistDuplicatesSkippedTotal, PSLRefreshSuccessTotal, PSLRefreshFailureTotal, PSLLastRefreshUnix, PSLConsecutiveFailures, PSLSizeDeltaWarningsTotal, AdminAuthFailuresTotal, AdminAuthSuccessTotal)
}

// Returns the /metrics HTTP handler
func Handler() http.Handler { Register(); return promhttp.HandlerFor(reg, promhttp.HandlerOpts{}) }

// Records metrics for a request.
func ObserveRequest(method, path, status string, dur time.Duration, statusCode int) {
	Register()
	HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
	HTTPRequestDuration.WithLabelValues(method, path, fmt.Sprintf("%d", statusCode)).Observe(dur.Seconds())
}

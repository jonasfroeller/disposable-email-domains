package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	RateLimitRPS   float64       // tokens added per second per IP
	RateLimitBurst int           // max burst tokens per IP
	RateLimiterTTL time.Duration // idle bucket eviction horizon

	PSLRefreshInterval     time.Duration // background PSL refresh cadence
	EnableSampleWarming    bool          // enable background warming job
	SampleCheckInterval    time.Duration // interval for sample warming requests
	TrustProxyHeaders      bool          // trust X-Forwarded-For / X-Real-IP when true
	AdminTokens            []string      // one or more admin tokens (rotation)
	RateLimitBypassDomains []string      // hostnames (exact match) that bypass rate limiter

	BatchMaxItems       int // cap for non-streaming batch endpoints
	BatchStreamMaxItems int // cap for streaming (NDJSON) endpoints
}

func Load(logger *log.Logger) Config {
	c := Config{
		RateLimitRPS:        5.0,
		RateLimitBurst:      20,
		RateLimiterTTL:      10 * time.Minute,
		PSLRefreshInterval:  24 * time.Hour,
		SampleCheckInterval: 10 * time.Minute,
		BatchMaxItems:       200_000,
		BatchStreamMaxItems: 1_000_000,
	}
	if v := os.Getenv("RATE_LIMIT_RPS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			c.RateLimitRPS = f
		} else if err != nil {
			logger.Printf("config: invalid RATE_LIMIT_RPS=%q: %v", v, err)
		}
	}
	if v := os.Getenv("RATE_LIMIT_BURST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.RateLimitBurst = n
		} else if err != nil {
			logger.Printf("config: invalid RATE_LIMIT_BURST=%q: %v", v, err)
		}
	}
	if v := os.Getenv("RATE_LIMIT_BUCKET_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.RateLimiterTTL = d
		} else if err != nil {
			logger.Printf("config: invalid RATE_LIMIT_BUCKET_TTL=%q: %v", v, err)
		}
	}
	if v := os.Getenv("PSL_REFRESH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.PSLRefreshInterval = d
		} else if err != nil {
			logger.Printf("config: invalid PSL_REFRESH_INTERVAL=%q: %v", v, err)
		}
	}
	if v := os.Getenv("ENABLE_SAMPLE_WARMING"); v != "" {
		vl := strings.ToLower(v)
		c.EnableSampleWarming = vl == "1" || vl == "true" || vl == "yes" || vl == "on"
	}
	if v := os.Getenv("SAMPLE_CHECK_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.SampleCheckInterval = d
		} else if err != nil {
			logger.Printf("config: invalid SAMPLE_CHECK_INTERVAL=%q: %v", v, err)
		}
	}
	if v := os.Getenv("TRUST_PROXY_HEADERS"); v != "" {
		vl := strings.ToLower(v)
		c.TrustProxyHeaders = vl == "1" || vl == "true" || vl == "yes" || vl == "on"
	}
	if v := os.Getenv("ADMIN_TOKENS"); v != "" { // comma-separated
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if len(p) >= 16 {
				c.AdminTokens = append(c.AdminTokens, p)
			} else if p != "" {
				logger.Printf("config: ignoring short admin token (<16 chars)")
			}
		}
	}
	if len(c.AdminTokens) == 0 { // fallback to single token
		if single := os.Getenv("ADMIN_TOKEN"); single != "" {
			if len(single) >= 16 {
				c.AdminTokens = []string{single}
			} else {
				logger.Printf("config: ADMIN_TOKEN provided but <16 chars; ignoring")
			}
		}
	}
	if v := os.Getenv("RATE_LIMIT_BYPASS_DOMAINS"); v != "" { // comma/space separated
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			part = strings.TrimSpace(strings.ToLower(part))
			if part == "" {
				continue
			}
			c.RateLimitBypassDomains = append(c.RateLimitBypassDomains, part)
		}
	}

	if v := os.Getenv("BATCH_MAX_ITEMS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.BatchMaxItems = n
		} else if err != nil {
			logger.Printf("config: invalid BATCH_MAX_ITEMS=%q: %v", v, err)
		}
	}
	if v := os.Getenv("BATCH_STREAM_MAX_ITEMS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.BatchStreamMaxItems = n
		} else if err != nil {
			logger.Printf("config: invalid BATCH_STREAM_MAX_ITEMS=%q: %v", v, err)
		}
	}
	return c
}

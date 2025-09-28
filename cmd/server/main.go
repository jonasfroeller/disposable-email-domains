package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"log/slog"

	"disposable-email-domains/internal/config"
	"disposable-email-domains/internal/domain"
	"disposable-email-domains/internal/pslrefresher"
	"disposable-email-domains/internal/router"
	"disposable-email-domains/internal/storage"
	slogadapter "disposable-email-domains/internal/util/logadapter"
)

var version string

func loadDotEnv(logger *log.Logger, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		logger.Printf("dotenv: read error: %v", err)
		return
	}
	for _, raw := range bytes.Split(data, []byte{'\n'}) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] == '#' {
			continue
		}
		eq := bytes.IndexByte(raw, '=')
		if eq <= 0 {
			continue
		}
		key := string(raw[:eq])
		val := string(raw[eq+1:])
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}

func main() {
	// version is injected via -ldflags "-X main.version=..."
	if version == "" {
		version = "dev"
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: false, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{Key: a.Key, Value: slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano))}
		}
		return a
	}})
	rootLogger := slog.New(handler)
	logger := slogadapter.New(rootLogger)

	loadDotEnv(logger, ".env")

	cfg := config.Load(logger)
	// Emit effective config (redacted tokens)
	{
		redacted := make([]string, 0, len(cfg.AdminTokens))
		for _, t := range cfg.AdminTokens {
			if len(t) <= 8 {
				redacted = append(redacted, "****")
				continue
			}
			redacted = append(redacted, t[:4]+"…"+t[len(t)-4:])
		}
		rootLogger.Info("effective_config",
			slog.Float64("rate_limit_rps", cfg.RateLimitRPS),
			slog.Int("rate_limit_burst", cfg.RateLimitBurst),
			slog.String("rate_limit_ttl", cfg.RateLimiterTTL.String()),
			slog.String("psl_refresh_interval", cfg.PSLRefreshInterval.String()),
			slog.Bool("sample_warming", cfg.EnableSampleWarming),
			slog.String("sample_check_interval", cfg.SampleCheckInterval.String()),
			slog.Bool("trust_proxy_headers", cfg.TrustProxyHeaders),
			slog.Any("admin_tokens", redacted),
			slog.Any("rate_limit_bypass_domains", cfg.RateLimitBypassDomains),
		)
	}
	refresher := pslrefresher.New(logger, "public_suffix_list.dat")
	refresher.Interval = cfg.PSLRefreshInterval
	// Perform an initial validated refresh (writes only if valid). If it fails,
	// the background loop will retry with backoff; readiness will reflect PSL presence.
	_ = refresher.RefreshNow()
	refresher.Start()

	internalStop := make(chan struct{})

	store := storage.NewMemoryStore()

	checker := domain.NewChecker("allowlist.conf", "blocklist.conf")
	if err := checker.Load(); err != nil {
		logger.Printf("failed to load lists: %v", err)
	}

	if len(cfg.AdminTokens) == 0 {
		rootLogger.Warn("no valid admin tokens configured - mutating endpoints disabled")
	}
	mux := router.New(store, logger, checker, cfg, refresher, version)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	if p := os.Getenv("PORT"); p != "" {
		srv.Addr = ":" + p
	}

	go func() {
		addr := srv.Addr
		url := "http://127.0.0.1" + addr
		if strings.HasPrefix(addr, ":") { // ":8080" style
			url = "http://127.0.0.1" + addr
		} else if strings.HasPrefix(addr, "0.0.0.0:") {
			url = "http://127.0.0.1" + addr[len("0.0.0.0"):]
		} else {
			url = "http://" + addr
		}
		rootLogger.Info("server starting", slog.String("addr", addr), slog.String("url", url), slog.String("version", version))
		log.Printf("Open: %s\n", url)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			rootLogger.Error("listen error", slog.String("error", err.Error()))
		}
	}()

	if cfg.EnableSampleWarming {
		go func() {
			interval := cfg.SampleCheckInterval
			client := &http.Client{Timeout: 5 * time.Second}
			samples := []string{"user@example.com", "test@good.com", "sub.bad.com", "neutral.io"}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
				case <-internalStop:
					return
				}
				body := `{"inputs":[` + quoteJoin(samples) + `]}`
				req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1"+srv.Addr+"/check", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					rootLogger.Warn("warm request error", slog.String("error", err.Error()))
					continue
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					rootLogger.Warn("warm unexpected status", slog.Int("status", resp.StatusCode))
				}
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	rootLogger.Info("shutdown signal received")

	// stop refresher first so no new file operations start during shutdown
	refresher.Stop()
	close(internalStop)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		rootLogger.Error("server shutdown error", slog.String("error", err.Error()))
	} else {
		rootLogger.Info("server stopped gracefully")
	}
}

func quoteJoin(elems []string) string {
	if len(elems) == 0 {
		return ""
	}
	b := strings.Builder{}
	for i, s := range elems {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		for _, r := range s {
			if r == '"' || r == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		b.WriteByte('"')
	}
	return b.String()
}

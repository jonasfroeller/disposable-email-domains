package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"disposable-email-domains/internal/domain"
	"disposable-email-domains/internal/router"
	"disposable-email-domains/internal/storage"
)

func fetchPSL(logger *log.Logger, dest string) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://publicsuffix.org/list/public_suffix_list.dat", nil)
	if err != nil {
		logger.Printf("psl: build request error: %v", err)
		return
	}
	req.Header.Set("User-Agent", "disposable-email-domains/psl-fetch")
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("psl: fetch error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Printf("psl: unexpected status: %s", resp.Status)
		return
	}
	f, err := os.Create(dest)
	if err != nil {
		logger.Printf("psl: create file error: %v", err)
		return
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		logger.Printf("psl: write file error: %v", err)
		return
	}
	logger.Printf("psl: saved to %s", dest)
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds|log.LUTC)

	fetchPSL(logger, "public_suffix_list.dat")

	store := storage.NewMemoryStore()

	checker := domain.NewChecker("allowlist.conf", "blocklist.conf")
	if err := checker.Load(); err != nil {
		logger.Printf("failed to load lists: %v", err)
	}

	mux := router.New(store, logger, checker)

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
		logger.Printf("server starting on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Println("shutdown signal received, shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Printf("server shutdown error: %v", err)
	} else {
		logger.Println("server stopped gracefully")
	}
}

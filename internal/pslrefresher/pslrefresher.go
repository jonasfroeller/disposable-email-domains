package pslrefresher

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"disposable-email-domains/internal/metrics"
)

// Refresher periodically downloads the public suffix list with integrity checks.
// It performs conditional requests and exponential backoff on failure.
type Refresher struct {
	URL                 string
	DestPath            string
	Interval            time.Duration
	Client              *http.Client
	Logger              *log.Logger
	stopCh              chan struct{}
	doneCh              chan struct{}
	lastModified        string
	etag                string
	mu                  sync.Mutex // guards tryRefresh (manual vs background)
	consecutiveFailures int
	lastSize            int
	lastSHA256          [32]byte
}

func New(logger *log.Logger, dest string) *Refresher {
	return &Refresher{
		URL:      "https://publicsuffix.org/list/public_suffix_list.dat",
		DestPath: dest,
		Interval: 24 * time.Hour,
		Client:   &http.Client{Timeout: 20 * time.Second},
		Logger:   logger,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start launches the background loop.
func (r *Refresher) Start() { go r.loop() }

// Stops signals termination and waits for completion.
func (r *Refresher) Stop() { close(r.stopCh); <-r.doneCh }

func (r *Refresher) loop() {
	defer close(r.doneCh)
	ticker := time.NewTicker(5 * time.Second) // immediate first attempt after short delay
	defer ticker.Stop()
	var backoff time.Duration
	first := true
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			if r.tryRefresh() {
				backoff = 0
				ticker.Reset(r.Interval)
				if first {
					r.Logger.Printf("psl: initial refresh succeeded")
				}
			} else {
				if backoff == 0 {
					backoff = 5 * time.Minute
				} else {
					backoff *= 2
				}
				if backoff > 6*time.Hour {
					backoff = 6 * time.Hour
				}
				ticker.Reset(backoff)
				r.Logger.Printf("psl: retry scheduled in %s", backoff)
			}
			first = false
		}
	}
}

// RefreshNow triggers an immediate synchronous refresh attempt.
// Returns true on success, false on failure.
func (r *Refresher) RefreshNow() bool { return r.tryRefresh() }

func (r *Refresher) tryRefresh() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	req, _ := http.NewRequest(http.MethodGet, r.URL, nil)
	if r.lastModified != "" {
		req.Header.Set("If-Modified-Since", r.lastModified)
	}
	if r.etag != "" {
		req.Header.Set("If-None-Match", r.etag)
	}
	req.Header.Set("User-Agent", "disposable-email-domains/psl-refresh")

	resp, err := r.Client.Do(req)
	if err != nil {
		r.Logger.Printf("psl: fetch error: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		r.Logger.Printf("psl: not modified")
		metrics.PSLRefreshSuccessTotal.Inc() // treat as success for availability visibility
		metrics.PSLLastRefreshUnix.Set(float64(time.Now().Unix()))
		r.consecutiveFailures = 0
		return true
	}
	if resp.StatusCode != http.StatusOK {
		r.Logger.Printf("psl: unexpected status %s", resp.Status)
		metrics.PSLRefreshFailureTotal.Inc()
		r.consecutiveFailures++
		metrics.PSLConsecutiveFailures.Set(float64(r.consecutiveFailures + 1))
		if r.consecutiveFailures == 5 || r.consecutiveFailures == 10 {
			r.Logger.Printf("psl: ERROR: %d consecutive failures fetching PSL", r.consecutiveFailures)
		}
		return false
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 3<<20)) // 3MB guard
	if err != nil {
		r.Logger.Printf("psl: read error: %v", err)
		metrics.PSLRefreshFailureTotal.Inc()
		r.consecutiveFailures++
		metrics.PSLConsecutiveFailures.Set(float64(r.consecutiveFailures))
		if r.consecutiveFailures == 5 || r.consecutiveFailures == 10 {
			r.Logger.Printf("psl: ERROR: %d consecutive failures fetching PSL", r.consecutiveFailures)
		}
		return false
	}

	if err := validate(data); err != nil {
		r.Logger.Printf("psl: validation failed: %v", err)
		metrics.PSLRefreshFailureTotal.Inc()
		r.consecutiveFailures++
		metrics.PSLConsecutiveFailures.Set(float64(r.consecutiveFailures))
		if r.consecutiveFailures == 5 || r.consecutiveFailures == 10 {
			r.Logger.Printf("psl: ERROR: %d consecutive failures fetching PSL", r.consecutiveFailures)
		}
		return false
	}

	if err := ensureDir(r.DestPath); err != nil {
		r.Logger.Printf("psl: ensure dir: %v", err)
		metrics.PSLRefreshFailureTotal.Inc()
		r.consecutiveFailures++
		metrics.PSLConsecutiveFailures.Set(float64(r.consecutiveFailures))
		if r.consecutiveFailures == 5 || r.consecutiveFailures == 10 {
			r.Logger.Printf("psl: ERROR: %d consecutive failures fetching PSL", r.consecutiveFailures)
		}
		return false
	}

	sum := sha256.Sum256(data)
	tmp := r.DestPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		r.Logger.Printf("psl: write tmp: %v", err)
		metrics.PSLRefreshFailureTotal.Inc()
		r.consecutiveFailures++
		metrics.PSLConsecutiveFailures.Set(float64(r.consecutiveFailures))
		if r.consecutiveFailures == 5 || r.consecutiveFailures == 10 {
			r.Logger.Printf("psl: ERROR: %d consecutive failures fetching PSL", r.consecutiveFailures)
		}
		return false
	}
	if err := os.Rename(tmp, r.DestPath); err != nil {
		r.Logger.Printf("psl: rename: %v", err)
		_ = os.Remove(tmp)
		metrics.PSLRefreshFailureTotal.Inc()
		return false
	}

	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		r.lastModified = lm
	}
	if et := resp.Header.Get("ETag"); et != "" {
		r.etag = et
	}

	r.Logger.Printf("psl: refreshed size=%d sha256=%x", len(data), sum[:6])
	metrics.PSLRefreshSuccessTotal.Inc()
	metrics.PSLLastRefreshUnix.Set(float64(time.Now().Unix()))
	metrics.PSLConsecutiveFailures.Set(0)
	// reset failure streak
	r.consecutiveFailures = 0
	// abnormal size delta detection (warn if size changed >20% from last successful size after first success)
	if r.lastSize > 0 {
		low := r.lastSize - (r.lastSize / 5)  // -20%
		high := r.lastSize + (r.lastSize / 5) // +20%
		if len(data) < low || len(data) > high {
			metrics.PSLSizeDeltaWarningsTotal.Inc()
			r.Logger.Printf("psl: warning: size delta significant prev=%d new=%d sha_prev=%x sha_new=%x", r.lastSize, len(data), r.lastSHA256[:6], sum[:6])
		}
	}
	r.lastSHA256 = sum
	r.lastSize = len(data)
	return true
}

func ensureDir(path string) error { return os.MkdirAll(filepath.Dir(path), 0o755) }

func validate(data []byte) error {
	if len(data) < 200_000 || len(data) > 2_000_000 {
		return fmt.Errorf("unexpected size %d", len(data))
	}
	head := data
	if len(head) > 1024 {
		head = head[:1024]
	}
	if bytes.Contains(bytes.ToLower(head), []byte("<html")) {
		return errors.New("looks like html")
	}
	s := string(data)
	if !strings.Contains(s, "===BEGIN ICANN DOMAINS===") {
		return errors.New("missing ICANN begin marker")
	}
	if !strings.Contains(s, "===END ICANN DOMAINS===") {
		return errors.New("missing ICANN end marker")
	}
	// line count
	sc := bufio.NewScanner(bytes.NewReader(data))
	lines := 0
	for sc.Scan() {
		lines++
	}
	if lines < 5000 {
		return fmt.Errorf("too few lines: %d", lines)
	}
	return nil
}

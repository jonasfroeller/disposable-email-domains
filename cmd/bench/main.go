package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// simple latency recorder (microseconds)
type recorder struct {
	mu   sync.Mutex
	durs []int64
}

func (r *recorder) add(d time.Duration) {
	us := d.Microseconds()
	if us < 0 {
		us = 0
	}
	r.mu.Lock()
	r.durs = append(r.durs, us)
	r.mu.Unlock()
}

func (r *recorder) percentiles() (p50, p95, p99 time.Duration) {
	r.mu.Lock()
	d := make([]int64, len(r.durs))
	copy(d, r.durs)
	r.mu.Unlock()
	if len(d) == 0 {
		return 0, 0, 0
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	idx := func(p float64) int {
		i := int(float64(len(d)-1) * p)
		if i < 0 {
			i = 0
		}
		if i >= len(d) {
			i = len(d) - 1
		}
		return i
	}
	return time.Duration(d[idx(0.50)]) * time.Microsecond, time.Duration(d[idx(0.95)]) * time.Microsecond, time.Duration(d[idx(0.99)]) * time.Microsecond
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	var (
		target      = flag.String("url", "http://127.0.0.1:8080/check", "Target URL (GET). If contains {q} placeholder it will be replaced with dynamic value")
		duration    = flag.Duration("duration", 10*time.Second, "Test duration")
		concurrency = flag.Int("c", runtime.NumCPU(), "Number of concurrent workers")
		qps         = flag.Int("qps", 0, "Global approximate queries per second (0 = max possible)")
		queriesFile = flag.String("queries", "", "Optional file with newline-separated query values (used for {q} placeholder)")
		insecure    = flag.Bool("allow-http", true, "Allow plain HTTP (set false to require https)")
		warmup      = flag.Duration("warmup", 0, "Optional warmup period (excluded from stats)")
		timeout     = flag.Duration("timeout", 5*time.Second, "Per request timeout")
	)
	flag.Parse()

	if !*insecure {
		if !strings.HasPrefix(*target, "https://") {
			fmt.Fprintln(os.Stderr, "refusing non-https target (use -allow-http=true to override)")
			os.Exit(1)
		}
	}
	if _, err := url.Parse(*target); err != nil {
		fmt.Fprintln(os.Stderr, "invalid url:", err)
		os.Exit(1)
	}

	var values []string
	if *queriesFile != "" {
		data, err := os.ReadFile(*queriesFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read queries file:", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			values = append(values, line)
		}
	}
	if len(values) == 0 {
		// fallback synthetic set
		for i := 0; i < 1000; i++ {
			values = append(values, fmt.Sprintf("u%03d@%s.example.com", i, randHex(3)))
		}
	}

	transport := &http.Transport{
		MaxIdleConns:        10000,
		MaxIdleConnsPerHost: 10000,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	client := &http.Client{Timeout: *timeout, Transport: transport}

	var (
		start        = time.Now()
		endTime      = start.Add(*duration)
		warmupUntil  = start.Add(*warmup)
		reqCount     int64
		successCount int64
		httpErrorCt  int64 // non-2xx HTTP responses
		netErrCt     int64 // total network-level errors
		timeoutCt    int64
		refusedCt    int64
		otherNetCt   int64
		statusCounts sync.Map // code -> *int64
		rec          recorder
	)

	ctx, cancel := context.WithDeadline(context.Background(), endTime)
	defer cancel()

	var globalTicker *time.Ticker
	if *qps > 0 {
		globalTicker = time.NewTicker(time.Second / time.Duration(*qps))
		defer globalTicker.Stop()
	}

	work := func(id int) {
		for {
			if ctx.Err() != nil {
				return
			}
			if *qps > 0 {
				<-globalTicker.C
			}
			idx := atomic.AddInt64(&reqCount, 1)
			val := values[idx%int64(len(values))]
			url := *target
			if strings.Contains(url, "{q}") {
				url = strings.ReplaceAll(url, "{q}", urlEncode(val))
			} else if strings.Contains(url, "?") {
				// append &q= if user didn't specify placeholder but target looks like /check
				// skip if already has q=
				if !strings.Contains(url, "q=") {
					url += "&q=" + urlEncode(val)
				}
			} else {
				// append ?q=
				if !strings.Contains(url, "q=") {
					url += "?q=" + urlEncode(val)
				}
			}
			st := time.Now()
			resp, err := client.Get(url)
			lat := time.Since(st)
			if time.Now().After(warmupUntil) {
				rec.add(lat)
			}
			if err != nil {
				classifyNetErr(err, &netErrCt, &timeoutCt, &refusedCt, &otherNetCt)
				continue
			}
			// drain body to allow reuse; small bodies expected
			io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&httpErrorCt, 1)
			}
			v, _ := statusCounts.LoadOrStore(resp.StatusCode, new(int64))
			atomic.AddInt64(v.(*int64), 1)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); work(i) }(i)
	}
	wg.Wait()

	total := atomic.LoadInt64(&reqCount)
	ok := atomic.LoadInt64(&successCount)
	httpErr := atomic.LoadInt64(&httpErrorCt)
	netErr := atomic.LoadInt64(&netErrCt)
	toErr := atomic.LoadInt64(&timeoutCt)
	refErr := atomic.LoadInt64(&refusedCt)
	othNet := atomic.LoadInt64(&otherNetCt)
	elapsed := time.Since(start)
	p50, p95, p99 := rec.percentiles()
	avgRPS := float64(total) / elapsed.Seconds()

	fmt.Println("=== Benchmark Summary ===")
	fmt.Printf("Target:      %s\n", *target)
	fmt.Printf("Duration:    %s (warmup %s)\n", elapsed.Truncate(time.Millisecond), *warmup)
	fmt.Printf("Workers:     %d\n", *concurrency)
	if *qps > 0 {
		fmt.Printf("QPS cap:     %d\n", *qps)
	}
	fmt.Printf("Requests:    %d (success %d, http_error %d, net_error %d)\n", total, ok, httpErr, netErr)
	fmt.Printf("Throughput:  %.1f req/s\n", avgRPS)
	fmt.Printf("Latency p50: %s  p95: %s  p99: %s\n", p50, p95, p99)
	fmt.Println("Status codes:")
	statusCounts.Range(func(k, v any) bool {
		fmt.Printf("  %d: %d\n", k.(int), atomic.LoadInt64(v.(*int64)))
		return true
	})
	if netErr > 0 {
		fmt.Println("Network errors:")
		fmt.Printf("  timeouts: %d\n", toErr)
		fmt.Printf("  refused:  %d\n", refErr)
		fmt.Printf("  other:    %d\n", othNet)
	}
}

func urlEncode(s string) string {
	// very small subset for speed; delegate to net/url if expanded usage later
	replacer := strings.NewReplacer(" ", "%20", "\"", "%22", "<", "%3C", ">", "%3E")
	return replacer.Replace(s)
}

func classifyNetErr(err error, netErrCt, timeoutCt, refusedCt, otherNetCt *int64) {
	atomic.AddInt64(netErrCt, 1)
	if ne, ok := err.(net.Error); ok {
		if ne.Timeout() {
			atomic.AddInt64(timeoutCt, 1)
			return
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		atomic.AddInt64(timeoutCt, 1)
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "No connection could be made") {
		atomic.AddInt64(refusedCt, 1)
		return
	}
	atomic.AddInt64(otherNetCt, 1)
}

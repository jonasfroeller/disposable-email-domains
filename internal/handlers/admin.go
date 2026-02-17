package handlers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"disposable-email-domains/internal/metrics"

	"golang.org/x/net/publicsuffix"
)

func (a *API) Blocklist(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/blocklist" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		summary := q.Get("summary") == "true"
		offset := 0
		limit := 0
		if s := strings.TrimSpace(q.Get("offset")); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v >= 0 {
				offset = v
			}
		}
		if s := strings.TrimSpace(q.Get("limit")); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v >= 0 {
				limit = v
			}
		}
		entries, total, err := readBlocklistEntriesPaged("blocklist.conf", offset, limit)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if summary {
			respondJSON(w, http.StatusOK, map[string]any{"count": total})
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": total, "offset": offset, "limit": limit})
	case http.MethodPost:
		var payload struct {
			Entries []string `json:"entries"`
			URL     string   `json:"url"`
			URLs    []string `json:"urls"`
		}
		if err := decodeJSON(w, r, &payload, 5<<20); err != nil { // 5MB
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(payload.Entries) == 0 && strings.TrimSpace(payload.URL) == "" && len(payload.URLs) == 0 {
			respondError(w, http.StatusBadRequest, "provide entries or url(s)")
			return
		}

		// Collect candidates
		candidates := make([]string, 0, len(payload.Entries))
		// Track unique incoming candidates across all sources (before comparing to existing file)
		incomingSet := make(map[string]struct{})
		for _, e := range payload.Entries {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == "" || strings.HasPrefix(e, "#") {
				continue
			}
			candidates = append(candidates, e)
			incomingSet[e] = struct{}{}
		}
		// Collect URLs to fetch (deduplicated)
		urlSet := make(map[string]struct{})
		if u := strings.TrimSpace(payload.URL); u != "" {
			urlSet[u] = struct{}{}
		}
		for _, u := range payload.URLs {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			urlSet[u] = struct{}{}
		}
		const (
			maxPerFetchEntries = 200_000 // safety upper bound
			maxLineLen         = 256
		)
		totalCandidateLimitTriggered := false
		if len(urlSet) > 0 {
			client := &http.Client{Timeout: 12 * time.Second}
			// cumulative limit across all fetched bodies (32MB)
			var cumulative int64
			const cumulativeCap = 32 << 20
			for u := range urlSet {
				if !(strings.HasPrefix(u, "https://")) { // enforce https only
					respondError(w, http.StatusBadRequest, "only https scheme allowed for remote lists")
					return
				}
				// Resolve host and reject private / special IP ranges to reduce SSRF risk.
				parsed, err := url.Parse(u)
				if err != nil {
					respondError(w, http.StatusBadRequest, "invalid url: "+err.Error())
					return
				}
				host := parsed.Host
				if hIdx := strings.Index(host, ":"); hIdx != -1 { // strip port
					host = host[:hIdx]
				}
				ips, err := net.LookupIP(host)
				if err != nil || len(ips) == 0 {
					respondError(w, http.StatusBadRequest, "dns lookup failed for host")
					return
				}
				for _, ip := range ips {
					if isDisallowedIP(ip) {
						respondError(w, http.StatusBadRequest, "disallowed host ip range")
						return
					}
				}

				resp, err := client.Get(u)
				if err != nil {
					respondError(w, http.StatusBadRequest, "failed to fetch url: "+err.Error())
					return
				}
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					_ = resp.Body.Close()
					respondError(w, http.StatusBadRequest, "fetch url status: "+resp.Status)
					return
				}
				const maxURLBody = 12 << 20 // 12MB per URL
				lr := &io.LimitedReader{R: resp.Body, N: maxURLBody + 1}
				data, err := io.ReadAll(lr)
				_ = resp.Body.Close()
				if err != nil {
					respondError(w, http.StatusBadRequest, "failed reading url body: "+err.Error())
					return
				}
				if int64(len(data)) > maxURLBody {
					respondError(w, http.StatusBadRequest, "url body too large")
					return
				}
				cumulative += int64(len(data))
				if cumulative > cumulativeCap {
					respondError(w, http.StatusBadRequest, "cumulative fetched data too large")
					return
				}

				trimmed := bytes.TrimSpace(data)

				// Try to parse as JSON array of strings first
				var arr []string
				if len(trimmed) > 0 && trimmed[0] == '[' && json.Unmarshal(trimmed, &arr) == nil {
					for _, v := range arr {
						v = strings.ToLower(strings.TrimSpace(v))
						if v == "" || strings.HasPrefix(v, "#") {
							continue
						}
						if !isLikelyDomain(v) {
							continue
						}
						if len(v) > maxLineLen {
							continue
						}
						// Enforce eTLD+1
						if etld1, err := publicsuffix.EffectiveTLDPlusOne(v); err == nil && etld1 != "" {
							v = etld1
						} else {
							continue // Skip if not a valid registrable domain (e.g. is a TLD)
						}
						if len(candidates) < maxPerFetchEntries {
							candidates = append(candidates, v)
							incomingSet[v] = struct{}{}
						} else {
							totalCandidateLimitTriggered = true
							break
						}
					}
					continue
				}

				// If content looks like a JSON object, reject to avoid accidentally ingesting documents like wildcard maps.
				if len(trimmed) > 0 && trimmed[0] == '{' {
					respondError(w, http.StatusBadRequest, "unsupported JSON document; expected array of strings")
					return
				}

				// Fallback to plaintext, one domain per non-empty, non-comment line
				s := bufio.NewScanner(bytes.NewReader(data))
				for s.Scan() {
					line := strings.ToLower(strings.TrimSpace(s.Text()))
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					if !isLikelyDomain(line) {
						continue
					}
					if len(line) > maxLineLen {
						continue
					}
					// Enforce eTLD+1
					if etld1, err := publicsuffix.EffectiveTLDPlusOne(line); err == nil && etld1 != "" {
						line = etld1
					} else {
						continue // Skip if not a valid registrable domain (e.g. is a TLD)
					}
					if len(candidates) < maxPerFetchEntries {
						candidates = append(candidates, line)
						incomingSet[line] = struct{}{}
					} else {
						totalCandidateLimitTriggered = true
						break
					}
				}
				if err := s.Err(); err != nil {
					respondError(w, http.StatusBadRequest, "failed reading url body: "+err.Error())
					return
				}
			}
		}
		if len(candidates) == 0 {
			respondError(w, http.StatusBadRequest, "no valid entries to add")
			return
		}
		if totalCandidateLimitTriggered {
			a.Logger.Println("blocklist fetch: candidate cap reached")
		}

		// Build existing set and count total lines for id calculation
		existingSet := make(map[string]struct{})
		totalLines, err := buildExistingSet("blocklist.conf", existingSet)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		existingBefore := len(existingSet)

		// Filter new unique entries
		unique := make([]string, 0, len(candidates))
		for _, c := range candidates {
			if _, ok := existingSet[c]; ok {
				continue
			}
			existingSet[c] = struct{}{}
			unique = append(unique, c)
		}

		// Atomic append: serialize and write via temp file rename
		if len(unique) > 0 {
			a.blMu.Lock()
			// read existing full file (including comments) to preserve content
			orig, _ := os.ReadFile("blocklist.conf")
			var b bytes.Buffer
			b.Write(orig)
			if len(orig) > 0 && !bytes.HasSuffix(orig, []byte{'\n'}) {
				b.WriteByte('\n')
			}
			for _, v := range unique {
				b.WriteString(v)
				b.WriteByte('\n')
			}
			tmpName := filepath.Join(filepath.Dir("blocklist.conf"), "blocklist.conf.tmp")
			if err := os.WriteFile(tmpName, b.Bytes(), 0o644); err != nil {
				a.blMu.Unlock()
				respondError(w, http.StatusInternalServerError, "write temp: "+err.Error())
				return
			}
			if err := os.Rename(tmpName, "blocklist.conf"); err != nil {
				a.blMu.Unlock()
				respondError(w, http.StatusInternalServerError, "rename: "+err.Error())
				return
			}
			// Ensure in-memory checker view reflects appended domains immediately.
			if a.Check != nil {
				a.Check.PatchBlock(unique)
			}
			// Update status snapshot
			if a.Check != nil {
				a.statusMu.Lock()
				a.status.BlocklistCount = a.Check.BlockCount()
				a.status.LastListUpdate = time.Now().UTC()
				a.statusMu.Unlock()
			}
			a.blMu.Unlock()
		}

		// Optional reload via query param (now generally unnecessary for correctness,
		// but kept for callers who want a full re-parse + validation path).
		reload := r.URL.Query().Get("reload") == "true"
		reloaded := false
		if reload && a.Check != nil {
			if err := a.Check.Reload(false); err == nil {
				reloaded = true
				a.statusMu.Lock()
				a.status.BlocklistCount = a.Check.BlockCount()
				a.status.AllowlistCount = a.Check.AllowCount()
				a.status.LastListUpdate = time.Now().UTC()
				a.statusMu.Unlock()
			}
		}

		// Compute ids for appended entries
		added := make([]map[string]any, 0, len(unique))
		for i, v := range unique {
			added = append(added, map[string]any{"id": totalLines + i + 1, "domain": v})
		}

		appended := len(unique)
		skipped := len(candidates) - len(unique)
		incomingTotal := len(candidates)
		incomingUnique := len(incomingSet)
		existingAfter := len(existingSet)
		if appended > 0 {
			metrics.BlocklistAppendsTotal.Add(float64(appended))
		}
		if skipped > 0 {
			metrics.BlocklistDuplicatesSkippedTotal.Add(float64(skipped))
		}
		respondJSON(w, http.StatusOK, map[string]any{
			"appended":           appended,
			"skipped_duplicates": skipped,
			"added":              added,
			"reloaded":           reloaded,
			"meta": map[string]any{
				"incoming_total":         incomingTotal,
				"incoming_unique":        incomingUnique,
				"existing_unique_before": existingBefore,
				"existing_unique_after":  existingAfter,
			},
		})
	default:
		respondMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (a *API) ReloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondMethodNotAllowed(w, http.MethodPost)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	strict := r.URL.Query().Get("strict") == "true"
	if err := a.Check.Reload(strict); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Update counts after full reload
	if a.Check != nil {
		a.statusMu.Lock()
		a.status.BlocklistCount = a.Check.BlockCount()
		a.status.AllowlistCount = a.Check.AllowCount()
		a.status.LastListUpdate = time.Now().UTC()
		a.statusMu.Unlock()
	}
	respondJSON(w, http.StatusOK, map[string]any{"reloaded": true, "strict": strict})
}

// readBlocklistEntriesPaged streams the file and returns up to 'limit' entries after skipping 'offset' entries.
func readBlocklistEntriesPaged(path string, offset, limit int) ([]map[string]any, int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, 0, nil
		}
		return nil, 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	fileLine := 0
	entriesSeen := 0
	var out []map[string]any
	for s.Scan() {
		fileLine++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entriesSeen++
		if entriesSeen <= offset {
			continue
		}
		if limit > 0 && len(out) >= limit {
			continue
		}
		out = append(out, map[string]any{"id": fileLine, "domain": strings.ToLower(line)})
	}
	if err := s.Err(); err != nil {
		return nil, entriesSeen, err
	}
	return out, entriesSeen, nil
}

func buildExistingSet(path string, set map[string]struct{}) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[strings.ToLower(line)] = struct{}{}
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return lineNo, nil
}

// isDisallowedIP returns true if the IP is within private, loopback, link-local,
// multicast, unspecified or unique-local (IPv6) ranges. This reduces SSRF risk
// when fetching remote blocklist sources.
func isDisallowedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Private IPv4 ranges
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10: // 10.0.0.0/8
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31: // 172.16.0.0/12
			return true
		case v4[0] == 192 && v4[1] == 168: // 192.168.0.0/16
			return true
		case v4[0] == 169 && v4[1] == 254: // link-local 169.254/16 (already caught, keep explicit)
			return true
		}
		return false
	}
	// Unique local IPv6 fc00::/7
	if ip.To16() != nil {
		b0 := ip[0]
		if b0&0xfe == 0xfc { // 0b11111100 -> fc00::/7
			return true
		}
	}
	return false
}

package handlers

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"disposable-email-domains/internal/domain"
)

func (a *API) CheckHandler(w http.ResponseWriter, r *http.Request) {
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" {
			respondError(w, http.StatusBadRequest, "missing q")
			return
		}
		res := a.Check.Check(q)
		respondJSON(w, http.StatusOK, res)
	default:
		respondMethodNotAllowed(w, http.MethodGet)
	}
}

// CheckEmailsBatch handles POST /check/emails
// Accepts either:
//   - Content-Type: application/json with body ["a@b.com", "c@d.com", ...]
//     or {"items":["a@b.com", ...]} or {"emails":[...]} or {"values":[...]}
//   - Content-Type: text/plain with newline-separated emails
//
// Returns JSON array of domain.Result objects in the same order as provided.
func (a *API) CheckEmailsBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondMethodNotAllowed(w, http.MethodPost)
		return
	}
	if r.URL.Path != "/check/emails" {
		http.NotFound(w, r)
		return
	}
	if a.Check == nil || !a.Check.IsReady() {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	items, err := parseBatchStrings(w, r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if r.URL.Query().Get("format") == "ndjson" {
		a.streamBatchNDJSON(w, r, items)
		return
	}
	max := 200000
	if a.cfg != nil && a.cfg.BatchMaxItems > 0 {
		max = a.cfg.BatchMaxItems
	}
	if len(items) > max {
		respondError(w, http.StatusRequestEntityTooLarge, "too many items (max "+strconv.Itoa(max)+")")
		return
	}
	results := make([]domain.Result, len(items))
	for i, s := range items {
		results[i] = a.Check.Check(s)
	}
	respondJSON(w, http.StatusOK, results)
}

// CheckDomainsBatch handles POST /check/domains with same formats as emails.
func (a *API) CheckDomainsBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondMethodNotAllowed(w, http.MethodPost)
		return
	}
	if r.URL.Path != "/check/domains" {
		http.NotFound(w, r)
		return
	}
	if a.Check == nil || !a.Check.IsReady() {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	items, err := parseBatchStrings(w, r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if r.URL.Query().Get("format") == "ndjson" {
		a.streamBatchNDJSON(w, r, items)
		return
	}
	max := 200000
	if a.cfg != nil && a.cfg.BatchMaxItems > 0 {
		max = a.cfg.BatchMaxItems
	}
	if len(items) > max {
		respondError(w, http.StatusRequestEntityTooLarge, "too many items (max "+strconv.Itoa(max)+")")
		return
	}
	results := make([]domain.Result, len(items))
	for i, s := range items {
		results[i] = a.Check.Check(s)
	}
	respondJSON(w, http.StatusOK, results)
}

// streamBatchNDJSON writes one JSON object per line for each input, minimizing memory usage.
func (a *API) streamBatchNDJSON(w http.ResponseWriter, r *http.Request, items []string) {
	max := 1_000_000
	if a.cfg != nil && a.cfg.BatchStreamMaxItems > 0 {
		max = a.cfg.BatchStreamMaxItems
	}
	if len(items) > max {
		respondError(w, http.StatusRequestEntityTooLarge, "too many items for streaming (max "+strconv.Itoa(max)+")")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	enc := json.NewEncoder(w)
	// Stream one by one; best-effort flush
	flusher, _ := w.(http.Flusher)
	for _, s := range items {
		res := a.Check.Check(s)
		if err := enc.Encode(res); err != nil {
			// can't write JSON? abort
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// Path-based check: /check/emails/{email}
func (a *API) CheckEmailPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	prefix := "/check/emails/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, prefix)
	if raw == "" || strings.Contains(raw, "/") {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	val, err := url.PathUnescape(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid path encoding")
		return
	}
	res := a.Check.Check(val)
	respondJSON(w, http.StatusOK, res)
}

// Path-based check: /check/domains/{domain}
func (a *API) CheckDomainPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	prefix := "/check/domains/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, prefix)
	if raw == "" || strings.Contains(raw, "/") {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	val, err := url.PathUnescape(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid path encoding")
		return
	}
	res := a.Check.Check(val)
	respondJSON(w, http.StatusOK, res)
}

// Alias Path-based check: /emails/{email}
// Mirrors CheckEmailPath but avoids the "/check" prefix to bypass certain upstream WAF rules.
func (a *API) CheckEmailAliasPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	var raw string
	switch {
	case strings.HasPrefix(r.URL.Path, "/emails/"):
		raw = strings.TrimPrefix(r.URL.Path, "/emails/")
	case strings.HasPrefix(r.URL.Path, "/e/"):
		raw = strings.TrimPrefix(r.URL.Path, "/e/")
	default:
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	if raw == "" || strings.Contains(raw, "/") {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	val, err := url.PathUnescape(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid path encoding")
		return
	}
	res := a.Check.Check(val)
	respondJSON(w, http.StatusOK, res)
}

// Alias Path-based check: /domains/{domain}
// Mirrors CheckDomainPath but avoids the "/check" prefix to bypass certain upstream WAF rules.
func (a *API) CheckDomainAliasPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	var raw string
	switch {
	case strings.HasPrefix(r.URL.Path, "/domains/"):
		raw = strings.TrimPrefix(r.URL.Path, "/domains/")
	case strings.HasPrefix(r.URL.Path, "/d/"):
		raw = strings.TrimPrefix(r.URL.Path, "/d/")
	default:
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	if raw == "" || strings.Contains(raw, "/") {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	val, err := url.PathUnescape(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid path encoding")
		return
	}
	res := a.Check.Check(val)
	respondJSON(w, http.StatusOK, res)
}

// parseBatchStrings parses the request body into a slice of strings.
// Supported formats:
// - JSON array of strings
// - JSON object with one of keys: items, values, emails, domains (array of strings)
// - text/plain newline-separated values
func parseBatchStrings(w http.ResponseWriter, r *http.Request) ([]string, error) {
	const maxBody = 16 << 20 // 16MB
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		// Attempt array first
		var arr []string
		if err := decodeJSON(w, r, &arr, maxBody); err == nil {
			return sanitizeStrings(arr), nil
		}
		// Attempt object with common keys
		var obj map[string]any
		if err := decodeJSON(w, r, &obj, maxBody); err != nil {
			return nil, err
		}
		for _, k := range []string{"items", "values", "emails", "domains"} {
			if v, ok := obj[k]; ok {
				switch vv := v.(type) {
				case []any:
					out := make([]string, 0, len(vv))
					for _, iv := range vv {
						if s, ok := iv.(string); ok {
							out = append(out, s)
						}
					}
					return sanitizeStrings(out), nil
				case []string:
					return sanitizeStrings(vv), nil
				}
			}
		}
		return nil, errors.New("invalid JSON payload; expected array of strings or {items|values|emails|domains: [...]} ")
	}
	// Fallback: treat as text
	limited := http.MaxBytesReader(w, r.Body, maxBody)
	defer limited.Close()
	var lines []string
	s := bufio.NewScanner(limited)
	// Increase scanner buffer for long lines
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New("empty body")
	}
	return sanitizeStrings(lines), nil
}

func sanitizeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

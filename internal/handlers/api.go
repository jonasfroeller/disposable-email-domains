package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"disposable-email-domains/internal/config"
	"disposable-email-domains/internal/domain"

	"golang.org/x/net/publicsuffix"
)

type Item struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Store interface (currently not heavily exercised; kept for future extension/testing scaffolding).
type Store interface {
	List() []Item
	Get(id string) (Item, bool)
	Create(name string) (Item, error)
	Update(id, name string) (Item, error)
	Delete(id string) bool
}

type API struct {
	Store  Store
	Logger *log.Logger
	Check  *domain.Checker
	// mutex to serialize blocklist mutation operations
	blMu     sync.Mutex
	statusMu sync.RWMutex
	status   ServiceStatus
	// optional config for limits
	cfg *config.Config
}

// Attaches configuration for limits and options.
func (a *API) SetConfig(cfg *config.Config) {
	a.cfg = cfg
}

// Lightweight snapshot for diagnostics.
type ServiceStatus struct {
	BlocklistCount int       `json:"blocklist_count"`
	AllowlistCount int       `json:"allowlist_count"`
	LastListUpdate time.Time `json:"last_list_update"`
	Ready          bool      `json:"ready"`
}

func (a *API) InitStatus() {
	if a.Check == nil || !a.Check.IsReady() {
		return
	}
	a.statusMu.Lock()
	a.status.BlocklistCount = a.Check.BlockCount()
	// allow count (reflecting raw length minus comments)
	a.status.AllowlistCount = a.Check.AllowCount()
	// get updatedAt from a check of a dummy value to avoid new accessor; UpdatedAt already exposed via a check result.
	if a.status.LastListUpdate.IsZero() {
		a.status.LastListUpdate = time.Now().UTC()
	}
	a.statusMu.Unlock()
}

// Helpers

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	w.WriteHeader(status)
	if v == nil || status == http.StatusNoContent {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

type apiError struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Meta    map[string]any `json:"meta,omitempty"`
	} `json:"error"`
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string, meta map[string]any) {
	if code == "" {
		code = http.StatusText(status)
	}
	var body apiError
	body.Error.Code = code
	body.Error.Message = msg
	if len(meta) > 0 {
		body.Error.Meta = meta
	}
	respondJSON(w, status, body)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	writeAPIError(w, status, "", msg, nil)
}

func respondMethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	respondError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			return errors.New("Content-Type must be application/json")
		}
	}

	if r.Body == nil {
		return errors.New("empty body")
	}
	defer r.Body.Close()

	limited := http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty body")
		}
		return err
	}
	if dec.More() {
		return errors.New("only a single JSON object is allowed")
	}
	return nil
}

// Filters out URLs, emails, and obviously invalid labels, and ensures the string has a known public suffix.
func isLikelyDomain(s string) bool {
	if s == "" {
		return false
	}
	// Reject if contains URL scheme or path/query fragments
	if strings.Contains(s, "://") || strings.ContainsAny(s, "/?@ \\:\t\n\r") {
		return false
	}
	// Trim leading dot and trailing dot, common in some lists
	s = strings.Trim(s, ".")
	if len(s) == 0 {
		return false
	}
	// Basic character check: allow a-z 0-9 - and dots
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			continue
		}
		return false
	}
	// Must contain at least one dot
	if !strings.Contains(s, ".") {
		return false
	}
	// Labels cannot start or end with '-'
	parts := strings.Split(s, ".")
	for _, p := range parts {
		if p == "" {
			return false
		}
		if p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
	}
	// Check it has a known public suffix and an eTLD+1
	if _, icann := publicsuffix.PublicSuffix(s); !icann {
		// still allow private suffixes, but ensure EffectiveTLDPlusOne works
		if _, err := publicsuffix.EffectiveTLDPlusOne(s); err != nil {
			return false
		}
		return true
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(s); err != nil {
		return false
	}
	return true
}

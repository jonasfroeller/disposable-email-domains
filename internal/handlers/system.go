package handlers

import (
	"net/http"
	"os"
	"time"
)

func (a *API) Health(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *API) Live(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"alive": true})
}

func (a *API) Favicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if r.URL.Path != "/favicon.ico" && r.URL.Path != "/favicon.png" {
		http.NotFound(w, r)
		return
	}
	const avatar = "https://avatars.githubusercontent.com/u/121523551?v=4"
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.Redirect(w, r, avatar, http.StatusFound)
}

// Returns quick diagnostic counts & last update timestamp.
func (a *API) Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	// Refresh dynamic readiness cheaply
	ready := a.Check != nil && a.Check.IsReady()
	a.statusMu.RLock()
	st := a.status
	a.statusMu.RUnlock()
	st.Ready = ready
	respondJSON(w, http.StatusOK, st)
}

// Reports application readiness (lists loaded & checker initialized & PSL file exists).
func (a *API) Ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil || !a.Check.IsReady() {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false})
		return
	}
	// Verify PSL snapshot exists
	if _, err := os.Stat("public_suffix_list.dat"); err != nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "error": "psl missing"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ready": true, "updated_at": a.Check.Validate().CheckedAt.Format(time.RFC3339)})
}

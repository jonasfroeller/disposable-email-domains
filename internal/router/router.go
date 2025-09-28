package router

import (
	"log"
	"net/http"

	"disposable-email-domains/internal/config"
	"disposable-email-domains/internal/domain"
	"disposable-email-domains/internal/handlers"
	"disposable-email-domains/internal/metrics"
	"disposable-email-domains/internal/middleware"
	"disposable-email-domains/internal/pslrefresher"
)

type storageAPI interface {
	List() []handlers.Item
	Get(id string) (handlers.Item, bool)
	Create(name string) (handlers.Item, error)
	Update(id, name string) (handlers.Item, error)
	Delete(id string) bool
}

func New(store storageAPI, logger *log.Logger, checker *domain.Checker, cfg config.Config, refresher *pslrefresher.Refresher, version string) http.Handler {
	api := &handlers.API{Store: store, Logger: logger, Check: checker}
	// attach config pointer for batch limits
	cfgCopy := cfg
	api.SetConfig(&cfgCopy)
	// Seed status counts after initial load (checker.Load already called in main before router.New)
	api.InitStatus()

	// configure trust proxy header behavior early
	middleware.SetTrustProxyHeaders(cfg.TrustProxyHeaders)

	mux := http.NewServeMux()
	mux.HandleFunc("/", api.Index)
	mux.HandleFunc("/healthz", api.Health)
	mux.HandleFunc("/livez", api.Live)
	mux.HandleFunc("/status", api.Status)
	mux.HandleFunc("/readyz", api.Ready)
	mux.HandleFunc("/favicon.ico", api.Favicon)
	mux.HandleFunc("/favicon.png", api.Favicon)
	mux.Handle("/metrics", metrics.Handler())

	// JSON check
	mux.HandleFunc("/check", api.CheckHandler)
	// Aliases to avoid potential upstream WAF blocking of "/check" prefix
	mux.HandleFunc("/q", api.CheckHandler) // GET /q?q=...
	// Batch JSON checks
	mux.HandleFunc("/check/emails", api.CheckEmailsBatch)   // POST array or text
	mux.HandleFunc("/check/domains", api.CheckDomainsBatch) // POST array or text
	mux.HandleFunc("/check/emails/", api.CheckEmailPath)
	mux.HandleFunc("/check/domains/", api.CheckDomainPath)
	// Aliases for path-based checks without the "/check" prefix (helps bypass strict WAFs)
	mux.HandleFunc("/emails/", api.CheckEmailAliasPath)
	mux.HandleFunc("/domains/", api.CheckDomainAliasPath)
	// Short aliases to avoid keywords like "emails"/"domains" being blocked upstream
	mux.HandleFunc("/e/", api.CheckEmailAliasPath)
	mux.HandleFunc("/d/", api.CheckDomainAliasPath)

	// Validation + reports
	mux.HandleFunc("/validate", api.ValidateHandler)
	mux.HandleFunc("/report", api.ReportValidateHTML)
	mux.HandleFunc("/report/emails/", api.ReportCheckEmailHTML)
	mux.HandleFunc("/report/domains/", api.ReportCheckDomainHTML)
	mux.HandleFunc("/report/check", api.ReportCheckQueryHTML)

	// Lists download
	mux.HandleFunc("/allowlist.conf", api.GetAllowlistFile)
	mux.HandleFunc("/blocklist.conf", api.GetBlocklistFile)
	mux.HandleFunc("/public_suffix_list.dat", api.GetPSLFile)
	mux.HandleFunc("/psl", api.GetPSLFile)
	mux.HandleFunc("/psl.txt", api.GetPSLFile)

	// Blocklist JSON management
	mux.HandleFunc("/blocklist", api.Blocklist)

	mux.HandleFunc("/reload", api.ReloadHandler)
	if refresher != nil {
		mux.HandleFunc("/admin/psl/refresh", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if ok := refresher.RefreshNow(); !ok {
				http.Error(w, "refresh failed", http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
				http.Error(w, "write error", http.StatusInternalServerError)
				return
			}
		})
	}

	var adminTokenList []string
	adminTokenList = append(adminTokenList, cfg.AdminTokens...)
	return middleware.Chain(mux,
		middleware.SecurityHeaders(),
		middleware.VersionHeader(version),
		middleware.Recover(logger),
		middleware.RequestIDMiddleware(),
		middleware.RedirectCheckPaths(cfg.EnableCheckRedirects),
		middleware.RateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst, cfg.RateLimiterTTL, logger, cfg.RateLimitBypassDomains),
		middleware.AdminGuardMulti(adminTokenList, logger),
		middleware.Logging(logger),
	)
}

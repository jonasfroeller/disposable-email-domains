package router

import (
	"log"
	"net/http"

	"disposable-email-domains/internal/domain"
	"disposable-email-domains/internal/handlers"
	"disposable-email-domains/internal/middleware"
)

type storageAPI interface {
	List() []handlers.Item
	Get(id string) (handlers.Item, bool)
	Create(name string) (handlers.Item, error)
	Update(id, name string) (handlers.Item, error)
	Delete(id string) bool
}

func New(store storageAPI, logger *log.Logger, checker *domain.Checker) http.Handler {
	api := &handlers.API{Store: store, Logger: logger, Check: checker}

	mux := http.NewServeMux()
	mux.HandleFunc("/", api.Index)
	mux.HandleFunc("/healthz", api.Health)

	// JSON check
	mux.HandleFunc("/check", api.CheckHandler)
	mux.HandleFunc("/check/emails/", api.CheckEmailPath)
	mux.HandleFunc("/check/domains/", api.CheckDomainPath)

	// Validation + reports
	mux.HandleFunc("/validate", api.ValidateHandler)
	mux.HandleFunc("/report", api.ReportValidateHTML)
	mux.HandleFunc("/report/emails/", api.ReportCheckEmailHTML)
	mux.HandleFunc("/report/domains/", api.ReportCheckDomainHTML)

	// Lists download
	mux.HandleFunc("/allowlist.conf", api.GetAllowlistFile)
	mux.HandleFunc("/blocklist.conf", api.GetBlocklistFile)
	mux.HandleFunc("/public_suffix_list.dat", api.GetPSLFile)

	// Blocklist JSON management
	mux.HandleFunc("/blocklist", api.Blocklist)

	mux.HandleFunc("/reload", api.ReloadHandler)

	return middleware.Chain(mux,
		middleware.SecurityHeaders(),
		middleware.Recover(logger),
		middleware.Logging(logger),
	)
}

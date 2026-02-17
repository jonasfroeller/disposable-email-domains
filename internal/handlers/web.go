package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"disposable-email-domains/internal/domain"
	"disposable-email-domains/web"
)

func (a *API) Index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	indexHTMLBytes, err := web.Content.ReadFile("templates/index.html")
	if err != nil {
		a.Logger.Printf("template read error: %v", err)
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	indexHTML := string(indexHTMLBytes)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https: data: avatars.githubusercontent.com; font-src 'self' data:; connect-src 'self' https:; script-src 'nonce-"+nonce+"'; frame-ancestors 'none'; base-uri 'none'")

	host := r.Host

	// Build endpoint metadata for the in-page API Explorer (used to render dynamic details)
	type ep struct {
		Method       string `json:"method"`
		Path         string `json:"path"`
		Desc         string `json:"desc"`
		SampleURL    string `json:"sample_url,omitempty"`
		RespType     string `json:"resp_type"`
		ContentType  string `json:"content_type"`
		BodyTemplate string `json:"body_template,omitempty"`
		NeedsToken   bool   `json:"needs_token,omitempty"`
	}
	// type strings derived dynamically where possible
	statusType := "" + (func() string { return (func(v any) string { return fmt.Sprintf("%T", v) })(ServiceStatus{}) })()
	resultType := "" + (func() string { return (func(v any) string { return fmt.Sprintf("%T", v) })(domain.Result{}) })()
	reportType := "" + (func() string { return (func(v any) string { return fmt.Sprintf("%T", v) })(domain.Report{}) })()

	// compose list
	eps := []ep{
		{Method: "GET", Path: "/healthz", Desc: "Health check", SampleURL: "/healthz", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json"},
		{Method: "GET", Path: "/livez", Desc: "Liveness (always OK)", SampleURL: "/livez", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json"},
		{Method: "GET", Path: "/status", Desc: "Status snapshot", SampleURL: "/status", RespType: statusType, ContentType: "application/json"},
		{Method: "GET", Path: "/readyz", Desc: "Readiness probe", SampleURL: "/readyz", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json"},
		{Method: "GET", Path: "/blocklist", Desc: "List blocklist (use ?summary=true or paginate ?offset=&limit=)", SampleURL: "/blocklist?summary=true", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json"},
		{Method: "POST", Path: "/blocklist", Desc: "Extend blocklist (entries/url(s))", SampleURL: "/blocklist", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json", BodyTemplate: `{"entries":["foo.com","bar.io"]}`, NeedsToken: true},
		{Method: "GET", Path: "/check", Desc: "Check via ?q=", SampleURL: "/check?q=test@example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "GET", Path: "/q", Desc: "Alias for /check?q= (WAF-safe)", SampleURL: "/q?q=test@example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "GET", Path: "/check/emails/{email}", Desc: "Check email", SampleURL: "/check/emails/test%40example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "GET", Path: "/check/domains/{domain}", Desc: "Check domain", SampleURL: "/check/domains/example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "GET", Path: "/emails/{email}", Desc: "Alias (WAF-safe) for email check", SampleURL: "/emails/test%40example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "GET", Path: "/domains/{domain}", Desc: "Alias (WAF-safe) for domain check", SampleURL: "/domains/example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "GET", Path: "/e/{email}", Desc: "Short alias (WAF-safe) for email check", SampleURL: "/e/test%40example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "GET", Path: "/d/{domain}", Desc: "Short alias (WAF-safe) for domain check", SampleURL: "/d/example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "POST", Path: "/check/emails", Desc: "Batch emails (JSON or text)", SampleURL: "/check/emails", RespType: "[]" + resultType, ContentType: "application/json", BodyTemplate: `{"items":["a@b.com","c@d.com"]}`},
		{Method: "POST", Path: "/check/domains", Desc: "Batch domains (JSON or text)", SampleURL: "/check/domains", RespType: "[]" + resultType, ContentType: "application/json", BodyTemplate: `{"items":["example.com","a.b.com"]}`},
		{Method: "GET", Path: "/validate", Desc: "Validate lists", SampleURL: "/validate", RespType: reportType, ContentType: "application/json"},
		{Method: "POST", Path: "/reload", Desc: "Full reload", SampleURL: "/reload", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json", NeedsToken: true},
		{Method: "GET", Path: "/report", Desc: "Validate report (HTML)", SampleURL: "/report", RespType: "text/html", ContentType: "text/html"},
		{Method: "GET", Path: "/report/check", Desc: "Check report via ?input=", SampleURL: "/report/check?input=test%40example.com", RespType: "text/html", ContentType: "text/html"},
		{Method: "GET", Path: "/report/emails/{email}", Desc: "Check report (HTML)", SampleURL: "/report/emails/test%40example.com", RespType: "text/html", ContentType: "text/html"},
		{Method: "GET", Path: "/report/domains/{domain}", Desc: "Check report (HTML)", SampleURL: "/report/domains/example.com", RespType: "text/html", ContentType: "text/html"},
		{Method: "GET", Path: "/allowlist.conf", Desc: "Download allowlist", SampleURL: "/allowlist.conf", RespType: "text/plain", ContentType: "text/plain"},
		{Method: "GET", Path: "/blocklist.conf", Desc: "Download blocklist", SampleURL: "/blocklist.conf", RespType: "text/plain", ContentType: "text/plain"},
		{Method: "GET", Path: "/public_suffix_list.dat", Desc: "Download PSL snapshot", SampleURL: "/public_suffix_list.dat", RespType: "text/plain", ContentType: "text/plain"},
		{Method: "GET", Path: "/psl", Desc: "Download PSL snapshot (alias)", SampleURL: "/psl", RespType: "text/plain", ContentType: "text/plain"},
		{Method: "GET", Path: "/psl.txt", Desc: "Download PSL snapshot (alias)", SampleURL: "/psl.txt", RespType: "text/plain", ContentType: "text/plain"},
		{Method: "GET", Path: "/metrics", Desc: "Prometheus metrics", SampleURL: "/metrics", RespType: "text/plain; OpenMetrics", ContentType: "text/plain"},
		{Method: "POST", Path: "/admin/psl/refresh", Desc: "Force PSL refresh", SampleURL: "/admin/psl/refresh", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json", NeedsToken: true},
	}
	epJSON, _ := json.Marshal(eps)

	data := struct {
		Host      string
		Nonce     string
		Endpoints template.JS
	}{
		Host:      host,
		Nonce:     nonce,
		Endpoints: template.JS(epJSON),
	}

	tmpl, err := template.New("index").Parse(indexHTML)
	if err != nil {
		a.Logger.Printf("template parsing error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		a.Logger.Printf("template execute error: %v", err)
	}
}

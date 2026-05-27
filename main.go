package main

import (
	"context"
	"database/sql"
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed security-maturity-assessment-browser.html
var deckDesktop []byte

//go:embed security-maturity-assessment-mobile.html
var deckMobile []byte

// portal/ holds the admin password portal templates. It's intentionally
// separate from the existing /admin static Pages mockup at the repo root.
//go:embed portal/login.html portal/admin.html
var portalFS embed.FS

//go:embed migrations/*.sql
var migrationsFS embed.FS

var (
	db             *sql.DB
	adminLoginTpl  *template.Template
	adminPortalTpl *template.Template
)

func main() {
	addr := envOr("LISTEN_ADDR", ":8080")
	must(loadKeys())

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL required")
	}
	if os.Getenv("ADMIN_PASSWORD") == "" && os.Getenv("ADMIN_TOKEN") == "" {
		log.Fatal("ADMIN_PASSWORD or ADMIN_TOKEN required")
	}

	adminLoginTpl = template.Must(template.ParseFS(portalFS, "portal/login.html"))
	adminPortalTpl = template.Must(template.ParseFS(portalFS, "portal/admin.html"))

	var err error
	db, err = sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatalf("open database: %s", redactDSN(err.Error()))
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("connect database: %s", redactDSN(err.Error()))
	}
	if err := applyMigrations(db); err != nil {
		log.Fatalf("apply migrations: %s", redactDSN(err.Error()))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", okHandler)

	mux.HandleFunc("/api/event", recordEvent)

	mux.HandleFunc("/admin", adminPortal)
	mux.HandleFunc("/admin/", http.NotFound)
	mux.HandleFunc("/admin/login", adminLogin)
	mux.HandleFunc("/admin/logout", adminLogout)
	mux.HandleFunc("/admin/mint", adminMint)
	mux.HandleFunc("/admin/qr", adminQR)
	mux.HandleFunc("/admin/stats", adminStatsHandler)
	mux.HandleFunc("/admin/leads", adminLeadsHandler)
	mux.HandleFunc("/admin/leads/status", adminLeadStatusHandler)
	mux.HandleFunc("/admin/events", adminEventsHandler)

	mux.HandleFunc("/", serveDeck)

	srv := &http.Server{
		Addr:              addr,
		Handler:           withLogging(withSecurityHeaders(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("assessment listening on %s", addr)
	must(srv.ListenAndServe())
}

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"rsc.io/qr"
)

const (
	sessCookieName      = "wt_sess"
	adminCookieName     = "wt_admin"
	tokenParam          = "t"
	maxEventsPerSession = 400
)

var (
	cookieSecure  = envOr("COOKIE_SECURE", "true") != "false"
	loginLimiter  = newLimiter(5, time.Minute)
	eventCounters = &sessionCounter{m: map[string]int{}}

	allowedPhases = map[string]bool{
		"sceneIntro": true, "sceneScenario": true, "sceneResults": true,
	}
	allowedScenarios = map[string]bool{
		"network": true, "app": true, "cnapp": true, "sspm": true,
	}
	// scenarioOrder is the deck's scenario order (see the scenarios array in
	// security-maturity-assessment-browser.html): Network, App, Cloud, Service.
	scenarioOrder = []string{"network", "app", "cnapp", "sspm"}
	allowedColors = map[string]bool{"red": true, "yellow": true, "green": true}

	emailRe    = regexp.MustCompile(`^[^@\s]{1,128}@[^@\s]{1,128}\.[^@\s]{1,32}$`)
	mobileUARe = regexp.MustCompile(`(?i)(Mobile|Android|iPhone|iPad|iPod|Opera Mini|IEMobile|Mobi)`)
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// dsnPwRe matches the password segment of a scheme://user:password@host DSN.
var dsnPwRe = regexp.MustCompile(`(://[^:@/\s]+:)[^@/\s]+(@)`)

// redactDSN masks DSN passwords in s so connection strings — and driver errors
// that embed DATABASE_URL — never reach the logs in clear text.
func redactDSN(s string) string {
	return dsnPwRe.ReplaceAllString(s, "${1}xxxxx${2}")
}

func okHandler(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }

func withLogging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s ip=%s dur=%s", r.Method, r.URL.Path, clientIP(r), time.Since(start))
	})
}

func withSecurityHeaders(h http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
		"font-src 'self' https://fonts.gstatic.com; " +
		"img-src 'self' data: blob:; " +
		"script-src 'self' 'unsafe-inline'; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if i := strings.Index(ip, ","); i > 0 {
		ip = ip[:i]
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip = host
	}
	return ip
}

func clientIPHash(r *http.Request) string {
	salt := envOr("IP_SALT", "wt")
	sum := sha256.Sum256([]byte(salt + ":" + clientIP(r)))
	return hex.EncodeToString(sum[:])[:16]
}

func pickDeck(r *http.Request) []byte {
	if r.Header.Get("Sec-CH-UA-Mobile") == "?1" {
		return deckMobile
	}
	if mobileUARe.MatchString(r.UserAgent()) {
		return deckMobile
	}
	return deckDesktop
}

func serveDeck(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if t := r.URL.Query().Get(tokenParam); t != "" {
		urlC, err := parseURLToken(t)
		if err != nil {
			http.Error(w, "this link is invalid or expired", http.StatusUnauthorized)
			return
		}
		sid := uuid.NewString()
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO sessions(id, event_id, presenter_id, ua, ip_hash, started_at)
			 VALUES ($1,$2,$3,$4,$5,now())`,
			sid, urlC.EventID, urlC.PresenterID, truncate(r.UserAgent(), 256), clientIPHash(r)); err != nil {
			log.Printf("session insert: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		exp := urlC.ExpiresAt.Time
		tok, err := mintSessionToken(sid, urlC.EventID, urlC.PresenterID, exp)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: sessCookieName, Value: tok, Path: "/",
			Expires: exp, HttpOnly: true, Secure: cookieSecure, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	c, err := r.Cookie(sessCookieName)
	if err != nil {
		http.Error(w, "this assessment requires a valid link from the event QR code", http.StatusUnauthorized)
		return
	}
	sess, err := parseSessionToken(c.Value)
	if err != nil {
		http.Error(w, "your session has expired — re-scan the event QR code", http.StatusUnauthorized)
		return
	}
	// If this session already produced a submission, a fresh page load means a
	// new visitor — booth staff hit refresh instead of "Retake". Rotate to a new
	// session so their picks/scores can't blend into the previous person's lead.
	// Fail open: never block the booth if the check or rotation hiccups.
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var submitted bool
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM submissions WHERE session_id = $1)`,
		sess.SessionID).Scan(&submitted); err != nil {
		log.Printf("serve deck submission check: %v", err)
	} else if submitted {
		if err := rotateSession(ctx, w, r, sess); err != nil {
			log.Printf("serve deck rotate: %v", err)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "User-Agent, Sec-CH-UA-Mobile")
	_, _ = w.Write(pickDeck(r))
}

type eventPayload struct {
	Event      string          `json:"event"`
	Phase      string          `json:"phase,omitempty"`
	DwellMs    int             `json:"dwell_ms,omitempty"`
	Scenario   string          `json:"scenario,omitempty"`
	OutcomeIdx int             `json:"outcome_idx"`
	Score      int             `json:"score"`
	Color      string          `json:"color,omitempty"`
	Email      string          `json:"email,omitempty"`
	Name       string          `json:"name,omitempty"`
	Title      string          `json:"title,omitempty"`
	Concerns   string          `json:"concerns,omitempty"`
	Scores     json.RawMessage `json:"scores,omitempty"`
}

func recordEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie(sessCookieName)
	if err != nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	sess, err := parseSessionToken(c.Value)
	if err != nil {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}
	if !eventCounters.allow(sess.SessionID, maxEventsPerSession) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var p eventPayload
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if p.DwellMs < 0 || p.DwellMs > 86_400_000 {
		p.DwellMs = 0
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	switch p.Event {

	case "phase_enter":
		if !allowedPhases[p.Phase] {
			http.Error(w, "unknown phase", http.StatusBadRequest)
			return
		}
		if p.Scenario != "" && !allowedScenarios[p.Scenario] {
			p.Scenario = ""
		}
		_, err = db.ExecContext(ctx,
			`INSERT INTO phase_events(session_id, phase, scenario, entered_at, dwell_ms)
			 VALUES ($1,$2,NULLIF($3,''),now(),$4)`,
			sess.SessionID, p.Phase, p.Scenario, p.DwellMs)

	case "pick":
		if !allowedScenarios[p.Scenario] {
			http.Error(w, "unknown scenario", http.StatusBadRequest)
			return
		}
		if p.OutcomeIdx < 0 || p.OutcomeIdx > 2 || p.Score < 0 || p.Score > 2 || !allowedColors[p.Color] {
			http.Error(w, "invalid pick", http.StatusBadRequest)
			return
		}
		_, err = db.ExecContext(ctx,
			`INSERT INTO picks(session_id, scenario, outcome_idx, score, color)
			 VALUES ($1,$2,$3,$4,$5)`,
			sess.SessionID, p.Scenario, p.OutcomeIdx, p.Score, p.Color)

	case "submit":
		email := strings.TrimSpace(strings.ToLower(p.Email))
		if !emailRe.MatchString(email) {
			http.Error(w, "invalid email", http.StatusBadRequest)
			return
		}
		if len(p.Scores) == 0 || len(p.Scores) > 4096 || !json.Valid(p.Scores) {
			http.Error(w, "invalid scores", http.StatusBadRequest)
			return
		}
		// Optional self-description fields from the results screen. Truncate
		// over-long input rather than rejecting — they're nice-to-haves and we
		// don't want to lose a lead because someone pasted a wall of text.
		name := truncate(strings.TrimSpace(p.Name), 120)
		title := truncate(strings.TrimSpace(p.Title), 120)
		concerns := truncate(strings.TrimSpace(p.Concerns), 2000)
		_, err = db.ExecContext(ctx,
			`INSERT INTO submissions(session_id, email, name, title, concerns, scores)
			 VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),$6)`,
			sess.SessionID, email, name, title, concerns, []byte(p.Scores))

	case "session_end":
		_, err = db.ExecContext(ctx,
			`UPDATE sessions SET ended_at = now() WHERE id = $1 AND ended_at IS NULL`,
			sess.SessionID)

	default:
		http.Error(w, "unknown event", http.StatusBadRequest)
		return
	}

	if err != nil {
		// A foreign-key violation means the session row behind this cookie is
		// gone — e.g. a lead was removed in the admin console while the browser
		// held onto its wt_sess cookie. Tell the client to re-scan instead of
		// silently dropping the write behind a generic 500.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			http.Error(w, "your session has expired — re-scan the event QR code", http.StatusUnauthorized)
			return
		}
		log.Printf("event insert (%s): %v", p.Event, err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rotateSession mints a fresh session for the same event/presenter as sess,
// inserts it, and sets the wt_sess cookie on w. The new session inherits the
// original link's expiry (carried on the session token), so rotation can never
// extend access past the event window. Shared by the explicit /api/session/new
// endpoint and by serveDeck when a reload lands on an already-submitted session.
func rotateSession(ctx context.Context, w http.ResponseWriter, r *http.Request, sess *sessClaims) error {
	sid := uuid.NewString()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sessions(id, event_id, presenter_id, ua, ip_hash, started_at)
		 VALUES ($1,$2,$3,$4,$5,now())`,
		sid, sess.EventID, sess.PresenterID, truncate(r.UserAgent(), 256), clientIPHash(r)); err != nil {
		return err
	}
	exp := sess.ExpiresAt.Time
	tok, err := mintSessionToken(sid, sess.EventID, sess.PresenterID, exp)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessCookieName, Value: tok, Path: "/",
		Expires: exp, HttpOnly: true, Secure: cookieSecure, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// sessionNewHandler rotates the caller to a brand-new session for the same
// event/presenter as their current (valid) session. The deck calls it from the
// "Retake Assessment" path so each run — a new passer-by on a shared iPad, or
// the same person going again — gets its own picks and can't blend scores with
// the previous run.
func sessionNewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie(sessCookieName)
	if err != nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	sess, err := parseSessionToken(c.Value)
	if err != nil {
		http.Error(w, "your session has expired — re-scan the event QR code", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := rotateSession(ctx, w, r, sess); err != nil {
		log.Printf("session rotate: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func adminAuthed(r *http.Request) bool {
	c, err := r.Cookie(adminCookieName)
	if err != nil {
		return false
	}
	_, err = parseAdminSession(c.Value)
	return err == nil
}

func authorizeAdmin(r *http.Request) bool {
	if adminAuthed(r) {
		return true
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	want := os.Getenv("ADMIN_TOKEN")
	if want == "" {
		return false
	}
	got := strings.TrimPrefix(auth, "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func renderLogin(w http.ResponseWriter, status int, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = adminLoginTpl.Execute(w, map[string]string{"Err": errMsg})
}

func adminPortal(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	if !adminAuthed(r) {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = adminPortalTpl.Execute(w, nil)
}

func adminLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if adminAuthed(r) {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		renderLogin(w, http.StatusOK, "")
	case http.MethodPost:
		ip := clientIP(r)
		if !loginLimiter.allow(ip) {
			renderLogin(w, http.StatusTooManyRequests, "Too many attempts — try again in a minute.")
			return
		}
		if err := r.ParseForm(); err != nil {
			renderLogin(w, http.StatusBadRequest, "Bad request.")
			return
		}
		pw := r.FormValue("password")
		want := os.Getenv("ADMIN_PASSWORD")
		if want == "" || subtle.ConstantTimeCompare([]byte(pw), []byte(want)) != 1 {
			loginLimiter.fail(ip)
			log.Printf("admin login FAIL ip=%s", ip)
			renderLogin(w, http.StatusUnauthorized, "Invalid password.")
			return
		}
		exp := time.Now().Add(8 * time.Hour)
		tok, err := mintAdminSession(exp)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: adminCookieName, Value: tok, Path: "/admin",
			Expires: exp, HttpOnly: true, Secure: cookieSecure, SameSite: http.SameSiteStrictMode,
		})
		log.Printf("admin login OK ip=%s", ip)
		http.Redirect(w, r, "/admin", http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: adminCookieName, Value: "", Path: "/admin",
		MaxAge: -1, HttpOnly: true, Secure: cookieSecure, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

type mintRequest struct {
	EventID     string `json:"event_id"`
	EventName   string `json:"event_name"`
	PresenterID string `json:"presenter_id"`
	NotBefore   string `json:"nbf"`
	Expires     string `json:"exp"`
}

type mintResponse struct {
	Token string `json:"token"`
	URL   string `json:"url,omitempty"`
}

func adminMint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !authorizeAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req mintRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	req.EventID = strings.TrimSpace(req.EventID)
	if req.EventID == "" || len(req.EventID) > 128 {
		http.Error(w, "event_id required (1-128 chars)", http.StatusBadRequest)
		return
	}
	if len(req.EventName) > 256 || len(req.PresenterID) > 128 {
		http.Error(w, "field too long", http.StatusBadRequest)
		return
	}
	nbf := time.Now()
	exp := time.Now().Add(48 * time.Hour)
	if req.NotBefore != "" {
		t, err := time.Parse(time.RFC3339, req.NotBefore)
		if err != nil {
			http.Error(w, "bad nbf", http.StatusBadRequest)
			return
		}
		nbf = t
	}
	if req.Expires != "" {
		t, err := time.Parse(time.RFC3339, req.Expires)
		if err != nil {
			http.Error(w, "bad exp", http.StatusBadRequest)
			return
		}
		exp = t
	}
	if exp.Before(nbf) || exp.Sub(nbf) > 30*24*time.Hour {
		http.Error(w, "invalid time window (max 30 days)", http.StatusBadRequest)
		return
	}
	tokenID := uuid.NewString()
	tok, err := mintURLToken(tokenID, req.EventID, req.EventName, req.PresenterID, nbf, exp)
	if err != nil {
		http.Error(w, "mint failed", http.StatusInternalServerError)
		return
	}
	// Record the mint for the admin Tokens tab (best-effort; never fail the mint).
	mctx, mcancel := context.WithTimeout(r.Context(), 5*time.Second)
	_, derr := db.ExecContext(mctx, `
		INSERT INTO minted_tokens (id, event_id, event_name, presenter_id, not_before, expires_at)
		VALUES ($1, $2, NULLIF($3,''), NULLIF($4,''), $5, $6)`,
		tokenID, req.EventID, req.EventName, req.PresenterID, nbf, exp)
	mcancel()
	if derr != nil {
		log.Printf("mint log: %v", derr)
	}
	log.Printf("admin mint event=%q presenter=%q nbf=%s exp=%s ip=%s",
		req.EventID, req.PresenterID, nbf.Format(time.RFC3339), exp.Format(time.RFC3339), clientIP(r))
	resp := mintResponse{Token: tok}
	if base := envOr("PUBLIC_URL", ""); base != "" {
		resp.URL = strings.TrimRight(base, "/") + "/?t=" + tok
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ── lead dashboard ───────────────────────────────────────────────────
//
// Scoring mirrors the deck's showResults() in
// security-maturity-assessment-browser.html: four scenarios, each scored
// 0/1/2 (red/yellow/green), so the max is 8 and pct = round(total/8*100).
// Bands (in priority order):
//   pct>=80              -> "Strong Posture"
//   reds==0              -> "Getting There"
//   reds>=3              -> "Significant Gaps"  (high priority / lowest band)
//   otherwise            -> "Mixed Posture"
// Per-domain scores come from the picks table (the unambiguous source of
// truth), using the latest pick per scenario per session.

const assessmentMaxScore = 8 // 4 scenarios * max score 2

// leadStatuses is the set of valid lead_status.status values.
var leadStatuses = map[string]bool{
	"new": true, "contacted": true, "meeting_booked": true, "closed": true,
}

// leadFunnelOrder is the lead lifecycle order shown in the dashboard funnel.
var leadFunnelOrder = []string{"new", "contacted", "meeting_booked", "closed"}

// postureBand returns the band label the deck would show for a given total
// score and red count. pct is total/assessmentMaxScore as a percentage.
func postureBand(total, reds int) string {
	pct := total * 100 / assessmentMaxScore
	switch {
	case pct >= 80:
		return "Strong Posture"
	case reds == 0:
		return "Getting There"
	case reds >= 3:
		return "Significant Gaps"
	default:
		return "Mixed Posture"
	}
}

type domainPosture struct {
	Scenario string `json:"scenario"`
	Red      int    `json:"red"`
	Yellow   int    `json:"yellow"`
	Green    int    `json:"green"`
}

type funnelStage struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

type adminStats struct {
	TotalSubmissions int             `json:"totalSubmissions"`
	AvgPosturePct    int             `json:"avgPosturePct"`
	HighPriority     int             `json:"highPriority"`
	MeetingsBooked   int             `json:"meetingsBooked"`
	PostureByDomain  []domainPosture `json:"postureByDomain"`
	Funnel           []funnelStage   `json:"funnel"`
}

func adminStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !adminAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	event := strings.TrimSpace(r.URL.Query().Get("event"))
	presenter := strings.TrimSpace(r.URL.Query().Get("presenter"))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	stats := adminStats{PostureByDomain: []domainPosture{}}

	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM submissions
		JOIN sessions sess ON sess.id = submissions.session_id
		WHERE (sess.event_id = $1 OR $1 = '')
		  AND (COALESCE(sess.presenter_id,'') = $2 OR $2 = '')`,
		event, presenter).Scan(&stats.TotalSubmissions); err != nil {
		log.Printf("stats submissions: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM lead_status ls
		JOIN submissions s ON s.id = ls.submission_id
		JOIN sessions sess ON sess.id = s.session_id
		WHERE ls.status = 'meeting_booked'
		  AND (sess.event_id = $1 OR $1 = '')
		  AND (COALESCE(sess.presenter_id,'') = $2 OR $2 = '')`,
		event, presenter).Scan(&stats.MeetingsBooked); err != nil {
		log.Printf("stats meetings: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Lead funnel: submissions grouped by status, treating a missing lead_status
	// row as 'new'. Emitted in lifecycle order (leadFunnelOrder).
	frows, err := db.QueryContext(ctx, `
		SELECT COALESCE(ls.status, 'new') AS status, count(*)
		FROM submissions s
		JOIN sessions sess ON sess.id = s.session_id
		LEFT JOIN lead_status ls ON ls.submission_id = s.id
		WHERE (sess.event_id = $1 OR $1 = '')
		  AND (COALESCE(sess.presenter_id,'') = $2 OR $2 = '')
		GROUP BY COALESCE(ls.status, 'new')`, event, presenter)
	if err != nil {
		log.Printf("stats funnel: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer frows.Close()
	funnelCounts := map[string]int{}
	for frows.Next() {
		var st string
		var n int
		if err := frows.Scan(&st, &n); err != nil {
			log.Printf("stats funnel scan: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		funnelCounts[st] = n
	}
	if err := frows.Err(); err != nil {
		log.Printf("stats funnel rows: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	stats.Funnel = make([]funnelStage, 0, len(leadFunnelOrder))
	for _, st := range leadFunnelOrder {
		stats.Funnel = append(stats.Funnel, funnelStage{Status: st, Count: funnelCounts[st]})
	}

	// Per-domain red/yellow/green counts, using the latest pick per scenario
	// per session so a session can't double-count a domain. Joined to
	// submissions so only sessions that actually submitted count — otherwise
	// abandoned sessions (picks made, never submitted) skew the chart and it
	// shows values even when there are zero leads.
	rows, err := db.QueryContext(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (p.session_id, p.scenario)
				p.session_id, p.scenario, p.color
			FROM picks p
			JOIN submissions s ON s.session_id = p.session_id
			JOIN sessions sess ON sess.id = p.session_id
			WHERE (sess.event_id = $1 OR $1 = '')
			  AND (COALESCE(sess.presenter_id,'') = $2 OR $2 = '')
			ORDER BY p.session_id, p.scenario, p.picked_at DESC
		)
		SELECT scenario,
			count(*) FILTER (WHERE color = 'red')    AS red,
			count(*) FILTER (WHERE color = 'yellow') AS yellow,
			count(*) FILTER (WHERE color = 'green')  AS green
		FROM latest
		GROUP BY scenario`, event, presenter)
	if err != nil {
		log.Printf("stats posture: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	byScenario := map[string]domainPosture{}
	for rows.Next() {
		var d domainPosture
		if err := rows.Scan(&d.Scenario, &d.Red, &d.Yellow, &d.Green); err != nil {
			log.Printf("stats posture scan: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		byScenario[d.Scenario] = d
	}
	if err := rows.Err(); err != nil {
		log.Printf("stats posture rows: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	// Emit in deck order, including any scenario with no picks yet.
	for _, id := range scenarioOrder {
		d, ok := byScenario[id]
		if !ok {
			d = domainPosture{Scenario: id}
		}
		stats.PostureByDomain = append(stats.PostureByDomain, d)
	}

	// Per-session total score + red count, joined to submissions so we only
	// count sessions that actually submitted. Used for avg posture and the
	// high-priority (lowest band) count.
	srows, err := db.QueryContext(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (p.session_id, p.scenario)
				p.session_id, p.scenario, p.score, p.color
			FROM picks p
			JOIN submissions s ON s.session_id = p.session_id
			JOIN sessions sess ON sess.id = p.session_id
			WHERE (sess.event_id = $1 OR $1 = '')
			  AND (COALESCE(sess.presenter_id,'') = $2 OR $2 = '')
			ORDER BY p.session_id, p.scenario, p.picked_at DESC
		)
		SELECT session_id,
			sum(score)::int                            AS total,
			count(*) FILTER (WHERE color = 'red')::int AS reds
		FROM latest
		GROUP BY session_id`, event, presenter)
	if err != nil {
		log.Printf("stats sessions: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer srows.Close()
	var pctSum, pctCount, highPriority int
	for srows.Next() {
		var sid string
		var total, reds int
		if err := srows.Scan(&sid, &total, &reds); err != nil {
			log.Printf("stats sessions scan: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		pct := total * 100 / assessmentMaxScore
		pctSum += pct
		pctCount++
		if postureBand(total, reds) == "Significant Gaps" {
			highPriority++
		}
	}
	if err := srows.Err(); err != nil {
		log.Printf("stats sessions rows: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if pctCount > 0 {
		stats.AvgPosturePct = pctSum / pctCount
	}
	stats.HighPriority = highPriority

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(stats)
}

// adminEvent is one event with the presenters seen for it in the session data.
type adminEvent struct {
	Event      string   `json:"event"`
	Presenters []string `json:"presenters"`
}

// adminEventsHandler returns events + presenters present in the data, for the
// dashboard's cascading Event -> Presenter filter dropdowns.
func adminEventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !adminAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT event_id, COALESCE(presenter_id, '') AS presenter, count(*)
		FROM sessions
		WHERE EXISTS (SELECT 1 FROM submissions sub WHERE sub.session_id = sessions.id)
		GROUP BY event_id, presenter_id
		ORDER BY event_id, presenter`)
	if err != nil {
		log.Printf("events query: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	events := []adminEvent{}
	idxByEvent := map[string]int{}
	for rows.Next() {
		var eventID, presenter string
		var n int
		if err := rows.Scan(&eventID, &presenter, &n); err != nil {
			log.Printf("events scan: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		i, ok := idxByEvent[eventID]
		if !ok {
			i = len(events)
			idxByEvent[eventID] = i
			events = append(events, adminEvent{Event: eventID, Presenters: []string{}})
		}
		if presenter != "" {
			events[i].Presenters = append(events[i].Presenters, presenter)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("events rows: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(events)
}

type leadDomain struct {
	Score int    `json:"score"` // 0/1/2, -1 if not answered
	Color string `json:"color"` // red|yellow|green|"" if not answered
}

type leadRow struct {
	SubmissionID int64                 `json:"submissionId"`
	Email        string                `json:"email"`
	Name         string                `json:"name,omitempty"`
	Title        string                `json:"title,omitempty"`
	Concerns     string                `json:"concerns,omitempty"`
	SubmittedAt  time.Time             `json:"submittedAt"`
	Domains      map[string]leadDomain `json:"domains"` // keyed by scenario id
	TotalScore   int                   `json:"totalScore"`
	Band         string                `json:"band"`
	Status       string                `json:"status"`
}

func adminLeadsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !adminAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 256 {
		q = q[:256]
	}
	event := strings.TrimSpace(r.URL.Query().Get("event"))
	presenter := strings.TrimSpace(r.URL.Query().Get("presenter"))

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// One row per submission, with the lead status (default 'new') and the
	// session so we can attach per-domain picks. $1 is the email filter:
	// empty string matches everything ('%%').
	rows, err := db.QueryContext(ctx, `
		SELECT s.id, s.email, COALESCE(s.name, ''), COALESCE(s.title, ''),
			COALESCE(s.concerns, ''),
			s.submitted_at, s.session_id,
			COALESCE(ls.status, 'new') AS status
		FROM submissions s
		JOIN sessions sess ON sess.id = s.session_id
		LEFT JOIN lead_status ls ON ls.submission_id = s.id
		WHERE s.email ILIKE '%' || $1 || '%'
		  AND (sess.event_id = $2 OR $2 = '')
		  AND (COALESCE(sess.presenter_id,'') = $3 OR $3 = '')
		ORDER BY s.submitted_at DESC
		LIMIT 500`, q, event, presenter)
	if err != nil {
		log.Printf("leads query: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	leads := []leadRow{}
	sessionIDs := []string{}
	// A session can carry more than one submission (someone who re-submitted),
	// so map each session to *every* lead row built from it. With a plain
	// map[string]int the later row clobbered the earlier one and only one of the
	// submissions got its picks attached — the rest rendered with blank scores.
	idxBySession := map[string][]int{}
	for rows.Next() {
		var l leadRow
		var sessionID string
		if err := rows.Scan(&l.SubmissionID, &l.Email, &l.Name, &l.Title, &l.Concerns, &l.SubmittedAt, &sessionID, &l.Status); err != nil {
			log.Printf("leads scan: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		l.Domains = map[string]leadDomain{}
		for _, id := range scenarioOrder {
			l.Domains[id] = leadDomain{Score: -1}
		}
		idxBySession[sessionID] = append(idxBySession[sessionID], len(leads))
		sessionIDs = append(sessionIDs, sessionID)
		leads = append(leads, l)
	}
	if err := rows.Err(); err != nil {
		log.Printf("leads rows: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Attach per-domain picks for just the sessions we loaded. We re-apply the
	// same email filter in a subquery (rather than binding a Go slice as a SQL
	// array) so this stays a plain parameterised query; rows for sessions we
	// didn't load are ignored via idxBySession below.
	if len(sessionIDs) > 0 {
		prows, err := db.QueryContext(ctx, `
			SELECT DISTINCT ON (p.session_id, p.scenario)
				p.session_id, p.scenario, p.score, p.color
			FROM picks p
			WHERE p.session_id IN (
				SELECT s.session_id FROM submissions s
				JOIN sessions sess ON sess.id = s.session_id
				WHERE s.email ILIKE '%' || $1 || '%'
				  AND (sess.event_id = $2 OR $2 = '')
				  AND (COALESCE(sess.presenter_id,'') = $3 OR $3 = '')
			)
			ORDER BY p.session_id, p.scenario, p.picked_at DESC`, q, event, presenter)
		if err != nil {
			log.Printf("leads picks: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer prows.Close()
		for prows.Next() {
			var sessionID, scenario, color string
			var score int
			if err := prows.Scan(&sessionID, &scenario, &score, &color); err != nil {
				log.Printf("leads picks scan: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			for _, i := range idxBySession[sessionID] {
				if _, known := leads[i].Domains[scenario]; !known {
					continue
				}
				leads[i].Domains[scenario] = leadDomain{Score: score, Color: color}
			}
		}
		if err := prows.Err(); err != nil {
			log.Printf("leads picks rows: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}

	// Derive total score and band per lead from the attached domains.
	for i := range leads {
		total, reds, answered := 0, 0, 0
		for _, id := range scenarioOrder {
			d := leads[i].Domains[id]
			if d.Score < 0 {
				continue
			}
			answered++
			total += d.Score
			if d.Color == "red" {
				reds++
			}
		}
		leads[i].TotalScore = total
		if answered > 0 {
			leads[i].Band = postureBand(total, reds)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(leads)
}

type leadStatusRequest struct {
	SubmissionID int64  `json:"submission_id"`
	Status       string `json:"status"`
	Note         string `json:"note"`
}

func adminLeadStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !adminAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req leadStatusRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.SubmissionID <= 0 {
		http.Error(w, "submission_id required", http.StatusBadRequest)
		return
	}
	if !leadStatuses[req.Status] {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}
	if len(req.Note) > 2000 {
		http.Error(w, "note too long", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// NULLIF keeps an empty note as SQL NULL rather than ''.
	res, err := db.ExecContext(ctx, `
		INSERT INTO lead_status (submission_id, status, note, updated_at)
		VALUES ($1, $2, NULLIF($3, ''), now())
		ON CONFLICT (submission_id) DO UPDATE
		SET status = EXCLUDED.status,
			note = EXCLUDED.note,
			updated_at = now()`,
		req.SubmissionID, req.Status, req.Note)
	if err != nil {
		log.Printf("lead status upsert: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Foreign key satisfied but no row touched should not happen; treat as
		// a bad submission id.
		http.Error(w, "unknown submission", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type leadDeleteRequest struct {
	SubmissionID int64 `json:"submission_id"`
}

// adminLeadDeleteHandler removes a lead by deleting its whole session; ON DELETE
// CASCADE clears the session's picks, submission, and lead_status. Used to drop
// double-scan duplicates.
func adminLeadDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !adminAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req leadDeleteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.SubmissionID <= 0 {
		http.Error(w, "submission_id required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("lead delete begin: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Remove only this lead's submission (its lead_status cascades), and capture
	// the session so we can clean it up too. Deleting the session directly would
	// take any sibling submissions on a shared session down with it — the
	// collateral we're avoiding here.
	var sessionID string
	err = tx.QueryRowContext(ctx,
		`DELETE FROM submissions WHERE id = $1 RETURNING session_id`, req.SubmissionID).Scan(&sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "unknown submission", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("lead delete: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Drop the session (and its picks/phase_events) only once no submission still
	// references it. Normal one-lead-per-session data gets a full clean purge;
	// a legacy shared session keeps its other leads intact.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE id = $1
		   AND NOT EXISTS (SELECT 1 FROM submissions WHERE session_id = $1)`, sessionID); err != nil {
		log.Printf("lead delete session cleanup: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("lead delete commit: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type mintedToken struct {
	ID          string     `json:"id"`
	EventID     string     `json:"eventId"`
	EventName   string     `json:"eventName"`
	PresenterID string     `json:"presenterId"`
	NotBefore   *time.Time `json:"notBefore"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	MintedAt    time.Time  `json:"mintedAt"`
}

// adminTokensHandler lists minted tokens for the admin Tokens tab (view/log only).
func adminTokensHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !adminAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT id, event_id, COALESCE(event_name,''), COALESCE(presenter_id,''),
			not_before, expires_at, minted_at
		FROM minted_tokens
		ORDER BY minted_at DESC
		LIMIT 500`)
	if err != nil {
		log.Printf("tokens query: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	tokens := []mintedToken{}
	for rows.Next() {
		var t mintedToken
		if err := rows.Scan(&t.ID, &t.EventID, &t.EventName, &t.PresenterID,
			&t.NotBefore, &t.ExpiresAt, &t.MintedAt); err != nil {
			log.Printf("tokens scan: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		log.Printf("tokens rows: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(tokens)
}

func adminQR(w http.ResponseWriter, r *http.Request) {
	if !adminAuthed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data := r.URL.Query().Get("data")
	if data == "" || len(data) > 2048 {
		http.Error(w, "bad data", http.StatusBadRequest)
		return
	}
	code, err := qr.Encode(data, qr.M)
	if err != nil {
		http.Error(w, "qr encode failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(code.PNG())
}

// ── rate limiting & misc ─────────────────────────────────────────────

type limiter struct {
	mu    sync.Mutex
	max   int
	win   time.Duration
	fails map[string][]time.Time
}

func newLimiter(max int, win time.Duration) *limiter {
	return &limiter{max: max, win: win, fails: map[string][]time.Time{}}
}

func (l *limiter) prune(key string) []time.Time {
	now := time.Now()
	cutoff := now.Add(-l.win)
	out := l.fails[key][:0]
	for _, t := range l.fails[key] {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	l.fails[key] = out
	return out
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key)) < l.max
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[key] = append(l.fails[key], time.Now())
}

type sessionCounter struct {
	mu sync.Mutex
	m  map[string]int
}

func (s *sessionCounter) allow(id string, max int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[id] >= max {
		return false
	}
	s.m[id]++
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

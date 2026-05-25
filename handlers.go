package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
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
	"rsc.io/qr"
)

const (
	sessCookieName      = "wt_sess"
	adminCookieName     = "wt_admin"
	tokenParam          = "t"
	maxEventsPerSession = 400
)

var (
	loginLimiter  = newLimiter(5, time.Minute)
	eventCounters = &sessionCounter{m: map[string]int{}}

	allowedPhases = map[string]bool{
		"sceneIntro": true, "sceneScenario": true, "sceneResults": true,
	}
	allowedScenarios = map[string]bool{
		"network": true, "app": true, "cnapp": true, "sspm": true,
	}
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
			Expires: exp, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	c, err := r.Cookie(sessCookieName)
	if err != nil {
		http.Error(w, "this assessment requires a valid link from the event QR code", http.StatusUnauthorized)
		return
	}
	if _, err := parseSessionToken(c.Value); err != nil {
		http.Error(w, "your session has expired — re-scan the event QR code", http.StatusUnauthorized)
		return
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
		_, err = db.ExecContext(ctx,
			`INSERT INTO submissions(session_id, email, scores)
			 VALUES ($1,$2,$3)`,
			sess.SessionID, email, []byte(p.Scores))

	case "session_end":
		_, err = db.ExecContext(ctx,
			`UPDATE sessions SET ended_at = now() WHERE id = $1 AND ended_at IS NULL`,
			sess.SessionID)

	default:
		http.Error(w, "unknown event", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("event insert (%s): %v", p.Event, err)
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
			Expires: exp, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
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
		MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

type mintRequest struct {
	EventID     string `json:"event_id"`
	EventName   string `json:"event_name"`
	PresenterID string `json:"presenter_id"`
	NotBefore   string `json:"nbf"`
	Expires     string `json:"exp"`
	MaxUses     int    `json:"max_uses"`
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
	tok, err := mintURLToken(req.EventID, req.EventName, req.PresenterID, nbf, exp, req.MaxUses)
	if err != nil {
		http.Error(w, "mint failed", http.StatusInternalServerError)
		return
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

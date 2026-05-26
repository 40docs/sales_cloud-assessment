# Sales Cloud Assessment

Interactive 4-scenario security maturity assessment for the AWS Summit booth.
Two deploy targets share one source — the canonical browser/mobile HTML
files at the repo root.

| Target               | Workflow            | Auth                  | Telemetry |
| -------------------- | ------------------- | --------------------- | --------- |
| GitHub Pages         | `.github/pages.yml` | none                  | no-op     |
| Container (k8s)      | `.github/build.yml` | per-link signed token | yes       |

The static Pages site stays as the unauthenticated preview. The container
adds auth, telemetry, and an admin portal for minting per-event QR tokens.

## Container shape

```
                ┌──────────────────────────────────────────────────────┐
  QR scan ────► │  GET  /             Verifies ?t=, sets wt_sess,      │
                │                     picks browser/mobile variant     │
                │  POST /api/event    phase_enter / pick / submit /    │
                │                     session_end (write-only)         │
                │                                                      │
  Admin in   ─► │  GET  /admin        Mint UI                          │
  browser       │  GET  /admin/login                                   │
                │  POST /admin/login  Password-gated, rate-limited     │
                │  POST /admin/mint   Issues per-event URL tokens      │
                │  GET  /admin/qr     Renders QR PNG                   │
                │  POST /admin/logout                                  │
                │                                                      │
  CLI / CI   ─► │  POST /admin/mint   Bearer ADMIN_TOKEN               │
                └──────────────────────────────────────────────────────┘
```

The container is a single Go binary that **embeds** both HTML variants
plus the admin-portal templates (under `portal/`, separate from the
existing Pages-served `admin/` dashboard mockup).

## Device variant selection (server-side)

1. `Sec-CH-UA-Mobile: ?1` client hint → mobile
2. UA contains `Mobile|Android|iPhone|iPad|iPod|Mobi|Opera Mini|IEMobile` → mobile
3. otherwise → desktop

Response sets `Vary: User-Agent, Sec-CH-UA-Mobile` so caches store both correctly.

## Telemetry captured

| Event          | Trigger                                          | Stored in     |
| -------------- | ------------------------------------------------ | ------------- |
| `phase_enter`  | Scene transition (sceneIntro / sceneScenario / sceneResults, with scenario id when applicable) | `phase_events` |
| `pick`         | Each scenario outcome selected                   | `picks`        |
| `submit`       | Email submission on results screen               | `submissions`  |
| `session_end`  | Tab/window close                                 | updates `sessions.ended_at` |

A small `<script>` block at the bottom of each variant wraps `goTo()`,
`pick()`, and `sendReport()` and emits these via `navigator.sendBeacon`.
On the Pages preview (no `/api/event` endpoint) the beacons silently no-op.

## Security model

| Surface         | Cookie         | Path scope | Token `typ` / `aud`              |
| --------------- | -------------- | ---------- | -------------------------------- |
| Attendee deck   | `wt_sess`      | `/`        | `sess` / `assessment-session`    |
| Admin portal    | `wt_admin`     | `/admin`   | `admin` / `assessment-admin`     |
| CLI mint        | _none_         | _none_     | bearer `ADMIN_TOKEN`             |

Attendee cookies cannot satisfy admin auth (parser verifies `aud` + `typ`).
Admin cookie is path-scoped to `/admin` and `SameSite=Strict`. CLI bearer
is verified with `crypto/subtle.ConstantTimeCompare`.

### Other defenses

- Strict CSP + HSTS + `X-Frame-Options: DENY` + `nosniff` + Referrer-Policy + Permissions-Policy on every response.
- `/api/event` input validation: phase allowlist, scenario allowlist (`network/app/cnapp/sspm`), `outcome_idx 0..2`, `score 0..2`, color in `{red,yellow,green}`, email regex, scores jsonb ≤ 4 KB.
- Rate limits: per-IP login (5/min), per-session event cap (400 events).
- Pod hardening: distroless static, non-root UID 65532, read-only rootfs, all caps dropped, `seccompProfile: RuntimeDefault`, no service-account token mounted.
- NetworkPolicy: ingress from `ingress-nginx` ns only; egress to CNPG Postgres, DNS, and 443 only.
- Optional admin IP allowlist via a separate Ingress with `whitelist-source-range`.
- PodDisruptionBudget minAvailable=1.
- Audit log for admin login (success + fail with IP) and every mint.

## Deploy

See [`chart/README.md`](chart/README.md).

## Local dev

```bash
export DATABASE_URL='postgres://assessment@localhost:5432/assessment?sslmode=disable'
export JWT_PRIVATE_KEY=$(openssl rand -base64 32)
export ADMIN_PASSWORD='choose-a-password'
export ADMIN_TOKEN=$(openssl rand -hex 32)
go run .
```

## Source of truth

The HTML files at the repo root are the source for **both** the Pages preview
and the container. Editing them updates both deploys. The container also
needs the telemetry `<script>` block at the bottom — if you regenerate the
HTML from scratch, re-add that block (see git history for the snippet).

CLAUDE.md has the editorial conventions for the assessment content.

## Local dev with Docker

End-to-end test of the container (server + Postgres + telemetry + admin
portal) from one machine. No k8s, no TLS, no real DNS.

```bash
git checkout containerize
echo "JWT_PRIVATE_KEY=$(openssl rand -base64 32)" > .env
docker compose up --build
```

In another terminal:

```bash
# Mint a token via the CLI bearer path
curl -s -X POST http://localhost:8080/admin/mint \
  -H "Authorization: Bearer localdev-cli-token" \
  -H "Content-Type: application/json" \
  -d '{"event_id":"local-test","exp":"2026-12-31T00:00:00Z"}'
# → {"token":"...","url":"http://localhost:8080/?t=..."}

# Open the returned url in a browser. Walk the assessment. Submit your email.

# Confirm telemetry landed in Postgres
docker compose exec postgres psql -U assessment -d assessment -c \
  "SELECT phase, scenario, dwell_ms FROM phase_events ORDER BY entered_at DESC LIMIT 10;"

docker compose exec postgres psql -U assessment -d assessment -c \
  "SELECT scenario, outcome_idx, score, color FROM picks ORDER BY picked_at DESC LIMIT 10;"

docker compose exec postgres psql -U assessment -d assessment -c \
  "SELECT email, submitted_at FROM submissions ORDER BY submitted_at DESC LIMIT 10;"
```

Alternative: skip curl and use the browser portal at
`http://localhost:8080/admin` — password `localdev`.

### Tear down

```bash
docker compose down -v       # -v drops the Postgres volume
```

### Important

`COOKIE_SECURE=false` is set in `compose.yaml` so cookies travel over plain
http. **Never set this in production** — the Helm chart does not expose this
knob, so prod always issues `Secure` cookies.

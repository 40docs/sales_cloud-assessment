CREATE TABLE IF NOT EXISTS sessions (
  id            uuid PRIMARY KEY,
  event_id      text NOT NULL,
  presenter_id  text,
  ua            text,
  ip_hash       text,
  started_at    timestamptz NOT NULL DEFAULT now(),
  ended_at      timestamptz
);
CREATE INDEX IF NOT EXISTS sessions_event_idx ON sessions(event_id, started_at);

CREATE TABLE IF NOT EXISTS phase_events (
  id          bigserial PRIMARY KEY,
  session_id  uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  phase       text NOT NULL,
  entered_at  timestamptz NOT NULL DEFAULT now(),
  dwell_ms    integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS phase_events_session_idx ON phase_events(session_id, entered_at);

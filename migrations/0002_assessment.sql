CREATE TABLE IF NOT EXISTS picks (
  id           bigserial PRIMARY KEY,
  session_id   uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  scenario     text NOT NULL,
  outcome_idx  smallint NOT NULL,
  score        smallint NOT NULL,
  color        text NOT NULL,
  picked_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS picks_session_idx ON picks(session_id, picked_at);

CREATE TABLE IF NOT EXISTS submissions (
  id            bigserial PRIMARY KEY,
  session_id    uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  email         text NOT NULL,
  scores        jsonb NOT NULL,
  submitted_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS submissions_email_idx ON submissions(lower(email), submitted_at);

ALTER TABLE phase_events ADD COLUMN IF NOT EXISTS scenario text;

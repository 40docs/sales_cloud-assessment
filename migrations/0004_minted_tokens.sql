CREATE TABLE IF NOT EXISTS minted_tokens (
  id           text PRIMARY KEY,        -- JWT jti (urlClaims.ID)
  event_id     text NOT NULL,
  event_name   text,
  presenter_id text,
  not_before   timestamptz,
  expires_at   timestamptz,
  minted_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS minted_tokens_minted_idx ON minted_tokens(minted_at DESC);

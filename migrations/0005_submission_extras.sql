-- Optional self-description fields captured on the results screen alongside
-- the email: a name and a free-text "what cyber risks keep you up at night
-- that wasn't covered" prompt. Both are nullable — submitting without them
-- continues to work exactly as before.
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS name     text;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS concerns text;

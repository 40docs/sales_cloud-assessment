CREATE TABLE IF NOT EXISTS lead_status (
  submission_id bigint PRIMARY KEY REFERENCES submissions(id) ON DELETE CASCADE,
  status     text NOT NULL DEFAULT 'new',   -- new | contacted | meeting_booked | closed
  note       text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Optional job title captured alongside name on the results screen.
-- Nullable: leaving the field blank keeps existing behaviour.
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS title text;

BEGIN;

CREATE TABLE dead_letters (
  dead_letter_id text PRIMARY KEY CHECK (dead_letter_id ~ '^dead_[A-Za-z0-9_-]+$'),
  run_id text NOT NULL REFERENCES runs(run_id),
  step_id text NOT NULL REFERENCES workflow_steps(step_id),
  step_name text NOT NULL,
  input_ref text NOT NULL,
  input_hash text NOT NULL CHECK (input_hash ~ '^[a-f0-9]{64}$'),
  error_code text NOT NULL,
  error_detail_redacted text,
  status text NOT NULL DEFAULT 'pending' CHECK (
    status IN ('pending', 'claimed', 'replayed', 'discarded')
  ),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  claimed_by text,
  claimed_at timestamptz,
  replayed_step_id text REFERENCES workflow_steps(step_id),
  replayed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dead_letters_claim_idx
  ON dead_letters (status, created_at);

CREATE OR REPLACE FUNCTION claim_dead_letters(
  worker_id text,
  maximum_items integer DEFAULT 10
) RETURNS SETOF dead_letters
LANGUAGE sql
AS $$
  WITH candidates AS (
    SELECT dead_letter_id
    FROM dead_letters
    WHERE status = 'pending'
    ORDER BY created_at, dead_letter_id
    FOR UPDATE SKIP LOCKED
    LIMIT maximum_items
  )
  UPDATE dead_letters AS item
  SET status = 'claimed',
      claimed_by = worker_id,
      claimed_at = now(),
      attempt_count = attempt_count + 1
  FROM candidates
  WHERE item.dead_letter_id = candidates.dead_letter_id
  RETURNING item.*;
$$;

COMMIT;

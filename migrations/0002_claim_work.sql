BEGIN;

CREATE OR REPLACE FUNCTION claim_work(
  worker_id text,
  requested_step_name text,
  maximum_items integer DEFAULT 10
) RETURNS SETOF workflow_steps
LANGUAGE sql
AS $$
  WITH candidates AS (
    SELECT step_id
    FROM workflow_steps
    WHERE status IN ('pending', 'retryable')
      AND not_before <= now()
      AND step_name = requested_step_name
    ORDER BY created_at
    FOR UPDATE SKIP LOCKED
    LIMIT maximum_items
  )
  UPDATE workflow_steps AS work
  SET status = 'claimed',
      claimed_by = worker_id,
      claimed_at = now(),
      started_at = COALESCE(started_at, now()),
      attempt_count = attempt_count + 1
  FROM candidates
  WHERE work.step_id = candidates.step_id
  RETURNING work.*;
$$;

COMMIT;

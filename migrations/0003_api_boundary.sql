BEGIN;

CREATE TABLE api_idempotency (
  scope text NOT NULL CHECK (
    scope IN (
      'runs', 'artifacts', 'observations', 'assessments',
      'evidence', 'reports', 'deliveries'
    )
  ),
  idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9_-]{32,128}$'),
  request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, idempotency_key)
);

CREATE TABLE api_records (
  collection text NOT NULL CHECK (
    collection IN (
      'runs', 'artifacts', 'observations', 'assessments',
      'evidence', 'reports', 'deliveries'
    )
  ),
  record_key text NOT NULL,
  payload jsonb NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[a-f0-9]{64}$'),
  idempotency_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (collection, record_key),
  FOREIGN KEY (collection, idempotency_key)
    REFERENCES api_idempotency (scope, idempotency_key)
);

CREATE TRIGGER api_idempotency_append_only
  BEFORE UPDATE OR DELETE ON api_idempotency
  FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER api_records_append_only
  BEFORE UPDATE OR DELETE ON api_records
  FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

COMMIT;

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE run_status AS ENUM (
  'planned', 'collecting', 'quarantined', 'sanitized', 'extracted', 'correlated',
  'triaged', 'analyzing', 'challenged', 'verified', 'published', 'closed',
  'retryable', 'degraded', 'terminal'
);
CREATE TYPE work_status AS ENUM ('pending', 'claimed', 'completed', 'retryable', 'dead');
CREATE TYPE source_status AS ENUM ('healthy', 'degraded', 'failed', 'disabled');
CREATE TYPE verification_status AS ENUM ('pending', 'verified', 'rejected');

CREATE TABLE runs (
  run_id text PRIMARY KEY CHECK (run_id ~ '^run_[A-Za-z0-9_-]+$'),
  mode text NOT NULL,
  edition text NOT NULL,
  status run_status NOT NULL DEFAULT 'planned',
  scheduled_for timestamptz NOT NULL,
  started_at timestamptz,
  completed_at timestamptz,
  code_revision text NOT NULL,
  policy_revision text NOT NULL,
  schema_version text NOT NULL,
  input_manifest_hash text,
  degraded boolean NOT NULL DEFAULT false,
  failure_code text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workflow_steps (
  step_id text PRIMARY KEY CHECK (step_id ~ '^step_[A-Za-z0-9_-]+$'),
  run_id text NOT NULL REFERENCES runs(run_id),
  step_name text NOT NULL,
  status work_status NOT NULL DEFAULT 'pending',
  idempotency_key text NOT NULL UNIQUE,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  not_before timestamptz NOT NULL DEFAULT now(),
  deadline timestamptz,
  claimed_by text,
  claimed_at timestamptz,
  input_hash text,
  output_hash text,
  actor text,
  error_code text,
  error_detail_redacted text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX workflow_steps_claim_idx
  ON workflow_steps (status, not_before, step_name, created_at);

CREATE TABLE source_registry (
  source_id text PRIMARY KEY,
  display_name text NOT NULL,
  source_class text NOT NULL,
  trust_tier smallint NOT NULL CHECK (trust_tier BETWEEN 0 AND 3),
  adapter text NOT NULL,
  enabled boolean NOT NULL DEFAULT false,
  approval_id text,
  terms_status text NOT NULL DEFAULT 'pending',
  terms_url text,
  terms_reviewed_at timestamptz,
  terms_reviewer text,
  retention_days integer NOT NULL CHECK (retention_days > 0),
  allowed_hosts jsonb NOT NULL DEFAULT '[]'::jsonb,
  config_revision text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT enabled_source_requires_approval
    CHECK (NOT enabled OR (approval_id IS NOT NULL AND terms_status = 'approved'))
);

CREATE TABLE source_cursors (
  source_id text PRIMARY KEY REFERENCES source_registry(source_id),
  cursor jsonb NOT NULL,
  cursor_hash text NOT NULL,
  updated_by_run_id text NOT NULL REFERENCES runs(run_id),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE source_health (
  source_health_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  source_id text NOT NULL REFERENCES source_registry(source_id),
  run_id text REFERENCES runs(run_id),
  status source_status NOT NULL,
  checked_at timestamptz NOT NULL,
  last_success_at timestamptz,
  freshness_seconds integer CHECK (freshness_seconds >= 0),
  latency_ms integer CHECK (latency_ms >= 0),
  error_rate double precision CHECK (error_rate BETWEEN 0 AND 1),
  error_code text,
  UNIQUE (source_id, checked_at)
);

CREATE TABLE raw_artifacts (
  artifact_id text PRIMARY KEY CHECK (artifact_id ~ '^ra_[A-Za-z0-9_-]+$'),
  run_id text NOT NULL REFERENCES runs(run_id),
  source_id text NOT NULL REFERENCES source_registry(source_id),
  canonical_uri text NOT NULL,
  retrieved_at timestamptz NOT NULL,
  published_at timestamptz,
  http_status integer CHECK (http_status BETWEEN 100 AND 599),
  response_headers_redacted jsonb NOT NULL DEFAULT '{}'::jsonb,
  content_type text NOT NULL,
  compressed_size bigint NOT NULL CHECK (compressed_size >= 0),
  content_hash text NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
  object_key text NOT NULL,
  object_version text,
  retention_until timestamptz NOT NULL,
  legal_hold boolean NOT NULL DEFAULT false,
  idempotency_key text NOT NULL UNIQUE,
  fetch_policy_revision text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_id, canonical_uri, content_hash)
);

CREATE TABLE sanitized_artifacts (
  sanitized_artifact_id text PRIMARY KEY CHECK (
    sanitized_artifact_id ~ '^sa_[A-Za-z0-9_-]+$'
  ),
  artifact_id text NOT NULL REFERENCES raw_artifacts(artifact_id),
  run_id text NOT NULL REFERENCES runs(run_id),
  sanitizer_revision text NOT NULL,
  original_hash text NOT NULL CHECK (original_hash ~ '^[a-f0-9]{64}$'),
  sanitized_hash text NOT NULL CHECK (sanitized_hash ~ '^[a-f0-9]{64}$'),
  disposition text NOT NULL CHECK (
    disposition IN ('allow', 'restricted', 'deterministic_only', 'blocked')
  ),
  content_risk text NOT NULL CHECK (content_risk IN ('low', 'medium', 'high', 'critical')),
  detected_patterns jsonb NOT NULL DEFAULT '[]'::jsonb,
  decisions jsonb NOT NULL,
  bounded_excerpt text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (artifact_id, sanitizer_revision)
);

CREATE TABLE observations (
  observation_id text PRIMARY KEY CHECK (observation_id ~ '^ob_[A-Za-z0-9_-]+$'),
  run_id text NOT NULL REFERENCES runs(run_id),
  sanitized_artifact_id text NOT NULL REFERENCES sanitized_artifacts(sanitized_artifact_id),
  source_id text NOT NULL REFERENCES source_registry(source_id),
  schema_version text NOT NULL,
  extractor_revision text NOT NULL,
  observation_type text NOT NULL,
  observed_at timestamptz NOT NULL,
  published_at timestamptz,
  payload jsonb NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (sanitized_artifact_id, extractor_revision, payload_hash)
);

CREATE TABLE entities (
  entity_id text PRIMARY KEY CHECK (entity_id ~ '^en_[A-Za-z0-9_-]+$'),
  entity_type text NOT NULL,
  canonical_name text NOT NULL,
  canonical_key text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE entity_aliases (
  entity_id text NOT NULL REFERENCES entities(entity_id),
  alias text NOT NULL,
  alias_normalized text NOT NULL,
  source_observation_id text REFERENCES observations(observation_id),
  PRIMARY KEY (entity_id, alias_normalized)
);

CREATE TABLE relationships (
  relationship_id text PRIMARY KEY CHECK (relationship_id ~ '^rel_[A-Za-z0-9_-]+$'),
  source_entity_id text NOT NULL REFERENCES entities(entity_id),
  target_entity_id text NOT NULL REFERENCES entities(entity_id),
  relationship_type text NOT NULL,
  observation_id text REFERENCES observations(observation_id),
  confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_entity_id, target_entity_id, relationship_type, observation_id)
);

CREATE TABLE clusters (
  cluster_id text PRIMARY KEY CHECK (cluster_id ~ '^cl_[A-Za-z0-9_-]+$'),
  run_id text NOT NULL REFERENCES runs(run_id),
  cluster_key text NOT NULL,
  state text NOT NULL,
  first_observed_at timestamptz NOT NULL,
  last_updated_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, cluster_key)
);

CREATE TABLE cluster_members (
  cluster_id text NOT NULL REFERENCES clusters(cluster_id),
  observation_id text NOT NULL REFERENCES observations(observation_id),
  membership_reason text NOT NULL,
  PRIMARY KEY (cluster_id, observation_id)
);

CREATE TABLE evidence_items (
  evidence_id text PRIMARY KEY CHECK (evidence_id ~ '^ev_[A-Za-z0-9_-]+$'),
  cluster_id text NOT NULL REFERENCES clusters(cluster_id),
  observation_id text NOT NULL REFERENCES observations(observation_id),
  source_id text NOT NULL REFERENCES source_registry(source_id),
  source_role text NOT NULL,
  canonical_uri text NOT NULL,
  retrieved_at timestamptz NOT NULL,
  published_at timestamptz,
  content_hash text NOT NULL,
  sanitized_hash text NOT NULL,
  excerpt text NOT NULL,
  claims_supported jsonb NOT NULL,
  injection_risk text NOT NULL,
  independence_group text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE evidence_lineage (
  child_evidence_id text PRIMARY KEY REFERENCES evidence_items(evidence_id),
  parent_evidence_id text REFERENCES evidence_items(evidence_id),
  relationship text NOT NULL CHECK (
    relationship IN (
      'original', 'quotes', 'reposts', 'syndicates', 'links_to', 'derives_from', 'independent'
    )
  ),
  confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  CHECK (child_evidence_id <> parent_evidence_id)
);

CREATE TABLE features (
  feature_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cluster_id text NOT NULL REFERENCES clusters(cluster_id),
  run_id text NOT NULL REFERENCES runs(run_id),
  feature_name text NOT NULL,
  window_minutes integer,
  numeric_value double precision,
  text_value text,
  input_hash text NOT NULL,
  feature_revision text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cluster_id, run_id, feature_name, window_minutes, feature_revision)
);

CREATE TABLE assessments (
  assessment_id text PRIMARY KEY CHECK (assessment_id ~ '^as_[A-Za-z0-9_-]+$'),
  cluster_id text NOT NULL REFERENCES clusters(cluster_id),
  run_id text NOT NULL REFERENCES runs(run_id),
  agent_role text NOT NULL,
  model_provider text,
  model_id text,
  model_parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
  prompt_revision text,
  policy_revision text NOT NULL,
  input_hash text NOT NULL,
  output_hash text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE assessment_claims (
  claim_id text PRIMARY KEY CHECK (claim_id ~ '^claim_[A-Za-z0-9_-]+$'),
  assessment_id text NOT NULL REFERENCES assessments(assessment_id),
  claim_text text NOT NULL,
  certainty text NOT NULL,
  verification_status verification_status NOT NULL DEFAULT 'pending',
  verifier_revision text
);

CREATE TABLE claim_evidence (
  claim_id text NOT NULL REFERENCES assessment_claims(claim_id),
  evidence_id text NOT NULL REFERENCES evidence_items(evidence_id),
  entailment_status verification_status NOT NULL DEFAULT 'pending',
  PRIMARY KEY (claim_id, evidence_id)
);

CREATE TABLE reports (
  report_id text PRIMARY KEY CHECK (report_id ~ '^rp_[A-Za-z0-9_-]+$'),
  run_id text NOT NULL REFERENCES runs(run_id),
  edition text NOT NULL,
  schema_version text NOT NULL,
  template_revision text NOT NULL,
  report_json jsonb NOT NULL,
  report_json_hash text NOT NULL CHECK (report_json_hash ~ '^[a-f0-9]{64}$'),
  rendered_html_hash text CHECK (rendered_html_hash ~ '^[a-f0-9]{64}$'),
  supersedes_report_id text REFERENCES reports(report_id),
  created_at timestamptz NOT NULL,
  UNIQUE (run_id, edition, template_revision)
);

CREATE TABLE model_usage (
  usage_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id text NOT NULL REFERENCES runs(run_id),
  step_id text REFERENCES workflow_steps(step_id),
  source_id text REFERENCES source_registry(source_id),
  assessment_id text REFERENCES assessments(assessment_id),
  report_id text REFERENCES reports(report_id),
  agent_id text,
  provider text NOT NULL,
  model text NOT NULL,
  input_tokens integer NOT NULL CHECK (input_tokens >= 0),
  output_tokens integer NOT NULL CHECK (output_tokens >= 0),
  cached_tokens integer NOT NULL DEFAULT 0 CHECK (cached_tokens >= 0),
  tool_calls integer NOT NULL DEFAULT 0 CHECK (tool_calls >= 0),
  latency_ms integer NOT NULL CHECK (latency_ms >= 0),
  estimated_currency numeric(14, 6) NOT NULL CHECK (estimated_currency >= 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE deliveries (
  delivery_id text PRIMARY KEY CHECK (delivery_id ~ '^dl_[A-Za-z0-9_-]+$'),
  report_id text NOT NULL REFERENCES reports(report_id),
  destination_type text NOT NULL,
  destination_ref text NOT NULL,
  idempotency_key text NOT NULL UNIQUE,
  status work_status NOT NULL DEFAULT 'pending',
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  provider_receipt_redacted jsonb,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

CREATE TABLE analyst_feedback (
  feedback_id text PRIMARY KEY CHECK (feedback_id ~ '^fb_[A-Za-z0-9_-]+$'),
  report_id text NOT NULL REFERENCES reports(report_id),
  finding_id text NOT NULL,
  taxonomy text NOT NULL,
  notes text,
  submitted_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policy_decisions (
  policy_decision_id text PRIMARY KEY CHECK (
    policy_decision_id ~ '^pd_[A-Za-z0-9_-]+$'
  ),
  run_id text REFERENCES runs(run_id),
  step_id text REFERENCES workflow_steps(step_id),
  actor text NOT NULL,
  action text NOT NULL,
  resource_ref text,
  decision text NOT NULL CHECK (decision IN ('allow', 'deny', 'quarantine', 'require_approval')),
  reason_code text NOT NULL,
  policy_revision text NOT NULL,
  input_hash text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE security_events (
  security_event_id text PRIMARY KEY CHECK (
    security_event_id ~ '^se_[A-Za-z0-9_-]+$'
  ),
  run_id text REFERENCES runs(run_id),
  artifact_id text REFERENCES raw_artifacts(artifact_id),
  category text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  event_payload_redacted jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION reject_row_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'immutable audit row cannot be changed';
END;
$$;

CREATE TRIGGER raw_artifacts_immutable
  BEFORE UPDATE OR DELETE ON raw_artifacts
  FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER sanitized_artifacts_immutable
  BEFORE UPDATE OR DELETE ON sanitized_artifacts
  FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER evidence_items_immutable
  BEFORE UPDATE OR DELETE ON evidence_items
  FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER reports_immutable
  BEFORE UPDATE OR DELETE ON reports
  FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER policy_decisions_append_only
  BEFORE UPDATE OR DELETE ON policy_decisions
  FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER security_events_append_only
  BEFORE UPDATE OR DELETE ON security_events
  FOR EACH ROW EXECUTE FUNCTION reject_row_mutation();

COMMIT;

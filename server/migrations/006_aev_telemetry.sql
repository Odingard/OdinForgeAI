-- AEV Telemetry Tables (D3)
-- Captures structured telemetry for exploit agent runs and chain executions

CREATE TABLE IF NOT EXISTS aev_runs (
  id VARCHAR PRIMARY KEY,
  evaluation_id VARCHAR,
  organization_id VARCHAR NOT NULL DEFAULT 'default',
  run_type VARCHAR NOT NULL,
  playbook_id VARCHAR,
  challenge_id VARCHAR,
  execution_mode VARCHAR NOT NULL DEFAULT 'safe',
  started_at TIMESTAMP DEFAULT NOW(),
  completed_at TIMESTAMP,
  duration_ms INTEGER,
  stop_reason VARCHAR,
  failure_code VARCHAR DEFAULT 'none',
  error_message TEXT,
  exploitable BOOLEAN,
  overall_confidence INTEGER,
  finding_count INTEGER DEFAULT 0,
  total_turns INTEGER DEFAULT 0,
  total_tool_calls INTEGER DEFAULT 0,
  exploit_state JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aev_tool_calls (
  id VARCHAR PRIMARY KEY,
  run_id VARCHAR NOT NULL REFERENCES aev_runs(id),
  evaluation_id VARCHAR,
  turn INTEGER NOT NULL DEFAULT 0,
  tool_name VARCHAR NOT NULL,
  arguments JSONB,
  result_summary TEXT,
  vulnerable BOOLEAN DEFAULT FALSE,
  confidence INTEGER DEFAULT 0,
  execution_time_ms INTEGER DEFAULT 0,
  failure_code VARCHAR DEFAULT 'none',
  called_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aev_llm_turns (
  id VARCHAR PRIMARY KEY,
  run_id VARCHAR NOT NULL REFERENCES aev_runs(id),
  turn INTEGER NOT NULL DEFAULT 0,
  model VARCHAR NOT NULL,
  had_tool_calls BOOLEAN DEFAULT FALSE,
  tool_call_count INTEGER DEFAULT 0,
  duration_ms INTEGER DEFAULT 0,
  failure_code VARCHAR DEFAULT 'none',
  called_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aev_failures (
  id VARCHAR PRIMARY KEY,
  run_id VARCHAR NOT NULL REFERENCES aev_runs(id),
  evaluation_id VARCHAR,
  failure_code VARCHAR NOT NULL,
  context VARCHAR,
  message TEXT,
  occurred_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_aev_runs_evaluation ON aev_runs(evaluation_id);
CREATE INDEX IF NOT EXISTS idx_aev_runs_org ON aev_runs(organization_id);
CREATE INDEX IF NOT EXISTS idx_aev_tool_calls_run ON aev_tool_calls(run_id);
CREATE INDEX IF NOT EXISTS idx_aev_llm_turns_run ON aev_llm_turns(run_id);
CREATE INDEX IF NOT EXISTS idx_aev_failures_run ON aev_failures(run_id);

-- Evidence artifact columns for object storage (D6)
ALTER TABLE validation_evidence_artifacts ADD COLUMN IF NOT EXISTS storage_key VARCHAR;
ALTER TABLE validation_evidence_artifacts ADD COLUMN IF NOT EXISTS object_storage_url VARCHAR;

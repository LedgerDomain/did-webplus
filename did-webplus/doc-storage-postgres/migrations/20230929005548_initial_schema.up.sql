-- Add up migration script here
CREATE TABLE IF NOT EXISTS did_document_records (
  self_hash TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  version_id bigint NOT NULL,
  valid_from timestamptz NOT NULL,
  did_document JSONB NOT NULL,
  CONSTRAINT did_version_idx UNIQUE (did, version_id),
  CONSTRAINT did_valid_from_idx UNIQUE (did, valid_from)
);
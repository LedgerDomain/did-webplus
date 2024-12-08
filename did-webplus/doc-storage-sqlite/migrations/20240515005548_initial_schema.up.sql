-- Add up migration script here
CREATE TABLE IF NOT EXISTS did_document_records (
  self_hash TEXT NOT NULL PRIMARY KEY,
  did TEXT NOT NULL,
  version_id bigint NOT NULL,
  valid_from datetime NOT NULL,
  did_document TEXT NOT NULL,
  CONSTRAINT did_version_idx UNIQUE (did, version_id),
  CONSTRAINT did_valid_from_idx UNIQUE (did, valid_from)
);
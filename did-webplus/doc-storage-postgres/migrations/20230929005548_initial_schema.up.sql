-- It's crucial that the JCS of the DID document is stored exactly, and therefore JSONB is the wrong
-- data type.  Indexing on the JSON in the DID document is also not going to be done via Postgres
-- JSON functionality, and would be done via explicit indexes on the relevant tables.

CREATE TABLE did_document_records (
    self_hash TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    version_id BIGINT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    -- This is the size (in bytes) of the did-documents.jsonl file that ends with this DID document, including
    -- the trailing newline.  This must be equal to the did_documents_jsonl_octet_length field of the previous DID document
    -- row + OCTET_LENGTH(did_document_jcs) + 1.
    did_documents_jsonl_octet_length BIGINT NOT NULL,
    -- This must be exactly the JCS of the DID document, not including the trailing newline.  JSONB is
    -- inappropriate (see Postgres docs on JSONB).
    did_document_jcs TEXT NOT NULL,

    CONSTRAINT did_version_idx UNIQUE (did, version_id),
    CONSTRAINT did_valid_from_idx UNIQUE (did, valid_from),
    CONSTRAINT did_did_documents_jsonl_octet_length_idx UNIQUE (did, did_documents_jsonl_octet_length)
);

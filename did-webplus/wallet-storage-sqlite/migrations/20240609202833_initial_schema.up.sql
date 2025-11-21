CREATE TABLE wallets (
    -- Primary key for efficient joins with other tables.
    rowid INTEGER PRIMARY KEY,
    -- Identifier for this wallet.
    wallet_uuid TEXT NOT NULL,
    -- Timestamp of wallet creation.
    created_at DATETIME NOT NULL,
    -- Timestamp of last update to this table.
    updated_at DATETIME NOT NULL,
    -- Timestamp of soft-deletion.  Null if not deleted.
    deleted_at_o DATETIME,
    -- User-specified name for this wallet.
    wallet_name_o TEXT
);

CREATE TABLE priv_keys (
    -- Primary key for efficient joins with other tables.
    rowid INTEGER PRIMARY KEY,
    -- The rowid in the wallets table of the wallet that owns this priv key.
    wallets_rowid INTEGER NOT NULL,
    -- Pub key corresponding to this priv key.
    pub_key TEXT NOT NULL,
    -- Hash of the pub key.  This is used in pre-rotation schemes, in particular in DID update rules.
    hashed_pub_key TEXT NOT NULL,
    -- Type of this key, e.g. "Ed25519", "Secp256k1", etc.
    key_type TEXT NOT NULL,
    -- If not null, specifies the DID that this key is restricted to, meaning that it can't be
    -- used (associated with) any other DID.  If null, then there is no restriction.
    did_restriction_o TEXT,
    -- If not null, specifies the key purposes this key can be used for, represented as bit flags.
    -- If null, then there is no restriction.
    key_purpose_restriction_o INTEGER,
    -- Timestamp of priv key creation.
    created_at DATETIME NOT NULL,
    -- Timestamp of last cryptographic operation.  Null if never used.
    last_used_at_o DATETIME,
    -- If not null, specifies the maximum number of times this key can be used in a cryptographic
    -- before it must be retired.  If null, then there is no restriction.
    max_usage_count_o INTEGER,
    -- Number of times this key has been used in a cryptographic operation.
    usage_count BIGINT NOT NULL,
    -- Timestamp of soft-deletion.  Null if not deleted.  If deleted, then priv_key_bytes_o must be set to null.
    deleted_at_o DATETIME,
    -- Format for the private key material.  E.g. "raw" for raw byte repr, or "jwk"  for JSON Web Key, etc.  If
    -- the key is deleted (i.e. if deleted_at_o is not null), then this must be null.
    priv_key_format_o TEXT,
    -- Private key material itself, in the format specified by priv_key_format.  If the key is deleted (i.e.
    -- if deleted_at_o is not null), then this must be null.
    priv_key_bytes_o BLOB,
    -- Optional comment field for this key.  Could be used to give a human-readable name, description, or
    -- intented usage for this key.
    comment_o TEXT,

    FOREIGN KEY(wallets_rowid) REFERENCES wallets(rowid) ON DELETE CASCADE,
    CONSTRAINT pub_key_idx UNIQUE (wallets_rowid, pub_key),
    CONSTRAINT hashed_pub_key_idx UNIQUE (wallets_rowid, hashed_pub_key)
);

-- This table mostly exists so that the DB is understandable by itself without the did:webplus codebase.
-- In particular, it represents the KeyPurpose <-> integer mapping.
CREATE TABLE key_purposes (
    rowid INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);

-- Populate key_purposes table.  This must match key_purposes.rs
INSERT INTO key_purposes(rowid, name) VALUES (0, 'authentication');
INSERT INTO key_purposes(rowid, name) VALUES (1, 'assertionMethod');
INSERT INTO key_purposes(rowid, name) VALUES (2, 'keyAgreement');
INSERT INTO key_purposes(rowid, name) VALUES (3, 'capabilityInvocation');
INSERT INTO key_purposes(rowid, name) VALUES (4, 'capabilityDelegation');
INSERT INTO key_purposes(rowid, name) VALUES (5, 'updateDIDDocument');

CREATE TABLE priv_key_usages (
    -- The rowid in the wallets table of the wallet that owns this priv key usage.
    wallets_rowid INTEGER NOT NULL,
    -- The rowid in the priv_keys table of the priv key that was used for this usage.
    priv_keys_rowid INTEGER NOT NULL,
    -- Timestamp for this particular usage
    used_at DATETIME NOT NULL,
    -- The kind of usage, e.g. "DIDCreate", "SignJWT", etc.
    usage_type TEXT NOT NULL,
    -- If not null, then is serialized data specifying some details for the usage.  This could be stripped of signatures
    -- made by any keys in this wallet, to avoid any risk of replay attacks.
    usage_spec_o BLOB,
    -- The verification method that was used, if there was one.  Otherwise null.
    verification_method_o TEXT,
    -- Specifies the KeyPurpose for the usage, if there was one, represented as an integer
    -- (see key_purposes table).  Otherwise null.
    key_purpose_o INTEGER,

    FOREIGN KEY(wallets_rowid) REFERENCES wallets(rowid) ON DELETE CASCADE,
    FOREIGN KEY(priv_keys_rowid) REFERENCES priv_keys(rowid) ON DELETE CASCADE
);

-- This is meant to hold DID docs only for controlled DIDs.
-- The contents of this table are shared by all wallet_uuid-s.
CREATE TABLE did_document_records (
    -- For efficient joins with verification_methods table.
    rowid INTEGER PRIMARY KEY,
    -- The selfHash field value for this DID document.
    self_hash TEXT NOT NULL,
    -- The DID that this DID document belongs to.
    did TEXT NOT NULL,
    -- The versionId field value for this DID document.
    version_id BIGINT NOT NULL,
    -- The timestamp at which this DID document becomes valid.
    valid_from DATETIME NOT NULL,
    -- This is the size (in bytes) of the did-documents.jsonl file that ends with this DID document, including
    -- the trailing newline.  This must be equal to the did_documents_jsonl_octet_length field of the previous DID document
    -- row + OCTET_LENGTH(did_document_jcs) + 1.
    did_documents_jsonl_octet_length BIGINT NOT NULL,
    -- This must be the JCS (JSON Canonicalization Scheme) representation of the DID document, not including
    -- the trailing newline.
    did_document_jcs TEXT NOT NULL,

    CONSTRAINT did_self_hash_idx UNIQUE (did, self_hash),
    CONSTRAINT did_version_id_idx UNIQUE (did, version_id),
    CONSTRAINT did_valid_from_idx UNIQUE (did, valid_from),
    CONSTRAINT did_did_documents_jsonl_octet_length_idx UNIQUE (did, did_documents_jsonl_octet_length)
);

-- This table is meant to hold the verification methods from ingested DID documents of controlled DIDs.
-- The contents of this table are shared by all wallet_uuid-s.  Note that there will be rows in this
-- table for verification methods not necessarily controlled by this wallet (e.g. where there is a
-- DID that is controlled by both this wallet and another).
CREATE TABLE verification_methods (
    rowid INTEGER PRIMARY KEY,
    -- The rowid in the did_document_records table that this verification method pertains to.
    did_document_records_rowid INTEGER NOT NULL,
    -- The key identifier fragment portion of the id field.  This identifies this verification within the DID document.
    key_id_fragment TEXT NOT NULL,
    -- The "controller" field for the verification method.  This must be a DID, but isn't necessarily the same as the
    -- DID in the id field.
    controller TEXT NOT NULL,
    -- The pub key for the verification method.
    pub_key TEXT NOT NULL,
    -- The purposes for this verification method, as the integer representation of KeyPurposeFlags
    -- not including that for UpdateDIDDocument. This is determined by this verification method's
    -- presence in the authentication, assertionMethod, keyAgreement, capabilityInvocation, and
    -- capabilityDelegation fields in the DID document.
    key_purpose_flags INTEGER NOT NULL,

    CONSTRAINT verification_method_id_idx UNIQUE (did_document_records_rowid, key_id_fragment),
    FOREIGN KEY(did_document_records_rowid) REFERENCES did_document_records(rowid) ON DELETE CASCADE
);

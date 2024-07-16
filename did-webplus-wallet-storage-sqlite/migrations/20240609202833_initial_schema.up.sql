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
    deleted_at_o DATETIME DEFAULT NULL,
    -- User-specified name for this wallet.
    wallet_name_o TEXT
);

CREATE TABLE priv_keys (
    -- The rowid in the wallets table of the wallet that owns this priv key.
    wallets_rowid INTEGER NOT NULL,
    -- Pub key corresponding to this priv key, in KERIVerifier format.
    pub_key TEXT NOT NULL,
    -- Type of this key, e.g. "Ed25519", "Secp256k1", etc.
    key_type TEXT NOT NULL,
    -- If not null, specifies the key purposes this key can be used for, represented as bit flags.
    -- If null, then there is no restriction.
    key_purpose_restriction_o INTEGER,
    -- Timestamp of priv key creation.
    created_at DATETIME NOT NULL,
    -- Timestamp of last cryptographic operation.  Null if never used.
    last_used_at_o DATETIME DEFAULT NULL,
    -- Number of times this key has been used in a cryptographic operation.
    usage_count BIGINT NOT NULL DEFAULT 0,
    -- Timestamp of soft-deletion.  Null if not deleted.  If deleted, then priv_key_bytes_o must be set to null.
    deleted_at_o DATETIME DEFAULT NULL,
    -- Format for the private key material.  E.g. "raw" for raw byte repr, or "jwk"  for JSON Web Key, etc.  If
    -- the key is deleted (i.e. if deleted_at_o is not null), then this must be null.
    priv_key_format_o TEXT,
    -- Private key material itself, in the format specified by priv_key_format.  If the key is deleted (i.e.
    -- if deleted_at_o is not null), then this must be null.
    priv_key_bytes_o BLOB,

    PRIMARY KEY(wallets_rowid, pub_key),
    FOREIGN KEY(wallets_rowid) REFERENCES wallets(rowid) ON DELETE CASCADE
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

CREATE TABLE priv_key_usages (
    -- The rowid in the wallets table of the wallet that owns this priv key usage.
    wallets_rowid INTEGER NOT NULL,
    -- Pub key identifying the priv key, in KERIVerifier format.
    pub_key TEXT NOT NULL,
    -- Timestamp for this particular usage
    used_at DATETIME NOT NULL,
    -- The kind of usage, e.g. "DIDCreate", "SignJWT", etc.
    usage_type TEXT NOT NULL,
    -- If not null, then is serialized data specifying some details for the usage.  Should be stripped of signatures
    -- made by any keys in this wallet.
    usage_spec_o BLOB,
    -- The fully-qualified DID resource (meaning a specific key ID in a specifically-versioned DID document)
    -- corresponding to this usage, if there was one.  Otherwise null.  "Fully qualified DID" is a DID having
    -- selfHash and versionId query params both set, and a DID resource is an identified key (or other resource) in
    -- a DID document.
    did_resource_fully_qualified_o TEXT,
    -- If there was a DID associated with this usage, then this specifies the KeyPurpose for the usage, represented
    -- as an integer (see key_purposes table).  Otherwise null.
    key_purpose_o INTEGER,

    FOREIGN KEY(wallets_rowid) REFERENCES wallets(rowid) ON DELETE CASCADE
);

-- This is meant to hold DID docs only for controlled DIDs.
-- The contents of this table are shared by all wallet_uuid-s.
CREATE TABLE did_documents (
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
    -- This must be the JCS (JSON Canonicalization Scheme) representation of the DID document.
    did_document_jcs TEXT NOT NULL,

    CONSTRAINT did_self_hash_idx UNIQUE (did, self_hash),
    CONSTRAINT did_version_id_idx UNIQUE (did, version_id),
    CONSTRAINT did_valid_from_idx UNIQUE (did, valid_from)
);

-- This table is meant to hold the verification methods from ingested DID documents of controlled DIDs.
-- The contents of this table are shared by all wallet_uuid-s.
CREATE TABLE verification_methods (
    -- For efficient joins with verification_method_purposes table.
    rowid INTEGER PRIMARY KEY,
    -- The rowid in the did_documents table that this verification method pertains to.
    did_documents_rowid INTEGER NOT NULL,
    -- The key identifier fragment portion of the id field.  This identifies this verification within the DID document.
    key_id_fragment TEXT NOT NULL,
    -- The "controller" field for the verification method.  This must be a DID, but isn't necessarily the same as the
    -- DID in the id field.
    controller TEXT NOT NULL,
    -- The pub key for the verification method.
    pub_key TEXT NOT NULL,
    -- The purposes for this verification method, as the integer representation of KeyPurposeFlags.
    -- This is determined by this verification method's presence in the authentication, assertionMethod,
    -- keyAgreement, capabilityInvocation, and capabilityDelegation fields in the DID document.
    key_purpose_flags INTEGER NOT NULL,

    CONSTRAINT verification_method_id_idx UNIQUE (did_documents_rowid, key_id_fragment),
    FOREIGN KEY(did_documents_rowid) REFERENCES did_documents(rowid) ON DELETE CASCADE
);

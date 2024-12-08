CREATE TABLE IF NOT EXISTS vjson_records (
    self_hash TEXT NOT NULL PRIMARY KEY,
    added_at DATETIME NOT NULL,
    vjson_jcs TEXT NOT NULL
);
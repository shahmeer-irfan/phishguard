-- PhishGuard local store.
-- Phase 0: ingest + parse + sync. Detector tables are created now but stay
-- empty until later phases so migrations don't churn.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ---------------------------------------------------------------- accounts

CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    provider      TEXT NOT NULL DEFAULT 'gmail',
    added_at      TEXT NOT NULL
);

-- Cursor for Gmail incremental sync. history_id is the watermark handed to
-- users.history.list; backfill_done gates whether incremental sync is safe.
CREATE TABLE IF NOT EXISTS sync_state (
    account_id        INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    history_id        TEXT,
    backfill_done     INTEGER NOT NULL DEFAULT 0,
    backfill_cursor   TEXT,              -- Gmail pageToken, survives interruption
    last_sync_at      TEXT,
    last_error        TEXT
);

-- ---------------------------------------------------------------- messages

CREATE TABLE IF NOT EXISTS messages (
    id                 INTEGER PRIMARY KEY,
    account_id         INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    gmail_id           TEXT NOT NULL,
    thread_id          TEXT,
    rfc822_message_id  TEXT,             -- the Message-ID: header, not Gmail's id
    history_id         TEXT,

    received_at        TEXT,             -- ISO8601 UTC, from Gmail internalDate
    date_header        TEXT,             -- raw Date: header, may be forged
    date_tz_offset     INTEGER,          -- minutes; a Layer-2 fingerprint feature

    from_addr          TEXT,             -- normalised lowercase addr-spec
    from_display       TEXT,             -- display name exactly as sent
    from_domain        TEXT,
    reply_to_addr      TEXT,
    return_path_addr   TEXT,
    to_addrs           TEXT,             -- JSON array
    cc_addrs           TEXT,             -- JSON array
    subject            TEXT,

    in_reply_to        TEXT,
    references_hdr     TEXT,             -- JSON array of Message-IDs

    -- Raw material for later layers, captured here because it is free at
    -- parse time and unrecoverable once the raw bytes are dropped.
    headers_json       TEXT NOT NULL,    -- ordered [[name, value], ...], case preserved
    header_order_hash  TEXT,             -- sha256 of lowercased header name sequence
    mime_signature     TEXT,             -- e.g. multipart/alternative(text/plain,text/html)
    x_mailer           TEXT,
    user_agent         TEXT,

    body_text          TEXT,
    body_html          TEXT,
    snippet            TEXT,

    labels_json        TEXT,             -- Gmail label ids, JSON array
    size_estimate      INTEGER,
    raw_gz             BLOB,             -- gzipped RFC822, for re-analysis
    parse_error        TEXT,

    ingested_at        TEXT NOT NULL,
    UNIQUE (account_id, gmail_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_from      ON messages(account_id, from_addr);
CREATE INDEX IF NOT EXISTS idx_messages_thread    ON messages(account_id, thread_id);
CREATE INDEX IF NOT EXISTS idx_messages_received  ON messages(account_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_rfc822id  ON messages(rfc822_message_id);

-- Received: chain, newest hop first (hop_index 0 = the hop closest to us).
CREATE TABLE IF NOT EXISTS received_hops (
    id          INTEGER PRIMARY KEY,
    message_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    hop_index   INTEGER NOT NULL,
    raw         TEXT NOT NULL,
    from_host   TEXT,
    from_ip     TEXT,
    by_host     TEXT,
    with_proto  TEXT,
    hop_time    TEXT
);
CREATE INDEX IF NOT EXISTS idx_hops_message ON received_hops(message_id);

-- Parsed Authentication-Results / ARC. Google evaluates these for us on
-- inbound mail, so on Gmail this is read, not recomputed.
CREATE TABLE IF NOT EXISTS auth_results (
    message_id     INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    authserv_id    TEXT,
    spf            TEXT,   -- pass/fail/softfail/neutral/none/temperror/permerror
    spf_domain     TEXT,
    dkim           TEXT,
    dkim_domain    TEXT,   -- the d= domain; alignment with From: matters
    dkim_selector  TEXT,
    dmarc          TEXT,
    dmarc_domain   TEXT,
    compauth       TEXT,
    arc_present    INTEGER NOT NULL DEFAULT 0,
    raw            TEXT
);

CREATE TABLE IF NOT EXISTS attachments (
    id            INTEGER PRIMARY KEY,
    message_id    INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    part_path     TEXT,          -- e.g. "1.2"
    filename      TEXT,
    content_type  TEXT,
    content_id    TEXT,
    is_inline     INTEGER NOT NULL DEFAULT 0,
    size_bytes    INTEGER,
    sha256        TEXT
);
CREATE INDEX IF NOT EXISTS idx_attach_message ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_attach_sha     ON attachments(sha256);

-- ---------------------------------------------------------------- contacts

CREATE TABLE IF NOT EXISTS contacts (
    id                INTEGER PRIMARY KEY,
    account_id        INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    canonical_email   TEXT NOT NULL,
    domain            TEXT,
    display_names_json TEXT NOT NULL DEFAULT '[]',
    first_seen        TEXT,
    last_seen         TEXT,
    inbound_count     INTEGER NOT NULL DEFAULT 0,
    outbound_count    INTEGER NOT NULL DEFAULT 0,  -- user wrote to them: strong trust signal
    is_trusted        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_id, canonical_email)
);
CREATE INDEX IF NOT EXISTS idx_contacts_domain ON contacts(account_id, domain);

-- Registration facts per organisational domain, filled by `analyze --online`
-- via RDAP. Cached hard: a domain's creation date never changes, and the only
-- reason to re-check is to pick up a domain we had not seen before.
CREATE TABLE IF NOT EXISTS domain_intel (
    domain      TEXT PRIMARY KEY,
    created_at  TEXT,
    expires_at  TEXT,
    registrar   TEXT,
    nameservers TEXT,
    source      TEXT,
    checked_at  TEXT NOT NULL,
    error       TEXT
);

-- Every link seen in every message. Populated during analysis, and kept for
-- its own sake: "this message links to a domain none of your mail has ever
-- linked to before" is a signal that only exists once there is a corpus.
CREATE TABLE IF NOT EXISTS message_links (
    id          INTEGER PRIMARY KEY,
    message_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    href        TEXT NOT NULL,
    host        TEXT,
    org         TEXT,
    anchor_text TEXT,
    source      TEXT
);
CREATE INDEX IF NOT EXISTS idx_links_message ON message_links(message_id);
CREATE INDEX IF NOT EXISTS idx_links_org     ON message_links(org);

-- Layer-2 fingerprints, one row per contact, stored as JSON.
-- A single versioned blob rather than typed columns: the feature set is still
-- moving, and `profile_version` lets a changed extractor invalidate every
-- profile at once instead of silently mixing old and new vectors.
CREATE TABLE IF NOT EXISTS contact_profiles (
    account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    canonical_email TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    technical_json  TEXT NOT NULL,
    style_json      TEXT NOT NULL,
    relationship_json TEXT NOT NULL,
    samples         INTEGER NOT NULL DEFAULT 0,
    built_at        TEXT NOT NULL,
    PRIMARY KEY (account_id, canonical_email)
);

-- Cached LLM intent verdicts (Layer 4), keyed by a hash of what was actually
-- sent. Re-analysis is then free, and the cache doubles as an audit trail of
-- every message that left the machine.
CREATE TABLE IF NOT EXISTS intent_cache (
    prompt_sha256 TEXT PRIMARY KEY,
    message_id    INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    model         TEXT,
    result_json   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    input_tokens  INTEGER,
    output_tokens INTEGER
);

-- ---------------------------------------------------------------- verdicts

CREATE TABLE IF NOT EXISTS verdicts (
    id             INTEGER PRIMARY KEY,
    message_id     INTEGER NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
    tier           TEXT NOT NULL,        -- safe | caution | danger
    score          REAL,
    model_version  TEXT,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    verdict_id  INTEGER NOT NULL REFERENCES verdicts(id) ON DELETE CASCADE,
    layer       INTEGER NOT NULL,
    code        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    weight      REAL,
    evidence_json TEXT,
    human_text  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict_id);
CREATE INDEX IF NOT EXISTS idx_findings_code    ON findings(code);
CREATE INDEX IF NOT EXISTS idx_verdicts_tier    ON verdicts(tier, score DESC);

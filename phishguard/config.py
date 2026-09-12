"""Paths and tunables. Everything lives under one app-support directory."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "PhishGuard"

# Read-only is deliberate for Phase 0 and the shipped product: we never mutate
# the user's mailbox. Widening this to gmail.modify would change the OAuth
# consent screen and the risk posture, so it is a product decision, not a
# convenience one.
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def app_support_dir() -> Path:
    override = os.environ.get("PHISHGUARD_HOME")
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME


@dataclass(frozen=True)
class Config:
    home: Path

    @property
    def db_path(self) -> Path:
        return self.home / "phishguard.db"

    @property
    def token_path(self) -> Path:
        """OAuth refresh token. Phase 0 writes this 0600 on disk; before ship it
        moves into the macOS Keychain (see README, Known gaps)."""
        return self.home / "credentials" / "token.json"

    @property
    def client_secret_path(self) -> Path:
        return self.home / "credentials" / "client_secret.json"

    def ensure(self) -> "Config":
        self.home.mkdir(parents=True, exist_ok=True)
        (self.home / "credentials").mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.home / "credentials", 0o700)
        return self


def load() -> Config:
    return Config(home=app_support_dir()).ensure()


# --- ingest tunables -------------------------------------------------------

# Gmail allows 250 quota units/user/sec; messages.get costs 5, so ~50/sec is
# the ceiling. We stay well under and let backoff handle the rest.
MAX_CONCURRENT_FETCHES = 8
BACKFILL_PAGE_SIZE = 500

# Keeping the raw bytes means detectors added in later phases can re-run over
# already-ingested mail without a second network round trip. Gzipped RFC822 is
# roughly 25-30% of the original; ~15k messages lands around 300-500 MB.
STORE_RAW = True
STORE_RAW_MAX_BYTES = 5 * 1024 * 1024

# Which Gmail labels to ingest. SPAM is included on purpose: it is the cheapest
# labelled negative set we will ever get for evaluation.
BACKFILL_LABELS = ["INBOX", "SPAM", "SENT"]

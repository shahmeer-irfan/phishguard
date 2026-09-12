"""Secret storage and database encryption.

Two gaps from Phase 0 close here. Both were listed as known and both matter
once the store holds a real mail archive rather than test fixtures: the
database becomes the single most sensitive file on the machine, and the OAuth
token is a standing read grant over the user's entire mailbox.

Neither mechanism is available everywhere, so both degrade explicitly. Silent
degradation would be the worst outcome - a user who believes their archive is
encrypted when it is not is worse off than one who knows it is not.
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("phishguard.security")

KEYCHAIN_SERVICE = "PhishGuard"
DB_KEY_ACCOUNT = "database-key"
TOKEN_ACCOUNT = "gmail-oauth-token"


# ----------------------------------------------------------- macOS Keychain

def keychain_available() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        subprocess.run(["security", "-h"], capture_output=True, timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def keychain_set(account: str, value: str) -> bool:
    """Store a secret. `-w` reads the value from argv, so it is visible in the
    process list for an instant; `security` offers no stdin form, and the
    alternative - leaving the secret in a world-readable file permanently - is
    worse. Hardened builds should use the Security framework via PyObjC."""
    if not keychain_available():
        return False
    try:
        subprocess.run(
            ["security", "add-generic-password", "-U",
             "-s", KEYCHAIN_SERVICE, "-a", account, "-w", value],
            capture_output=True, check=True, timeout=15,
        )
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("keychain write failed: %s", exc)
        return False


def keychain_get(account: str) -> str | None:
    if not keychain_available():
        return None
    try:
        result = subprocess.run(
            ["security", "find-generic-password",
             "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def keychain_delete(account: str) -> bool:
    if not keychain_available():
        return False
    try:
        result = subprocess.run(
            ["security", "delete-generic-password",
             "-s", KEYCHAIN_SERVICE, "-a", account],
            capture_output=True, timeout=15,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ------------------------------------------------------------- OAuth token

class TokenStore:
    """OAuth token, in the Keychain where possible and on disk otherwise.

    Reads prefer the Keychain but fall back to the file, so an existing Phase-0
    install keeps working; `migrate_to_keychain` moves it across once and
    removes the plaintext copy.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    @property
    def backend(self) -> str:
        if keychain_available():
            return "keychain"
        return "file"

    def read(self) -> str | None:
        value = keychain_get(TOKEN_ACCOUNT)
        if value:
            return value
        if self.path.exists():
            try:
                return self.path.read_text(encoding="utf-8")
            except OSError:
                return None
        return None

    def write(self, value: str) -> str:
        """Returns the backend actually used, so callers can tell the truth."""
        if keychain_set(TOKEN_ACCOUNT, value):
            # Remove the on-disk copy: leaving it behind means the weakest
            # storage still governs, and the Keychain buys nothing.
            if self.path.exists():
                try:
                    self.path.unlink()
                except OSError:
                    pass
            return "keychain"

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(value, encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.path, 0o600)
        return "file"

    def delete(self) -> None:
        keychain_delete(TOKEN_ACCOUNT)
        if self.path.exists():
            try:
                self.path.unlink()
            except OSError:
                pass

    def migrate_to_keychain(self) -> bool:
        if not self.path.exists() or not keychain_available():
            return False
        try:
            value = self.path.read_text(encoding="utf-8")
        except OSError:
            return False
        if not value.strip():
            return False
        if keychain_set(TOKEN_ACCOUNT, value):
            try:
                self.path.unlink()
            except OSError:
                pass
            return True
        return False


# ------------------------------------------------------ database encryption

def sqlcipher_module():
    """The SQLCipher driver, if one is installed.

    SQLCipher is a drop-in SQLite replacement that encrypts pages on disk. It
    is optional because it ships as a compiled extension, and requiring it
    would make Phases 0-5 uninstallable on a machine without a toolchain.
    """
    for name in ("pysqlcipher3.dbapi2", "sqlcipher3.dbapi2", "sqlcipher3"):
        try:
            return __import__(name, fromlist=["connect"])
        except Exception:
            continue
    return None


def encryption_available() -> bool:
    return sqlcipher_module() is not None


def get_or_create_db_key() -> str | None:
    """A 256-bit key, held in the Keychain.

    Returns None when there is nowhere safe to keep it. Writing the key next to
    the database it encrypts would be theatre, so this deliberately refuses
    rather than inventing a hiding place.
    """
    existing = keychain_get(DB_KEY_ACCOUNT)
    if existing:
        return existing
    if not keychain_available():
        return None
    key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    return key if keychain_set(DB_KEY_ACCOUNT, key) else None


def status() -> dict[str, object]:
    """What protection is actually in force. Surfaced by `phishguard security`."""
    keychain = keychain_available()
    cipher = encryption_available()
    return {
        "platform": sys.platform,
        "keychain_available": keychain,
        "sqlcipher_available": cipher,
        "token_backend": "keychain" if keychain else "file (0600)",
        "database_encrypted": bool(keychain and cipher),
        "warnings": _warnings(keychain, cipher),
    }


def _warnings(keychain: bool, cipher: bool) -> list[str]:
    out: list[str] = []
    if not cipher:
        out.append(
            "The message store is UNENCRYPTED. It holds full message bodies, "
            "headers and attachment metadata for every message indexed. Install "
            "SQLCipher (pip install sqlcipher3-binary) to encrypt it."
        )
    if not keychain:
        out.append(
            "No macOS Keychain on this platform, so the OAuth token is kept in a "
            "0600 file and no database key can be stored safely. Anyone who can "
            "read your home directory can read your mail archive and use the "
            "token to fetch more."
        )
    if cipher and not keychain:
        out.append(
            "SQLCipher is installed but there is no Keychain to hold the key, so "
            "encryption stays off - a key stored beside its database protects "
            "nothing."
        )
    return out


def connect_encrypted(path: str, key: str):
    """Open an encrypted database. Raises if SQLCipher is unavailable."""
    module = sqlcipher_module()
    if module is None:
        raise RuntimeError("SQLCipher is not installed")
    conn = module.connect(path, isolation_level=None)
    # The key must be applied before any other statement touches the file.
    conn.execute(f"PRAGMA key = \"x'{base64.b64decode(key).hex()}'\"")
    conn.execute("PRAGMA cipher_memory_security = ON")
    return conn

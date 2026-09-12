"""Google OAuth (installed-app flow).

Scope is gmail.readonly and stays that way: PhishGuard never mutates the
mailbox, so a compromise of this token cannot destroy mail.

gmail.readonly is a *restricted* scope. Shipping this publicly requires Google
OAuth verification plus an annual third-party CASA assessment. For development
keep the Cloud project's consent screen in "Testing" mode with your own address
added as a test user - that path needs no verification and no review latency.
"""

from __future__ import annotations

import json
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

from ..config import GMAIL_SCOPES, Config
from ..security import TokenStore


class AuthError(RuntimeError):
    pass


SETUP_HELP = """\
No OAuth client secret found at:
  {path}

To create one (a few minutes, free):
  1. https://console.cloud.google.com/ -> create or pick a project
  2. APIs & Services -> Library -> enable "Gmail API"
  3. APIs & Services -> OAuth consent screen -> External -> keep it in
     "Testing" and add your own Gmail address under Test users
  4. Credentials -> Create credentials -> OAuth client ID -> Desktop app
  5. Download the JSON and save it to the path above

Staying in Testing mode caps you at 100 test users and requires no Google
review. Do not move to Production until the product is real - that triggers
a security assessment for restricted scopes.
"""


def _write_private(path: Path, data: str) -> str:
    """Persist the token through TokenStore, which prefers the Keychain."""
    return TokenStore(path).write(data)


def _read_token(path: Path) -> str | None:
    return TokenStore(path).read()


def load_credentials(cfg: Config, interactive: bool = True) -> Credentials:
    """Return usable credentials, refreshing or prompting as needed."""
    creds: Credentials | None = None

    stored = _read_token(cfg.token_path)
    if stored:
        try:
            creds = Credentials.from_authorized_user_info(json.loads(stored), GMAIL_SCOPES)
        except (ValueError, KeyError, TypeError):
            creds = None  # corrupt token: fall through to a fresh consent

    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            _write_private(cfg.token_path, creds.to_json())
            return creds
        except Exception:
            creds = None  # refresh token revoked or expired; re-consent below

    if not interactive:
        raise AuthError("no valid credentials and interactive consent is disabled; run: phishguard auth")

    if not cfg.client_secret_path.exists():
        raise AuthError(SETUP_HELP.format(path=cfg.client_secret_path))

    flow = InstalledAppFlow.from_client_secrets_file(str(cfg.client_secret_path), GMAIL_SCOPES)
    # port=0 lets the OS pick a free loopback port; the redirect URI for a
    # Desktop-app client accepts any localhost port.
    creds = flow.run_local_server(port=0, prompt="consent", open_browser=True)
    _write_private(cfg.token_path, creds.to_json())
    return creds


def revoke(cfg: Config) -> bool:
    """Forget the local token, in both the Keychain and on disk. Does not revoke
    server-side - point the user at https://myaccount.google.com/permissions."""
    store = TokenStore(cfg.token_path)
    had = store.read() is not None
    store.delete()
    return had

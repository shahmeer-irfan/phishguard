# PhishGuard — email side, Phase 0

Local-first ingest layer for the anti-phishing Mac app. This phase does one job
and does it properly: get the user's mail onto the machine, parsed, without
losing any of the artefacts the detection layers will need later.

| Phase | What it adds |
|---|---|
| 0 | Gmail ingest, MIME parsing, local store, incremental sync |
| 1 | Layer 0 (protocol) + Layer 1 (identity), three-tier verdicts, findings API |
| 2 | Layer 3 — links, HTML, attachments, QR codes |
| 3 | Layer 2 — sender fingerprinting (technical + stylometric + relationship) |
| 4 | Layer 4 — intent analysis via Claude, on the ambiguous band only |
| 5 | Evaluation: synthetic attacks, metrics, ablation, threshold sweeps |
| — | Keychain token storage, optional SQLCipher database encryption |

Layer numbering follows the original taxonomy, not the build order: Layer 2 was
built third because it needs the contact history the earlier phases collect.

---

## Why it is shaped this way

Three decisions drive the whole design:

**`format='raw'`, not `format='full'`.** Gmail's parsed format has already
thrown away header order and exact MIME encoding. Those two things are the
backbone of Layer-2 sender fingerprinting, and they are unrecoverable once
dropped. We take the bytes as they arrived and parse them ourselves.

**compat32 parsing, not `policy.default`.** The modern email policy decodes and
re-folds headers for you, which again destroys raw casing and encoded-word
form. We keep the raw header pairs and decode explicitly only where a human
needs to read the result.

**Raw bytes are retained, gzipped.** Every detector added in Phases 1–4 can
re-run over the whole history without a second trip to Gmail. That is the
difference between iterating on detection in minutes and in hours.

Read-only OAuth scope (`gmail.readonly`), forever. The app never mutates the
mailbox, so a stolen token cannot destroy mail.

---

## Setup

```bash
pip install -r requirements.txt
```

Create a Google OAuth client (Desktop app) and drop the JSON at the path
`phishguard auth` prints. Keep the consent screen in **Testing** mode —
`gmail.readonly` is a restricted scope, and Production requires Google
verification plus an annual third-party CASA assessment.

```bash
python -m phishguard auth
python -m phishguard backfill --max 2000
python -m phishguard stats
```

## Commands

| Command | Purpose |
|---|---|
| `auth` | One-time Google consent |
| `backfill [--labels L] [--max N]` | Index history. Defaults to `INBOX,SPAM,SENT` |
| `sync` | Apply changes since the last run |
| `watch [--interval S]` | Poll forever |
| `stats` | Message counts, date range, DMARC breakdown |
| `contacts [-n N]` | The contact graph, ranked by affinity |
| `show <gmail_id> [--body]` | Dump one stored message with its auth results and hop chain |
| `inspect <file.eml>` | Parse a local `.eml` — no network, no database |

`inspect` is the fast loop for testing against real samples: in Gmail, *Show
original → Download original*, then point it at the file.

## Why SPAM and SENT are backfilled

- **SPAM** is the cheapest labelled negative set you will ever get. It is the
  evaluation data for Phase 5, free and specific to this user.
- **SENT** establishes *outbound* contact history. The user having written to an
  address is a far stronger trust signal than having received from one — anyone
  can send you mail. `top_contacts` weights outbound 3×.

Note the sampling bias this creates and state it in any evaluation: everything
in `INBOX` already survived Google's spam filter, so the corpus is made of hard
cases. Measured recall will look poor against naive baselines for that reason.

## What gets captured for later layers

Free at parse time, unrecoverable afterwards:

- `header_order_hash` — the header-name sequence, minus hop-added headers.
  Close to a mail-client serial number.
- `mime_signature` — e.g. `multipart/mixed(multipart/alternative(text/plain,text/html),application/pdf)`
- `date_tz_offset` — kept separately from the UTC timestamp on purpose
- `x_mailer` / `user_agent`, full ordered `headers_json`
- Parsed `Received:` chain (index 0 = closest to us, highest = claimed origin)
- Parsed `Authentication-Results` (SPF / DKIM `d=` / DMARC / ARC presence)
- Attachment names, types, sizes, SHA-256
- Both `text/plain` **and** `text/html` bodies, including parts a mail client
  would hide — hidden text is evidence, not noise

---

# Phase 1 — detection

```bash
python -m phishguard analyze            # score everything stored
python -m phishguard report             # what got flagged, and why
python -m phishguard verdict <gmail_id> # the full reasoning for one message
python -m phishguard inspect x.eml --detect   # Layer 0 only, offline
```

## Layer 0 — protocol truth

DMARC (with the published policy, lifted from Google's own comment), SPF, DKIM,
DKIM `d=` alignment, `Reply-To` / `Return-Path` divergence, ARC.

A DMARC failure against `p=reject` is a **hard danger** verdict: the domain
owner has explicitly stated this mail is forged, and turning that into a
probability would only blur it.

ARC is honoured as a mitigating signal. Forwarded mail legitimately breaks SPF,
and ignoring that is the single largest source of false positives at this layer.

## Layer 1 — identity

Display-name impersonation against the contact graph, lookalike domains
(visual / typo / TLD-swap / cousin), homoglyph and punycode domains,
freemail-posing-as-corporate, first contact, and domain registration age.

Two properties do most of the work:

**Impersonation needs no history with the sender** — only history with the
person being imitated. That is what makes it fire on first contact, which is
exactly when phishing arrives.

**The contact graph cannot poison itself.** Every sender becomes a contact row,
phishers included. A contact is only usable as an impersonation *target* once
the user has written to them, or received at least three messages. Without that
gate, the first fake "Abdul" would register as the reference identity and
validate every later one.

## Fusion

Findings carry a severity (what the UI shows) and a weight (what the maths
uses). Independent evidence combines by **noisy-OR**, so five weak signals
raise suspicion without any one being treated as proof, and the score stays
bounded.

Mitigating findings are **scoped to their layer**. This is the load-bearing
rule:

> `abdul@evil-abdul.com` passes SPF, DKIM and DMARC perfectly while being a
> complete impersonation.

A DMARC pass proves the *domain* is genuine. That is not an answer to "this is
not the domain that person uses" — the two statements are about different
things. Letting one cancel the other would make the product confidently clear
the exact attack it exists to catch. The verdict UI shows both side by side:

```
DANGER   score 0.73
  [L1] HIGH     DISPLAY_NAME_IMPERSONATION
         This message is signed "Abdul Rehman", but that name belongs to
         abdul@company.com in your contacts - not to abdul@evil-abdul.com.
  [L0] in favour  DMARC_PASS
         Verified as genuinely sent by evil-abdul.com.
```

Thresholds: `danger >= 0.70`, `caution >= 0.28`. Verdicts are stamped with a
model version and re-scored automatically when the ruleset changes.

Outbound mail is never scored — `SENT` exists to build the trust graph, not to
be judged.

## Optional: domain age

`analyze --online` fills a registration-date cache over RDAP (JSON over HTTPS,
no extra dependency). It is opt-in and leaks only domain names already present
in the user's mail — never an address, subject or body.

---

# Phase 2 — content and payload

Layers 0 and 1 judge *who sent* the message. Layer 3 judges *what it asks you
to do*: click a link, open a file, scan a code. It is also the only layer that
still works against a genuinely compromised account — there the envelope is
real and the identity is real, and the payload is the sole thing out of place.

(Layer 2, sender fingerprinting, is Phase 3. The numbering follows the original
taxonomy, not the build order.)

## Links

Anchor-text/href mismatch, the `user@host` userinfo trick, raw-IP hosts,
homoglyph hosts, lookalikes of domains you actually use, brand-in-subdomain
(`company.com.secure-login.ru`), open-redirect parameters, shorteners, free
hosting platforms, credential-page wording, non-standard ports, `javascript:`
and `data:` schemes, and `<meta refresh>` redirects.

Links are read from **both** the HTML and plain-text parts, because the two are
allowed to disagree and some kits rely on exactly that.

**Nothing here touches the network.** Expanding a shortener means telling the
attacker's server that the message was opened and handing over the user's IP,
so redirect-following is a Phase 3 opt-in, not a background scan.

One finding per *kind*, not per link — a newsletter with forty shortened links
is one observation.

## HTML

Concealed text (display/visibility/opacity, zero font size, white-on-white),
credential forms, forms posting off-domain, image-only messages, meta refresh.

Parsed with stdlib `html.parser` rather than BeautifulSoup, deliberately: a
lenient tree-builder silently *repairs* malformed markup, and malformed markup
is the point — it is how a kit gets the mail client to render one thing while a
scanner reads another. A streaming parser sees the document as sent.

## Attachments

Executables, scripts, containers (`.iso`, `.lnk`), macro documents, `.html`
attachments, OneNote, double extensions (`invoice.pdf.exe`),
extension/MIME-type mismatch, and password-protected archives *when the body
supplies the password* — locking an archive is how you make it unscannable, and
the victim then needs the password in the clear.

**RLO filenames are a hard danger verdict.** A `U+202E` override reverses how
the rest of the name renders, so `invoice<RLO>gpj.exe` is displayed as
`invoiceexe.jpg`. There is no benign use; presence alone is proof of intent.

## QR codes (quishing)

A QR code is a URL no text scanner can read and no hover can preview, and
scanning it moves the click onto a phone, away from every desktop protection.

Decoded payloads are **re-run through the full link pipeline** — otherwise the
detector could only say "there is a QR code here", which is true of plenty of
legitimate newsletters.

OpenCV is an optional dependency (`pip install opencv-python-headless`), chosen
over pyzbar because it needs no native library beyond its own wheel — which
matters for a signed `.app`. Without it the pipeline still reports that an
unreadable image is carrying the message.

Only images whose **bytes are in the message** are considered. A remote
`<img src="https://cdn...">` cannot be scanned at all, and reporting it as
"unscanned" would fire on every newsletter with a logo.

## Link corpus

Every link is stored in `message_links` as analysis runs. That accumulates the
answer to a question no single message can settle: *has any mail this user has
ever received linked to this domain before?*

## Tests

```bash
python tests/test_offline.py    # 9  - parser and store
python tests/test_detect.py     # 22 - Layer 0/1, fusion, domain logic
python tests/test_content.py    # 31 - Layer 3 links, HTML, attachments, QR
```

62 tests, no credentials needed.

The false-positive tests carry as much weight as the detection ones — an
ordinary newsletter, a plain personal email, a real login link on a domain you
use, and a tracking pixel all have to come back clean. A content layer that
cries wolf is worse than none, because it teaches the user to dismiss the
banner.

## Layout

```
phishguard/
  config.py            paths, scopes, ingest tunables
  cli.py               command line
  db/schema.sql        full schema (detector tables created, unused until later)
  db/store.py          persistence, contact graph, watermark handling
  gmail/auth.py        OAuth installed-app flow
  gmail/client.py      API wrapper: retries, jittered backoff, quota pacing
  gmail/sync.py        backfill + incremental (history.list)
  parse/headers.py     addresses, dates, Authentication-Results, Received chain
  parse/message.py     RFC822 -> ParsedMessage
  detect/base.py       Finding vocabulary, severities, mitigation scoping
  detect/view.py       MessageView: the flat shape detectors consume
  detect/context.py    contact graph shaped for detection, trust gating
  detect/domains.py    eTLD+1, freemail, lookalikes, homoglyphs (stdlib only)
  detect/layer0.py     protocol truth
  detect/layer1.py     identity
  detect/scoring.py    noisy-OR fusion, layer-scoped mitigation, tiers
  detect/engine.py     orchestration, persistence, queries
  detect/intel.py      RDAP domain age (opt-in)
  detect/urls.py       URL dissection, shorteners, redirects, brand tricks
  detect/content.py    streaming HTML parser: links, forms, hidden text, images
  detect/attachments.py extension/type classification, RLO, double extensions
  detect/layer3.py     content and payload
  detect/qr.py         optional QR decoding (opencv)
```

## Known gaps, deliberately deferred

- **Token storage.** `token.json` is written `0600` on disk. Before ship it
  moves into the macOS Keychain.
- **Database encryption.** The store is plaintext SQLite. Once it holds a real
  mail archive it needs SQLCipher with a Keychain-held key. This is the single
  most important thing to fix before anyone but you runs it.
- **Sync is poll-based.** Gmail push needs a Cloud Pub/Sub endpoint, which a
  local-first desktop app does not have. Polling costs one quota unit per call.
- **Single account.** The schema is multi-account; the CLI assumes one.

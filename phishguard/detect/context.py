"""The contact graph, shaped for detection.

Built once per analysis run and reused across messages: the alternative is a
query per detector per message, which turns a 15k-message pass into an hour.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..db.store import Store
from ..parse.headers import canonical_address, split_address
from . import domains as D


@dataclass
class ContactRef:
    canonical_email: str
    domain: str
    display_names: list[str]
    inbound: int
    outbound: int

    @property
    def trust(self) -> float:
        """0..1. Outbound dominates: the user having *written to* an address is
        a declared relationship, while inbound alone only proves someone can
        spell your address.

        Outbound saturates fast (two replies is already a real correspondence)
        because this value decides how strongly an impersonation of this person
        is reported. Requiring a long history before treating someone as
        impersonable would leave the most valuable targets - a manager you
        email occasionally - under-protected.
        """
        score = min(1.0, self.outbound / 2.0) * 0.6 + min(1.0, self.inbound / 10.0) * 0.4
        return round(score, 3)

    @property
    def is_reference_grade(self) -> bool:
        """Whether this contact may serve as an impersonation *target*.

        This gate is what stops the system poisoning itself. Every sender that
        has ever mailed the user becomes a contact row, phishers included. If a
        single inbound message were enough to define an identity, the first
        fake 'Abdul' would register as the reference copy and every later one
        would validate against it.
        """
        return self.outbound > 0 or self.inbound >= 3


@dataclass
class AnalysisContext:
    account_id: int
    account_email: str = ""
    account_domains: set[str] = field(default_factory=set)

    contacts: dict[str, ContactRef] = field(default_factory=dict)
    by_display_name: dict[str, list[ContactRef]] = field(default_factory=dict)
    reference_domains: dict[str, float] = field(default_factory=dict)
    domain_intel: dict[str, dict[str, Any]] = field(default_factory=dict)
    profiles: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------- lookups

    def contact_for(self, addr: str) -> ContactRef | None:
        return self.contacts.get(canonical_address(addr)) if addr else None

    def profile_for(self, addr: str):
        """Layer-2 fingerprint for a sender, or None when none has been built."""
        return self.profiles.get(canonical_address(addr)) if addr else None

    def impersonation_targets(self, display_name: str) -> list[ContactRef]:
        """Reference-grade contacts who normally use this display name."""
        return self.by_display_name.get(D.normalise_display_name(display_name), [])

    def nearest_reference_domain(self, domain: str) -> tuple[str, str, float] | None:
        """(known_domain, kind, confidence) for the closest lookalike match."""
        if not domain:
            return None
        org = D.org_domain(domain)
        if org in self.reference_domains:
            return None  # it *is* a known domain, not an imitation of one
        best: tuple[str, str, float] | None = None
        for known in self.reference_domains:
            hit = D.lookalike_kind(org, known)
            if hit and (best is None or hit[1] > best[2]):
                best = (known, hit[0], hit[1])
        return best

    def is_known_domain(self, domain: str) -> bool:
        return D.org_domain(domain) in self.reference_domains

    def is_own_address(self, addr: str) -> bool:
        return bool(addr) and canonical_address(addr) == canonical_address(self.account_email)


def build_context(store: Store, account_id: int) -> AnalysisContext:
    ctx = AnalysisContext(account_id=account_id)
    ctx.account_email = store.account_email(account_id) or ""
    if ctx.account_email:
        ctx.account_domains.add(D.org_domain(split_address(ctx.account_email)[1]))

    rows = store.conn.execute(
        "SELECT * FROM contacts WHERE account_id = ?", (account_id,)
    ).fetchall()

    for row in rows:
        try:
            names = json.loads(row["display_names_json"]) or []
        except (TypeError, ValueError):
            names = []
        ref = ContactRef(
            canonical_email=row["canonical_email"],
            domain=row["domain"] or "",
            display_names=names,
            inbound=int(row["inbound_count"] or 0),
            outbound=int(row["outbound_count"] or 0),
        )
        ctx.contacts[ref.canonical_email] = ref

        if not ref.is_reference_grade:
            continue

        for name in names:
            key = D.normalise_display_name(name)
            if len(key) < 3:
                continue
            ctx.by_display_name.setdefault(key, []).append(ref)

        # Freemail domains are never a reference identity: half the planet is
        # on gmail.com, so treating it as "a known domain" would both suppress
        # real findings and generate nonsense lookalike matches.
        org = D.org_domain(ref.domain)
        if org and not D.is_freemail(org):
            ctx.reference_domains[org] = max(ctx.reference_domains.get(org, 0.0), ref.trust)

    for org in ctx.account_domains:
        if org and not D.is_freemail(org):
            ctx.reference_domains.setdefault(org, 1.0)

    try:
        for row in store.conn.execute("SELECT * FROM domain_intel"):
            ctx.domain_intel[row["domain"]] = dict(row)
    except Exception:
        pass  # table arrives with the Phase 1 migration; absence is not fatal

    from .profiles import load_all
    ctx.profiles = load_all(store, account_id)

    return ctx

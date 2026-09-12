"""Evaluation: metrics, per-layer ablation, threshold sweeps.

Numbers only mean something with their caveats attached, so the report prints
them together. Two in particular:

**The benign set is pre-filtered.** Everything in INBOX already survived
Google's spam filter, so the benign class is unusually clean and the attack
class is made of hard cases. Precision here is optimistic relative to a raw
mail stream; recall is pessimistic.

**Synthetic attacks measure coverage of modelled techniques.** They are a floor,
not an estimate of real-world recall - they cannot contain a technique nobody
implemented.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..db.store import Store
from ..detect import layer0, layer1, layer2, layer3
from ..detect.base import Finding, Tier
from ..detect.context import AnalysisContext
from ..detect.scoring import CAUTION_THRESHOLD, DANGER_THRESHOLD, fuse
from ..detect.view import MessageView
from ..parse.message import parse_rfc822
from .synth import SourceMessage, generate

LAYERS: dict[int, Callable[[MessageView, AnalysisContext], list[Finding]]] = {
    0: layer0.run, 1: layer1.run, 2: layer2.run, 3: layer3.run,
}


@dataclass
class Sample:
    view: MessageView
    label: str                    # "attack" | "benign"
    transform: str = "genuine"
    target_layer: int | None = None


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "precision": round(self.precision, 4), "recall": round(self.recall, 4),
                "f1": round(self.f1, 4), "fpr": round(self.false_positive_rate, 4)}


def score_with_layers(view: MessageView, ctx: AnalysisContext,
                      layers: Iterable[int]) -> tuple[float, Tier, list[Finding]]:
    findings: list[Finding] = []
    for n in sorted(layers):
        fn = LAYERS.get(n)
        if fn is not None:
            findings += fn(view, ctx)
    verdict = fuse(findings)
    return verdict.score, verdict.tier, findings


def evaluate(samples: list[Sample], ctx: AnalysisContext,
             layers: Iterable[int] = (0, 1, 2, 3),
             threshold: float = DANGER_THRESHOLD,
             flag_caution: bool = True) -> dict[str, Any]:
    """Score every sample and summarise.

    `flag_caution` decides what counts as a positive: with it, anything above
    the caution line is treated as "the user was warned"; without it, only a
    danger verdict counts. The two answer different questions - whether the
    system surfaced the attack at all, versus whether it called it outright.
    """
    overall = Metrics()
    by_transform: dict[str, Metrics] = {}
    misses: list[dict[str, Any]] = []
    false_alarms: list[dict[str, Any]] = []
    scores = {"attack": [], "benign": []}

    for sample in samples:
        score, tier, findings = score_with_layers(sample.view, ctx, layers)
        cut = CAUTION_THRESHOLD if flag_caution else threshold
        flagged = score >= cut
        scores[sample.label].append(score)

        bucket = by_transform.setdefault(sample.transform, Metrics())
        if sample.label == "attack":
            if flagged:
                overall.tp += 1
                bucket.tp += 1
            else:
                overall.fn += 1
                bucket.fn += 1
                misses.append({
                    "transform": sample.transform, "score": round(score, 3),
                    "from": sample.view.from_addr, "subject": sample.view.subject[:60],
                })
        else:
            if flagged:
                overall.fp += 1
                bucket.fp += 1
                false_alarms.append({
                    "score": round(score, 3), "from": sample.view.from_addr,
                    "subject": sample.view.subject[:60],
                    "codes": [f.code for f in findings if not f.mitigating][:4],
                })
            else:
                overall.tn += 1
                bucket.tn += 1

    return {
        "layers": sorted(layers),
        "threshold": CAUTION_THRESHOLD if flag_caution else threshold,
        "overall": overall.as_dict(),
        "by_transform": {k: v.as_dict() for k, v in sorted(by_transform.items())},
        "mean_score": {k: round(sum(v) / len(v), 4) if v else 0.0
                       for k, v in scores.items()},
        "misses": misses[:20],
        "false_alarms": false_alarms[:20],
        "n_attack": sum(1 for s in samples if s.label == "attack"),
        "n_benign": sum(1 for s in samples if s.label == "benign"),
    }


def ablate(samples: list[Sample], ctx: AnalysisContext) -> list[dict[str, Any]]:
    """What each layer is worth.

    Cumulative (0, 0-1, 0-2, 0-3) rather than leave-one-out: the layers are
    designed to compound, so the honest question is what each one adds on top of
    the ones before it, not what survives when it alone is removed.
    """
    rows: list[dict[str, Any]] = []
    for upto in (0, 1, 2, 3):
        result = evaluate(samples, ctx, layers=range(0, upto + 1))
        rows.append({
            "layers": f"0-{upto}" if upto else "0",
            **result["overall"],
        })
    return rows


def sweep_thresholds(samples: list[Sample], ctx: AnalysisContext,
                     steps: int = 20) -> list[dict[str, Any]]:
    """Precision/recall across the whole threshold range.

    Scoring once and re-thresholding, rather than re-scoring per step - the
    verdict is a monotone function of the score, so re-running the detectors
    would produce identical findings at 20x the cost.
    """
    scored: list[tuple[str, float]] = []
    for sample in samples:
        score, _, _ = score_with_layers(sample.view, ctx, (0, 1, 2, 3))
        scored.append((sample.label, score))

    rows: list[dict[str, Any]] = []
    for i in range(1, steps):
        cut = i / steps
        m = Metrics()
        for label, score in scored:
            flagged = score >= cut
            if label == "attack":
                m.tp += flagged
                m.fn += not flagged
            else:
                m.fp += flagged
                m.tn += not flagged
        rows.append({"threshold": round(cut, 3), **m.as_dict()})
    return rows


# ------------------------------------------------------------ dataset build

def load_samples(store: Store, account_id: int, ctx: AnalysisContext,
                 per_transform: int = 20, benign_limit: int = 300,
                 seed: int = 20250909) -> tuple[list[Sample], dict[str, Any]]:
    """Benign mail from the store, attacks synthesised against the same contacts.

    Benign samples exclude anything the detector currently calls dangerous.
    That is a real limitation and it is stated in the report: a true positive
    sitting in the inbox would otherwise be counted as a false alarm, but
    excluding by current verdict also means the benign set cannot contain a
    miss the detector already makes.
    """
    rows = store.conn.execute(
        """SELECT m.*, v.tier FROM messages m
           LEFT JOIN verdicts v ON v.message_id = m.id
           WHERE m.account_id = ? AND m.from_addr != ''
             AND m.labels_json NOT LIKE '%SENT%'
           ORDER BY m.received_at DESC LIMIT ?""",
        (account_id, benign_limit * 3),
    ).fetchall()

    benign_rows = [r for r in rows if (r["tier"] or "safe") != "danger"][:benign_limit]
    excluded = len(rows) - len(benign_rows)

    samples: list[Sample] = []
    sources: list[SourceMessage] = []
    for row in benign_rows:
        view = _view_from_row(store, row)
        samples.append(Sample(view=view, label="benign"))
        sources.append(SourceMessage(
            gmail_id=row["gmail_id"], from_addr=row["from_addr"],
            from_display=row["from_display"] or "", subject=row["subject"] or "",
            body_text=row["body_text"] or "",
            to_addr=ctx.account_email or "user@example.com",
            x_mailer=row["x_mailer"], message_id=row["rfc822_message_id"],
        ))

    attacks = generate(sources, per_transform=per_transform, seed=seed)
    for attack in attacks:
        parsed = parse_rfc822(attack.raw)
        samples.append(Sample(
            view=MessageView.from_parsed(parsed, gmail_id=f"synth-{attack.transform}"),
            label="attack", transform=attack.transform,
            target_layer=attack.target_layer,
        ))

    meta = {
        "benign": len(benign_rows),
        "attacks": len(attacks),
        "excluded_from_benign": excluded,
        "transforms": sorted({a.transform for a in attacks}),
        "seed": seed,
    }
    return samples, meta


def _view_from_row(store: Store, row: Any) -> MessageView:
    auth = store.conn.execute(
        "SELECT * FROM auth_results WHERE message_id = ?", (row["id"],)).fetchone()
    hops = store.conn.execute(
        "SELECT * FROM received_hops WHERE message_id = ? ORDER BY hop_index",
        (row["id"],)).fetchall()
    atts = store.conn.execute(
        "SELECT * FROM attachments WHERE message_id = ?", (row["id"],)).fetchall()
    return MessageView.from_db(row, auth, hops, atts)


# ----------------------------------------------------------------- report

CAVEATS = [
    "Benign samples come from INBOX, which Google's spam filter has already "
    "cleaned. Precision here is optimistic against a raw mail stream.",
    "Attacks are synthetic, built from the seven modelled techniques. They "
    "measure coverage of what was implemented, and cannot contain a technique "
    "nobody thought of - treat recall as a floor, not an estimate.",
    "Benign samples currently judged 'danger' are excluded, so the benign set "
    "cannot contain a false negative the detector already makes.",
    "Attack and source messages share contacts, so Layer 1 and Layer 2 see the "
    "same contact graph they would in production - but the synthetic bodies are "
    "drawn from a small fixed pool of templates.",
]


def full_report(store: Store, account_id: int, ctx: AnalysisContext,
                per_transform: int = 20, benign_limit: int = 300,
                seed: int = 20250909) -> dict[str, Any]:
    samples, meta = load_samples(store, account_id, ctx, per_transform,
                                 benign_limit, seed)
    if not samples:
        return {"error": "no samples; run backfill and analyze first"}
    return {
        "dataset": meta,
        "headline": evaluate(samples, ctx),
        "danger_only": evaluate(samples, ctx, flag_caution=False),
        "ablation": ablate(samples, ctx),
        "thresholds": sweep_thresholds(samples, ctx),
        "caveats": CAVEATS,
    }


def render(report: dict[str, Any]) -> str:
    if "error" in report:
        return report["error"]
    lines: list[str] = []
    d = report["dataset"]
    lines.append(f"dataset: {d['benign']} benign, {d['attacks']} synthetic attacks "
                 f"across {len(d['transforms'])} techniques (seed {d['seed']})")

    def block(title: str, m: dict[str, Any]) -> None:
        lines.append(f"\n{title}")
        lines.append(f"  precision {m['precision']:.3f}   recall {m['recall']:.3f}   "
                     f"f1 {m['f1']:.3f}   false-alarm rate {m['fpr']:.3f}")
        lines.append(f"  tp {m['tp']}  fp {m['fp']}  tn {m['tn']}  fn {m['fn']}")

    block("flagged = caution or danger", report["headline"]["overall"])
    block("flagged = danger only", report["danger_only"]["overall"])

    lines.append("\nper technique (caution or danger)")
    for name, m in report["headline"]["by_transform"].items():
        if name == "genuine":
            continue
        total = m["tp"] + m["fn"]
        lines.append(f"  {name:<24} caught {m['tp']}/{total}  recall {m['recall']:.3f}")

    lines.append("\nlayer ablation (cumulative)")
    lines.append(f"  {'layers':<8} {'precision':>9} {'recall':>8} {'f1':>7} {'fpr':>7}")
    for row in report["ablation"]:
        lines.append(f"  {row['layers']:<8} {row['precision']:>9.3f} {row['recall']:>8.3f} "
                     f"{row['f1']:>7.3f} {row['fpr']:>7.3f}")

    best = max(report["thresholds"], key=lambda r: r["f1"])
    lines.append(f"\nbest f1 at threshold {best['threshold']:.2f}: "
                 f"precision {best['precision']:.3f}, recall {best['recall']:.3f}")
    prec95 = [r for r in report["thresholds"] if r["precision"] >= 0.95]
    if prec95:
        pick = max(prec95, key=lambda r: r["recall"])
        lines.append(f"highest recall at >=0.95 precision: {pick['recall']:.3f} "
                     f"(threshold {pick['threshold']:.2f})")

    if report["headline"]["misses"]:
        lines.append("\nmissed attacks")
        for m in report["headline"]["misses"][:8]:
            lines.append(f"  {m['transform']:<24} score {m['score']:.2f}  {m['from']}")
    if report["headline"]["false_alarms"]:
        lines.append("\nfalse alarms")
        for f in report["headline"]["false_alarms"][:8]:
            lines.append(f"  score {f['score']:.2f}  {f['from']}  {','.join(f['codes'])}")

    lines.append("\nread these numbers with:")
    for c in report["caveats"]:
        lines.append(f"  - {c}")
    return "\n".join(lines)


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, default=str)

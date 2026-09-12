"""Fusion: findings in, one verdict out.

Three rules govern this file, and they are the whole reason it exists
separately from the detectors:

1. A hard verdict wins outright. When the protocol has already settled the
   question, converting that into a probability only blurs it.
2. Independent evidence combines by noisy-OR, not by summing. Five weak
   signals should raise suspicion without any of them being weighted as though
   it were proof, and the result must stay bounded.
3. Reassurance cannot outrank an identity mismatch. This is the important one:
   `abdul@evil-abdul.com` passes SPF, DKIM and DMARC perfectly while being a
   complete impersonation. If a DMARC pass were allowed to damp that finding,
   the product would confidently clear the exact attack it exists to catch.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .base import Finding, Severity, Tier

MODEL_VERSION = "p5-rules-1"

DANGER_THRESHOLD = 0.70
CAUTION_THRESHOLD = 0.28

# How far positive evidence of a given strength may be discounted by
# mitigating findings. Critical evidence is effectively undampenable.
_MITIGATION_CEILING = {
    Severity.CRITICAL: 0.05,
    Severity.HIGH: 0.25,
    Severity.MEDIUM: 0.55,
    Severity.LOW: 0.80,
    Severity.INFO: 0.90,
}

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                   Severity.HIGH, Severity.CRITICAL]


@dataclass
class Verdict:
    tier: Tier
    score: float
    findings: list[Finding] = field(default_factory=list)
    headline: str = ""
    model_version: str = MODEL_VERSION

    @property
    def risk_findings(self) -> list[Finding]:
        return sorted(
            (f for f in self.findings if not f.mitigating),
            key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.weight),
            reverse=True,
        )

    @property
    def mitigating_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.mitigating]


def noisy_or(weights: list[float]) -> float:
    """P(at least one signal is real), assuming independence.

    Saturating and order-independent: adding a sixth weak signal to five
    existing ones nudges the result rather than doubling it, and nothing can
    push the score past 1.
    """
    product = 1.0
    for w in weights:
        product *= (1.0 - max(0.0, min(1.0, w)))
    return 1.0 - product


def fuse(findings: list[Finding]) -> Verdict:
    hard = next((f for f in findings if f.hard_tier is not None), None)
    risks = [f for f in findings if not f.mitigating]
    mitigators = [f for f in findings if f.mitigating]

    if hard is not None:
        score = 0.97 if hard.hard_tier is Tier.DANGER else 0.02
        return Verdict(tier=hard.hard_tier, score=score, findings=findings,
                       headline=hard.human_text)

    # Risk is fused per layer, and mitigation is applied inside the layer it
    # is scoped to, before the layers are combined. Scoring globally would let
    # a Layer-0 success bleed into a Layer-1 accusation - see rule 3 above.
    by_layer: dict[int, list[Finding]] = {}
    for f in risks:
        by_layer.setdefault(f.layer, []).append(f)

    adjusted: list[float] = []
    for layer, layer_risks in by_layer.items():
        layer_score = noisy_or([f.weight for f in layer_risks])
        peak = max(layer_risks, key=lambda f: _SEVERITY_ORDER.index(f.severity))
        ceiling = _MITIGATION_CEILING[peak.severity]
        relief = min(
            noisy_or([m.weight for m in mitigators if m.applies_to(layer)]), ceiling
        )
        adjusted.append(layer_score * (1.0 - relief))

    score = round(max(0.0, min(1.0, noisy_or(adjusted))), 4)

    if score >= DANGER_THRESHOLD:
        tier = Tier.DANGER
    elif score >= CAUTION_THRESHOLD:
        tier = Tier.CAUTION
    else:
        tier = Tier.SAFE

    return Verdict(tier=tier, score=score, findings=findings,
                   headline=_headline(tier, risks, mitigators))


def _headline(tier: Tier, risks: list[Finding], mitigators: list[Finding]) -> str:
    """One sentence for the UI.

    A verdict the user cannot act on is not a verdict, and a list of nine
    findings is not something anyone reads at 9am. The strongest single reason
    leads; the rest stay available underneath.
    """
    if tier is Tier.SAFE and not risks:
        if mitigators:
            return mitigators[0].human_text
        return "Nothing suspicious found in this message's sender or routing."
    if not risks:
        return "No specific concerns identified."
    top = max(risks, key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.weight))
    return top.human_text

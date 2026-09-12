"""Finding vocabulary shared by every detector.

A detector never returns a score. It returns evidence: what it saw, how much
that should move the needle, and a sentence a non-technical person can read.
Fusion happens in one place (scoring.py) so weights stay comparable and the
verdict stays explainable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Tier(str, Enum):
    SAFE = "safe"
    CAUTION = "caution"
    DANGER = "danger"


@dataclass
class Finding:
    code: str                       # stable machine id, e.g. DISPLAY_NAME_IMPERSONATION
    layer: int                      # 0 = protocol, 1 = identity, ...
    severity: Severity
    weight: float                   # 0..1 contribution to the noisy-OR fusion
    human_text: str                 # shown in the UI, plain English, no jargon
    evidence: dict[str, Any] = field(default_factory=dict)

    # Mitigating findings argue *for* the message. They are fused separately
    # and damp the risk score rather than adding to it.
    mitigating: bool = False

    # Which layers a mitigating finding is allowed to reassure about. None
    # means all of them.
    #
    # This exists because reassurance does not transfer across layers. A DMARC
    # pass proves the *domain* is genuine, which is simply not an answer to
    # "this domain is not the one that person uses" - the two statements are
    # about different things, and letting one cancel the other is a category
    # error, not a weighting choice. Scoping keeps a protocol success from
    # quietly clearing an identity mismatch.
    scope: frozenset[int] | None = None

    def applies_to(self, layer: int) -> bool:
        return self.scope is None or layer in self.scope

    # A hard verdict skips fusion entirely. Reserved for cases where the
    # protocol already gives a definitive answer and a probability would only
    # blur it - see scoring.py.
    hard_tier: Tier | None = None

    def as_row(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "code": self.code,
            "severity": self.severity.value,
            "weight": self.weight,
            "human_text": self.human_text,
        }


# Severity is what the UI sorts and colours by; weight is what the maths uses.
# Keeping them separate means we can retune scoring without changing how
# anything is presented.
DEFAULT_WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 0.10,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.45,
    Severity.HIGH: 0.70,
    Severity.CRITICAL: 0.90,
}

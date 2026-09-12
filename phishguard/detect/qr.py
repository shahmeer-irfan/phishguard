"""QR decoding for "quishing".

A QR code is a URL that no text scanner can read and no hover can preview, so
putting the payload in an image defeats every link check in Layer 3 at once -
and moves the click onto a phone, off whatever protections the desktop has.
That is why it became the fastest-growing delivery method.

OpenCV is an optional dependency, chosen over pyzbar because it needs no native
library beyond its own wheel - which matters when the end product is a signed
.app bundle. When it is absent the pipeline still reports *that* an unreadable
image is carrying the message; it simply cannot say what the code contains.
"""

from __future__ import annotations

import logging

log = logging.getLogger("phishguard.qr")

try:  # pragma: no cover - availability depends on the install
    import cv2  # type: ignore
    import numpy as np  # type: ignore

    _AVAILABLE = True
except Exception:  # ImportError, or a broken native build
    cv2 = None  # type: ignore
    np = None  # type: ignore
    _AVAILABLE = False


def available() -> bool:
    return _AVAILABLE


def decode(image_bytes: bytes) -> list[str]:
    """Every QR payload in one image. Empty when none, or when unavailable."""
    if not _AVAILABLE or not image_bytes:
        return []
    try:
        buf = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
        if img is None:
            return []

        detector = cv2.QRCodeDetector()
        ok, payloads, _, _ = detector.detectAndDecodeMulti(img)
        if ok and payloads:
            return [p for p in payloads if p]

        # Single-code fallback: detectAndDecodeMulti misses some low-contrast
        # codes that the single-code path still reads.
        payload, _, _ = detector.detectAndDecode(img)
        return [payload] if payload else []
    except Exception as exc:
        log.debug("qr decode failed: %s", exc)
        return []


def decode_all(images: list[bytes], max_images: int = 8) -> list[str]:
    out: list[str] = []
    for blob in images[:max_images]:
        out.extend(decode(blob))
    return list(dict.fromkeys(out))

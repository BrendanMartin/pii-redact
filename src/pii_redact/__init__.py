"""pii-redact: Pure-regex PII redaction library."""

from __future__ import annotations

from dataclasses import dataclass

from .patterns import DETECTORS


@dataclass(frozen=True, slots=True)
class PiiMatch:
    """A single PII detection result."""

    type: str
    value: str
    start: int
    end: int


def scan(text: str) -> list[PiiMatch]:
    """Scan *text* for all known PII types and return matches.

    Returns a de-duplicated list sorted by position. When two matches
    overlap, the longer (outer) match is kept and the shorter one is
    dropped.
    """
    matches: list[PiiMatch] = []
    for pii_type, detect_fn in DETECTORS.items():
        matches.extend(detect_fn(text, pii_type))
    matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
    return _dedupe(matches)


def scan_one(text: str, pii_type: str) -> list[PiiMatch]:
    """Scan *text* for a specific PII type only.

    Raises ``ValueError`` if *pii_type* is not a known detector name.
    """
    detect_fn = DETECTORS.get(pii_type)
    if detect_fn is None:
        raise ValueError(
            f"Unknown PII type: {pii_type!r}. Known types: {sorted(DETECTORS)}"
        )
    matches = detect_fn(text, pii_type)
    matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
    return matches


def _dedupe(matches: list[PiiMatch]) -> list[PiiMatch]:
    """Remove matches fully contained within an earlier, longer match."""
    kept: list[PiiMatch] = []
    for m in matches:
        if any(k.start <= m.start and k.end >= m.end for k in kept):
            continue
        kept.append(m)
    return kept

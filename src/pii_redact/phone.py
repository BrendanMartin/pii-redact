"""US phone number detection using pure regex with validation heuristics.

Patterns inspired by Presidio PhoneRecognizer and commonregex-improved.
Instead of the ``phonenumbers`` library we use compiled regexes with
post-match validation to reject impossible area codes and exchanges.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import PiiMatch

# ---------------------------------------------------------------------------
# Invalid area codes / exchanges
# ---------------------------------------------------------------------------
# Area codes cannot start with 0 or 1. Exchange (next 3 digits) also
# cannot start with 0 or 1. N11 codes (e.g. 911, 411) are services,
# not assignable numbers.
_INVALID_AREA_CODES = frozenset({
    "000", "100", "200", "211", "311", "411", "511", "611", "711", "811", "911",
})

# ---------------------------------------------------------------------------
# Core phone regex
# ---------------------------------------------------------------------------
# Matches US phone formats:
#   (555) 123-4567  |  555-123-4567  |  555.123.4567
#   +1-555-123-4567 |  +1 (555) 123-4567  |  1-555-123-4567
#   +15551234567    |  15551234567
#
# Uses word boundaries and lookbehind/lookahead to avoid matching
# inside longer digit sequences (part numbers, dimensions).
_PHONE_RE = re.compile(
    r"""
    (?<!\d)                          # not preceded by a digit
    (?<!\d[.\-])                     # not preceded by digit + separator (avoids mid-number)
    (?:
        (?:\+?1[\s.\-]?)?           # optional country code +1
        (?:
            \((?P<area1>[2-9]\d{2})\)  # (NPA) with parens
            |
            (?P<area2>[2-9]\d{2})      # NPA without parens
        )
        (?P<sep1>[\s.\-]?)           # separator (area -> exchange)
        (?P<exchange>[2-9]\d{2})     # exchange (NXX)
        (?P<sep2>[\s.\-]?)           # separator (exchange -> subscriber)
        (?P<subscriber>\d{4})        # subscriber number
    )
    (?!\d)                           # not followed by a digit
    (?![.\-]\d)                      # not followed by separator + digit
    """,
    re.VERBOSE,
)


def _is_valid_phone(m: re.Match[str]) -> bool:
    """Post-match validation: reject impossible area codes and patterns."""
    area = m.group("area1") or m.group("area2")
    exchange = m.group("exchange")

    if area is None or exchange is None:
        return False

    # Separator consistency: an un-parenthesized number must group its 10 digits
    # uniformly — either fully separated (650-300-7562 / 650.300.7562 / 650 300 7562)
    # or fully joined (6503007562). A mix (no separator between area and exchange
    # but one before the subscriber, e.g. "650300 7562") is not a real phone
    # grouping — it's a part number that coincidentally has a valid NPA/NXX.
    if m.group("area1") is None and bool(m.group("sep1")) != bool(m.group("sep2")):
        return False

    # Area code cannot be an N11 or start with 0/1
    if area in _INVALID_AREA_CODES:
        return False

    # Exchange cannot be N11 pattern (X11)
    if exchange[1:] == "11":
        return False

    # Reject 555-01XX range (reserved fictitious numbers)
    if area == "555" and exchange == "010":
        return False

    return True


def detect_phones(text: str, pii_type: str) -> list[PiiMatch]:
    """Find US phone numbers in *text*."""
    from . import PiiMatch

    results: list[PiiMatch] = []
    for m in _PHONE_RE.finditer(text):
        if _is_valid_phone(m):
            results.append(
                PiiMatch(
                    type=pii_type,
                    value=m.group(),
                    start=m.start(),
                    end=m.end(),
                )
            )
    return results

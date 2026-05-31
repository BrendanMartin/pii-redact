"""Compiled regex patterns for PII detection.

Pattern sources:
- Microsoft Presidio  (email, IP, SSN, URL recognizers)
- scrubadub           (email, URL, SSN detectors)
- commonregex-improved (street address, general patterns)

Every detector function has the signature:
    (text: str, pii_type: str) -> list[PiiMatch]
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from . import PiiMatch

# ───────────────────────────────────────────────────────────────────
# Email
# ───────────────────────────────────────────────────────────────────
# Merged from Presidio EmailRecognizer and scrubadub EmailDetector.
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]"
    r"(?:[.a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]{0,62}"
    r"[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-])?"
    r"@"
    r"[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?"
    r"\.[a-zA-Z]{2,63}\b"
)


def _detect_email(text: str, pii_type: str) -> list[PiiMatch]:
    from . import PiiMatch

    return [
        PiiMatch(type=pii_type, value=m.group(), start=m.start(), end=m.end())
        for m in _EMAIL_RE.finditer(text)
    ]


# ───────────────────────────────────────────────────────────────────
# URL
# ───────────────────────────────────────────────────────────────────
# Merged from Presidio UrlRecognizer and scrubadub UrlDetector.
# Matches http(s):// URLs and www. prefixed URLs.
_URL_RE = re.compile(
    r"(?i)"
    r"(?:https?://(?:www\.)?|www\.)"
    r"[-\w@:%.\+~#=]{2,256}"
    r"\.[a-z]{2,63}"
    r"(?:/[-\w@:%\+.~#?&/=]*)?"
)


def _detect_url(text: str, pii_type: str) -> list[PiiMatch]:
    from . import PiiMatch

    return [
        PiiMatch(type=pii_type, value=m.group(), start=m.start(), end=m.end())
        for m in _URL_RE.finditer(text)
    ]


# ───────────────────────────────────────────────────────────────────
# US Street Address
# ───────────────────────────────────────────────────────────────────
# Matches patterns like: 123 Main St, 4567 Elm Avenue, 89 Oak Blvd
# Requires a leading house number and a known street suffix.
_STREET_SUFFIXES = (
    r"ST|STREET|AVE|AVENUE|BLVD|BOULEVARD|DR|DRIVE|PKWY|PARKWAY|"
    r"RD|ROAD|LN|LANE|CT|COURT|WAY|PL|PLACE|CIR|CIRCLE|"
    r"HWY|HIGHWAY|TRL|TRAIL|TERR?|TERRACE|LOOP|RUN|PATH|PIKE|"
    r"ALY|ALLEY|SQ|SQUARE|PASS"
)

_STREET_RE = re.compile(
    r"\b"
    r"(?P<number>\d{1,6})"                      # house number
    r"\s+"
    r"(?P<street>"
    r"(?:[NSEW]\.?\s+)?"                          # optional directional
    r"(?:[A-Z][a-zA-Z']+(?:\s+[A-Z][a-zA-Z']+)*)"  # street name words
    r")"
    r"\s+"
    r"(?P<suffix>" + _STREET_SUFFIXES + r")"     # street suffix
    r"\.?"
    r"(?:\s+(?:APT|STE|SUITE|UNIT|#)\s*\S+)?"   # optional unit
    r"\b",
    re.IGNORECASE,
)


def _detect_street_address(text: str, pii_type: str) -> list[PiiMatch]:
    from . import PiiMatch

    results: list[PiiMatch] = []
    for m in _STREET_RE.finditer(text):
        # Reject if "number" looks like a part number or dimension context.
        # Street numbers are at most 6 digits; skip anything longer
        # (already enforced by regex). Also reject if the preceding char
        # is a letter (e.g. "REV D 123" should not trigger).
        num = m.group("number")
        start = m.start()
        if start > 0 and text[start - 1].isalpha():
            continue
        # Reject very large numbers unlikely to be street addresses
        if int(num) > 99999:
            continue
        results.append(
            PiiMatch(type=pii_type, value=m.group(), start=m.start(), end=m.end())
        )
    return results


# ───────────────────────────────────────────────────────────────────
# US City / State / ZIP
# ───────────────────────────────────────────────────────────────────
_US_STATES = (
    r"AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|"
    r"MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|"
    r"SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC|PR|VI|GU|AS|MP|"
    # Full state names (common ones)
    r"Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|"
    r"Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|"
    r"Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|"
    r"Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|"
    r"New\s+Hampshire|New\s+Jersey|New\s+Mexico|New\s+York|"
    r"North\s+Carolina|North\s+Dakota|Ohio|Oklahoma|Oregon|"
    r"Pennsylvania|Rhode\s+Island|South\s+Carolina|South\s+Dakota|"
    r"Tennessee|Texas|Utah|Vermont|Virginia|Washington|"
    r"West\s+Virginia|Wisconsin|Wyoming"
)

_CITY_STATE_ZIP_RE = re.compile(
    r"\b"
    r"(?P<city>[A-Z][a-zA-Z.\-']+(?:\s+[A-Z][a-zA-Z.\-']+)*)"  # city name
    r",\s*"
    r"(?P<state>" + _US_STATES + r")"                             # state
    r"\s+"
    r"(?P<zip>\d{5}(?:-\d{4})?)"                                  # ZIP
    r"\b",
    re.IGNORECASE,
)


def _detect_city_state_zip(text: str, pii_type: str) -> list[PiiMatch]:
    from . import PiiMatch

    return [
        PiiMatch(type=pii_type, value=m.group(), start=m.start(), end=m.end())
        for m in _CITY_STATE_ZIP_RE.finditer(text)
    ]


# ───────────────────────────────────────────────────────────────────
# Social Security Number
# ───────────────────────────────────────────────────────────────────
# From Presidio UsSsnRecognizer and scrubadub SocialSecurityNumberDetector.
# Requires delimiters (dash, space, or dot) to reduce false positives
# on engineering part numbers.
_SSN_RE = re.compile(
    r"\b"
    r"(?!000|666|9\d{2})"    # area cannot be 000, 666, or 900-999
    r"(?P<area>[0-9]{3})"
    r"(?P<sep>[- .])"
    r"(?!00)"                 # group cannot be 00
    r"(?P<group>[0-9]{2})"
    r"(?P=sep)"               # same delimiter
    r"(?!0000)"               # serial cannot be 0000
    r"(?P<serial>[0-9]{4})"
    r"\b"
)


def _detect_ssn(text: str, pii_type: str) -> list[PiiMatch]:
    from . import PiiMatch

    results: list[PiiMatch] = []
    for m in _SSN_RE.finditer(text):
        digits = m.group("area") + m.group("group") + m.group("serial")
        # Reject all-same-digit
        if len(set(digits)) == 1:
            continue
        # Reject well-known invalid SSNs
        if digits in ("123456789", "987654321", "078051120"):
            continue
        results.append(
            PiiMatch(type=pii_type, value=m.group(), start=m.start(), end=m.end())
        )
    return results


# ───────────────────────────────────────────────────────────────────
# IPv4 Address
# ───────────────────────────────────────────────────────────────────
# From Presidio IpRecognizer.
_IPV4_RE = re.compile(
    r"\b"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"(?:/(?:[0-2]?\d|3[0-2]))?"   # optional CIDR
    r"\b"
)


def _detect_ipv4(text: str, pii_type: str) -> list[PiiMatch]:
    from . import PiiMatch

    results: list[PiiMatch] = []
    for m in _IPV4_RE.finditer(text):
        val = m.group()
        # Strip optional CIDR for validation
        addr = val.split("/")[0]
        octets = addr.split(".")
        # Reject 0.0.0.0 and 255.255.255.255
        nums = [int(o) for o in octets]
        if all(n == 0 for n in nums) or all(n == 255 for n in nums):
            continue
        results.append(
            PiiMatch(type=pii_type, value=val, start=m.start(), end=m.end())
        )
    return results


# ───────────────────────────────────────────────────────────────────
# Detector registry
# ───────────────────────────────────────────────────────────────────
from .phone import detect_phones  # noqa: E402

DETECTORS: dict[str, Callable[[str, str], list[PiiMatch]]] = {
    "phone": detect_phones,
    "email": _detect_email,
    "url": _detect_url,
    "street_address": _detect_street_address,
    "city_state_zip": _detect_city_state_zip,
    "ssn": _detect_ssn,
    "ipv4": _detect_ipv4,
}

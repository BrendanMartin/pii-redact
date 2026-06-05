"""Tests for pii_redact detectors.

Each detector has positive cases (should match) and negative cases
(should NOT match). Negative cases are especially important for
engineering drawing text where false positives on dimensions, part
numbers, tolerances, and rev letters are unacceptable.
"""

from __future__ import annotations

import pytest

from pii_redact import PiiMatch, scan, scan_one


# ─── Helpers ──────────────────────────────────────────────────────


def _values(matches: list[PiiMatch]) -> list[str]:
    return [m.value for m in matches]


def _has(text: str, pii_type: str, expected: str) -> None:
    matches = scan_one(text, pii_type)
    vals = _values(matches)
    assert expected in vals, f"Expected {expected!r} in {vals}"


def _not_has(text: str, pii_type: str) -> None:
    matches = scan_one(text, pii_type)
    assert matches == [], f"Expected no matches, got {_values(matches)}"


# ═══════════════════════════════════════════════════════════════════
# Phone
# ═══════════════════════════════════════════════════════════════════


class TestPhone:
    """US phone number detection."""

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("Call (561) 845-1234", "(561) 845-1234"),
            ("Call 561-845-1234", "561-845-1234"),
            ("Call 561.845.1234", "561.845.1234"),
            ("Call +1-561-845-1234", "+1-561-845-1234"),
            ("Call +1 (561) 845-1234", "+1 (561) 845-1234"),
            ("Call 1-561-845-1234", "1-561-845-1234"),
            ("ph: (212) 555-1234", "(212) 555-1234"),
            ("fax 800-555-0199", "800-555-0199"),
            ("5618451234", "5618451234"),       # fully joined 10 digits — still valid
        ],
    )
    def test_positive(self, text: str, expected: str) -> None:
        _has(text, "phone", expected)

    @pytest.mark.parametrize(
        "text",
        [
            "903490",           # part number — 6 digits
            "12345",            # 5-digit number
            "123456789",        # 9 digits no separators
            "2.500",            # dimension
            "+/- .005",         # tolerance
            "REV D",            # revision letter
            "3.250 x 1.750",   # dimensions
            "DWG 1234-5678",   # drawing number (only 8 digits)
            "650300 7562",      # part number — 6 joined digits + space + 4 (inconsistent grouping)
            "234567 8901",      # same shape, valid NPA/NXX by luck — must not match
        ],
    )
    def test_negative(self, text: str) -> None:
        _not_has(text, "phone")

    def test_multiple(self) -> None:
        text = "Call (561) 845-1234 or 212-555-1234"
        matches = scan_one(text, "phone")
        assert len(matches) == 2


# ═══════════════════════════════════════════════════════════════════
# Email
# ═══════════════════════════════════════════════════════════════════


class TestEmail:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("email joe@acme.com please", "joe@acme.com"),
            ("send to alice.bob+tag@sub.example.co.uk", "alice.bob+tag@sub.example.co.uk"),
            ("test user_name@domain.org end", "user_name@domain.org"),
            ("UPPER@CASE.COM", "UPPER@CASE.COM"),
        ],
    )
    def test_positive(self, text: str, expected: str) -> None:
        _has(text, "email", expected)

    @pytest.mark.parametrize(
        "text",
        [
            "not-an-email",
            "just@",
            "@domain.com",
            "user@.com",
            "903490",
            "REV D",
            "2.500 x 1.750",
        ],
    )
    def test_negative(self, text: str) -> None:
        _not_has(text, "email")


# ═══════════════════════════════════════════════════════════════════
# URL
# ═══════════════════════════════════════════════════════════════════


class TestUrl:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("visit https://example.com", "https://example.com"),
            ("go to http://foo.bar.com/path?q=1", "http://foo.bar.com/path?q=1"),
            ("see www.example.org/page", "www.example.org/page"),
            ("https://sub.domain.co.uk/a/b", "https://sub.domain.co.uk/a/b"),
        ],
    )
    def test_positive(self, text: str, expected: str) -> None:
        _has(text, "url", expected)

    @pytest.mark.parametrize(
        "text",
        [
            "not a url",
            "ftp://files.example.com",  # only http(s) and www
            "903490",
            "2.500",
            "file.dwg",
        ],
    )
    def test_negative(self, text: str) -> None:
        _not_has(text, "url")


# ═══════════════════════════════════════════════════════════════════
# Street Address
# ═══════════════════════════════════════════════════════════════════


class TestStreetAddress:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("ship to 123 Main St", "123 Main St"),
            ("at 4567 Elm Avenue", "4567 Elm Avenue"),
            ("addr: 89 Oak Blvd", "89 Oak Blvd"),
            ("1600 Pennsylvania Ave", "1600 Pennsylvania Ave"),
            ("742 Evergreen Terrace", "742 Evergreen Terrace"),
            ("100 N Broadway Rd", "100 N Broadway Rd"),
        ],
    )
    def test_positive(self, text: str, expected: str) -> None:
        _has(text, "street_address", expected)

    @pytest.mark.parametrize(
        "text",
        [
            "903490",                   # part number
            "REV D",                    # revision letter
            "2.500 DIA",                # dimension
            "+/- .005",                 # tolerance
            "3 HOLES EQ SP",           # drawing callout (no suffix)
            "MATERIAL: 6061-T6",       # material spec
        ],
    )
    def test_negative(self, text: str) -> None:
        _not_has(text, "street_address")


# ═══════════════════════════════════════════════════════════════════
# City / State / ZIP
# ═══════════════════════════════════════════════════════════════════


class TestCityStateZip:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("Miami, FL 33101", "Miami, FL 33101"),
            ("New York, NY 10001", "New York, NY 10001"),
            ("Los Angeles, CA 90210-1234", "Los Angeles, CA 90210-1234"),
            ("Portland, Oregon 97201", "Portland, Oregon 97201"),
        ],
    )
    def test_positive(self, text: str, expected: str) -> None:
        _has(text, "city_state_zip", expected)

    @pytest.mark.parametrize(
        "text",
        [
            "903490",
            "REV D",
            "2.500",
            "SCALE: 1/2",
            "TOLERANCE +/- .005",
            "QTY 12345",
        ],
    )
    def test_negative(self, text: str) -> None:
        _not_has(text, "city_state_zip")


# ═══════════════════════════════════════════════════════════════════
# SSN
# ═══════════════════════════════════════════════════════════════════


class TestSsn:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("ssn 219-45-6789", "219-45-6789"),
            ("ssn: 234 56 7890", "234 56 7890"),
            ("ssn 456.78.9012", "456.78.9012"),
        ],
    )
    def test_positive(self, text: str, expected: str) -> None:
        _has(text, "ssn", expected)

    @pytest.mark.parametrize(
        "text",
        [
            "903490",                # part number
            "000-12-3456",           # area 000 invalid
            "666-12-3456",           # area 666 invalid
            "900-12-3456",           # area 9XX invalid
            "123-00-4567",           # group 00 invalid
            "123-45-0000",           # serial 0000 invalid
            "123456789",             # no delimiters
            "111-11-1111",           # all same digit
            "078-05-1120",           # well-known invalid SSN
            "DWG 1234-5678",        # drawing number
            "PART# 903-49-0000",    # part number that looks like SSN but serial 0000
            "2.500",                 # dimension
            "REV D",                 # revision
            "+/- .005",              # tolerance
        ],
    )
    def test_negative(self, text: str) -> None:
        _not_has(text, "ssn")


# ═══════════════════════════════════════════════════════════════════
# IPv4
# ═══════════════════════════════════════════════════════════════════


class TestIpv4:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("server at 192.168.1.1", "192.168.1.1"),
            ("ip: 10.0.0.1", "10.0.0.1"),
            ("host 172.16.254.1", "172.16.254.1"),
            ("addr 8.8.8.8", "8.8.8.8"),
            ("cidr 10.0.0.0/24", "10.0.0.0/24"),
        ],
    )
    def test_positive(self, text: str, expected: str) -> None:
        _has(text, "ipv4", expected)

    @pytest.mark.parametrize(
        "text",
        [
            "903490",
            "2.500",             # dimension
            "1.750 x 2.500",    # dimensions
            "REV D",
            "+/- .005",
            "999.999.999.999",  # invalid octets
            "256.1.1.1",        # invalid octet
        ],
    )
    def test_negative(self, text: str) -> None:
        _not_has(text, "ipv4")


# ═══════════════════════════════════════════════════════════════════
# scan() integration
# ═══════════════════════════════════════════════════════════════════


class TestScan:
    def test_mixed(self) -> None:
        text = "Call (561) 845-1234 or email joe@acme.com, ip 10.0.0.1"
        matches = scan(text)
        types = {m.type for m in matches}
        assert "phone" in types
        assert "email" in types
        assert "ipv4" in types

    def test_positions(self) -> None:
        text = "joe@acme.com"
        matches = scan(text)
        assert len(matches) == 1
        m = matches[0]
        assert m.start == 0
        assert m.end == len(text)
        assert m.value == text

    def test_empty(self) -> None:
        assert scan("no pii here at all") == []

    def test_unknown_type(self) -> None:
        with pytest.raises(ValueError, match="Unknown PII type"):
            scan_one("text", pii_type="bogus")


# ═══════════════════════════════════════════════════════════════════
# Engineering drawing false positive safety
# ═══════════════════════════════════════════════════════════════════


class TestEngineeringDrawingSafety:
    """Ensure common engineering drawing text does not trigger PII matches."""

    @pytest.mark.parametrize(
        "text",
        [
            "903490",
            "PART NO. 903490-01",
            "DWG NO. 12345-678",
            "REV D",
            "REV. B",
            "2.500 DIA",
            "3.250 x 1.750 x 0.500",
            "+/- .005",
            "TOLERANCE: +/- 0.010",
            ".125 THRU",
            "4X .250-20 UNC",
            "MATERIAL: 6061-T6 ALUMINUM",
            "SCALE: 1:2",
            "SCALE 1/4",
            "FINISH: ANODIZE PER MIL-A-8625",
            "UNLESS OTHERWISE SPECIFIED",
            "DIMENSIONS ARE IN INCHES",
            "THIRD ANGLE PROJECTION",
            "QTY 5",
            "SHT 1 OF 3",
            "SECTION A-A",
            "DETAIL B SCALE 2:1",
            "R.125 TYP",
            "45 DEG X .030",
            "NOTE: DEBURR ALL EDGES",
        ],
    )
    def test_no_false_positives(self, text: str) -> None:
        matches = scan(text)
        assert matches == [], f"False positive on engineering text {text!r}: {_values(matches)}"

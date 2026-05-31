# pii-redact

Pure-regex PII redaction library. Zero external dependencies -- just compiled regex patterns.

## Package Structure

```
src/pii_redact/
  __init__.py       Public API: scan(), scan_one(), PiiMatch
  patterns.py       All compiled regexes and detector functions
  phone.py          US phone number regex detection (pure regex, no external libs)
tests/
  test_patterns.py  Tests for each pattern with positive and negative cases
```

## Running Tests

```bash
uv run pytest tests/ -v
```

## Design Decisions

- Zero external dependencies. All detection is pure compiled regex.
- Patterns sourced from commonregex-improved, scrubadub, and Microsoft Presidio.
- Engineering drawing text safety: negative tests for part numbers, dimensions, tolerances, rev letters.
- Phone validation uses regex heuristics instead of the phonenumbers library.

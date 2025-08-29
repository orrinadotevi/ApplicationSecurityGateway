"""
PII Redaction Utilities for LLM-ASG (Step 3)
- Detects & redacts common PII: SSN, email, phone, credit card
- Returns redacted text + hit counts by type
- Configurable via env:
    REDACTION_ENABLED=true|false
    REDACTION_KEEP_LAST4=true|false  (applies to SSN & card)
"""
from __future__ import annotations
import os, re
from dataclasses import dataclass
from typing import Dict, Tuple

# Compile regexes once for speed. Patterns are conservative to reduce false positives.
# Note: Keep patterns simple + explainable for capstone.
SSN_RE   = re.compile(r'(?i)\b(\d{3})[-\s]?(\d{2})[-\s]?(\d{4})\b')
EMAIL_RE = re.compile(r'(?i)\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b', re.IGNORECASE)
PHONE_RE = re.compile(r'(?i)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b')
CARD_RE  = re.compile(r'\b(?:\d[ -]*?){13,19}\b')  # naive card finder (Luhn not applied; keep simple)

# Env toggles
REDACTION_ENABLED   = os.getenv("REDACTION_ENABLED", "true").lower() in ("1", "true", "yes", "on")
REDACTION_KEEP_LAST4= os.getenv("REDACTION_KEEP_LAST4", "true").lower() in ("1", "true", "yes", "on")
REDACT_UPSTREAM     = os.getenv("REDACT_UPSTREAM", "true").lower() in ("1", "true", "yes", "on")

@dataclass
class RedactionResult:
    text: str
    hits: Dict[str, int]

def _mask_digits_keep_last4(s: str) -> str:
    """Mask all digits except last 4; keep separators."""
    digits = [c for c in s if c.isdigit()]
    if len(digits) <= 4:
        return '*' * len(digits)
    keep = ''.join(digits[-4:])
    masked = '*' * (len(digits) - 4) + keep
    out, i = [], 0
    for ch in s:
        if ch.isdigit():
            out.append(masked[i]); i += 1
        else:
            out.append(ch)
    return ''.join(out)

def redact_text(text: str) -> RedactionResult:
    """
    Redact PII in text. Returns redacted text + counts per type.
    If REDACTION_ENABLED is False, returns original text with zero hits.
    """
    if not REDACTION_ENABLED or not isinstance(text, str) or not text:
        return RedactionResult(text=text, hits={})

    hits = {"ssn":0, "email":0, "phone":0, "card":0}
    out = text

    # SSN
    def _ssn_sub(m):
        nonlocal hits
        hits["ssn"] += 1
        whole = m.group(0)
        return _mask_digits_keep_last4(whole) if REDACTION_KEEP_LAST4 else "***-**-****"
    out = SSN_RE.sub(_ssn_sub, out)

    # Email
    def _email_sub(m):
        nonlocal hits
        hits["email"] += 1
        local, domain = m.group(1), m.group(2)
        masked_local = local[0] + "***" if len(local) >= 2 else "***"
        return f"{masked_local}@{domain}"
    out = EMAIL_RE.sub(_email_sub, out)

    # Phone
    def _phone_sub(m):
        nonlocal hits
        hits["phone"] += 1
        whole = m.group(0)
        return _mask_digits_keep_last4(whole) if REDACTION_KEEP_LAST4 else "***-***-****"
    out = PHONE_RE.sub(_phone_sub, out)

    # Credit card (very naive)
    def _card_sub(m):
        nonlocal hits
        hits["card"] += 1
        whole = m.group(0)
        return _mask_digits_keep_last4(whole) if REDACTION_KEEP_LAST4 else "**** **** **** ****"
    out = CARD_RE.sub(_card_sub, out)

    # Remove zero entries for cleanliness
    hits = {k:v for k,v in hits.items() if v>0}
    return RedactionResult(text=out, hits=hits)

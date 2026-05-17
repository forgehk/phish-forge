"""Body and header heuristic detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .parser import ParsedEmail
from .urls import levenshtein

@dataclass(frozen=True)
class Signal:
    name: str
    weight: int
    detail: str = ""

URGENCY_PATTERNS = (
    re.compile(r"\b(within|in)\s+\d+\s+hour", re.I),
    re.compile(r"\b(immediate|urgent|asap|right away|final notice)\b", re.I),
    re.compile(r"\b(account|access)\s+(will be|has been)\s+(locked|suspended|disabled)", re.I),
    re.compile(r"\bexpir(es?|ing)\s+(today|tomorrow|soon)\b", re.I),
)

CREDENTIAL_REQUEST_PATTERNS = (
    re.compile(r"\b(verify|confirm|update)\s+your\s+(password|login|credentials|account)", re.I),
    re.compile(r"\bclick\s+here\s+to\s+(verify|confirm|update|log\s*in)", re.I),
    re.compile(r"\b(re-?enter|provide)\s+your\s+(password|login)", re.I),
)

GENERIC_GREETING_PATTERNS = (
    re.compile(r"^\s*Dear\s+(Customer|User|Sir/Madam|Sir or Madam|Account Holder|Member),", re.I | re.M),
    re.compile(r"^\s*Hello\s+(Customer|User|Valued Member),", re.I | re.M),
)

def analyze_body(email: ParsedEmail) -> list[Signal]:
    text = email.body_text or _strip_html(email.body_html)
    signals: list[Signal] = []
    for pattern in URGENCY_PATTERNS:
        m = pattern.search(text)
        if m:
            signals.append(Signal("urgency_language", 12, m.group(0)))
            break
    for pattern in CREDENTIAL_REQUEST_PATTERNS:
        m = pattern.search(text)
        if m:
            signals.append(Signal("credential_request", 15, m.group(0)))
            break
    for pattern in GENERIC_GREETING_PATTERNS:
        m = pattern.search(text)
        if m:
            signals.append(Signal("generic_greeting", 6, m.group(0).strip()))
            break
    return signals

BRANDS_TO_CHECK = ("paypal", "amazon", "google", "microsoft", "apple", "chase", "wells")

def analyze_headers(email: ParsedEmail) -> list[Signal]:
    signals: list[Signal] = []
    auth = email.authentication_results.lower()
    if "spf=fail" in auth:
        signals.append(Signal("spf_fail", 15, "Authentication-Results: spf=fail"))
    elif "spf=softfail" in auth:
        signals.append(Signal("spf_softfail", 8))
    if "dkim=fail" in auth:
        signals.append(Signal("dkim_fail", 15))
    elif "dkim=none" in auth and email.from_email:
        signals.append(Signal("dkim_none", 5))
    if "dmarc=fail" in auth:
        signals.append(Signal("dmarc_fail", 18))

    # Reply-To domain mismatch with From domain
    if email.reply_to and email.reply_to_domain and email.from_domain:
        if email.reply_to_domain != email.from_domain:
            signals.append(
                Signal(
                    "reply_to_mismatch",
                    10,
                    f"From={email.from_domain} but Reply-To={email.reply_to_domain}",
                )
            )

    # Display name impersonates a brand but envelope is something else.
    # Literal containment + fuzzy match (Levenshtein 1) catches tricks like
    # "PayPaI" (capital I) which lowercases to "paypai".
    if email.from_display and email.from_email:
        display_lower = email.from_display.lower()
        from_d = email.from_domain
        words = re.findall(r"[a-z0-9]+", display_lower)
        for brand in BRANDS_TO_CHECK:
            if brand in from_d:
                continue
            matched = brand in display_lower
            if not matched:
                for w in words:
                    if len(brand) >= 5 and abs(len(w) - len(brand)) <= 1 and levenshtein(w, brand) <= 1:
                        matched = True
                        break
            if matched:
                signals.append(
                    Signal(
                        "display_name_impersonation",
                        20,
                        f"display='{email.from_display}' but sender={email.from_email}",
                    )
                )
                break
    return signals

def _strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", " ", s or "")

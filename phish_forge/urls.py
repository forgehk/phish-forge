"""URL-level heuristic scoring.

Each detector returns a list of signals; the caller sums their weights into a
per-URL score and an overall verdict contribution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

HIGH_RISK_TLDS = {"tk", "ml", "gq", "cf", "zip", "mov", "country", "kim", "work"}

LINK_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "lnkd.in", "cutt.ly",
}

# Brands commonly impersonated. (domain, weight).
COMMON_BRANDS = (
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "instagram.com", "netflix.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "github.com", "linkedin.com", "dropbox.com", "docusign.com",
)

SUSPICIOUS_PATH_KEYWORDS = (
    "verify", "secure", "account-update", "login-reset",
    "confirm-identity", "unlock", "suspend", "billing-update",
)

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

@dataclass(frozen=True)
class UrlSignal:
    name: str
    weight: int  # contribution to URL risk score (0-100)
    detail: str = ""

def analyze_url(url: str) -> list[UrlSignal]:
    """Return a list of risk signals for `url`."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return []
    signals: list[UrlSignal] = []

    # IP in URL
    if IP_RE.match(host):
        signals.append(UrlSignal("ip_in_url", 25, f"raw IP {host}"))

    # TLD risk
    parts = host.split(".")
    tld = parts[-1] if parts else ""
    if tld in HIGH_RISK_TLDS:
        signals.append(UrlSignal("high_risk_tld", 20, f".{tld}"))

    # Link shortener
    if host in LINK_SHORTENERS:
        signals.append(UrlSignal("link_shortener", 15, host))

    # Suspicious path keywords
    path = (parsed.path or "").lower()
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in path:
            signals.append(UrlSignal("suspicious_path_keyword", 10, kw))
            break

    # Typosquat or homoglyph of a known brand
    typo = _typosquat_match(host, COMMON_BRANDS)
    if typo:
        brand, kind = typo
        signals.append(UrlSignal(kind, 30, f"resembles {brand}"))

    # Brand-in-subdomain trick: paypal.com.evil.com
    sub_match = _brand_in_subdomain(host, COMMON_BRANDS)
    if sub_match:
        signals.append(UrlSignal("brand_in_subdomain", 25, f"{sub_match} in subdomain"))

    return signals

def levenshtein(a: str, b: str) -> int:
    """Standard Wagner-Fischer Levenshtein distance."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]

def _typosquat_match(host: str, brands: tuple[str, ...]) -> tuple[str, str] | None:
    """Return (brand, signal_kind) if host looks like a brand typo, else None."""
    # Strip 'www.'
    if host.startswith("www."):
        host = host[4:]
    for brand in brands:
        if host == brand:
            return None
        # quick typosquat: same length-ish, distance 1-2
        if abs(len(host) - len(brand)) <= 2 and 0 < levenshtein(host, brand) <= 2:
            return brand, "typosquat"
        # homoglyph: same length, but contains confusables that look like the brand
        if _looks_like_homoglyph(host, brand):
            return brand, "homoglyph"
    return None

def _looks_like_homoglyph(host: str, brand: str) -> bool:
    # Replace common confusables and compare.
    confusables = str.maketrans({"l": "1", "I": "1", "0": "o", "5": "s"})
    return host.translate(confusables) == brand.translate(confusables) and host != brand

def _brand_in_subdomain(host: str, brands: tuple[str, ...]) -> str | None:
    """Detect e.g. 'paypal.com.attacker.tk' — brand appears as subdomain."""
    for brand in brands:
        if host.endswith("." + brand):
            return None  # legitimate subdomain
        # brand appears earlier in the host
        bare_brand = brand.split(".")[0]  # 'paypal' from 'paypal.com'
        labels = host.split(".")
        if bare_brand in labels[:-2]:
            return brand
    return None

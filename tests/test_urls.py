"""Tests for URL heuristics."""

from phish_forge.urls import analyze_url, levenshtein

def names(url: str) -> set[str]:
    return {s.name for s in analyze_url(url)}

def test_ip_url_flagged():
    assert "ip_in_url" in names("http://192.168.1.1/login")

def test_high_risk_tld_flagged():
    assert "high_risk_tld" in names("http://example.tk/")

def test_shortener_flagged():
    assert "link_shortener" in names("https://bit.ly/3xyZ123")

def test_typosquat_flagged():
    assert "typosquat" in names("http://paypa1.com/")

def test_visual_lookalike_flagged():
    # Capital-I homoglyph lowercases to 'paypai' which is Levenshtein-1 from
    # 'paypal', so the typosquat detector picks it up. We just want SOMETHING
    # to fire -- the verdict is "this URL looks like paypal.com but isn't."
    sigs = names("http://paypaI.com/")
    assert sigs & {"typosquat", "homoglyph"}

def test_brand_in_subdomain_flagged():
    assert "brand_in_subdomain" in names("http://paypal.com.attacker.tk/")

def test_legitimate_url_clean():
    # Stripe's real domain should produce no risk signals.
    assert analyze_url("https://dashboard.stripe.com/invoices") == []

def test_suspicious_path_keyword():
    assert "suspicious_path_keyword" in names("https://example-domain.com/verify-now")

def test_levenshtein_basic():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("abc", "abc") == 0

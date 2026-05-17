"""Tests for body and header heuristics."""

from phish_forge.heuristics import analyze_body, analyze_headers
from phish_forge.parser import parse_eml

URGENT = """From: "PayPaI" <x@evil.tk>
To: y@z.com
Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail

Dear Customer,

Your account will be locked in 24 hours. Click here to verify your password.
"""

CLEAN = """From: "Stripe" <invoices@stripe.com>
To: y@z.com
Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass

Hi Hasan,

Your April invoice is now available in your Stripe dashboard.
"""

def test_body_urgency_detected():
    e = parse_eml(URGENT)
    sigs = {s.name for s in analyze_body(e)}
    assert "urgency_language" in sigs

def test_body_credential_request_detected():
    e = parse_eml(URGENT)
    sigs = {s.name for s in analyze_body(e)}
    assert "credential_request" in sigs

def test_body_generic_greeting_detected():
    e = parse_eml(URGENT)
    sigs = {s.name for s in analyze_body(e)}
    assert "generic_greeting" in sigs

def test_clean_body_has_no_phish_signals():
    e = parse_eml(CLEAN)
    sigs = {s.name for s in analyze_body(e)}
    assert "urgency_language" not in sigs
    assert "credential_request" not in sigs
    assert "generic_greeting" not in sigs

def test_headers_spf_fail():
    e = parse_eml(URGENT)
    sigs = {s.name for s in analyze_headers(e)}
    assert "spf_fail" in sigs
    assert "dmarc_fail" in sigs

def test_headers_clean():
    e = parse_eml(CLEAN)
    sigs = {s.name for s in analyze_headers(e)}
    assert "spf_fail" not in sigs
    assert "dmarc_fail" not in sigs

def test_display_name_impersonation():
    e = parse_eml(URGENT)
    sigs = {s.name for s in analyze_headers(e)}
    assert "display_name_impersonation" in sigs

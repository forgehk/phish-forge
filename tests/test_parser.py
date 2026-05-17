"""Tests for the EML parser."""

from __future__ import annotations

from phish_forge.parser import parse_eml

SAMPLE = """From: "Alice" <alice@example.com>
Reply-To: <bob@elsewhere.com>
To: <c@x.com>
Subject: hello
Authentication-Results: mx; spf=pass smtp.mailfrom=alice@example.com
Content-Type: text/plain; charset=utf-8

Hi! Check https://example.com/page and http://attacker.tk/login.
"""

def test_parses_headers():
    p = parse_eml(SAMPLE)
    assert p.from_email == "alice@example.com"
    assert p.from_display == "Alice"
    assert p.reply_to == "bob@elsewhere.com"
    assert p.subject == "hello"

def test_extracts_urls():
    p = parse_eml(SAMPLE)
    assert "https://example.com/page" in p.urls
    assert "http://attacker.tk/login" in p.urls

def test_domains():
    p = parse_eml(SAMPLE)
    assert p.from_domain == "example.com"
    assert p.reply_to_domain == "elsewhere.com"

def test_auth_results_captured():
    p = parse_eml(SAMPLE)
    assert "spf=pass" in p.authentication_results.lower()

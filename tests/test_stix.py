"""Tests for the STIX 2.1 indicator export."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from phish_forge.cli import main
from phish_forge.scoring import analyze
from phish_forge.stix import _quote, to_stix_bundle

FIXTURES = Path(__file__).parent.parent / "fixtures"
WHEN = datetime(2026, 11, 12, 17, 30, 5, 123456, tzinfo=timezone.utc)
ID_RE = re.compile(r"^indicator--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _patterns(bundle: dict) -> list[str]:
    return [o["pattern"] for o in bundle.get("objects", [])]


def test_phishing_sample_exports_flagged_observables_only():
    bundle = to_stix_bundle(analyze(FIXTURES / "phishing_sample.eml"), created=WHEN)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert _patterns(bundle) == [
        "[url:value = 'http://paypa1.com-secure-login.tk/verify']",
        "[url:value = 'https://bit.ly/3xyZ123']",
        "[email-addr:value = 'noreply@paypa1-secure.tk']",
        "[email-addr:value = 'support-team@helpdesk.click']",
    ]
    # the legitimate https://paypal.com/legal link is not an indicator
    assert not any("paypal.com/legal" in p for p in _patterns(bundle))


def test_indicator_has_required_stix_properties():
    bundle = to_stix_bundle(analyze(FIXTURES / "phishing_sample.eml"), created=WHEN)
    for obj in bundle["objects"]:
        assert obj["type"] == "indicator"
        assert obj["spec_version"] == "2.1"
        assert ID_RE.match(obj["id"])
        assert obj["created"] == obj["modified"] == obj["valid_from"] == "2026-11-12T17:30:05.123Z"
        assert obj["pattern_type"] == "stix"
        assert obj["indicator_types"] == ["malicious-activity"]
        assert 0 <= obj["confidence"] <= 100


def test_indicator_ids_are_stable_across_runs():
    report = analyze(FIXTURES / "phishing_sample.eml")
    a = to_stix_bundle(report, created=WHEN)
    b = to_stix_bundle(report)
    assert [o["id"] for o in a["objects"]] == [o["id"] for o in b["objects"]]


def test_benign_report_gives_bundle_without_objects():
    bundle = to_stix_bundle(analyze(FIXTURES / "legitimate_sample.eml"), created=WHEN)
    assert "objects" not in bundle


def test_suspicious_verdict_uses_anomalous_activity():
    raw = """From: "Billing" <billing@example.org>
To: y@z.com
Subject: invoice

See https://bit.ly/abc and http://files.example.tk/doc
"""
    report = analyze(raw)
    assert report.verdict.value == "suspicious"
    bundle = to_stix_bundle(report, created=WHEN)
    assert {tuple(o["indicator_types"]) for o in bundle["objects"]} == {("anomalous-activity",)}
    # no header signal fired, so the sender is not reported
    assert all(p.startswith("[url:value") for p in _patterns(bundle))


def test_quote_escapes_backslash_and_quote():
    assert _quote("http://a.tk/it's") == r"'http://a.tk/it\'s'"
    assert _quote("a\\b") == r"'a\\b'"


def test_cli_stix_flag_prints_bundle(capsys):
    assert main(["analyze", str(FIXTURES / "phishing_sample.eml"), "--stix"]) == 0
    bundle = json.loads(capsys.readouterr().out)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 4

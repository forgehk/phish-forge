"""End-to-end scoring tests against fixture .eml files."""

from pathlib import Path

from phish_forge.scoring import Verdict, analyze

FIXTURES = Path(__file__).parent.parent / "fixtures"

def test_phishing_sample_flagged():
    report = analyze(FIXTURES / "phishing_sample.eml")
    assert report.verdict == Verdict.PHISHING
    assert report.score >= 50

def test_legitimate_sample_clean():
    report = analyze(FIXTURES / "legitimate_sample.eml")
    assert report.verdict == Verdict.BENIGN
    assert report.score < 25

def test_verdict_from_score():
    assert Verdict.from_score(80) == Verdict.PHISHING
    assert Verdict.from_score(30) == Verdict.SUSPICIOUS
    assert Verdict.from_score(10) == Verdict.BENIGN

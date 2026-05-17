"""Combine signals into a single verdict."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .heuristics import Signal, analyze_body, analyze_headers
from .parser import ParsedEmail, parse_eml
from .urls import UrlSignal, analyze_url

class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"

    @classmethod
    def from_score(cls, score: int) -> "Verdict":
        if score >= 50:
            return cls.PHISHING
        if score >= 25:
            return cls.SUSPICIOUS
        return cls.BENIGN

@dataclass
class UrlReport:
    url: str
    signals: list[UrlSignal] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(s.weight for s in self.signals))

@dataclass
class AnalysisReport:
    verdict: Verdict
    score: int
    header_signals: list[Signal] = field(default_factory=list)
    body_signals: list[Signal] = field(default_factory=list)
    urls: list[UrlReport] = field(default_factory=list)
    email: ParsedEmail | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "headers": [_sig_to_dict(s) for s in self.header_signals],
            "body": [_sig_to_dict(s) for s in self.body_signals],
            "urls": [
                {
                    "url": u.url,
                    "score": u.score,
                    "signals": [
                        {"name": s.name, "weight": s.weight, "detail": s.detail}
                        for s in u.signals
                    ],
                }
                for u in self.urls
            ],
            "subject": self.email.subject if self.email else "",
            "from": self.email.from_email if self.email else "",
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

def _sig_to_dict(s: Signal) -> dict[str, Any]:
    return {"name": s.name, "weight": s.weight, "detail": s.detail}

def analyze(source: str | ParsedEmail) -> AnalysisReport:
    """Score an .eml file (path or raw text) or pre-parsed ParsedEmail."""
    email = source if isinstance(source, ParsedEmail) else parse_eml(source)
    header_signals = analyze_headers(email)
    body_signals = analyze_body(email)
    url_reports = [UrlReport(u, analyze_url(u)) for u in email.urls]

    score = (
        sum(s.weight for s in header_signals)
        + sum(s.weight for s in body_signals)
        + sum(u.score for u in url_reports)
    )
    score = min(100, score)
    return AnalysisReport(
        verdict=Verdict.from_score(score),
        score=score,
        header_signals=header_signals,
        body_signals=body_signals,
        urls=url_reports,
        email=email,
    )

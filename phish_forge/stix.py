"""Export an analysis report as a STIX 2.1 bundle of indicators.

Only things the analysis actually flagged become indicators: URLs with at
least one risk signal, the From address when a header check fired, and the
Reply-To address when it points somewhere other than From. A benign report
produces an empty bundle, so piping every verdict into a TIP is safe.

Indicator ids are derived from the pattern (UUIDv5), so the same URL or
sender seen in two emails maps to the same indicator and dedups downstream.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .scoring import AnalysisReport, Verdict

# Fixed namespace for deterministic indicator ids.
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/forgehk/phish-forge")


def to_stix_bundle(report: AnalysisReport, created: datetime | None = None) -> dict[str, Any]:
    """Return a STIX 2.1 bundle (as a dict) with one indicator per flagged observable."""
    ts = _timestamp(created or datetime.now(timezone.utc))
    bundle: dict[str, Any] = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}"}
    if report.verdict == Verdict.BENIGN:
        return bundle

    indicator_type = "malicious-activity" if report.verdict == Verdict.PHISHING else "anomalous-activity"
    subject = report.email.subject if report.email else ""
    objects: list[dict[str, Any]] = []

    for u in report.urls:
        if u.score == 0:
            continue
        reasons = ", ".join(s.name for s in u.signals)
        objects.append(
            _indicator(
                pattern=f"[url:value = {_quote(u.url)}]",
                name=f"Phishing URL: {u.url}",
                description=f"Flagged by phish-forge ({reasons}) in email {subject!r}.",
                indicator_type=indicator_type,
                confidence=u.score,
                ts=ts,
            )
        )

    email = report.email
    if email and email.from_email and report.header_signals:
        reasons = ", ".join(s.name for s in report.header_signals)
        objects.append(
            _indicator(
                pattern=f"[email-addr:value = {_quote(email.from_email)}]",
                name=f"Phishing sender: {email.from_email}",
                description=f"Sender of email {subject!r}; header checks: {reasons}.",
                indicator_type=indicator_type,
                confidence=report.score,
                ts=ts,
            )
        )
    if email and email.reply_to and any(s.name == "reply_to_mismatch" for s in report.header_signals):
        objects.append(
            _indicator(
                pattern=f"[email-addr:value = {_quote(email.reply_to)}]",
                name=f"Phishing reply-to: {email.reply_to}",
                description=f"Reply-To of email {subject!r} differs from the From domain.",
                indicator_type=indicator_type,
                confidence=report.score,
                ts=ts,
            )
        )

    if objects:  # STIX 2.1: if present, "objects" must not be empty
        bundle["objects"] = objects
    return bundle


def to_stix_json(report: AnalysisReport, created: datetime | None = None) -> str:
    return json.dumps(to_stix_bundle(report, created), indent=2)


def _indicator(
    *, pattern: str, name: str, description: str, indicator_type: str, confidence: int, ts: str
) -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(NAMESPACE, pattern)}",
        "created": ts,
        "modified": ts,
        "name": name,
        "description": description,
        "indicator_types": [indicator_type],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts,
        "confidence": max(0, min(100, confidence)),
    }


def _quote(value: str) -> str:
    """Quote a STIX patterning string literal (backslash and quote are escaped)."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _timestamp(dt: datetime) -> str:
    """RFC 3339 UTC timestamp with millisecond precision, as STIX expects."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"

"""Parse a raw .eml into the fields downstream scorers need."""

from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any

@dataclass
class ParsedEmail:
    raw: str
    headers: dict[str, str]
    from_display: str
    from_email: str
    reply_to: str
    return_path: str
    subject: str
    body_text: str
    body_html: str
    urls: list[str] = field(default_factory=list)
    authentication_results: str = ""

    @property
    def from_domain(self) -> str:
        if "@" not in self.from_email:
            return ""
        return self.from_email.rsplit("@", 1)[1].lower()

    @property
    def reply_to_domain(self) -> str:
        if "@" not in self.reply_to:
            return ""
        return self.reply_to.rsplit("@", 1)[1].lower()

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

def parse_eml(source: str | Path) -> ParsedEmail:
    """Parse `source` (either a file path or raw .eml string)."""
    if isinstance(source, Path) or (isinstance(source, str) and len(source) < 4096 and Path(source).exists()):
        raw = Path(source).read_text(encoding="utf-8", errors="replace")
    else:
        raw = source  # type: ignore[assignment]
    msg: EmailMessage = email.message_from_string(raw, policy=policy.default)  # type: ignore[assignment]
    return _from_message(raw, msg)

def _from_message(raw: str, msg: EmailMessage) -> ParsedEmail:
    headers = {k.lower(): str(v) for k, v in msg.items()}
    display, addr = parseaddr(msg.get("From", ""))
    reply_to = ""
    if msg.get("Reply-To"):
        reply_to = parseaddr(msg.get("Reply-To", ""))[1]
    return_path = ""
    if msg.get("Return-Path"):
        return_path = parseaddr(msg.get("Return-Path", ""))[1]
    text = _body_part(msg, "text/plain") or ""
    html = _body_part(msg, "text/html") or ""
    urls = list(_extract_urls(text)) + list(_extract_urls(html))
    return ParsedEmail(
        raw=raw,
        headers=headers,
        from_display=display,
        from_email=addr.lower(),
        reply_to=reply_to.lower(),
        return_path=return_path.lower(),
        subject=str(msg.get("Subject", "")),
        body_text=text,
        body_html=html,
        urls=_dedup(urls),
        authentication_results=str(msg.get("Authentication-Results", "")),
    )

def _body_part(msg: EmailMessage, content_type: str) -> str | None:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == content_type and not part.is_multipart():
                try:
                    return part.get_content()
                except (LookupError, UnicodeDecodeError):
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        return payload.decode("utf-8", errors="replace")
        return None
    if msg.get_content_type() == content_type:
        try:
            return msg.get_content()
        except (LookupError, UnicodeDecodeError):
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                return payload.decode("utf-8", errors="replace")
    return None

def _extract_urls(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(").,;:!?")
        out.append(url)
    return out

def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

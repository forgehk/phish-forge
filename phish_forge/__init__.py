"""phish-forge: parse, analyze, score phishing .eml files."""

from .parser import ParsedEmail, parse_eml
from .scoring import Verdict, analyze

__version__ = "0.1.0"
__all__ = ["ParsedEmail", "parse_eml", "Verdict", "analyze"]

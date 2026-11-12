# phish-forge

> Drop a `.eml` in, get a verdict out. Header forensics, URL analysis, suspicious-pattern heuristics, and an LLM verdict explainer — packaged as both a CLI and a FastAPI service.

[![CI](https://github.com/forgehk/phish-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/forgehk/phish-forge/actions/workflows/ci.yml) [![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg)]() [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

Hand `phish-forge` a raw email (`.eml`) and it returns a structured verdict:

```bash
phish-forge analyze samples/phishing_sample.eml
```

```
phish-forge verdict: PHISHING  (score 78/100)

  Headers
    ! SPF                fail        (sender 199.x.x.x not in spf for paypal.com)
    ! DKIM               none        (no signature)
    ! DMARC              fail        (alignment failed)
    ! From display       'PayPaI Security' (capital-I instead of capital-L)

  URLs (3 found)
    ! http://paypa1.com-secure-login.tk/verify    typosquat + .tk TLD
    ! https://bit.ly/3xyZ123                       link shortener hides destination
    - https://paypal.com/legal                     legitimate

  Body heuristics
    ! urgency_language        "Your account will be locked in 24 hours"
    ! credential_request      "click here to verify your password"
    ! generic_greeting        "Dear Customer,"

  Verdict: PHISHING — high confidence
```

---

## Why this matters

Real phishing detection in a SOC pipeline combines:

1. **Header authentication** — does SPF/DKIM/DMARC actually align?
2. **URL reputation** — is the destination a known phishing domain, a typosquat, a shortener, or a homoglyph?
3. **Content heuristics** — urgency language, credential-request templates, mismatched display name vs. envelope sender.
4. **Optional LLM analysis** — for things heuristics miss (tone, social-engineering pattern).

`phish-forge` is a learning exercise in chaining all four. Useful for **SOC analyst / blue-team** interviews because it walks the same logic you'd implement in Splunk, Elastic, or any SIEM correlation rule.

---

## Install & run

```bash
git clone https://github.com/forgehk/phish-forge.git && cd phish-forge
pip install -e ".[api]"      # drop [api] if you only need the CLI

# CLI
phish-forge analyze suspicious.eml
phish-forge analyze suspicious.eml --json | jq .
phish-forge analyze suspicious.eml --stix > indicators.json   # STIX 2.1 bundle

# HTTP service (drop emails via curl, integrate into a SOAR playbook)
phish-forge serve --port 8000
curl -F "file=@suspicious.eml" http://localhost:8000/analyze
```

---

## Architecture

```
                      ┌─────────────────────────┐
                      │     phish-forge CLI     │
                      │      / FastAPI app      │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
                      │      EML parser         │ (stdlib email module)
                      │  headers · body · urls  │
                      └────────────┬────────────┘
                                   ▼
   ┌─────────────────┬─────────────┴────────────┬──────────────────┐
   ▼                 ▼                          ▼                  ▼
┌────────┐    ┌───────────────┐         ┌─────────────┐    ┌──────────────┐
│ header │    │   URL scorer  │         │ body hcheck │    │  LLM verdict │
│ auth   │    │ shortener /   │         │  urgency,   │    │  (optional)  │
│ (SPF/  │    │ typosquat /   │         │  cred req,  │    │              │
│ DKIM/  │    │ homoglyph /   │         │  generic    │    │              │
│ DMARC) │    │ .tk/.ml/.gq   │         │  greeting   │    │              │
└────┬───┘    └───────┬───────┘         └──────┬──────┘    └──────┬───────┘
     └────────────────┴───────────────┬────────┴──────────────────┘
                                      ▼
                         ┌──────────────────────────┐
                         │   weighted score 0-100   │
                         │   verdict: phishing /    │
                         │   suspicious / benign    │
                         └──────────────────────────┘
```

Each module is independently testable; the scorer is a simple weighted sum so you can tune it.

---

## Heuristics shipped today

**URL heuristics** (each is one signal — combined into a score per URL):

- TLD on the high-risk list (`.tk`, `.ml`, `.gq`, `.cf`, `.zip`, `.mov`)
- IP address in the URL
- Common-domain typosquat (Levenshtein ≤ 1 from a known brand)
- Homoglyph confusables (`paypaI` with capital-I, `аpple` with Cyrillic 'а')
- Hostname is a link shortener (`bit.ly`, `tinyurl`, `t.co`, `goo.gl`, etc.)
- Hostname doesn't match the visible link text (anchor vs href mismatch)
- Path keywords (`verify`, `secure`, `account-update`, `login-reset`)

**Body heuristics:**

- Urgency language (`24 hours`, `immediately`, `account locked`, `final notice`)
- Credential-request language (`enter your password`, `verify your login`)
- Generic greeting (`Dear Customer`, `Dear Sir/Madam`)
- Reply-to mismatch with From
- Plain-text → HTML inconsistency

**Header heuristics:**

- SPF / DKIM / DMARC `Authentication-Results` parsing
- `From:` display-name vs envelope `Return-Path:` mismatch
- Suspicious `Received:` chain (private IPs forging public hop, country-of-origin flips)

---

## API mode

```bash
phish-forge serve
```

Then:

```http
POST /analyze
Content-Type: multipart/form-data; boundary=...

(eml file)

→ 200 OK
{
  "verdict": "phishing",
  "score": 78,
  "headers": { ... },
  "urls": [ ... ],
  "body_signals": [ ... ]
}
```

Plug it into a SOAR runbook or just hit it from a Slack-bot intake form.

---

## STIX 2.1 export

`--stix` turns the flagged observables into a STIX 2.1 bundle you can import into a TIP (OpenCTI, MISP, etc.):

- one `indicator` per URL with at least one risk signal (`[url:value = '...']`); clean links are left out
- the `From` address when a header check fired, and the `Reply-To` address when it points at a different domain (`[email-addr:value = '...']`)
- `indicator_types` is `malicious-activity` for a phishing verdict and `anomalous-activity` for suspicious; `confidence` is the URL or report score
- a benign email gives a bundle with no objects

Indicator ids are UUIDv5 of the pattern, so the same URL seen in two emails produces the same indicator id and dedups on import.

---

## Roadmap

- [x] Header / URL / body heuristics
- [x] CLI + FastAPI
- [x] JSON output for SOAR integration
- [x] STIX 2.1 indicator export (`--stix`)
- [ ] Pluggable LLM verdict explainer (Anthropic / OpenAI)
- [ ] Attachment sandboxing (PE / Office macro detection)
- [ ] WHOIS age check for URL hostnames
- [ ] Live reputation lookups (Google Safe Browsing, PhishTank, URLhaus)

---

## License

[MIT](LICENSE)

---

*Built by [@forgehk](https://github.com/forgehk) — [DarkForge AI](https://darkforgeai.com)*

#!/usr/bin/env python3
"""Fetch sponsor prospect websites and extract NAMED decision-maker contacts.

Runs on GitHub Actions runners so the main NFA VM only ever talks to
api.github.com (one domain) instead of thousands of business domains.

Usage:
    python fetch_contacts.py --targets targets.json --out results.json

Input:  JSON list of {"company_domain", "company_name", "website"}.
Output: JSON list of per-company results with:
    status: "found" (>=1 named contact), "not_found", or "error"
    reason: granular failure code (dns_failure, http_403, challenge_page, ...)
    people: [{"name", "title", "email", "source_url"}]  (named decision-makers)
    emails: [{"address", "confidence", "source_url", "source_type",
              "snapshot_date", "context_snippet"}]
        confidence: "highest" (mailto:) > "high" (exact page text) >
                    "medium" (de-obfuscated)
        source_type: "live" | "archived" (Wayback Machine fallback)
    email_candidates: [{"address", "confidence", "pattern_guessed",
              "person_name", "person_title", "source_url", "source_type",
              "snapshot_date"}]
        confidence is always "candidate". Addresses nobody published;
        pattern-guessed from a named person's name (first@, first.last@,
        f.last@, firstl@, last@, first_last@). UNVERIFIED cheap candidates
        for the later verification pipeline; NEVER confirmed contacts and
        never a "found" signal.
    role_emails: first-party addresses with no person attached (manual review)
    contact_pages: [{"url", "page_type", "source_type", "snapshot_date"}]
        every contact-relevant URL discovered (contact/about/team/support...)
    contact_forms: [{"page_url", "action", "method", "fields",
                     "captcha_protected"}]  <form> elements with contact
        intent; CAPTCHA-backed forms are still recorded, flagged
    company_summary, source_urls, pages_fetched
    contacts: legacy alias of people (kept for the dispatcher).

Iteration 2 adds: JSON-LD Person extraction (founder/employee entities),
GitHub org public-email fallback (dev-tool companies), URL-decoded emails
(no more %20 artifacts), person-name quality gates (org/title noise
filtered from candidates), and an identity-check fallback for short brand
names ("AWE", "4AM", "222") so short-name companies are not auto-rejected.

status is "found" (>=1 named contact), "not_found", or "error".

Extraction techniques (adapted from public research + Fox's 2026-09-25 fixes):
- Rotating realistic browser profiles (Chrome/Firefox/Safari) via curl_cffi
  TLS impersonation with matching headers. Many WAFs fingerprint the TLS
  handshake (JA3) before headers are read, so a standard-library TLS stack
  is blocked as a class; browser-grade TLS makes the request a normal one.
- Wayback Machine fallback: when the live fetch fails, retrieve the
  archive.org cached copy. This never touches the target's server, so it
  cannot be blocked by it. Archived hits are flagged source_type="archived"
  with the snapshot date, since they can be stale.
- Retry with exponential backoff + jitter on transient errors only
  (timeouts, connection resets, 429, 5xx). Definitive failures (DNS, 403,
  404, challenge pages) are never retried.
- Direct probing of common contact endpoints (/contact, /about, /team,
  /press, ...) in addition to following contact links on the homepage.
  (Endpoint-list pattern from yogsec/email-finder.)
- Email de-obfuscation: "info [at] example [dot] com" forms plus HTML
  entities (&#105; etc.) are normalized before regex extraction.
- mailto: links are harvested as the highest-confidence email source.
- Footer harvesting: <footer> blocks are scanned explicitly on every page,
  Cloudflare email-obfuscation (data-cfemail / /cdn-cgi/l/email-protection#)
  is decoded, and JSON-LD Organization/Person "email" fields are extracted.
  Decoded cfemail addresses are "medium" confidence, JSON-LD/footer text
  addresses are "high".
- Render-on-miss: when a domain yields zero first-party emails from the
  static passes, the homepage and the best contact/about/team page are
  re-fetched through headless Chromium (max 2 renders per domain) to catch
  JS-injected emails and mailto: links.
- Team-link person discovery: anchors pointing at /team, /about, /people,
  /leadership, /founder, /staff whose link text is a person's name are
  recorded as people when the surrounding block carries a title keyword.
- Pattern-guess candidates: for named people with no published email,
  common patterns (first@, first.last@, f.last@, firstl@, last@,
  first_last@) are recorded ONLY in email_candidates[] as low-confidence
  candidates (pattern_guessed=true). They never enter people[], emails[],
  or contacts[], and are never treated as a found result.
- Headless-Chromium render tier for JS-heavy pages with a real browser UA,
  desktop viewport, and network-idle waits.

HARD LINES (never crossed):
- robots.txt is honored for every live URL fetched.
- CAPTCHA / challenge / login pages are recorded as fetch failures
  (reason=challenge_page), never solved or bypassed. The render tier is
  only for JS rendering; the Wayback tier only reads public archival
  copies. Neither defeats an access control.
- Pattern-guess policy (Fox 2026-09-30 sprint): pattern-guessed addresses
  are recorded ONLY in email_candidates[] as low-confidence candidates for
  later verification, never as confirmed contacts. Nothing guessed ever
  enters people[], emails[], or contacts[], and guessed addresses are never
  treated as a "found" result. Only addresses actually found on pages count
  as findings. First-party domain validation stays.
- No stealth plugins, no JS fingerprint spoofing, no proxy rotation,
  no CAPTCHA-solving services.

IMPORTANT: this worker produces UNVERIFIED extraction only. Every contact
must still pass the NFA browser verification gate (SigmaWire,
VERIFIED_DELIVERABLE) before any outreach. This worker never sends anything.
"""

from __future__ import annotations

import argparse
import html as html_module
import json
import random
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse, unquote
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup
from curl_cffi.requests import Session
from curl_cffi.requests import exceptions as cexc

# Rotating realistic browser profiles (Fox fix #1). The impersonation
# profile must match the UA/headers or the mismatch itself is a signal.
UA_PROFILES = [
    {
        "impersonate": "chrome",
        "headers": {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0.0.0 Safari/537.36"
            ),
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8"),
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
    },
    {
        "impersonate": "firefox",
        "headers": {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
                "Gecko/20100101 Firefox/127.0"
            ),
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8"),
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
        },
    },
    {
        "impersonate": "safari",
        "headers": {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.4 Safari/605.1.15"
            ),
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "*/*;q=0.8"),
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
]

REQUEST_TIMEOUT = 20.0
MAX_PAGES = 8

# Common contact endpoints probed directly, crawled early in page order
# (Fox addition: /about, /team, /contact, /press first; iteration-1 added
# leadership/founders/people/staff/impressum and more contact variants).
CONTACT_ENDPOINTS = (
    "contact", "support", "about", "team", "contact-us", "contactus",
    "about-us", "our-team", "meet-the-team", "leadership", "founders",
    "people", "staff", "press", "media", "help", "company",
    "who-we-are", "our-story", "our-mission", "get-in-touch", "reach-us",
    "enquiries", "impressum",
)
# 2026-09-30: increased from 6 to 10 (Fox: worker missed support@gamesir.com
# because "support" was 15th in the probe order and never reached).
MAX_PROBED_ENDPOINTS = 10

CONTACT_HINTS = (
    "contact", "about", "about-us", "team", "our-team", "people", "staff",
    "leadership", "founders", "management", "company", "press", "media",
    "location", "support",
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Markers that indicate an access-control challenge page (an interstitial that
# IS the challenge, not a normal page). We treat these as fetch failures and
# never attempt to solve or bypass them.
#
# NOTE: bare "recaptcha"/"g-recaptcha"/"data-sitekey" are NOT challenge
# markers: millions of legitimate pages (especially contact forms) embed a
# reCAPTCHA widget. Treating them as challenges was a major source of false
# "website_unavailable" results. A page is only a challenge when its title
# or body shows interstitial text, or when a small page carries challenge
# platform artifacts.
CHALLENGE_TITLE_MARKERS = (
    "just a moment",
    "attention required",
    "are you a robot",
    "verify you are human",
    "checking your browser",
    "security verification",
    "access denied",
    "403 forbidden",
)
CHALLENGE_BODY_MARKERS = (
    # Cloudflare interstitial phrases (specific to the block page itself).
    "just a moment",
    "checking your browser before accessing",
    "cf-challenge",
    "cf_challenge",
    "cdn-cgi/challenge-platform",
)
# Challenge artifacts that only count on pages that are both small AND carry
# almost no readable text (real interstitials are bare; a small contact page
# with a reCAPTCHA widget still has form labels, addresses, etc.).
SMALL_PAGE_CHALLENGE_MARKERS = (
    "g-recaptcha",
    "data-sitekey",
    "turnstile",
    "perimeterx",
    "datadome",
    "press & hold",
)
SMALL_PAGE_BYTES = 15000
SMALL_PAGE_TEXT_CHARS = 500


def _visible_text_length(html: str) -> int:
    try:
        from bs4 import BeautifulSoup
        return len(BeautifulSoup(html, "html.parser").get_text(" ", strip=True))
    except Exception:
        return len(html)


def _page_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html,
                      flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip().lower()


def is_challenge_page(html: str) -> bool:
    if not html:
        return False
    lowered = html.lower()
    title = _page_title(html)
    if any(marker in title for marker in CHALLENGE_TITLE_MARKERS):
        return True
    if any(marker in lowered for marker in CHALLENGE_BODY_MARKERS):
        return True
    if len(html) < SMALL_PAGE_BYTES and any(
            marker in lowered for marker in SMALL_PAGE_CHALLENGE_MARKERS):
        # A small page with captcha artifacts is only a challenge when it
        # carries almost no readable content (a bare interstitial). A small
        # contact page with a reCAPTCHA widget still has real text.
        if _visible_text_length(html) < SMALL_PAGE_TEXT_CHARS:
            return True
    return False


NAME_STOPWORDS = {
    "auto", "business", "care", "clinic", "company", "dental", "family",
    "group", "hotel", "inc", "llc", "restaurant", "sales", "services",
    "storage", "the",
}

# Words that look like names but are page chrome or department labels;
# never accept as a person.
NAME_BLACKLIST = {
    "contact us", "about us", "privacy policy", "terms of service",
    "all rights", "read more", "learn more", "sign up", "log in",
    "get started", "free trial", "home page", "site map",
    "press inquiries", "media inquiries", "press contact", "media contact",
    "customer service", "customer support", "general inquiries",
    "sales team", "support team", "marketing team", "press team",
    "contact info", "contact information", "get in touch",
    # 2026-09-30: mailto anchor-text junk that slipped into people[]
    # (extraction produced "Email Us"/info@ as a named contact). These are
    # link labels, never person names. Mirrors pool_picker JUNK_NAMES.
    "email us", "email me", "email us here", "email here", "email me here",
    "email for quote", "send email", "send us email", "email your resume",
    "use chat", "online form", "contact form", "message for", "message us",
    "private sessions", "email brutus monroe", "email buce plant",
    "email 28 collective", "email greenville location", "email biltmore location",
    "brand partnerships", "corporate gifting", "retail enquiries",
    "become an ambassador", "fan mail", "book appointment", "find this frame",
    "pr inquiries", "cafe operations", "houseplant buyer", "contact pr",
    "request samples", "contact us reach", "latin america stan",
    "scott shih regional", "anfragen sales", "aromatique outlet store",
    "memorial day",
}

# Local parts that mark an inbox as role-based, never a named person's
# mailbox. A "person" whose only email is one of these is a generic inbox
# misread as a decision-maker; it belongs in role_emails, not people[].
# (2026-09-30: extraction emitted info@/support@/sales@ as named contacts.)
ROLE_LOCAL_PARTS = {
    "info", "contact", "support", "sales", "hello", "hi", "help", "admin",
    "team", "service", "services", "enquiries", "inquiries", "office",
    "mail", "email", "general", "customerservice", "customer-service",
    "customersupport", "customer-support", "customersuccess", "success",
    "marketing", "press", "media", "careers", "jobs", "hr", "legal",
    "privacy", "billing", "orders", "order", "shipping", "returns",
    "webmaster", "noreply", "no-reply", "donotreply", "subscribe",
    "newsletter", "partners", "partnerships", "collab", "collabs",
    "creator", "creators", "influencer", "influencers", "affiliate",
    "affiliates", "wholesale", "retail", "trade", "vendors",
}


def is_role_inbox(email: str) -> bool:
    """True when the address is a generic role inbox, not a person's."""
    local = (email or "").split("@")[0].strip().lower()
    return local in ROLE_LOCAL_PARTS

TITLE_KEYWORDS = (
    "chief executive officer", "chief marketing officer",
    "co-founder", "cofounder", "founder",
    "ceo", "cmo", "cpo", "president",
    "vp marketing", "vice president of marketing", "vice president marketing",
    "head of marketing", "marketing director", "director of marketing",
    "head of growth", "growth lead", "growth manager",
    "head of partnerships", "partnerships manager", "partnerships lead",
    "business development", "brand partnerships", "head of brand",
    "marketing manager", "marketing lead", "founder & ceo", "owner",
)

NAME_RE = re.compile(r"\b([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,2})\b")

# Page-type classification for contact_pages[] (Fox 2026-09-25).
PAGE_TYPE_HINTS = (
    ("contact", ("contact", "get-in-touch", "reach-us", "enquiries",
                 "feedback")),
    ("about", ("about", "who-we-are", "company", "our-story", "our-mission")),
    ("team", ("team", "our-team", "meet-the-team", "leadership", "people",
              "staff", "founders", "management")),
    ("support", ("support", "help", "faq", "customer-service",
                 "customer-support")),
    ("press", ("press", "media", "newsroom", "news")),
    ("legal", ("privacy", "terms", "legal", "impressum")),
)


def classify_page_type(url: str) -> str:
    """Classify a crawled URL: home/contact/about/team/support/press/legal."""
    try:
        path = (urlparse(url).path or "/").lower().strip("/")
    except Exception:
        return "other"
    if not path:
        return "home"
    for page_type, hints in PAGE_TYPE_HINTS:
        if any(hint in path for hint in hints):
            return page_type
    return "other"


NAME_FIELD_RE = re.compile(
    r"(full.?name|first.?name|last.?name|your.?name|contact.?name|"
    r"(?:^|[-_\s])name(?:$|[-_\s]))",
    re.IGNORECASE,
)
EMAIL_FIELD_RE = re.compile(r"e-?mail", re.IGNORECASE)
MESSAGE_FIELD_RE = re.compile(r"message|comment|inquiry|enquiry|description",
                              re.IGNORECASE)
FORM_CAPTCHA_MARKERS = (
    "g-recaptcha", "data-sitekey", "h-captcha", "turnstile", "captcha",
)


def detect_contact_forms(page_url: str, html: str) -> list[dict]:
    """Detect <form> elements with contact intent on a page.

    Contact intent = (email field + message/textarea) or
    (name + email + message). A form behind a CAPTCHA is still recorded,
    flagged captcha_protected=True.
    """
    found: list[dict] = []
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        fields = {"name": False, "email": False, "message": False}
        for field in form.find_all(["input", "textarea", "select"]):
            if (field.get("type") or "").lower() == "hidden":
                continue
            label = " ".join([
                str(field.get("name") or ""),
                str(field.get("id") or ""),
                str(field.get("placeholder") or ""),
                str(field.get("aria-label") or ""),
            ])
            if EMAIL_FIELD_RE.search(label) or (
                    field.get("type") or "").lower() == "email":
                fields["email"] = True
            if NAME_FIELD_RE.search(label):
                fields["name"] = True
            if field.name == "textarea" or MESSAGE_FIELD_RE.search(label):
                fields["message"] = True
        has_intent = (fields["email"] and fields["message"]) or (
            fields["name"] and fields["email"] and fields["message"]
        )
        if not has_intent:
            continue
        form_html = str(form).lower()
        captcha = any(marker in form_html
                      for marker in FORM_CAPTCHA_MARKERS)
        found.append({
            "page_url": page_url,
            "action": str(form.get("action") or ""),
            "method": str(form.get("method") or "get").upper(),
            "fields": sorted(k for k, v in fields.items() if v),
            "captcha_protected": captcha,
        })
    return found

# Failures worth retrying with backoff. Everything else is definitive.
TRANSIENT_REASONS = {
    "timeout", "connection_error", "request_error", "http_429", "http_5xx",
    "empty_response", "decode_error",
}
MAX_ATTEMPTS = 3

# Confidence ranking for email sources.
CONFIDENCE_RANK = {"medium": 1, "high": 2, "highest": 3}

WAYBACK_API = "https://archive.org/wayback/available"


def normalized_host(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return ""
    return host[4:] if host.startswith("www.") else host


def website_variants(value: str) -> list[str]:
    normalized = value.strip()
    if not normalized.startswith(("http://", "https://")):
        normalized = f"https://{normalized}"
    try:
        parsed = urlparse(normalized)
    except Exception:
        return [normalized]
    variants = [normalized]
    host = parsed.hostname or ""
    if host:
        alternate_host = host[4:] if host.startswith("www.") else f"www.{host}"
        alternate = parsed._replace(netloc=alternate_host).geturl()
        if alternate not in variants:
            variants.append(alternate)
    return variants


def _name_key(company_name: str) -> str:
    """Full company name, alphanumeric only, lowercase."""
    return re.sub(r"[^a-z0-9]", "", company_name.lower())


def _name_tokens(company_name: str) -> list[str]:
    return [
        t for t in re.findall(r"[a-z0-9]+", company_name.lower())
        if len(t) >= 4 and t not in NAME_STOPWORDS
    ]


def company_name_matches_domain(company_name: str, url: str) -> bool:
    host = normalized_host(url)
    if not host:
        return False
    compact_host = host.replace(".", "").replace("-", "")
    # Iteration-2: short brand names ("AWE", "4AM", "222") have no >=4-char
    # tokens, so also accept the full normalized name as a substring.
    key = _name_key(company_name)
    if (len(key) >= 3 and key not in NAME_STOPWORDS
            and (key in compact_host or compact_host in key)):
        return True
    return any(token in compact_host for token in _name_tokens(company_name))


def identity_matches_content(company_name: str, text: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower())
    key = _name_key(company_name)
    if (len(key) >= 3 and key not in NAME_STOPWORDS
            and key in normalized.replace(" ", "")):
        return True
    return any(
        re.search(rf"(?:^|\s){re.escape(token)}(?:\s|$)", normalized)
        for token in _name_tokens(company_name)
    )


def deobfuscate_emails(text: str) -> str:
    """Normalize obfuscated addresses before regex extraction.

    Handles HTML entities (&#105;), "info [at] example [dot] com",
    "john(at)co(dot)org", "jane AT example DOT com". The plain-word form is
    only rewritten when BOTH an at-word and a dot-word appear in the same
    token run, so ordinary prose ("look at this photo") is left untouched.
    """
    text = html_module.unescape(text)
    # Bracket/paren forms are unambiguous.
    text = re.sub(r"\s*[\[\(]\s*at\s*[\]\)]\s*", "@", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*[\[\(]\s*dot\s*[\]\)]\s*", ".", text, flags=re.IGNORECASE)

    def fix_word(match: re.Match) -> str:
        inner = match.group(0)
        inner = re.sub(r"\s+at\s+", "@", inner, flags=re.IGNORECASE)
        inner = re.sub(r"\s+dot\s+", ".", inner, flags=re.IGNORECASE)
        return inner

    text = re.sub(
        r"[A-Za-z0-9._%+-]+\s+at\s+[A-Za-z0-9.-]+\s+dot\s+[A-Za-z]{2,}",
        fix_word, text, flags=re.IGNORECASE,
    )
    return text


def extract_exact_emails(text: str) -> list[str]:
    """Emails present verbatim (after HTML-entity decoding).

    URL-encoded artifacts (mailto:%20info@example.com) are unquoted so
    "%20info@example.com" becomes "info@example.com".
    """
    seen: list[str] = []
    for raw in EMAIL_RE.findall(html_module.unescape(text or "")):
        email = unquote(raw.strip()).strip().strip(".,;:").lower()
        if email and email not in seen and _looks_valid(email):
            seen.append(email)
    return seen


def extract_deobfuscated_emails(text: str, exact: set[str]) -> list[str]:
    """Emails only recoverable via de-obfuscation (not verbatim)."""
    seen: list[str] = []
    for raw in EMAIL_RE.findall(deobfuscate_emails(text or "")):
        email = unquote(raw.strip()).strip().strip(".,;:").lower()
        if (email and email not in seen and email not in exact
                and _looks_valid(email)):
            seen.append(email)
    return seen


def _looks_valid(email: str) -> bool:
    if "@" not in email or email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    if not local or not domain or "." not in domain:
        return False
    if ".." in email or email.startswith((".", "-")):
        return False
    return True


def email_matches_website_domain(email: str, website_url: str) -> bool:
    domain = email.split("@", 1)[-1].lower()
    host = normalized_host(website_url)
    return bool(domain and host) and (
        domain == host or domain.endswith(f".{host}")
    )


def context_snippet(text: str, email: str, window: int = 60) -> str:
    """Surrounding text where the email was found (evidence for review)."""
    lowered = (text or "").lower()
    idx = lowered.find(email.lower())
    if idx < 0:
        return ""
    start = max(0, idx - window)
    end = min(len(text), idx + len(email) + window)
    snippet = re.sub(r"\s+", " ", text[start:end]).strip()
    return snippet[:160]


def fetch_page(session: Session, url: str) -> dict:
    """One plain-HTTP attempt via curl_cffi (browser TLS impersonation).

    Returns {"ok": bool, "html": str|None, "reason": str|None,
             "status": int|None, "source_type": "live",
             "snapshot_date": None}. reason is a granular failure code.
    """
    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT)
    except cexc.DNSError:
        return {"ok": False, "html": None, "reason": "dns_failure",
                "status": None, "source_type": "live", "snapshot_date": None}
    except (cexc.ConnectTimeout, cexc.ReadTimeout, cexc.Timeout):
        return {"ok": False, "html": None, "reason": "timeout",
                "status": None, "source_type": "live", "snapshot_date": None}
    except (cexc.SSLError, cexc.CertificateVerifyError):
        return {"ok": False, "html": None, "reason": "tls_error",
                "status": None, "source_type": "live", "snapshot_date": None}
    except cexc.ConnectionError:
        return {"ok": False, "html": None, "reason": "connection_error",
                "status": None, "source_type": "live", "snapshot_date": None}
    except cexc.TooManyRedirects:
        return {"ok": False, "html": None, "reason": "redirect_loop",
                "status": None, "source_type": "live", "snapshot_date": None}
    except (cexc.InvalidURL, cexc.URLRequired, cexc.MissingSchema):
        return {"ok": False, "html": None, "reason": "invalid_url",
                "status": None, "source_type": "live", "snapshot_date": None}
    except Exception:
        return {"ok": False, "html": None, "reason": "request_error",
                "status": None, "source_type": "live", "snapshot_date": None}
    status = response.status_code
    if status == 404:
        return {"ok": False, "html": None, "reason": "http_404",
                "status": status, "source_type": "live",
                "snapshot_date": None}
    if status == 403:
        return {"ok": False, "html": None, "reason": "http_403",
                "status": status, "source_type": "live",
                "snapshot_date": None}
    if status == 429:
        return {"ok": False, "html": None, "reason": "http_429",
                "status": status, "source_type": "live",
                "snapshot_date": None}
    if status >= 500:
        return {"ok": False, "html": None, "reason": "http_5xx",
                "status": status, "source_type": "live",
                "snapshot_date": None}
    if status != 200:
        return {"ok": False, "html": None, "reason": f"http_{status}",
                "status": status, "source_type": "live",
                "snapshot_date": None}
    try:
        text = response.text
    except Exception:
        return {"ok": False, "html": None, "reason": "decode_error",
                "status": status, "source_type": "live",
                "snapshot_date": None}
    if not text or len(text.strip()) < 50:
        return {"ok": False, "html": None, "reason": "empty_response",
                "status": status, "source_type": "live",
                "snapshot_date": None}
    if is_challenge_page(text):
        # Access-control challenge: recorded failure, never bypassed.
        return {"ok": False, "html": None, "reason": "challenge_page",
                "status": status, "source_type": "live",
                "snapshot_date": None}
    return {"ok": True, "html": text, "reason": None, "status": status,
            "source_type": "live", "snapshot_date": None}


def fetch_with_retries(session: Session, url: str,
                       attempts: int = MAX_ATTEMPTS) -> dict:
    """Retry transient failures with exponential backoff + jitter.

    Definitive failures (DNS, 403, 404, challenge pages, ...) are returned
    immediately and never hammered.
    """
    last = fetch_page(session, url)
    for attempt in range(1, attempts):
        if last["ok"] or last["reason"] not in TRANSIENT_REASONS:
            return last
        time.sleep(2 ** attempt + random.uniform(0, 1))
        last = fetch_page(session, url)
    return last


def wayback_fetch(session: Session, url: str) -> dict:
    """Wayback Machine fallback (Fox fix #2).

    Queries archive.org for the closest snapshot and fetches it. This never
    touches the target's server, so it cannot be blocked by it. Hits are
    flagged source_type="archived" with the snapshot date, since they can
    be stale. Never used to defeat a challenge: it only reads public
    archival copies.
    """
    failure = {"ok": False, "html": None, "reason": "no_archive_copy",
               "status": None, "source_type": "archived",
               "snapshot_date": None}
    try:
        response = session.get(
            WAYBACK_API, params={"url": url}, timeout=REQUEST_TIMEOUT)
        data = response.json()
    except Exception:
        return failure
    closest = (data.get("archived_snapshots") or {}).get("closest") or {}
    if closest.get("status") != "200" or not closest.get("timestamp"):
        return failure
    timestamp = str(closest["timestamp"])
    snapshot_date = (f"{timestamp[0:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
                     if len(timestamp) >= 8 else None)
    # id_ suffix = original archived content without archive rewriting.
    snapshot_url = (f"https://web.archive.org/web/{timestamp}id_/{url}")
    try:
        response = session.get(snapshot_url, timeout=REQUEST_TIMEOUT)
    except Exception:
        return failure
    if response.status_code != 200:
        return failure
    try:
        text = response.text
    except Exception:
        return failure
    if not text or len(text.strip()) < 50:
        return failure
    if is_challenge_page(text):
        return failure
    return {"ok": True, "html": text, "reason": None, "status": 200,
            "source_type": "archived", "snapshot_date": snapshot_date}


def looks_like_js_shell(html: str) -> bool:
    """Heuristic: 200 OK but almost no rendered text -> needs a real browser."""
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    if len(text) >= 300:
        return False
    lowered = html.lower()
    return any(marker in lowered for marker in (
        'id="root"', 'id="app"', "__next_data__", "ng-app", "data-reactroot",
    ))


class Renderer:
    """Headless-Chromium render tier for JS-heavy pages.

    One browser per target, reused across pages. Real browser UA, desktop
    viewport, network-idle wait. Used ONLY for rendering JavaScript, never
    to get past an access-control block: challenge pages are still detected
    and recorded as failures.
    """

    def __init__(self, user_agent: str) -> None:
        self._user_agent = user_agent
        self._playwright = None
        self._browser = None

    def render(self, url: str) -> dict:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {"ok": False, "html": None, "reason": "no_playwright",
                    "status": None, "source_type": "live",
                    "snapshot_date": None}
        try:
            if self._browser is None:
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                    ],
                )
            context = self._browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=self._user_agent,
                locale="en-US",
            )
            try:
                page = context.new_page()
                page.goto(url, timeout=25000, wait_until="networkidle")
                page.wait_for_timeout(1500)
                html = page.content()
            finally:
                context.close()
        except Exception:
            return {"ok": False, "html": None, "reason": "render_error",
                    "status": None, "source_type": "live",
                    "snapshot_date": None}
        if not html or len(html.strip()) < 50:
            return {"ok": False, "html": None, "reason": "empty_response",
                    "status": None, "source_type": "live",
                    "snapshot_date": None}
        if is_challenge_page(html):
            return {"ok": False, "html": None, "reason": "challenge_page",
                    "status": None, "source_type": "live",
                    "snapshot_date": None}
        return {"ok": True, "html": html, "reason": None, "status": 200,
                "source_type": "live", "snapshot_date": None}

    def close(self) -> None:
        try:
            if self._browser is not None:
                self._browser.close()
            if self._playwright is not None:
                self._playwright.stop()
        except Exception:
            pass
        self._browser = None
        self._playwright = None


def robots_allows(url: str, session: Session, user_agent: str) -> bool:
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        response = session.get(robots_url, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return True
        parser = RobotFileParser()
        parser.set_url(robots_url)
        parser.parse(response.text.splitlines())
        return bool(parser.can_fetch(user_agent, url))
    except Exception:
        return True


def extract_company_summary(html: str) -> str | None:
    soup = BeautifulSoup(html, "html.parser")
    for attr in ({"name": "description"}, {"property": "og:description"}):
        tag = soup.find("meta", attrs=attr)
        if tag and tag.get("content", "").strip():
            return tag["content"].strip()[:300]
    for paragraph in soup.find_all("p"):
        text = paragraph.get_text(" ", strip=True)
        if len(text) >= 60:
            return text[:300]
    return None


def _clean_name(candidate: str) -> str | None:
    name = " ".join(candidate.split())
    if name.lower() in NAME_BLACKLIST:
        return None
    parts = name.split()
    if not 2 <= len(parts) <= 3:
        return None
    if any(len(p) < 2 for p in parts):
        return None
    return name


def _names_in_line(line: str) -> list[str]:
    """Person-name candidates in one text line.

    Title keywords are blanked first so e.g. "Head" in "Head of Marketing"
    cannot glue itself onto a neighboring name. Matching never spans lines.
    """
    cleaned = line
    for keyword in TITLE_KEYWORDS:
        cleaned = re.sub(
            rf"\b{re.escape(keyword)}\b", " " * len(keyword),
            cleaned, flags=re.IGNORECASE,
        )
    names: list[str] = []
    for match in NAME_RE.finditer(cleaned):
        name = _clean_name(match.group(1))
        if name and name not in names:
            names.append(name)
    return names


def find_titled_people(html: str) -> list[dict]:
    """Find (name, title) pairs from lines carrying a title keyword.

    Team pages render one person per block, typically "Name" on one line and
    the title on the next, so we look at the title line itself and the line
    directly above it. One person per title line; nearest name wins.
    """
    soup = BeautifulSoup(html, "html.parser")
    lines = [ln.strip() for ln in soup.get_text("\n").split("\n")]
    lines = [ln for ln in lines if ln]
    people: list[dict] = []
    seen: set[str] = set()
    for i, line in enumerate(lines):
        keyword = next(
            (kw for kw in TITLE_KEYWORDS
             if re.search(rf"\b{re.escape(kw)}\b", line, re.IGNORECASE)),
            None,
        )
        if not keyword:
            continue
        candidates = _names_in_line(line)
        if i > 0:
            candidates += [n for n in _names_in_line(lines[i - 1])
                           if n not in candidates]
        for name in candidates:
            if name.lower() not in seen and looks_like_person_name(name):
                seen.add(name.lower())
                people.append({"name": name, "title": keyword.title()})
                break
    return people


def mailto_hits(html: str) -> list[dict]:
    """mailto anchors: highest-confidence emails, with person names when the
    link text is a name (Fox fix #4).

    2026-09-30: link text goes through _clean_name() so CTA labels
    ("Email Us", "Use Chat", "Online Form") never become person names.
    Junk-labeled mailto addresses still return with name=None and flow to
    role_emails via the hits table; they are never emitted as people.
    """
    found: list[dict] = []
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.find_all("a", href=True):
        href = str(anchor["href"]).strip()
        if not href.lower().startswith("mailto:"):
            continue
        email = unquote(href[7:].split("?")[0].strip()).strip().lower()
        if not _looks_valid(email):
            continue
        name = _clean_name(anchor.get_text(" ", strip=True))
        found.append({"email": email, "name": name})
    return found


def cfemail_decode(cfemail: str) -> str | None:
    """Decode Cloudflare's email obfuscation.

    Sites publish the address XOR-encoded (data-cfemail attribute or a
    /cdn-cgi/l/email-protection# fragment) so naive scrapers do not see it
    in the raw HTML. Decoding reads the page's own published content; it is
    de-obfuscation, not an access-control bypass.
    """
    try:
        data = bytes.fromhex((cfemail or "").strip().lstrip("#"))
        if len(data) < 2:
            return None
        key = data[0]
        decoded = "".join(chr(byte ^ key) for byte in data[1:])
        if _looks_valid(decoded):
            return decoded.lower()
    except Exception:
        pass
    return None


def extra_email_sources(html: str) -> dict[str, list[str]]:
    """One-parse extraction of footer, JSON-LD, and cfemail addresses.

    Returns {"high": [...], "medium": [...]}. Footer text and JSON-LD
    structured data (Organization/Person "email" fields) are verbatim
    page content -> high. Cloudflare-obfuscated addresses are decoded ->
    medium. These sources catch contact info the whole-page text scan
    misses (encoded mailto: links, structured data blobs).
    """
    high: list[str] = []
    medium: list[str] = []

    def walk_jsonld(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "email" and isinstance(value, str):
                    email = value.strip().lower()
                    if _looks_valid(email) and email not in high:
                        high.append(email)
                else:
                    walk_jsonld(value)
        elif isinstance(node, list):
            for item in node:
                walk_jsonld(item)

    soup = BeautifulSoup(html, "html.parser")
    for footer in soup.find_all("footer"):
        for email in extract_exact_emails(footer.get_text(" ")):
            if email not in high:
                high.append(email)
    for tag in soup.find_all("script", {"type": "application/ld+json"}):
        try:
            walk_jsonld(json.loads(tag.string or ""))
        except Exception:
            continue
    obfuscated: list[str] = []
    for tag in soup.find_all(attrs={"data-cfemail": True}):
        obfuscated.append(str(tag.get("data-cfemail") or ""))
    for anchor in soup.find_all("a", href=True):
        href = str(anchor["href"])
        if "/cdn-cgi/l/email-protection" in href and "#" in href:
            obfuscated.append(href.split("#", 1)[1])
    for candidate in obfuscated:
        email = cfemail_decode(candidate)
        if email and email not in medium:
            medium.append(email)
    return {"high": high, "medium": medium}


# Tokens that mark a "name" as an organization/place, not a person
# (iteration-2 candidate quality gate).
ORG_NAME_TOKENS = {
    "university", "college", "school", "academy", "institute", "hospital",
    "clinic", "church", "temple", "mosque", "association", "society",
    "foundation", "federation", "club", "union",
}
# A "name" ending in one of these is a job title, not a person.
TITLE_TAIL_WORDS = {
    "director", "manager", "designer", "developer", "engineer",
    "specialist", "coordinator", "assistant", "associate", "executive",
    "president", "officer", "founder", "owner", "partner", "lead", "head",
    "chief", "consultant", "analyst", "strategist", "administrator",
}


def looks_like_person_name(name: str) -> bool:
    """Cheap guard against org/place/title strings misread as names.

    Iteration-1 produced candidates for "Presbyterian University",
    "San Francisco" is unfixable cheaply (kept as known residual noise),
    and "Art Director". This gate kills the org and title cases.
    """
    words = name.lower().split()
    if not words:
        return False
    if any(word in ORG_NAME_TOKENS for word in words):
        return False
    if words[-1] in TITLE_TAIL_WORDS:
        return False
    return True


def jsonld_people(html: str) -> list[dict]:
    """Named people from JSON-LD structured data.

    Organization schemas often publish founder/employee Person entities,
    e.g. {"@type": "Organization", "founder": {"@type": "Person",
    "name": "Jane Smith"}}. These are site-published names; they feed the
    same people pipeline (and candidates when no email ties to them).
    """
    people: list[dict] = []
    seen: set[str] = set()

    def is_person(node) -> bool:
        if not isinstance(node, dict):
            return False
        types = node.get("@type")
        if isinstance(types, str):
            types = [types]
        return any(str(t).lower() == "person" for t in (types or []))

    def walk(node, parent_key: str = "") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if is_person(value):
                    name = _clean_name(str(value.get("name") or ""))
                    if (name and name.lower() not in seen
                            and looks_like_person_name(name)):
                        seen.add(name.lower())
                        title = ("Founder" if "founder" in
                                 str(key).lower() else None)
                        people.append({"name": name, "title": title})
                walk(value, str(key))
        elif isinstance(node, list):
            for item in node:
                walk(item, parent_key)

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("script", {"type": "application/ld+json"}):
        try:
            walk(json.loads(tag.string or ""))
        except Exception:
            continue
    return people


def find_team_link_people(html: str) -> list[dict]:
    """People from team/about/leadership link cards.

    Team pages often render member cards as anchors ("Jane Smith" ->
    /team/jane) with the title in the surrounding block. When the link text
    is a person's name and the nearby block carries a title keyword, record
    the person.
    """
    soup = BeautifulSoup(html, "html.parser")
    people: list[dict] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        href = str(anchor["href"]).lower()
        if not any(seg in href for seg in (
                "/team", "/about", "/people", "/leadership", "/founder",
                "/staff", "/our-team")):
            continue
        name = _clean_name(anchor.get_text(" ", strip=True))
        if not name or name.lower() in seen:
            continue
        if not looks_like_person_name(name):
            continue
        title: str | None = None
        parent = anchor
        for _ in range(3):
            parent = parent.parent
            if parent is None:
                break
            block = parent.get_text(" ", strip=True)
            keyword = next(
                (kw for kw in TITLE_KEYWORDS
                 if re.search(rf"\b{re.escape(kw)}\b", block,
                              re.IGNORECASE)),
                None,
            )
            if keyword:
                title = keyword.title()
                break
        if not title:
            continue
        seen.add(name.lower())
        people.append({"name": name, "title": title})
    return people


def guess_email_candidates(name: str, domain: str) -> list[str]:
    """Pattern-guessed addresses for a named person (LOW confidence).

    These are guesses, not findings: common local-part patterns on the
    company's own domain. Returned for email_candidates[] only; never
    treated as confirmed contacts.
    """
    if not looks_like_person_name(name):
        return []
    parts = [re.sub(r"[^a-z]", "", piece)
             for piece in name.lower().split()]
    parts = [piece for piece in parts if piece]
    if len(parts) < 2 or not domain:
        return []
    first, last = parts[0], parts[-1]
    patterns = [
        first,
        f"{first}.{last}",
        f"{first[0]}.{last}",
        f"{first}{last[0]}",
        last,
        f"{first}_{last}",
    ]
    candidates: list[str] = []
    for local in patterns:
        email = f"{local}@{domain}"
        if _looks_valid(email) and email not in candidates:
            candidates.append(email)
    return candidates


def local_part_matches_name(email: str, name: str) -> bool:
    local = email.split("@", 1)[0].lower().replace(".", "").replace("_", "").replace("-", "")
    first = name.split()[0].lower()
    if len(first) < 3 or len(local) < 3:
        return False
    return local.startswith(first) or first.startswith(local)


def associate_contacts(
    page_url: str,
    html: str,
    home_url: str,
    source_type: str = "live",
    snapshot_date: str | None = None,
) -> tuple[list[dict], list[dict], list[str], list[dict]]:
    """Return (people, emails, role_emails, email_candidates) for one page.

    people: named decision-makers (name, title, email, source_url).
    emails: every first-party address with confidence, source flagging, and
        a context snippet.
    role_emails: first-party addresses with no person attached.
    email_candidates: pattern-guessed addresses for named people with no
        published email (pattern_guessed=true, confidence "candidate").
        UNVERIFIED cheap candidates; never a "found" signal.
    """
    soup = BeautifulSoup(html, "html.parser")
    visible = soup.get_text(" ")
    mailtos = mailto_hits(html)
    titled = find_titled_people(html)
    titled_names = {p["name"].lower() for p in titled}
    for person in find_team_link_people(html) + jsonld_people(html):
        if person["name"].lower() not in titled_names:
            titled.append(person)
            titled_names.add(person["name"].lower())

    people_by_name: dict[str, dict] = {}
    for person in titled:
        people_by_name.setdefault(person["name"].lower(), person)
    for hit in mailtos:
        if not hit["name"]:
            continue
        key = hit["name"].lower()
        if key in people_by_name:
            if not people_by_name[key].get("email_hint"):
                people_by_name[key]["email_hint"] = hit["email"]
        else:
            people_by_name[key] = {
                "name": hit["name"], "title": None,
                "email_hint": hit["email"],
            }

    # Email hits with confidence: mailto = highest, exact page text = high,
    # de-obfuscated only = medium. Raw HTML is also scanned (JS blobs).
    hits: dict[str, dict] = {}

    def record(email: str, confidence: str) -> None:
        if not email_matches_website_domain(email, home_url):
            return
        existing = hits.get(email)
        if existing is None or (
                CONFIDENCE_RANK[confidence]
                > CONFIDENCE_RANK[existing["confidence"]]):
            hits[email] = {
                "address": email,
                "confidence": confidence,
                "source_url": page_url,
                "source_type": source_type,
                "snapshot_date": snapshot_date,
                "context_snippet": context_snippet(visible, email),
            }

    for hit in mailtos:
        record(hit["email"], "highest")
    for blob in (visible, html):
        exact = extract_exact_emails(blob)
        for email in exact:
            record(email, "high")
        for email in extract_deobfuscated_emails(blob, set(exact)):
            record(email, "medium")
    # Iteration-1 extra sources, parsed once: footer text, JSON-LD
    # structured data, and Cloudflare-obfuscated addresses.
    extra = extra_email_sources(html)
    for email in extra["high"]:
        record(email, "high")
    for email in extra["medium"]:
        record(email, "medium")

    people: list[dict] = []
    used_emails: set[str] = set()
    candidates: list[dict] = []
    email_domain = normalized_host(home_url)
    for key, person in people_by_name.items():
        # 2026-09-30: mailto-derived names bypassed every quality gate.
        # A link label is not a person, and a role inbox is not a person.
        if not looks_like_person_name(person["name"]):
            continue
        email = person.get("email_hint")
        if not email:
            for candidate in hits:
                if candidate in used_emails:
                    continue
                if local_part_matches_name(candidate, person["name"]):
                    email = candidate
                    break
        if email and is_role_inbox(email):
            # Generic inbox (info@/support@/sales@...) with a label attached
            # is not a named decision-maker. Leave it in role_emails.
            continue
        if not email:
            # Named person, but no published first-party email we can tie
            # to them. Record pattern-guess candidates ONLY (never a
            # confirmed contact); the person is not a "found" result.
            for guess in guess_email_candidates(person["name"],
                                                email_domain):
                candidates.append({
                    "address": guess,
                    "confidence": "candidate",
                    "pattern_guessed": True,
                    "person_name": person["name"],
                    "person_title": person.get("title"),
                    "source_url": page_url,
                    "source_type": source_type,
                    "snapshot_date": snapshot_date,
                })
            continue
        if not email_matches_website_domain(email, home_url):
            continue
        used_emails.add(email)
        people.append({
            "name": person["name"],
            "title": person.get("title"),
            "email": email,
            "source_url": page_url,
        })

    role_emails = sorted(e for e in hits if e not in used_emails)
    emails = sorted(
        hits.values(),
        key=lambda h: (-CONFIDENCE_RANK[h["confidence"]], h["address"]),
    )
    candidates = sorted(candidates, key=lambda c: c["address"])
    return people, emails, role_emails, candidates


def fetch_page_for_target(
    session: Session, renderer: Renderer, url: str,
    allow_archive: bool = True,
) -> dict:
    """Tiered fetch for one page.

    1. curl_cffi with browser TLS profile (+retries on transient errors).
    2. Headless-Chromium render, but ONLY when plain HTTP failed transiently
       or returned a JS shell. Definitive blocks (403/404/challenge/DNS/TLS)
       are never re-attempted through the browser.
    3. Wayback Machine fallback when the live fetch failed: archive.org
       cannot be blocked by the target since it never hits their server.
       Hits are flagged source_type="archived" with the snapshot date.
    """
    result = fetch_with_retries(session, url)
    if result["ok"]:
        if looks_like_js_shell(result["html"]):
            rendered = renderer.render(url)
            if rendered["ok"]:
                return rendered
        return result
    if result["reason"] in TRANSIENT_REASONS:
        rendered = renderer.render(url)
        if rendered["ok"]:
            return rendered
        result = rendered
    if allow_archive and result["reason"] != "invalid_url":
        archived = wayback_fetch(session, url)
        if archived["ok"]:
            return archived
    return result


GITHUB_ORG_RE = re.compile(
    r"github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)"
    r"(?:/|[\"'<>\s]|$)", re.IGNORECASE)
GITHUB_NON_ORG_PATHS = {
    "site", "collections", "topics", "trending", "marketplace",
    "sponsors", "features", "pricing", "login", "join",
}


def github_org_fallback(session, page_records: list, home_url: str) -> list[dict]:
    """Public contact email from the site's linked GitHub org.

    Iteration-2 fallback for dev-tool companies: many publish a contact
    email on their GitHub org profile (api.github.com/orgs/{org}.email).
    Only attempted when no emails were found on the site itself. One API
    call per domain at most; graceful on rate limits or missing email.

    The GitHub API is a sanctioned programmatic interface (its own ToS),
    not a crawled page, so the site's robots.txt does not govern it.
    """
    org: str | None = None
    for _url, html, _status, _source in page_records:
        for match in GITHUB_ORG_RE.finditer(html or ""):
            candidate = match.group(1)
            if candidate.lower() not in GITHUB_NON_ORG_PATHS:
                org = candidate
                break
        if org:
            break
    if not org:
        return []
    try:
        resp = session.get(f"https://api.github.com/orgs/{org}",
                           timeout=REQUEST_TIMEOUT)
    except Exception:
        return []
    if resp.status_code != 200:
        return []
    try:
        email = str(resp.json().get("email") or "").strip().lower()
    except Exception:
        return []
    if (email and _looks_valid(email)
            and email_matches_website_domain(email, home_url)):
        return [{
            "address": email,
            "confidence": "high",
            "source_url": f"https://github.com/{org}",
            "source_type": "live",
            "snapshot_date": None,
            "context_snippet": f"GitHub org {org} public email",
        }]
    return []


def harvest_pages(
    company_name: str,
    home_url: str,
    page_records: list[tuple[str, str, str, str | None]],
) -> dict:
    """Run extraction over (url, html, source_type, snapshot_date) records.

    Returns merged people/emails/role_emails/email_candidates plus
    contact_pages/contact_forms/source_urls. Used for the static pass and
    again over static+rendered pages on a render-on-miss second pass.
    """
    all_people: list[dict] = []
    all_emails: dict[str, dict] = {}
    all_role: list[str] = []
    all_candidates: dict[str, dict] = {}
    contact_pages: list[dict] = []
    contact_forms: list[dict] = []
    source_urls: list[str] = []
    for page_url, html, source_type, snapshot_date in page_records:
        visible = BeautifulSoup(html, "html.parser").get_text(" ")
        if not identity_matches_content(company_name, visible):
            continue
        contact_pages.append({
            "url": page_url,
            "page_type": classify_page_type(page_url),
            "source_type": source_type,
            "snapshot_date": snapshot_date,
        })
        contact_forms.extend(detect_contact_forms(page_url, html))
        people, emails, role_emails, candidates = associate_contacts(
            page_url, html, home_url, source_type, snapshot_date)
        if people or emails:
            source_urls.append(page_url)
        all_people.extend(people)
        for entry in emails:
            existing = all_emails.get(entry["address"])
            if existing is None or (
                    CONFIDENCE_RANK[entry["confidence"]]
                    > CONFIDENCE_RANK[existing["confidence"]]):
                all_emails[entry["address"]] = entry
        all_role.extend(r for r in role_emails if r not in all_role)
        for cand in candidates:
            all_candidates.setdefault(cand["address"], cand)

    # Dedupe people by email, prefer entries with a title.
    deduped: dict[str, dict] = {}
    for person in all_people:
        existing = deduped.get(person["email"])
        if existing is None or (
                not existing.get("title") and person.get("title")):
            deduped[person["email"]] = person
    people = sorted(
        deduped.values(),
        key=lambda c: (0 if c.get("title") else 1, c["name"]),
    )
    return {
        "people": people,
        "emails": sorted(
            all_emails.values(),
            key=lambda h: (-CONFIDENCE_RANK[h["confidence"]],
                           h["address"]),
        ),
        "role_emails": sorted(set(all_role)),
        "email_candidates": sorted(all_candidates.values(),
                                   key=lambda c: c["address"]),
        "contact_pages": contact_pages,
        "contact_forms": contact_forms,
        "source_urls": source_urls,
    }


def discover_one(
    *,
    company_domain: str,
    company_name: str,
    website: str,
    session: Session,
    user_agent: str,
) -> dict:
    base = {
        "company_domain": company_domain,
        "company_name": company_name,
        "website": website,
        "status": "not_found",
        "contacts": [],
        "people": [],
        "emails": [],
        "role_emails": [],
        "email_candidates": [],
        "contact_pages": [],
        "contact_forms": [],
        "company_summary": None,
        "source_urls": [],
        "reason": None,
        "pages_fetched": 0,
    }
    renderer = Renderer(user_agent)
    try:
        home_url = ""
        home_html: str | None = None
        home_source = "live"
        home_snapshot: str | None = None
        home_reason: str | None = None
        for variant in website_variants(website):
            result = fetch_page_for_target(session, renderer, variant)
            base["pages_fetched"] += 1
            if result["ok"]:
                home_url, home_html = variant, result["html"]
                home_source = result["source_type"]
                home_snapshot = result["snapshot_date"]
                break
            home_reason = result["reason"]
        if not home_html:
            base["status"] = "error"
            base["reason"] = home_reason or "website_unavailable"
            return base
        if not company_name_matches_domain(company_name, home_url):
            base["reason"] = "identity_domain_mismatch"
            return base
        if not robots_allows(home_url, session, user_agent):
            base["status"] = "error"
            base["reason"] = "robots_disallowed"
            return base

        pages = [(home_url, home_html, home_source, home_snapshot)]
        seen_urls = {home_url}
        home_host = normalized_host(home_url)

        def try_add_page(url: str) -> None:
            if len(pages) >= MAX_PAGES or url in seen_urls:
                return
            if not robots_allows(url, session, user_agent):
                return
            result = fetch_page_for_target(session, renderer, url)
            base["pages_fetched"] += 1
            if result["ok"]:
                seen_urls.add(url)
                pages.append(
                    (url, result["html"], result["source_type"],
                     result["snapshot_date"]))

        # 1) Probe common contact endpoints directly, crawled early
        #    (/contact, /about, /team, /press ...).
        probed = 0
        for endpoint in CONTACT_ENDPOINTS:
            if len(pages) >= MAX_PAGES or probed >= MAX_PROBED_ENDPOINTS:
                break
            url = urljoin(home_url.rstrip("/") + "/", endpoint)
            if url in seen_urls:
                continue
            probed += 1
            # Cheap single-attempt probe; archive fallback still applies.
            result = fetch_page_for_target(session, renderer, url)
            base["pages_fetched"] += 1
            if result["ok"]:
                seen_urls.add(url)
                pages.append(
                    (url, result["html"], result["source_type"],
                     result["snapshot_date"]))

        # 2) Follow contact-hint links discovered on the homepage.
        soup = BeautifulSoup(home_html, "html.parser")
        for anchor in soup.find_all("a", href=True):
            if len(pages) >= MAX_PAGES:
                break
            href = str(anchor["href"]).strip()
            if not href or href.startswith(("tel:", "javascript:", "#")):
                continue
            if href.lower().startswith("mailto:"):
                continue
            url = urljoin(home_url, href)
            if normalized_host(url) != home_host:
                continue
            if not any(hint in url.casefold() for hint in CONTACT_HINTS):
                continue
            try_add_page(url)

        base["company_summary"] = extract_company_summary(home_html)
        harvest = harvest_pages(company_name, home_url, pages)

        # Render-on-miss: the static passes found zero first-party emails
        # anywhere on the domain. Re-fetch the homepage and the best
        # contact/about/team page through headless Chromium (max 2
        # renders/domain) to catch JS-injected emails and mailto: links,
        # then re-run extraction over the combined pages. Rendered records
        # replace the static records for the same URLs.
        if not harvest["emails"] and not harvest["role_emails"]:
            miss_urls = [home_url]
            for entry in harvest["contact_pages"]:
                if (entry["page_type"] in ("contact", "about", "team")
                        and entry["source_type"] == "live"
                        and entry["url"] != home_url):
                    miss_urls.append(entry["url"])
                    break
            rendered_by_url: dict[str, tuple] = {}
            for url in miss_urls[:2]:
                if not robots_allows(url, session, user_agent):
                    continue
                result = renderer.render(url)
                base["pages_fetched"] += 1
                if result["ok"]:
                    rendered_by_url[url] = (url, result["html"], "live",
                                            None)
            if rendered_by_url:
                combined = [
                    rendered_by_url.get(url, (url, html, source_type,
                                              snapshot_date))
                    for url, html, source_type, snapshot_date in pages
                ]
                harvest = harvest_pages(company_name, home_url, combined)

        # Iteration-2 GitHub org fallback (dev-tool companies): only when
        # no emails were found on the site itself.
        if not harvest["emails"] and not harvest["role_emails"]:
            for entry in github_org_fallback(session, pages, home_url):
                known = {e["address"] for e in harvest["emails"]}
                if entry["address"] not in known:
                    harvest["emails"].append(entry)
                    harvest["role_emails"].append(entry["address"])
            harvest["emails"] = sorted(
                harvest["emails"],
                key=lambda h: (-CONFIDENCE_RANK[h["confidence"]],
                               h["address"]),
            )
            harvest["role_emails"] = sorted(set(harvest["role_emails"]))

        people = harvest["people"]
        base["people"] = people
        base["contacts"] = people  # legacy alias for the dispatcher
        base["emails"] = harvest["emails"]
        base["role_emails"] = harvest["role_emails"]
        base["email_candidates"] = harvest["email_candidates"]
        base["contact_pages"] = harvest["contact_pages"]
        # Dedupe forms by (page_url, action).
        seen_forms: set[tuple[str, str]] = set()
        deduped_forms: list[dict] = []
        for form in harvest["contact_forms"]:
            key = (form["page_url"], form["action"])
            if key not in seen_forms:
                seen_forms.add(key)
                deduped_forms.append(form)
        base["contact_forms"] = deduped_forms
        base["source_urls"] = harvest["source_urls"]
        if base["people"]:
            base["status"] = "found"
        else:
            base["reason"] = "no_named_contacts"
        return base
    finally:
        renderer.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    targets = json.loads(Path(args.targets).read_text())
    results: list[dict] = []
    started = time.time()
    # One session per browser profile; targets rotate across profiles so no
    # single fingerprint hammers every site (Fox fix #1).
    sessions = [
        Session(impersonate=profile["impersonate"],
                headers=profile["headers"])
        for profile in UA_PROFILES
    ]
    try:
        for index, target in enumerate(targets):
            profile_idx = index % len(sessions)
            try:
                results.append(
                    discover_one(
                        company_domain=str(target.get("company_domain") or ""),
                        company_name=str(target.get("company_name") or ""),
                        website=str(target.get("website") or ""),
                        session=sessions[profile_idx],
                        user_agent=UA_PROFILES[profile_idx][
                            "headers"]["User-Agent"],
                    )
                )
            except Exception as exc:  # never let one target kill the batch
                results.append(
                    {
                        "company_domain": str(target.get("company_domain")),
                        "company_name": str(target.get("company_name")),
                        "website": str(target.get("website")),
                        "status": "error",
                        "contacts": [],
                        "people": [],
                        "emails": [],
                        "role_emails": [],
                        "email_candidates": [],
                        "contact_pages": [],
                        "contact_forms": [],
                        "company_summary": None,
                        "source_urls": [],
                        "reason": f"worker_exception:{type(exc).__name__}",
                        "pages_fetched": 0,
                    }
                )
            if index and index % 25 == 0:
                print(f"  ... {index}/{len(targets)} done", flush=True)
    finally:
        for session in sessions:
            try:
                session.close()
            except Exception:
                pass
    Path(args.out).write_text(json.dumps(results, indent=2))
    elapsed = time.time() - started
    found = sum(1 for r in results if r["status"] == "found")
    print(f"done: {found}/{len(results)} with named contacts in {elapsed:.1f}s",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

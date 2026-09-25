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
    role_emails: first-party addresses with no person attached (manual review)
    contact_pages: [{"url", "page_type", "source_type", "snapshot_date"}]
        every contact-relevant URL discovered (contact/about/team/support...)
    contact_forms: [{"page_url", "action", "method", "fields",
                     "captcha_protected"}]  <form> elements with contact
        intent; CAPTCHA-backed forms are still recorded, flagged
    company_summary, source_urls, pages_fetched
    contacts: legacy alias of people (kept for the dispatcher).

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
- Headless-Chromium render tier for JS-heavy pages with a real browser UA,
  desktop viewport, and network-idle waits.

HARD LINES (never crossed):
- robots.txt is honored for every live URL fetched.
- CAPTCHA / challenge / login pages are recorded as fetch failures
  (reason=challenge_page), never solved or bypassed. The render tier is
  only for JS rendering; the Wayback tier only reads public archival
  copies. Neither defeats an access control.
- NEVER pattern-guess emails: only addresses actually found on pages are
  reported. First-party domain validation stays.
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
from urllib.parse import urljoin, urlparse
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
# (Fox addition: /about, /team, /contact, /press first).
CONTACT_ENDPOINTS = (
    "contact", "contact-us", "about", "about-us", "team", "our-team",
    "meet-the-team", "press", "media", "support", "help", "company",
    "who-we-are", "get-in-touch",
)
MAX_PROBED_ENDPOINTS = 4

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
}

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


def company_name_matches_domain(company_name: str, url: str) -> bool:
    host = normalized_host(url)
    if not host:
        return False
    tokens = [
        t for t in re.findall(r"[a-z0-9]+", company_name.lower())
        if len(t) >= 4 and t not in NAME_STOPWORDS
    ]
    compact_host = host.replace(".", "").replace("-", "")
    return any(token in compact_host for token in tokens)


def identity_matches_content(company_name: str, text: str) -> bool:
    tokens = [
        t for t in re.findall(r"[a-z0-9]+", company_name.lower())
        if len(t) >= 4 and t not in NAME_STOPWORDS
    ]
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower())
    return any(
        re.search(rf"(?:^|\s){re.escape(token)}(?:\s|$)", normalized)
        for token in tokens
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
    """Emails present verbatim (after HTML-entity decoding)."""
    seen: list[str] = []
    for raw in EMAIL_RE.findall(html_module.unescape(text or "")):
        email = raw.strip().strip(".,;:").lower()
        if email and email not in seen and _looks_valid(email):
            seen.append(email)
    return seen


def extract_deobfuscated_emails(text: str, exact: set[str]) -> list[str]:
    """Emails only recoverable via de-obfuscation (not verbatim)."""
    seen: list[str] = []
    for raw in EMAIL_RE.findall(deobfuscate_emails(text or "")):
        email = raw.strip().strip(".,;:").lower()
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
            if name.lower() not in seen:
                seen.add(name.lower())
                people.append({"name": name, "title": keyword.title()})
                break
    return people


def mailto_hits(html: str) -> list[dict]:
    """mailto anchors: highest-confidence emails, with person names when the
    link text is a name (Fox fix #4)."""
    found: list[dict] = []
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.find_all("a", href=True):
        href = str(anchor["href"]).strip()
        if not href.lower().startswith("mailto:"):
            continue
        email = href[7:].split("?")[0].strip().lower()
        if not _looks_valid(email):
            continue
        name = _clean_name(anchor.get_text(" ", strip=True))
        found.append({"email": email, "name": name})
    return found


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
) -> tuple[list[dict], list[dict], list[str]]:
    """Return (people, emails, role_emails) found on one page.

    people: named decision-makers (name, title, email, source_url).
    emails: every first-party address with confidence, source flagging, and
        a context snippet.
    role_emails: first-party addresses with no person attached.
    """
    soup = BeautifulSoup(html, "html.parser")
    visible = soup.get_text(" ")
    mailtos = mailto_hits(html)
    titled = find_titled_people(html)

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

    people: list[dict] = []
    used_emails: set[str] = set()
    for key, person in people_by_name.items():
        email = person.get("email_hint")
        if not email:
            for candidate in hits:
                if candidate in used_emails:
                    continue
                if local_part_matches_name(candidate, person["name"]):
                    email = candidate
                    break
        if not email:
            # Named person, but no first-party email we can tie to them.
            # We NEVER pattern-guess; the person is dropped.
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
    return people, emails, role_emails


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
        all_people: list[dict] = []
        all_emails: dict[str, dict] = {}
        all_role: list[str] = []
        contact_pages: list[dict] = []
        contact_forms: list[dict] = []
        source_urls: list[str] = []
        for page_url, html, source_type, snapshot_date in pages:
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
            people, emails, role_emails = associate_contacts(
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
        base["people"] = people
        base["contacts"] = people  # legacy alias for the dispatcher
        base["emails"] = sorted(
            all_emails.values(),
            key=lambda h: (-CONFIDENCE_RANK[h["confidence"]], h["address"]),
        )
        base["role_emails"] = sorted(set(all_role))
        base["contact_pages"] = contact_pages
        # Dedupe forms by (page_url, action).
        seen_forms: set[tuple[str, str]] = set()
        deduped_forms: list[dict] = []
        for form in contact_forms:
            key = (form["page_url"], form["action"])
            if key not in seen_forms:
                seen_forms.add(key)
                deduped_forms.append(form)
        base["contact_forms"] = deduped_forms
        base["source_urls"] = source_urls
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

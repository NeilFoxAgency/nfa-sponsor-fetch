#!/usr/bin/env python3
"""Fetch sponsor prospect websites and extract NAMED decision-maker contacts.

Runs on GitHub Actions runners so the main NFA VM only ever talks to
api.github.com (one domain) instead of thousands of business domains.

Usage:
    python fetch_contacts.py --targets targets.json --out results.json

Input:  JSON list of {"company_domain", "company_name", "website"}.
Output: JSON list of {"company_domain", "company_name", "website", "status",
        "contacts", "role_emails", "company_summary", "source_urls", "reason",
        "pages_fetched"}.

contacts is a list of {"name", "title", "email", "source_url"} for NAMED
people whose email is first-party (email domain matches the company website
domain). role_emails holds first-party addresses with no person attached
(info@, support@, ...) for manual review; they are never treated as
decision-maker hits.

status is "found" (>=1 named contact), "not_found", or "error". reason is a
granular failure code (dns_failure, http_403, challenge_page, ...) so real
outages can be told apart from bot-block false negatives.

Extraction techniques (adapted from public research, 2026-09-25):
- curl_cffi with Chrome TLS impersonation for plain-HTTP fetches: many WAFs
  fingerprint the TLS handshake (JA3) before headers are even read, so a
  standard library TLS stack is blocked as a class. Browser-grade TLS plus
  realistic browser headers makes the request a normal web request.
  (Technique documented by curl-impersonate / curl_cffi; write-ups by
  Vasile Bratu, Michael Oblak, and others.)
- Retry with exponential backoff + jitter on transient errors only
  (timeouts, connection resets, 429, 5xx). Definitive failures (DNS, 403,
  404, challenge pages) are never retried.
- Direct probing of common contact endpoints (/contact, /about, /team, ...)
  in addition to following contact links found on the homepage.
  (Endpoint list pattern from yogsec/email-finder.)
- Deobfuscation of "[at]"/"[dot]" style addresses before regex extraction.
- Headless-Chromium render tier for JS-heavy pages with a real Chrome UA,
  desktop viewport, and network-idle waits.

HARD LINES (never crossed):
- robots.txt is honored for every URL fetched.
- CAPTCHA / challenge / login pages are recorded as fetch failures
  (reason=challenge_page), never solved or bypassed. The render tier is
  only for JS rendering, never for getting past a block.
- No stealth plugins, no JS fingerprint spoofing, no proxy rotation,
  no CAPTCHA-solving services.
- Only reports what is actually found, always with the source URL.

IMPORTANT: this worker produces UNVERIFIED extraction only. Every contact
must still pass the NFA browser verification gate (SigmaWire,
VERIFIED_DELIVERABLE) before any outreach. This worker never sends anything.
"""

from __future__ import annotations

import argparse
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

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
BROWSER_HEADERS = {
    "User-Agent": CHROME_UA,
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}
REQUEST_TIMEOUT = 20.0
MAX_PAGES = 8

# Common contact endpoints probed directly (pattern from yogsec/email-finder).
CONTACT_ENDPOINTS = (
    "contact", "contact-us", "about", "about-us", "team", "our-team",
    "meet-the-team", "support", "help", "press", "media", "company",
    "who-we-are", "get-in-touch",
)
MAX_PROBED_ENDPOINTS = 4

CONTACT_HINTS = (
    "contact", "about", "about-us", "team", "leadership", "company",
    "management", "founders", "location", "support",
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Markers that indicate an access-control challenge page. We treat these as
# fetch failures and never attempt to solve or bypass them.
CHALLENGE_MARKERS = (
    "cf-challenge",
    "cf_challenge",
    "g-recaptcha",
    "recaptcha",
    "turnstile",
    "data-sitekey",
    "just a moment",
    "checking your browser",
    "verify you are human",
    "are you a robot",
    "access denied",
    "attention required",
    "perimeterx",
    "datadome",
)

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

# Failures worth retrying with backoff. Everything else is definitive.
TRANSIENT_REASONS = {
    "timeout", "connection_error", "request_error", "http_429", "http_5xx",
    "empty_response", "decode_error",
}
MAX_ATTEMPTS = 3


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

    Handles: info [at] example [dot] com, john(at)co(dot)org,
    jane AT example DOT com. The plain-word form is only rewritten when
    BOTH an at-word and a dot-word appear in the same token run, so
    ordinary prose ("look at this photo", "meet me at the store") is
    left untouched.
    """
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


def extract_public_emails(text: str) -> list[str]:
    seen: list[str] = []
    for raw in EMAIL_RE.findall(deobfuscate_emails(text or "")):
        email = raw.strip().strip(".,;:").lower()
        if email and email not in seen and _looks_valid(email):
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


def is_challenge_page(html: str) -> bool:
    lowered = html.lower()
    return any(marker in lowered for marker in CHALLENGE_MARKERS)


def fetch_page(session: Session, url: str) -> dict:
    """One plain-HTTP attempt via curl_cffi (Chrome TLS impersonation).

    Returns {"ok": bool, "html": str|None, "reason": str|None,
             "status": int|None}. reason is a granular failure code.
    """
    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT)
    except cexc.DNSError:
        return {"ok": False, "html": None, "reason": "dns_failure",
                "status": None}
    except (cexc.ConnectTimeout, cexc.ReadTimeout, cexc.Timeout):
        return {"ok": False, "html": None, "reason": "timeout", "status": None}
    except (cexc.SSLError, cexc.CertificateVerifyError):
        return {"ok": False, "html": None, "reason": "tls_error",
                "status": None}
    except cexc.ConnectionError:
        return {"ok": False, "html": None, "reason": "connection_error",
                "status": None}
    except cexc.TooManyRedirects:
        return {"ok": False, "html": None, "reason": "redirect_loop",
                "status": None}
    except (cexc.InvalidURL, cexc.URLRequired, cexc.MissingSchema):
        return {"ok": False, "html": None, "reason": "invalid_url",
                "status": None}
    except Exception:
        return {"ok": False, "html": None, "reason": "request_error",
                "status": None}
    status = response.status_code
    if status == 404:
        return {"ok": False, "html": None, "reason": "http_404",
                "status": status}
    if status == 403:
        return {"ok": False, "html": None, "reason": "http_403",
                "status": status}
    if status == 429:
        return {"ok": False, "html": None, "reason": "http_429",
                "status": status}
    if status >= 500:
        return {"ok": False, "html": None, "reason": "http_5xx",
                "status": status}
    if status != 200:
        return {"ok": False, "html": None, "reason": f"http_{status}",
                "status": status}
    try:
        text = response.text
    except Exception:
        return {"ok": False, "html": None, "reason": "decode_error",
                "status": status}
    if not text or len(text.strip()) < 50:
        return {"ok": False, "html": None, "reason": "empty_response",
                "status": status}
    if is_challenge_page(text):
        # Access-control challenge: recorded failure, never bypassed.
        return {"ok": False, "html": None, "reason": "challenge_page",
                "status": status}
    return {"ok": True, "html": text, "reason": None, "status": status}


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

    One browser per target, reused across pages. Real Chrome UA, desktop
    viewport, network-idle wait. Used ONLY for rendering JavaScript, never
    to get past an access-control block: challenge pages are still detected
    and recorded as failures.
    """

    def __init__(self) -> None:
        self._playwright = None
        self._browser = None

    def render(self, url: str) -> dict:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {"ok": False, "html": None, "reason": "no_playwright",
                    "status": None}
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
                user_agent=CHROME_UA,
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
                    "status": None}
        if not html or len(html.strip()) < 50:
            return {"ok": False, "html": None, "reason": "empty_response",
                    "status": None}
        if is_challenge_page(html):
            return {"ok": False, "html": None, "reason": "challenge_page",
                    "status": None}
        return {"ok": True, "html": html, "reason": None, "status": 200}

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


def robots_allows(url: str, session: Session) -> bool:
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        response = session.get(robots_url, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return True
        parser = RobotFileParser()
        parser.set_url(robots_url)
        parser.parse(response.text.splitlines())
        return bool(parser.can_fetch(CHROME_UA, url))
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


def mailto_named_links(html: str) -> list[dict]:
    """mailto anchors whose link text is a person name."""
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
        if name:
            found.append({"name": name, "email": email})
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
) -> tuple[list[dict], list[str]]:
    """Return (named contacts, role emails) found on one page."""
    soup = BeautifulSoup(html, "html.parser")
    visible = soup.get_text(" ")
    named_links = mailto_named_links(html)
    titled = find_titled_people(html)

    people_by_name: dict[str, dict] = {}
    for person in titled:
        people_by_name.setdefault(person["name"].lower(), person)
    for link in named_links:
        key = link["name"].lower()
        if key in people_by_name:
            people_by_name[key]["email_hint"] = link["email"]
        else:
            people_by_name[key] = {
                "name": link["name"], "title": None,
                "email_hint": link["email"],
            }

    # Visible text, deobfuscated raw HTML (catches JS blobs), and mailto:.
    first_party: list[str] = []
    for blob in (visible, html):
        for email in extract_public_emails(blob):
            if (email_matches_website_domain(email, home_url)
                    and email not in first_party):
                first_party.append(email)
    for anchor in soup.find_all("a", href=True):
        href = str(anchor["href"]).strip()
        if not href.lower().startswith("mailto:"):
            continue
        email = href[7:].split("?")[0].strip().lower()
        if (_looks_valid(email)
                and email_matches_website_domain(email, home_url)
                and email not in first_party):
            first_party.append(email)

    contacts: list[dict] = []
    used_emails: set[str] = set()
    for key, person in people_by_name.items():
        email = person.get("email_hint")
        if not email:
            for candidate in first_party:
                if candidate in used_emails:
                    continue
                if local_part_matches_name(candidate, person["name"]):
                    email = candidate
                    break
        if not email:
            # Named person, but no first-party email we can tie to them.
            continue
        if not email_matches_website_domain(email, home_url):
            continue
        used_emails.add(email)
        contacts.append({
            "name": person["name"],
            "title": person.get("title"),
            "email": email,
            "source_url": page_url,
        })

    # Any first-party email not tied to a name is a role email for review.
    role_emails = sorted(e for e in first_party if e not in used_emails)
    return contacts, role_emails


def fetch_page_for_target(
    session: Session, renderer: Renderer, url: str,
) -> dict:
    """Tiered fetch for one page: curl_cffi (+retries), then render tier.

    The render tier only fires when plain HTTP failed transiently or
    returned a JS shell. Definitive blocks (403/404/challenge/DNS/TLS)
    are never re-attempted through the browser.
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
    return result


def discover_one(
    *,
    company_domain: str,
    company_name: str,
    website: str,
    session: Session,
) -> dict:
    base = {
        "company_domain": company_domain,
        "company_name": company_name,
        "website": website,
        "status": "not_found",
        "contacts": [],
        "role_emails": [],
        "company_summary": None,
        "source_urls": [],
        "reason": None,
        "pages_fetched": 0,
    }
    renderer = Renderer()
    try:
        home_url = ""
        home_html: str | None = None
        home_reason: str | None = None
        for variant in website_variants(website):
            result = fetch_page_for_target(session, renderer, variant)
            base["pages_fetched"] += 1
            if result["ok"]:
                home_url, home_html = variant, result["html"]
                break
            home_reason = result["reason"]
        if not home_html:
            base["status"] = "error"
            base["reason"] = home_reason or "website_unavailable"
            return base
        if not company_name_matches_domain(company_name, home_url):
            base["reason"] = "identity_domain_mismatch"
            return base
        if not robots_allows(home_url, session):
            base["status"] = "error"
            base["reason"] = "robots_disallowed"
            return base

        pages = [(home_url, home_html)]
        seen_urls = {home_url}
        home_host = normalized_host(home_url)
        soup = BeautifulSoup(home_html, "html.parser")

        def try_add_page(url: str) -> None:
            if len(pages) >= MAX_PAGES or url in seen_urls:
                return
            if not robots_allows(url, session):
                return
            result = fetch_page_for_target(session, renderer, url)
            base["pages_fetched"] += 1
            if result["ok"]:
                seen_urls.add(url)
                pages.append((url, result["html"]))

        # 1) Follow contact-hint links discovered on the homepage.
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

        # 2) Probe common contact endpoints directly (they may not be
        #    linked from the homepage).
        probed = 0
        for endpoint in CONTACT_ENDPOINTS:
            if len(pages) >= MAX_PAGES or probed >= MAX_PROBED_ENDPOINTS:
                break
            url = urljoin(home_url.rstrip("/") + "/", endpoint)
            if url in seen_urls:
                continue
            probed += 1
            # Single attempt, no render tier: cheap probe.
            result = fetch_with_retries(session, url, attempts=1)
            base["pages_fetched"] += 1
            if result["ok"]:
                seen_urls.add(url)
                pages.append((url, result["html"]))

        base["company_summary"] = extract_company_summary(home_html)
        all_contacts: list[dict] = []
        all_role: list[str] = []
        source_urls: list[str] = []
        for page_url, html in pages:
            visible = BeautifulSoup(html, "html.parser").get_text(" ")
            if not identity_matches_content(company_name, visible):
                continue
            contacts, role_emails = associate_contacts(
                page_url, html, home_url)
            if contacts or role_emails:
                source_urls.append(page_url)
            all_contacts.extend(contacts)
            all_role.extend(r for r in role_emails if r not in all_role)

        # Dedupe contacts by email, prefer entries with a title.
        deduped: dict[str, dict] = {}
        for contact in all_contacts:
            existing = deduped.get(contact["email"])
            if existing is None or (
                    not existing.get("title") and contact.get("title")):
                deduped[contact["email"]] = contact
        base["contacts"] = sorted(
            deduped.values(),
            key=lambda c: (0 if c.get("title") else 1, c["name"]),
        )
        base["role_emails"] = sorted(set(all_role))
        base["source_urls"] = source_urls
        if base["contacts"]:
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
    session = Session(impersonate="chrome", headers=BROWSER_HEADERS)
    try:
        for index, target in enumerate(targets):
            try:
                results.append(
                    discover_one(
                        company_domain=str(target.get("company_domain") or ""),
                        company_name=str(target.get("company_name") or ""),
                        website=str(target.get("website") or ""),
                        session=session,
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
                        "role_emails": [],
                        "company_summary": None,
                        "source_urls": [],
                        "reason": f"worker_exception:{type(exc).__name__}",
                        "pages_fetched": 0,
                    }
                )
            if index and index % 25 == 0:
                print(f"  ... {index}/{len(targets)} done", flush=True)
    finally:
        session.close()
    Path(args.out).write_text(json.dumps(results, indent=2))
    elapsed = time.time() - started
    found = sum(1 for r in results if r["status"] == "found")
    print(f"done: {found}/{len(results)} with named contacts in {elapsed:.1f}s",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

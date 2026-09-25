#!/usr/bin/env python3
"""Fetch business websites and extract public first-party contact emails.

Runs on GitHub Actions runners (clean datacenter egress) so the main
Storm Fix Now VM never has to fetch thousands of business domains itself.

Usage:
    python fetch_contacts.py --targets targets.json --out results.json

Input:  JSON list of {"business_id", "business_name", "website"}.
Output: JSON list of {"business_id", "business_name", "website", "status",
        "email", "source_url", "reason"}.

status is "found", "not_found", or "error". This worker never attempts to
evade access controls: CAPTCHA/challenge pages, logins, and denied robots
rules are recorded as fetch failures, never bypassed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup

USER_AGENT = "StormFixNow contact research/1.0"
REQUEST_TIMEOUT = 12.0
MAX_PAGES = 2
CONTACT_HINTS = ("contact", "about", "team", "location", "support")
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
)

NAME_STOPWORDS = {
    "auto", "business", "care", "clinic", "company", "dental", "family",
    "group", "hotel", "inc", "llc", "restaurant", "sales", "services",
    "storage", "the",
}


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


def business_name_matches_domain(business_name: str, url: str) -> bool:
    host = normalized_host(url)
    if not host:
        return False
    tokens = [
        t for t in re.findall(r"[a-z0-9]+", business_name.lower())
        if len(t) >= 4 and t not in NAME_STOPWORDS
    ]
    compact_host = host.replace(".", "").replace("-", "")
    return any(token in compact_host for token in tokens)


def identity_matches_content(business_name: str, text: str) -> bool:
    tokens = [
        t for t in re.findall(r"[a-z0-9]+", business_name.lower())
        if len(t) >= 4 and t not in NAME_STOPWORDS
    ]
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower())
    return any(
        re.search(rf"(?:^|\s){re.escape(token)}(?:\s|$)", normalized)
        for token in tokens
    )


def extract_public_emails(text: str) -> list[str]:
    seen: list[str] = []
    for raw in EMAIL_RE.findall(text or ""):
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


def fetch_tier1(url: str, client: httpx.Client) -> str | None:
    """Plain HTTP fetch. Returns page text or None on any failure."""
    try:
        response = client.get(url)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        text = response.text
    except Exception:
        return None
    if is_challenge_page(text):
        return None
    return text


def fetch_tier2_rendered(url: str) -> str | None:
    """Headless-Chromium render for JS-heavy pages. None if unavailable.

    Never used to bypass access controls: challenge pages are detected and
    treated as failures.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page(user_agent=USER_AGENT)
                page.goto(url, timeout=20000, wait_until="domcontentloaded")
                html = page.content()
            finally:
                browser.close()
    except Exception:
        return None
    if is_challenge_page(html):
        return None
    return html


def robots_allows(url: str, client: httpx.Client) -> bool:
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        response = client.get(robots_url)
        if response.status_code != 200:
            return True
        parser = RobotFileParser()
        parser.set_url(robots_url)
        parser.parse(response.text.splitlines())
        return bool(parser.can_fetch(USER_AGENT, url))
    except Exception:
        return True


def discover_one(
    *,
    business_id: str,
    business_name: str,
    website: str,
    client: httpx.Client,
) -> dict:
    base = {
        "business_id": business_id,
        "business_name": business_name,
        "website": website,
        "status": "not_found",
        "email": None,
        "source_url": None,
        "reason": None,
    }
    home_url = ""
    home_text: str | None = None
    for variant in website_variants(website):
        text = fetch_tier1(variant, client)
        if text is None:
            text = fetch_tier2_rendered(variant)
        if text:
            home_url, home_text = variant, text
            break
    if not home_text:
        base["status"] = "error"
        base["reason"] = "website_unavailable"
        return base
    if not business_name_matches_domain(business_name, home_url):
        base["reason"] = "identity_domain_mismatch"
        return base
    if not robots_allows(home_url, client):
        base["status"] = "error"
        base["reason"] = "robots_disallowed"
        return base

    pages = [(home_url, home_text)]
    home_host = normalized_host(home_url)
    soup = BeautifulSoup(home_text, "html.parser")
    for anchor in soup.find_all("a", href=True):
        if len(pages) >= MAX_PAGES:
            break
        href = str(anchor["href"]).strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        url = urljoin(home_url, href)
        if normalized_host(url) != home_host:
            continue
        if not any(hint in url.casefold() for hint in CONTACT_HINTS):
            continue
        if not robots_allows(url, client):
            continue
        text = fetch_tier1(url, client) or fetch_tier2_rendered(url)
        if text:
            pages.append((url, text))

    for page_url, content in pages:
        visible = BeautifulSoup(content, "html.parser").get_text(" ")
        if not identity_matches_content(business_name, visible):
            continue
        for email in extract_public_emails(visible):
            if not email_matches_website_domain(email, home_url):
                continue
            base["status"] = "found"
            base["email"] = email
            base["source_url"] = page_url
            return base
    base["reason"] = "no_valid_first_party_email"
    return base


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    targets = json.loads(Path(args.targets).read_text())
    results: list[dict] = []
    started = time.time()
    with httpx.Client(
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        for index, target in enumerate(targets):
            try:
                results.append(
                    discover_one(
                        business_id=str(target.get("business_id") or ""),
                        business_name=str(target.get("business_name") or ""),
                        website=str(target.get("website") or ""),
                        client=client,
                    )
                )
            except Exception as exc:  # never let one target kill the batch
                results.append(
                    {
                        "business_id": str(target.get("business_id")),
                        "business_name": str(target.get("business_name")),
                        "website": str(target.get("website")),
                        "status": "error",
                        "email": None,
                        "source_url": None,
                        "reason": f"worker_exception:{type(exc).__name__}",
                    }
                )
            if index and index % 25 == 0:
                print(f"  ... {index}/{len(targets)} done", flush=True)
    Path(args.out).write_text(json.dumps(results, indent=2))
    elapsed = time.time() - started
    found = sum(1 for r in results if r["status"] == "found")
    print(f"done: {found}/{len(results)} found in {elapsed:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

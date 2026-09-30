#!/usr/bin/env python3
"""Programmatic contact discovery via Keenable API.

No LLM tokens burned: search + fetch + LLM-extraction all happen on
Keenable's side. This script parses JSON with code only.

Pipeline:
  1. Search Keenable (realtime) for the company's contact pages
  2. Fetch each candidate URL with a prompt asking for emails/contact info
  3. Parse the extracted JSON with code, validate email format
  4. Output structured JSON: [{url, emails[], source}]

Usage:
  discover.py DOMAIN [COMPANY_NAME] [--max-pages N] [--json]

Budget: ~1 credit per search + 1 per fetch. A typical run (1 search +
3 fetches) = ~4 credits. At 100K/month, that's ~25,000 companies/month.

Auth: KEENABLE_API_KEY env var (GitHub Actions secret) or the local
skill CLI. This script uses the env var directly for portability.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

API = "https://api.keenable.ai"
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Prompt sent to Keenable's LLM for extraction (their compute, not ours).
EMAIL_PROMPT = (
    "List every email address visible on this page. "
    "Return ONLY a JSON array of strings, e.g. [\"a@b.com\"]. "
    "No other text, no explanations."
)


def _api_key() -> str:
    key = os.environ.get("KEENABLE_API_KEY", "").strip()
    if not key:
        raise RuntimeError("KEENABLE_API_KEY not set")
    return key


def _post(path: str, payload: dict, timeout: int = 30) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        API + path, data=body,
        headers={"Content-Type": "application/json",
                 "Accept": "application/json",
                 "X-API-Key": _api_key()},
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _get(path: str, params: dict, timeout: int = 60) -> dict:
    qs = urllib.parse.urlencode(params)
    req = urllib.request.Request(
        API + path + "?" + qs,
        headers={"Accept": "application/json",
                 "X-API-Key": _api_key()})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def search_contact_pages(domain: str, company: str,
                         max_results: int = 10) -> list[dict]:
    """Search for the company's contact pages. Returns [{url, title}]."""
    queries = [
        f"site:{domain} contact",
        f"{domain} contact email",
    ]
    if company and company.lower() not in domain.lower():
        queries.append(f"{company} contact email")
    seen: dict[str, dict] = {}
    for q in queries:
        try:
            d = _post("/v1/search", {
                "query": q, "mode": "realtime",
                "max_results": max_results, "snippet_max_length": 180,
            })
        except Exception:
            continue
        for r in d.get("results", []):
            url = r.get("url", "")
            if not url or url in seen:
                continue
            # Keep only URLs plausibly on the target domain
            host = urllib.parse.urlparse(url).hostname or ""
            dom_root = domain.split(".")[-2] if "." in domain else domain
            if dom_root not in host:
                continue
            seen[url] = {"url": url, "title": r.get("title", "")}
        time.sleep(0.15)  # stay well under 10 req/sec
    return list(seen.values())


def extract_emails(url: str) -> list[str]:
    """Fetch a page with LLM extraction; parse emails with regex (code)."""
    try:
        d = _get("/v1/fetch", {
            "url": url, "max_chars": 8000, "prompt": EMAIL_PROMPT,
        })
    except Exception:
        return []
    content = d.get("content", "") or ""
    # The LLM returns a JSON array, but be defensive: regex-scan regardless.
    emails = EMAIL_RE.findall(content)
    # Dedupe, lowercase, drop obvious junk
    out = []
    for e in dict.fromkeys(emails):
        e = e.lower()
        if e.endswith((".png", ".jpg", ".gif", ".svg")):
            continue
        if len(e) > 254:
            continue
        out.append(e)
    return out


def discover(domain: str, company: str = "",
             max_pages: int = 5) -> dict:
    """Full pipeline: search -> extract -> structured result."""
    domain = domain.lower().strip().lstrip("www.")
    company = company or domain
    pages = search_contact_pages(domain, company)
    results = []
    for p in pages[:max_pages]:
        emails = extract_emails(p["url"])
        time.sleep(0.15)
        if emails:
            results.append({
                "url": p["url"],
                "title": p["title"],
                "emails": emails,
                "source": "keenable-search+extract",
            })
    return {
        "domain": domain,
        "company": company,
        "pages_checked": min(len(pages), max_pages),
        "contacts": results,
        "credits_used": 1 + min(len(pages), max_pages),  # approx
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("domain", help="company domain, e.g. magicspoon.com")
    ap.add_argument("company", nargs="?", default="",
                    help="company name (defaults to domain)")
    ap.add_argument("--max-pages", type=int, default=5)
    args = ap.parse_args()
    try:
        out = discover(args.domain, args.company, args.max_pages)
    except RuntimeError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

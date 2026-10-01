#!/usr/bin/env python3
"""Bulk contact enrichment for the overnight 57K backfill (Fox 2026-09-30).

Asyncio-based for throughput: static crawl with high concurrency, then
KeenAble search+extract for companies where static found zero emails.

Waterfall per company:
  1. Static: fetch homepage + contact/about/team pages concurrently,
     regex-extract emails (free, our compute).
  2. KeenAble: if zero emails, search (realtime) for contact pages then
     fetch top pages with LLM email extraction (their compute).
     Paced via KEENABLE_PACING (seconds between calls) to respect the
     10 req/sec org-wide limit across parallel workers.

Usage:
  python bulk_enrich.py --targets shards/shard-00.json --out results/shard-00.json

Output: JSON list of {company_domain, company_name, website, status,
  emails[], contact_pages[], keenable_credits, error}.
  status: "found" (>=1 email), "not_found", "error".

Env:
  KEENABLE_API_KEY: KeenAble API key (required for tier 2)
  KEENABLE_PACING: seconds between KeenAble calls (default 2.0 =
    0.5/sec per worker; 20 workers = 10/sec org-wide)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
import urllib.parse

try:
    import aiohttp  # noqa: F401  (kept for compatibility; transport is curl)
except ImportError:
    pass  # curl subprocess is the actual transport

API = "https://api.keenable.ai"
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Pages to try per company (static tier). Homepage first, then likely
# contact pages. Keep it small for bulk throughput.
CONTACT_PATHS = ["", "/contact", "/contact-us", "/about", "/about-us", "/team"]

# Junk emails to ignore
JUNK_PATTERNS = re.compile(
    r"(example\.com|test\.com|\.png|\.jpg|\.gif|\.svg|"
    r"sentry|wixpress|schema\.org)$",
    re.IGNORECASE,
)

EMAIL_PROMPT = (
    "List every email address visible on this page. "
    "Return ONLY a JSON array of strings. No other text."
)


def _api_key() -> str:
    return os.environ.get("KEENABLE_API_KEY", "").strip()


def extract_emails(html: str, domain: str) -> list[str]:
    """Regex-extract first-party emails from HTML."""
    import html as _html
    # Decode entities first (prevents u003e-style artifacts)
    text = _html.unescape(html)
    found = []
    for m in EMAIL_RE.finditer(text):
        addr = m.group(0).lower()
        # Drop artifacts from encoded text
        if addr.startswith(("u003e", "u003c", ">", "<")):
            continue
        if len(addr) > 254 or JUNK_PATTERNS.search(addr):
            continue
        # First-party: email domain matches company domain (or subdomain)
        email_host = addr.split("@")[1]
        dom_root = ".".join(domain.split(".")[-2:])
        email_root = ".".join(email_host.split(".")[-2:])
        if email_root != dom_root:
            continue
        if addr not in found:
            found.append(addr)
    return found


async def fetch_page(url: str, timeout: int = 20) -> str | None:
    """Fetch via curl (handles the egress proxy correctly; aiohttp cannot
    do the proxy TLS handshake on this VM)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sL", "--max-time", str(timeout),
            "--max-filesize", "2000000",
            "-A", "Mozilla/5.0 (compatible; NFA-enrich/1.0)",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout + 5)
        if proc.returncode != 0:
            return None
        text = out.decode("utf-8", errors="ignore")
        # Quick HTML check
        if "<html" not in text.lower()[:2000] and "<body" not in text.lower()[:2000]:
            if len(text) < 500:
                return None
        return text
    except Exception:
        return None


async def static_enrich(company: dict) -> dict:
    """Tier 1: static crawl. Returns {emails, contact_pages}."""
    domain = company["company_domain"]
    website = (company.get("website") or f"https://{domain}").rstrip("/")
    emails: list[str] = []
    contact_pages: list[str] = []

    async def check(path: str):
        url = website + path
        html = await fetch_page(url)
        if not html:
            return
        for addr in extract_emails(html, domain):
            if addr not in emails:
                emails.append(addr)
        # Record if this looks like a contact page
        if path and ("contact" in path or "about" in path or "team" in path):
            contact_pages.append(url)

    await asyncio.gather(*[check(p) for p in CONTACT_PATHS])
    return {"emails": emails, "contact_pages": contact_pages}


async def _curl_json(method: str, url: str, key: str,
                     data: dict | None = None,
                     params: dict | None = None,
                     timeout: int = 30,
                     _retry_429: int = 3) -> dict | None:
    """curl-based JSON API call (egress-proxy safe).

    Handles 429 (rate limit: exponential backoff) and 402 (credits
    exhausted: raise immediately so the run stops instead of burning
    through the shard with failed calls).
    """
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "--max-time", str(timeout),
           "-X", method,
           "-H", f"X-API-Key: {key}",
           "-H", "Content-Type: application/json",
           "-H", "Accept: application/json"]
    if params:
        qs = urllib.parse.urlencode(params)
        url = url + "?" + qs
    if data is not None:
        cmd += ["-d", json.dumps(data)]
    cmd.append(url)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout + 5)
        finally:
            # Ensure the transport is fully closed before the loop ends;
            # prevents "Event loop is closed" noise on shutdown.
            try:
                await asyncio.wait_for(proc.wait(), 5)
            except Exception:
                pass
        if proc.returncode != 0:
            return None
        text = out.decode("utf-8", errors="ignore")
        # Split off the trailing HTTP status code
        *body_lines, status_line = text.rsplit("\n", 1)
        body = "\n".join(body_lines)
        try:
            status = int(status_line.strip())
        except ValueError:
            status = 0
        if status == 402:
            raise RuntimeError(
                "KeenAble 402: credits exhausted; stopping shard")
        if status == 429 and _retry_429 > 0:
            await asyncio.sleep(2 ** (3 - _retry_429) * 2)
            return await _curl_json(method, url, key, data, params,
                                    timeout, _retry_429 - 1)
        if status == 429:
            return None  # retries exhausted; skip this call
        if status in (401, 403):
            raise RuntimeError(
                f"KeenAble auth error {status}; stopping shard")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None
    except RuntimeError:
        raise
    except Exception:
        return None


async def keenable_search(domain: str, company_name: str) -> tuple[list[str], int]:
    """Search KeenAble for the company's contact pages.
    Returns (urls, credits_used)."""
    key = _api_key()
    if not key:
        return [], 0
    queries = [f"site:{domain} contact", f"{domain} contact email"]
    if company_name and company_name.lower() not in domain.lower():
        queries.append(f"{company_name} contact email")
    urls: list[str] = []
    credits = 0
    for q in queries[:2]:  # max 2 searches per company (save credits)
        await _keenable_gate()
        data = await _curl_json(
            "POST", API + "/v1/search", key,
            data={"query": q, "mode": "realtime",
                  "max_results": 5, "snippet_max_length": 180},
            timeout=30)
        credits += 1
        if data is None:
            continue
        for r in data.get("results", []):
            url = r.get("url", "")
            host = urllib.parse.urlparse(url).hostname or ""
            dom_root = ".".join(domain.split(".")[-2:])
            if dom_root in host and url not in urls:
                urls.append(url)
    return urls[:3], credits


async def keenable_extract(url: str, domain: str) -> tuple[list[str], int]:
    """Fetch a page via KeenAble with LLM email extraction.
    Returns (first-party emails, credits_used)."""
    key = _api_key()
    if not key:
        return [], 0
    await _keenable_gate()
    data = await _curl_json(
        "GET", API + "/v1/fetch", key,
        params={"url": url, "max_chars": 8000, "prompt": EMAIL_PROMPT},
        timeout=60)
    if data is None:
        return [], 1
    content = data.get("content", "") or ""
    emails = []
    for m in EMAIL_RE.finditer(content):
        addr = m.group(0).lower()
        if len(addr) > 254 or JUNK_PATTERNS.search(addr):
            continue
        email_host = addr.split("@")[1]
        dom_root = ".".join(domain.split(".")[-2:])
        email_root = ".".join(email_host.split(".")[-2:])
        if email_root != dom_root:
            continue
        if addr not in emails:
            emails.append(addr)
    return emails, 1


def pacing() -> float:
    return float(os.environ.get("KEENABLE_PACING", "2.0"))


# Global rate limiter: max 1 KeenAble call per PACING seconds ACROSS ALL
# coroutines in this job. The old code slept per-coroutine, so 30 concurrent
# coroutines could fire 30 simultaneous requests. This shared lock ensures
# the job stays under its fair share of the 10/sec org limit.
_keenable_lock: asyncio.Lock | None = None
_keenable_last_call: float = 0.0


async def _keenable_gate() -> None:
    """Block until this job may make its next KeenAble call."""
    global _keenable_last_call
    if _keenable_lock is None:
        return
    async with _keenable_lock:
        now = time.monotonic()
        wait = pacing() - (now - _keenable_last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        _keenable_last_call = time.monotonic()


def _init_rate_limiter() -> None:
    global _keenable_lock
    _keenable_lock = asyncio.Lock()


async def enrich_one(sem: asyncio.Semaphore,
                     company: dict) -> dict:
    """Full waterfall for one company."""
    domain = company["company_domain"]
    result = {
        "company_domain": domain,
        "company_name": company.get("company_name", domain),
        "website": company.get("website", ""),
        "status": "not_found",
        "emails": [],
        "contact_pages": [],
        "keenable_credits": 0,
        "error": None,
    }
    async with sem:
        try:
            # Tier 1: static
            static = await static_enrich(company)
            result["emails"] = static["emails"]
            result["contact_pages"] = static["contact_pages"]

            # Tier 2: KeenAble (only if static found nothing)
            if not result["emails"] and _api_key():
                urls, search_credits = await keenable_search(
                    domain, result["company_name"])
                result["keenable_credits"] += search_credits
                for url in urls:
                    addrs, fetch_credits = await keenable_extract(url, domain)
                    result["keenable_credits"] += fetch_credits
                    for addr in addrs:
                        if addr not in result["emails"]:
                            result["emails"].append(addr)
                    if url not in result["contact_pages"]:
                        result["contact_pages"].append(url)
            result["status"] = "found" if result["emails"] else "not_found"
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"{type(e).__name__}: {str(e)[:100]}"
    return result


async def main_async(targets: list[dict],
                     concurrency: int) -> list[dict]:
    _init_rate_limiter()
    sem = asyncio.Semaphore(concurrency)
    tasks = [enrich_one(sem, c) for c in targets]
    results = []
    for i, coro in enumerate(asyncio.as_completed(tasks)):
        results.append(await coro)
        if (i + 1) % 100 == 0:
            print(f"  progress: {i + 1}/{len(targets)}", flush=True)
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--concurrency", type=int, default=50)
    args = ap.parse_args()

    with open(args.targets) as f:
        targets = json.load(f)
    print(f"enriching {len(targets)} companies "
          f"(concurrency {args.concurrency})", flush=True)
    t0 = time.time()
    results = asyncio.run(main_async(targets, args.concurrency))
    dt = time.time() - t0

    found = sum(1 for r in results if r["status"] == "found")
    credits = sum(r["keenable_credits"] for r in results)
    print(f"done in {dt:.0f}s: {found}/{len(results)} found, "
          f"~{credits} keenable credits", flush=True)

    # FIX 2026-09-30: create the output parent dir. The workflow only ran
    # mkdir -p bulk-results in the commit step AFTER the script, so the
    # script crashed with FileNotFoundError after doing all the work.
    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(results, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())

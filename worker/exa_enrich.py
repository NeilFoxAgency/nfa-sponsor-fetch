#!/usr/bin/env python3
"""Exa-based contact enrichment for the $20 credit spend-down (Fox 2026-09-30).

Uses Exa semantic search to find contact emails for companies where the
KeenAble bulk pass found nothing. Budget: ~$20 (~2,857 searches at $0.007).

Waterfall per company:
  1. Exa search: "contact email <company> <domain>" with contents
  2. Regex-extract emails from returned page contents
  3. Filter to domain-matching emails

Usage:
  python exa_enrich.py --targets shards/exa-00.json --out results/exa-00.json

Output: JSON list of {company_domain, company_name, website, status,
  emails[], exa_cost, error}.
  status: "found" (>=1 email), "not_found", "error".

Env:
  EXA_API_KEY: Exa API key (repo secret)
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

API = "https://api.exa.ai"
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Junk emails to ignore
JUNK_PREFIXES = {"noreply", "no-reply", "donotreply", "do-not-reply", "mailer-daemon",
                 "postmaster", "abuse", "spam", "bounce", "unsubscribe"}
JUNK_DOMAINS = {"example.com", "test.com", "email.com", "gmail.com", "yahoo.com",
                "hotmail.com", "outlook.com", "aol.com", "icloud.com"}


def _api_key() -> str:
    key = os.environ.get("EXA_API_KEY", "")
    if not key:
        print("EXA_API_KEY not set", file=sys.stderr)
        sys.exit(2)
    return key


def extract_emails(text: str, domain: str) -> list[str]:
    """Extract plausible company emails from text."""
    found = []
    domain_lower = domain.lower()
    for m in EMAIL_RE.finditer(text or ""):
        email = m.group(0).lower()
        local, _, email_domain = email.partition("@")
        if local in JUNK_PREFIXES:
            continue
        if email_domain in JUNK_DOMAINS:
            continue
        # Prefer emails on the company's domain, but accept others
        # (founder might use personal domain)
        if len(local) < 2 or len(email) > 100:
            continue
        if email not in found:
            found.append(email)
    # Sort: domain-matching first
    found.sort(key=lambda e: (0 if e.endswith("@" + domain_lower) else 1, e))
    return found[:10]


async def _curl_json(method: str, url: str, key: str,
                     payload: dict | None = None,
                     timeout: int = 60) -> tuple[int, dict]:
    """POST JSON via curl subprocess (egress proxy blocks urllib on some hosts)."""
    import subprocess
    import tempfile

    cmd = ["curl", "-sS", "-m", str(timeout), "-w", "\n%{http_code}",
           "-X", method, url,
           "-H", "Content-Type: application/json",
           "-H", f"x-api-key: {key}"]
    if payload:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as f:
            json.dump(payload, f)
            tmpfile = f.name
        cmd += ["--data-binary", f"@{tmpfile}"]
    else:
        tmpfile = None

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        if tmpfile:
            os.unlink(tmpfile)
        text = stdout.decode("utf-8", errors="replace")
        # Last line is the HTTP code
        lines = text.rsplit("\n", 1)
        if len(lines) == 2:
            body, code_str = lines
            try:
                code = int(code_str.strip())
            except ValueError:
                code = 0
        else:
            body, code = text, 0
        try:
            data = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            data = {"_raw": body[:500]}
        return code, data
    except Exception as e:
        if tmpfile and os.path.exists(tmpfile):
            os.unlink(tmpfile)
        return 0, {"_error": str(e)}


async def exa_search_emails(domain: str, company_name: str,
                            key: str) -> tuple[list[str], float]:
    """Search Exa for contact emails. Returns (emails, cost_usd)."""
    query = f"{company_name} {domain} contact email"
    payload = {
        "query": query,
        "numResults": 5,
        "contents": {"text": True, "maxCharacters": 3000},
    }
    code, data = await _curl_json("POST", f"{API}/search", key, payload)

    if code == 402:
        raise RuntimeError("EXA_402_CREDITS_EXHAUSTED")
    if code in (401, 403):
        raise RuntimeError(f"EXA_{code}_AUTH_ERROR")
    if code == 429:
        # Simple backoff and retry once
        await asyncio.sleep(5)
        code, data = await _curl_json("POST", f"{API}/search", key, payload)
        if code != 200:
            return [], 0.007

    if code != 200:
        return [], 0.007

    # Extract emails from all result contents
    all_text = []
    for result in data.get("results", []):
        text = result.get("text", "")
        if text:
            all_text.append(text)
        # Also check title/snippet
        title = result.get("title", "")
        if title:
            all_text.append(title)

    combined = "\n".join(all_text)
    emails = extract_emails(combined, domain)
    # Cost: ~$0.007 per search (neural)
    return emails, 0.007


async def enrich_one(sem: asyncio.Semaphore, company: dict,
                     key: str) -> dict:
    domain = company.get("domain", "")
    name = company.get("name", domain)
    website = company.get("website", f"https://{domain}")

    result = {
        "company_domain": domain,
        "company_name": name,
        "website": website,
        "status": "not_found",
        "emails": [],
        "exa_cost": 0.0,
        "error": None,
    }

    async with sem:
        try:
            emails, cost = await exa_search_emails(domain, name, key)
            result["exa_cost"] = cost
            if emails:
                result["emails"] = emails
                result["status"] = "found"
        except RuntimeError as e:
            # Fatal: credit exhausted or auth error - re-raise to stop shard
            if "EXA_402" in str(e) or "EXA_401" in str(e) or "EXA_403" in str(e):
                raise
            result["error"] = str(e)
            result["status"] = "error"
        except Exception as e:
            result["error"] = str(e)[:200]
            result["status"] = "error"

    return result


async def main_async(targets: list[dict], out_path: str,
                     concurrency: int = 5) -> None:
    key = _api_key()
    # Ensure output directory exists (the 2026-09-30 FileNotFoundError lesson)
    out_parent = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(out_parent, exist_ok=True)

    sem = asyncio.Semaphore(concurrency)
    results = []

    # Process with limited concurrency to avoid rate limits
    for i in range(0, len(targets), concurrency):
        batch = targets[i:i + concurrency]
        tasks = [enrich_one(sem, c, key) for c in batch]
        try:
            batch_results = await asyncio.gather(*tasks)
            results.extend(batch_results)
        except RuntimeError as e:
            if "EXA_402" in str(e):
                print(f"FATAL: Exa credits exhausted after {len(results)} companies",
                      file=sys.stderr)
                break
            raise

        # Progress
        done = len(results)
        found = sum(1 for r in results if r["status"] == "found")
        total_cost = sum(r["exa_cost"] for r in results)
        print(f"Progress: {done}/{len(targets)} "
              f"({found} found, ${total_cost:.2f} spent)", flush=True)

        # Stop if we're approaching the $20 budget
        if total_cost >= 19.50:
            print(f"Budget limit reached: ${total_cost:.2f}", file=sys.stderr)
            break

        # Pace: ~1 search/sec to be safe
        await asyncio.sleep(1.0)

    # Write results
    with open(out_path, "w") as f:
        json.dump(results, f, indent=1)

    found = sum(1 for r in results if r["status"] == "found")
    total_cost = sum(r["exa_cost"] for r in results)
    print(f"Done: {len(results)} companies, {found} with emails, "
          f"${total_cost:.2f} spent")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", required=True,
                        help="JSON file with company list")
    parser.add_argument("--out", required=True,
                        help="Output JSON path")
    parser.add_argument("--concurrency", type=int, default=5)
    args = parser.parse_args()

    with open(args.targets) as f:
        targets = json.load(f)
    if isinstance(targets, dict):
        targets = targets.get("companies", targets.get("targets", []))

    print(f"Enriching {len(targets)} companies with Exa", flush=True)
    asyncio.run(main_async(targets, args.out, args.concurrency))
    return 0


if __name__ == "__main__":
    sys.exit(main())

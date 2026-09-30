#!/usr/bin/env python3
"""
Multi-search-engine contact discovery for the GitHub worker.

Searches multiple engines in parallel for company contact pages,
then returns URLs for the worker to scrape for emails.

Engines:
- KeenAble API (keenable.ai) - requires KEENABLE_API_KEY env var
- DuckDuckGo (via ddgs library) - no key needed
- Bing RSS - no key needed, RSS endpoint

Usage:
    from search_discovery import discover_contact_pages
    urls = discover_contact_pages("magicspoon.com", "Magic Spoon")

For GitHub Actions: set KEENABLE_API_KEY as a repository secret.
"""

import concurrent.futures
import json
import os
import re
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus

import urllib.request
import urllib.error


def search_keenable(domain, company_name, max_results=10):
    """
    Search KeenAble API for contact pages.
    Requires KEENABLE_API_KEY environment variable.
    Returns list of URLs.
    """
    api_key = os.environ.get("KEENABLE_API_KEY", "").strip()
    if not api_key:
        return []
    
    urls = []
    queries = [
        f"site:{domain} contact",
        f"{domain} email address",
        f"{company_name} contact email",
    ]
    
    for query in queries:
        try:
            payload = {
                "query": query,
                "max_results": max_results,
            }
            body = json.dumps(payload).encode()
            req = urllib.request.Request(
                "https://api.keenable.ai/v1/search",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-API-Key": api_key,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                for result in data.get("results", []):
                    url = result.get("url", "")
                    if url and domain in url:
                        urls.append(url)
                    if len(urls) >= max_results:
                        break
        except Exception:
            continue
        if len(urls) >= max_results:
            break
    
    return list(dict.fromkeys(urls))


def search_duckduckgo(domain, company_name, max_results=10):
    """
    Search DuckDuckGo HTML endpoint for contact pages.
    Note: Currently blocked by bot challenge. Kept for future if protection lifts.
    """
    return []  # Blocked by anomaly.js challenge as of 2026-09-30


def search_bing_rss(domain, company_name, max_results=10):
    """Search Bing via RSS endpoint for contact pages."""
    urls = []
    try:
        # Bing RSS doesn't respect site: operator well, so search for domain + contact terms
        # and filter results to the target domain
        queries = [
            f"{domain} contact",
            f"{domain} email address",
        ]
        for query in queries:
            url = f"https://www.bing.com/search?q={quote_plus(query)}&format=rss"
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    xml_data = resp.read()
                    root = ET.fromstring(xml_data)
                    for item in root.findall('.//item'):
                        link = item.find('link')
                        if link is not None and link.text:
                            link_url = link.text
                            # Only keep URLs on the target domain (or close variants)
                            if domain in link_url or domain.replace('.', '') in link_url.replace('.', ''):
                                urls.append(link_url)
                            if len(urls) >= max_results:
                                break
            except Exception:
                continue
            if len(urls) >= max_results:
                break
    except Exception:
        pass
    
    return list(dict.fromkeys(urls))


def discover_contact_pages(domain, company_name, max_per_engine=10):
    """
    Search multiple engines in parallel for contact pages.
    Returns deduplicated list of URLs.
    """
    all_urls = []
    
    engines = [
        ('keenable', search_keenable),
        ('duckduckgo', search_duckduckgo),
        ('bing', search_bing_rss),
    ]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(engines)) as executor:
        future_to_engine = {
            executor.submit(func, domain, company_name, max_per_engine): name
            for name, func in engines
        }
        
        for future in concurrent.futures.as_completed(future_to_engine):
            engine_name = future_to_engine[future]
            try:
                urls = future.result()
                all_urls.extend(urls)
            except Exception:
                continue
    
    # Dedupe, preserve order
    seen = set()
    result = []
    for url in all_urls:
        if url not in seen:
            seen.add(url)
            result.append(url)
    
    return result


if __name__ == '__main__':
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else 'magicspoon.com'
    name = sys.argv[2] if len(sys.argv) > 2 else 'Magic Spoon'
    
    urls = discover_contact_pages(domain, name)
    print(f"Found {len(urls)} contact page URLs for {domain}:")
    for url in urls:
        print(f"  - {url}")

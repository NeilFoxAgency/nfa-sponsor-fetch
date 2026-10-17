#!/usr/bin/env python3
"""Regression tests for robots.txt enforcement in fetch_contacts.

These tests pin the worker's documented hard line: "robots.txt is honored
for every live URL fetched." They spin up a real local HTTP server and use
its request log as ground truth for what the worker actually fetched.

Covered behavior:
1. When robots.txt disallows the homepage, the homepage is never fetched
   and the result is status="error" / reason="robots_disallowed".
2. Directly probed contact endpoints (/contact, /about, ...) are checked
   against robots.txt before fetching; disallowed endpoints are skipped.
3. robots.txt is fetched once per origin no matter how many page URLs are
   checked (the checks are cheap; the fetch is not repeated).
4. A normal allowed site still extracts a named contact end-to-end
   (guards against the pre-fetch checks breaking the happy path).

The tests need no network beyond 127.0.0.1 and no pytest fixtures, so they
run under plain pytest (`pytest worker/`) or any unittest-style runner.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fetch_contacts as fc  # noqa: E402

FILLER = "lorem ipsum dolor sit amet consectetur adipiscing elit " * 12

WAYBACK_FAILURE = {
    "ok": False,
    "html": None,
    "reason": "no_archive_copy",
    "status": None,
    "source_type": "archived",
    "snapshot_date": None,
}


class _Site:
    """A local website with a configurable robots.txt and page map.

    `requests` records the path of every HTTP request the worker makes;
    it is the ground truth for fetch-ordering assertions.
    """

    def __init__(self, robots: str, pages: dict[str, str] | None = None,
                 default_html: str | None = None):
        self.robots = robots
        self.pages = dict(pages or {})
        self.default_html = default_html or self.page_html()
        self.requests: list[str] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib hook name
                site.requests.append(self.path)
                if self.path == "/robots.txt":
                    body, ctype = site.robots, "text/plain"
                else:
                    body = site.pages.get(self.path, site.default_html)
                    ctype = "text/html"
                payload = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # keep test output quiet
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)

    @staticmethod
    def page_html(extra_body: str = "") -> str:
        return (
            "<html><head><title>Acme Widgets</title></head><body>"
            f"<p>{FILLER}</p>{extra_body}</body></html>"
        )

    def __enter__(self) -> "_Site":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def _run_discovery(site: _Site) -> dict:
    """Run discover_one against the local site with externalities stubbed.

    The Wayback fallback is disabled (it would otherwise reach archive.org)
    and the identity gates are neutralized (a 127.0.0.1 host can never
    contain the company-name tokens); neither is under test here.
    """
    session = fc.Session(impersonate="chrome")
    try:
        with mock.patch.object(fc, "wayback_fetch",
                               return_value=WAYBACK_FAILURE), \
             mock.patch.object(fc, "company_name_matches_domain",
                               return_value=True), \
             mock.patch.object(fc, "identity_matches_content",
                               return_value=True):
            return fc.discover_one(
                company_domain="acme-widgets.test",
                company_name="Acme Widgets",
                website=site.url,
                session=session,
                user_agent=fc.UA_PROFILES[0]["headers"]["User-Agent"],
            )
    finally:
        session.close()


def test_homepage_never_fetched_when_robots_disallows_all():
    """robots.txt must be consulted BEFORE the first page fetch."""
    with _Site(robots="User-agent: *\nDisallow: /\n") as site:
        result = _run_discovery(site)
        assert result["status"] == "error"
        assert result["reason"] == "robots_disallowed"
        assert result["pages_fetched"] == 0
        # Only robots.txt may be requested; the homepage ("/") must not be.
        assert "/robots.txt" in site.requests
        assert "/" not in site.requests


def test_probed_endpoints_respect_robots():
    """Directly probed endpoints (/contact, ...) honor robots.txt too."""
    with _Site(robots="User-agent: *\nDisallow: /contact\n") as site:
        result = _run_discovery(site)
        assert result["status"] in ("found", "not_found", "error")
        # The disallowed endpoint must never be fetched...
        assert "/contact" not in site.requests
        # ...while allowed probes and the homepage still are.
        assert "/" in site.requests
        assert "/about" in site.requests


def test_robots_txt_fetched_once_per_origin():
    """robots.txt is cached: many URL checks cost one robots.txt fetch."""
    home = _Site.page_html('<a href="/contact">Contact us</a>')
    with _Site(robots="User-agent: *\nAllow: /\n",
               pages={"/": home}) as site:
        _run_discovery(site)
        robots_fetches = site.requests.count("/robots.txt")
        # Homepage + probed endpoints + the discovered /contact link all
        # trigger robots checks; the file itself must be fetched once.
        assert len(site.requests) > 2
        assert robots_fetches == 1


def test_named_contact_still_extracted_when_allowed():
    """Happy path: an allowed site with a titled person + mailto works."""
    home = _Site.page_html(
        "<p>Jane Smith</p><p>Founder</p>"
        '<a href="mailto:jane@127.0.0.1">Jane Smith</a>'
    )
    with _Site(robots="User-agent: *\nAllow: /\n",
               pages={"/": home}) as site:
        result = _run_discovery(site)
        assert result["status"] == "found"
        names = [p["name"] for p in result["people"]]
        assert "Jane Smith" in names
        jane = next(p for p in result["people"] if p["name"] == "Jane Smith")
        assert jane["email"] == "jane@127.0.0.1"

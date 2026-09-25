# nfa-sponsor-fetch

Fetch proxy for the Neil Fox Agency sponsor pipeline. GitHub Actions runners
fetch sponsor-prospect websites and extract NAMED decision-maker contacts, so
the main NFA VM only ever talks to `api.github.com` (one domain) instead of
thousands of business domains.

Public repo: Actions minutes are unlimited, so batch volume can grow freely.

## How a batch flows

1. The dispatcher (`ops/sponsor-fetch/` on the NFA VM) writes
   `batches/<batch_id>/targets.json` via the GitHub API and dispatches the
   `fetch-sponsors` workflow with `batch_id`.
2. The runner installs deps + headless Chromium, runs
   `worker/fetch_contacts.py`, and commits `batches/<batch_id>/results.json`.
3. The dispatcher polls for `results.json` and converts hits into
   `sponsor_contacts` rows flagged extracted-unverified.

## What the worker extracts

Input targets: `{"company_domain", "company_name", "website"}`.

Per company, `results.json` holds:

- `status`: `found` (>=1 named contact), `not_found`, or `error`
- `contacts`: list of `{"name", "title", "email", "source_url"}` for NAMED
  people (name + title found near each other on the site) whose email is
  first-party (email domain matches the company website domain)
- `emails`: every first-party address with `confidence` (`highest` = mailto:,
  `high` = exact page text, `medium` = de-obfuscated), `source_url`,
  `source_type` (`live` | `archived`), `snapshot_date`, `context_snippet`
- `role_emails`: first-party addresses with no person attached
  (`info@`, `support@`, ...) for manual review, never treated as hits
- `contact_pages`: every contact-relevant URL discovered, with `url`,
  `page_type` (home/contact/about/team/support/press/legal/other)
- `contact_forms`: `<form>` elements with contact intent, with `page_url`,
  `action`, `fields`, `captcha_protected` (CAPTCHA-backed forms are still
  recorded, flagged — a form is a fallback lead when no email is found)
- `company_summary`: one-line description from meta/og tags or first paragraph
- `reason`: granular failure code (`dns_failure`, `http_403`,
  `challenge_page`, `robots_disallowed`, `identity_domain_mismatch`,
  `no_named_contacts`, ...)

## Hard gates

- This system NEVER sends anything. It only extracts public information.
- Worker output is UNVERIFIED. Every contact must still pass the existing
  NFA browser verification gate (SigmaWire, VERIFIED_DELIVERABLE) before any
  outreach. One cold email per company ever; suppression/DNC checks and the
  AgentMail-only sending rule are unchanged.

## Rules the worker follows

- Tiered fetch per page: (1) curl_cffi with rotating Chrome/Firefox/Safari
  TLS profiles + retries on transient errors; (2) headless Chromium only for
  JS-heavy pages, never to defeat a block; (3) Wayback Machine fallback when
  the live fetch fails (archive.org cannot be blocked by the target; hits are
  flagged `archived` with the snapshot date).
- Honors robots.txt; denied pages are recorded as failures.
- CAPTCHA / challenge / login pages are detected and treated as fetch
  failures, never solved or bypassed.
- Only first-party emails (email domain matches the company website domain)
  are reported; company identity must match the domain and page content.
  Emails are never pattern-guessed, only reported as actually found.

# sfn-fetch-proxy

Private helper repo for Storm Fix Now. GitHub Actions runners fetch business
websites and extract public first-party contact emails, so the main VM only
ever talks to `api.github.com` (one domain) instead of thousands of business
domains.

## How a batch flows

1. The VM writes `batches/<batch_id>/targets.json` (via the GitHub API) and
   dispatches the `fetch-contacts` workflow with `batch_id`.
2. The runner installs deps + headless Chromium, runs
   `worker/fetch_contacts.py`, and commits `batches/<batch_id>/results.json`.
3. The VM polls for `results.json` and converts hits into contact records.

## Cost

$0. Private repos get 2,000 Actions minutes/month on Linux runners; a daily
batch of a few hundred sites takes a few minutes. No subscriptions, no cards.

## Rules the worker follows

- Plain HTTP first, headless Chromium only as a fallback for JS-heavy pages.
- Honors robots.txt; denied pages are recorded as failures.
- CAPTCHA / challenge / login pages are detected and treated as fetch
  failures — never solved or bypassed.
- Only first-party emails (email domain matches the business website domain)
  are reported; identity match required between business name and page.

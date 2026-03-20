# Website Audit Tool

A Flask application for passive website intelligence gathering, with a cleaner built-in technology profiler, PDF export, stricter CMS detection, and Vercel-friendly static asset handling.

## What it does

- Detects traditional, headless, proprietary, and government CMS platforms from public evidence
- Infers plugins, modules, frontend libraries, infrastructure, transport settings, cookies, and runtime clues
- Ranks multiple CMS findings into primary and secondary results with confidence labels
- Organizes technology findings into structured sections such as edge delivery, application platform, frontend experience, analytics, security, and data
- Checks key security headers and applies secure response headers to the app itself
- Generates a health score, explanation table, recommendations, and a PDF report
- Shows an engaged loading state while an audit is in progress

## Project structure

```text
audit_tool/              Flask app factory, routes, and HTTP fetch helpers
detectors/               CMS, plugin, module, library, security, and technology fingerprint rules
services/                Passive profiling, scoring, recommendations, and version guidance
pdf/                     Report generation
public/                  Vercel-friendly static assets
templates/               Jinja templates
scanner.py               Passive audit orchestration entry point
app.py                   Development and Vercel Flask entry point
requirements.txt         Python dependencies
```

## Run locally

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Start the app with `python3 app.py`.
4. Open `http://127.0.0.1:5000`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## API endpoints

- `GET /` serves the single-page interface
- `POST /scan` accepts `{"url":"https://example.com"}` and returns JSON results
- `POST /export-pdf` accepts a scan result payload and returns a PDF download

## Detection strategy

- The audit is passive only. It relies on public HTML, headers, asset paths, cookie names, and generator metadata.
- CMS detection includes traditional platforms, proprietary builders, headless CMS products, and government-focused platforms such as SharePoint, Sitefinity, CivicPlus, CivicLive, ProdCity, TerminalFour, ButterCMS, Craft CMS, and Granicus products when strong public signals are present.
- The built-in profiler now groups detections into stable presentation sections instead of a long mixed list.
- Technology signatures live in [detectors/stack_detector.py](/var/www/website-audit-tool/detectors/stack_detector.py) and can be extended safely over time.
- The CMS classifier lives in [detectors/cms_detector.py](/var/www/website-audit-tool/detectors/cms_detector.py) and produces a ranked primary/secondary CMS summary.
- WordPress recommended versions are resolved live from the official WordPress core update API instead of relying on a stale hardcoded release string.

## Security posture

- The app checks key response headers on the target site.
- The Flask app now sends `Content-Security-Policy`, `Referrer-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy` by default.
- User input is validated before any outbound request is made.

## Notes and limitations

- This is not an active scanner or penetration test.
- Version detection remains best-effort and may stay `Not publicly exposed`.
- Highly protected websites may still block datacenter traffic or require browser rendering.
- TLS validation now uses the `certifi` CA bundle for both `requests` and the curl fallback to reduce environment-specific certificate trust failures.
- If a target still serves a broken or privately issued certificate chain, the fetcher now performs a last-resort insecure retry automatically and surfaces a warning in the audit results.
- Public hints can be missing or intentionally misleading, so treat the report as evidence-based guidance, not proof of full stack ownership.

## Deploying To Vercel

This project is structured to fit Vercel's Flask and Python deployment model:

- `app.py` exports the Flask `app` object, which Vercel uses as the entrypoint.
- Static assets live in `public/**`, which Vercel serves efficiently.
- Templates remain in `templates/**` and continue to render through Flask.
- Python dependencies are installed from `requirements.txt`.
- `vercel.json` explicitly includes the Flask app package, detectors, services, PDF code, templates, and public assets in the serverless bundle.

Recommended steps:

1. Push this repository to GitHub.
2. Create a free Vercel account and import the repo.
3. Keep the framework as auto-detected Python or Flask if Vercel suggests it.
4. Leave the root as the repository root.
5. Add any required environment variables in the Vercel project settings before production use.
6. Deploy.

What Vercel should see at build time:

- `app.py` at the repository root
- `requirements.txt` at the repository root
- static assets under `public/`
- Flask templates under `templates/`

For local parity with Vercel CLI:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
vercel dev
```

## Troubleshooting

- If you see `TemplateNotFound`, confirm you are running the app from this project root.
- If PDF export fails, confirm `reportlab` installed successfully.
- If target sites return `403 Forbidden`, the site may be blocking automated traffic.
- If HTTPS fetches fail with `CERTIFICATE_VERIFY_FAILED`, update dependencies so `certifi` is installed and retry. The app now uses `certifi` for both the default HTTP client and curl fallback, then automatically falls back once more without certificate verification if the target's chain is still broken.

## CI validation

GitHub Actions now includes:

- `validate.yml` on pushes and pull requests:
  installs dependencies from `requirements.txt`, compiles the Python source tree, and imports the Flask app as a smoke test.
- `pr-release-comment.yml` on PR merge into `main`:
  posts a release-oriented comment back on the merged pull request so the merge event is explicitly marked for release/deployment follow-up.

## Changelog

- See [CHANGELOG.md](/var/www/website-audit-tool/CHANGELOG.md) for a running record of notable project changes.

## Extending the tool

- Add new CMS fingerprints in [detectors/cms_detector.py](/var/www/website-audit-tool/detectors/cms_detector.py)
- Expand passive technology signatures in [detectors/stack_detector.py](/var/www/website-audit-tool/detectors/stack_detector.py)
- Tune score weighting in [services/score_engine.py](/var/www/website-audit-tool/services/score_engine.py)
- Adjust the presentation in [templates/index.html](/var/www/website-audit-tool/templates/index.html)
